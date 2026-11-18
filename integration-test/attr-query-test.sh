#!/usr/bin/env bash
# oidc + zpr-attr/1 trusted-service end-to-end test (zipline#81, epic #72
# E1; on Zodes since zl-zipline#234). oidc-file-interplay-test.sh's harness
# (fake IdP, no browser, no Google) with the `file` decorator replaced by
# the networked `zpr-attr/1` attribute service: the reference
# `zpr-attr-server` from zl-zpr-visaservice (zipline#80) serving
# attr-query-data.json over pinned TLS on the relay namespace's loopback,
# next to the visa service.
#
# The relay and the visa service run as in zode-link-test.sh, and zb and zc
# join through the relay (pregen/attr-query.zpl). A user logs in on zb with
# `ph-cli connect` (zl-zipline#233), so zb's own actor carries the user's
# attributes; zc is device-only and provides Web.
#   - `google` (api = "oidc", the fake IdP) authenticates zb's user and
#     mints the identity attribute user.sub (+ user.email).
#   - `zipline` (api = "zpr-attr/1") decorates that identity over HTTPS:
#     POST {url}/query keyed on user.sub, answering with user.dept and the
#     `contractor` tag, authenticated by the bearer token the vs reads from
#     <ts_secrets_dir>/zipline.token (zipline#78).
#   - The only policy statement referencing a trusted-service attribute is
#     `allow contractor users to access Web.` — it references only
#     zipline's tag, so `google` survives compilation by the
#     identity-vendor retention rule (zipline#23). The zpdump pre-check
#     below asserts both services are in the binary without needing root.
#
# The four legs, in order:
#   1. Decoration: after the OIDC login zb's actor carries user.sub,
#      user.email, user.dept, user.zpr.tag.contractor and
#      user.zpr.authority = google, and the `contractor` visa carries
#      traffic (zb -> Web on zc).
#   2. Untargeted notify: `zpr-attr-server --notify` with no identity pairs
#      posts the "everything changed" `{}` body (zipline#79); reconcile
#      re-queries with UNCHANGED data and must converge — same attributes,
#      no spurious revocation, connectivity intact. This leg runs before
#      the data edit on purpose: "no spurious revocation" is only provable
#      while the data still vends the tag.
#   3. Revocation: the store's data drops `contractor` (the server is
#      restarted on the edited JSON — the reference server loads its data
#      once at startup), then a TARGETED notify (user.sub=user-a) with a
#      `Permission::Notify` key bound to the zipline service id (the
#      zipline#79 V2 surface). The queued TrustedServiceChange event
#      re-queries, the tag disappears, the visa is revoked, and a fresh
#      connect attempt (ping) is denied, while the Zodes' device flows to
#      the visa service still work.
#   4. SKIP_NOTIFY=1 negative knob: skips ONLY the notify posts (both of
#      them; the untargeted one is skipped too so the negative run reaches
#      the revocation window quickly). With no notify the revocation
#      assertion MUST fail inside its bounded poll window — proving leg 3
#      depends on the queued change event, not on TTL expiry. A SKIP_NOTIFY
#      run is therefore EXPECTED to end in FAILURE at "revocation". The
#      poll window (REVOKE_POLL_SECS) is deliberately far under the
#      fixture's 90 s attribute TTL so autonomous TTL-driven re-query
#      cannot fake a pass.
#
# The vs admin TLS cert is minted at runtime with an IP SAN for the VS ZPR
# address, signed by the pregen test CA — NOT emit_vs_config's pregen
# *.zpr.org cert — because `zpr-attr-server --notify` verifies TLS strictly
# (unlike vs-admin), and the admin URL names the VS by IP literal.
set -euo pipefail

# vss_rpc=DEBUG, appended to any DEBUG_TARGETS given: the Zodes log the
# identity-provider list they get over VSS at debug level, and the test
# waits for it.
DEBUG_TARGETS="${DEBUG_TARGETS:-all=INFO} vss_rpc=DEBUG"

# 1 = skip the notify posts (the negative leg; see header). Default 0.
SKIP_NOTIFY=${SKIP_NOTIFY:-0}

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

ZODE_POLICY_BIN=attr-query.bin2

# The reference zpr-attr/1 server (zl-zpr-visaservice zpr-attr-server,
# zipline#80). CI extracts it from the visa-service release next to this
# script; locally, build it in zl-zpr-visaservice (`cargo build -p
# zpr-attr-server`) and copy it here, or point ZPR_ATTR_SERVER_BIN at it.
ZPR_ATTR_SERVER_BIN="${ZPR_ATTR_SERVER_BIN:-$(realpath -s "$(dirname "$0")/zpr-attr-server")}"
# Optional: with a zpdump on hand the both-services check runs first.
# Absent, the check is skipped with a warning (the fixture Makefile's
# compile is the fallback evidence).
ZPDUMP_BIN="${ZPDUMP_BIN:-$(realpath -s "$(dirname "$0")/zpdump" 2>/dev/null || true)}"

# The attribute service listens on the relay namespace's loopback; the
# port is pinned in the fixture's [trusted_services.zipline] url.
ATTR_PORT=8443

# How long the revocation leg polls for the visa to go. Deliberately far
# under the fixture's 90 s attribute TTL: in a SKIP_NOTIFY=1 run nothing
# may revoke inside this window, and a window near the TTL would let an
# autonomous TTL-driven re-query fake a pass.
REVOKE_POLL_SECS=25

if [ ! -e "$ZPR_ATTR_SERVER_BIN" ]; then
  echo "zpr-attr-server binary not found, expected it at $ZPR_ATTR_SERVER_BIN"
  echo "build it in zl-zpr-visaservice: cargo build -p zpr-attr-server"
  echo "then copy target/debug/zpr-attr-server next to this script, or set ZPR_ATTR_SERVER_BIN"
  exit 1
fi

if ! command -v jq > /dev/null; then
  echo "jq is required for the admin-surface assertions"
  exit 1
fi

#
# Pre-check: both trusted services must be in the compiled policy.
# `google` is referenced by no ZPL statement, so its presence here is the
# identity-vendor retention rule (zipline#23) at work; `zipline` proves the
# zpr-attr/1 declaration (zipline#76) survived weaving.
#
if [ -n "$ZPDUMP_BIN" ] && [ -x "$ZPDUMP_BIN" ]; then
  DUMP=$("$ZPDUMP_BIN" "$PREGEN/$ZODE_POLICY_BIN")
  for WANT in "google trusted (oidc)" "zipline trusted (zpr-attr/1)"; do
    if ! grep -qF "$WANT" <<<"$DUMP"; then
      echo "FAILURE: compiled policy is missing '$WANT' — was the fixture"
      echo "compiled with a zplc older than 0.19.0 (zipline#76)?"
      exit 1
    fi
  done
  echo "zpdump pre-check OK: both trusted services present in $ZODE_POLICY_BIN"
else
  echo "WARNING: zpdump not available (set ZPDUMP_BIN); skipping the both-services pre-check"
fi

# Launch the reference attribute server on the relay's loopback, serving
# data file $1 over TLS pinned to the pregen CA (the CA the fixture's
# ca_cert_path embeds into the policy).
function launch_attr_server() {
  in_ns zpr-relay \
    "$ZPR_ATTR_SERVER_BIN" \
    --listen "127.0.0.1:$ATTR_PORT" \
    --cert attr-server.crt --key attr-server.key \
    --token-file attr-server.token \
    --data "$1" \
    2>&1 | tee -a attr-server.log | prefix_log attr-server &
}

# The server is up when /schema answers 200 to the bearer token.
function check_attr_server() {
  in_ns zpr-relay curl --silent --fail \
    --cacert "$PREGEN/ca-cert.pem" \
    -H "Authorization: Bearer $(cat attr-server.token)" \
    --output /dev/null "https://127.0.0.1:$ATTR_PORT/schema"
}

# Stop the serve-mode server (notify-mode invocations exit on their own).
#
# SIGTERM, not SIGINT: a job launched with `&` from a non-interactive shell
# inherits SIGINT *ignored*, and unlike ph/vs the reference server installs
# no handler to override that, so a SIGINT is silently dropped, the old
# server keeps the port, and the data-v2 relaunch fails with "Address
# already in use". Then wait for the listener to be gone rather than racing
# the relaunch.
function stop_attr_server() {
  pkill_own -SIGTERM -f "zpr-attr-server --listen" || true
  wait_for 10 attr_server_down
}

function attr_server_down() {
  ! check_attr_server
}

# Post a change notification from the relay's namespace with the
# service-bound notify key (zipline#79). The arguments are the --notify
# identity pairs; none means the untargeted `{}` body.
function attr_notify() {
  in_ns zpr-relay \
    "$ZPR_ATTR_SERVER_BIN" \
    --notify "$@" \
    --vs-url "$ADMIN_URL" \
    --vs-service zipline \
    --vs-api-key-file notify.key \
    --vs-ca-cert "$PREGEN/ca-cert.pem"
}

# Run vs-admin against the admin API from the relay's namespace.
function vs_admin() {
  in_ns zpr-relay \
    "$VS_ADMIN_BIN" --svc-url "$ADMIN_URL" --ca-cert ca.crt \
    --api-key-file vs-admin.key --format compact "$@"
}

# Print the address of the user actor: the one whose attributes carry
# user.sub == user-a. Deliberately found by its attributes rather than by
# zb's address: the actor API identifies actors by assigned ZPR address
# (zipline#31), and this checks that the login landed on some actor.
function find_user_actor() {
  local ADDR DESC
  for ADDR in $(vs_admin actors | jq -r '.[].zpr_addr'); do
    DESC=$(vs_admin actors --addr "$ADDR" 2>/dev/null) || continue
    if jq -e '.attrs[] | select(.key=="user.sub") | select(.value == ["user-a"])' \
        >/dev/null 2>&1 <<<"$DESC"; then
      echo "$ADDR"
      return 0
    fi
  done
  return 1
}

# Assert the five interplay attributes on the user actor. user.sub and
# user.email come from google (the authenticator); user.dept and
# user.zpr.tag.contractor from the zipline attribute service (the
# decorator; tag => presence is the assertion, not a value); and
# user.zpr.authority must name google — the credential verifier — and
# never zipline (zipline#25/#26). $1 is the phase label.
function assert_user_actor() {
  local PHASE=$1 DESC CHECK
  DESC=$(vs_admin actors --addr "$USER_ACTOR_ADDR") || {
    echo "ASSERTION FAILED ($PHASE): could not fetch actor $USER_ACTOR_ADDR"
    return 1
  }
  for CHECK in \
    '.attrs[] | select(.key=="user.sub")                 | select(.value == ["user-a"])' \
    '.attrs[] | select(.key=="user.email")               | select(.value == ["user-a@example.com"])' \
    '.attrs[] | select(.key=="user.dept")                | select(.value == ["engineering"])' \
    '.attrs[] | select(.key=="user.zpr.tag.contractor")' \
    '.attrs[] | select(.key=="user.zpr.authority")       | select(.value == ["google"])'
  do
    if ! jq -e "$CHECK" >/dev/null <<<"$DESC"; then
      echo "ASSERTION FAILED ($PHASE): no attribute matching: $CHECK"
      echo "actor descriptor was:"
      jq . <<<"$DESC" || echo "$DESC"
      return 1
    fi
  done
  echo "assertion OK: the user actor's attributes ($PHASE)"
}

# True once the contractor tag is GONE from the user actor — the
# revocation leg's convergence signal.
function contractor_tag_gone() {
  local DESC
  DESC=$(vs_admin actors --addr "$USER_ACTOR_ADDR") || return 1
  ! jq -e '.attrs[] | select(.key=="user.zpr.tag.contractor")' \
      >/dev/null <<<"$DESC"
}

# The Zodes' device flows to the visa service, which no attribute change
# touches ($1 is the phase label).
function plumbing_test() {
  local RESULT=0
  zode_ping zb "$VS_ZPR_ADDR" "zb reaches the visa service ($1)" 10 || RESULT=1
  zode_ping zc "$VS_ZPR_ADDR" "zc reaches the visa service ($1)" 10 || RESULT=1
  return "$RESULT"
}

enter_test_namespace "$@"

zode_begin

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
create_idp_cert

# The attribute data, two revisions: v1 vends dept + the contractor tag;
# v2 is v1 with contractor dropped (the revocation leg's edit).
cp "$PREGEN/attr-query-data.json" attr-data-v1.json
jq 'del(."user.sub"."user-a".contractor)' attr-data-v1.json > attr-data-v2.json

# The zipline bearer token (zipline#78), written twice: attr-server.token
# is the server's --token-file; zipline.token is what the vs reads from
# <ts_secrets_dir>/<id>.token. Same secret, two consumers.
openssl rand -hex 32 > attr-server.token
cp attr-server.token zipline.token
chmod 600 attr-server.token zipline.token

# Mint a TLS certificate $1.crt/$1.key for CN $2 with the IP SAN $3, signed
# by the PREGEN CA (the CA the fixture's ca_cert_path embedded into the
# policy). -CAserial keeps openssl's serial bookkeeping in the working
# directory instead of littering pregen/.
function mint_ip_cert() {
  openssl req -new -newkey rsa:2048 -nodes -keyout "$1.key" \
    -subj "/CN=$2" -out "$1.csr" 2> /dev/null
  openssl x509 -req -in "$1.csr" -CA "$PREGEN/ca-cert.pem" \
    -CAkey "$PREGEN/ca-key.pem" -CAserial pregen-ca.srl -CAcreateserial \
    -days 1 -out "$1.crt" \
    -extfile <(printf "subjectAltName=IP:%s" "$3") 2> /dev/null
}

# The attribute server's certificate, which the vs's pinned client checks,
# and the vs admin certificate, which `zpr-attr-server --notify` checks
# strictly against the IP literal in the admin URL.
mint_ip_cert attr-server 127.0.0.1 127.0.0.1
mint_ip_cert vs-admin-tls vs-admin "$VS_ZPR_ADDR"

# The vs config, which launch_zode_vs keeps. Not emit_vs_config: admin_cert
# is the runtime-minted IP-SAN cert (see above), and ts_secrets_dir points
# the zipline token read at this directory (it defaults to the config dir;
# explicit is better than implicit here).
cat > vs-config.toml <<EOF
[core]
admin_cert = "$PWD/vs-admin-tls.crt"
admin_key = "$PWD/vs-admin-tls.key"
vk_uri = "redis://127.0.0.1:6379"
ts_secrets_dir = "."
EOF

# Admin API keys, which launch_zode_vs keeps: mint two directly in the
# format vsapikey uses (vs/src/apikey.rs: zpr_vsapi.<id_hex>.<b64url_secret>;
# vs_keys.toml stores the sha256 of the secret). vs-admin.key is the
# readwrite key the assertions use; notify.key is a Permission::Notify key
# BOUND to the zipline service id (zipline#79) — the least-privilege key
# the attribute server posts change notifications with.
python3 - <<'PYEOF'
import base64, hashlib, secrets

def mint(permission, description, service=None):
    key_id = secrets.token_bytes(4).hex()
    secret = secrets.token_bytes(32)
    b64 = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
    lines = [
        f'[keys.{key_id}]',
        'owner = "integration-test"',
        f'permission = "{permission}"',
        'status = "active"',
        'created = "2026-09-22"',
        f'secret_hash = "{hashlib.sha256(secret).hexdigest()}"',
        f'description = "{description}"',
    ]
    if service is not None:
        lines.append(f'service = "{service}"')
    return "\n".join(lines) + "\n", f"zpr_vsapi.{key_id}.{b64}\n"

rw_toml, rw_key = mint("readwrite", "attr-query-test admin")
notify_toml, notify_key = mint("notify", "attr-query-test notify", service="zipline")
with open("vs_keys.toml", "w") as f:
    f.write(rw_toml + "\n" + notify_toml)
with open("vs-admin.key", "w") as f:
    f.write(rw_key)
with open("notify.key", "w") as f:
    f.write(notify_key)
PYEOF
chmod 600 vs-admin.key notify.key

PASS=0
# The relay's IdP instance only serves the visa service's JWKS refresh;
# zb's mints the token of the user who logs in on zb.
launch_zode_idp relay user-vs-unused || PASS=1
launch_zode_idp zb user-a || PASS=1

# The attribute server starts before the visa service: the policy load
# reads the zipline token and runs the advisory schema check against a live
# server.
if [[ "$PASS" == 0 ]]; then
  echo "Launching zpr-attr-server (data v1: dept + contractor)"
  launch_attr_server attr-data-v1.json
  wait_for 15 check_attr_server || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  launch_relay || PASS=1
fi
if [[ "$PASS" == 0 ]]; then
  launch_zode_vs || PASS=1
fi
if [[ "$PASS" == 0 ]]; then
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem"
  wait_log_after 60 zb.log 'registered VSS' 0 "zb joins and registers its VSS" || PASS=1
  wait_log_after 60 zc.log 'registered VSS' 0 "zc joins and registers its VSS" || PASS=1
  wait_log_after 30 zb.log 'received services update with [1-9]' 0 "zb has the identity-provider list" || PASS=1
fi

#
# Leg 1: login, decoration and connect-path assertions
#
if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"
  echo "== 1. zb's user (sub user-a) logs in with ph-cli connect"
  start_zode_login zb connect connect.out || PASS=1
  if wait "$LOGIN_PID"; then
    echo "assertion OK: connect exits 0"
  else
    echo "ASSERTION FAILED: connect exited non-zero:"
    cat connect.out
    PASS=1
  fi
fi

if [[ "$PASS" == 0 ]]; then
  echo "Locating the user actor on the admin API"
  USER_ACTOR_ADDR=""
  for _ in $(seq 1 15); do
    USER_ACTOR_ADDR=$(find_user_actor) && break
    sleep 1
  done
  if [ -z "$USER_ACTOR_ADDR" ]; then
    echo "ASSERTION FAILED: no actor carrying user.sub == user-a on the admin API"
    vs_admin actors || true
    PASS=1
  elif [[ "$USER_ACTOR_ADDR" != "$ZB_ZPR_ADDR" ]]; then
    echo "ASSERTION FAILED: the user is on actor $USER_ACTOR_ADDR, not on zb's own actor $ZB_ZPR_ADDR"
    PASS=1
  else
    echo "assertion OK: the user is on zb's own actor ($USER_ACTOR_ADDR)"
  fi
fi

if [[ "$PASS" == 0 ]]; then
  assert_user_actor "connect path" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  # The `contractor` visa's evidence: zb (the contractor user) reaches Web
  # on zc. The first echoes wait for the visa request.
  zode_ping zb "$ZC_ZPR_ADDR" "the contractor visa carries zb -> Web" 20 || PASS=1
  plumbing_test "connect path" || PASS=1
fi

#
# Leg 2: untargeted notify with UNCHANGED data — reconcile must converge
# with no spurious revocation. Runs before the data edit on purpose (see
# header). Skipped under SKIP_NOTIFY so the negative run posts no
# notifications at all.
#
if [[ "$PASS" == 0 ]]; then
  if [[ "$SKIP_NOTIFY" == 1 ]]; then
    echo "SKIP_NOTIFY=1: skipping the untargeted-notify leg"
  else
    echo "== 2. untargeted notify (empty body: everything changed, data unchanged)"
    attr_notify || PASS=1
    if [[ "$PASS" == 0 ]]; then
      sleep 5
      assert_user_actor "after untargeted notify" || PASS=1
      zode_ping zb "$ZC_ZPR_ADDR" "zb still reaches Web after the untargeted notify" || PASS=1
    fi
  fi
fi

#
# Leg 3: revocation. Drop `contractor` from the data (server restart — the
# reference server loads its data once at startup), post the TARGETED
# notify with the service-bound notify key, and poll for the visa to go.
# Under SKIP_NOTIFY=1 the notify is skipped and this poll MUST time out —
# quote that failure as the negative evidence (leg 4).
#
if [[ "$PASS" == 0 ]]; then
  echo "== 3. revocation: restarting zpr-attr-server on data v2 (contractor dropped)"
  stop_attr_server
  launch_attr_server attr-data-v2.json
  wait_for 15 check_attr_server || PASS=1
fi

# The visa service's re-check after an attribute change (its visa sweep)
# revoking a visa, and zb dropping it (as in zode-login-test.sh). The
# actor loses the tag first; the sweep that revokes the visa follows.
VS_SWEEP_REVOKED='visa sweep reason=AttributeChange .* revoked=[1-9]'
REVOKED='Revoked visa [0-9]+'
# The visa service refusing a visa request (vreq): what a fresh connect
# attempt meets once the contractor visa is gone.
EVAL_DENIED='eval denied'

if [[ "$PASS" == 0 ]]; then
  SWEEPS=$(log_count vs.log "$VS_SWEEP_REVOKED")
  REVOCATIONS=$(log_count zb.log "$REVOKED")
  if [[ "$SKIP_NOTIFY" == 1 ]]; then
    echo "SKIP_NOTIFY=1: NOT posting the targeted notify — the revocation poll"
    echo "below must now FAIL inside ${REVOKE_POLL_SECS}s (well under the 90s TTL),"
    echo "proving revocation rides on the queued change event, not TTL expiry."
  else
    echo "Targeted notify: user.sub=user-a changed"
    attr_notify user.sub=user-a || PASS=1
  fi
fi

if [[ "$PASS" == 0 ]]; then
  echo "Polling for the contractor tag to leave the actor (${REVOKE_POLL_SECS}s)"
  if wait_for "$REVOKE_POLL_SECS" contractor_tag_gone; then
    echo "assertion OK: the contractor tag is gone (revocation)"
  else
    echo "ASSERTION FAILED (revocation): user.zpr.tag.contractor still on the"
    echo "actor after ${REVOKE_POLL_SECS}s — no revocation happened"
    PASS=1
  fi
fi

if [[ "$PASS" == 0 ]]; then
  # Once the sweep has revoked the contractor visa and zb has dropped it, a
  # fresh connect attempt is DENIED: zb must ask for a new visa, which the
  # visa service refuses, and no echo is answered. Revoking that visa must
  # not take the fabric down.
  wait_log_after 30 vs.log "$VS_SWEEP_REVOKED" "$SWEEPS" "the visa service's sweep revokes the contractor visa" || PASS=1
  wait_log_after 10 zb.log "$REVOKED" "$REVOCATIONS" "zb drops the revoked visa" || PASS=1
  DENIALS=$(log_count vs.log "$EVAL_DENIED")
  zode_no_ping zb "$ZC_ZPR_ADDR" "a fresh zb -> Web connect is not answered (revocation)" || PASS=1
  wait_log_after 5 vs.log "$EVAL_DENIED" "$DENIALS" "the visa service denies zb's new visa request for Web (revocation)" || PASS=1
  plumbing_test "after the revocation" || PASS=1
fi

zode_report "$PASS"
