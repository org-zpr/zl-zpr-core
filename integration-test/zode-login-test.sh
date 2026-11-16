#!/usr/bin/env bash
#
# A Zode's own login (zl-zipline#233), docs/OIDC.md "A Zode's own login".
#
# The relay and the visa service run as in zode-link-test.sh, and zb joins
# through its initial link. The policy (pregen/zodes-login.zpl) lets zb's
# actor ping the visa service as a machine (the device flow) and ping the
# relay only with the logged-in user's OIDC subject (the user flow). A fake
# IdP runs in zpr-zb, for ph-cli's login, and in zpr-vs, for the visa
# service's JWKS. ph-cli runs with --no-browser, and curl in zpr-zb drives
# the authorization URL it prints, as in one-node-oidc-test.sh.
#
# Scenarios:
#   1. zb logged out: the user flow is denied, the device flow works.
#   2. `ph-cli connect`: exit 0, logged in, the user flow is admitted.
#   3. `ph-cli logout`: exit 0, the visa service's attribute sweep revokes
#      the user flow's visa and a new user flow is denied; the device flow
#      still works.
#   4. A resident `ph-cli auth-agent` logs in. A policy install while logged
#      in (gate g116 q3) is answered with a renewal: still logged in, the
#      user flow still admitted.
#   5. The login lives 60 s (expiration_seconds): the agent renews it
#      silently, and the user flow outlives the first expiry.
#   6. A visa-service restart replaces zb's VS-API session, which drops the
#      login (g116 q2 = prompt): the resident agent prints a new URL, curl
#      drives it, and the user flow is admitted again.
#
# Each check names the log line or ph-cli output it reads.
#
set -euo pipefail

# vss_rpc=DEBUG: zb logs the identity-provider list it gets over VSS.
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO vss_rpc=DEBUG}

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

ZODE_POLICY_BIN=zodes-login.bin2

enter_test_namespace "$@"

zode_begin

create_zode_network "zb:$ZB_SUBSTRATE_ADDR"
create_idp_cert
PASS=0
launch_zode_idp vs user-vs-unused || PASS=1
launch_zode_idp zb user-zb || PASS=1
launch_zode_vs
launch_relay
launch_vs_adapter || PASS=1

# What the logs say (zode_login.rs, vss_worker.rs, visa_table.rs) and what
# ph-cli prints (adapter/cli/src/main.rs, zode_login.rs format_status).
REGISTERED='registered VSS'
IDP_LIST='received services update with [1-9]'
LOGGED_IN="Zode login: logged in with $(ere_escape "$IDP_ISSUER")"
LOGGED_OUT='Zode login: logged out'
REVOKED='Revoked visa [0-9]+'
# The visa service's re-check after an attribute change (its visa sweep).
VS_SWEEP_REVOKED='visa sweep reason=AttributeChange .* revoked=[1-9]'
POLICY_RENEWAL='Zode login: policy re-authentication answered with a renewal'
RENEWED='Zode login: renewed; expires in'
EXPIRED='Zode login: expired without a renewal'
REPLACED="Zode login: the visa service replaced this node's VS-API session, which dropped the login"
ASK_AGENT='Zode login: asking the resident auth agent for a new login'
URL_LINE='Open this URL to continue: '

# Run ph-cli against zb, in zb's namespace, trusting the fake IdP.
function zb_cli() {
  in_ns zpr-zb env -u BROWSER SSL_CERT_FILE="$PWD/ca.crt" \
    "$PH_DEBUG_BIN" -p zb.sock "$@"
}

# Succeed when `ph-cli login-status` on zb has the line $1.
function zb_status_is() {
  zb_cli login-status 2> /dev/null | grep -qxF -- "$1"
}

# Wait up to $1 seconds for `ph-cli login-status` on zb to have the line
# $2; $3 is the assertion message.
function assert_status() {
  if wait_for "$1" zb_status_is "$2"; then
    echo "assertion OK: $3"
  else
    echo "ASSERTION FAILED: $3 (no line '$2' in login-status):"
    zb_cli login-status || true
    return 1
  fi
}

# Succeed when ph-cli output file $1 holds more than $2 authorization URLs.
function url_count_above() {
  (( $(grep -cF -- "$URL_LINE" "$1" || true) > $2 ))
}

# Wait for ph-cli output file $1 to print an authorization URL beyond the
# first $2, and drive it with curl in zpr-zb: the fake IdP redirects to
# ph-cli's loopback callback.
function drive_login_url() {
  local URL
  if ! wait_for 30 url_count_above "$1" "$2"; then
    echo "ASSERTION FAILED: ph-cli printed no new authorization URL:"
    cat "$1"
    return 1
  fi
  URL=$(sed -n "s/.*$URL_LINE//p" "$1" | tail -n 1)
  in_ns zpr-zb curl --silent --show-error --location --cacert ca.crt \
    --output /dev/null "$URL" || true
}

# zode_ping's warm-up for the user flow right after a login: the first
# echoes wait for the visa request that the login now lets through.
USER_FLOW_WARMUP=20

if [[ "$PASS" == 0 ]]; then
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  wait_log_after 60 zb.log "$REGISTERED" 0 "zb joins and registers its VSS" || PASS=1
  wait_log_after 30 zb.log "$IDP_LIST" 0 "zb has the identity-provider list" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  echo "== 1. zb logged out"
  assert_status 0 "State: logged out" "login-status: logged out" || PASS=1
  zode_ping zb "$VS_ZPR_ADDR" "the device flow (zb to the visa service) works" 10 || PASS=1
  zode_no_ping zb "$RELAY_ZPR_ADDR" "the user flow (zb to the relay) is denied" || PASS=1

  echo "== 2. ph-cli connect"
  zb_cli connect --no-browser > connect.out 2>&1 &
  CONNECT_PID=$!
  drive_login_url connect.out 0 || PASS=1
  if wait "$CONNECT_PID"; then
    echo "assertion OK: connect exits 0"
  else
    echo "ASSERTION FAILED: connect exited non-zero:"
    cat connect.out
    PASS=1
  fi
  wait_log_after 5 zb.log "$LOGGED_IN" 0 "zb logs the login" || PASS=1
  assert_status 0 "State: logged in" "login-status: logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is admitted" "$USER_FLOW_WARMUP" || PASS=1

  echo "== 3. ph-cli logout"
  REVOCATIONS=$(log_count zb.log "$REVOKED")
  SWEEPS=$(log_count vs.log "$VS_SWEEP_REVOKED")
  if zb_cli logout; then
    echo "assertion OK: logout exits 0"
  else
    echo "ASSERTION FAILED: logout exited non-zero"
    PASS=1
  fi
  wait_log_after 5 zb.log "$LOGGED_OUT" 0 "zb logs the logout" || PASS=1
  assert_status 0 "State: logged out" "login-status: logged out" || PASS=1
  wait_log_after 10 vs.log "$VS_SWEEP_REVOKED" "$SWEEPS" "the visa service re-checks zb's visas and revokes the user flow's" || PASS=1
  wait_log_after 10 zb.log "$REVOKED" "$REVOCATIONS" "zb drops the revoked visa" || PASS=1
  zode_no_ping zb "$RELAY_ZPR_ADDR" "a new user flow is denied" || PASS=1
  zode_ping zb "$VS_ZPR_ADDR" "the device flow still works: the machine stays connected" || PASS=1

  echo "== 4. resident auth-agent; a policy install while logged in"
  LOGINS=$(log_count zb.log "$LOGGED_IN")
  zb_cli auth-agent --no-browser > agent.out 2>&1 &
  drive_login_url agent.out 0 || PASS=1
  wait_log_after 15 zb.log "$LOGGED_IN" "$LOGINS" "the agent logs zb in" || PASS=1
  assert_status 0 "Auth agent: registered" "login-status: the agent is registered" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is admitted" "$USER_FLOW_WARMUP" || PASS=1
  POLICY_RENEWALS=$(log_count zb.log "$POLICY_RENEWAL")
  install_zode_policy "$ZODE_POLICY_BIN" || PASS=1
  wait_log_after 30 zb.log "$POLICY_RENEWAL" "$POLICY_RENEWALS" "zb answers the policy re-authentication with a renewal (q3)" || PASS=1
  assert_status 0 "State: logged in" "login-status: still logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is still admitted" || PASS=1

  echo "== 5. silent renewal"
  RENEWALS=$(log_count zb.log "$RENEWED")
  # Due at half the 60 s lifetime after the last renewal or login.
  wait_log_after 45 zb.log "$RENEWED" "$RENEWALS" "the agent renews the login silently" || PASS=1
  wait_log_after 45 zb.log "$RENEWED" "$((RENEWALS + 1))" "and renews it again" || PASS=1
  assert_no_log zb.log "$EXPIRED" "the login never expired" || PASS=1
  if url_count_above agent.out 1; then
    echo "ASSERTION FAILED: a renewal asked the user to log in again"
    PASS=1
  else
    echo "assertion OK: no renewal asked the user (one authorization URL)"
  fi
  assert_status 0 "State: logged in" "login-status: still logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow outlives the first expiry" || PASS=1

  echo "== 6. a visa-service restart"
  LOGINS=$(log_count zb.log "$LOGGED_IN")
  restart_zode_vs || PASS=1
  wait_log_after 60 zb.log "$REPLACED" 0 "zb's new VS-API session dropped the login" || PASS=1
  wait_log_after 5 zb.log "$ASK_AGENT" 0 "zb asks the resident agent for a new login (q2)" || PASS=1
  drive_login_url agent.out 1 || PASS=1
  wait_log_after 15 zb.log "$LOGGED_IN" "$LOGINS" "zb is logged in again" || PASS=1
  assert_status 0 "State: logged in" "login-status: logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is admitted again" "$USER_FLOW_WARMUP" || PASS=1
fi

zode_report "$PASS"
