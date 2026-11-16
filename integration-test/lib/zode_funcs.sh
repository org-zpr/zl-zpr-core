#!/usr/bin/env bash

#
# Shared set-up for the Zode netns tests (zl-zipline#250, #254).
# Source it after lib/common_funcs.sh. The layout matches pregen/zodes.zplc
# and pregen/zodes-pair.zplc:
#
#   zpr-relay ---- br0 ---- zpr-zb
#   (relay Zode       \--- zpr-zc
#    + visa service)
#
# The relay hosts the visa service in its own namespace, on its own TUN
# (zl-zipline#229): the relay's `ph node` puts both its own ZPR address and
# vs.zpr on tun0, so vs.zpr is a local actor of the relay, and the visa
# service runs next to it. There is no `ph adapter` for the visa service.
# The relay's VS-API session to vs.zpr, and the visa service's VSS session
# to the relay, stay in the host (over lo). The other Zodes sit on one
# substrate segment (a bridge
# in the relay's namespace) and dial the relay through their configured
# initial link. A Zode in the relay's topology joins through it
# (zl-zipline#252): the relay hands it bootstrap visas for its own
# visa-service session.
#
# Each Zode is a `ph node` with its own certificate (CN = its policy node
# name), signed by the test CA unless a test says otherwise.
#

export RUST_BACKTRACE=1
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO}
KM_IMPL=${KM_IMPL:-noise}

PH_BIN="${PH_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph")}"
PH_DEBUG_BIN="${PH_DEBUG_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph-cli")}"
VS_BIN="${VS_BIN:-$(realpath "$(dirname "$0")/vs")}"
VS_ADMIN_BIN="${VS_ADMIN_BIN:-$(realpath "$(dirname "$0")/vs-admin")}"
VALKEY_SERVER_BIN="${VALKEY_SERVER_BIN:-$(realpath -s "$(dirname "$0")/valkey-server")}"
PREGEN=$(realpath "$(dirname "$0")/pregen")

ZODE_PORT=5000

VS_ZPR_ADDR=fd5a:5052::1
RELAY_ZPR_ADDR=fd5a:5052::2
ZB_ZPR_ADDR=fd5a:5052::3
ZC_ZPR_ADDR=fd5a:5052::4
ADMIN_URL="https://[$VS_ZPR_ADDR]:8182"

RELAY_SUBSTRATE_ADDR=10.2.0.1
ZB_SUBSTRATE_ADDR=10.2.0.2
ZC_SUBSTRATE_ADDR=10.2.0.3

# The policy the visa service starts with. A script may set it after
# sourcing this file.
ZODE_POLICY_BIN=zodes.bin2

# What ph logs when it refuses a Stream ID Request that does not come from
# the visa's previous hop (gap 7, zl-zipline#253; mgmt/node.rs
# prepare_next_hop_bind), and the counter of every refused request.
PREV_HOP_REFUSED="refusing Stream ID Request from .*: not the visa's previous hop"
REJECTED='Stream ID Request Rejected'

# The bulk transfer of the demo test (zl-zipline#231): BULK_COUNT echo
# requests of BULK_SIZE payload bytes, BULK_INTERVAL seconds apart (about
# 2 MB each way in about 10 s). BULK_PAYLOAD is what one direction carries,
# the yardstick for the relay's received-byte counter.
BULK_COUNT=2000
BULK_SIZE=1000
BULK_INTERVAL=0.005
BULK_PAYLOAD=$((BULK_COUNT * BULK_SIZE))

# Check that every binary and fixture the Zode tests use is present.
function zode_preflight() {
  local F
  for F in "$VS_BIN" "$VS_ADMIN_BIN" "$VALKEY_SERVER_BIN" "$PREGEN/$ZODE_POLICY_BIN"
  do
    if [ ! -e "$F" ]; then
      echo "required file not found: $F"
      exit 1
    fi
  done
  for F in "$PH_BIN" "$PH_DEBUG_BIN"
  do
    if [ ! -x "$F" ]; then
      echo "required binary not found or not executable: $F"
      exit 1
    fi
  done
}

# Common start of every Zode test, called right after enter_test_namespace:
# check prerequisites, move into a fresh working directory that the EXIT
# trap removes, and make the test CA.
function zode_begin() {
  zode_preflight
  trap zode_cleanup EXIT
  TMPDIR=$(mktemp -d)
  pushd "$TMPDIR" > /dev/null
  create_ca_key_and_cert ca
}

# The EXIT trap: print every log under the working directory when
# ZPR_TEST_VERBOSE is set, including those of a test's legs in
# subdirectories, then common_funcs' cleanup (which stops everything and
# removes the directory). cleanup prints the top-level valkey.log and
# vs.log itself, so they are left to it.
function zode_cleanup() {
  if [ "${ZPR_TEST_VERBOSE:-no}" != "no" ]; then
    local LOG
    while read -r LOG
    do
      case "$LOG" in
        valkey.log | vs.log) ;;
        *) emitlog "$LOG" ;;
      esac
    done < <(cd "$TMPDIR" && find . -name '*.log' -printf '%P\n' | sort)
  fi
  cleanup
}

# Stop every process the test started and remove its namespaces, so a test
# can run its next leg from a clean start. The same first steps as
# common_funcs' cleanup, which the EXIT trap still runs at the end.
function zode_stop_all() {
  local PID
  for PID in $(get_descendants) $(jobs -p)
  do
    kill -9 "$PID" 2> /dev/null || true
  done
  wait -f
  destroy_network
}

# Make a second CA, unrelated to the test CA, as $1.key and $1.crt in the
# working directory. A certificate it signs fails verification against the
# test CA (create_ca_key_and_cert copies the test CA from pregen instead).
function create_other_ca() {
  "$ZPR_PKI_BIN" gencakey > "$1.key"
  "$ZPR_PKI_BIN" gencacert /CN="$1" 1 < "$1.key" > "$1.crt"
}

# Build the namespaces in the diagram above. Arguments are NAME:ADDR pairs,
# one per Zode on the bridge (e.g. zb:10.2.0.2); each gets namespace
# zpr-NAME with ADDR/24 on its veth0.
#
# No TUN gets an address here: each `ph node` applies its own ZPR
# addresses, the relay's vs.zpr included (Assembly::
# ensure_local_zpr_addrs_on_tun), which this layout tests.
function create_zode_network() {
  local PAIR NAME ADDR NS

  new_netns zpr-relay

  # The Zodes' shared segment.
  in_ns zpr-relay ip link add br0 type bridge
  in_ns zpr-relay ip addr add "$RELAY_SUBSTRATE_ADDR/24" dev br0
  in_ns zpr-relay ip link set br0 up

  for PAIR in "$@"
  do
    NAME=${PAIR%%:*}
    ADDR=${PAIR#*:}
    NS=zpr-$NAME
    new_netns "$NS"
    connect_ns "$NS" veth0 zpr-relay "veth-$NAME"
    in_ns zpr-relay ip link set "veth-$NAME" master br0
    in_ns zpr-relay ip link set "veth-$NAME" up
    in_ns "$NS" ip addr add "$ADDR/24" dev veth0
    in_ns "$NS" ip link set veth0 up
  done

  for NS in "${!NETNS_PID[@]}"
  do
    in_ns "$NS" ip link set lo up
    in_ns "$NS" ip tuntap add name tun0 mode tun multi_queue
    in_ns "$NS" ip link set tun0 up
  done
}

# Write the visa service's config, certificate and admin API key, start
# valkey and the visa service with the Zode policy in the relay's
# namespace, and wait until the relay has registered with the visa service.
# Run from the test's working directory, after launch_relay: the visa
# service binds its listeners to vs.zpr, which must already be on the
# relay's TUN. Returns non-zero if the relay does not register.
function launch_zode_vs() {
  # The visa service still serves TLS on VS-API and admin with this
  # certificate.
  create_actor_key_and_cert ca vs.zpr
  emit_vs_config ca vs.zpr > vs-config.toml
  write_vs_admin_key

  in_ns zpr-relay "$VALKEY_SERVER_BIN" \
    --save "" \
    --appendonly no 2>&1 | tee valkey.log | prefix_log valkey &
  # check_vs_valkey_port, in the relay's namespace.
  wait_for 15 in_ns zpr-relay bash -c 'exec 3<>/dev/tcp/127.0.0.1/6379'

  start_vs --clear-state

  wait_for 30 check_registered relay.log || {
    echo "the relay did not register with the visa service"
    return 1
  }
}

# Start the visa service with the Zode policy in the relay's namespace,
# appending to vs.log; extra arguments go to vs (launch_zode_vs passes
# --clear-state, a restart keeps the state in valkey). SSL_CERT_FILE lets it
# fetch an OIDC trusted service's JWKS from a fake IdP whose certificate the
# test CA signed.
function start_vs() {
  in_ns zpr-relay env XDG_DATA_HOME=/tmp SSL_CERT_FILE="$PWD/ca.crt" "$VS_BIN" \
    -c vs-config.toml \
    "$@" \
    "$PREGEN/$ZODE_POLICY_BIN" 2>&1 | tee -a vs.log | prefix_log vs &
  sleep 2
}

# The PID of this run's visa service. Anchored on $VS_BIN, as
# ph_pid_for_socket is on $PH_BIN: env execs it.
function vs_pid() {
  pgrep_own -f "^$(ere_escape "$VS_BIN") -c vs-config.toml" | head -n 1
}

# Restart the visa service, keeping its state: kill it at once, wait for it
# to be gone, and start it again. Every node's VS-API session breaks and
# reconnects with a new authentication.
function restart_zode_vs() {
  local PID
  PID=$(vs_pid)
  if [ -z "$PID" ]; then
    echo "no running visa service"
    return 1
  fi
  kill -9 "$PID"
  wait_for 10 process_exited "$PID"
  start_vs
}

# The fake IdP the OIDC Zode tests use (lib/fake-idp.py). Every consumer
# dials the policy's issuer on its own loopback, so one instance runs in
# each namespace that needs it; they share the signing keys, the TLS
# certificate and one state directory, as in one-node-oidc-test.sh.
IDP_PORT=9000
IDP_ISSUER="https://127.0.0.1:$IDP_PORT"
FAKE_IDP=$(realpath "$(dirname "$0")/lib/fake-idp.py")

# Make the fake IdP's TLS certificate for 127.0.0.1, signed by the test CA,
# and its state directory. Run after create_ca_key_and_cert.
function create_idp_cert() {
  mkdir -p idp-state
  openssl req -new -newkey rsa:2048 -nodes -keyout idp.key \
    -subj "/CN=127.0.0.1" -out idp.csr 2> /dev/null
  openssl x509 -req -in idp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -out idp.crt \
    -extfile <(printf "subjectAltName=IP:127.0.0.1") 2> /dev/null
}

# Start a fake IdP in namespace zpr-$1 that mints tokens for subject $2,
# and wait until it answers discovery. Returns non-zero if it does not.
function launch_zode_idp() {
  in_ns "zpr-$1" python3 "$FAKE_IDP" \
    --port "$IDP_PORT" \
    --state-dir idp-state \
    --tls-cert idp.crt --tls-key idp.key \
    --signing-key "$PREGEN/fake-idp-rsa.key" \
    --client-id zpr-test-client \
    --sub "$2" --email "$2@example.com" --hd example.com \
    2>&1 | tee "idp-$1.log" | prefix_log "idp-$1" &
  wait_for 15 in_ns "zpr-$1" curl --silent --cacert ca.crt \
    --output /dev/null "$IDP_ISSUER/.well-known/openid-configuration"
}

# Mint an admin API key the way vsapikey does (vs/src/apikey.rs), as
# one-node-policy-reauth-test.sh does: the visa service reads vs_keys.toml
# from its config directory, and vs-admin reads vs-admin.key.
function write_vs_admin_key() {
  python3 - <<'PYEOF'
import base64, hashlib, secrets

key_id = secrets.token_bytes(4).hex()
secret = secrets.token_bytes(32)
b64 = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
with open("vs_keys.toml", "w") as f:
    f.write(f'[keys.{key_id}]\n')
    f.write('owner = "integration-test"\n')
    f.write('permission = "readwrite"\n')
    f.write('status = "active"\n')
    f.write('created = "2026-11-12"\n')
    f.write(f'secret_hash = "{hashlib.sha256(secret).hexdigest()}"\n')
    f.write('description = "zode tests"\n')
with open("vs-admin.key", "w") as f:
    f.write(f"zpr_vsapi.{key_id}.{b64}\n")
PYEOF
  chmod 600 vs-admin.key
}

# Hot-install the compiled policy $1 (a file name in pregen) with vs-admin,
# from inside the relay's netns. Fails if the visa service rejects it.
function install_zode_policy() {
  echo "Installing policy: $1"
  in_ns zpr-relay \
    "$VS_ADMIN_BIN" --svc-url "$ADMIN_URL" --ca-cert ca.crt \
    --api-key-file vs-admin.key --format compact install "$PREGEN/$1"
}

# Start the relay Zode (`relay = true`, ZODE_LINKS.md rule 4) with its own
# ZPR address first and vs.zpr after it (zl-zipline#229), and wait until
# vs.zpr is on its TUN. $1 is its `forwarding` setting, `true` (the
# default) or `false`: a relay that does not forward refuses forward-only
# visas (visa_mgmt.rs insert_visa). Returns non-zero if vs.zpr never
# appears.
function launch_relay() {
  local FORWARDING=${1:-true}
  create_actor_key_and_cert ca relay

  in_ns zpr-relay "$PH_BIN" \
    node \
    --logging "$DEBUG_TARGETS" \
    --control-path relay.sock \
    --advertised-substrate-addr "$RELAY_SUBSTRATE_ADDR:$ZODE_PORT" \
    --ca-file ca.crt \
    --certificate-file relay.crt \
    --private-key-file relay.key \
    --auth-private-key "$PREGEN/node-rsa-key.pem" \
    --km-impl "$KM_IMPL" \
    --relay true \
    --forwarding "$FORWARDING" \
    --tun-if tun0 \
    --zpr-addr "$RELAY_ZPR_ADDR" \
    --zpr-addr "$VS_ZPR_ADDR" 2>&1 | tee relay.log | prefix_log relay &

  wait_for 15 relay_has_vs_addr || {
    echo "the relay did not put $VS_ZPR_ADDR on its TUN"
    return 1
  }
}

# True once vs.zpr is on the relay's tun0.
function relay_has_vs_addr() {
  in_ns zpr-relay ip -6 addr show dev tun0 | grep -q "inet6 $VS_ZPR_ADDR/"
}

# Section 7 check 1 (zl-zipline#229): the relay's traffic to vs.zpr stays
# in the host. vs.zpr is a local address of the relay, so the kernel routes
# it over lo, never through the TUN and `ph`.
function assert_vs_route_local() {
  local ROUTE
  ROUTE=$(in_ns zpr-relay ip -6 route get "$VS_ZPR_ADDR")
  if [[ "$ROUTE" == *" dev lo "* ]]; then
    echo "assertion OK: the relay routes $VS_ZPR_ADDR over lo"
  else
    echo "ASSERTION FAILED: the relay routes $VS_ZPR_ADDR as '$ROUTE', not over lo"
    return 1
  fi
}

# Assert that the relay's namespace has an established TCP connection from
# address $1 to [$2]:$3 ($4 is the assertion message). This checks the
# source address the client bound, which `ss` shows as the local address.
function assert_relay_conn() {
  local CONNS
  CONNS=$(in_ns zpr-relay ss -Htn state established)
  if grep -qE "\[$(ere_escape "$1")\]:[0-9]+ +\[$(ere_escape "$2")\]:$3( |\$)" <<< "$CONNS"; then
    echo "assertion OK: $4"
  else
    echo "ASSERTION FAILED: $4 (no connection from [$1] to [$2]:$3)"
    echo "$CONNS"
    return 1
  fi
}

# Start Zode NAME in namespace zpr-NAME with an initial link to the relay.
# $1 = name (its certificate CN), $2 = substrate address, $3 = ZPR address,
# $4 = its RSA authentication key, $5 = the CA that signs its certificate
# (default `ca`, the test CA). Its own --ca-file is always the test CA, so
# with another signing CA the Zode still accepts the relay, and it is the
# relay that must refuse the Zode. Its key and certificate are made on the
# first launch and reused on a restart. The log is appended to, so a
# restart keeps the earlier lines.
function launch_zode() {
  local NAME=$1 SUBSTRATE=$2 ZPR_ADDR=$3 AUTH_KEY=$4 SIGNING_CA=${5:-ca}
  [ -e "$NAME.crt" ] || create_actor_key_and_cert "$SIGNING_CA" "$NAME"

  in_ns "zpr-$NAME" "$PH_BIN" \
    node \
    --logging "$DEBUG_TARGETS" \
    --control-path "$NAME.sock" \
    --self-addr "$SUBSTRATE:$ZODE_PORT" \
    --initial-link "relay@$RELAY_SUBSTRATE_ADDR:$ZODE_PORT" \
    --ca-file ca.crt \
    --certificate-file "$NAME.crt" \
    --private-key-file "$NAME.key" \
    --auth-private-key "$AUTH_KEY" \
    --km-impl "$KM_IMPL" \
    --tun-if tun0 \
    --zpr-addr "$ZPR_ADDR" 2>&1 | tee -a "$NAME.log" | prefix_log "$NAME" &
}

# Kill Zode NAME ($1) at once, as a crash or force-quit would, and wait for
# it to be gone.
function kill_zode() {
  local PID
  PID=$(ph_pid_for_socket "$1.sock")
  if [ -z "$PID" ]; then
    echo "no running Zode $1"
    return 1
  fi
  kill -9 "$PID"
  wait_for 10 process_exited "$PID"
  rm -f "$1.sock"
}

# True once the Zode logging to $1 has registered with the visa service.
function check_registered() {
  grep -q "registered VSS" "$1"
}

# The number of Active links Zode NAME ($1) has to substrate address $2,
# from `ph-cli link show`. Prints "query-failed" and fails when ph-cli does,
# so a dead control socket never reads as zero links.
function active_links_to() {
  local OUT
  if ! OUT=$("$PH_DEBUG_BIN" -p "$1.sock" link show 2> /dev/null); then
    echo "query-failed"
    return 1
  fi
  grep -cE "^ *[0-9]+: $(ere_escape "$2"):[0-9]+ \(Active\)" <<< "$OUT" || true
}

# Succeed when Zode $1 has exactly $3 Active links to substrate address $2.
function has_active_links() {
  [[ "$(active_links_to "$1" "$2")" == "$3" ]]
}

# Wait up to $1 seconds for Zode $2 to have exactly $4 Active links to
# substrate address $3; $5 is the assertion message.
function assert_active_links() {
  if wait_for "$1" has_active_links "$2" "$3" "$4"; then
    echo "assertion OK: $5"
  else
    echo "ASSERTION FAILED: $5 (expected $4 Active links from $2 to $3, got $(active_links_to "$2" "$3"))"
    "$PH_DEBUG_BIN" -p "$2.sock" link show || true
    return 1
  fi
}

# Succeed when log $1 matches the extended regex $2 more than $3 times.
function log_count_above() {
  local N
  N=$(grep -cE -- "$2" "$1" || true)
  (( N > $3 ))
}

# Wait up to $1 seconds for log $2 to match the extended regex $3 more than
# $4 times (pass the count from before the step); $5 is the message.
function wait_log_after() {
  if wait_for "$1" log_count_above "$2" "$3" "$4"; then
    echo "assertion OK: $5"
  else
    echo "ASSERTION FAILED: $5 (no new match for '$3' in $2)"
    return 1
  fi
}

# The number of lines of log $1 matching the extended regex $2.
function log_count() {
  grep -cE -- "$2" "$1" || true
}

# Assert that log $1 matches the extended regex $2 exactly $3 times (pass
# the count from before the step plus what the step must add); $4 is the
# message.
function assert_log_count() {
  local N
  N=$(log_count "$1" "$2")
  if (( N == $3 )); then
    echo "assertion OK: $4"
  else
    echo "ASSERTION FAILED: $4 (expected $3 matches for '$2' in $1, got $N)"
    return 1
  fi
}

# Assert that log $1 does not match the extended regex $2 ($3 = message).
function assert_no_log() {
  if grep -qE -- "$2" "$1"; then
    echo "ASSERTION FAILED: $3 (unexpected match for '$2' in $1):"
    grep -E -- "$2" "$1" | head -n 5
    return 1
  fi
  echo "assertion OK: $3"
}

# The visa IDs of the relay's last hand-off to Zode $2, as "FORWARD REVERSE",
# from the relay's log $1 (bootstrap_handoff.rs: `handed bootstrap visas
# [A, B] to "CN"`). Prints nothing if there was none.
function last_handoff_ids() {
  grep -oE "handed bootstrap visas \[[0-9, ]+\] to \"$2\"" "$1" | tail -n 1 \
    | grep -oE '\[[0-9, ]+\]' | tr -d '[],' || true
}

# Succeed when $1 is exactly two different visa IDs, both from the visa
# service: at least MIN_VISA_ID (config.rs), so never ph's self-granted
# VS-API pair, IDs 1 and 2. $2 is the assertion message.
function assert_issued_ids() {
  local IDS
  read -r -a IDS <<< "$1"
  if (( ${#IDS[@]} == 2 )) && (( IDS[0] >= 1000 && IDS[1] >= 1000 )) \
    && (( IDS[0] != IDS[1] )); then
    echo "assertion OK: $2 ($1)"
  else
    echo "ASSERTION FAILED: $2 (got '$1')"
    return 1
  fi
}

# Succeed when the hand-off $1 holds two visa-service IDs ([assert_issued_ids])
# that share none with the other hand-off $2: every join gets new visas
# (J6), and no joiner gets another's. $3 names the hand-off in the message.
function assert_new_ids() {
  assert_issued_ids "$1" "$3 holds two visa-service IDs" || return 1
  local ID
  for ID in $1
  do
    if [[ " $2 " == *" $ID "* ]]; then
      echo "ASSERTION FAILED: $3 reuses visa $ID of the other hand-off ($2)"
      return 1
    fi
  done
  echo "assertion OK: $3 shares no ID with the other hand-off ($1; other $2)"
}

# Check the joiner's visa table as it starts (J1, J4), from its log $1:
# every visa inserted into its table (visa_table.rs logs each insert) up to
# the first installed hand-off is exactly the hand-off $2, and the log never
# shows ph's self-granted VS-API pair, IDs 1 and 2.
function assert_joiner_table() {
  local INSERTED
  INSERTED=$(sed -nE '/installed bootstrap visas/q; s/.*Visa inserted into VisaTable ID: ([0-9]+),.*/\1/p' "$1" \
    | sort -n | tr '\n' ' ')
  if [[ "$INSERTED" == "$(tr ' ' '\n' <<< "$2" | sort -n | tr '\n' ' ')" ]]; then
    echo "assertion OK: the joiner's table holds only its bootstrap visas ($2)"
  else
    echo "ASSERTION FAILED: the joiner's table holds [$INSERTED], not only its bootstrap visas ($2)"
    return 1
  fi
  assert_no_log "$1" 'Visa inserted into VisaTable ID: [12],' "the joiner never grants itself VS-API visas 1 and 2"
}

# J11 after a join of Zode $2 with the hand-off $3 ("FORWARD REVERSE"): wait
# up to $1 seconds for the Zode's own VS-API visa (J5a) to supersede the
# forward bootstrap visa and for its VS-API stream to be rebound onto it.
# Then check that no rebind failed on that Zode, in its log and its
# `Rebind Failed` counter. With the stream off the bootstrap visa, its
# expiry (5 minutes) does not break the session, so there is no J10 rejoin.
function assert_superseded() {
  local FORWARD=${3%% *}
  wait_log_after "$1" "$2.log" "visa [0-9]+ supersedes visa ${FORWARD}([^0-9]|\$)" 0 \
    "$2's own VS-API visa supersedes bootstrap visa $FORWARD (J5a)" || return 1
  wait_log_after "$1" "$2.log" "rebound a stream from visa $FORWARD onto visa [0-9]+" 0 \
    "$2's VS-API stream moves off bootstrap visa $FORWARD (J11)" || return 1
  assert_no_log "$2.log" 'its rebind onto visa [0-9]+ failed' "no rebind failed on $2" || return 1
  assert_counter_zero "$2" "Rebind Failed"
}

# Succeed when Zode $1's management counter $2 (as `ph-cli counters` names
# it) is zero.
function assert_counter_zero() {
  local VALUE
  VALUE=$("$PH_DEBUG_BIN" -p "$1.sock" counters | sed -nE "s/^$2: ([0-9]+)\$/\\1/p")
  if [[ "$VALUE" == 0 ]]; then
    echo "assertion OK: $1's '$2' counter is 0"
  else
    echo "ASSERTION FAILED: $1's '$2' counter is '$VALUE', not 0"
    return 1
  fi
}

# Assert that no Zode named in the arguments refused a Stream ID Request
# as not from the visa's previous hop (gap 7), in its log, and that its
# `Stream ID Request Rejected` counter, which counts every refusal for any
# reason, is zero. Checks every Zode before failing.
function assert_no_refusals() {
  local ZODE RESULT=0
  for ZODE in "$@"
  do
    assert_no_log "$ZODE.log" "$PREV_HOP_REFUSED" "$ZODE refused no request from a previous hop" || RESULT=1
    assert_counter_zero "$ZODE" "$REJECTED" || RESULT=1
  done
  return "$RESULT"
}

# Ping $2 from Zode $1's namespace, from its own ZPR address, and assert
# that it answers ($3 is the assertion message). The first echo makes the
# Zode request a visa, so up to $4 (default 3) one-second warm-up echoes
# may go unanswered before the five that must all be answered.
function zode_ping() {
  wait_for "${4:-3}" in_ns "zpr-$1" ping -q -n -c 1 -W 1 "$2" > /dev/null 2>&1 || true
  if in_ns "zpr-$1" ping -q -n -c 5 -w 10 "$2" > /dev/null; then
    echo "assertion OK: $3"
  else
    echo "ASSERTION FAILED: $3 ($1 did not get all five echo replies from $2)"
    return 1
  fi
}

# Ping $2 from Zode $1's namespace and assert that none of five echoes is
# answered ($3 is the assertion message). ping's exit status cannot tell
# "no reply" from "some replies", so this reads the received count from its
# summary; no summary (ping itself failed) fails the assertion too.
function zode_no_ping() {
  local OUT RECEIVED
  OUT=$(in_ns "zpr-$1" ping -q -n -c 5 -W 1 "$2" 2>&1 || true)
  RECEIVED=$(sed -nE 's/.*, ([0-9]+) received.*/\1/p' <<< "$OUT")
  if [[ "$RECEIVED" == 0 ]]; then
    echo "assertion OK: $3"
  else
    echo "ASSERTION FAILED: $3 ($1 pinging $2: $(tail -n 2 <<< "$OUT" | head -n 1))"
    return 1
  fi
}

# Drop the substrate traffic between Zodes $1 and $2 only (names with a
# <NAME>_SUBSTRATE_ADDR above, e.g. zb), in both directions: each one's
# veth0 drops what it sends to the other's substrate address. Both still
# reach the relay over the same bridge.
function block_pair() {
  local FROM TO TO_ADDR
  for FROM in "$1" "$2"
  do
    TO=$1
    [[ "$FROM" == "$1" ]] && TO=$2
    TO_ADDR=${TO^^}_SUBSTRATE_ADDR
    in_ns "zpr-$FROM" tc qdisc add dev veth0 root handle 1: prio
    in_ns "zpr-$FROM" tc filter add dev veth0 parent 1: protocol ip u32 \
      match ip dst "${!TO_ADDR}/32" action drop
  done
}

# Undo block_pair $1 $2: remove the filter from both Zodes' veth0.
function unblock_pair() {
  in_ns "zpr-$1" tc qdisc del dev veth0 root
  in_ns "zpr-$2" tc qdisc del dev veth0 root
}

# Print the bytes the relay has received on its substrate: the RX byte
# counter of br0 in the relay's namespace (zl-zipline#231; the netns
# counterpart of the dashboard's relay container rx). br0 counts only the
# frames the bridge passes up to the relay's own stack (addressed to the
# relay, or broadcast and multicast), not those it bridges from one Zode's
# port to another's. So zb-zc traffic over their direct link, which crosses
# the bridge, is not counted, while the same traffic through the relay is.
# The veth-NAME port counters would count both. Never make br0 promiscuous
# (tcpdump on it, say): the bridge then passes every frame up and counts it.
# Read over netlink (`ip -s link`), which honours the namespace.
function relay_rx_bytes() {
  local BYTES
  BYTES=$(in_ns zpr-relay ip -s link show dev br0 | awk 'f { print $1; exit } /RX:/ { f = 1 }')
  if [[ ! "$BYTES" =~ ^[0-9]+$ ]]; then
    echo "cannot read br0's RX bytes in zpr-relay (got '$BYTES')" >&2
    return 1
  fi
  echo "$BYTES"
}

# Send the bulk transfer from Zode $1 to ZPR address $2: BULK_COUNT echo
# requests of BULK_SIZE bytes, BULK_INTERVAL seconds apart, with a 60 s
# deadline. Fails unless at least 95% are answered, or if any reply's
# payload differs from what was sent ($3 is the assertion message). ping
# compares the payload only without -q, and reports a difference as "wrong
# data byte", so it runs without -q and only its summary is printed. Ping
# first with zode_ping, so the flow's visa is in place and the transfer
# does not wait on it.
function bulk_ping() {
  local OUT RECEIVED
  OUT=$(in_ns "zpr-$1" ping -n -c "$BULK_COUNT" -s "$BULK_SIZE" -i "$BULK_INTERVAL" -w 60 "$2" 2>&1 || true)
  RECEIVED=$(sed -nE 's/.*, ([0-9]+) received.*/\1/p' <<< "$OUT")
  if grep -q 'wrong data byte' <<< "$OUT"; then
    echo "ASSERTION FAILED: $3 ($1 pinging $2: a reply's payload differs from the request's)"
    return 1
  fi
  if [[ -n "$RECEIVED" ]] && (( RECEIVED * 100 >= BULK_COUNT * 95 )); then
    echo "assertion OK: $3 ($RECEIVED of $BULK_COUNT answered)"
  else
    echo "ASSERTION FAILED: $3 ($1 pinging $2: $(tail -n 2 <<< "$OUT" | head -n 1))"
    return 1
  fi
}

# Assert that the relay received less than a tenth of BULK_PAYLOAD since
# its br0 RX byte count was $1 (from relay_rx_bytes before a bulk_ping):
# the transfer did not cross the relay ($2 is the assertion message). Keep-
# alives, VS-API traffic and neighbour discovery stay far below the bound.
function assert_relay_rx_flat() {
  local NOW DELTA
  NOW=$(relay_rx_bytes) || return 1
  DELTA=$((NOW - $1))
  if (( DELTA < BULK_PAYLOAD / 10 )); then
    echo "assertion OK: $2 (relay received $DELTA bytes, bound $((BULK_PAYLOAD / 10)))"
  else
    echo "ASSERTION FAILED: $2 (relay received $DELTA bytes, bound $((BULK_PAYLOAD / 10)))"
    return 1
  fi
}

# Assert that the relay received at least BULK_PAYLOAD since its br0 RX
# byte count was $1: the transfer crossed the relay, whose substrate
# receives every echo request from one end and every reply from the other
# ($2 is the assertion message).
function assert_relay_rx_rose() {
  local NOW DELTA
  NOW=$(relay_rx_bytes) || return 1
  DELTA=$((NOW - $1))
  if (( DELTA >= BULK_PAYLOAD )); then
    echo "assertion OK: $2 (relay received $DELTA bytes, at least $BULK_PAYLOAD)"
  else
    echo "ASSERTION FAILED: $2 (relay received $DELTA bytes, fewer than $BULK_PAYLOAD)"
    return 1
  fi
}

# Drop all substrate traffic of Zode NAME ($1), both ways, or restore it.
function block_substrate() {
  in_ns "zpr-$1" tc qdisc add dev veth0 root netem loss 100%
  in_ns zpr-relay tc qdisc add dev "veth-$1" root netem loss 100%
}
function unblock_substrate() {
  in_ns "zpr-$1" tc qdisc del dev veth0 root
  in_ns zpr-relay tc qdisc del dev "veth-$1" root
}

# Cut the relay off from its visa service: stop the visa service's process
# (SIGSTOP), so its sockets stay open but nothing answers. With the visa
# service in the relay's namespace there is no substrate link to block.
function stop_vs() {
  kill -STOP "$(vs_pid)"
}

# Let the visa service that stop_vs stopped run again (SIGCONT).
function cont_vs() {
  kill -CONT "$(vs_pid)"
}

# Print the verdict for $1 (0 = pass) and exit with it.
function zode_report() {
  echo
  if [[ "$1" == 0 ]]
  then echo "SUCCESS"
  else echo "FAILURE"
  fi
  exit "$1"
}
