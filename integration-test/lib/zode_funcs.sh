#!/usr/bin/env bash

#
# Shared set-up for the Zode netns tests (zl-zipline#250; #254 adds more).
# Source it after lib/common_funcs.sh. The layout matches
# pregen/zodes.zplc:
#
#   zpr-vs ---- zpr-relay ---- br0 ---- zpr-zb
#   (visa        (relay Zode,       \--- zpr-zc
#    service)     docks the VS)
#
# The visa service runs as an adapter docked on the relay, as in
# one-node-test.sh. The other Zodes sit on one substrate segment (a bridge
# in the relay's namespace) and dial the relay through their configured
# initial link. Before zl-zipline#252 only the relay has a visa-service
# session: zb and zc link to the relay but cannot reach the visa service.
#
# Each Zode is a `ph node` with its own certificate (CN = its policy node
# name), signed by the test CA.
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
# The whole ZPRnet, routed through the visa service's TUN.
ZPR_SUBNET=fd5a:5052::/32
ADMIN_URL="https://[$VS_ZPR_ADDR]:8182"

RELAY_SUBSTRATE_ADDR_VS=10.0.0.1
VS_SUBSTRATE_ADDR=10.0.0.2
RELAY_SUBSTRATE_ADDR=10.2.0.1
ZB_SUBSTRATE_ADDR=10.2.0.2
ZC_SUBSTRATE_ADDR=10.2.0.3

ZODE_POLICY_BIN=zodes.bin2

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

# The EXIT trap: print the Zode logs when ZPR_TEST_VERBOSE is set, then
# common_funcs' cleanup (which stops everything and removes the directory).
function zode_cleanup() {
  if [ "${ZPR_TEST_VERBOSE:-no}" != "no" ]; then
    local LOG
    for LOG in relay.log zb.log zc.log
    do
      emitlog "$LOG"
    done
  fi
  cleanup
}

# Build the namespaces in the diagram above. Arguments are NAME:ADDR pairs,
# one per Zode on the bridge (e.g. zb:10.2.0.2); each gets namespace
# zpr-NAME with ADDR/24 on its veth0.
#
# A Zode's TUN gets no address here: `ph node` applies its own ZPR address.
# The visa service's adapter TUN is addressed here, as in create_network.
function create_zode_network() {
  local PAIR NAME ADDR NS

  new_netns zpr-vs
  new_netns zpr-relay

  # The visa service docks on the relay over its own veth pair.
  connect_ns zpr-vs veth0 zpr-relay veth-vs
  in_ns zpr-vs ip addr add "$VS_SUBSTRATE_ADDR/24" dev veth0
  in_ns zpr-relay ip addr add "$RELAY_SUBSTRATE_ADDR_VS/24" dev veth-vs
  in_ns zpr-vs ip link set veth0 up
  in_ns zpr-relay ip link set veth-vs up

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

  # After the link is up: see the kernel note in create_network.
  in_ns zpr-vs ip addr add "$VS_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
}

# Write the visa service's config, certificate and admin API key, then start
# valkey and the visa service with the Zode policy. Run from the test's
# working directory, after create_ca_key_and_cert.
function launch_zode_vs() {
  create_actor_key_and_cert ca vs.zpr
  cp "$PREGEN/actorvs-rsa.key" actorvs-rsa.key
  emit_vs_config ca vs.zpr > vs-config.toml
  write_vs_admin_key

  in_ns zpr-vs "$VALKEY_SERVER_BIN" \
    --save "" \
    --appendonly no 2>&1 | tee valkey.log | prefix_log valkey &
  wait_for 15 check_vs_valkey_port

  in_ns zpr-vs env XDG_DATA_HOME=/tmp "$VS_BIN" \
    -c vs-config.toml \
    --clear-state \
    "$PREGEN/$ZODE_POLICY_BIN" 2>&1 | tee vs.log | prefix_log vs &
  sleep 2
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
# from inside the zpr-vs netns. Fails if the visa service rejects it.
function install_zode_policy() {
  echo "Installing policy: $1"
  in_ns zpr-vs \
    "$VS_ADMIN_BIN" --svc-url "$ADMIN_URL" --ca-cert ca.crt \
    --api-key-file vs-admin.key --format compact install "$PREGEN/$1"
}

# Start the relay Zode (`relay = true`, ZODE_LINKS.md rule 4).
function launch_relay() {
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
    --forwarding true \
    --tun-if tun0 \
    --zpr-addr "$RELAY_ZPR_ADDR" 2>&1 | tee relay.log | prefix_log relay &
}

# Dock the visa service's adapter on the relay and wait until the relay has
# registered with it. Returns non-zero if it does not.
function launch_vs_adapter() {
  in_ns zpr-vs "$PH_BIN" \
    adapter \
    --logging "$DEBUG_TARGETS" \
    --control-path vs.sock \
    --self-addr "$VS_SUBSTRATE_ADDR" \
    --ca-file ca.crt \
    --certificate-file vs.zpr.crt \
    --private-key-file vs.zpr.key \
    --bootstrap-key actorvs-rsa.key \
    --km-impl "$KM_IMPL" \
    --tun-if tun0 \
    --io-engine auto \
    --node-addr "$RELAY_SUBSTRATE_ADDR_VS" \
    --zpr-addr "$VS_ZPR_ADDR" 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

  wait_for 30 check_registered relay.log || {
    echo "the relay did not register with the visa service"
    return 1
  }
}

# Start Zode NAME in namespace zpr-NAME with an initial link to the relay.
# $1 = name (its certificate CN), $2 = substrate address, $3 = ZPR address,
# $4 = its RSA authentication key. Its key and certificate are made on the
# first launch and reused on a restart. The log is appended to, so a
# restart keeps the earlier lines.
function launch_zode() {
  local NAME=$1 SUBSTRATE=$2 ZPR_ADDR=$3 AUTH_KEY=$4
  [ -e "$NAME.crt" ] || create_actor_key_and_cert ca "$NAME"

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
# from `ph-cli link show`.
function active_links_to() {
  "$PH_DEBUG_BIN" -p "$1.sock" link show 2> /dev/null \
    | grep -cE "^ *[0-9]+: $(ere_escape "$2"):[0-9]+ \(Active\)" || true
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

# Assert that log $1 does not match the extended regex $2 ($3 = message).
function assert_no_log() {
  if grep -qE -- "$2" "$1"; then
    echo "ASSERTION FAILED: $3 (unexpected match for '$2' in $1):"
    grep -E -- "$2" "$1" | head -n 5
    return 1
  fi
  echo "assertion OK: $3"
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

# Print the verdict for $1 (0 = pass) and exit with it.
function zode_report() {
  echo
  if [[ "$1" == 0 ]]
  then echo "SUCCESS"
  else echo "FAILURE"
  fi
  exit "$1"
}
