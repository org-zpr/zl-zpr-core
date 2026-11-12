#!/usr/bin/env bash

#
# Shared set-up for the Zode netns tests (zl-zipline#222):
# zode-join-test.sh, zode-line-test.sh and zode-wrong-ca-test.sh.
#
# Source it after lib/common_funcs.sh. The layout matches the
# pregen/zodes.zplc policy:
#
#   zpr-vs ---- zpr-relay ---- br0 ---- zpr-zb
#   (visa        (relay Zode,       \--- zpr-zc
#    service)     docks the VS)      \-- (any further Zode)
#
# The visa service runs as an adapter docked on the relay, as in
# one-node-test.sh. Every other Zode sits on one substrate segment (a bridge
# in the relay's namespace) and joins through its configured initial link to
# the relay: it has no visa service of its own, so it reaches the visa
# service only with the bootstrap visas the relay hands it (pd gate g60).
#
# Each Zode is a `ph node` with its own certificate (CN = its policy node
# name), signed by the test CA unless a test says otherwise, and its own RSA
# authentication key from pregen.
#

export RUST_BACKTRACE=1
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO}
KM_IMPL=${KM_IMPL:-noise}

PH_BIN="${PH_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph")}"
PH_DEBUG_BIN="${PH_DEBUG_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph-cli")}"
VS_BIN="${VS_BIN:-$(realpath "$(dirname "$0")/vs")}"
VALKEY_SERVER_BIN="${VALKEY_SERVER_BIN:-$(realpath -s "$(dirname "$0")/valkey-server")}"
PREGEN=$(realpath "$(dirname "$0")/pregen")

ZODE_PORT=5000

VS_ZPR_ADDR=fd5a:5052::1
RELAY_ZPR_ADDR=fd5a:5052::2
ZB_ZPR_ADDR=fd5a:5052::3
ZC_ZPR_ADDR=fd5a:5052::4
# The whole ZPRnet, routed through the visa service's TUN: the visa service
# dials each Zode's VSS server, not only the relay's.
ZPR_SUBNET=fd5a:5052::/32

RELAY_SUBSTRATE_ADDR_VS=10.0.0.1
VS_SUBSTRATE_ADDR=10.0.0.2
RELAY_SUBSTRATE_ADDR=10.2.0.1
ZB_SUBSTRATE_ADDR=10.2.0.2
ZC_SUBSTRATE_ADDR=10.2.0.3
# Not in the policy: used for a Zode the relay must refuse.
ZX_SUBSTRATE_ADDR=10.2.0.9

ZODE_POLICY_BIN=zodes.bin2

# Check that every binary and fixture the Zode tests use is present.
function zode_preflight() {
  local F
  for F in "$VS_BIN" "$VALKEY_SERVER_BIN" "$PREGEN/$ZODE_POLICY_BIN"
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
  if systemctl is-active --quiet valkey-server 2>/dev/null; then
    echo "valkey-server system service is running. Please stop it before running this test:"
    echo "  sudo systemctl stop valkey-server"
    exit 1
  fi
}

# Common start of every Zode test, called right after enter_test_namespace:
# check prerequisites, move into a fresh working directory that the EXIT
# trap removes, and make the test CA. $@ = the logs to print when
# ZPR_TEST_VERBOSE is set.
function zode_begin() {
  zode_preflight
  ZPR_TEST_LOGS=("$@")
  trap cleanup EXIT
  TMPDIR=$(mktemp -d)
  pushd "$TMPDIR" > /dev/null
  create_ca_key_and_cert ca
}

# Build the namespaces in the diagram above. Arguments are NAME:ADDR pairs,
# one per Zode on the bridge (e.g. zb:10.2.0.2); each gets namespace
# zpr-NAME with ADDR/24 on its veth0.
#
# A Zode's TUN gets no address here: `ph node` applies its own ZPR address
# (assembly.rs ensure_local_zpr_addrs_on_tun). The visa service's adapter
# TUN is addressed here, as in create_network.
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

  # The Zodes' shared segment. A /24 for the reason create_network gives.
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

# Write the visa service's config and certificate, then start valkey and
# the visa service with the Zode policy. Run from the test's working
# directory, after create_ca_key_and_cert.
function launch_zode_vs() {
  create_actor_key_and_cert ca vs.zpr
  cp "$PREGEN/actorvs-rsa.key" actorvs-rsa.key
  emit_vs_config ca vs.zpr > vs-config.toml

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

# Start the relay Zode. $1 is its `forwarding` setting (true or false):
# whether it accepts forward-only visas and so carries zb-zc traffic.
function launch_relay() {
  local FORWARDING=$1
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
    --forwarding "$FORWARDING" \
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

# Start a joining Zode NAME in namespace zpr-NAME, with only an initial link
# to the relay and no visa service of its own.
#
# $1 = name (its certificate CN and policy node name), $2 = substrate
# address, $3 = ZPR address, $4 = the CA that signs its certificate (the
# Zode itself always trusts ca.crt), $5 = its RSA authentication key.
function launch_zode() {
  local NAME=$1 SUBSTRATE=$2 ZPR_ADDR=$3 SIGNING_CA=$4 AUTH_KEY=$5
  create_actor_key_and_cert "$SIGNING_CA" "$NAME"

  in_ns "zpr-$NAME" "$PH_BIN" \
    node \
    --logging "$DEBUG_TARGETS" \
    --control-path "$NAME.sock" \
    --advertised-substrate-addr "$SUBSTRATE:$ZODE_PORT" \
    --initial-link "relay@$RELAY_SUBSTRATE_ADDR:$ZODE_PORT" \
    --ca-file ca.crt \
    --certificate-file "$NAME.crt" \
    --private-key-file "$NAME.key" \
    --auth-private-key "$AUTH_KEY" \
    --km-impl "$KM_IMPL" \
    --tun-if tun0 \
    --zpr-addr "$ZPR_ADDR" 2>&1 | tee "$NAME.log" | prefix_log "$NAME" &
}

# Make a second, unrelated CA named $1 ($1.key, $1.crt).
function create_other_ca() {
  "$ZPR_PKI_BIN" gencakey > "$1.key"
  "$ZPR_PKI_BIN" gencacert /CN="$1" 1 < "$1.key" > "$1.crt"
}

# True once the Zode logging to $1 has authenticated with the visa service
# and the visa service has reached its VSS server (vs_worker.rs).
function check_registered() {
  grep -q "registered VSS" "$1"
}

# Wait up to $1 seconds for Zode log $2 to show registration.
function wait_registered() {
  wait_for "$1" check_registered "$2" || {
    echo "ASSERTION FAILED: $2 shows no registration with the visa service"
    return 1
  }
  echo "assertion OK: $2 registered with the visa service"
}

# What ph logs when it refuses a StreamIdRequest from a link that is not the
# visa's previous hop (gap 7, zl-zipline#222; mgmt/node.rs).
GAP7_REFUSAL="refusing StreamIdRequest from .*: not the visa's previous hop"

# Assert that log $1 matches the extended regex $2, with $3 as the message.
function assert_log() {
  if grep -qE -- "$2" "$1"; then
    echo "assertion OK: $3"
  else
    echo "ASSERTION FAILED: $3 (no match for '$2' in $1)"
    return 1
  fi
}

# Assert that log $1 does not match the extended regex $2.
function assert_no_log() {
  if grep -qE -- "$2" "$1"; then
    echo "ASSERTION FAILED: $3 (unexpected match for '$2' in $1):"
    grep -E -- "$2" "$1" | head -n 5
    return 1
  fi
  echo "assertion OK: $3"
}

# Assert that log $1 matches the extended regex $2 exactly $3 times.
function assert_log_count() {
  local N
  N=$(grep -cE -- "$2" "$1" || true)
  if [[ "$N" == "$3" ]]; then
    echo "assertion OK: $4"
  else
    echo "ASSERTION FAILED: $4 (expected $3 matches for '$2' in $1, got $N)"
    return 1
  fi
}

# Ping $3 from namespace $1 ($2 is a label). The first echo also makes the
# visa service issue the visas, so allow a few tries before the real check.
function zode_ping() {
  local NS=$1 LABEL=$2 DEST=$3
  wait_for 10 in_ns "$NS" ping -q -c 1 -W 1 "$DEST" > /dev/null || true
  if in_ns "$NS" ping -q -c 5 -w 5 "$DEST" > /dev/null; then
    echo "assertion OK: $LABEL reaches $DEST"
  else
    echo "ASSERTION FAILED: $LABEL cannot reach $DEST"
    return 1
  fi
}

# Assert that $3 is NOT reachable from namespace $1 ($2 is a label).
function zode_no_ping() {
  local NS=$1 LABEL=$2 DEST=$3
  if in_ns "$NS" ping -q -c 3 -w 5 "$DEST" > /dev/null; then
    echo "ASSERTION FAILED: $LABEL unexpectedly reaches $DEST"
    return 1
  fi
  echo "assertion OK: $LABEL cannot reach $DEST"
}

# Stop every process this test started and tear down its namespaces, so a
# test can run a second leg from a clean slate. The EXIT trap's cleanup does
# the same at the end.
function zode_stop_all() {
  stop_test_processes
  destroy_network
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
