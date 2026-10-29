#!/usr/bin/env bash
# node-restart-test.sh — regression test for zipline#167.
#
# A node restarting under a running visa service must reliably bring every
# link back to Active. The failure this guards against is the node
# re-register race: the node's disconnect used to tear down the VS's own
# adapter actor, so a restarted node that re-authenticated and called
# register_vss BEFORE the VS adapter re-docked was denied SourceNotFound
# and torn down again; the node side then wedged its VS connection
# ("connect called but already connected to VS-API") and never recovered.
#
# The test brings up the one-node-test.sh topology to all-Active, then
# restarts the node several times with the VS kept running. There is no race
# to force on the node side: a restarted node always calls register_vss
# BEFORE it forwards the VS adapter's re-dock to the VS (deferred_vs_connect,
# sent only once the VSS is registered). What decides whether the VS still
# holds its own adapter's actor at that point is how the old node left:
#
#   - kill (SIGKILL, crash semantics): the node says nothing; its replacement
#     connects with ctype=Reset, whose teardown always spared the VS adapter.
#   - graceful (SIGINT): the node sends a NodeShutdown self-disconnect, and
#     the VS's disconnect cascade ran over every adapter docked to it — the
#     path that dropped the VS's own adapter before the zipline#167 fix.
#
# The graceful round ($GRACEFUL_ROUND) waits for the VS to log that
# NodeShutdown disconnect before relaunching, so the cascade provably ran
# before the new node registers. The other rounds SIGKILL the node.
# Pass = carrier and pings return on every round.
#
# No process is ever SIGSTOPped: an earlier forced round froze the VS adapter,
# which cut the node's only path to the VS and left the launch wrappers stopped
# so cleanup hung (https://github.com/org-zpr/zl-zipline/issues/171).
set -euo pipefail

export RUST_BACKTRACE=1
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO}
KM_IMPL=${KM_IMPL:-noise}

# How many node restarts, and which one is graceful (SIGINT) rather than a
# SIGKILL. GRACEFUL_ROUND=0 runs SIGKILL restarts only.
RESTART_ROUNDS=${RESTART_ROUNDS:-3}
GRACEFUL_ROUND=${GRACEFUL_ROUND:-2}

PH_BIN="${PH_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph")}"
PH_DEBUG_BIN="${PH_DEBUG_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph-cli")}"
VS_BIN="${VS_BIN:-$(realpath "$(dirname "$0")/vs")}"
VALKEY_SERVER_BIN="${VALKEY_SERVER_BIN:-$(realpath -s "$(dirname "$0")/valkey-server")}"

PREGEN=$(realpath "$(dirname $0)/pregen")
NODE_AUTH_PRIVATE_KEY="${NODE_AUTH_PRIVATE_KEY:-$PREGEN/node-rsa-key.pem}"

source "$(dirname $0)/lib/common_funcs.sh"

# Re-exec inside an unprivileged user+network namespace; everything below
# runs there and needs no sudo.
enter_test_namespace "$@"

NODE_SUBSTRATE_ADDR_VS=10.0.0.1
NODE_SUBSTRATE_ADDR_A=10.0.1.1
NODE_SUBSTRATE_ADDR_B=10.0.2.1
NODE_SUBSTRATE_ADDR_C=10.0.3.1
VS_SUBSTRATE_ADDR=10.0.0.2
A_SUBSTRATE_ADDR=10.0.1.2
B_SUBSTRATE_ADDR=10.0.2.2
C_SUBSTRATE_ADDR=10.0.3.2

ACTOR_PROTOCOL="ipv6"
NUM_ACTORS=3
# Defines POLICY_BIN, NODE_ZPR_ADDR, VS_ZPR_ADDR, A/B/C_ZPR_ADDR.
source "$(dirname $0)/lib/parse_arguments.sh"

if [ ! -e "$VS_BIN" ]; then
  echo "vs binary not found, expected it at $VS_BIN"
  exit 1
fi

if systemctl is-active --quiet valkey-server 2>/dev/null; then
  echo "valkey-server system service is running. Please stop it before running this test:"
  echo "  sudo systemctl stop valkey-server"
  exit 1
fi

if [ ! -e "$VALKEY_SERVER_BIN" ]; then
  echo "valkey-server binary not found, expected it at $VALKEY_SERVER_BIN"
  exit 1
fi

if [ ! -e "$PREGEN/$POLICY_BIN" ]; then
  echo "policy file not found (expected .bin2): $PREGEN/$POLICY_BIN"
  exit 1
fi

if [ ! -x "$PH_BIN" ]; then
  echo "ph binary not found or not executable: $PH_BIN"
  exit 1
fi

if [ ! -x "$PH_DEBUG_BIN" ]; then
  echo "ph-cli binary not found or not executable: $PH_DEBUG_BIN"
  exit 1
fi

if [ ! -e "$NODE_AUTH_PRIVATE_KEY" ]; then
  echo "node auth private key not found: $NODE_AUTH_PRIVATE_KEY"
  exit 1
fi

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
ADAPTER3_SOCK=adapter3.sock

#
# Set up automatic cleanup
#

trap cleanup EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" > /dev/null

echo "Setting up network"

destroy_network
create_network

create_ca_key_and_cert ca
create_actor_key_and_cert ca vs.zpr

cp "$PREGEN/node.key" node.key
cp "$PREGEN/node-cert.pem" node.crt
cp "$PREGEN/node-pubkey.pem" node.pubkey
cp "$PREGEN/actor1-rsa.key" actor1-rsa.key
cp "$PREGEN/actor2-rsa.key" actor2-rsa.key
cp "$PREGEN/actor3-rsa.key" actor3-rsa.key
cp "$PREGEN/actorvs-rsa.key" actorvs-rsa.key

emit_vs_config ca vs.zpr > vs-config.toml
copy_address_store

#
# Launch ValKey + Visa Service (these stay up across every node restart)
#

echo "Launching ValKey"

in_ns zpr-vs "$VALKEY_SERVER_BIN" \
    --save "" \
    --appendonly no 2>&1 | tee valkey.log | prefix_log valkey &

wait_for 15 check_vs_valkey_port

echo "Launching Visa Service"

in_ns zpr-vs env XDG_DATA_HOME=/tmp "$VS_BIN" \
    -c vs-config.toml \
    --clear-state \
    "$PREGEN/$POLICY_BIN" 2>&1 | tee vs.log | prefix_log vs &

sleep 2

#
# Launch the node (restarted by the test) and the adapters
#

# Launch (or relaunch) the node. Appends to node.log so the whole history
# survives the restarts.
function launch_node() {
  rm -f "$NODE_SOCK"
  in_ns zpr-node "$PH_BIN" \
    node \
    --logging "$DEBUG_TARGETS" \
    --control-path "$NODE_SOCK" \
    --advertised-substrate-addr "$NODE_SUBSTRATE_ADDR_VS":5000 \
    --ca-file ca.crt \
    --certificate-file node.crt \
    --private-key-file node.key \
    --auth-private-key "$NODE_AUTH_PRIVATE_KEY" \
    --km-impl "$KM_IMPL" \
    --tun-if tun0 \
    --zpr-addr "$NODE_ZPR_ADDR" 2>&1 | tee -a node.log | prefix_log zpr-node &
}

echo "Launching Node"
launch_node

sleep 2

echo "Launching Adapters"

in_ns zpr-vs "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$VS_SOCK" \
  --self-addr "$VS_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --certificate-file vs.zpr.crt \
  --private-key-file vs.zpr.key \
  --bootstrap-key actorvs-rsa.key \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine auto \
  --node-addr "$NODE_SUBSTRATE_ADDR_VS" \
  --zpr-addr "$VS_ZPR_ADDR" 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

sleep 5

in_ns zpr-a "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER1_SOCK" \
  --self-addr "$A_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --bootstrap-key actor1-rsa.key \
  --name adapter1 \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine io_uring \
  --node-addr "$NODE_SUBSTRATE_ADDR_A" \
  --zpr-addr "$A_ZPR_ADDR" 2>&1 | tee adapter1.log | prefix_log zpr-a &

in_ns zpr-b "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER2_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --bootstrap-key actor2-rsa.key \
  --name adapter2 \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine posix_unbatched \
  --node-addr "$NODE_SUBSTRATE_ADDR_B" \
  --zpr-addr "$B_ZPR_ADDR" 2>&1 | tee adapter2.log | prefix_log zpr-b &

if [[ "$NUM_ACTORS" -ge 3 ]]; then
  in_ns zpr-c "$PH_BIN" \
    adapter \
    --logging "$DEBUG_TARGETS" \
    --control-path "$ADAPTER3_SOCK" \
    --self-addr "$C_SUBSTRATE_ADDR" \
    --ca-file ca.crt \
    --bootstrap-key actor3-rsa.key \
    --name adapter3 \
    --km-impl "$KM_IMPL" \
    --tun-if tun0 \
    --node-addr "$NODE_SUBSTRATE_ADDR_C" \
    --zpr-addr "$C_ZPR_ADDR" 2>&1 | tee adapter3.log | prefix_log zpr-c &
fi

#
# Helpers for the restart loop
#

# All TUN carriers up (five in three-actor mode, four with --num_actors 2),
# allowing $1 seconds.
function wait_all_carriers() {
  local timeout=$1
  wait_for "$timeout" check_carrier zpr-node tun0 || return 1
  wait_for "$timeout" check_carrier zpr-vs tun0 || return 1
  wait_for "$timeout" check_carrier zpr-a tun0 || return 1
  wait_for "$timeout" check_carrier zpr-b tun0 || return 1
  if [[ "$NUM_ACTORS" -ge 3 ]]; then
    wait_for "$timeout" check_carrier zpr-c tun0 || return 1
  fi
  return 0
}

# One quick end-to-end probe: node->VS plus one actor-to-actor pair (a->c in
# three-actor mode, a->b with --num_actors 2). Carrier alone is not a
# readiness signal after a node restart — the surviving namespaces' tun
# carriers never drop, so wait_all_carriers returns long before the
# restarted node has re-authenticated and the adapters' visas are rebuilt
# (~25s of auth + re-dock). Used with wait_for so the strict ping_test
# below only runs once the data path is actually back.
function zpr_data_path_up() {
  local peer_addr=$B_ZPR_ADDR
  if [[ "$NUM_ACTORS" -ge 3 ]]; then peer_addr=$C_ZPR_ADDR; fi
  in_ns zpr-node ping -q -c 1 -W 2 "$VS_ZPR_ADDR" > /dev/null 2>&1 || return 1
  in_ns zpr-a ping -q -c 1 -W 2 "$peer_addr" > /dev/null 2>&1 || return 1
  return 0
}

# Succeed once vs.log has grown past line $1 with the VS processing the
# node's graceful-shutdown self-disconnect — the cascade over its adapters.
function vs_saw_node_shutdown() {
  tail -n +"$(( $1 + 1 ))" vs.log | grep -q "disconnect actor at $NODE_ZPR_ADDR for reason NodeShutdown"
}

# Stop the node and relaunch it. $1 == "graceful" sends SIGINT and, before
# relaunching, waits for the VS to have processed the node's NodeShutdown
# disconnect; anything else SIGKILLs it (crash semantics, no goodbye).
function restart_node() {
  local mode=$1 node_pid vs_log_mark

  node_pid=$(ph_pid_for_socket "$NODE_SOCK")
  if [ -z "$node_pid" ]; then
    echo "could not find the node's pid"
    return 1
  fi

  vs_log_mark=$(wc -l < vs.log)

  if [ "$mode" == "graceful" ]; then
    echo "Stopping node gracefully ($node_pid)"
    kill -SIGINT "$node_pid"
  else
    echo "Killing node ($node_pid)"
    kill -SIGKILL "$node_pid"
  fi
  wait_for 15 process_exited "$node_pid" || { echo "node did not exit"; return 1; }

  if [ "$mode" == "graceful" ]; then
    if ! wait_for 10 vs_saw_node_shutdown "$vs_log_mark"; then
      echo "VS never processed the node's NodeShutdown disconnect"
      return 1
    fi
    echo "VS processed the node's NodeShutdown disconnect"
  fi

  sleep 1
  echo "Relaunching node"
  launch_node
  return 0
}

#
# Baseline: everything Active once
#

PASS=0
echo "Wait for TUN carrier (baseline)..."
if ! wait_all_carriers 15; then
  echo "BASELINE FAILED: carrier never arrived"
  PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  sleep 1
  echo "TEST STARTING"
  if ! ping_test; then
    echo "BASELINE FAILED: ping test"
    PASS=1
  fi
fi

#
# Restart loop
#

if [[ "$PASS" == 0 ]]; then
  for (( round=1; round<=RESTART_ROUNDS; round++ )); do
    MODE=kill
    if [[ "$round" == "$GRACEFUL_ROUND" ]]; then MODE=graceful; fi
    echo
    echo "==== Node restart round $round/$RESTART_ROUNDS ($MODE) ===="

    if ! restart_node "$MODE"; then
      echo "ROUND $round FAILED: restart"
      PASS=1
      break
    fi

    # Carrier must return on every netns; the re-registered node and the
    # re-docked adapters need a little time for auth + visas.
    if ! wait_all_carriers 90; then
      echo "ROUND $round FAILED: carrier did not return after node restart"
      PASS=1
      break
    fi

    # Carrier is necessary but not sufficient: the VS only notices the dead
    # dock link after ~3 missed keep-alives and the adapters re-dock a few
    # seconds later, so give the data path time to actually come back before
    # the strict all-pairs ping check.
    if ! wait_for 90 zpr_data_path_up; then
      echo "ROUND $round FAILED: data path did not return after node restart"
      PASS=1
      break
    fi

    sleep 1
    if ! ping_test; then
      echo "ROUND $round FAILED: ping test after node restart"
      PASS=1
      break
    fi
    echo "==== Round $round OK: all links Active ===="
  done
fi

#
# Cleanup
#

for pid in $(get_descendants)
do
  echo
  echo "Terminating $pid"
  sleep 1
  kill -SIGINT "$pid"
  sleep 1
done

stty sane || true

#
# Report status
#

echo
if [[ "$PASS" == 0 ]]
then echo "SUCCESS"
else echo "FAILURE"
fi

exit "$PASS"
