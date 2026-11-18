#!/usr/bin/env bash
#
# Ping mesh between three Zodes (zl-zipline#234; the Zode port of the
# classic adapter-docked one-node ping test).
#
# A relay Zode (relay = true) hosts the visa service (zl-zipline#229).
# Zodes zb, zc and zd are in the relay's topology (pregen/zodes-ping.zplc)
# and each dials the relay through its initial link. Each Zode runs a
# different packet I/O engine: zb `auto`, zc `io_uring`, zd
# `posix_unbatched`. The test checks that:
#   - each endpoint authenticates as a device, with its RSA bootstrap key
#     alone (no user login);
#   - every endpoint pings every other one, from its own ZPR address, across
#     the relay (forward-only visas there), and the visa service;
#   - `ph-cli tun` on a Zode prints its TUN, then each of its --zpr-addr
#     addresses (zipline#202);
#   - no Zode counts an actor packet out of order;
#   - no Zode refused a Stream ID Request.
#
# Not covered here: joins in detail are zode-join-test.sh's, traffic
# identity between two joiners is zode-line-test.sh's.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

# The third endpoint, which only this test has (pregen/zodes-ping.zplc).
ZD_ZPR_ADDR=fd5a:5052::5
ZD_SUBSTRATE_ADDR=10.2.0.4

# The endpoint Zodes, and the packet I/O engine each one runs.
ENDPOINTS=(zb zc zd)
declare -A IO_ENGINE=([zb]=auto [zc]=io_uring [zd]=posix_unbatched)

ZODE_POLICY_BIN=zodes-ping.bin2
zode_begin

# What the logs say once a Zode has authenticated (vs_worker.rs).
GRANTED='node access granted to visa service'

# Assert that `ph-cli tun` on Zode $1 prints exactly the lines $2...: the
# TUN interface, then each of its ZPR addresses (zipline#202), read back
# over the admin RPC.
function assert_ph_cli_tun() {
  local NAME=$1 OUT WANT
  shift
  WANT=$(printf '%s\n' "$@")
  if ! OUT=$("$PH_DEBUG_BIN" -p "$NAME.sock" tun); then
    echo "ASSERTION FAILED: ph-cli tun on $NAME exited non-zero"
    return 1
  fi
  if [[ "$OUT" == "$WANT" ]]; then
    echo "assertion OK: ph-cli tun on $NAME prints" "$@"
  else
    echo "ASSERTION FAILED: ph-cli tun on $NAME: expected" "$@" "; got:"
    echo "$OUT"
    return 1
  fi
}

# Assert that Zode $1 counted no actor packet out of order. Each fastpath
# worker reports its own counter, so `ph-cli counters` prints one line per
# worker; this sums them.
function assert_no_actor_ooo() {
  local OUT TOTAL
  if ! OUT=$("$PH_DEBUG_BIN" -p "$1.sock" counters); then
    echo "ASSERTION FAILED: ph-cli counters on $1 exited non-zero"
    return 1
  fi
  TOTAL=$(awk -F': ' '$1 == "Actor Packets Out-Of-Order" { n++; sum += $2 } END { if (n) print sum }' <<< "$OUT")
  if [[ "$TOTAL" == 0 ]]; then
    echo "assertion OK: $1 counted no actor packet out of order"
  else
    echo "ASSERTION FAILED: $1 counted '$TOTAL' actor packets out of order"
    return 1
  fi
}

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR" "zd:$ZD_SUBSTRATE_ADDR"
PASS=0
launch_relay || PASS=1
launch_zode_vs || PASS=1

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  for NAME in "${ENDPOINTS[@]}"
  do
    ZPR_ADDR=${NAME^^}_ZPR_ADDR
    SUBSTRATE=${NAME^^}_SUBSTRATE_ADDR
    launch_zode "$NAME" "${!SUBSTRATE}" "${!ZPR_ADDR}" "$PREGEN/$NAME-rsa-key.pem" ca \
      --io-engine "${IO_ENGINE[$NAME]}"
  done

  echo "== every endpoint authenticates as a device"
  for NAME in "${ENDPOINTS[@]}"
  do
    wait_log_after 60 "$NAME.log" "$GRANTED" 0 \
      "$NAME authenticates with its bootstrap key" || PASS=1
    # `auto` picks an engine for the host, so only an explicit one is checked.
    if [[ "${IO_ENGINE[$NAME]}" != auto ]]; then
      wait_log_after 5 "$NAME.log" "Using packet I/O engine ${IO_ENGINE[$NAME]}\$" 0 \
        "$NAME runs I/O engine ${IO_ENGINE[$NAME]}" || PASS=1
    fi
  done
fi

if [[ "$PASS" == 0 ]]; then
  echo "== every endpoint reaches the visa service"
  for NAME in "${ENDPOINTS[@]}"
  do
    zode_ping "$NAME" "$VS_ZPR_ADDR" "$NAME pings the visa service" || PASS=1
  done

  echo "== ping mesh between the endpoints"
  for FROM in "${ENDPOINTS[@]}"
  do
    for TO in "${ENDPOINTS[@]}"
    do
      [[ "$FROM" == "$TO" ]] && continue
      TO_ADDR=${TO^^}_ZPR_ADDR
      zode_ping "$FROM" "${!TO_ADDR}" "$FROM pings $TO" || PASS=1
    done
  done

  echo "== ph-cli tun"
  assert_ph_cli_tun zb tun0 "$ZB_ZPR_ADDR" || PASS=1
  assert_ph_cli_tun relay tun0 "$RELAY_ZPR_ADDR" "$VS_ZPR_ADDR" || PASS=1

  echo "== no actor packet out of order"
  for NAME in relay "${ENDPOINTS[@]}"
  do
    assert_no_actor_ooo "$NAME" || PASS=1
  done

  echo "== no Stream ID Request was refused"
  assert_no_refusals relay "${ENDPOINTS[@]}" || PASS=1
fi

zode_report "$PASS"
