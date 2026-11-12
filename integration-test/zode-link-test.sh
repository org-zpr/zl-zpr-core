#!/usr/bin/env bash
#
# Zode link lifecycle (zl-zipline#250, docs/ZODE_LINKS.md).
#
# A relay Zode (relay = true) docks the visa service. Zode zb has an initial
# link to the relay; zb is in the relay's topology. Zode zc has a
# certificate from the same CA and an initial link to the relay, but is in
# no policy. Before zl-zipline#252 only the relay has a visa-service session,
# so the relay's side carries the link-state reports.
#
# Scenarios, each checking the exact link count on both ends (no leaked or
# duplicate links):
#   1. zb joins: one Active link at each end; the relay reports zb up.
#   2. zb restarts on the same address: the relay ends with one link to zb
#      (rule 5) and reports it up again.
#   3. zc dials the relay: refused after keying, logged, no link (rule 3).
#   4. The substrate between the relay and zb is blocked past the keep-alive
#      tolerance: the relay clears the link and reports zb down (rules 9,
#      10); zb redials with backoff (rule 11); unblocked, the link is back
#      and reported up.
#   5. A policy without the relay-zb link: the relay closes the link and
#      stops reporting it (rule 12), and zb's redials are refused (rule 3).
#      The policy with the link back lets zb's next redial in.
#   6. The relay never dials (rule 4).
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

zode_begin

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
launch_zode_vs
launch_relay

PASS=0
launch_vs_adapter || PASS=1

# What the logs say (link_state.rs, zode_links.rs, assembly.rs).
ZB_ACCEPTED='accepted Zode link with peer CN Some\("zb"\)'
ZC_REFUSED='refusing Zode link with peer CN Some\("zc"\): unknown CN'
ZB_REFUSED='refusing Zode link with peer CN Some\("zb"\): unknown CN'
REPORT_ZB_UP='reported Zode link states to the visa service: \[.*zb=Up'
REPORT_ZB_DOWN='reported Zode link states to the visa service: \[.*zb=Down'
REPORT_WITHOUT_ZB='reported Zode link states to the visa service: \[\]'
DIAL='Started Zode link with .* as the dialer'
KEEPALIVE_LOST='failed to respond to keep-alive messages'

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  echo "== 1. zb joins"
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  assert_active_links 20 relay "$ZB_SUBSTRATE_ADDR" 1 "the relay has one Active link to zb" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb has one Active link to the relay" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_UP" 0 "the relay reports zb up to the visa service" || PASS=1

  echo "== 2. zb restarts on the same address"
  UP_REPORTS=$(log_count relay.log "$REPORT_ZB_UP")
  ACCEPTED=$(log_count relay.log "$ZB_ACCEPTED")
  kill_zode zb || PASS=1
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  wait_log_after 20 relay.log "$ZB_ACCEPTED" "$ACCEPTED" "the relay accepts the restarted zb" || PASS=1
  assert_active_links 10 relay "$ZB_SUBSTRATE_ADDR" 1 "the relay still has exactly one link to zb" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "the restarted zb has one link to the relay" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_UP" "$UP_REPORTS" "the relay reports zb up again" || PASS=1

  echo "== 3. zc, not in the relay's topology, dials the relay"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/node-rsa-key.pem"
  wait_log_after 20 relay.log "$ZC_REFUSED" 0 "the relay refuses zc after keying: unknown CN" || PASS=1
  assert_active_links 0 relay "$ZC_SUBSTRATE_ADDR" 0 "the relay has no link to zc" || PASS=1
  kill_zode zc || PASS=1

  echo "== 4. the substrate between the relay and zb is blocked"
  DOWN_REPORTS=$(log_count relay.log "$REPORT_ZB_DOWN")
  UP_REPORTS=$(log_count relay.log "$REPORT_ZB_UP")
  ZB_DIALS=$(log_count zb.log "$DIAL")
  block_substrate zb
  wait_log_after 30 relay.log "$KEEPALIVE_LOST" 0 "the relay gives up on the silent link" || PASS=1
  assert_active_links 10 relay "$ZB_SUBSTRATE_ADDR" 0 "the relay cleared its link to zb" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_DOWN" "$DOWN_REPORTS" "the relay reports zb down" || PASS=1
  # zb loses the link too and redials with backoff: 1, 2, 4 ... seconds.
  wait_log_after 30 zb.log "$DIAL" $((ZB_DIALS + 2)) "zb keeps redialing its initial link" || PASS=1
  unblock_substrate zb
  assert_active_links 40 relay "$ZB_SUBSTRATE_ADDR" 1 "the link is back, once" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb has one link to the relay again" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_UP" "$UP_REPORTS" "the relay reports zb up again" || PASS=1

  echo "== 5. a policy without the relay-zb link"
  REFUSED=$(log_count relay.log "$ZB_REFUSED")
  EMPTY_REPORTS=$(log_count relay.log "$REPORT_WITHOUT_ZB")
  install_zode_policy zodes-unlinked.bin2 || PASS=1
  assert_active_links 20 relay "$ZB_SUBSTRATE_ADDR" 0 "the relay closes the removed link" || PASS=1
  wait_log_after 10 relay.log "$REPORT_WITHOUT_ZB" "$EMPTY_REPORTS" "the relay no longer reports zb" || PASS=1
  wait_log_after 40 relay.log "$ZB_REFUSED" "$REFUSED" "zb's redials are refused: unknown CN" || PASS=1
  install_zode_policy "$ZODE_POLICY_BIN" || PASS=1
  assert_active_links 60 relay "$ZB_SUBSTRATE_ADDR" 1 "with the link back, zb's next redial gets in" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb has one link to the relay" || PASS=1

  echo "== 6. the relay never dials"
  assert_no_log relay.log "$DIAL" "the relay started no link as the dialer" || PASS=1
fi

zode_report "$PASS"
