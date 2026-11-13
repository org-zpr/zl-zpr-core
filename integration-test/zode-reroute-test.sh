#!/usr/bin/env bash
#
# A direct Zode link drops and the flow re-routes through the relay
# (zl-zipline#251's netns acceptance, run in #254; Zodes plan W5),
# docs/ZODE_LINKS.md rules 9, 10, 14 and 15, and F3, F4 and F6.
#
# pregen/zodes-direct.zplc links the relay to zb and to zc, and zb to zc.
# zb and zc both have a substrate address in the policy, so the visa
# service proposes the zb-zc link (rule 13b); zb, the lower ZPR address,
# owns it and dials zc. The relay is the only transit node.
#   1. zb and zc join through the relay, then bring the zb-zc link up and
#      both report it up. The visa service routes over the link once both
#      ends have (rule 14).
#   2. zb pings zc over the direct link: the relay inserts no forward-only
#      visa for the flow (the only forward-only visas the relay can hold
#      here are for zb-zc flows). No Zode has refused a Stream ID Request.
#   3. The substrate between zb and zc is blocked; both still reach the
#      relay. Each end gives up on the silent link, clears it (rule 9) and
#      reports it down (rule 10); losing the link revokes the flow's visas
#      locally (F3), and the visa service revokes them too (rule 15, F4).
#      zb's next echo finds no visa and requests one (F6): the new route
#      crosses the relay, which now inserts forward-only visas, and the
#      ping succeeds again.
# No Zode refuses a Stream ID Request as not from the visa's previous hop
# in the whole run. The Stream ID Request Rejected counters are checked only
# before the block: a request pending over the lost link is refused by
# design (rule 9).
#
# Not covered: the link coming back after an unblock. That needs a new
# setTopology (rule 13), and is not in #251's acceptance.
#
# Joins wait 20-30 s: see zode-link-test.sh.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

ZODE_POLICY_BIN=zodes-direct.bin2
zode_begin

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
launch_zode_vs
launch_relay

PASS=0
launch_vs_adapter || PASS=1

# What the logs say (vss_rpc.rs, link_state.rs, zode_links.rs,
# visa_table.rs; the visa service's topology_mgr.rs).
TOPOLOGY='received topology update with [1-9][0-9]* links'
FORWARD_ONLY='Visa inserted into VisaTable ID: [0-9]+, Type: ForwardOnly'
KEEPALIVE_LOST='failed to respond to keep-alive messages'
REPORT_ZC_UP='reported Zode link states to the visa service: \[.*zc=Up'
REPORT_ZB_UP='reported Zode link states to the visa service: \[.*zb=Up'
REPORT_ZC_DOWN='reported Zode link states to the visa service: \[.*zc=Down'
REPORT_ZB_DOWN='reported Zode link states to the visa service: \[.*zb=Down'
VS_LINK_UP='link zb-zc between .* is now up'
VS_LINK_DOWN='link zb-zc between .* is now down'

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  echo "== 1. zb and zc join and bring their direct link up"
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem"
  wait_log_after 45 zb.log "$TOPOLOGY" 0 "zb joins and receives its topology" || PASS=1
  wait_log_after 45 zc.log "$TOPOLOGY" 0 "zc joins and receives its topology" || PASS=1
  assert_active_links 20 zb "$ZC_SUBSTRATE_ADDR" 1 "zb has one Active link to zc" || PASS=1
  assert_active_links 5 zc "$ZB_SUBSTRATE_ADDR" 1 "zc has one Active link to zb" || PASS=1
  wait_log_after 10 zb.log "$REPORT_ZC_UP" 0 "zb reports the zb-zc link up" || PASS=1
  wait_log_after 10 zc.log "$REPORT_ZB_UP" 0 "zc reports the zb-zc link up" || PASS=1
  wait_log_after 10 vs.log "$VS_LINK_UP" 0 "the visa service routes over the zb-zc link (rule 14)" || PASS=1

  echo "== 2. zb pings zc over the direct link"
  FORWARD_ONLY_BEFORE=$(log_count relay.log "$FORWARD_ONLY")
  zode_ping zb "$ZC_ZPR_ADDR" "zb reaches zc" || PASS=1
  if log_count_above relay.log "$FORWARD_ONLY" "$FORWARD_ONLY_BEFORE"; then
    echo "ASSERTION FAILED: the relay inserted a forward-only visa: the flow did not go direct"
    PASS=1
  else
    echo "assertion OK: the relay inserted no forward-only visa: the flow went direct"
  fi
  assert_no_refusals relay zb zc || PASS=1

  echo "== 3. the substrate between zb and zc is blocked"
  block_pair zb zc
  wait_log_after 30 zb.log "$KEEPALIVE_LOST" 0 "zb gives up on the silent link" || PASS=1
  wait_log_after 30 zc.log "$KEEPALIVE_LOST" 0 "zc gives up on the silent link" || PASS=1
  assert_active_links 10 zb "$ZC_SUBSTRATE_ADDR" 0 "zb cleared its link to zc (rule 9)" || PASS=1
  assert_active_links 10 zc "$ZB_SUBSTRATE_ADDR" 0 "zc cleared its link to zb (rule 9)" || PASS=1
  wait_log_after 10 zb.log "$REPORT_ZC_DOWN" 0 "zb reports the zb-zc link down (rule 10)" || PASS=1
  wait_log_after 10 zc.log "$REPORT_ZB_DOWN" 0 "zc reports the zb-zc link down (rule 10)" || PASS=1
  wait_log_after 10 vs.log "$VS_LINK_DOWN" 0 "the visa service stops routing over the zb-zc link" || PASS=1
  assert_active_links 0 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb still has its link to the relay" || PASS=1
  assert_active_links 0 zc "$RELAY_SUBSTRATE_ADDR" 1 "zc still has its link to the relay" || PASS=1
  # The link is already down here, so the bound is the revoke and zb's
  # re-request (F6): 20 one-second warm-up echoes, then five that must all
  # be answered.
  zode_ping zb "$ZC_ZPR_ADDR" "zb reaches zc again, through the relay" 20 || PASS=1
  wait_log_after 10 relay.log "$FORWARD_ONLY" "$FORWARD_ONLY_BEFORE" \
    "the relay now carries the flow on forward-only visas" || PASS=1

  echo "== the whole run"
  # Only the previous-hop refusal: the counters may count requests that
  # were pending over the lost link (rule 9).
  for ZODE in relay zb zc
  do
    assert_no_log "$ZODE.log" "$PREV_HOP_REFUSED" "$ZODE refused no request from a previous hop" || PASS=1
  done
fi

zode_report "$PASS"
