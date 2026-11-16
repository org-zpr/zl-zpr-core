#!/usr/bin/env bash
#
# A direct Zode link drops and the flow re-routes through the relay, then
# the link comes back and new flows go direct again: the netns version of
# the Zodes demo (zl-zipline#231, plan "Demo"; #251's acceptance, run in
# #254; Zodes plan W5), docs/ZODE_LINKS.md rules 9, 10, 13, 14 and 15, and
# F3, F4 and F6.
#
# pregen/zodes-direct.zplc links the relay to zb and to zc, and zb to zc.
# zb and zc both have a substrate address in the policy, so the visa
# service proposes the zb-zc link (rule 13b); zb, the lower ZPR address,
# owns it and dials zc. The relay is the only transit node.
#
# Whether a transfer crosses the relay is read from the bytes the relay
# receives on its substrate (relay_rx_bytes: br0's RX counter, which does
# not count frames bridged between zb and zc). Steps 2 and 4 require it to
# stay below a tenth of the transfer, step 3 to rise by at least the whole
# transfer, so the same counter is shown to see relayed traffic in the run.
#   1. zb and zc join through the relay, then bring the zb-zc link up and
#      both report it up. The visa service routes over the link once both
#      ends have (rule 14).
#   2. zb pings zc over the direct link: the relay inserts no forward-only
#      visa for the flow (the only forward-only visas the relay can hold
#      here are for zb-zc flows). A bulk transfer zb -> zc leaves the
#      relay's received bytes flat. No Zode has refused a Stream ID Request.
#   3. The substrate between zb and zc is blocked; both still reach the
#      relay. Each end gives up on the silent link, clears it (rule 9) and
#      reports it down (rule 10); losing the link revokes the flow's visas
#      locally (F3), and the visa service revokes them too (rule 15, F4).
#      zb's next echo finds no visa and requests one (F6): the new route
#      crosses the relay, which now inserts forward-only visas, and the
#      ping succeeds again. The same bulk transfer now raises the relay's
#      received bytes.
#   4. The block is lifted. Nothing retries a link reported down by itself
#      (rule 10), only a new setTopology does (rule 13), so the test
#      re-installs the running policy, which pushes topology to every Zode.
#      zb dials zc again, both report the link up, and the visa service
#      routes over it. zb's existing flow to zc keeps its relay-path visa
#      until it expires (Zodes plan 5.8: only new visas take the direct
#      link), so the new flow is zc -> zb, which no visa covers yet: its
#      bulk transfer leaves the relay's received bytes flat again.
#      zl-zipline#268 will have the visa service re-propose a down link by
#      itself; this step then waits for that retry instead of re-installing.
# No Zode refuses a Stream ID Request as not from the visa's previous hop
# in the whole run. The Stream ID Request Rejected counters are checked only
# before the block: a request pending over the lost link is refused by
# design (rule 9).
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
PASS=0
launch_relay || PASS=1
launch_zode_vs || PASS=1

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
  RX_BEFORE=$(relay_rx_bytes) || PASS=1
  bulk_ping zb "$ZC_ZPR_ADDR" "zb's bulk transfer to zc completes" || PASS=1
  assert_relay_rx_flat "${RX_BEFORE:-0}" "the bulk transfer does not cross the relay" || PASS=1

  echo "== 3. the substrate between zb and zc is blocked"
  # Counted just before the block, so only what the block causes matches
  # below, not an earlier loss of the link (a flap while it came up).
  ZB_LOST=$(log_count zb.log "$KEEPALIVE_LOST")
  ZC_LOST=$(log_count zc.log "$KEEPALIVE_LOST")
  ZB_DOWN=$(log_count zb.log "$REPORT_ZC_DOWN")
  ZC_DOWN=$(log_count zc.log "$REPORT_ZB_DOWN")
  VS_DOWN=$(log_count vs.log "$VS_LINK_DOWN")
  block_pair zb zc
  wait_log_after 30 zb.log "$KEEPALIVE_LOST" "$ZB_LOST" "zb gives up on the silent link" || PASS=1
  wait_log_after 30 zc.log "$KEEPALIVE_LOST" "$ZC_LOST" "zc gives up on the silent link" || PASS=1
  assert_active_links 10 zb "$ZC_SUBSTRATE_ADDR" 0 "zb cleared its link to zc (rule 9)" || PASS=1
  assert_active_links 10 zc "$ZB_SUBSTRATE_ADDR" 0 "zc cleared its link to zb (rule 9)" || PASS=1
  wait_log_after 10 zb.log "$REPORT_ZC_DOWN" "$ZB_DOWN" "zb reports the zb-zc link down (rule 10)" || PASS=1
  wait_log_after 10 zc.log "$REPORT_ZB_DOWN" "$ZC_DOWN" "zc reports the zb-zc link down (rule 10)" || PASS=1
  wait_log_after 10 vs.log "$VS_LINK_DOWN" "$VS_DOWN" "the visa service stops routing over the zb-zc link" || PASS=1
  assert_active_links 0 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb still has its link to the relay" || PASS=1
  assert_active_links 0 zc "$RELAY_SUBSTRATE_ADDR" 1 "zc still has its link to the relay" || PASS=1
  # The link is already down here, so the bound is the revoke and zb's
  # re-request (F6): 20 one-second warm-up echoes, then five that must all
  # be answered.
  zode_ping zb "$ZC_ZPR_ADDR" "zb reaches zc again, through the relay" 20 || PASS=1
  wait_log_after 10 relay.log "$FORWARD_ONLY" "$FORWARD_ONLY_BEFORE" \
    "the relay now carries the flow on forward-only visas" || PASS=1
  RX_BEFORE=$(relay_rx_bytes) || PASS=1
  bulk_ping zb "$ZC_ZPR_ADDR" "zb's bulk transfer to zc completes through the relay" || PASS=1
  assert_relay_rx_rose "${RX_BEFORE:-0}" "the bulk transfer crosses the relay" || PASS=1

  echo "== 4. the block is lifted and the policy re-installed"
  # Counted before the unblock, so only the link's return matches below.
  ZB_TOPOLOGY=$(log_count zb.log "$TOPOLOGY")
  ZC_TOPOLOGY=$(log_count zc.log "$TOPOLOGY")
  ZB_UP=$(log_count zb.log "$REPORT_ZC_UP")
  ZC_UP=$(log_count zc.log "$REPORT_ZB_UP")
  VS_UP=$(log_count vs.log "$VS_LINK_UP")
  unblock_pair zb zc || PASS=1
  # The trigger for rule 13 until zl-zipline#268 (see the header).
  install_zode_policy "$ZODE_POLICY_BIN" || PASS=1
  wait_log_after 30 zb.log "$TOPOLOGY" "$ZB_TOPOLOGY" "zb receives topology again" || PASS=1
  wait_log_after 30 zc.log "$TOPOLOGY" "$ZC_TOPOLOGY" "zc receives topology again" || PASS=1
  assert_active_links 30 zb "$ZC_SUBSTRATE_ADDR" 1 "zb has its link to zc again (rule 13)" || PASS=1
  assert_active_links 10 zc "$ZB_SUBSTRATE_ADDR" 1 "zc has its link to zb again" || PASS=1
  wait_log_after 15 zb.log "$REPORT_ZC_UP" "$ZB_UP" "zb reports the zb-zc link up again" || PASS=1
  wait_log_after 15 zc.log "$REPORT_ZB_UP" "$ZC_UP" "zc reports the zb-zc link up again" || PASS=1
  wait_log_after 15 vs.log "$VS_LINK_UP" "$VS_UP" "the visa service routes over the zb-zc link again" || PASS=1
  # A new flow: zc has never pinged zb, so its first echo requests a visa,
  # and the visa service routes it over the direct link.
  zode_ping zc "$ZB_ZPR_ADDR" "zc reaches zb" || PASS=1
  RX_BEFORE=$(relay_rx_bytes) || PASS=1
  bulk_ping zc "$ZB_ZPR_ADDR" "zc's bulk transfer to zb completes" || PASS=1
  assert_relay_rx_flat "${RX_BEFORE:-0}" "the new flow's bulk transfer does not cross the relay" || PASS=1

  echo "== the whole run"
  # Only the previous-hop refusal: the counters may count requests that
  # were pending over the lost link (rule 9).
  for ZODE in relay zb zc
  do
    assert_no_log "$ZODE.log" "$PREV_HOP_REFUSED" "$ZODE refused no request from a previous hop" || PASS=1
  done
fi

zode_report "$PASS"
