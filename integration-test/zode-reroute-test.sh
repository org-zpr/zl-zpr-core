#!/usr/bin/env bash
#
# A direct Zode link drops and the flow re-routes through the relay, then
# the link comes back and new flows go direct again: the netns version of
# the Zodes demo (zl-zipline#231; #251's acceptance, run in #254),
# docs/ZODE_LINKS.md rules 9, 10, 13, 13a, 14 and 15,
# and F3, F4 and F6. It also runs the visa service's bounded re-proposal of
# a direct link reported down (zl-zipline#268, visaservice#71).
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
#   3. The substrate between zb and zc is blocked, and stays blocked for the
#      whole step; both still reach the relay. Each end gives up on the
#      silent link, clears it (rule 9) and reports it down (rule 10); losing
#      the link revokes the flow's visas locally (F3), and the visa service
#      revokes them too (rule 15, F4). The Zodes do not redial by themselves
#      (rule 10): the visa service proposes the link to both ends again
#      LINK_REPROPOSE_DELAY (5 s) after the first down report (rule 13).
#      zb's one attempt cannot get through the block, so zb reports the link
#      failed, and the visa service leaves the pair out of topology (rule
#      13a). zb's next echo finds no visa and requests one (F6): the new
#      route crosses the relay, which now inserts forward-only visas, and
#      the ping succeeds again. The same bulk transfer now raises the
#      relay's received bytes. By the end of the step, well past another
#      delay, the link has been proposed again exactly once: the bound.
#   4. The block is lifted. The failed mark holds until something about the
#      pair changes (rule 13a; a policy install is not such a change), so
#      zc restarts. Its new session clears the mark and the visa service
#      proposes the link again. zb dials zc, both report the link up, and
#      the visa service routes over it. The restarted zc has no visa yet,
#      so its flow to zb is new: its bulk transfer leaves the relay's
#      received bytes flat again (only new visas take the direct link:
#      docs/ROUTING.md, Design decisions, "Link down revokes; link up does
#      not").
#   5. A blip heals by itself. The link is blocked until both ends report
#      it down, then unblocked at once. With no policy install and no
#      restart, the visa service proposes it again, zb dials zc within its
#      link-up window, and both report it up. This holds only for an outage
#      that clears within about LINK_REPROPOSE_DELAY + LINK_UP_WINDOW
#      (5 s + 10 s) of the first down report; a longer one ends as step 3.
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
REPORT_ZC_FAILED='reported Zode link states to the visa service: \[.*zc=Failed'
# The visa service's two lines for a down direct link (vsapi_worker.rs
# repropose_link_after_down) and its rule-13a mark (topology_mgr.rs).
VS_REPROPOSED='proposing link .* again after a down report'
VS_FAILED_PAIR='reported failed; left out of topology'
# Logged on every policy install (admin_service.rs).
VS_POLICY_INSTALL='policy updated successfully'

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
  VS_REPROPOSALS=$(log_count vs.log "$VS_REPROPOSED")
  VS_FAILED=$(log_count vs.log "$VS_FAILED_PAIR")
  ZB_FAILED=$(log_count zb.log "$REPORT_ZC_FAILED")
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
  # The visa service's one retry (rules 10 and 13), LINK_REPROPOSE_DELAY
  # after the first down report; zb's attempt fails within its
  # LINK_UP_WINDOW, and rule 13a marks the pair.
  wait_log_after 20 vs.log "$VS_REPROPOSED" "$VS_REPROPOSALS" \
    "the visa service proposes the zb-zc link again after the down report" || PASS=1
  wait_log_after 30 zb.log "$REPORT_ZC_FAILED" "$ZB_FAILED" "zb's attempt fails and it reports the link failed" || PASS=1
  wait_log_after 10 vs.log "$VS_FAILED_PAIR" "$VS_FAILED" "the visa service leaves the zb-zc pair out of topology (rule 13a)" || PASS=1
  # The link is already down here, so the bound is the revoke and zb's
  # re-request (F6): 20 one-second warm-up echoes, then five that must all
  # be answered.
  zode_ping zb "$ZC_ZPR_ADDR" "zb reaches zc again, through the relay" 20 || PASS=1
  wait_log_after 10 relay.log "$FORWARD_ONLY" "$FORWARD_ONLY_BEFORE" \
    "the relay now carries the flow on forward-only visas" || PASS=1
  RX_BEFORE=$(relay_rx_bytes) || PASS=1
  bulk_ping zb "$ZC_ZPR_ADDR" "zb's bulk transfer to zc completes through the relay" || PASS=1
  assert_relay_rx_rose "${RX_BEFORE:-0}" "the bulk transfer crosses the relay" || PASS=1
  # The pings above span well over another LINK_REPROPOSE_DELAY since the
  # failed report, so a second retry would have shown by now.
  assert_log_count vs.log "$VS_REPROPOSED" $((VS_REPROPOSALS + 1)) \
    "the visa service proposed the link again exactly once (rule 13a bounds it)" || PASS=1

  echo "== 4. the block is lifted and zc restarts"
  # Counted before the unblock, so only the link's return matches below.
  ZB_TOPOLOGY=$(log_count zb.log "$TOPOLOGY")
  ZC_TOPOLOGY=$(log_count zc.log "$TOPOLOGY")
  ZB_UP=$(log_count zb.log "$REPORT_ZC_UP")
  ZC_UP=$(log_count zc.log "$REPORT_ZB_UP")
  VS_UP=$(log_count vs.log "$VS_LINK_UP")
  unblock_pair zb zc || PASS=1
  # The pair change rule 13a waits for: zc's new session clears the mark
  # and the visa service proposes the link to both ends again.
  kill_zode zc || PASS=1
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem"
  wait_log_after 45 zc.log "$TOPOLOGY" "$ZC_TOPOLOGY" "the restarted zc joins and receives its topology" || PASS=1
  wait_log_after 30 zb.log "$TOPOLOGY" "$ZB_TOPOLOGY" "zb receives topology again" || PASS=1
  assert_active_links 30 zb "$ZC_SUBSTRATE_ADDR" 1 "zb has its link to zc again (rule 13)" || PASS=1
  assert_active_links 10 zc "$ZB_SUBSTRATE_ADDR" 1 "zc has its link to zb again" || PASS=1
  wait_log_after 15 zb.log "$REPORT_ZC_UP" "$ZB_UP" "zb reports the zb-zc link up again" || PASS=1
  wait_log_after 15 zc.log "$REPORT_ZB_UP" "$ZC_UP" "zc reports the zb-zc link up again" || PASS=1
  wait_log_after 15 vs.log "$VS_LINK_UP" "$VS_UP" "the visa service routes over the zb-zc link again" || PASS=1
  # A new flow: the restarted zc holds no visa, so its first echo requests
  # one, and the visa service routes it over the direct link.
  zode_ping zc "$ZB_ZPR_ADDR" "zc reaches zb" || PASS=1
  RX_BEFORE=$(relay_rx_bytes) || PASS=1
  bulk_ping zc "$ZB_ZPR_ADDR" "zc's bulk transfer to zb completes" || PASS=1
  assert_relay_rx_flat "${RX_BEFORE:-0}" "the new flow's bulk transfer does not cross the relay" || PASS=1

  echo "== 5. a blip: the link drops and comes back by itself"
  ZB_LOST=$(log_count zb.log "$KEEPALIVE_LOST")
  ZB_DOWN=$(log_count zb.log "$REPORT_ZC_DOWN")
  ZC_DOWN=$(log_count zc.log "$REPORT_ZB_DOWN")
  VS_DOWN=$(log_count vs.log "$VS_LINK_DOWN")
  VS_REPROPOSALS=$(log_count vs.log "$VS_REPROPOSED")
  ZB_UP=$(log_count zb.log "$REPORT_ZC_UP")
  ZC_UP=$(log_count zc.log "$REPORT_ZB_UP")
  VS_UP=$(log_count vs.log "$VS_LINK_UP")
  VS_INSTALLS=$(log_count vs.log "$VS_POLICY_INSTALL")
  block_pair zb zc
  wait_log_after 30 zb.log "$KEEPALIVE_LOST" "$ZB_LOST" "zb gives up on the silent link" || PASS=1
  wait_log_after 10 zb.log "$REPORT_ZC_DOWN" "$ZB_DOWN" "zb reports the zb-zc link down" || PASS=1
  wait_log_after 10 zc.log "$REPORT_ZB_DOWN" "$ZC_DOWN" "zc reports the zb-zc link down" || PASS=1
  wait_log_after 10 vs.log "$VS_LINK_DOWN" "$VS_DOWN" "the visa service stops routing over the zb-zc link" || PASS=1
  # At once: the outage must clear inside LINK_REPROPOSE_DELAY +
  # LINK_UP_WINDOW of the first down report (see the header).
  unblock_pair zb zc || PASS=1
  wait_log_after 20 vs.log "$VS_REPROPOSED" "$VS_REPROPOSALS" \
    "the visa service proposes the zb-zc link again, with no install or restart" || PASS=1
  wait_log_after 20 zb.log "$REPORT_ZC_UP" "$ZB_UP" "zb reports the zb-zc link up again" || PASS=1
  wait_log_after 10 zc.log "$REPORT_ZB_UP" "$ZC_UP" "zc reports the zb-zc link up again" || PASS=1
  wait_log_after 10 vs.log "$VS_LINK_UP" "$VS_UP" "the visa service routes over the zb-zc link again" || PASS=1
  assert_active_links 5 zb "$ZC_SUBSTRATE_ADDR" 1 "zb has its link to zc again" || PASS=1
  assert_log_count vs.log "$VS_POLICY_INSTALL" "$VS_INSTALLS" "no policy was installed during the blip" || PASS=1

  echo "== the whole run"
  # Only the previous-hop refusal: the counters may count requests that
  # were pending over the lost link (rule 9).
  for ZODE in relay zb zc
  do
    assert_no_log "$ZODE.log" "$PREV_HOP_REFUSED" "$ZODE refused no request from a previous hop" || PASS=1
  done
fi

zode_report "$PASS"
