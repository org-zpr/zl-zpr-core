#!/usr/bin/env bash
#
# Zode links (zl-zipline#250) and the relay join (zl-zipline#252),
# docs/ZODE_LINKS.md.
#
# A relay Zode (relay = true) docks the visa service. Zode zb has an initial
# link to the relay; zb is in the relay's topology. Zode zc has a
# certificate from the same CA and an initial link to the relay, but is in
# no policy.
#
# Scenarios, each checking the exact link count on both ends (no leaked or
# duplicate links):
#   1. zb joins (J1-J5, J11): one Active link at each end. The relay requests
#      zb's bootstrap visas and hands them off; zb starts with an empty visa
#      table, so it holds exactly those two (IDs from the visa service, not
#      the self-granted 1 and 2). zb authenticates, reports its link up,
#      registers its VSS and receives its topology. Its own VS-API visas
#      (J5a) supersede the bootstrap pair and its live session moves onto
#      them with no failed rebind.
#   2. zb restarts on the same address: the relay ends with one link to zb
#      (rule 5) and reports it up again; the restarted zb joins again with
#      fresh bootstrap visas (J6).
#   3. zc dials the relay: refused after keying, logged, no link (rule 3),
#      and the relay never asks the visa service for zc's visas.
#   4. The substrate between the relay and zb is blocked past the keep-alive
#      tolerance: the relay clears the link and reports zb down (rules 9,
#      10); zb's session breaks and it rejoins (J10), redialing with backoff
#      (rule 11). Unblocked, the link is back, the relay hands off new
#      bootstrap visas, and zb's session comes back.
#   5. A policy without the relay-zb link: the relay closes the link and
#      stops reporting it (rule 12), and zb's redials are refused (rule 3).
#      The policy with the link back lets zb's next redial in.
#   6. The relay cannot reach the visa service: it cannot get zb's bootstrap
#      visas, so it closes zb's link instead of handing off (J7).
#   7. The relay never dials (rule 4).
#
# Every Stream ID Request in the run crosses the relay-zb Zode link, in both
# directions: the join, the J11 rebinds, the VSS flow, the restart and the
# rejoin. Each is bound only if it comes from the visa's previous hop (gap
# 7, zl-zipline#253), so the run also shows that the check refuses none of
# them: no previous-hop refusal is logged on either Zode, and no Stream ID
# Request is refused at all until scenario 2 starts breaking links. After
# that some refusals are by design: a request pending over a lost link
# (rule 9), or the relay asking the restarted zb for a stream for a visa
# of the zb that crashed, which the visa service no longer has.
#
# Joins wait 20-30 s: the joiner's TCP dial to the visa service starts
# before the hand-off and relies on SYN retransmits, so it connects a few
# seconds after the bootstrap visas are installed.
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

# What the logs say (link_state.rs, zode_links.rs, bootstrap_handoff.rs,
# vs_worker.rs, vss_worker.rs, visa_table.rs).
ZB_ACCEPTED='accepted Zode link with peer CN Some\("zb"\)'
ZC_REFUSED='refusing Zode link with peer CN Some\("zc"\): unknown CN'
ZB_REFUSED='refusing Zode link with peer CN Some\("zb"\): unknown CN'
REPORT_ZB_UP='reported Zode link states to the visa service: \[.*zb=Up'
REPORT_ZB_DOWN='reported Zode link states to the visa service: \[.*zb=Down'
REPORT_WITHOUT_ZB='reported Zode link states to the visa service: \[\]'
DIAL='Started Zode link with .* as the dialer'
KEEPALIVE_LOST='failed to respond to keep-alive messages'
# The join (J2-J5).
REQUEST_ZB='requesting bootstrap visas for "zb"'
REQUEST_ZC='requesting bootstrap visas for "zc"'
HANDED_ZB='handed bootstrap visas \[[0-9]+, [0-9]+\] to "zb"'
REFUSED_ZB_J7='no bootstrap visas for "zb": .*closing the link \(J7\)'
INSTALLED='installed bootstrap visas \[[0-9]+, [0-9]+\] bound to the link'
GRANTED='node access granted to visa service'
REGISTERED='registered VSS'
TOPOLOGY='received topology update with [1-9][0-9]* links'
REPORT_RELAY_UP='reported Zode link states to the visa service: \[.*relay=Up'
REJOIN='rejoining \(J10\)'
# J11: a failed rebind (mgmt/node.rs rebind_failed).
REBIND_FAILED='its rebind onto visa [0-9]+ failed'
# Gap 7's refusal, PREV_HOP_REFUSED, is in lib/zode_funcs.sh.

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  echo "== 1. zb joins"
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  assert_active_links 20 relay "$ZB_SUBSTRATE_ADDR" 1 "the relay has one Active link to zb" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb has one Active link to the relay" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_UP" 0 "the relay reports zb up to the visa service" || PASS=1
  wait_log_after 10 relay.log "$REQUEST_ZB" 0 "the relay requests zb's bootstrap visas (J2)" || PASS=1
  wait_log_after 10 relay.log "$HANDED_ZB" 0 "the relay hands them off (J4)" || PASS=1
  HANDOFF=$(last_handoff_ids relay.log zb)
  assert_issued_ids "$HANDOFF" "the hand-off holds two visa-service IDs" || PASS=1
  # The relay's log shows message 146 queued, not received: wait for zb.
  wait_log_after 10 zb.log "$INSTALLED" 0 "zb installs the hand-off (J4)" || PASS=1
  assert_joiner_table zb.log "$HANDOFF" || PASS=1
  wait_log_after 30 zb.log "$GRANTED" 0 "zb authenticates over its bootstrap visas (J5)" || PASS=1
  wait_log_after 10 zb.log "$REPORT_RELAY_UP" 0 "zb reports its initial link up itself" || PASS=1
  wait_log_after 20 zb.log "$REGISTERED" 0 "zb registers its VSS" || PASS=1
  wait_log_after 20 zb.log "$TOPOLOGY" 0 "zb receives its topology" || PASS=1
  assert_superseded 20 zb "$HANDOFF" || PASS=1
  assert_no_log zb.log "$REJOIN" "zb has not rejoined" || PASS=1
  # Gap 7: the join, both directions and J11 ran under the previous-hop
  # check, and no Stream ID Request was refused on either Zode.
  assert_no_refusals relay zb || PASS=1

  echo "== 2. zb restarts on the same address"
  UP_REPORTS=$(log_count relay.log "$REPORT_ZB_UP")
  ACCEPTED=$(log_count relay.log "$ZB_ACCEPTED")
  HANDOFFS=$(log_count relay.log "$HANDED_ZB")
  REGISTRATIONS=$(log_count zb.log "$REGISTERED")
  kill_zode zb || PASS=1
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  wait_log_after 20 relay.log "$ZB_ACCEPTED" "$ACCEPTED" "the relay accepts the restarted zb" || PASS=1
  assert_active_links 10 relay "$ZB_SUBSTRATE_ADDR" 1 "the relay still has exactly one link to zb" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "the restarted zb has one link to the relay" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_UP" "$UP_REPORTS" "the relay reports zb up again" || PASS=1
  wait_log_after 10 relay.log "$HANDED_ZB" "$HANDOFFS" "the restarted zb gets a new hand-off (J6)" || PASS=1
  assert_new_ids "$(last_handoff_ids relay.log zb)" "$HANDOFF" "the new hand-off" || PASS=1
  HANDOFF=$(last_handoff_ids relay.log zb)
  wait_log_after 30 zb.log "$REGISTERED" "$REGISTRATIONS" "the restarted zb registers its VSS" || PASS=1
  assert_superseded 20 zb "$HANDOFF" || PASS=1

  echo "== 3. zc, not in the relay's topology, dials the relay"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/node-rsa-key.pem"
  wait_log_after 20 relay.log "$ZC_REFUSED" 0 "the relay refuses zc after keying: unknown CN" || PASS=1
  assert_active_links 0 relay "$ZC_SUBSTRATE_ADDR" 0 "the relay has no link to zc" || PASS=1
  assert_no_log relay.log "$REQUEST_ZC" "the relay never requests visas for zc" || PASS=1
  kill_zode zc || PASS=1

  echo "== 4. the substrate between the relay and zb is blocked"
  DOWN_REPORTS=$(log_count relay.log "$REPORT_ZB_DOWN")
  UP_REPORTS=$(log_count relay.log "$REPORT_ZB_UP")
  ZB_DIALS=$(log_count zb.log "$DIAL")
  REJOINS=$(log_count zb.log "$REJOIN")
  HANDOFFS=$(log_count relay.log "$HANDED_ZB")
  REGISTRATIONS=$(log_count zb.log "$REGISTERED")
  block_substrate zb
  wait_log_after 30 relay.log "$KEEPALIVE_LOST" 0 "the relay gives up on the silent link" || PASS=1
  assert_active_links 10 relay "$ZB_SUBSTRATE_ADDR" 0 "the relay cleared its link to zb" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_DOWN" "$DOWN_REPORTS" "the relay reports zb down" || PASS=1
  wait_log_after 20 zb.log "$REJOIN" "$REJOINS" "zb's session broke: it rejoins (J10)" || PASS=1
  # zb loses the link too and redials with backoff: 1, 2, 4 ... seconds.
  wait_log_after 30 zb.log "$DIAL" $((ZB_DIALS + 2)) "zb keeps redialing its initial link" || PASS=1
  unblock_substrate zb
  assert_active_links 40 relay "$ZB_SUBSTRATE_ADDR" 1 "the link is back, once" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb has one link to the relay again" || PASS=1
  wait_log_after 10 relay.log "$REPORT_ZB_UP" "$UP_REPORTS" "the relay reports zb up again" || PASS=1
  wait_log_after 10 relay.log "$HANDED_ZB" "$HANDOFFS" "the rejoin gets a new hand-off (J6)" || PASS=1
  assert_new_ids "$(last_handoff_ids relay.log zb)" "$HANDOFF" "the rejoin's hand-off" || PASS=1
  HANDOFF=$(last_handoff_ids relay.log zb)
  wait_log_after 30 zb.log "$REGISTERED" "$REGISTRATIONS" "zb's session is back: it registers its VSS again" || PASS=1
  assert_superseded 20 zb "$HANDOFF" || PASS=1

  echo "== 5. a policy without the relay-zb link"
  REFUSED=$(log_count relay.log "$ZB_REFUSED")
  EMPTY_REPORTS=$(log_count relay.log "$REPORT_WITHOUT_ZB")
  install_zode_policy zodes-unlinked.bin2 || PASS=1
  assert_active_links 20 relay "$ZB_SUBSTRATE_ADDR" 0 "the relay closes the removed link" || PASS=1
  wait_log_after 10 relay.log "$REPORT_WITHOUT_ZB" "$EMPTY_REPORTS" "the relay no longer reports zb" || PASS=1
  wait_log_after 40 relay.log "$ZB_REFUSED" "$REFUSED" "zb's redials are refused: unknown CN" || PASS=1
  install_zode_policy "$ZODE_POLICY_BIN" || PASS=1
  # Slow on purpose: the visa service applies this policy only after the
  # previous policy pass, which sends zb's VSS calls (set-services,
  # request-auths, ...) over the link it just removed and waits out a 10 s
  # timeout for each (up to about 50 s). Then zb's redial backoff (rule 11)
  # can add up to 30 s.
  assert_active_links 120 relay "$ZB_SUBSTRATE_ADDR" 1 "with the link back, zb's next redial gets in" || PASS=1
  assert_active_links 5 zb "$RELAY_SUBSTRATE_ADDR" 1 "zb has one link to the relay" || PASS=1

  echo "== 6. the relay cannot reach the visa service"
  REFUSALS=$(log_count relay.log "$REFUSED_ZB_J7")
  HANDOFFS=$(log_count relay.log "$HANDED_ZB")
  kill_zode zb || PASS=1
  block_substrate vs
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  wait_log_after 30 relay.log "$REFUSED_ZB_J7" "$REFUSALS" "the relay closes zb's link instead of handing off (J7)" || PASS=1
  if log_count_above relay.log "$HANDED_ZB" "$HANDOFFS"; then
    echo "ASSERTION FAILED: the relay handed zb bootstrap visas without the visa service"
    PASS=1
  else
    echo "assertion OK: no hand-off without the visa service"
  fi
  unblock_substrate vs

  echo "== 7. the relay never dials"
  assert_no_log relay.log "$DIAL" "the relay started no link as the dialer" || PASS=1
  assert_no_log relay.log "$REBIND_FAILED" "no rebind failed at the relay (J11)" || PASS=1
  assert_counter_zero relay "Rebind Failed" || PASS=1
  # Gap 7, over the whole run (zb.log spans every zb process).
  assert_no_log relay.log "$PREV_HOP_REFUSED" "the relay refused no request from a previous hop" || PASS=1
  assert_no_log zb.log "$PREV_HOP_REFUSED" "zb refused no request from a previous hop" || PASS=1
fi

zode_report "$PASS"
