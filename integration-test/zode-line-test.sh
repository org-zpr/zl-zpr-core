#!/usr/bin/env bash
#
# Three Zodes in a line, zb - relay - zc (zl-zipline#254; Zodes plan W1
# and W4), docs/ZODE_LINKS.md F1, F2 and F8.
#
# The relay is linked to zb and to zc, and zb and zc are not linked to each
# other (pregen/zodes-pair.zplc), so their traffic crosses the relay. The
# relay is neither end of that flow: the visa service gives it forward-only
# visas for it. The relay's `forwarding` setting decides whether it accepts
# them. It is a `ph` setting, so changing it means a restart, and a
# restarted Zode refuses its first Stream ID Requests (zl-zipline#262);
# instead each leg runs from a clean start, in its own subdirectory:
#   1. forwarding on: zb pings zc and zc pings zb. The policy allows only
#      Zb -> PingableZc and Zc -> PingableZb, so a reply shows the traffic
#      carried the sender's own identity (W4). The relay inserted
#      forward-only visas, so it carried the flow (W1). No Zode refused a
#      Stream ID Request, and the relay refused no forward-only visa.
#   2. forwarding off: zb and zc still join and ping the visa service,
#      whose visas end at the relay. zb cannot reach zc, and the relay logs
#      that it refuses the forward-only visas. No Zode refused a Stream ID
#      Request as not from the visa's previous hop.
#
# Joins wait 20-30 s: see zode-link-test.sh.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

ZODE_POLICY_BIN=zodes-pair.bin2
zode_begin

# What the logs say (visa_table.rs, visa_mgmt.rs, vss_rpc.rs).
FORWARD_ONLY='Visa inserted into VisaTable ID: [0-9]+, Type: ForwardOnly'
FORWARDING_OFF='refusing forward-only visa .*: forwarding is off on this node'
# A join is complete once the visa service has reached the Zode's VSS and
# sent it topology.
TOPOLOGY='received topology update with [1-9][0-9]* links'

# Run one leg in subdirectory $1 ("on" or "off"), with the relay's
# forwarding on or off: start everything, join zb and zc, run the leg's
# checks, then stop everything. Returns non-zero if any assertion fails.
function run_leg() {
  local LEG=$1 RESULT=0 FORWARDING=false
  [[ "$LEG" == on ]] && FORWARDING=true

  echo "== leg: the relay's forwarding is $LEG"
  mkdir "$LEG"
  cp ca.key ca.crt "$LEG"/
  pushd "$LEG" > /dev/null

  create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
  launch_zode_vs
  launch_relay "$FORWARDING"
  launch_vs_adapter || RESULT=1

  if [[ "$RESULT" == 0 ]]; then
    launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
    launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem"
    wait_log_after 45 zb.log "$TOPOLOGY" 0 "zb joins and receives its topology" || RESULT=1
    wait_log_after 45 zc.log "$TOPOLOGY" 0 "zc joins and receives its topology" || RESULT=1
  fi

  if [[ "$RESULT" == 0 && "$LEG" == on ]]; then
    zode_ping zb "$ZC_ZPR_ADDR" "zb reaches zc through the relay" || RESULT=1
    zode_ping zc "$ZB_ZPR_ADDR" "zc reaches zb through the relay" || RESULT=1
    wait_log_after 10 relay.log "$FORWARD_ONLY" 0 "the relay carries the flow on forward-only visas" || RESULT=1
    assert_no_log relay.log "$FORWARDING_OFF" "the relay refuses no forward-only visa" || RESULT=1
    assert_no_refusals relay zb zc || RESULT=1
  elif [[ "$RESULT" == 0 ]]; then
    zode_ping zb "$VS_ZPR_ADDR" "zb reaches the visa service" || RESULT=1
    zode_ping zc "$VS_ZPR_ADDR" "zc reaches the visa service" || RESULT=1
    zode_no_ping zb "$ZC_ZPR_ADDR" "zb cannot reach zc" || RESULT=1
    wait_log_after 10 relay.log "$FORWARDING_OFF" 0 "the relay refuses the forward-only visas" || RESULT=1
    assert_no_log relay.log "$FORWARD_ONLY" "the relay holds no forward-only visa" || RESULT=1
    assert_no_log relay.log "$PREV_HOP_REFUSED" "the relay refused no request from a previous hop" || RESULT=1
    # The relay's Stream ID Request Rejected counter is not checked in this
    # leg: refusing to carry zb-zc traffic is what the leg is for, so a
    # request it cannot bind may be refused there by design. zb and zc
    # refuse nothing.
    assert_no_refusals zb zc || RESULT=1
  fi

  zode_stop_all
  popd > /dev/null
  return "$RESULT"
}

PASS=0
echo "TEST STARTING"
run_leg on || PASS=1
run_leg off || PASS=1

zode_report "$PASS"
