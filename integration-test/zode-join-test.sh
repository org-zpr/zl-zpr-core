#!/usr/bin/env bash
#
# Zode join (zl-zipline#222, Zodes plan W3 and W4).
#
# A relay Zode docks the visa service. Zodes zb and zc have no visa service
# of their own and only an initial link to the relay (lib/zode_funcs.sh has
# the layout). Each must:
#   - receive exactly its own two visa-service bootstrap visas from the
#     relay (pd gate g60) -- never another Zode's;
#   - authenticate with the visa service through the relay;
# and then an application on zb reaches a service on zc under zb's own
# identity (W4): the ping leaves zb's TUN from zb's ZPR address, and policy
# allows only Zb to access PingableZc.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

zode_begin valkey.log vs.log relay.log adapter-vs.log zb.log zc.log

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
launch_zode_vs
launch_relay true

PASS=0
launch_vs_adapter || PASS=1

if [[ "$PASS" == 0 ]]; then
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" ca "$PREGEN/zb-rsa-key.pem"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" ca "$PREGEN/zc-rsa-key.pem"

  wait_registered 45 zb.log || PASS=1
  wait_registered 45 zc.log || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  # The hand-off: the relay sends each Zode only the entries topology gives
  # it for that Zode's CN, and each Zode installs exactly two.
  assert_log relay.log "handing 2 bootstrap visa\(s\) to zb" "the relay hands zb its two bootstrap visas" || PASS=1
  assert_log relay.log "handing 2 bootstrap visa\(s\) to zc" "the relay hands zc its two bootstrap visas" || PASS=1
  assert_log_count zb.log "installed handed-off bootstrap visa" 2 "zb installs exactly two handed-off visas" || PASS=1
  assert_log_count zc.log "installed handed-off bootstrap visa" 2 "zc installs exactly two handed-off visas" || PASS=1

  # Each joined Zode reaches the visa service through the relay.
  zode_ping zpr-zb zb "$VS_ZPR_ADDR" || PASS=1
  zode_ping zpr-zc zc "$VS_ZPR_ADDR" || PASS=1

  # W4: zb's application traffic reaches zc, across the relay.
  zode_ping zpr-zb zb "$ZC_ZPR_ADDR" || PASS=1
  zode_ping zpr-zc zc "$ZB_ZPR_ADDR" || PASS=1

  # Gap 7: each Zode on these paths binds a stream only for its visa's
  # previous hop. The pings above crossed the relay, so every StreamIdRequest
  # they needed passed that check; none may have been refused. (A request
  # from a link that is not the previous hop is refused in the ph unit
  # tests: no Zode here sends one.)
  for LOG in relay.log zb.log zc.log; do
    assert_no_log "$LOG" "$GAP7_REFUSAL" "no StreamIdRequest refused in $LOG" || PASS=1
  done
fi

zode_report "$PASS"
