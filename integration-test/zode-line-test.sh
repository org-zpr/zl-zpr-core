#!/usr/bin/env bash
#
# Three Zodes in a line, zb - relay - zc (zl-zipline#222, moved from #219;
# Zodes plan W1).
#
# zb and zc are not linked to each other, so their traffic crosses the
# relay. The relay is neither end of that flow, so the visa service gives it
# only forward-only visas for it. Two legs, each from a clean start:
#   1. relay `forwarding` on: zb and zc reach each other, and the relay
#      refuses nothing;
#   2. relay `forwarding` off: the relay refuses the forward-only visas and
#      logs it, and zb and zc cannot reach each other. They still join and
#      reach the visa service, whose visas end at the relay.
# That leg 2 refuses the very visas leg 1 needed shows the relay held only
# forward-only visas for the flow.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

REFUSAL="refusing forward-only visa .*forwarding is off on this node"

zode_begin \
  on/vs.log on/relay.log on/zb.log on/zc.log \
  off/vs.log off/relay.log off/zb.log off/zc.log

# Run one leg in subdirectory $1 with the relay's forwarding set to $1
# ("on" or "off"). Returns non-zero if any assertion fails.
function run_leg() {
  local LEG=$1 FORWARDING=false RESULT=0
  [[ "$LEG" == on ]] && FORWARDING=true

  echo "LEG: relay forwarding $LEG"
  mkdir "$LEG"
  cp ca.key ca.crt "$LEG"/
  pushd "$LEG" > /dev/null

  create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
  launch_zode_vs
  launch_relay "$FORWARDING"
  launch_vs_adapter || RESULT=1

  if [[ "$RESULT" == 0 ]]; then
    launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" ca "$PREGEN/zb-rsa-key.pem"
    launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" ca "$PREGEN/zc-rsa-key.pem"
    wait_registered 45 zb.log || RESULT=1
    wait_registered 45 zc.log || RESULT=1
  fi

  if [[ "$RESULT" == 0 ]]; then
    zode_ping zpr-zb zb "$VS_ZPR_ADDR" || RESULT=1
    if [[ "$LEG" == on ]]; then
      zode_ping zpr-zb zb "$ZC_ZPR_ADDR" || RESULT=1
      zode_ping zpr-zc zc "$ZB_ZPR_ADDR" || RESULT=1
      assert_no_log relay.log "$REFUSAL" "the relay refuses no forward-only visa" || RESULT=1
    else
      zode_no_ping zpr-zb zb "$ZC_ZPR_ADDR" || RESULT=1
      assert_log relay.log "$REFUSAL" "the relay refuses and logs the forward-only visa" || RESULT=1
    fi
  fi

  zode_stop_all
  popd > /dev/null
  return "$RESULT"
}

PASS=0
run_leg on || PASS=1
run_leg off || PASS=1

zode_report "$PASS"
