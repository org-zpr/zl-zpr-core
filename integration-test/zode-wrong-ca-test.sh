#!/usr/bin/env bash
#
# Refused Zode links (zl-zipline#222: moved from #220, and the gap-5
# certificate-name check; Zodes plan W2).
#
# Next to a good Zode zb, which must join (so the refusals below are not an
# artefact of a broken set-up), two Zodes that the relay must refuse:
#   - zc, a Zode in the policy whose certificate is signed by another CA:
#     its certificate fails verification and it never links;
#   - zx, a certificate from the right CA with a CN that is in neither the
#     relay's topology nor its initial links: the relay closes the link
#     after keying, before Hello.
# Neither ever receives bootstrap visas or reaches the visa service.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

zode_begin valkey.log vs.log relay.log adapter-vs.log zb.log zc.log zx.log

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR" "zx:$ZX_SUBSTRATE_ADDR"
create_other_ca otherca
launch_zode_vs
launch_relay true

PASS=0
launch_vs_adapter || PASS=1

if [[ "$PASS" == 0 ]]; then
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" ca "$PREGEN/zb-rsa-key.pem"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" otherca "$PREGEN/zc-rsa-key.pem"
  # zx has no policy entry; any authentication key will do, it never gets
  # far enough to use it.
  launch_zode zx "$ZX_SUBSTRATE_ADDR" fd5a:5052::9 ca "$PREGEN/zc-rsa-key.pem"

  wait_registered 45 zb.log || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  # Give the refused Zodes as long as zb needed, and a few redials more.
  sleep 10

  assert_log relay.log "peer certificate is not signed by our CA; aborting handshake" "the relay refuses zc's certificate from another CA" || PASS=1
  assert_log relay.log "peer certificate CN .*zx.* is not in this Zode's topology; closing" "the relay closes zx's link: CN not allowed" || PASS=1

  for Z in zc zx
  do
    assert_no_log "$Z.log" "installed handed-off bootstrap visa" "$Z receives no bootstrap visas" || PASS=1
    assert_no_log "$Z.log" "registered VSS" "$Z never reaches the visa service" || PASS=1
  done
  assert_no_log relay.log "handing .* bootstrap visa\(s\) to (zc|zx)" "the relay hands nothing to zc or zx" || PASS=1
fi

zode_report "$PASS"
