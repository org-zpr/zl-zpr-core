#!/usr/bin/env bash
#
# A Zode whose certificate comes from another CA is refused (zl-zipline#254;
# Zodes plan W2), docs/ZODE_LINKS.md rule 3 and SECURITY_MODEL.md.
#
# zb and zc are both in the relay's topology (pregen/zodes-pair.zplc), each
# with an initial link to the relay. zb's certificate is signed by the test
# CA, and zb joins: it is the control, so zc's refusal cannot be an artefact
# of a broken set-up. zc's certificate is signed by another CA, so the
# relay's Noise handshake refuses it before any link exists. zc's own
# --ca-file is the test CA, so zc accepts the relay's certificate and it is
# the relay that judges zc's (and not the other way round).
#   - The relay logs that zc's certificate is not signed by its CA, and no
#     link to zc exists at either end, however often zc redials.
#   - The relay never asks the visa service for zc's bootstrap visas, and
#     zc never installs a hand-off or registers with the visa service.
#   - zb's join is unaffected: it registers, its own VS-API visa supersedes
#     its bootstrap visa, and neither the relay nor zb refuses a Stream ID
#     Request.
#
# Not covered: a certificate from the right CA whose CN is in no policy;
# zode-link-test.sh scenario 3 covers it.
#
# Joins wait 20-30 s: see zode-link-test.sh.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

ZODE_POLICY_BIN=zodes-pair.bin2
zode_begin

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
create_other_ca otherca
launch_zode_vs
launch_relay

PASS=0
launch_vs_adapter || PASS=1

# What the logs say (km_noise.rs, peer_mgmt.rs, bootstrap_handoff.rs,
# vs_worker.rs).
WRONG_CA='peer certificate is not signed by our CA'
DIAL='Started Zode link with .* as the dialer'
REQUEST_ZC='requesting bootstrap visas for "zc"'
HANDED_ZB='handed bootstrap visas \[[0-9]+, [0-9]+\] to "zb"'
INSTALLED='installed bootstrap visas'
REGISTERED='registered VSS'

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem" otherca

  echo "== zb, signed by the test CA, joins"
  wait_log_after 30 relay.log "$HANDED_ZB" 0 "the relay hands zb its bootstrap visas" || PASS=1
  HANDOFF=$(last_handoff_ids relay.log zb)
  wait_log_after 30 zb.log "$REGISTERED" 0 "zb registers its VSS" || PASS=1
  assert_superseded 20 zb "$HANDOFF" || PASS=1

  echo "== zc, signed by another CA, is refused"
  wait_log_after 20 relay.log "$WRONG_CA" 0 "the relay refuses zc's certificate from another CA" || PASS=1
  # zc redials with backoff (1, 2, 4 ... s): wait for three more dials, so
  # the negatives below have had several chances to go wrong.
  wait_log_after 30 zc.log "$DIAL" 3 "zc keeps redialing the relay" || PASS=1
  assert_active_links 0 relay "$ZC_SUBSTRATE_ADDR" 0 "the relay has no link to zc" || PASS=1
  assert_active_links 0 zc "$RELAY_SUBSTRATE_ADDR" 0 "zc has no link to the relay" || PASS=1
  assert_no_log relay.log "$REQUEST_ZC" "the relay never requests visas for zc" || PASS=1
  assert_no_log zc.log "$INSTALLED" "zc never installs bootstrap visas" || PASS=1
  assert_no_log zc.log "$REGISTERED" "zc never registers with the visa service" || PASS=1

  echo "== no Stream ID Request was refused"
  assert_no_refusals relay zb || PASS=1
fi

zode_report "$PASS"
