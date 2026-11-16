#!/usr/bin/env bash
#
# Two Zodes join through the relay at once (zl-zipline#254; Zodes plan W3,
# and W4 against the visa service), docs/ZODE_LINKS.md J1-J5 and J11.
#
# A relay Zode (relay = true) docks the visa service. Zodes zb and zc are
# both in the relay's topology (pregen/zodes-pair.zplc) and start together,
# each with an initial link to the relay. For each of them:
#   - the relay requests its bootstrap visas and hands them off (J2-J4):
#     two visa-service IDs, none of them the other joiner's;
#   - it starts with an empty visa table, so before it authenticates the
#     table holds only its own hand-off (J1, J4);
#   - it authenticates (J5), reports the relay link up, registers its VSS
#     and receives its topology, and its own VS-API visa supersedes the
#     forward bootstrap visa with no failed rebind (J5a, J11);
#   - it pings the visa service from its own ZPR address (W4).
# Every Stream ID Request in the run crosses a Zode link, so at the end no
# Zode has refused one, as not from the visa's previous hop (gap 7) or for
# any other reason.
#
# Not covered here: a restart, a rejoin and an unknown CN are
# zode-link-test.sh's; traffic between the joiners is zode-line-test.sh's.
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
launch_zode_vs
launch_relay

PASS=0
launch_vs_adapter || PASS=1

# What the logs say (bootstrap_handoff.rs, zode_links.rs, vs_worker.rs,
# vss_worker.rs).
INSTALLED='installed bootstrap visas \[[0-9]+, [0-9]+\] bound to the link'
GRANTED='node access granted to visa service'
REGISTERED='registered VSS'
TOPOLOGY='received topology update with [1-9][0-9]* links'
REPORT_RELAY_UP='reported Zode link states to the visa service: \[.*relay=Up'

# Check the join of Zode $1 (zb or zc), started with the other: its links,
# the relay's hand-off to it, its table before authenticating, and what it
# does once authenticated. Sets HANDOFF_<NAME> to its hand-off's IDs.
# Returns non-zero if any assertion fails.
function check_join() {
  local NAME=$1 RESULT=0 SUBSTRATE HANDOFF
  SUBSTRATE=${NAME^^}_SUBSTRATE_ADDR
  SUBSTRATE=${!SUBSTRATE}

  echo "== $NAME joins"
  assert_active_links 20 relay "$SUBSTRATE" 1 "the relay has one Active link to $NAME" || RESULT=1
  assert_active_links 5 "$NAME" "$RELAY_SUBSTRATE_ADDR" 1 "$NAME has one Active link to the relay" || RESULT=1
  wait_log_after 10 relay.log "reported Zode link states to the visa service: \[.*$NAME=Up" 0 \
    "the relay reports $NAME up to the visa service" || RESULT=1
  wait_log_after 10 relay.log "requesting bootstrap visas for \"$NAME\"" 0 \
    "the relay requests $NAME's bootstrap visas (J2)" || RESULT=1
  wait_log_after 10 relay.log "handed bootstrap visas \[[0-9]+, [0-9]+\] to \"$NAME\"" 0 \
    "the relay hands them off to $NAME (J4)" || RESULT=1
  HANDOFF=$(last_handoff_ids relay.log "$NAME")
  assert_issued_ids "$HANDOFF" "$NAME's hand-off holds two visa-service IDs" || RESULT=1
  wait_log_after 10 "$NAME.log" "$INSTALLED" 0 "$NAME installs its hand-off (J4)" || RESULT=1
  assert_joiner_table "$NAME.log" "$HANDOFF" || RESULT=1
  wait_log_after 30 "$NAME.log" "$GRANTED" 0 "$NAME authenticates over its bootstrap visas (J5)" || RESULT=1
  wait_log_after 10 "$NAME.log" "$REPORT_RELAY_UP" 0 "$NAME reports its initial link up itself" || RESULT=1
  wait_log_after 20 "$NAME.log" "$REGISTERED" 0 "$NAME registers its VSS" || RESULT=1
  wait_log_after 20 "$NAME.log" "$TOPOLOGY" 0 "$NAME receives its topology" || RESULT=1
  assert_superseded 20 "$NAME" "$HANDOFF" || RESULT=1

  printf -v "HANDOFF_${NAME^^}" '%s' "$HANDOFF"
  return "$RESULT"
}

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem"

  HANDOFF_ZB=""
  HANDOFF_ZC=""
  check_join zb || PASS=1
  check_join zc || PASS=1

  echo "== each joiner got its own hand-off"
  assert_new_ids "$HANDOFF_ZC" "$HANDOFF_ZB" "zc's hand-off (the other is zb's)" || PASS=1

  echo "== each joiner reaches the visa service (W4)"
  zode_ping zb "$VS_ZPR_ADDR" "zb pings the visa service" || PASS=1
  zode_ping zc "$VS_ZPR_ADDR" "zc pings the visa service" || PASS=1

  echo "== no Stream ID Request was refused"
  assert_no_refusals relay zb zc || PASS=1
fi

zode_report "$PASS"
