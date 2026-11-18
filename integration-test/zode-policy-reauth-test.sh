#!/usr/bin/env bash
#
# Policy-install re-authentication on Zodes (zipline#124, umbrella #118;
# ported from one-node-policy-reauth-test.sh by zl-zipline#234).
#
# Every policy install obliges every connected actor to re-authenticate
# under the new policy generation (vinst) within the visa service's
# `reauth_deadline`, and whoever cannot is disconnected (zipline#123). On
# Zodes every actor is a Zode: a node with its own actor. The relay and the
# visa service run as in zode-link-test.sh, and zb and zc join through the
# relay (pregen/zodes-policy-reauth.zpl). They cover both ways a Zode
# answers the visa service's requestAuthentication:
#   - zb is DEVICE-ONLY: nobody logs in on it, so it re-authenticates the
#     node in place with its bootstrap key (zipline#121, K2). The relay
#     does the same.
#   - zc has a user logged in through a resident `ph-cli auth-agent`, so it
#     answers with a silent renewal of that login (zl-zipline#233, g116
#     q3): its bootstrap signature plus an OIDC token the agent refreshes
#     over the back channel.
#
# Legs:
#
#   1. Device survival. Install the same policy three times under a
#      continuous ping on zc's user flow to zb. Assert: not one ping is
#      lost; the relay and zb each re-authenticate in place exactly once
#      per install, and zc renews its login exactly once per install and
#      never re-authenticates in place (which would drop the login);
#      nothing is refused.
#   2. OIDC survival. One more install. Assert: zc's renewal is a
#      back-channel refresh (a new `POST /token`, NO new `GET /auth`: the
#      user is never re-prompted), the agent stays resident, traffic
#      flows; every obligation is satisfied and pruned, nobody revoked.
#   3. zb's key removed. Install a variant lacking zb's bootstrap key.
#      Assert: zb PRESENTS its key and is REFUSED (the failure is exercised
#      end to end, zipline#104), the sweep disconnects zb within
#      reauth_deadline + one sweep period, and zc is unaffected.
#   4. zc's key removed. Install a variant lacking zc's key (and zb's).
#      Assert: zc's renewal is refused although its user is still logged
#      in, its fallback in-place re-authentication is refused too, and the
#      sweep disconnects zc within the same bound; the relay stays.
#
# The OIDC lifetime in zodes-policy-reauth.zplc is LONG (3600 s), so the
# login's clock-driven renewal cannot fire inside the run: every
# re-authentication observed here is install-driven. `reauth_deadline` is
# a visa-service setting (vs-config.toml), set to 60 s, so the disconnect
# legs wait out 60 s + one 30 s sweep period + slack rather than the 300 s
# default.
#
# The run takes several minutes: legs 3 and 4 each wait out a real
# reauth-deadline clock that cannot be fast-forwarded from outside.
#
set -euo pipefail

# vss_rpc=DEBUG: the Zodes log the identity-provider list they get over VSS.
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO vss_rpc=DEBUG}

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

# The base policy and its two key-removal variants (legs 3 and 4). All three
# compile the same zodes-policy-reauth.zpl: the RULES never change, so any
# disconnection the variants cause comes from the failed re-authentication,
# not from a rule change.
ZODE_POLICY_BIN=zodes-policy-reauth.bin2
POLICY_NO_ZB_BIN=zodes-policy-reauth-no-zb.bin2
POLICY_NO_ZC_BIN=zodes-policy-reauth-no-zc.bin2

# What the vs-config sets `reauth_deadline` to: how long a connected actor
# has, after an install, to re-authenticate before the sweep disconnects it.
REAUTH_DEADLINE=60

# How long to wait for the re-authentications of one install to land. They
# complete in seconds (the fan-out is immediate and the netns has no real
# latency); generous for slow CI runners.
REAUTH_WAIT=60

# How long the disconnect legs allow the sweep to act, measured FROM THE
# POLICY INSTALL: the deadline plus one sweep period (MIN_VISA_LIFETIME,
# 30 s), plus a small slack for the install RPC and log flushing. The wait
# is anchored at the install, not started fresh after the refusal check: a
# fresh wait on top of the earlier ones would pass disconnections far
# beyond the configured bound.
SWEEP_PERIOD=30
REVOKE_SLACK=15

# What the logs say. ph: vss_worker.rs (in-place re-authentication, K2) and
# zode_login.rs; the visa service: vsapi_worker.rs, auth_sweep.rs and
# connection_control.rs.
REGISTERED='registered VSS'
IDP_LIST='received services update with [1-9]'
LOGGED_IN="Zode login: logged in with $(ere_escape "$IDP_ISSUER")"
SELF_REAUTH_OK='self re-authentication with the visa service succeeded'
SELF_REAUTH_FAILED='self re-authentication with the visa service failed'
POLICY_RENEWAL='Zode login: policy re-authentication answered with a renewal'
NO_POLICY_RENEWAL='Zode login: no renewal for the policy re-authentication'
# The visa service logs the node's CN as an Option. It logs zc's login too.
ZC_REAUTHORIZED="reauthorized node Some\\(\"zc\"\\) at address $(ere_escape "$ZC_ZPR_ADDR") "
ZC_REAUTH_REFUSED="reauthorize failed for actor $(ere_escape "$ZC_ZPR_ADDR") "
ZB_AUTH_REFUSED='authentication failed for zb: '
PRUNED='satisfied by all connected actors, pruning'
SWEEP_DISCONNECT='reauth sweep: node .* by the deadline; disconnecting it'

# The two IdP endpoints the OIDC leg counts in the fake IdP's log. A silent
# renewal is a back-channel `grant_type=refresh_token` POST to /token; any
# GET /auth after the login means the user was re-prompted.
AUTH_REQUEST='"GET /auth'
TOKEN_REQUEST='"POST /token'

# Seconds left until the disconnect bound for an install made at $1 (a
# $SECONDS snapshot taken just before the install): the reauth deadline,
# plus one sweep period, plus REVOKE_SLACK. May be <= 0 if the checks in
# between already overran the bound.
function revoke_budget() {
  echo $(( $1 + REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK - SECONDS ))
}

# Wait for the sweep to disconnect Zode $1 (its ZPR address $2) within the
# bound for the install made at $3: the sweep's log line and the visa
# service's Admin disconnect of it.
function assert_swept() {
  local BUDGET
  BUDGET=$(revoke_budget "$3")
  if (( BUDGET <= 0 )); then
    echo "ASSERTION FAILED: the disconnect bound ($((REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK))s from the install) elapsed before this check ran"
    return 1
  fi
  wait_log_after "$BUDGET" vs.log \
    "reauth sweep: node $(ere_escape "$2") did not re-authenticate under vinst .* by the deadline; disconnecting it" 0 \
    "the sweep disconnects $1 within the bound" || return 1
  echo "(found $(( SECONDS - $3 ))s after the install; the bound is $((REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK))s)"
  wait_log_after 10 vs.log "disconnect actor at $(ere_escape "$2") for reason Admin" 0 \
    "the visa service records an Admin disconnect of $1"
}

enter_test_namespace "$@"

zode_begin

for P in "$POLICY_NO_ZB_BIN" "$POLICY_NO_ZC_BIN"
do
  if [ ! -e "$PREGEN/$P" ]; then
    echo "required file not found: $PREGEN/$P"
    exit 1
  fi
done

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
create_idp_cert

# The stock vs-config plus the short reauth deadline this test waits out
# (the appended key stays inside the [core] table). launch_zode_vs keeps it.
emit_vs_config ca vs.zpr > vs-config.toml
echo "reauth_deadline = $REAUTH_DEADLINE" >> vs-config.toml

PASS=0
# The relay's instance only serves the visa service's JWKS refresh; zc's
# mints the token of the user who logs in on zc.
launch_zode_idp relay user-vs-unused || PASS=1
launch_zode_idp zc user-zc || PASS=1
launch_relay || PASS=1
launch_zode_vs || PASS=1

if [[ "$PASS" == 0 ]]; then
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem"
  wait_log_after 60 zb.log "$REGISTERED" 0 "zb joins and registers its VSS" || PASS=1
  wait_log_after 60 zc.log "$REGISTERED" 0 "zc joins and registers its VSS" || PASS=1
  wait_log_after 30 zc.log "$IDP_LIST" 0 "zc has the identity-provider list" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  echo "== BASELINE: zc's user logs in through a resident auth agent"
  start_zode_login zc auth-agent agent.out || PASS=1
  AGENT_PID=$LOGIN_PID
  wait_log_after 30 zc.log "$LOGGED_IN" 0 "the agent logs zc's user in" || PASS=1
  zode_ping zb "$VS_ZPR_ADDR" "zb's device flow to the visa service works" 10 || PASS=1
  zode_ping zc "$VS_ZPR_ADDR" "zc's device flow to the visa service works" 10 || PASS=1
  zode_ping zc "$ZB_ZPR_ADDR" "zc's user flow to zb works" 20 || PASS=1
fi

#
# Leg 1: three installs of the same policy under a continuous ping.
#
# Re-installing the same .bin2 is not a no-op: every hot install advances
# the policy generation (vinst) and records a re-authentication obligation
# for it (zipline#123). Keeping the content identical isolates the
# machinery under test: nothing about the rules changes, so any disturbance
# can only come from the re-authentication path.
#
if [[ "$PASS" == 0 ]]; then
  echo "== 1. device survival across three policy installs"

  # The assertion is ZERO loss: the in-place re-authentication keeps the
  # Zodes' visas and links (zipline#121), and zc's renewal keeps its user.
  ZC_REAUTHS=$(log_count vs.log "$ZC_REAUTHORIZED")
  in_ns zpr-zc ping -n -i 0.2 "$ZB_ZPR_ADDR" > cont-ping.log 2>&1 &
  sleep 2

  for I in 1 2 3
  do
    install_zode_policy "$ZODE_POLICY_BIN" || { PASS=1; break; }
    # Counts ratchet: install I is done when the I-th line of each kind is
    # in the log, so the exact counts below can give one of each kind to
    # each install.
    wait_log_after "$REAUTH_WAIT" relay.log "$SELF_REAUTH_OK" $((I - 1)) \
      "install $I: the relay re-authenticates in place" || PASS=1
    wait_log_after "$REAUTH_WAIT" zb.log "$SELF_REAUTH_OK" $((I - 1)) \
      "install $I: zb re-authenticates in place with its bootstrap key" || PASS=1
    wait_log_after "$REAUTH_WAIT" zc.log "$POLICY_RENEWAL" $((I - 1)) \
      "install $I: zc answers with a renewal of its login" || PASS=1
    wait_log_after "$REAUTH_WAIT" vs.log "$ZC_REAUTHORIZED" $((ZC_REAUTHS + I - 1)) \
      "install $I: the visa service reauthorizes zc" || PASS=1
    [[ "$PASS" == 0 ]] || break
  done

  # Stop the continuous ping and give it a moment to print its summary.
  pkill_own -SIGINT -f "ping -n -i 0.2 $ZB_ZPR_ADDR" || true
  sleep 2
fi

if [[ "$PASS" == 0 ]]; then
  # Exactly one of each per install: one more would mean that something
  # other than the installs drove a re-authentication.
  assert_log_count relay.log "$SELF_REAUTH_OK" 3 "the relay re-authenticated exactly once per install" || PASS=1
  assert_log_count zb.log "$SELF_REAUTH_OK" 3 "zb re-authenticated exactly once per install" || PASS=1
  assert_log_count zc.log "$POLICY_RENEWAL" 3 "zc renewed exactly once per install" || PASS=1
  assert_no_log zc.log "$SELF_REAUTH_OK" "zc never re-authenticated in place, which would drop its login" || PASS=1
  assert_no_log vs.log 'reauthorize failed|authentication failed for' "the visa service refused nobody" || PASS=1

  PING_TX=$(sed -nE 's/^([0-9]+) packets transmitted.*/\1/p' cont-ping.log)
  PING_RX=$(sed -nE 's/^[0-9]+ packets transmitted, ([0-9]+) received.*/\1/p' cont-ping.log)
  if [[ -z "$PING_TX" || -z "$PING_RX" ]] || (( PING_TX == 0 )); then
    echo "ASSERTION FAILED: the continuous ping printed no summary:"
    tail -n 5 cont-ping.log || true
    PASS=1
  elif (( PING_RX != PING_TX )); then
    echo "ASSERTION FAILED: the continuous ping lost packets across the installs: $PING_RX/$PING_TX"
    PASS=1
  else
    echo "assertion OK: the continuous ping lost nothing across three installs ($PING_RX/$PING_TX)"
  fi
fi

#
# Leg 2: one more install; zc's renewal is a SILENT refresh.
#
if [[ "$PASS" == 0 ]]; then
  echo "== 2. OIDC survival: the renewal is a back-channel refresh"
  AUTH_BEFORE=$(log_count idp-zc.log "$AUTH_REQUEST")
  TOKEN_BEFORE=$(log_count idp-zc.log "$TOKEN_REQUEST")
  install_zode_policy "$ZODE_POLICY_BIN" || PASS=1
  wait_log_after "$REAUTH_WAIT" zc.log "$POLICY_RENEWAL" 3 "zc answers the fourth install with a renewal" || PASS=1
  wait_log_after "$REAUTH_WAIT" zb.log "$SELF_REAUTH_OK" 3 "zb re-authenticates in place again" || PASS=1
  wait_log_after "$REAUTH_WAIT" relay.log "$SELF_REAUTH_OK" 3 "the relay re-authenticates in place again" || PASS=1
  assert_log_count idp-zc.log "$AUTH_REQUEST" "$AUTH_BEFORE" "zc's user was not re-prompted (no new GET /auth)" || PASS=1
  if (( $(log_count idp-zc.log "$TOKEN_REQUEST") > TOKEN_BEFORE )); then
    echo "assertion OK: the agent refreshed the token over the back channel (new POST /token)"
  else
    echo "ASSERTION FAILED: zc's IdP saw no back-channel refresh (POST /token stayed at $TOKEN_BEFORE)"
    PASS=1
  fi
  if kill -0 "$AGENT_PID" 2> /dev/null; then
    echo "assertion OK: the auth agent is still resident"
  else
    echo "ASSERTION FAILED: the auth agent exited during the installs:"
    cat agent.out
    PASS=1
  fi
  zode_ping zc "$ZB_ZPR_ADDR" "zc's user flow to zb still works after four installs" || PASS=1

  # Every obligation so far (one per install) was satisfied by every
  # connected actor and pruned, and nobody was disconnected.
  wait_log_after 90 vs.log "$PRUNED" 3 "the sweep pruned all four satisfied obligations" || PASS=1
  assert_no_log vs.log "$SWEEP_DISCONNECT" "nobody was disconnected in the survival legs" || PASS=1
fi

#
# Leg 3: zb's bootstrap key removed: zb is disconnected, zc is unaffected.
#
if [[ "$PASS" == 0 ]]; then
  echo "== 3. a policy without zb's bootstrap key"
  # The deadline clock starts at the install.
  LEG3_INSTALL_TS=$SECONDS
  install_zode_policy "$POLICY_NO_ZB_BIN" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  # End to end (the zipline#104 lesson): it is not enough that zb goes
  # away. It must have PRESENTED its key under the new generation and been
  # REFUSED.
  wait_log_after "$REAUTH_WAIT" zb.log "$SELF_REAUTH_FAILED" 0 \
    "zb presents its removed key and its in-place re-authentication fails" || PASS=1
  wait_log_after 10 vs.log "$ZB_AUTH_REFUSED" 0 "the visa service refuses zb's authentication" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  assert_swept zb "$ZB_ZPR_ADDR" "$LEG3_INSTALL_TS" || PASS=1
  assert_no_log vs.log "disconnect actor at $(ere_escape "$ZC_ZPR_ADDR") " "zc was not disconnected" || PASS=1
  assert_no_log vs.log "disconnect actor at $(ere_escape "$RELAY_ZPR_ADDR") " "the relay was not disconnected" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  # zc is unaffected: still logged in, and its device still reaches the
  # visa service, while zb, disconnected and its visas gone, is not
  # answered at all (zero replies, not merely fewer than sent).
  zode_ping zc "$VS_ZPR_ADDR" "zc still reaches the visa service" || PASS=1
  zode_no_ping zc "$ZB_ZPR_ADDR" "zb no longer answers zc's user flow" || PASS=1
fi

#
# Leg 4: zc's bootstrap key removed: zc is disconnected although its user
# is still logged in.
#
if [[ "$PASS" == 0 ]]; then
  echo "== 4. a policy without zc's bootstrap key"
  LEG4_INSTALL_TS=$SECONDS
  install_zode_policy "$POLICY_NO_ZC_BIN" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  # The same end-to-end discipline as leg 3: zc must try the renewal and
  # be refused, then fall back to the in-place re-authentication and be
  # refused again.
  wait_log_after "$REAUTH_WAIT" vs.log "$ZC_REAUTH_REFUSED" 0 "the visa service refuses zc's renewal" || PASS=1
  wait_log_after "$REAUTH_WAIT" zc.log "$NO_POLICY_RENEWAL" 0 "zc falls back to an in-place re-authentication" || PASS=1
  wait_log_after "$REAUTH_WAIT" zc.log "$SELF_REAUTH_FAILED" 0 "zc's in-place re-authentication fails" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  assert_swept zc "$ZC_ZPR_ADDR" "$LEG4_INSTALL_TS" || PASS=1
  assert_no_log vs.log "disconnect actor at $(ere_escape "$RELAY_ZPR_ADDR") " "the relay was not disconnected" || PASS=1
fi

# No Zode saw actor packets out of order at any point.
for ZODE in relay zb zc
do
  APOOO=$("$PH_DEBUG_BIN" -p "$ZODE.sock" counters 2> /dev/null \
    | awk -F': ' '$1 == "Actor Packets Out-Of-Order" { n += $2 } END { print n }' || true)
  if [ -n "$APOOO" ] && (( APOOO != 0 )); then
    echo "ASSERTION FAILED: $ZODE counted $APOOO actor packets out of order"
    PASS=1
  fi
done

zode_report "$PASS"
