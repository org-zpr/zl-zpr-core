#!/usr/bin/env bash
#
# oidc + file trusted-service interplay end to end (zipline#27, the epic
# zipline#22 finale), on Zodes. The layout and the fake IdPs are those of
# zode-login-test.sh: a user logs in on zb with `ph-cli connect`, and zb's
# own actor carries the user's attributes. The policy
# (pregen/oidc-file-interplay.zpl) is the master plan's Background
# configuration:
#
#   - `google` (api = "oidc", the fake IdP) authenticates the user and
#     mints the identity attribute user.sub (+ user.email).
#   - `happyfile` (api = "file") decorates that identity: happyfile.json is
#     keyed on user.sub and vends user.hair_color and the `lazy` tag.
#   - The only policy statement referencing a trusted-service attribute is
#     `allow lazy users to access Web.` (Web is the relay's ping service).
#     It references only happyfile's tag, so `google` survives compilation
#     by the identity-vendor retention rule (zipline#23), not by an
#     attribute reference. The zpdump pre-check below asserts both services
#     are in the binary; a compiler without the rule prunes google and the
#     check fails.
#
# What is asserted, and why the refresh legs exist (zipline#24/#25/#26):
#   1. Logged out, zb cannot reach Web.
#   2. After the OIDC login, the visa service's actor of zb carries
#      user.sub, user.email, user.zpr.tag.lazy and user.zpr.authority =
#      google, and the `lazy` visa works (zb reaches Web).
#   3. The same assertions hold across attribute-refresh cycles in which
#      the decorating store answers. This is the load-bearing part: the
#      zipline#24 regression (a decorating store displacing the
#      authenticator's user.zpr.authority) is invisible on the login path
#      alone. The authority is displaced once, and the attribute loss
#      (google's vouched_here gate pruning user.sub, then happyfile's
#      lookup missing and `lazy` vanishing) only shows on the *following*
#      refresh. A test that logs in and stops would pass against the broken
#      code.
#
# Refresh cycles are driven deterministically through the admin API:
# `vs-admin services --id happyfile --flush` records TrustedServiceChange,
# whose handler reconciles stale or TTL-expired trusted attributes on
# actors behind live visas (vs/src/event_mgr.rs). The final cycle first
# waits out happyfile's expiration_seconds (90 s, chosen to exceed the
# visa service's 60 s MIN_ATTRIBUTE_TTL while keeping this wait bounded),
# so the TTL-expiry path is exercised too, not just the revision-moved
# path.
#
# The admin surface is the ZPR-address-keyed actor API (zipline#31):
# `vs-admin actors --addr` returns the descriptor with attrs. Assertions go
# through jq and tolerate extra fields.
#
set -euo pipefail

# vss_rpc=DEBUG: zb logs the identity-provider list it gets over VSS.
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO vss_rpc=DEBUG}

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

ZODE_POLICY_BIN=oidc-file-interplay.bin2

# Optional: with a zpdump on hand the both-services check runs before any
# namespace is set up. Absent, the check is skipped with a warning (the
# fixture Makefile's compile is the fallback evidence).
ZPDUMP_BIN="${ZPDUMP_BIN:-$(realpath -s "$(dirname "$0")/zpdump" 2> /dev/null || true)}"

# happyfile's expiration_seconds in the fixture; the TTL-expiry refresh leg
# waits this out (plus slack). Keep in sync with oidc-file-interplay.zplc.
HAPPYFILE_TTL=90

if ! command -v jq > /dev/null; then
  echo "jq is required for the admin-surface assertions"
  exit 1
fi

#
# Pre-check: both trusted services must be in the compiled policy.
# `google` is referenced by no ZPL statement, so its presence here is the
# identity-vendor retention rule (zipline#23) at work. A compiler without
# the rule prunes it, every login then fails with no OIDC service in the
# fabric, and this catches that without ever touching a netns.
#
if [ -n "$ZPDUMP_BIN" ] && [ -x "$ZPDUMP_BIN" ]; then
  DUMP=$("$ZPDUMP_BIN" "$(dirname "$0")/pregen/$ZODE_POLICY_BIN")
  for WANT in "google trusted (oidc)" "happyfile trusted (file)"; do
    if ! grep -qF "$WANT" <<< "$DUMP"; then
      echo "FAILURE: compiled policy is missing '$WANT': was the fixture"
      echo "compiled with a zplc that lacks the identity-vendor retention rule (zipline#23)?"
      exit 1
    fi
  done
  echo "zpdump pre-check OK: both trusted services present in $ZODE_POLICY_BIN"
else
  echo "WARNING: zpdump not available (set ZPDUMP_BIN); skipping the both-services pre-check"
fi

enter_test_namespace "$@"

zode_begin

# happyfile's attribute data: the visa service reads
# file_ts_dir/happyfile.json, and file_ts_dir defaults to its config
# file's directory (the working directory).
cp "$PREGEN/happyfile.json" happyfile.json

PASS=0
launch_login_zodes user-a || PASS=1

# Assert the four interplay attributes on zb's actor. user.sub and
# user.email come from google (the authenticator), user.zpr.tag.lazy from
# happyfile (the decorator; for a tag, presence is the assertion, not a
# value), and user.zpr.authority must name google, the credential
# verifier, and never happyfile (zipline#25/#26). $1 is the phase.
function assert_user_actor() {
  local RESULT=0
  assert_zb_actor "$1: user.sub from google" user.sub '["user-a"]' || RESULT=1
  assert_zb_actor "$1: user.email from google" user.email '["user-a@example.com"]' || RESULT=1
  assert_zb_actor "$1: the lazy tag from happyfile" user.zpr.tag.lazy || RESULT=1
  assert_zb_actor "$1: the user's authority is google" user.zpr.authority '["google"]' || RESULT=1
  return "$RESULT"
}

# What the visa service logs once a trusted-service change has reconciled
# the actors behind live visas (vs/src/event_mgr.rs).
ACTORS_REFRESHED='trusted service changed: actors refreshed=[1-9]'

# Drive one deterministic refresh cycle: flush happyfile's file store
# (TrustedServiceChange: reconcile stale or TTL-expired attributes on
# actors behind live visas), and wait for the visa service to refresh an
# actor, so the assertions after it read a refreshed actor.
function refresh_cycle() {
  local REFRESHES
  REFRESHES=$(log_count vs.log "$ACTORS_REFRESHED")
  vs_admin services --id happyfile --flush
  wait_log_after 10 vs.log "$ACTORS_REFRESHED" "$REFRESHES" "the visa service refreshes zb's actor"
}

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  echo "== 1. logged out"
  zode_no_ping zb "$RELAY_ZPR_ADDR" "zb, logged out, cannot reach Web" || PASS=1

  echo "== 2. log in as user-a"
  zb_connect || PASS=1
  assert_user_actor "login" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the lazy visa: zb reaches Web" "$USER_FLOW_WARMUP" || PASS=1
fi

#
# Refresh legs: the part a user.zpr.authority-displacement regression needs
# (zipline#24).
#

if [[ "$PASS" == 0 ]]; then
  echo "== 3. refresh cycle 1 (happyfile flush, reconcile)"
  refresh_cycle || PASS=1
  assert_user_actor "after refresh 1" || PASS=1
fi

# Cycle 2 matters independently of cycle 1: with the displacement bug the
# authority flips on the first refresh, and the *attribute loss* (sub and
# email pruned by the vouched_here gate, then lazy lost) follows on the
# next one.
if [[ "$PASS" == 0 ]]; then
  echo "== 4. refresh cycle 2 (the following refresh)"
  refresh_cycle || PASS=1
  assert_user_actor "after refresh 2" || PASS=1
fi

# TTL leg: wait out happyfile's expiration_seconds so the next reconcile
# takes the TTL-expired path rather than the revision-moved one, then
# assert again and check that the visa still carries traffic.
if [[ "$PASS" == 0 ]]; then
  echo "== 5. waiting out happyfile's TTL (${HAPPYFILE_TTL}s + slack), then refresh"
  sleep $((HAPPYFILE_TTL + 5))
  refresh_cycle || PASS=1
  assert_user_actor "after the TTL-expired refresh" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "zb still reaches Web" || PASS=1
fi

zode_report "$PASS"
