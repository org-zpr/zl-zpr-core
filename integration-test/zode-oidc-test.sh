#!/usr/bin/env bash
#
# OIDC on a logged-in Zode: the identity provider rotates its signing key,
# and the identity provider withdraws a login's refresh grant
# (docs/OIDC.md). zode-login-test.sh covers the login itself, the logout
# and the silent renewal; this test covers the two legs it does not.
#
# The layout, the policy (pregen/zodes-login.zpl) and the fake IdPs are
# those of zode-login-test.sh: zb's own actor pings the visa service as a
# machine (the device flow), and pings the relay only while the user
# user-zb is logged in on zb (the user flow). The login lives 60 s and
# allows offline access, so a resident auth agent renews it with its
# refresh token about 30 s after each login.
#
# Legs:
#   1. Key rotation. A `ph-cli connect` on zb logs in with the IdP's first
#      signing key, which the visa service knows from the policy's seed
#      JWKS, so it fetches nothing; zb logs out. `fake-idp.py --rotate`
#      then switches every IdP instance to its second key, which the seed
#      leaves out. The next login presents a key ID the visa service's
#      cache does not know: it fetches the IdP's live JWKS once, admits
#      the login, and the user flow is admitted.
#   2. Revocation. A resident `ph-cli auth-agent` logs zb in and renews
#      the login once, then `fake-idp.py --revoke-refresh` models the user withdrawing the
#      application's access. The next silent renewal presents the refresh
#      grant and the IdP refuses it (`invalid_grant`). zb retries until the
#      login expires and then logs the user out itself: the visa service's
#      actor of zb loses every user attribute, and a new user flow is
#      denied while the device flow still works.
#
#      The leg binds no user flow while logged in. The visa service bounds
#      a user flow's visas by the login's expiry, so at the expiry they have
#      expired rather than been revoked, and ph checks a visa's expiry only
#      when a new flow is matched (zl-zipline#271): a stream bound before
#      the expiry outlives it (zl-zipline#274). Leg 1 shows that a login
#      admits the user flow.
#
# Each check names the log line, IdP request or ph-cli output it reads.
#
set -euo pipefail

# vss_rpc=DEBUG: zb logs the identity-provider list it gets over VSS.
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO vss_rpc=DEBUG}

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

ZODE_POLICY_BIN=zodes-login.bin2

enter_test_namespace "$@"

zode_begin

PASS=0
launch_login_zodes user-zb || PASS=1

# The visa service's JWKS fetch from the IdP in its own namespace, and a
# failed one (connection_control.rs).
JWKS_FETCH='"GET /jwks'
JWKS_FETCH_FAILED='JWKS refresh after validation failure failed'
# The IdP's refusal of a refresh grant: the login's token-endpoint request
# answers 200, so a 400 is the revoked grant.
REFRESH_REFUSED='"POST /token[^"]*" 400'

# The login expires 60 s after its last renewal; the next renewal is due
# 30 s in and is retried every 10 s, so the expiry comes at most about
# 60 s after the grant is revoked. Generous for a slow runner.
REVOCATION_WAIT=90

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  echo "== 1. the IdP rotates its signing key"
  # A login with the first key needs no fetch: the seed JWKS has it.
  zb_connect || PASS=1
  assert_no_log idp-relay.log "$JWKS_FETCH" "the visa service checks the first key against its seed JWKS, with no fetch" || PASS=1
  if zb_cli logout; then
    echo "assertion OK: logout exits 0"
  else
    echo "ASSERTION FAILED: logout exited non-zero"
    PASS=1
  fi
  python3 "$FAKE_IDP" --state-dir idp-state --rotate
  FETCHES=$(log_count idp-relay.log "$JWKS_FETCH")
  zb_connect || PASS=1
  wait_log_after 5 idp-relay.log "$JWKS_FETCH" "$FETCHES" "the visa service fetches the IdP's live JWKS for the new key" || PASS=1
  assert_no_log vs.log "$JWKS_FETCH_FAILED" "the visa service's JWKS fetch succeeded" || PASS=1
  assert_status 0 "State: logged in" "login-status: logged in with the rotated key" || PASS=1
  assert_zb_actor "the visa service's actor of zb carries the user's subject" user.oidc-subject '["user-zb"]' || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is admitted" "$USER_FLOW_WARMUP" || PASS=1
  if zb_cli logout; then
    echo "assertion OK: logout exits 0"
  else
    echo "ASSERTION FAILED: logout exited non-zero"
    PASS=1
  fi
fi

if [[ "$PASS" == 0 ]]; then
  echo "== 2. the IdP revokes the refresh grant"
  LOGINS=$(log_count zb.log "$LOGGED_IN")
  zb_cli auth-agent --no-browser > agent.out 2>&1 &
  drive_login_url agent.out 0 || PASS=1
  wait_log_after 15 zb.log "$LOGGED_IN" "$LOGINS" "the agent logs zb in" || PASS=1
  assert_zb_actor "the visa service's actor of zb carries the user's subject" user.oidc-subject '["user-zb"]' || PASS=1
  # The grant works before it is revoked: the IdP refuses an unknown
  # refresh token the same way as a revoked one.
  RENEWALS=$(log_count zb.log "$RENEWED")
  wait_log_after 45 zb.log "$RENEWED" "$RENEWALS" "the agent renews the login once with its refresh grant" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  REFUSALS=$(log_count idp-zb.log "$REFRESH_REFUSED")
  FAILURES=$(log_count zb.log "$RENEWAL_FAILED: .*invalid_grant")
  python3 "$FAKE_IDP" --state-dir idp-state --revoke-refresh
  wait_log_after "$REVOCATION_WAIT" idp-zb.log "$REFRESH_REFUSED" "$REFUSALS" "the IdP refuses the revoked refresh grant" || PASS=1
  wait_log_after 15 zb.log "$RENEWAL_FAILED: .*invalid_grant" "$FAILURES" "zb's silent renewal fails with invalid_grant" || PASS=1
  wait_log_after "$REVOCATION_WAIT" zb.log "$EXPIRED" 0 "the login expires and zb logs the user out" || PASS=1
  assert_status 5 "Last failure: LoginExpired" "login-status: logged out, the login expired" || PASS=1
  assert_zb_actor_lacks "the visa service's actor of zb has no user attribute left" user. || PASS=1
  zode_no_ping zb "$RELAY_ZPR_ADDR" "a new user flow is denied" || PASS=1
  zode_ping zb "$VS_ZPR_ADDR" "the device flow still works: the machine stays connected" || PASS=1
fi

zode_report "$PASS"
