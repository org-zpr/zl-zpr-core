#!/usr/bin/env bash
#
# A Zode's own login (zl-zipline#233), docs/OIDC.md "A Zode's own login".
#
# The relay and the visa service run as in zode-link-test.sh, and zb joins
# through its initial link. The policy (pregen/zodes-login.zpl) lets zb's
# actor ping the visa service as a machine (the device flow) and ping the
# relay only with the logged-in user's OIDC subject (the user flow). A fake
# IdP runs in zpr-zb, for ph-cli's login, and in zpr-relay, for the visa
# service's JWKS (the relay hosts the visa service, zl-zipline#229). ph-cli runs with --no-browser, and curl in zpr-zb drives
# the authorization URL it prints (lib/zode_funcs.sh, core-tests-oidc helpers).
#
# Scenarios:
#   1. zb logged out: the user flow is denied, the device flow works.
#   2. `ph-cli connect`: exit 0, logged in, the user flow is admitted.
#   3. `ph-cli logout`: exit 0, the visa service's attribute sweep revokes
#      the user flow's visa and a new user flow is denied; the device flow
#      still works.
#   4. A resident `ph-cli auth-agent` logs in. A policy install while logged
#      in (gate g116 q3) is answered with a renewal: still logged in, the
#      user flow still admitted.
#   5. The login lives 60 s (expiration_seconds): the agent renews it
#      silently, and the user flow outlives the first expiry.
#   6. A visa-service restart replaces zb's VS-API session, which drops the
#      login (g116 q2 = prompt): the resident agent prints a new URL, curl
#      drives it, and the user flow is admitted again.
#
# Each check names the log line or ph-cli output it reads.
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

# What the logs say beyond the shared patterns in lib/zode_funcs.sh
# (zode_login.rs).
REPLACED="Zode login: the visa service replaced this node's VS-API session, which dropped the login"
ASK_AGENT='Zode login: asking the resident auth agent for a new login'

if [[ "$PASS" == 0 ]]; then
  echo "TEST STARTING"

  echo "== 1. zb logged out"
  assert_status 0 "State: logged out" "login-status: logged out" || PASS=1
  zode_ping zb "$VS_ZPR_ADDR" "the device flow (zb to the visa service) works" 10 || PASS=1
  zode_no_ping zb "$RELAY_ZPR_ADDR" "the user flow (zb to the relay) is denied" || PASS=1

  echo "== 2. ph-cli connect"
  zb_connect || PASS=1
  assert_status 0 "State: logged in" "login-status: logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is admitted" "$USER_FLOW_WARMUP" || PASS=1

  echo "== 3. ph-cli logout"
  REVOCATIONS=$(log_count zb.log "$REVOKED")
  SWEEPS=$(log_count vs.log "$VS_SWEEP_REVOKED")
  if zode_cli zb logout; then
    echo "assertion OK: logout exits 0"
  else
    echo "ASSERTION FAILED: logout exited non-zero"
    PASS=1
  fi
  wait_log_after 5 zb.log "$LOGGED_OUT" 0 "zb logs the logout" || PASS=1
  assert_status 0 "State: logged out" "login-status: logged out" || PASS=1
  wait_log_after 10 vs.log "$VS_SWEEP_REVOKED" "$SWEEPS" "the visa service re-checks zb's visas and revokes the user flow's" || PASS=1
  wait_log_after 10 zb.log "$REVOKED" "$REVOCATIONS" "zb drops the revoked visa" || PASS=1
  zode_no_ping zb "$RELAY_ZPR_ADDR" "a new user flow is denied" || PASS=1
  zode_ping zb "$VS_ZPR_ADDR" "the device flow still works: the machine stays connected" || PASS=1

  echo "== 4. resident auth-agent; a policy install while logged in"
  LOGINS=$(log_count zb.log "$LOGGED_IN")
  start_zode_login zb auth-agent agent.out || PASS=1
  wait_log_after 15 zb.log "$LOGGED_IN" "$LOGINS" "the agent logs zb in" || PASS=1
  assert_status 0 "Auth agent: registered" "login-status: the agent is registered" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is admitted" "$USER_FLOW_WARMUP" || PASS=1
  POLICY_RENEWALS=$(log_count zb.log "$POLICY_RENEWAL")
  install_zode_policy "$ZODE_POLICY_BIN" || PASS=1
  wait_log_after 30 zb.log "$POLICY_RENEWAL" "$POLICY_RENEWALS" "zb answers the policy re-authentication with a renewal (q3)" || PASS=1
  assert_status 0 "State: logged in" "login-status: still logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is still admitted" || PASS=1

  echo "== 5. silent renewal"
  RENEWALS=$(log_count zb.log "$RENEWED")
  # Due at half the 60 s lifetime after the last renewal or login.
  wait_log_after 45 zb.log "$RENEWED" "$RENEWALS" "the agent renews the login silently" || PASS=1
  wait_log_after 45 zb.log "$RENEWED" "$((RENEWALS + 1))" "and renews it again" || PASS=1
  assert_no_log zb.log "$EXPIRED" "the login never expired" || PASS=1
  if url_count_above agent.out 1; then
    echo "ASSERTION FAILED: a renewal asked the user to log in again"
    PASS=1
  else
    echo "assertion OK: no renewal asked the user (one authorization URL)"
  fi
  assert_status 0 "State: logged in" "login-status: still logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow outlives the first expiry" || PASS=1

  echo "== 6. a visa-service restart"
  LOGINS=$(log_count zb.log "$LOGGED_IN")
  restart_zode_vs || PASS=1
  wait_log_after 60 zb.log "$REPLACED" 0 "zb's new VS-API session dropped the login" || PASS=1
  wait_log_after 5 zb.log "$ASK_AGENT" 0 "zb asks the resident agent for a new login (q2)" || PASS=1
  drive_login_url zb agent.out 1 || PASS=1
  wait_log_after 15 zb.log "$LOGGED_IN" "$LOGINS" "zb is logged in again" || PASS=1
  assert_status 0 "State: logged in" "login-status: logged in" || PASS=1
  zode_ping zb "$RELAY_ZPR_ADDR" "the user flow is admitted again" "$USER_FLOW_WARMUP" || PASS=1
fi

zode_report "$PASS"
