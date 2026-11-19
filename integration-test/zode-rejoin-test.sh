#!/usr/bin/env bash
#
# A Zode never matches a new flow to an expired visa (zl-zipline#271).
#
# zb - relay - zc (pregen/zodes-rejoin.zplc). zc serves UDP/53, and zb may
# reach it only while zb has its `device.hostname` attribute, which lives
# ATTR_LIFETIME seconds; so every visa for that service expires during the
# test, as the DNS visas of a ZIPLINE network do.
#
# The visa service forgets a visa when it expires, so no revocation (link
# down, rejoin) ever reaches a Zode's expired copy. Before the fix a Zode
# kept matching new flows to it, and once the next hop had lost its copy
# every bind was refused ("visa N not found"), for good. Now an expired
# visa is ejected, by the Zode's expiry sweep (zl-zipline#274) or at the
# latest by the next match, and the Zode asks for a new one. Each scenario
# waits until the visas of the last query have expired, then restarts a
# Zode, so the relay drops its copies (link down):
#   A. zb is killed and rejoins. zc's reply visa zc:53 -> zb:* has expired;
#      zc ejects it (sweep or first reply), and zb gets every reply.
#   B. zc is stopped and rejoins. zb's visa zb -> zc:53 has expired; zb
#      ejects it (sweep or next query), and gets every reply.
#
# Every query of A and B comes after the visas of the last one expired, so
# the visa service refreshes the attribute then: no query falls in the
# attribute's last 30 s, in which the visa service denies new visas
# (zl-zipline#275).
#
# A departed Zode is removed (zl-zipline#284). The visa service removes a
# Zode none of whose links has come back up ZODE_DEPARTURE_GRACE (10 s)
# after a link-down report, unless it rejoined meanwhile; and ph deregisters
# first (notify_disconnect, NodeShutdown) on a graceful stop. So:
#   A. zb, back at once, is never removed, and keeps an actor.
#   B. zc's SIGTERM deregisters it: its actor is gone within 5 s, long
#      before the link loss is even detected (9-12 s).
#   C. zb is frozen (SIGSTOP) for 35 s: alive, but every link down past
#      the grace. The visa service removes it; once thawed it rejoins
#      (J10), its reconnect is refused (outOfSync), it connects as reset,
#      and gets every reply again with no manual step. C's new
#      authentication refreshes zb's attribute, so its query is safe too.
#
# Takes about five minutes, most of it waiting for visas to expire.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

enter_test_namespace "$@"

ZODE_POLICY_BIN=zodes-rejoin.bin2
zode_begin

# expiration_seconds of the `hostnames` trusted service in
# pregen/zodes-rejoin.zplc: no visa for DnsZc outlives it.
ATTR_LIFETIME=90
# The `hostnames` file trusted service reads hostnames.json from the visa
# service's file_ts_dir, which defaults to the directory of its config.
cp "$PREGEN/zodes-rejoin-hostnames.json" hostnames.json

UDP_ECHO=$(realpath "$(dirname "$0")/lib/udp_echo.py")
# What the logs say (vss_rpc.rs, visa_table.rs).
TOPOLOGY='received topology update with [1-9][0-9]* links'
REGISTERED='registered VSS'
EJECTED='visa [0-9]+ has expired: ejecting it'
RESULT=0

# Assert ($1) that zb gets a reply to every query to zc's UDP/53: three
# rounds of two concurrent queries. The first query of a flow waits for a
# visa, so up to five tries.
function dns_ok() {
  local TRY
  for TRY in 1 2 3 4 5; do
    if in_ns zpr-zb python3 "$UDP_ECHO" query "$ZC_ZPR_ADDR" 3; then
      echo "assertion OK: $1"
      return 0
    fi
  done
  echo "ASSERTION FAILED: $1"
  return 1
}

# Wait until every visa the last query used has expired.
function wait_past_expiry() {
  echo "waiting $((ATTR_LIFETIME + 5)) s for the DnsZc visas to expire"
  sleep $((ATTR_LIFETIME + 5))
}

# What the visa service logs (vsapi_worker.rs remove_if_departed,
# connection_control.rs disconnect_locked) when it removes the Zode at
# ZPR address $1: for a departure, or for a disconnect with reason $2.
function departed() { echo "Zode $(ere_escape "$1"): every link down for"; }
function disconnected() { echo "disconnect actor at $(ere_escape "$1") for reason $2"; }
# What a removed Zode logs when it comes back (vs_worker.rs, R16).
CONNECT_AS_RESET='visa service refused a reconnect \(OutOfSync\).*connecting as reset'

# Succeed when the visa service has no actor at ZPR address $1: its admin
# API answers 404. A failed lookup of any other kind does not count.
function actor_gone() {
  local OUT
  OUT=$(vs_admin actors --addr "$1" 2>&1) && return 1
  grep -q 'status code: 404' <<< "$OUT"
}

# Succeed when the visa service has an actor at ZPR address $1.
function actor_present() {
  vs_admin actors --addr "$1" > /dev/null 2>&1
}

# Assert ($3) that within $1 seconds the visa service has no actor at ZPR
# address $2.
function assert_actor_gone() {
  if wait_for "$1" actor_gone "$2"; then
    echo "assertion OK: $3"
  else
    echo "ASSERTION FAILED: $3 (the visa service still has an actor at $2)"
    return 1
  fi
}

# Assert ($2) that the visa service has an actor at ZPR address $1.
function assert_actor_present() {
  if actor_present "$1"; then
    echo "assertion OK: $2"
  else
    echo "ASSERTION FAILED: $2 (the visa service has no actor at $1)"
    return 1
  fi
}

# Send signal $2 to Zode NAME ($1) without waiting for it to exit. Prints
# its PID, for wait_zode_exit.
function signal_zode() {
  local PID
  PID=$(ph_pid_for_socket "$1.sock")
  kill "-$2" "$PID"
  echo "$PID"
}

# Wait until Zode NAME ($1, with PID $2) has exited, and remove its socket.
function wait_zode_exit() {
  wait_for 15 process_exited "$2"
  rm -f "$1.sock"
}

# Start the stopped Zode NAME ($1, with substrate address $2, ZPR address
# $3 and authentication key $4) again, and wait until it has rejoined:
# registered with the visa service and got topology since the counts $5
# and $6 (registrations and topology updates in its log).
function relaunch_zode() {
  local NAME=$1 REG=$5 TOP=$6
  launch_zode "$NAME" "$2" "$3" "$4"
  wait_rejoined "$NAME" "$REG" "$TOP"
}

# Wait until Zode NAME ($1) has registered with the visa service and got
# topology since the counts $2 and $3 (from its log, before the step).
function wait_rejoined() {
  wait_log_after 45 "$1.log" "$REGISTERED" "$2" "$1 registers again" || RESULT=1
  wait_log_after 45 "$1.log" "$TOPOLOGY" "$3" "$1 gets topology again" || RESULT=1
}

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
launch_relay true
launch_zode_vs
launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem"
launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem"
wait_log_after 45 zb.log "$TOPOLOGY" 0 "zb joins" || RESULT=1
wait_log_after 45 zc.log "$TOPOLOGY" 0 "zc joins" || RESULT=1

in_ns zpr-zc python3 "$UDP_ECHO" serve &
sleep 1
dns_ok "before: zb gets UDP replies from zc" || RESULT=1

echo "== A. zb is killed and rejoins after its DnsZc visas expired"
# Counted before the wait: the expiry sweep may eject during it.
EJECTED_BEFORE=$(log_count zc.log "$EJECTED")
wait_past_expiry
REG=$(log_count zb.log "$REGISTERED")
TOP=$(log_count zb.log "$TOPOLOGY")
PID=$(signal_zode zb KILL)
wait_zode_exit zb "$PID"
relaunch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem" "$REG" "$TOP"
dns_ok "A: the rejoined zb gets UDP replies from zc" || RESULT=1
wait_log_after 5 zc.log "$EJECTED" "$EJECTED_BEFORE" "A: zc ejected its expired reply visa" || RESULT=1

echo "== B. zc is stopped and rejoins after zb's DnsZc visa expired"
EJECTED_BEFORE=$(log_count zb.log "$EJECTED")
wait_past_expiry
# Every departure check A's link-down reports scheduled ran during the wait.
assert_no_log vs.log "$(departed "$ZB_ZPR_ADDR")" "A: zb, back at once, was never removed" || RESULT=1
assert_actor_present "$ZB_ZPR_ADDR" "A: the visa service still has zb's actor" || RESULT=1
REG=$(log_count zc.log "$REGISTERED")
TOP=$(log_count zc.log "$TOPOLOGY")
SHUTDOWNS=$(log_count vs.log "$(disconnected "$ZC_ZPR_ADDR" NodeShutdown)")
PID=$(signal_zode zc TERM)
assert_actor_gone 5 "$ZC_ZPR_ADDR" "B: zc's actor is gone within 5 s of its SIGTERM" || RESULT=1
wait_log_after 1 vs.log "$(disconnected "$ZC_ZPR_ADDR" NodeShutdown)" "$SHUTDOWNS" \
  "B: zc deregistered (NodeShutdown)" || RESULT=1
wait_zode_exit zc "$PID"
# The UDP/53 service keeps running in zc's namespace across the restart.
relaunch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem" "$REG" "$TOP"
dns_ok "B: zb gets UDP replies from the rejoined zc" || RESULT=1
wait_log_after 5 zb.log "$EJECTED" "$EJECTED_BEFORE" "B: zb ejected its expired visa to zc" || RESULT=1

echo "== C. zb is frozen past the departure grace, removed, and rejoins"
REG=$(log_count zb.log "$REGISTERED")
TOP=$(log_count zb.log "$TOPOLOGY")
RESETS=$(log_count zb.log "$CONNECT_AS_RESET")
PID=$(signal_zode zb STOP)
# Link-loss detection (9-12 s), plus ZODE_DEPARTURE_GRACE (10 s), plus slack.
echo "zb frozen; waiting 35 s"
sleep 35
assert_log_count vs.log "$(departed "$ZB_ZPR_ADDR")" 1 "C: the visa service removed the departed zb" || RESULT=1
assert_actor_gone 0 "$ZB_ZPR_ADDR" "C: zb's actor is gone" || RESULT=1
kill -CONT "$PID"
wait_log_after 45 zb.log "$CONNECT_AS_RESET" "$RESETS" "C: zb's reconnect is refused; it connects as reset" || RESULT=1
wait_rejoined zb "$REG" "$TOP"
dns_ok "C: the rejoined zb gets UDP replies from zc" || RESULT=1

zode_stop_all
zode_report "$RESULT"
