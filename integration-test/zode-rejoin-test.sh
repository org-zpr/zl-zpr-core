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
# every bind was refused ("visa N not found"), for good. Now the match
# ejects the expired visa and the Zode asks for a new one. Each scenario
# waits until the visas of the last query have expired, then restarts a
# Zode, so the relay drops its copies (link down):
#   A. zb is killed and rejoins. zc's reply visa zc:53 -> zb:* has expired;
#      zc ejects it at the first reply, and zb gets every reply.
#   B. zc is stopped and rejoins. zb's visa zb -> zc:53 has expired; zb
#      ejects it at the next query, and gets every reply.
#
# Every query comes after the visas of the last one expired, so the visa
# service refreshes the attribute then: no query falls in the attribute's
# last 30 s, in which the visa service denies new visas (zl-zipline#275).
#
# Takes about four minutes, most of it waiting for visas to expire.
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

# Stop Zode NAME ($1, with substrate address $2, ZPR address $3 and
# authentication key $4) with signal $5, start it again, and wait until it
# has rejoined: registered with the visa service and got topology.
function restart_zode() {
  local NAME=$1 SUBSTRATE=$2 ZPR_ADDR=$3 AUTH_KEY=$4 SIGNAL=$5 REG TOP PID
  REG=$(log_count "$NAME.log" "$REGISTERED")
  TOP=$(log_count "$NAME.log" "$TOPOLOGY")
  PID=$(ph_pid_for_socket "$NAME.sock")
  kill "-$SIGNAL" "$PID"
  wait_for 15 process_exited "$PID"
  rm -f "$NAME.sock"
  launch_zode "$NAME" "$SUBSTRATE" "$ZPR_ADDR" "$AUTH_KEY"
  wait_log_after 45 "$NAME.log" "$REGISTERED" "$REG" "$NAME registers again" || RESULT=1
  wait_log_after 45 "$NAME.log" "$TOPOLOGY" "$TOP" "$NAME gets topology again" || RESULT=1
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
wait_past_expiry
EJECTED_BEFORE=$(log_count zc.log "$EJECTED")
restart_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem" 9
dns_ok "A: the rejoined zb gets UDP replies from zc" || RESULT=1
wait_log_after 5 zc.log "$EJECTED" "$EJECTED_BEFORE" "A: zc ejected its expired reply visa" || RESULT=1

echo "== B. zc is stopped and rejoins after zb's DnsZc visa expired"
wait_past_expiry
EJECTED_BEFORE=$(log_count zb.log "$EJECTED")
# The UDP/53 service keeps running in zc's namespace across the restart.
restart_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem" TERM
dns_ok "B: zb gets UDP replies from the rejoined zc" || RESULT=1
wait_log_after 5 zb.log "$EJECTED" "$EJECTED_BEFORE" "B: zb ejected its expired visa to zc" || RESULT=1

zode_stop_all
zode_report "$RESULT"
