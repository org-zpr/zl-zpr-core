#!/usr/bin/env bash
#
# SECURITY TESTING integration test.
#
# Models a malicious relay (a compromised binary) that corrupts the ICMP echo
# requests it forwards between two Zodes and re-forges their A2A MICV. A
# correct receiver rejects the forgery, so the mangled ping never reaches zc.
# A tcpdump on zc's TUN watches for the injected "YOU HAVE BEEN PWNED"
# payload and FAILS the test if it ever arrives.
#
# Layout (pregen/zodes-pair.zplc, lib/zode_funcs.sh): zb - relay - zc. zb and
# zc are not linked to each other, so zb's pings to zc cross the relay on a
# forward-only visa, which tells the relay neither the flow nor zc's A2A key.
# The relay rebuilds the flow from the visa's previous and next hop (zb and
# zc), as an attacker on that path could, and forges an unkeyed MICV.
#
# The relay is launched with --security-testing-mangle-forwarded-pings, so the
# PH binaries MUST be built with the `enable-security-testing` feature:
#   cargo build -p ph --features enable-security-testing
#
# Run it several ways to see the A2A MICV do its job:
#   ./a2a-pubkey-test.sh                     # keyed MICV: PASSES (forgery rejected)
#   ./a2a-pubkey-test.sh --unkeyed           # unkeyed MICV: FAILS (forgery accepted)
#   ./a2a-pubkey-test.sh --unkeyed --reuse   # unkeyed, no recompute: PASSES
#
# The last case is the key extra evidence: with --reuse the relay mangles the
# payload but keeps the original MICV, so even an unkeyed receiver rejects it --
# proving the MICV genuinely covers the payload (not just a prefix of it).
#
# Every run also checks that the relay did mangle pings (so a pass is not
# just a relay that left them alone), and, when the forgery is meant to be
# rejected, that zc rejected them on their MICV.
#
set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"
source "$(dirname "$0")/lib/zode_funcs.sh"

# The payload the malicious relay injects; see security_testing_mangle_ping().
PWNED_STRING="YOU HAVE BEEN PWNED"

# Re-exec inside an unprivileged user+network namespace; everything below
# runs there and needs no sudo.
enter_test_namespace "$@"

# Optionally force old-style unkeyed A2A MICVs on every Zode (the "old way"
# the A2A key replaced). With this set the forgery succeeds and the test fails.
UNKEYED_ARGS=()
# By default the relay recomputes the MICV after mangling (the forgery). With
# --reuse it keeps the original MICV instead, so the mangled ping is rejected
# regardless of keying.
RECOMPUTE_ARGS=()
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --unkeyed)
      UNKEYED_ARGS=(--security-testing-unkeyed-a2a-micv)
      shift
      ;;
    --reuse)
      RECOMPUTE_ARGS=(--security-testing-recompute-micvs false)
      shift
      ;;
    --help)
      echo "Usage: $0 [--unkeyed] [--reuse]"
      exit 1
      ;;
    *)
      echo "Error: unexpected argument $1" >&2
      echo "Usage: $0 [--unkeyed] [--reuse]"
      exit 1
      ;;
  esac
done

zode_preflight

# The mangle flag only exists in a feature build; bail early with a clear message
# rather than failing obscurely at relay launch.
if ! "$PH_BIN" node --help 2>&1 | grep -q -- --security-testing-mangle-forwarded-pings; then
  echo "ph binary was not built with the 'enable-security-testing' feature."
  echo "Rebuild with: cargo build -p ph --features enable-security-testing"
  exit 1
fi

if ! command -v tcpdump > /dev/null; then
  echo "tcpdump not found; it is required to detect the injected payload"
  exit 1
fi

# What the relay logs for each ping it mangles (fastpath.rs).
MANGLED='SECURITY TESTING: mangled forwarded ping'
# What zc's fastpath counts for each packet whose A2A MICV does not verify.
MICV_FAILURE='MICV Failure'

# The sum of Zode $1's counter $2 over its fastpath workers (`ph-cli
# counters` prints one line per worker). Prints nothing if ph-cli fails.
function counter_sum() {
  local OUT
  OUT=$("$PH_DEBUG_BIN" -p "$1.sock" counters) || return 1
  awk -F': ' -v name="$2" '$1 == name { sum += $2 } END { print sum + 0 }' <<< "$OUT"
}

ZODE_POLICY_BIN=zodes-pair.bin2
zode_begin

PWNED_PCAP="$TMPDIR/zc-icmp.pcap"

create_zode_network "zb:$ZB_SUBSTRATE_ADDR" "zc:$ZC_SUBSTRATE_ADDR"
PASS=0
echo "Launching relay (MALICIOUS: mangling forwarded pings${UNKEYED_ARGS[*]:+, unkeyed MICVs}${RECOMPUTE_ARGS[*]:+, reusing original MICV})"
launch_relay true \
  --security-testing-mangle-forwarded-pings \
  "${UNKEYED_ARGS[@]}" "${RECOMPUTE_ARGS[@]}" || PASS=1
launch_zode_vs || PASS=1

if [[ "$PASS" == 0 ]]; then
  launch_zode zb "$ZB_SUBSTRATE_ADDR" "$ZB_ZPR_ADDR" "$PREGEN/zb-rsa-key.pem" ca "${UNKEYED_ARGS[@]}"
  launch_zode zc "$ZC_SUBSTRATE_ADDR" "$ZC_ZPR_ADDR" "$PREGEN/zc-rsa-key.pem" ca "${UNKEYED_ARGS[@]}"
  wait_log_after 60 zb.log 'node access granted to visa service' 0 "zb authenticates" || PASS=1
  wait_log_after 60 zc.log 'node access granted to visa service' 0 "zc authenticates" || PASS=1
fi

if [[ "$PASS" == 0 ]]; then
  #
  # Watch zc for the injected payload. We capture the decapsulated ICMP zc
  # delivers to its TUN: a rejected forgery never reaches here, an accepted
  # one arrives carrying the PWNED string.
  #
  echo "Starting packet capture on zc..."
  # Safety net: SIGTERM lets tcpdump exit cleanly (and restore the terminal it
  # touched); --kill-after escalates to SIGKILL only if it's wedged in an idle
  # poll() ignoring catchable signals. -U writes each packet immediately, so the
  # pcap is complete even under a hard kill.
  # The unique pcap path makes the pkill match exactly this tcpdump.
  in_ns zpr-zc timeout -s TERM --kill-after=3 60 \
    tcpdump -Z root -i tun0 -n -U -w "$PWNED_PCAP" icmp6 2>/dev/null &
  sleep 2

  MICV_BEFORE=$(counter_sum zc "$MICV_FAILURE") || PASS=1

  echo "TEST STARTING: ping zb -> zc through the relay"
  # We do NOT check whether the pings are answered: a correctly rejected
  # forgery just means no reply, which is the passing case. The first echoes
  # wait for zb's visa, so send enough for some to cross the relay.
  in_ns zpr-zb ping -6 -q -c 10 -w 15 "$ZC_ZPR_ADDR" || true

  sleep 2
  # Stop the capture: SIGTERM first so tcpdump cleans up and restores the tty,
  # then SIGKILL as a backstop if it's stuck idle. DON'T block on wait: the
  # process does not reliably get reaped promptly, which previously hung the
  # whole script.
  pkill_own -TERM -f "tcpdump -Z root -i tun0 -n -U -w $PWNED_PCAP" 2>/dev/null || true
  sleep 1
  pkill_own -KILL -f "tcpdump -Z root -i tun0 -n -U -w $PWNED_PCAP" 2>/dev/null || true
  stty sane 2>/dev/null || true

  # The relay must have mangled pings, or a pass below proves nothing.
  if grep -q "$MANGLED" relay.log; then
    echo "assertion OK: the relay mangled forwarded pings"
  else
    echo "ASSERTION FAILED: the relay mangled no forwarded ping"
    PASS=1
  fi

  #
  # Verdict: any captured packet containing the injected string is a breach.
  #
  if grep -a -q "$PWNED_STRING" "$PWNED_PCAP" 2>/dev/null; then
    echo "SECURITY FAILURE: mangled payload \"$PWNED_STRING\" reached zc!"
    PASS=1
  else
    echo "No mangled payload reached zc (forgery rejected)."
    # And zc dropped the mangled pings on a failed MICV, not for another
    # reason. The counter also counts link-HMAC failures, but the relay
    # mangles before it seals the packet for the link to zc, so the mangle
    # cannot fail zc's link check; and --unkeyed shows the same forgery
    # passing that link check and reaching zc's A2A check.
    MICV_AFTER=$(counter_sum zc "$MICV_FAILURE") || PASS=1
    if (( MICV_AFTER > MICV_BEFORE )); then
      echo "assertion OK: zc rejected $((MICV_AFTER - MICV_BEFORE)) packets on their MICV"
    else
      echo "ASSERTION FAILED: zc's '$MICV_FAILURE' counter did not rise ($MICV_BEFORE -> $MICV_AFTER)"
      PASS=1
    fi
  fi
fi

# The pcap is owned by the invoking user now (no sudo involved), but keep the
# explicit removal so the trap cleanup's rm never prompts.
rm -f "$PWNED_PCAP" 2>/dev/null || true

zode_report "$PASS"
