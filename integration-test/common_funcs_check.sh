#!/usr/bin/env bash
#
# Self-check for the process and namespace helpers in lib/common_funcs.sh.
# Needs no root or built binaries, only unprivileged user namespaces
# (`unshare -r`, the same host prerequisite as the integration tests):
#
#   ./integration-test/common_funcs_check.sh
#
# Deliberately not named *-test.sh, so `make docker-test` does not pick it up
# as an integration test.

set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"

WORKDIR=$(mktemp -d)
WRAPPER_PIDS=()
trap 'for w in "${WRAPPER_PIDS[@]}"; do pkill -P "$w" 2> /dev/null || true; done; rm -rf "$WORKDIR"' EXIT

FAILURES=0

# Report a failed check and remember it for the exit status.
function fail() {
  echo "FAIL: $1"
  FAILURES=$((FAILURES + 1))
}

# Start a fake ph serving control socket $1 and set FAKE_PH_PID to its PID
# and FAKE_WRAPPER_PID to the PID of the process wrapping it.
#
# The tests launch ph through wrappers (`nsenter ... env ... $PH_BIN zode
# --control-path S`) whose command lines may also contain "--control-path
# S", and the outermost wrapper has the lowest PID. Model that with a bash
# parent whose command line contains the whole ph invocation, and a child
# whose command line starts with $PH_BIN, the way ph's does once nsenter or
# env has exec'd it.
#
# An optional $2 prefixes the launch, e.g. `unshare -r` to start the fake
# in a different user namespace, the way a concurrent test run's ph is.
function start_fake_ph() {
  ${2:-} bash -c "(exec -a '$PH_BIN zode --control-path $1 --initial-link relay@10.0.0.1:5000' sleep 30); true" 2> /dev/null &
  FAKE_WRAPPER_PID=$!
  WRAPPER_PIDS+=("$FAKE_WRAPPER_PID")

  FAKE_PH_PID=""
  for _ in $(seq 50); do
    FAKE_PH_PID=$(pgrep -P "$FAKE_WRAPPER_PID" || true)
    [ -n "$FAKE_PH_PID" ] && return 0
    sleep 0.1
  done
  echo "FAIL: fake ph for $1 did not start"
  exit 1
}

# The binary path carries regex metacharacters ("+", "."), which must match
# literally.
PH_BIN="$WORKDIR/build+asan/ph"
SOCK="adapter1-$$.sock"

# A concurrent run's ph: same binary, same (relative) socket name, but in
# another user namespace. Started first so it has the lowest PID.
start_fake_ph "$SOCK" "unshare -r"
FOREIGN_PID=$FAKE_PH_PID

# A decoy whose socket name matches "$SOCK" read as a regex ("." matching
# "X"). Started first so it has the lower PID, which `head -n 1` would pick.
start_fake_ph "adapter1-$$Xsock"
DECOY_PID=$FAKE_PH_PID

start_fake_ph "$SOCK"
PH_PID=$FAKE_PH_PID
PH_WRAPPER_PID=$FAKE_WRAPPER_PID

# ph_pid_for_socket must pick ph itself: not a process that wraps it
# (zipline#116), and not a process whose socket merely matches as a regex.
FOUND=$(ph_pid_for_socket "$SOCK")
[ "$FOUND" = "$PH_PID" ] \
  || fail "ph_pid_for_socket returned '$FOUND', want ph at $PH_PID (wrapper $PH_WRAPPER_PID, decoy $DECOY_PID, other run $FOREIGN_PID)"

# pkill_own must signal only this run's processes, never a concurrent run's
# match in another user namespace.
pkill_own -STOP -f "^$(ere_escape "$PH_BIN") .*--control-path $(ere_escape "$SOCK")( |\$)"
[ "$(ps -o stat= -p "$FOREIGN_PID" | cut -c1)" != T ] \
  || fail "pkill_own stopped PID $FOREIGN_PID in another user namespace"
[ "$(ps -o stat= -p "$PH_PID" | cut -c1)" = T ] \
  || fail "pkill_own did not stop this run's PID $PH_PID"
kill -CONT "$PH_PID" "$FOREIGN_PID" 2> /dev/null || true

FOUND=$(ph_pid_for_socket "other-$$.sock")
[ -z "$FOUND" ] || fail "ph_pid_for_socket matched an unrelated socket: '$FOUND'"

# process_exited must be false for a live process and true once it is gone.
process_exited "$PH_PID" && fail "process_exited says live PID $PH_PID has exited"
kill "$PH_PID"
wait "$PH_WRAPPER_PID" 2> /dev/null || true
process_exited "$PH_PID" || fail "process_exited says dead PID $PH_PID is still alive"

# enter_test_namespace must re-exec the calling script however it was
# started. `bash script.sh` from the script's own directory leaves $0 as a
# bare file name, which unshare would look up on PATH (review of
# zl-zpr-core#82).
cat > "$WORKDIR/userns-probe.sh" <<EOF
source "$(realpath "$(dirname "$0")")/lib/common_funcs.sh"
enter_test_namespace "\$@"
echo "in userns: \${ZPR_TEST_IN_USERNS:-no} args: \$*"
EOF
OUT=$(cd "$WORKDIR" && PATH=/usr/bin:/bin bash userns-probe.sh a "b c" 2> /dev/null) || true
[ "$OUT" = "in userns: 1 args: a b c" ] \
  || fail "enter_test_namespace did not re-exec 'bash userns-probe.sh': $OUT"

# A namespace holder must not outlive its test shell. A SIGKILLed shell
# runs no EXIT trap, so destroy_network never sees the holder (review of
# zl-zpr-core#82). Model it: a shell creates a namespace, reports the
# holder's PID, and is killed.
cat > "$WORKDIR/holder-probe.sh" <<EOF
source "$(realpath "$(dirname "$0")")/lib/common_funcs.sh"
enter_test_namespace
new_netns probe
echo "\${NETNS_PID[probe]}" > "$WORKDIR/holder.pid"
kill -KILL \$\$
EOF
bash "$WORKDIR/holder-probe.sh" 2> /dev/null || true
HOLDER=$(cat "$WORKDIR/holder.pid" 2> /dev/null || true)
if [ -z "$HOLDER" ]; then
  fail "holder probe did not create a namespace"
elif ! wait_for 3 process_exited "$HOLDER"; then
  fail "namespace holder $HOLDER outlived its SIGKILLed test shell"
  kill -KILL "$HOLDER" 2> /dev/null || true
fi

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES check(s) failed"
  exit 1
fi
echo "PASS"
