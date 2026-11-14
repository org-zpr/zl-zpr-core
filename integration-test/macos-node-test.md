# macOS node test

Hand-run, end-to-end verification that `ph node` on macOS carries real
traffic between Linux adapters and hosts the visa service's support service
(VSS). This is the macOS sibling of `windows-node-test.md`: the **Mac is the
node** and everything else — valkey, the visa service, the visa service's
adapter, and two client adapters — runs on the Linux host. There is no
automated macOS CI that carries real traffic (master-plan decision M5), so
run this whenever a change touches the macOS node path (node self-addressing
through `TunCtl` (zipline#159), the optional-address `new_mq` (zipline#161),
the VSS bind, forwarding through the `posix_unbatched` engine, shutdown).

It exercises: utun interface creation (named and kernel-chosen) and node
self-addressing (`ifconfig ... inet6 <addr>/32 alias` + the visa-service
route via `/sbin/route`), the dock listener on a wildcard `self_addr` with
pktinfo reply steering, the VSS TCP listener on the node's ZPR address, visa
issuance through the node, adapter-to-adapter traffic forwarded by the Mac
node, and Ctrl-C shutdown that leaves no stale utun state behind.

Two machines:

* **Mac** (Apple Silicon or Intel) — runs `ph node` under `sudo` from a
  terminal. The Linux host must be able to reach the Mac's LAN IP directly.
* **Linux host** — runs valkey, the visa service, the visa service's adapter
  and two client adapters (`adapter1`, `adapter2`), all inside the existing
  integration-test Docker image with `--network host`. This side is
  **identical to `windows-node-test.md` section 1** and is scripted by the
  shared `integration-test/remote-node-host-env.sh`; the steps are
  referenced below, not repeated — the only difference is that
  `NODE_LAN_IP` is the Mac's LAN IP instead of a Windows VM's.

The keys and certificates come from `integration-test/pregen` and are
**test-only fixtures** — do not reuse them outside a private test network.

Topology, all through the Mac node:

```
   Linux host (docker, host network)                 Mac
  ┌────────────────────────────────────┐          ┌────────────────────┐
  │ netns zpr-vs: valkey, vs,          │   UDP    │ ph node            │
  │   vs-adapter  (fd5a:5052::1) ──────┼──:5000──▶│  self_addr         │
  │ netns zpr-a1: adapter1             │          │  0.0.0.0:5000      │
  │   (fd5a:5052:8888::1:1) ───────────┼──:5000──▶│  advertised        │
  │ netns zpr-a2: adapter2 + http:8080 │          │  <Mac LAN IP>:5000 │
  │   (fd5a:5052:8888::2:1) ───────────┼──:5000──▶│  zpr-addr          │
  └────────────────────────────────────┘          │  fd5a:5052::2      │
                                                  │  VSS :8183         │
                                                  └────────────────────┘
```

The traffic step is `adapter1` fetching from an HTTP server behind
`adapter2`: every data packet crosses the Mac's single unbatched substrate
socket twice (in from `adapter1`, out to `adapter2`).

## Prerequisites

Linux host: exactly as in `windows-node-test.md` "Prerequisites, Linux
host" — `make` at the `zl-zpr-core` root, `vs` and `zplc` from sibling
checkouts, Docker with the `zpr-integration-test` image built.

Mac:

* `ph` and `ph-cli` built on the Mac: `make` at the `zl-zpr-core` repository
  root (plain `cargo build -p ph -p ph-cli` works too). Nothing else — there
  is no wintun analogue; `utun` devices are in-kernel and `ph` creates them
  through a `PF_SYSTEM` control socket. Creation requires root, hence
  `sudo` below.
* If the Mac's application firewall is enabled (System Settings → Network →
  Firewall), expect it to interfere with the inbound dock (UDP 5000) and VSS
  (TCP 8183) listeners — settling what actually happens is checklist
  item 4. The command-line tool is
  `/usr/libexec/ApplicationFirewall/socketfilterfw`; the expected fix, if
  one is needed, is to allow the binary **the test actually runs** — the
  copy in `~/zpr-node` that section 2 starts, not the build-tree
  `target/debug/ph` (the firewall keys rules on the executable's path, so a
  rule for the build-tree copy does nothing for the copy the node runs as):

  ```sh
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ~/zpr-node/ph
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ~/zpr-node/ph
  ```

  On the first run add nothing up front: watch what fails (no dock → UDP
  blocked; docks up but the visa service never registers → TCP 8183
  blocked), apply the fix, and record the result in Findings.

## 1. Linux side up

Follow `windows-node-test.md` **section 1 verbatim** — same script, same
commands, same container invocation — with one substitution:

```sh
export NODE_LAN_IP=<Mac LAN IP>      # the Mac's IP as seen FROM THE LINUX HOST
```

instead of the Windows VM's IP. Everything else is unchanged: `export
WORK=$(mktemp -d /tmp/zpr-node.XXXX)`, then
`integration-test/remote-node-host-env.sh prepare` on the host,
`sudo -E ... nat-up` on the host, the `docker run` from that document, and
`integration-test/remote-node-host-env.sh up` inside the container. The
"Linux-side layout" section there describes what gets built; none of it is
Windows-specific. As there, **no link is `Active`** until the node is up in
section 2 — the adapters retry their dock in the background.

**Run `nat-up` before `up`.** If the adapters start first, their UDP flows
get conntrack entries without NAT; the node then sees the namespace
addresses (`10.0.x.2`) as sources, its replies go nowhere, and every
handshake times out until those entries expire (about a minute, during
which the node accumulates `Keying` links that never complete).

## 2. Mac side

Copy from the Linux host to a working directory on the Mac (e.g.
`~/zpr-node`), next to the `ph` / `ph-cli` binaries or anywhere you like:

* the staged node material: `$WORK/node/ca.crt`, `$WORK/node/node.crt`,
  `$WORK/node/node.key`, `$WORK/node/node-rsa-key.pem`.

Start the node from a terminal. The macOS engine is the same POSIX engine
the Linux integration tests use: a **wildcard bind with pktinfo** is
supported and is what this test exercises (checklist item 3). A wildcard
`self_addr` cannot be advertised, so `--advertised-substrate-addr` names the
address the adapters dial:

```sh
cd ~/zpr-node
sudo ./ph node -l all=INFO \
  --self-addr 0.0.0.0:5000 \
  --advertised-substrate-addr "<Mac LAN IP>:5000" \
  --tun-if utun9 --zpr-addr fd5a:5052::2 \
  --ca-file ca.crt --certificate-file node.crt --private-key-file node.key \
  --auth-private-key node-rsa-key.pem
```

(`--tun-if` on macOS must be of the form `utunN`; `utun9` is arbitrary but
high enough not to collide with the system's own utuns. Checklist item 2
also runs this **without** `--tun-if` to confirm the kernel-chosen-name
path.)

Expected startup, in order:

* utun creation (the device appears in `ifconfig` as `utun9`);
* `applying node ZPR address fd5a:5052::2/32 to the TUN device` — the node
  self-addresses via `ifconfig ... inet6 fd5a:5052::2/32 alias`
  (zipline#159/#161). On macOS (unlike Windows) the `/32` alias puts the
  whole ZPR internal network on-link, so **no separate visa-service host
  route is installed by the node** — whether the kernel actually installs
  the on-link route for `fd5a:5052::/32` is checklist item 1;
* `advertising substrate address <Mac LAN IP>:5000 to the visa service`;
* `Using packet I/O engine posix_unbatched`;
* within ~30 s of the Linux side being up: the vs adapter's dock completing
  and the visa-service connection registering (the Linux-side `vs.log` shows
  the VSS registration; the adapters go `Active`).

Leave the node running and open a **second terminal** for the checks.

## 3. Checks

On the Mac (second terminal):

```sh
cd ~/zpr-node
# NOT under sudo: `sudo ph node` binds /var/run/zpr/<SUDO_UID>/control.sock
# owned by you, and `sudo ph-cli` (uid 0) would look in /var/run/zpr/0/.
./ph-cli link show             # expect THREE links (vs adapter, adapter1, adapter2), all (Active)
./ph-cli counters
ifconfig utun9                 # the utun exists and carries fd5a:5052::2 prefixlen 32
netstat -rn -f inet6 | grep -i 'fd5a:5052\|utun9'   # route shape — evidence for checklist item 1
```

On the Linux host (container shell): identical to `windows-node-test.md`
section 3 "On the Linux host" — `ph-cli link show` against both adapter
sockets, the 4-packet `ping -6`, the HTTP fetch, and the two
numbers-for-the-record commands (flood ping loss %, `blob` download rate).

Pass criteria:

* Mac `link show` reports three links `(Active)`; `counters` answers over
  the control socket (non-zero after the pings).
* `ping -6` from `zpr-a1` gets replies from `fd5a:5052:8888::2:1` (0% loss
  on the 4-packet check).
* The HTTP fetch returns the `http.server` directory listing, and the `blob`
  fetch completes (its rate and the flood-ping loss are recorded, whatever
  they are — the numbers are findings, not gates).

## 4. Checklist — the unknowns this run settles

These are the six open questions from zipline#164. Record each one in
**Findings** as PASS / FAIL / N-A plus a line of evidence; a FAIL becomes
either a small fix in the same PR (with a unit test) or a filed zipline
issue whose number goes in Findings.

1. **Route shape after the `/32 alias`.** After `ifconfig utun9 inet6
   fd5a:5052::2/32 alias`, does the kernel install an on-link route for
   `fd5a:5052::/32` via the utun, or is an explicit `add_route` what would
   make `fd5a:5052::1` reachable? Evidence: `netstat -rn -f inet6` before
   and after startup, and whether the visa service registers (visas issued,
   adapters `Active`) with only the alias in place. Record which, and
   whether `/32` or a `/128` host route is the right thing for a node (an
   adapter wants the /32; a node needs only the visa service on-link, since
   everything else is forwarded by the node itself). Any adjustment to the
   zipline#159 helper this implies is reported on zipline#159.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
2. **`tun_if` set and unset both start.** Run once with `--tun-if utun9`
   (the main run above) and once without `--tun-if` (kernel-chosen `utunN`,
   zipline#161's `new_mq` path). Evidence: both starts reach the
   self-addressing line; `ifconfig` shows the created interface; with the
   flag unset, note the name the kernel chose.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
3. **Wildcard `self_addr` with pktinfo.** With `--self-addr 0.0.0.0:5000`,
   replies leave from the address the adapter docked to (the
   `posix_unbatched` pktinfo path). Evidence: docks complete and stay up
   (an asymmetric reply source would break the handshake). **Scope note:**
   this run exercises the pktinfo path through a single Mac address only —
   `remote-node-host-env.sh` points every adapter at the one `NODE_LAN_IP`
   and installs NAT only toward it, and the compiled policy advertises a
   single node substrate address, so docking adapters through a second Mac
   interface (Wi-Fi + Ethernet) is not verifiable with this environment as
   it stands. Multi-address support in the test env is deferred to
   zipline#172; do not try to improvise it in this run.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
4. **Application firewall.** With the firewall enabled, does inbound UDP
   5000 / TCP 8183 prompt, silently drop, or pass? Evidence: the
   add-nothing-first procedure from "Prerequisites, Mac"; record the final
   required `socketfilterfw` command set (possibly none — the firewall may
   be off, or signed-binary prompting may cover it; record which).
   `[ ] UDP 5000 affected?  [ ] TCP 8183 affected?  Fix: ________________`
5. **Two or more adapters docked through the one `posix_unbatched`
   worker.** macOS forces a single worker (`new_mq` rejects more). Evidence:
   the flood-ping loss % and the `blob` download rate from section 3,
   recorded verbatim. Numbers only — no tuning in this task.
   `loss: ________ %   rate: ________ bytes/s`
6. **Shutdown.** Ctrl-C in the node terminal: graceful-shutdown log lines
   (`Got Ctrl-C; attempting graceful shutdown`), the process exits on its
   own, and the utun is gone (`ifconfig utun9` reports no such interface —
   a utun is process-scoped, so its address and route must die with the
   process; confirm `netstat -rn -f inet6` carries no stale `fd5a:5052`
   route). The Linux adapters log the dock link going down (see each
   `adapter*.log`). Then start `ph node` a second time with the same
   command line: it must come up without failing on a stale route or a
   stale `utun9`.
   `[ ] PASS / [ ] FAIL: ______________________________________________`

## 5. Teardown

Mac: Ctrl-C already stopped the node (section 4, item 6); if a
`socketfilterfw` rule was added in item 4 and you want it gone:

```sh
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove ~/zpr-node/ph
```

Linux: identical to `windows-node-test.md` section 5 —
`integration-test/remote-node-host-env.sh down` in the container, then
`sudo integration-test/remote-node-host-env.sh nat-down` on the host (plain
`sudo`, no `-E`), then `rm -rf "$WORK"`.

## Recording the result

Paste the transcript (node startup lines, `ph-cli` output from both sides,
`netstat`/`ifconfig` route evidence, ping/HTTP/rate output, shutdown and the
post-exit `ifconfig`) on the PR or issue the run verifies, and fill in
**Findings** below in the same PR.

Packet captures, if needed: `tcpdump -ni utun9` works on the Mac;
`ip netns exec zpr-vs tcpdump -ni tun0` on the Linux side.

## Findings

*(filled in by the first run; keep one dated subsection per run)*

### 2026-10-02 — first end-to-end run

* Build commit (`zl-zpr-core`): `4a0e815` (same build on the Mac and the
  Linux host) · vs `d741bdc` (`zl-zpr-visaservice`)
* macOS version / chip: macOS 26.5.2, Apple M2 (arm64), Mac on Wi-Fi
  (192.168.0.65); Linux host NATs the adapters as 192.168.0.212

| # | Checklist item | Result | Evidence / issue |
|---|---|---|---|
| 1 | route shape after `/32 alias` (on-link vs explicit; /32 vs /128) | PASS | Before: no `fd5a` routes. After: kernel installs `fd5a:5052::/32 … Uc utun9` on-link plus `fd5a:5052::2 link#21 UHL lo0`. VS registered (`registered VSS`), VSS TLS connection from `[fd5a:5052::1]`, adapters Active — the alias alone suffices; no explicit `add_route` needed. The /32 is harmless for a node: everything else in the ZPR network is forwarded by the node itself, so no change to the zipline#159 helper. |
| 2 | `tun_if` set (`utun9`) and unset (kernel-chosen) both start | PASS | `--tun-if utun9`: `utun9` created and addressed. Unset: kernel chose `utun6` (system had `utun0`–`utun5`), same address + `/32` route, 3 links Active, ping 4/4, HTTP OK. |
| 3 | wildcard `self_addr` + pktinfo reply steering | PASS | `--self-addr 0.0.0.0:5000` (`udp4 *.5000`), all three docks complete and stay Active through the flood ping and 64 MiB fetch. Single Mac address only (scope note; zipline#172). |
| 4 | application firewall: UDP 5000 / TCP 8183, `socketfilterfw` fix | N-A | Firewall disabled (`socketfilterfw --getglobalstate`: State = 0); left off by choice. No rules needed or added. |
| 5 | ≥2 adapters, one socket (numbers) | PASS | loss: 0 % (500/500, `-i 0.02`, rtt avg 15.5 ms over Wi-Fi) · rate: 8432600 bytes/s (64 MiB `blob`) |
| 6 | Ctrl-C teardown + clean second start | PASS | `Got SIGINT; attempting graceful shutdown`, links reset, visas revoked, `notify_disconnect succeeded`, process exits on its own. `ifconfig utun9`: does not exist; no `fd5a` routes. All three adapters log `Received terminate for dock link … fully shut down`. Second start with the same command line: clean (re-binds the leftover `control.sock` path), adapters Active again in ~10 s, ping 4/4, HTTP OK. |

Other observations from this run:

* **Doc fix:** section 3 used `sudo ./ph-cli`; that fails (`no live packet
  handler socket (tried /var/run/zpr/0/control.sock …)`) because the
  sudo-started node binds `/var/run/zpr/<SUDO_UID>/control.sock`. Fixed to
  plain `./ph-cli`.
* **Doc fix:** `nat-up` must precede `up` (see section 1 note). This run
  started the adapters first; the first docks arrived un-NATed from
  `10.0.x.2` and timed out until conntrack expired (~1 min), then docked
  normally from `192.168.0.212`.
* **Stale `Keying` links:** those three un-NATed links (3–5) stayed in
  `Keying` on the node for the whole run, re-timing-out the handshake, and
  were only removed at shutdown. Not macOS-specific — a node keeps
  never-completing links from a vanished peer indefinitely.
* **Log noise on normal shutdown:** `ERROR startup: visa service connection
  manager terminated: Ok(())` and two `ERROR startup: VSConn lifecycle
  channel closed unexpectedly` are logged on a graceful Ctrl-C.
* **Leftover socket:** `/var/run/zpr/501/control.sock` stays on disk after
  exit; harmless (the next start re-binds it).
* `WARN startup: Unable to enable ingress packet steering: packet steering
  not supported on this OS` at every start — expected on macOS.
