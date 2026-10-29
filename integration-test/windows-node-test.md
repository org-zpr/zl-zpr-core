# Windows node test

Hand-run, end-to-end verification that `ph node` on Windows carries real
traffic between Linux adapters and hosts the visa service's support service
(VSS). This is the role-inverted twin of `windows-adapter-test.md`: there the
Windows VM was an adapter docked to a Linux node; here the **Windows VM is the
node** and everything else — valkey, the visa service, the visa service's
adapter, and two client adapters — runs on the Linux host. There is no
automated Windows CI that carries real traffic, so run this whenever a change
touches the Windows node path (node self-addressing through `TunCtl`
(zipline#159), the substrate socket (zipline#160), the VSS bind, forwarding
through the `windows_unbatched` engine, shutdown).

It exercises: Wintun interface creation and node self-addressing (address +
visa-service /128 route via `netsh`), the dock listener on a concrete
`self_addr`, the VSS TCP listener on the node's ZPR address, visa issuance
through the node, adapter-to-adapter traffic forwarded by the Windows node,
and graceful Ctrl-C shutdown that leaves no Wintun adapter behind.

Two machines:

* **Windows 11 VM** (or physical box) — runs `ph.exe node` from an elevated
  PowerShell. The Linux host must be able to reach the VM's LAN IP directly
  (bridged networking, or libvirt NAT where the VM is reachable from the
  host).
* **Linux host** — runs valkey, the visa service, the visa service's adapter
  and two client adapters (`adapter1`, `adapter2`), all inside the existing
  integration-test Docker image with `--network host`. Each `ph adapter` gets
  its own network namespace because running two adapters in one namespace is
  unsupported (the second refuses activation: "already routes to interface").
  `integration-test/remote-node-host-env.sh` scripts this whole side (it is
  shared with `macos-node-test.md` — the remote node can be a Windows VM or
  a Mac); the
  layout it builds is described in "Linux-side layout" below.

The keys and certificates come from `integration-test/pregen` and are
**test-only fixtures** — do not reuse them outside a private test network.

Topology, all through the Windows node:

```
   Linux host (docker, host network)                 Windows VM
  ┌────────────────────────────────────┐          ┌───────────────────┐
  │ netns zpr-vs: valkey, vs,          │   UDP    │ ph.exe node       │
  │   vs-adapter  (fd5a:5052::1) ──────┼──:5000──▶│  self_addr        │
  │ netns zpr-a1: adapter1             │          │  <VM LAN IP>:5000 │
  │   (fd5a:5052:8888::1:1) ───────────┼──:5000──▶│  zpr-addr         │
  │ netns zpr-a2: adapter2 + http:8080 │          │  fd5a:5052::2     │
  │   (fd5a:5052:8888::2:1) ───────────┼──:5000──▶│  VSS :8183        │
  └────────────────────────────────────┘          └───────────────────┘
```

The traffic step is `adapter1` fetching from an HTTP server behind
`adapter2`: every data packet crosses the VM's single unbatched substrate
socket twice (in from `adapter1`, out to `adapter2`).

## Prerequisites

Linux host:

* Binaries built on the host: `make` at the `zl-zpr-core` root (gives
  `target/debug/ph`, `ph-cli`), plus `vs` from a sibling `zl-zpr-visaservice`
  checkout (`make` there) and `zplc` from a sibling `zl-zpr-compiler`
  checkout. The helper script finds them at those sibling paths; override
  with `PH_BIN` / `PHCLI_BIN` / `VS_BIN` / `ZPLC_BIN`.
* Docker running, caller in the `docker` group. Build the test image once:
  `make -C integration-test docker-image`.

Windows VM:

* `ph.exe` and `ph-cli.exe` built on the VM, and `wintun.dll` placed next to
  `ph.exe` — exactly as in `windows-adapter-test.md` "Prerequisites, Windows
  VM" (build commands, DLL source and signing notes are there; they are
  identical for the node role).
* The VM must expose **more than one logical CPU** to Windows — check with
  `(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors`.
  libvirt presents vCPUs as sockets by default and Windows 11 *Home* uses
  only one socket, leaving 1 usable CPU; the node then livelocks (a
  tokio/mio re-register loop starves the fastpath — the management side
  goes silent for 13–25 s right after the VSAPI TLS handshake). libvirt
  fix: `<topology sockets='1' cores='4'/>` in the domain XML.

## 1. Linux side up

From the `zl-zpr-core` repository root on the Linux host. Everything is
driven by two variables: the VM's LAN IP as seen from the Linux host, and a
scratch directory.

```sh
export NODE_LAN_IP=192.168.122.188   # the Windows VM's IP as seen FROM THE LINUX HOST
export WORK=$(mktemp -d /tmp/zpr-node.XXXX)

# Generate keys, configs, policy; compiles the policy with zplc.
integration-test/remote-node-host-env.sh prepare

# Forwarding + FORWARD accepts + NAT so the namespaced adapters can reach
# the VM — on the HOST, as root (the integration-test image has no iptables
# and a read-only /proc/sys; with --network host the rules cover the
# container anyway). The VM must NOT be inside 10.0.[0-2].0/24 — those are
# the namespace subnets, and the script refuses such a NODE_LAN_IP loudly.
sudo -E integration-test/remote-node-host-env.sh nat-up

# Enter the integration-test container (host network; the capabilities and
# the apparmor opt-out are what `ip netns` and TUN creation need — narrower
# than the adapter test's --privileged, which some setups block).
docker run --rm -it --network host \
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=NET_RAW \
  --security-opt apparmor=unconfined --device /dev/net/tun \
  -e NODE_LAN_IP -v "$(realpath ..)":"$(realpath ..)" -v "$WORK":"$WORK" -e WORK \
  -w "$PWD" zpr-integration-test bash

# Inside the container: namespaces, valkey, vs, vs-adapter, adapter1,
# adapter2, and the HTTP server behind adapter2.
integration-test/remote-node-host-env.sh up
```

`up` ends by printing `ph-cli link show` for each adapter. **No link is
`Active` yet** — the node does not exist until section 2 — and that is
expected: the adapters keep retrying their dock in the background and go
`Active` on their own once the node is up. If a `ph` or `vs` process exited
instead, read its log in `$WORK` before moving on.

### Linux-side layout (what the script builds)

For auditing; the script is the executable form of this list.

* Three namespaces: `zpr-vs` (valkey, `vs`, the vs adapter), `zpr-a1`
  (`adapter1`), `zpr-a2` (`adapter2` + `python3 -m http.server 8080` bound to
  `adapter2`'s ZPR address, serving `$WORK/www` which contains a 64 MiB
  `blob` for the throughput number). Each namespace joins the host over a
  veth /24 (`10.0.0.x`, `10.0.1.x`, `10.0.2.x`) with a default route to the
  host side, the same shape as `windows-adapter-test.md` 1b.
* Unlike the adapter test, the node the adapters dock to is **not** on this
  host, so the namespaces need a route to the VM: `nat-up` (run on the host,
  as root) enables `net.ipv4.ip_forward`, inserts `FORWARD` accept rules for
  the `veth-zpr-*` interfaces (Docker hosts set the filter-table `FORWARD`
  policy to DROP, which would discard the namespace traffic before NAT), and
  adds one `MASQUERADE` rule scoped to namespace→VM traffic
  (`10.0.0.0/22 -> $NODE_LAN_IP/32`); `nat-down` removes all of them. The VM
  therefore sees all three adapters as the Linux host's LAN IP on distinct
  UDP source ports, which the dock does not care about. `NODE_LAN_IP` must
  not be inside the namespace subnets `10.0.[0-2].0/24` — the host would
  treat the VM as on-link on an isolated veth; the script rejects that with
  guidance. (Alternative, if you prefer no NAT: add a route on the VM for
  `10.0.0.0/22` via the Linux host's LAN IP and skip the MASQUERADE.)
* TUN devices are pre-created with their address already set, working around
  the Linux TUN bug described in `docs/SETUP.md` (required whenever
  `zpr_addr` is given): `fd5a:5052::1` for the vs adapter,
  `fd5a:5052:8888::1:1` / `::2:1` for `adapter1` / `adapter2`.
* Policy (`$WORK/remote-node.zpl` + `.zplc`): the node is the VM
  (`substrate_addrs.in1 = "<VM LAN IP>:5000"`, ZPR address `fd5a:5052::2`);
  services `A2Web` (TCP 8080) and `A2Ping` behind `adapter2`, `A1Ping`
  behind `adapter1`; `allow A1 to access A2Web / A2Ping`, `allow A2 to
  access A1Ping`. Static ZPR addresses come from the `addresses` file store
  exactly as in the adapter test.
* Identities: `actor1` → `adapter1`, `actor2` → `adapter2`, `actorvs` + a
  generated `vs.zpr` noise certificate for the vs adapter; the node's key
  material (`node.key`, `node.crt`, `node-rsa-key.pem`) is staged in
  `$WORK/node/` for copying to the VM.

## 2. Windows side

Copy to a directory on the VM (e.g. `C:\zpr-node`):

* `ph.exe`, `ph-cli.exe`, `wintun.dll` (all three in the same directory),
* from the Linux host, the staged node material: `$WORK/node/ca.crt`,
  `$WORK/node/node.crt`, `$WORK/node/node.key`, `$WORK/node/node-rsa-key.pem`.

Firewall first. Two rules are *expected* to be necessary — the dock listener
(UDP 5000 on the LAN interface) and the VSS listener (TCP 8183, reached over
the Wintun interface, which Windows places on the Public profile where
unsolicited inbound is dropped). The dock rule can be added now:

```powershell
New-NetFirewallRule -DisplayName zpr-node-dock -Direction Inbound `
  -Protocol UDP -LocalPort 5000 -Action Allow
```

The VSS rule **cannot be added up front**: `-InterfaceAlias zpr-node` fails
with "The specified interface was not found" until `ph.exe node` has created
the adapter. Add it from the second PowerShell after the node is up; once
created it persists across node restarts and VM reboots:

```powershell
New-NetFirewallRule -DisplayName zpr-node-vss -Direction Inbound `
  -Protocol TCP -LocalPort 8183 -InterfaceAlias zpr-node -Action Allow
```

Checklist item 3 asks which rules are *actually* required: on the first run,
add no rules, watch what fails (no dock → UDP rule; dock up but the visa
service never registers → VSS rule), add them one at a time and record the
result. On later runs add the dock rule up front and the VSS rule after
startup, if an earlier run has not already left it in place.

Start the node from an **elevated** PowerShell (Wintun device creation
requires it). The concrete `--self-addr` is decision N1 of the win-node plan:
the Windows engine rejects a wildcard bind by design, and with a concrete
address no separate `advertised_substrate_addr` is needed (it defaults to
`self_addr` when that is specific).

```powershell
cd C:\zpr-node
.\ph.exe node -l all=INFO `
  --self-addr <VM LAN IP>:5000 `
  --tun-if zpr-node --zpr-addr fd5a:5052::2 `
  --ca-file ca.crt --certificate-file node.crt --private-key-file node.key `
  --auth-private-key node-rsa-key.pem
```

Expected startup, in order:

* `WinTun: Creating adapter` (plus `Removed orphaned adapter` after a
  previous hard kill);
* `applying node ZPR address fd5a:5052::2/32 to the TUN device` — the node
  self-addresses via `netsh` (zipline#159) — and the visa-service host-route
  install that follows it (`fd5a:5052::1/128` on `zpr-node`; `netsh
  interface ipv6 show route` confirms);
* `advertising substrate address <VM LAN IP>:5000 to the visa service`;
* `Using packet I/O engine windows_unbatched`;
* within ~30 s of the Linux side being up: the vs adapter's dock completing
  and the visa-service connection registering (the Linux-side `vs.log` shows
  the VSS registration; the adapters go `Active`).

Leave the console running and open a **second elevated PowerShell** for the
checks.

## 3. Checks

On the VM (second elevated PowerShell):

```powershell
cd C:\zpr-node
.\ph-cli.exe link show        # expect THREE links (vs adapter, adapter1, adapter2), all (Active)
.\ph-cli.exe counters
Get-NetAdapter -Name zpr-node # the Wintun adapter exists; note its reported Status
```

On the Linux host (container shell):

```sh
# Dock state from each adapter's side: one link, (Active).
target/debug/ph-cli -p "$WORK/adapter1.sock" link show
target/debug/ph-cli -p "$WORK/adapter2.sock" link show

# ICMPv6 through ZPR, adapter1 -> adapter2, forwarded by the Windows node.
ip netns exec zpr-a1 ping -6 -c 4 fd5a:5052:8888::2:1

# The traffic step: HTTP through ZPR, adapter1 fetches from behind adapter2.
ip netns exec zpr-a1 curl -6 -sS "http://[fd5a:5052:8888::2:1]:8080/" | head -5

# Numbers for checklist item 4 (>=2 adapters, one unbatched socket) — record
# both results verbatim in Findings; do NOT tune anything:
ip netns exec zpr-a1 ping -6 -c 500 -i 0.02 -q fd5a:5052:8888::2:1   # record the loss %
ip netns exec zpr-a1 curl -6 -sS -o /dev/null \
  -w 'speed_download=%{speed_download} bytes/s\n' \
  "http://[fd5a:5052:8888::2:1]:8080/blob"                           # record the rate
```

Pass criteria:

* VM `link show` reports three links `(Active)`; `counters` answers over the
  named pipe (non-zero after the pings).
* `ping -6` from `zpr-a1` gets replies from `fd5a:5052:8888::2:1` (0% loss on
  the 4-packet check).
* The HTTP fetch returns the `http.server` directory listing, and the `blob`
  fetch completes (its rate and the flood-ping loss are recorded, whatever
  they are — the numbers are findings, not gates).

## 4. Checklist — the unknowns this run settles

These are the six open questions from zipline#162. Record each one in
**Findings** as PASS / FAIL / N-A plus a line of evidence; a FAIL becomes
either a small fix in the same PR (with a unit test) or a filed zipline
issue whose number goes in Findings.

1. **Duplicate-address detection / tentative bind.** Does the VSS bind (the
   `vss_addr` listener on `fd5a:5052::2:8183`, `adapter/ph/src/main.rs`,
   `launch_vss` call) fail at startup because the freshly `netsh`-added
   address is still tentative? Evidence: `VSS server terminated` /
   bind-error lines in the node console right after the self-addressing
   lines. If it fails, the fix is a bounded wait for the address to leave
   the tentative state (the Windows arm of the zipline#159 helper), not a
   sleep.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
2. **On-link reachability of `fd5a:5052::1`** with the `/128` route
   installed at startup. Evidence: `netsh interface ipv6 show route` lists
   `fd5a:5052::1/128` on `zpr-node`, and the visa service registers (visas
   are issued; adapters go Active).
   `[ ] PASS / [ ] FAIL: ______________________________________________`
3. **Which firewall rules are actually required.** Evidence: the
   add-one-at-a-time procedure from section 2; list the final required set.
   `[ ] UDP 5000 required?  [ ] TCP 8183 required?  Other: ______________`
4. **Two or more adapters docked through one unbatched socket.** Evidence:
   the flood-ping loss % and the `blob` download rate from section 3,
   recorded verbatim. Numbers only — no tuning in this task.
   `loss: ________ %   rate: ________ bytes/s`
5. **`set_carrier` is a NOP on Windows.** The node calls "carrier ON" at
   startup (`tun_ctl.set_carrier`, node arm of `main.rs`); on Windows this
   does nothing. Evidence: no carrier-related error in the node console, and
   `Get-NetAdapter -Name zpr-node` reports the adapter usable (record the
   Status it shows) — i.e. the NOP has no visible effect, good or bad.
   `[ ] PASS / [ ] FAIL: Status reported: _____________________________`
6. **Shutdown.** Ctrl-C in the node console: graceful-shutdown log lines,
   process exits on its own, `Get-NetAdapter -Name zpr-node` then reports no
   adapter, and the Linux adapters log the dock link going down
   (`disconnect_adapters` ran — see each `adapter*.log`). Then start
   `ph.exe node` a second time with the same command line: it must come up
   without "held by another process" or an orphaned-adapter error.
   `[ ] PASS / [ ] FAIL: ______________________________________________`

## 5. Teardown

VM: Ctrl-C already stopped the node (section 4, item 6); remove the firewall
rules:

```powershell
Remove-NetFirewallRule -DisplayName zpr-node-dock
Remove-NetFirewallRule -DisplayName zpr-node-vss
```

Linux (container shell): `integration-test/remote-node-host-env.sh down`
kills the started processes and deletes the namespaces. Back on the host:
`sudo integration-test/remote-node-host-env.sh nat-down` removes the
FORWARD accepts and the MASQUERADE rule — it finds them by scanning the live
tables, so it needs no environment and plain `sudo` (no `-E`) is correct
here. Then `rm -rf "$WORK"`.

## Recording the result

Paste the transcript (node startup lines, `ph-cli` output from both sides,
ping/HTTP/rate output, shutdown and the post-exit `Get-NetAdapter`) on the PR
or issue the run verifies, and fill in **Findings** below in the same PR.

Packet captures: `pktmon` on the VM does **not** capture Wintun traffic —
capture on the Linux side instead (e.g.
`ip netns exec zpr-vs tcpdump -ni tun0`).

## Findings

*(filled in by the first run; keep one dated subsection per run)*

### 2026-10-01 — first end-to-end run

* Build commit (`zl-zpr-core`): `1da1f10` (same build on the VM and the
  Linux host) · vs `0.21.0` (`zl-zpr-visaservice` `546386f`)
* Windows version / OS build (`winver`): Windows 11 Home 25H2, build
  26200.9457

| # | Checklist item | Result | Evidence / issue |
|---|---|---|---|
| 1 | tentative-address VSS bind | **FAIL → fixed in `1da1f10`** | VSS bind failed on every start with error 10049 (`AddrNotAvailable`) while the freshly added address was still `Tentative` (applied at 36.93, `Tentative` at 37.41, bind fail at 37.86, `Preferred` at 38.82, `DadTransmits=1`). Fix: Windows `add_address` now waits, bounded at 5 s, for the address to leave the tentative state, reading DAD state via IP Helper `GetUnicastIpAddressEntry` (not netsh, whose text output is localized); wait loop in `sys/dad.rs` with 6 unit tests that run on Linux. After the fix the listener comes up: `TCP [fd5a:5052::2]:8183 LISTENING`. |
| 2 | `fd5a:5052::1` on-link via /128 route | PASS | `netsh interface ipv6 show route`: `fd5a:5052::1/128 Manual zpr-node`; the node reached the VSAPI, visas were issued, all three links `Active`. |
| 3 | firewall rules actually required | UDP 5000 **required**; TCP 8183 kept | With no rules all docks hit `handshake timeout`; adding `zpr-node-dock` (UDP 5000) let them dock. The `zpr-node-vss` (TCP 8183) rule was kept per the doc — the VS reaches the node's VSS through the Wintun interface on the Public profile. Removing it alone was not tested. |
| 4 | ≥2 adapters, one socket (numbers) | recorded | flood ping loss **0 %** (500 packets, `-i 0.02`); `blob` download **6,751,114 bytes/s** (64 MiB in 9.94 s). |
| 5 | `set_carrier` NOP, no visible effect | PASS | No carrier-related error; `Get-NetAdapter zpr-node`: Status `Up`, MediaConnectionState `Connected`. |
| 6 | Ctrl-C teardown + clean second start | PASS (teardown) / second start: **zipline#167** | `Got Ctrl-C; attempting graceful shutdown` → `Removed peer link 13/12/10`, `VS API notify_disconnect succeeded`; `Get-NetAdapter zpr-node` → none; the process exits by itself. Second starts came up without held or orphan errors (one logged `Removed orphaned adapter "zpr-node 1"`). One of three restarts then failed to re-register with the VS — a VS/node restart ordering race, not Windows-specific, filed as [zipline#167](https://github.com/org-zpr/zl-zipline/issues/167). |

Minor observation, not filed: on Ctrl-C, `adapter1` received
`Terminate ... reason Reset`, while `adapter2` dropped the node's terminate
as `unexpected ZPI value 0 (expected ZPIPair { encr: 133, hmac: 6 })` and
noticed the node had gone only through missed keep-alives.
