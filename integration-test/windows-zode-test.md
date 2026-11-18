# Windows Zode test

Hand-run, end-to-end verification that `ph zode` on Windows joins a ZPRnet
and carries real traffic. The **Windows VM is a Zode** (CN `zb`) that dials
a relay Zode on the Linux host; the relay hosts the visa service. There is
no automated Windows CI that carries real traffic, so run this whenever a
change touches the Windows datapath (Wintun, the named-pipe control channel,
the `windows_unbatched` engine, shutdown).

It exercises:

* Wintun interface creation and the Zode's self-addressing;
* a wildcard bind with no advertised address: the Zode reports its initial
  link's current local address to the visa service (zl-zipline#230);
* joining through the relay, and the visa service reaching the Zode's VSS
  over the Wintun interface;
* logging a person in on the Zode with `ph-cli` over the named pipe
  (section 3, zl-zipline#233);
* who may open the control pipe (section 4, zipline#154);
* graceful Ctrl-C shutdown that leaves no Wintun adapter behind.

Two machines:

* **Linux host** — runs the relay Zode, valkey and the visa service, all in
  the host's network namespace, inside the integration-test Docker image
  with `--network host`. It uses `lib/zode_funcs.sh` and the Zode netns test
  fixtures.
* **Windows 11 VM** (or physical box) — runs `ph.exe zode` from an elevated
  PowerShell. It must reach the Linux host directly (bridged networking, or
  libvirt NAT, where the host is `192.168.122.1`).

The keys and certificates come from `integration-test/pregen` and are
**test-only fixtures** — do not reuse them outside a private test network.

```
   Linux host (docker, host network)            Windows VM
  ┌──────────────────────────────────┐        ┌────────────────────────┐
  │ ph zode (relay), TUN zrelay      │  UDP   │ ph.exe zode (zb)       │
  │   fd5a:5052::2, vs.zpr           │◀─:5000─┤  self_addr 0.0.0.0:5000│
  │   advertised 192.168.122.1:5000  │        │  initial link: relay   │
  │ valkey, vs (bind vs.zpr)         │        │  zpr-addr fd5a:5052::3 │
  └──────────────────────────────────┘        │  VSS :8183             │
                                              └────────────────────────┘
```

## Prerequisites

Linux host:

* Binaries built on the host: `make` at the `zl-zpr-core` root (gives
  `target/debug/ph`, `ph-cli`), plus `vs` from a sibling
  `zl-zpr-visaservice` checkout and `zplc` from a sibling `zl-zpr-compiler`
  checkout, both from a compatible build set with this core (see
  `docs/BUILD.md`, "Compatible build sets", in `zl-zpr-dev-context`).
  Symlink `vs` into `integration-test/`, as for the netns tests (see the
  README): the container below mounts the sibling checkouts at the same
  paths, so the link resolves inside it.
* Docker running, caller in the `docker` group. Build the test image once:
  `make -C integration-test docker-image`.

Windows VM:

* `ph.exe` and `ph-cli.exe` built on the VM per the Windows build
  prerequisites in `docs/SETUP.md` ("Windows"):

  ```powershell
  cargo build -p ph
  cargo build -p ph-cli --no-default-features
  ```

* `wintun.dll` (x64) from <https://www.wintun.net> placed **in the same
  directory as `ph.exe`**. The DLL is loaded at runtime; without it `ph`
  exits at startup with a load error. `wintun.dll` is signed by WireGuard
  LLC; `ph.exe` itself is unsigned and runs fine from an elevated console.
* The VM must expose **more than one logical CPU** to Windows — check with
  `(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors`.
  libvirt presents vCPUs as sockets by default and Windows 11 *Home* uses
  only one socket, leaving 1 usable CPU; `ph` then livelocks (a tokio/mio
  re-register loop starves the fastpath — the management side goes silent
  for 13–25 s right after the VSAPI TLS handshake). libvirt fix:
  `<topology sockets='1' cores='4'/>` in the domain XML.

## 1. Linux side: the relay and the visa service

The relay runs in the host's network namespace, so the VM reaches it at the
host's address on the VM network (`192.168.122.1` for libvirt NAT). The
relay hosts the visa service (zl-zipline#229): the relay's TUN carries its
own address and `vs.zpr`, and valkey and `vs` run in the same namespace,
started after the relay.

The fixture policy `pregen/zodes-login.zplc` gives the relay the substrate
address `10.2.0.1:5000`, gives zb none, and names a fake identity provider
on `127.0.0.1:9000` for section 3. Copy `pregen` to a scratch directory,
point both at the host's address, and compile it. From the `zl-zpr-core`
root:

```sh
export WORK=$(mktemp -d /tmp/zpr-zode.XXXX)
cp -r integration-test/pregen "$WORK/pregen" && cd "$WORK/pregen"
sed -i -e 's/i0 = "10.2.0.1:5000"/i0 = "192.168.122.1:5000"/' \
  -e 's|https://127.0.0.1:9000|https://192.168.122.1:9443|' zodes-login.zplc
zplc -c zodes-login.zplc -k zpr-rsa-key.pem -f v2 -o zodes-remote.bin2 zodes-login.zpl
cd -
```

Enter the integration-test container (host network; the capabilities and
the apparmor opt-out are what TUN creation needs):

```sh
# Where integration-test/vs points (a linked worktree's sibling checkout or a
# build-set directory may lie outside the parent mounted below).
VS_DIR=$(dirname "$(realpath integration-test/vs)")
docker run --rm -it --network host \
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=NET_RAW \
  --security-opt apparmor=unconfined --device /dev/net/tun \
  -v "$(realpath ..)":"$(realpath ..)" -v "$WORK":"$WORK" -e WORK \
  -v "$VS_DIR":"$VS_DIR" \
  -w "$PWD/integration-test" zpr-integration-test bash
```

Inside the container, from `integration-test/`:

```sh
source lib/common_funcs.sh; source lib/zode_funcs.sh
PREGEN=$WORK/pregen ZODE_POLICY_BIN=zodes-remote.bin2
RELAY_IP=192.168.122.1      # the host as the Windows Zode sees it
mkdir -p "$WORK/run" && cd "$WORK/run"
create_ca_key_and_cert ca
# A fresh, one-day CA for the fake IdP's certificate (section 3). The test
# CA's key is a checked-in fixture, so it is never put in a trust store.
openssl req -x509 -newkey rsa:2048 -nodes -keyout idp-ca.key -out idp-ca.crt \
  -subj /CN=zpr-test-idp-ca -days 1 2> /dev/null
ip tuntap add name zrelay mode tun multi_queue && ip link set zrelay up
create_actor_key_and_cert ca relay
# The relay lists vs.zpr after its own address and applies both to zrelay.
"$PH_BIN" zode -l all=INFO --control-path relay.sock \
  --advertised-substrate-addr "$RELAY_IP:5000" \
  --ca-file ca.crt --certificate-file relay.crt --private-key-file relay.key \
  --auth-private-key "$PREGEN/node-rsa-key.pem" --km-impl noise \
  --relay true --forwarding true --tun-if zrelay \
  --zpr-addr "$RELAY_ZPR_ADDR" --zpr-addr "$VS_ZPR_ADDR" > relay.log 2>&1 &
until ip -6 addr show dev zrelay | grep -q "inet6 $VS_ZPR_ADDR/"; do sleep 1; done
# The visa service binds vs.zpr, so it starts only now, in the same namespace.
# `vs --clear-state` flushes whatever answers on its Valkey port, so the test
# Valkey gets a port of its own, and the visa service starts only once that
# Valkey is up and is the one holding the port.
create_actor_key_and_cert ca vs.zpr
VK_PORT=6390
emit_vs_config ca vs.zpr | sed "s|127.0.0.1:6379|127.0.0.1:$VK_PORT|" > vs-config.toml
write_vs_admin_key
if (exec 3<>/dev/tcp/127.0.0.1/$VK_PORT) 2> /dev/null; then
  echo "127.0.0.1:$VK_PORT is in use: set another VK_PORT and run these lines again"
else
  "$VALKEY_SERVER_BIN" --port "$VK_PORT" --save "" --appendonly no > valkey.log 2>&1 &
  VK_PID=$!
  wait_for 15 bash -c "exec 3<>/dev/tcp/127.0.0.1/$VK_PORT" && kill -0 "$VK_PID" &&
    env XDG_DATA_HOME=/tmp SSL_CERT_FILE="$PWD/idp-ca.crt" "$VS_BIN" -c vs-config.toml \
      --clear-state "$PREGEN/$ZODE_POLICY_BIN" > vs.log 2>&1 &
fi
wait_for 30 check_registered relay.log   # the relay registered with the VS
create_actor_key_and_cert ca zb      # the Windows Zode's identity
```

Leave this shell open: section 3 starts the fake identity provider in it,
and section 5 tears it down.

## 2. Windows side: a Zode with a wildcard address

Copy `ph.exe`, `ph-cli.exe` and `wintun.dll` to a directory such as
`C:\zpr-zode`, with `ca.crt`, `zb.crt` and `zb.key` from `$WORK/run` and
`pregen/zb-rsa-key.pem`.

zb runs on the default config: no `--self-addr`, so it binds the wildcard
`0.0.0.0:5000`, and no `--advertised-substrate-addr`. On every VS-API
`connect` and `open` it reports its initial link's current local address,
with `self_addr`'s port. The address follows the network that way, so a
laptop Zode needs no address in its config. Network-change runs (switching
the VM's network) are tracked in
[zl-zipline#263](https://github.com/org-zpr/zl-zipline/issues/263).

From an **elevated** PowerShell (Wintun device creation requires it):

```powershell
cd C:\zpr-zode
.\ph.exe zode -l all=INFO --initial-link relay@192.168.122.1:5000 `
  --tun-if zpr-zode --zpr-addr fd5a:5052::3 `
  --ca-file ca.crt --certificate-file zb.crt -k zb.key `
  --auth-private-key zb-rsa-key.pem
```

No inbound rule is needed for the link: zb dials out, and the replies are
allowed. The visa service reaches zb's VSS (TCP 8183) over the Wintun
interface, which Windows places on the Public profile, where unsolicited
inbound is dropped. The rule **cannot be added up front**:
`-InterfaceAlias zpr-zode` fails with "The specified interface was not
found" until `ph.exe` has created the adapter. Add it from a **second
elevated PowerShell** once the Zode is up, and keep it until section 5:

```powershell
New-NetFirewallRule -DisplayName zpr-zode-vss -Direction Inbound `
  -Protocol TCP -LocalPort 8183 -InterfaceAlias zpr-zode -Action Allow
```

**Expected:**

* zb: `WinTun: Creating adapter` (plus `Removed orphaned adapter` after a
  previous hard kill); `Using packet I/O engine windows_unbatched`;
  `dock listening on 0.0.0.0:5000`; `reporting substrate address the
  initial link's local address at each connect/open, port 5000 (wildcard
  self_addr) to the visa service`; `Started Zode link with
  192.168.122.1:5000 as the dialer`; `installed bootstrap visas [...] bound
  to the link`; `node access granted to visa service`; `registered VSS`;
  `received topology update`. No startup error.
* `netstat -ano -p UDP` shows `0.0.0.0:5000`. `.\ph-cli.exe link show`
  shows one link, `192.168.122.1:5000 (Active)`; `.\ph-cli.exe counters`
  answers over the named pipe.
* relay.log: `Started Zode link with <VM IP>:5000 as the answerer`, then
  `handed bootstrap visas [...] to "zb"`. The relay's topology goes from
  `peer unset, ... peer cn "zb"` to `peer <VM IP>:5000, ... peer cn "zb"`.
  That is the address the visa service holds for zb: zb's real address on
  the VM network.
* `ping -6 -n 5 fd5a:5052::1` (the visa service, through the relay): 5/5.

## 3. Log in on the Zode (zl-zipline#233)

A person logs in on the Zode with `ph-cli`, and the Zode's own actor gains
the user's OIDC attributes until `ph-cli logout`. This section checks that
on Windows: the admin RPC `login` over the named pipe, the visa-service
nonce, and the agent callback to `ph-cli`. The policy from section 1 lets
zb reach the relay (`fd5a:5052::2`) only while the user `user-zb` is logged
in.

Setup, beyond sections 1 and 2:

* **The fake IdP on the Linux host's address**, with a server certificate
  for that IP signed by section 1's IdP CA. In the container shell, in
  `$WORK/run`:

  ```sh
  HOST_IP=192.168.122.1
  openssl req -new -newkey rsa:2048 -nodes -keyout idp.key -subj "/CN=$HOST_IP" -out idp.csr
  openssl x509 -req -in idp.csr -CA idp-ca.crt -CAkey idp-ca.key -CAcreateserial -days 1 \
    -out idp.crt -extfile <(printf "subjectAltName=IP:$HOST_IP")
  mkdir -p idp-state
  python3 "$FAKE_IDP" --host "$HOST_IP" --port 9443 \
    --state-dir idp-state --tls-cert idp.crt --tls-key idp.key \
    --signing-key "$PREGEN/fake-idp-rsa.key" \
    --client-id zpr-test-client --sub user-zb --email user-zb@example.com \
    --hd example.com > idp.log 2>&1 &
  ```

* **Windows must trust the IdP CA** for `ph-cli` to reach the IdP: `ph-cli`
  uses the system trust store. Copy `idp-ca.crt` from `$WORK/run` to
  `C:\zpr-zode` (never `idp-ca.key`). This is a change to the test host;
  section 5 undoes it. From the elevated PowerShell:

  ```powershell
  Import-Certificate -FilePath C:\zpr-zode\idp-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
  ```

  Without it, the login stops at the IdP with `IdpUnreachable` (exit 4),
  after the nonce and the agent callback have run.
* **The VSS firewall rule** (`zpr-zode-vss`, section 2) is needed: the
  identity-provider list reaches the Zode over its VSS connection. Without
  it, `connect` fails with `AuthUnavailable` (exit 1) before asking for a
  nonce.

On the Zode, **as yourself, not elevated** (so `ph-cli` can open the
browser), in `C:\zpr-zode`:

```powershell
.\ph-cli.exe login-status            # State: logged out
.\ph-cli.exe auth-agent --no-browser # prints a URL: open it in the VM's browser; stays resident
```

Then, from another PowerShell:

```powershell
.\ph-cli.exe login-status            # State: logged in, Issuer, Expires in, Auth agent: registered
ping -6 -n 5 fd5a:5052::2            # the relay, as the logged-in user: replies (the first may be lost)
.\ph-cli.exe logout                  # Logged out; the Zode stays connected
# Wait ~10 s: the visa service revokes the user flow's visa (vs.log, zb's log).
ping -6 -n 3 fd5a:5052::2            # no replies
ping -6 -n 3 fd5a:5052::1            # the visa service: still replies (the device flow)
.\ph-cli.exe logout                  # logout failed: not logged in (exit 1)
```

`ph-cli connect --no-browser` logs in the same way and exits once the
login completes, instead of staying resident as the agent.

Pass criteria: `auth-agent` prints `Logged in`; `login-status` shows the
issuer and the time left; the ping to the relay is answered while logged in
and not after `logout`, while the ping to the visa service is answered
throughout; zb's log shows `Zode login: logged in with
<issuer>` and `Zode login: logged out`, and never a token or a nonce.

When `ph` runs as a Windows service (LocalSystem), your account must be in
the configured `control_group` to reach the pipe (section 4).

## 4. Control pipe access for non-elevated `ph-cli` (zipline#154) — operator-run

**Operator-run.** This section needs a Windows VM; nothing on the Linux
build host runs it, and the unit gate only *compiles* the Windows-only
tests (`cargo xwin check --tests`). It checks the control pipe's DACL from
`docs/SETUP.md` ("Control pipe access and non-elevated `ph-cli`") in the
two launch modes that matter: `ph` under a service identity (SYSTEM, via
`psexec -s`), and `ph` from an elevated console. Run it before merging a
change to `sys/windows/control.rs`, `sys/control_access.rs`, or
`admin_api::local_group_sid`.

The checks use `ph-cli link show` as the round-trip. A denied open
surfaces as `ph-cli`'s "no live packet handler socket (tried … and …)"
error, because both candidate pipes refuse it; `-p \\.\pipe\zpr-control`
shows the raw `Access is denied` instead.

### 4a. One-time setup (elevated PowerShell)

Keep the Linux side from section 1 up, so `ph.exe` joins as in section 2.
Then create the group and two local test users (the passwords are
throwaway; this VM is a test box):

```powershell
net localgroup zipline /add
net user zpr-member  'Smoke-154-a!' /add
net user zpr-outside 'Smoke-154-b!' /add
net localgroup zipline zpr-member /add
# Windows unit tests that only compile on the build host — run them here:
cargo test -p admin-api local_group
```

Expected: the three `local_group` tests pass (`Users` resolves to
`S-1-5-32-545`, a random name is `None`, `SYSTEM` is `None`).

Membership is read at logon. `runas` starts a fresh logon, so it always
sees the current membership; an interactive session of a user added to the
group must log off and on first (the re-logon caveat in `docs/SETUP.md`).

### 4b. `ph` under a service identity (operator-run)

Stop the `ph.exe` from section 2 first (Ctrl-C). From an elevated
PowerShell, with [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec):

```powershell
cd C:\zpr-zode
psexec -s -w C:\zpr-zode C:\zpr-zode\ph.exe zode -l all=INFO `
  --initial-link relay@192.168.122.1:5000 --tun-if zpr-zode --zpr-addr fd5a:5052::3 `
  --ca-file ca.crt --certificate-file zb.crt -k zb.key `
  --auth-private-key zb-rsa-key.pem --control-group zipline
```

Expected startup line, in addition to section 2's:
`control pipe: granting local group 'zipline' (S-1-5-21-…) access`.

Then, from the **non-elevated** desktop session (or `runas`):

```powershell
# Member: succeeds.
runas /user:zpr-member  "cmd /k C:\zpr-zode\ph-cli.exe link show"
# Non-member: denied.
runas /user:zpr-outside "cmd /k C:\zpr-zode\ph-cli.exe link show"
# Your own admin account, NOT elevated, not in the group: denied
# (an unelevated admin token holds Administrators deny-only).
C:\zpr-zode\ph-cli.exe link show
```

Pass criteria (each one operator-run):

* [ ] **4b-1** `zpr-member`, not elevated: `link show` reports the link to
  the relay.
* [ ] **4b-2** `zpr-outside`: denied (the "no live packet handler socket"
  error, or `Access is denied` with `-p \\.\pipe\zpr-control`).
* [ ] **4b-3** Your admin account, not elevated, not a member: denied.
* [ ] **4b-4** `net localgroup zipline <your account> /add`, log off and on,
  repeat 4b-3: now succeeds.

Ctrl-C does not reach a `psexec -s` process; stop it with
`taskkill /im ph.exe /f` (the next start reaps the stale Wintun adapter,
see section 5).

### 4c. `ph` from an elevated console (operator-run)

Section 2's command line, plus `--control-group zipline`:

```powershell
cd C:\zpr-zode
.\ph.exe zode -l all=INFO --initial-link relay@192.168.122.1:5000 `
  --tun-if zpr-zode --zpr-addr fd5a:5052::3 `
  --ca-file ca.crt --certificate-file zb.crt -k zb.key `
  --auth-private-key zb-rsa-key.pem --control-group zipline
```

* [ ] **4c-1** Same user, **not elevated** (a normal PowerShell as the
  account that started `ph`): `.\ph-cli.exe link show` succeeds through the
  owner-SID ACE, without group membership. (Remove yourself from the group
  first if 4b-4 added you, and log off and on.)
* [ ] **4c-2** `runas /user:zpr-member "cmd /k C:\zpr-zode\ph-cli.exe link show"`:
  succeeds through the group ACE (the over-the-shoulder case).
* [ ] **4c-3** `runas /user:zpr-outside "cmd /k C:\zpr-zode\ph-cli.exe link show"`:
  denied.

### 4d. Group configured but missing (operator-run)

Section 2's command line, plus `--control-group zpr-no-such-group`.

* [ ] **4d-1** One warning at startup:
  `control group 'zpr-no-such-group' not found on this host; the control channel keeps its default access`.
  `ph` keeps running, and an elevated `ph-cli link show` still works.

### 4e. Cleanup

```powershell
net user zpr-member /delete
net user zpr-outside /delete
net localgroup zipline /delete
```

## 5. Shutdown and teardown

In the PowerShell running `ph.exe`, press **Ctrl-C** once. Expect
`attempting graceful shutdown` in the log and the process exiting on its
own. Then check that the Wintun adapter is gone:

```powershell
Get-NetAdapter -Name zpr-zode   # expect: no matching adapter / error
```

A leftover `zpr-zode` adapter is a failure (the delete-on-exit path in
`sys/windows/zprtun.rs` did not run). After a hard kill (not Ctrl-C) a stale
adapter is expected (Windows names it `zpr-zode 1`, so check `Get-NetAdapter`
without `-Name`); the next `ph.exe` startup reaps it (`Removed orphaned
adapter "zpr-zode 1"`).

Then undo the changes to the VM:

```powershell
Remove-NetFirewallRule -DisplayName zpr-zode-vss
# Only if section 3 imported the IdP CA: the thumbprint Import-Certificate printed.
Remove-Item Cert:\LocalMachine\Root\<thumbprint>
```

Linux: leave the container (`exit` stops the relay, valkey, the visa
service and the IdP with it). `zrelay` is in the host's namespace and
outlives the container, so delete it, and the scratch directory, on the
host:

```sh
sudo ip link del zrelay
sudo rm -rf "$WORK"
```

## Recording the result

Paste the transcript (Zode startup lines, `ph-cli` output, ping output,
shutdown and the post-exit `Get-NetAdapter`) on the PR or issue the run
verifies, and fill in **Findings** below in the same PR. For section 4,
paste the ticked checklist with each check's `ph-cli` output and the `ph`
startup line for the group.

Packet captures: `pktmon` on the VM does **not** capture Wintun traffic —
capture on the Linux side instead (`tcpdump -ni zrelay`, where the visa
service runs beside the relay).

## Findings

*(keep one dated subsection per run)*

### 2026-11-14 — Zode with a wildcard address (section 2, zl-zipline#230)

* Build (`zl-zpr-core`): `feature/zodes-230-2-network-change` at `81c474e`,
  the same build on the VM and the Linux host · vs `v0.22.0-zodes.8` ·
  policy: `pregen/zodes.zplc`, relay `i0` rewritten, zplc 0.21.0
* Windows 11 Home, version 10.0.26200; VM at 192.168.122.39 on libvirt NAT

| Check | Result | Evidence |
|---|---|---|
| start with the wildcard and no advertised address, then join | PASS | `dock listening on 0.0.0.0:5000` (`UDP 0.0.0.0:5000`); no startup error; `Using packet I/O engine windows_unbatched`; bootstrap visas installed, `node access granted`, `registered VSS`, topology received. zb `link show`: one link, `192.168.122.1:5000 (Active)`. The relay accepted one link from `192.168.122.39:5000` and handed it bootstrap visas. The relay's topology went from `peer unset` to `peer 192.168.122.39:5000` for zb. `ping -6` to the visa service: 5/5, 1-15 ms. Only the temporary VSS rule was added, and it was removed. |

### 2026-11-13 — Zode login (zl-zipline#233), partial

* Build: `zl-zpr-core` `feature/zodes-233-zode-login` @ `1fa417b`, on the VM
  (Windows 11). Linux side: a relay Zode in the host netns advertising
  `192.168.122.1:5000`, the visa service (`v0.22.0-zodes.6`) docked on it
  from a netns, the zodes fixture policy plus a fake-IdP trusted service, and
  `fake-idp.py --host 192.168.122.1`. The VM ran Zode `zb`
  (`--self-addr 192.168.122.39:5000 --initial-link relay@192.168.122.1:5000`).
* No change to the VM: no firewall rule, no CA in the trust store.
* Result: the Zode joined, got its VS-API session and registered its VSS,
  but the visa service could not reach the VSS (no VSS firewall rule), so
  no identity provider was listed. Over the named pipe: `login-status`
  printed `State: logged out` (exit 0); `logout` printed `logout failed: not
  logged in` (exit 1); `connect --no-browser` printed `login failed:
  AuthUnavailable` (exit 1, Zode log `Zode login requested` / `Zode login
  failed: AuthUnavailable`); `login-status` then showed `Last failure:
  AuthUnavailable`. The nonce, the agent callback and a completed login were
  not reached: they need the VSS rule and the CA trusted.
