# Setting up a ZPRnet by hand

A step-by-step walkthrough of standing up a minimal ZPRnet of Zodes: a
relay Zode that hosts the visa service, and endpoint Zodes that join through
it. It ends with a reference for the control socket and for certificate
verification.

A Zode is a ZPR node that carries its own host's traffic: `ph zode`, the
only mode of `ph`. Every Zode is either a **relay** (`relay = true`), which
never dials and accepts links from the Zodes in its topology, or dials its
relay over its **initial link** (`initial_link`). Exactly one of the two is
required.

The scripts in [`../integration-test/`](../integration-test/) do all of this
automatically on network namespaces (`lib/zode_funcs.sh` starts the relay
and the Zodes, and `pregen/zodes.zplc` is their policy); read them when a
step here is unclear or has drifted.

You need these binaries on hand:

* `ph` from this repository (`make`, then `target/debug/ph`).
* `vs` from the [zpr-visaservice repository](https://github.com/org-zpr/zpr-visaservice).
* `zplc` from the [zpr-compiler repository](https://github.com/org-zpr/zpr-compiler),
  unless you already have a compiled policy.

Take `vs` and `zplc` from a build set compatible with this `ph` (see
`docs/BUILD.md`, "Compatible build sets", in `zl-zpr-dev-context`): a
compiler without Zode support rejects the policy below, whose endpoint
Zodes have no substrate addresses.

This walkthrough uses three Linux hosts:

* the relay, `relay`, on substrate address `129.6.7.1`, with ZPR address
  `fd5a:5052::2`. It also runs Valkey and the visa service, which listens on
  `vs.zpr` (`fd5a:5052::1`), an address the relay puts on its own TUN;
* `web`, ZPR address `fd5a:5052::3`, which serves HTTP on port 80;
* `laptop`, ZPR address `fd5a:5052::4`, which may reach `web`'s service.

Each name is also the Zode's certificate CN, and its node name in the
policy.


## Create authentication keys to share with the visa service

Each Zode authenticates to the visa service with an RSA key whose public
half is in the policy. The policy also names one for `vs.zpr`, as the test
fixtures do:

```sh
for NAME in relay web laptop vs; do
  openssl genrsa -out $NAME-private-key.pem
  openssl rsa -in $NAME-private-key.pem -pubout -out $NAME-public-key.pem
done
```

Each Zode keeps its private key (`auth_private_key` below); the public keys
go into the policy's `[bootstrap]` section.


## Create a certificate authority keypair

In addition to the visa service authentication, there is a separate
authentication check when a link between two Zodes comes up. This uses
certificates holding noise keys and signed by a certificate authority (CA),
and each Zode verifies its peer's. So we need a certificate authority.

We'll put the authority related files into a directory named `authority`.
You will be prompted for a pass phrase. You'll need to use that whenever
you sign a certificate using the authority key.

```bash
# A place to put the files
mkdir authority

cd authority

# New key for the CA
openssl genrsa -aes256 -out auth-ca.key 4096

# New self-signed cert
openssl req -x509 -new -nodes -key auth-ca.key -sha256 -days 1826 -out auth-ca.crt
```

## Create a signed noise certificate for each Zode

Using the handy `zpr-pki` script, one certificate per Zode, with the Zode's
name as its CN:

```sh
for NAME in relay web laptop; do
  ./integration-test/lib/zpr-pki genkey >$NAME-noise.key
  # First extract a public key from the private one
  ./integration-test/lib/zpr-pki pubkey <$NAME-noise.key >$NAME-noise-pub.pem
  # Then sign the public key
  ./integration-test/lib/zpr-pki gensignedcert authority/auth-ca.crt authority/auth-ca.key \
    /CN=$NAME 365 < $NAME-noise-pub.pem >$NAME-noise.crt
done
```

## Create TLS credentials for the visa service

These are used over the HTTPS admin interface.  By default the visa service will
look for two files:

- `admin-tls-cert.pem`
- `admin-tls-key.pem`

Create them like so:

```sh
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out admin-tls-cert.pem -keyout admin-tls-key.pem
```


## Create a configuration file for each Zode

The schema, with every key explained, is
[`adapter/ph/example-node-config.toml`](../adapter/ph/example-node-config.toml).
Unknown sections and keys are refused. Any setting can also be given, or
overridden, on the command line (`ph zode --help`).

The relay, `relay-conf.toml`. It lists its own ZPR address first and
`vs.zpr` after it, and puts both on its TUN. `forwarding = true` lets it
carry traffic between the other Zodes:

```toml
[global]
ca_file = "authority/auth-ca.crt"
certificate_file = "relay-noise.crt"
private_key_file = "relay-noise.key"
self_addr = "129.6.7.1:5000"
zpr_addr = [ "fd5a:5052::2", "fd5a:5052::1" ]
tun_if = "tun9"

[node]
relay = true
forwarding = true

[authentication]
auth_private_key = "relay-private-key.pem"
```

An endpoint Zode, `web-conf.toml`. Its initial link names the relay's
substrate address and certificate CN. With no `self_addr` it binds the
wildcard address, and reports its initial link's local address to the visa
service, so it needs no address of its own in the config:

```toml
[global]
ca_file = "authority/auth-ca.crt"
certificate_file = "web-noise.crt"
private_key_file = "web-noise.key"
zpr_addr = [ "fd5a:5052::3" ]
tun_if = "tun9"

[node]
initial_link = { addr = "129.6.7.1:5000", cn = "relay" }

[authentication]
auth_private_key = "web-private-key.pem"
```

`laptop-conf.toml` is the same with `laptop` in place of `web` and
`fd5a:5052::4` as its address.


## Configure the visa service (optional)

The visa service does not require custom configuration. However if you want
to customize it you can get it to spit out a configuration file. The default
name for it is `vs.toml`, so:

```sh
./vs --gen-config >vs.toml
```


## Start Valkey

Valkey is **required** by the visa service. Run it on the relay host.

On linux systems it may be installed as a service:

```sh
# check status
systemctl status valkey-server

# and if not running:
systemctl start valkey-server
```

Or you can just start it in the foreground in a terminal:

```sh
valkey-server
```


## Write a policy and compile it.

Here is a simple policy to let `laptop` access a "WebService" on `web`,
over HTTP port 80.

Create a file called `zpr-web.zpl` with these contents:

```
define zode as a device with zpr.adapter.cn.

define Laptop as zode with zpr.adapter.cn:laptop.

define WebService as a service with device.zpr.adapter.cn:web.

allow Laptop to access WebService.
```

Then write a configuration file. It names each Zode, the links between
them, and the relay that hosts the visa service (`dock_node`). Only the
relay has a substrate address in the policy: the visa service learns each
other Zode's address from what it reports when it connects. Create a file
called `zpr-web.zplc` with these contents:

```toml
[resolver]
order = ["hosts", "dns"]

[resolver.hosts]
"relay.zpr" = "fd5a:5052::2"
"web.zpr" = "fd5a:5052::3"
"laptop.zpr" = "fd5a:5052::4"

[nodes.relay]
provider = [ [ "device.zpr.adapter.cn", "relay" ] ]
zpr_address = "relay.zpr"
transit = true

[nodes.relay.substrate_addrs]
i0 = "129.6.7.1:5000"

[nodes.web]
provider = [ [ "device.zpr.adapter.cn", "web" ] ]
zpr_address = "web.zpr"

[nodes.laptop]
provider = [ [ "device.zpr.adapter.cn", "laptop" ] ]
zpr_address = "laptop.zpr"

[links.relay-web]
peers = [ { node = "relay" }, { node = "web" } ]

[links.relay-laptop]
peers = [ { node = "relay" }, { node = "laptop" } ]

[trusted_services.default]
cert_path = "authority/auth-ca.crt"

[visa_service]
dock_node = "relay"

[bootstrap]
"relay" = "relay-public-key.pem"
"web" = "web-public-key.pem"
"laptop" = "laptop-public-key.pem"
"vs.zpr" = "vs-public-key.pem"

[protocols.http]
l4protocol = "iana.TCP"
port = 80

[services.WebService]
protocol = "http"
```

To compile, use the compiler:

```bash
zplc zpr-web.zpl

# This will create the binary policy file, "zpr-web.bin2"
```

## Start the relay, the visa service, and the endpoint Zodes

`ph` expects to be able to access directory `/var/run/zpr`. On each host:

    sudo mkdir -p /var/run/zpr

On Linux, create each Zode's TUN interface first, as the integration tests
do: a multi-queue TUN, up, with no address. `ph zode` applies its own ZPR
addresses to it (the relay's `vs.zpr` included).

```bash
sudo ip tuntap add name tun9 mode tun multi_queue
sudo ip link set tun9 up
```

On the relay host, start the relay:

    sudo ./ph zode -c /path/to/relay-conf.toml

The visa service binds `vs.zpr`, so start it only once the relay has put
`fd5a:5052::1` on `tun9` (`ip -6 addr show dev tun9`), on the same host:

    ./vs /path/to/zpr-web.bin2

The relay connects to the visa service and logs `registered VSS`. Then, on
the `web` and `laptop` hosts:

    sudo ./ph zode -c /path/to/web-conf.toml
    sudo ./ph zode -c /path/to/laptop-conf.toml

Each dials the relay, receives bootstrap visas from it, connects to the visa
service, and logs `registered VSS`. `ph-cli link show` on each shows its
link to the relay `(Active)`. Now start the web service on `web`, and
`laptop` can reach it at `http://[fd5a:5052::3]/`.


## Control socket ownership and `ph-cli` access

`ph` needs root (it creates a TUN interface), but `ph-cli` should not.
`ph` decides who owns its control socket at startup, and the
socket path and permissions follow from that. There are two modes:

**Sudo/pkexec-invoked (owner known).** When `ph` is started with
`sudo ph ...` (or via `pkexec`), it recovers the invoking user from
`SUDO_UID`/`SUDO_GID` (or `PKEXEC_UID`) and puts the socket in a per-user
directory, chowned to that user with mode `0600`:

    /var/run/zpr/<uid>/control.sock

The per-user base is fixed at `/var/run/zpr` — deliberately not derived
from `HOME`/`XDG_DATA_HOME`, since `ph` runs in root's environment and
`ph-cli` in the user's, and the two must agree on the path.

`ph-cli`, run as that same user with no `sudo` and no `-p`, looks in the
per-user directory for its own uid first and connects directly. Because each
invoking user gets their own directory, two Zodes started by two different
users on one host do not collide.

**systemd-started (owner unknown).** When `ph` is started by systemd,
launchd, `su -`, or a direct root login, there is no invoking user to
recover. The socket stays at the shared path (`/var/run/zpr/control.sock`).
If a control group is configured — `control_group = "<name>"` in the
config file's `[global]` section, or `--control-group <name>` on the
command line (the flag wins) — and that group exists, the socket is
chgrp'd to it with mode `0660`, so the group's members can use `ph-cli`
without sudo. The packager that installs `ph` as a service owns the group:
it creates it at install, deletes it at uninstall, and passes its name to
`ph` (Zipline uses `zipline`;
[org-zpr/zipline#29](https://github.com/org-zpr/zipline/issues/29)). With
no group configured, or a configured group that does not exist, the socket
is left exactly as before (root-only) and `ph` logs one warning — the group
is a packaging/admin choice, never a hard runtime dependency. The setting
has no default, and it is ignored when an owner was resolved (the
sudo/pkexec mode above always wins).

**Behaviour change (zipline#154).** Before this setting existed, an
ownerless `ph` looked for a hard-coded group named `zpr`. It no longer
does: a host that relied on a `zpr` group must now say so explicitly, with
`control_group = "zpr"` (or `--control-group zpr`). Without that, the
socket stays root-only and `ph` logs the warning.

`ph-cli`'s default search order is: the per-user socket for your uid, then
the shared socket under your data home, then the fixed shared socket
`/var/run/zpr/control.sock`. The last entry is there because "the shared
path" depends on the environment: it lives under `$XDG_DATA_HOME`, or
`~/.local/share` if that exists, and only falls back to `/var/run`
otherwise. A service-started `ph` has no `HOME` and so binds under
`/var/run/zpr`, while a desktop user's `ph-cli` usually has
`~/.local/share`. Without the fixed entry, a `control_group` member would
need `-p` (zipline#77). A candidate is chosen by actually connecting to it,
not by checking the pathname exists — a stale socket file left behind by a
dead `ph` (nothing unlinks it on a crash) never shadows a live server at a
later path. If none answers, `ph-cli` fails with an error naming every
path tried. An explicit `-p` (control) always wins, on both `ph` and
`ph-cli`, as does an explicit `control_path` in the config file — so
multi-Zode and test setups keep full control.

**Security note.** Reaching the control socket means being able to start and
stop links and to log a user in or out on this Zode (`ph-cli connect`,
`auth-agent`, `logout`) — i.e. to supply and observe user credentials for
this Zode. Socket access is Zode control. Membership in the
configured control group grants exactly that, on every platform, so treat
it accordingly: it is not a low-privilege convenience group.


## Windows

`ph zode` runs on Windows 10/11 x64. It creates a Wintun interface, applies
its own ZPR address to it, links to its relay, and carries this machine's
own traffic, exactly like `sudo ph zode -c x.toml` on Linux — within the
constraints below.

**Windows constraints** (deliberate, in this release):

* **Wildcard and multi-homed binds are allowed**, as on unix: the Windows
  engine reads each datagram's destination and sets each send's source
  with `IP_PKTINFO`/`IPV6_PKTINFO` (`WSARecvMsg`/`WSASendMsg`,
  [zipline#150](https://github.com/org-zpr/zl-zipline/issues/150)). A Zode
  with a wildcard `self_addr` reports its initial link's local address to
  the visa service, so the address follows a network change
  ([zl-zipline#230](https://github.com/org-zpr/zl-zipline/issues/230)); a
  relay with a wildcard `self_addr` needs `advertised_substrate_addr`.
* **Elevated console** — Wintun device creation requires Run as
  administrator.
* **A single, unbatched datapath worker** — Wintun enforces one queue and
  the `windows_unbatched` engine drives one substrate socket; functional
  parity with Linux is the bar, throughput is not (measured numbers are in
  the test document below).
* **An inbound firewall rule is required** for TCP 8183 (the VSS listener)
  on the Wintun interface, which Windows places on the Public profile where
  unsolicited inbound is dropped. A Zode that dials its relay needs no rule
  for its link; a relay also needs UDP on its link port (5000 by default).
  The exact rule and when it can be added are in the test document below.
* **One `ph` instance per user without `--control-path`**: the default
  control path is derived from the owner alone, so two Zodes for the same
  user on one host need explicit `--control-path`s to coexist
  ([zipline#169](https://github.com/org-zpr/zl-zipline/issues/169)).

The hand-run, end-to-end verification of a Windows Zode (a Windows VM
joining a relay on a Linux host, reaching the visa service, a user login,
and control pipe access) is
[`integration-test/windows-zode-test.md`](../integration-test/windows-zode-test.md);
run it whenever a change touches the Windows path. CI covers Windows
builds and unit tests (`.github/workflows/adapter.yml` builds and tests `ph`
and `ph-cli` on `windows-latest`), but there is no automated end-to-end
Windows tier that carries real traffic
([zipline#152](https://github.com/org-zpr/zl-zipline/issues/152)); note
that Actions is currently disabled on this fork, so no CI runs here either
way.

**Not supported on Windows** (deliberately, in this release):

* **packet capture to a file** — `ph-cli capture set-file` returns
  `Unsupported`. This is now true on every platform, not only Windows: capture
  needs the capnproto-rust FD-passing fork, which normal builds no longer use
  (see the workspace root `Cargo.toml`),
* a **Windows service or installer** — this repository ships none;
  `ph.exe` is started by hand from an elevated console, and packaging
  (including the service) belongs to Zipline
  ([zipline#147](https://github.com/org-zpr/zl-zipline/issues/147)). The
  contract a service package relies on is under "Control pipe access and
  non-elevated `ph-cli`" below,
* **`ph-cli` filter compilation** — the `pcap` feature is off on Windows, so
  capture filter strings cannot be compiled there.

### Build prerequisites

Building on Windows natively:

1. Visual Studio Build Tools with the "Desktop development with C++"
   workload (MSVC + Windows SDK + CMake).
2. Rust via [rustup](https://rustup.rs) (defaults to
   `x86_64-pc-windows-msvc`).
3. [NASM](https://nasm.us) (`choco install -y nasm`) — required by
   `aws-lc-rs`.
4. Cap'n Proto (`choco install -y capnproto`) — `capnp.exe` must be on
   `PATH`.

Then:

```powershell
cargo build -p ph
cargo build -p ph-cli --no-default-features   # pcap off on Windows
```

Cross-checking from Linux without a Windows box:
`cargo xwin check -p ph -p ph-cli --target x86_64-pc-windows-msvc`
(build errors only — it compiles no test code and links nothing).

### Running

1. Download the signed `wintun.dll` (x64) from
   [wintun.net](https://www.wintun.net) and place it **in the same directory
   as `ph.exe`**. It is loaded at runtime; without it `ph` exits at startup.
2. Write a Zode config as on Linux (same TOML schema; see the examples
   above). Windows-style paths in double-quoted TOML strings need
   escaped backslashes — prefer single-quoted literals: `ca_file = 'C:\zpr\ca.crt'`.
3. Start from an **elevated** (Run as administrator) console — Wintun device
   creation requires it:

   ```powershell
   .\ph.exe zode -c zode.toml
   ```

4. `ph-cli.exe` talks to it over a named pipe instead of the unix socket;
   commands are unchanged. `ph-cli` tries `\\.\pipe\zpr-control-<sid>` (its
   own user SID) first, then the shared `\\.\pipe\zpr-control`, which is
   where `ph` binds unless `--control-path` says otherwise. Who may open the
   pipe is the next subsection.

Ctrl-C shuts down gracefully and deletes the Wintun adapter; a second Ctrl-C
hard-exits. After a crash or hard kill, a stale adapter may remain, named
with a suffix (`zpr 1`, so `Get-NetAdapter -Name zpr` does not show it) — the
next `ph.exe` startup deletes it (`WinTun: Removed orphaned adapter "zpr 1"`).

`ph.exe` does not need to be code-signed to run from an elevated console
(`wintun.dll` is signed by WireGuard LLC); verified on Windows 11 with
Defender SmartScreen at defaults.

### Control pipe access and non-elevated `ph-cli`

The control pipe's DACL is protected (nothing inherited) and grants full
access to exactly: `BUILTIN\Administrators`, the user `ph` runs as, and —
when configured — one local group:

    D:P(A;;GA;;;BA)(A;;GA;;;<ph user SID>)[(A;;GA;;;<group SID>)]

Administrators alone is not enough for everyday use: an administrator's
non-elevated token carries `BUILTIN\Administrators` as deny-only, and a
non-admin user has no matching ACE at all. The group is what lets the
expected deployment — `ph` as a Windows service (LocalSystem, session 0),
users running `ph-cli` as themselves, not elevated — work:

```powershell
# Service-run ph (the packager's service unit passes the name):
ph.exe zode -c C:\ProgramData\zipline\zode.toml --control-group zipline
```

The setting is the same one the unix arm uses: `control_group` in
`[global]`, or `--control-group` (the flag wins). At startup `ph` looks the
name up on the local machine only — `<COMPUTERNAME>\<name>`, then
`BUILTIN\<name>`, never an unqualified name, so a same-named domain group
cannot stand in — and requires the result to be a group. The SID placed in
the DACL is the one Windows returns for that lookup
(`ConvertSidToStringSidW`), never text from the config. If the group is
configured but missing, `ph` keeps the two-ACE DACL and logs one warning:

    control group 'zipline' not found on this host; the control channel keeps its default access

**Packager contract.** The packager owns the group's name and lifecycle on
all three platforms: it creates the group at install, deletes it at
uninstall, and passes the name to `ph` from its service unit
(`zipline-svc` on Windows, `zipline.service` / the launchd plist on
Linux/macOS) — [org-zpr/zipline#29](https://github.com/org-zpr/zipline/issues/29).
An administrator then adds the users who may drive the Zode
(`net localgroup zipline <user> /add`); that is the deliberate admission
step, and nothing is opened up by default. Until a unit passes the name,
the group exists but grants nothing.

How each launch mode is covered:

| How `ph` runs | Who reaches the pipe | How |
|---|---|---|
| Service (LocalSystem) — the expected common case | members of the configured group, not elevated | group ACE |
| Elevated console, same user as `ph-cli` | that user, elevated or not (non-elevated: checked by the VM test) | user-SID ACE |
| Elevated console via over-the-shoulder credentials (a different admin account) | members of the configured group | group ACE |

**Re-logon caveat.** Group membership is read into a user's token at
logon: a user just added to the group must log off and on again (or start
a new logon session) before `ph-cli` can open the pipe.

The security note above applies unchanged: membership in the control group
is Zode control.

The operator-run checks of each launch mode are section 4 of
[`integration-test/windows-zode-test.md`](../integration-test/windows-zode-test.md).


## macOS

`ph zode` runs on a Mac — Apple Silicon or Intel — started by hand with
`sudo ph zode -c x.toml`, exactly as on Linux. It creates a utun interface,
applies its own ZPR address to it, links to its relay, and carries this
machine's own traffic.

**macOS constraints** (deliberate, in this release):

* **A dev/demo Zode** — functional parity with Linux is the bar, not
  throughput. No launchd service; `ph` is started by hand from a terminal.
* **`sudo` is required** — creating a utun needs root, same as the TUN on
  Linux. No TUN pre-creation is needed or possible: `ph` creates the utun
  itself through `TunCtl`. `tun_if`, when set, must be of the form `utunN`;
  left unset, the kernel picks the name.
* **A single, unbatched datapath worker** — the macOS `posix_unbatched`
  engine forces one worker (`new_mq` rejects more). Wildcard and
  multi-homed binds are allowed (pktinfo), as on Windows.
* **IPv6 ZPR addresses only** — `TunCtl::add_address` (and `add_route`)
  return `Unsupported` for IPv4 on macOS; the ZPR internal network is
  IPv6 (`fd5a:5052::/32`).
* **One `ph` instance per user without `--control-path`**: the default
  control path is derived from the owner alone
  ([zipline#169](https://github.com/org-zpr/zl-zipline/issues/169)).

**Addressing.** The Zode creates the utun through `TunCtl` and applies its
ZPR address with `ifconfig <utun> inet6 <addr>/32 alias`. The alias alone
installs the on-link `fd5a:5052::/32` route via the utun — no explicit
route is needed; the kernel does it as part of the alias (verified in the
first end-to-end run, 2026-10-02). No manual `ifconfig` or `route` step is
required before starting `ph`.

**Firewall.** The application firewall has **not been exercised** — it was
disabled on the test Mac (`socketfilterfw --getglobalstate`: State = 0).
A Zode that dials its relay needs nothing for its link; the exposed piece
is TCP 8183 (the VSS listener), which the visa service reaches over the
utun. `/usr/libexec/ApplicationFirewall/socketfilterfw` is the knob if it
is blocked; rules key on the executable's path, so allow the copy of `ph`
you actually start.

The hand-run, end-to-end verification of a macOS Zode (a Mac joining a
relay on a Linux host, reaching the visa service, and a user login) is
[`integration-test/macos-zode-test.md`](../integration-test/macos-zode-test.md);
run it whenever a change touches the macOS path. There is no automated
macOS end-to-end tier.


## Certificate and peer verification reference

### Local certificate (`certificate_file`)

A Zode needs `certificate_file`, and `private_key_file` or
`--noise-private-key`; config validation fails without them. Its name is
the certificate's CN, which is also its node name in the policy.

### Peer certificate verification (`ca_file`)

Every link is between two Zodes, and each verifies the other's certificate
against `ca_file`:

| `ca_file` | Behavior |
|-----------|-----------|
| present | The peer's certificate must be signed by the CA; a link to a peer whose certificate is not is rejected |
| absent | `ph` logs `no ca_file configured; peer certificates will not be verified` at startup, and the noise key manager (the default) refuses to start any Zode link |
