# Setting up a ZPRnet by hand

A step-by-step walkthrough of standing up a minimal ZPRnet: one node, one
visa service, and the adapters that connect them. It ends with a reference
for the control socket and for certificate verification.

The scripts in [`../integration-test/`](../integration-test/) do all of this
automatically on network namespaces; read them when a step here is unclear
or has drifted.

You need these binaries on hand:

* `ph` from this repository (`make`, then `target/debug/ph`).
* `vs` from the [zpr-visaservice repository](https://github.com/org-zpr/zpr-visaservice).
* `zplc` from the [zpr-compiler repository](https://github.com/org-zpr/zpr-compiler),
  unless you already have a compiled policy.

A minimal ZPRnet has a node and a visa service. You will probably also
want a service or two that run on the net, plus some client adapters
that connect in and access the services.


## Create authentication keys to share with the visa service

In order to connect to the initial ZPRnet each adapter needs to share an
RSA key with the visa service.  This is done via policy.  Since we are
going to need a node and a visa service we need two keys.

```sh
openssl genrsa -out node-private-key.pem
openssl genrsa -out vs-private-key.pem
```

The private keys stay with the visa service adapter and node, but we need
to put the public keys in the policy, so first extract them:

```sh
openssl rsa -in node-private-key.pem -pubout -out node-public-key.pem
openssl rsa -in vs-private-key.pem -pubout -out vs-public-key.pem
```

Then in the policy `zplc` file, add a bootstrap section that looks like
this:

```toml
[bootstrap]
"node.zpr.org" = "/path/to/node-public-key.pem"
"vs.zpr" = "/path/to/vs-public-key.pem"
```


## Create a certificate authority keypair

In addition to the visa service authentication, there is a separate
authentication check when the link is first brought up between an adapter
and a node.  This uses certificates holding noise keys and signed by a
certificate authority (CA).  Adapters verify the certs they get from
a node.  So we need a certificate authority:

We'll put the authority related file into a directory named `authority`.
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

## Create a signed noise certificate for the node

Using the handy `zpr-pki` script:

```sh
./integration-test/lib/zpr-pki genkey >node-noise.key

# First extract a public key from the private one
./integration-test/lib/zpr-pki pubkey <node-noise.key >node-noise-pub.pem

# Then sign the public key
./integration-test/lib/zpr-pki gensignedcert authority/auth-ca.crt authority/auth-ca.key \
  /CN=node.zpr.org 365 < node-noise-pub.pem >node-noise.crt
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


## Create a configuration file for your node

Assuming:
- Node substrate (dock) address is `129.6.7.1`
- Node ZPR address is `fd5a:5052:90de::1`

Sample configuration, place in a file named `node-conf.toml`.

```toml
[global]
# ca_file is needed for the node to verify adapter certificates and recognize
# the visa-service adapter as special.  Without it, VS routing will not work.
ca_file = "authority/auth-ca.crt"
certificate_file = "node-noise.crt"
private_key_file = "node-noise.key"
self_addr = "129.6.7.1:5000"
zpr_addr = [ "fd5a:5052:90de::1" ]
tun_if = "tun9"

[authentication]
auth_private_key = "node-private-key.pem"
```


## Create a signed noise certificate for the visa service adapter

The visa service adapter must present a CA-signed certificate so the node can
recognize it as the special visa-service peer.  The certificate CN **must** be
`vs.zpr` — that is the hard-coded visa-service distinguished name the node
matches against.  Generate and sign one:

```sh
./integration-test/lib/zpr-pki genkey >vs-noise.key
./integration-test/lib/zpr-pki pubkey <vs-noise.key >vs-noise-pub.pem
./integration-test/lib/zpr-pki gensignedcert authority/auth-ca.crt authority/auth-ca.key \
  /CN=vs.zpr 365 < vs-noise-pub.pem >vs-noise.crt
```


## Create a configuration file for the visa service adapter

Sample configuration, place in a file named `adapter-vs-conf.toml`.

```toml
[global]
# ca_file is optional for link establishment, but the VS adapter must present
# a CA-signed certificate_file so the node can recognize it as the visa service.
ca_file = "authority/auth-ca.crt"
certificate_file = "vs-noise.crt"   # CN must be "vs.zpr"
private_key_file = "vs-noise.key"
zpr_addr = [ "fd5a:5052::1" ]
tun_if = "tun9"

[adapter]
node_addr = "129.6.7.1:5000"
node_public_key_file = "node-noise-pub.pem"
bootstrap_key = "vs-private-key.pem"
```

`name` is not set here because `certificate_file` is present — the CN is read
from the certificate, not from `name`.  `name` is only required for adapters
that have no `certificate_file` (self-signed cert path).


## Configure the visa service (optional)

The visa service does not require custom configuration. However if you want
to customize it you can get it to spit out a configuration file. The default
name for it is `vs.toml`, so:

```sh
./vs --gen-config >vs.toml
```


## Start Valkey

Valkey is **required** by the visa service.

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

Here is a simple policy to let any connected "user" access a "WebService".

We assume:
- WebService is connected using an adapter with `CN=web.zpr.org`.
- WebService has a bootstrap public RSA key in `web-public-key.pem`.
- WebService is accessed using HTTP port 80.

Create a file called `zpr-full-access.zpl` with these contents:

```
Define WebService as a service with device.zpr.adapter.cn:'web.zpr.org'.
Allow user to access WebService.
```

Then write a configuration file.
Create a file called `zpr-full-access.zplc` with these contents.

```toml
[nodes."node"]
provider = [ ["device.zpr.adapter.cn", "node.zpr.org"]]
zpr_address = "fd5a:5052:90de::1"

[trusted_services.default]

[visa_service]
dock_node = "node"
admin_attrs = [ [ "device.zpr.adapter.cn", "admin.zpr.org" ] ]

[bootstrap]
"node.zpr.org" = "node-public-key.pem"
"web.zpr.org" = "web-public-key.pem"

[protocols.http]
l4protocol = "iana.TCP"
port = 80

[services.WebService]
protocol = "http"
```

To compile, use the compiler:

```bash
zplc zpr-full-access.zpl

# This will create the binary policy file, "zpr-full-access.bin2"
```

## Start up the node, the visa service and the visa service adapter.

Assuming you have three separate hosts for this. The node should be run
on a Linux host but other platforms may work.  This assumes Linux.  Note
that for any node or adapter where the ZPR address is specified in the
config file, and you are running on Linux, you must manually configure
the network TUN interface to work around a known bug in the Linux
TUN library we are using.

So to prepare the Linux host to run the node, first set up the tun.
In the config file above we set the name to `tun9` so we set that up
here:

```bash
# IP configuration for the node.
sudo ip tuntap add name tun9 mode tun multi_queue
sudo ip link set tun9 mtu 1400
sudo ip addr add fd5a:5052:90de::1/32 dev tun9
sudo ip link set tun9 up
```

The binary also expects to be able to access directory `/var/run/zpr`, so:

    sudo mkdir /var/run/zpr

Then you can start the node:

    sudo ./ph node -c /path/to/node-conf.toml

If the visa service is also running on linux as this guide assumes, then we
need to configure its TUN interface similar to what we did for the node.

```bash
# IP configuration for the visa service adapter.
sudo ip tuntap add name tun9 mode tun multi_queue
sudo ip link set tun9 mtu 1400
sudo ip addr add fd5a:5052::1/32 dev tun9
sudo ip link set tun9 up
```

Now start the visa service:

    ./vs /path/to/zpr-full-access.bin2

On the visa service host, in another terminal start the adapter:

    sudo ./ph adapter -c /path/to/adapter-vs-conf.toml


Now you can attach additional adapters and start up the "WebService".


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
invoking user gets their own directory, two adapters started by two different
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
multi-adapter and test setups keep full control.

**Security note.** Reaching the control socket means being able to start and
stop links and register an `AuthAgent` — i.e. to supply and observe user
credentials for this adapter, and to receive the IdP `client_secret` in a
HelloResponse. Socket access is adapter control. Membership in the
configured control group grants exactly that, on every platform, so treat
it accordingly: it is not a low-privilege convenience group.


## Windows

`ph` runs on Windows 10/11 x64 in both roles. `ph adapter` creates a Wintun
interface, docks to a node, and carries this machine's own traffic, exactly
like `sudo ph adapter -c x.toml` on Linux. `ph node` creates a Wintun
interface, applies its own ZPR address and the visa-service route to it,
accepts docking adapters, and forwards their traffic, exactly like
`sudo ph node -c x.toml` on Linux — within the constraints below.

**Windows node constraints** (deliberate, in this release):

* **A concrete `self_addr` is required**, unconditionally: the Windows
  substrate engine rejects a wildcard bind by design, and startup fails
  cleanly with a message naming the fix. An explicit
  `advertised_substrate_addr` is no substitute — the bind check runs before
  the advertised address is selected, so a wildcard `self_addr` fails at
  startup regardless. With a concrete `self_addr`, no separate
  `advertised_substrate_addr` is needed.
* **Single-homed only** — one substrate address, configured once at startup;
  multi-homed hosts and address changes while running are
  [zipline#150](https://github.com/org-zpr/zl-zipline/issues/150).
* **Elevated console** — Wintun device creation requires Run as
  administrator, same as the adapter role.
* **A single, unbatched datapath worker** — Wintun enforces one queue and
  the `windows_unbatched` engine drives one substrate socket; functional
  parity with Linux is the bar, throughput is not (measured numbers are in
  the test document below).
* **Inbound firewall rules are required**: UDP on the dock port (5000 by
  default) on the LAN interface, and TCP 8183 (the VSS listener) on the
  Wintun interface, which Windows places on the Public profile where
  unsolicited inbound is dropped. The exact rules and when each can be added
  are in the test document below.
* **One `ph` instance per user without `--control-path`**: the default
  control path is derived from the owner alone, so a node and an adapter for
  the same user on one host need explicit `--control-path`s to coexist
  ([zipline#169](https://github.com/org-zpr/zl-zipline/issues/169)).

The hand-run, end-to-end verification of the Windows node (a Windows VM
forwarding real traffic between Linux adapters and hosting the visa
service's support service) is
[`integration-test/windows-node-test.md`](../integration-test/windows-node-test.md);
run it whenever a change touches the Windows node path. CI covers Windows
builds and unit tests (`.github/workflows/adapter.yml` builds and tests `ph`
and `ph-cli` on `windows-latest`), but there is no automated end-to-end
Windows tier that carries real traffic
([zipline#152](https://github.com/org-zpr/zl-zipline/issues/152)); note
that Actions is currently disabled on this fork, so no CI runs here either
way.

**Not supported on Windows** (deliberately, in this release):

* **packet capture to a file** — `ph-cli capture set-file` returns
  `Unsupported`,
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
2. Write an adapter config as on Linux (same TOML schema; see the adapter
   examples above). Windows-style paths in double-quoted TOML strings need
   escaped backslashes — prefer single-quoted literals: `ca_file = 'C:\zpr\ca.crt'`.
3. Start from an **elevated** (Run as administrator) console — Wintun device
   creation requires it:

   ```powershell
   .\ph.exe adapter -c adapter.toml
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
ph.exe adapter -c C:\ProgramData\zipline\adapter.toml --control-group zipline
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
An administrator then adds the users who may drive the adapter
(`net localgroup zipline <user> /add`); that is the deliberate admission
step, and nothing is opened up by default. Until a unit passes the name,
the group exists but grants nothing.

How each launch mode is covered:

| How `ph` runs | Who reaches the pipe | How |
|---|---|---|
| Service (LocalSystem) — the expected common case | members of the configured group, not elevated | group ACE |
| Elevated console, same user as `ph-cli` | that user, elevated or not (non-elevated: checked by the VM smoke) | user-SID ACE |
| Elevated console via over-the-shoulder credentials (a different admin account) | members of the configured group | group ACE |

**Re-logon caveat.** Group membership is read into a user's token at
logon: a user just added to the group must log off and on again (or start
a new logon session) before `ph-cli` can open the pipe.

The security note above applies unchanged: membership in the control group
is adapter control.

For an end-to-end walkthrough against a Linux node and visa service, see
[`integration-test/windows-adapter-test.md`](../integration-test/windows-adapter-test.md).


## macOS

`ph` runs on a Mac — Apple Silicon or Intel — in both roles, started by
hand with `sudo ph node -c x.toml` / `sudo ph adapter -c x.toml` exactly as
on Linux. The node creates a utun interface, applies its own ZPR address to
it, accepts docking adapters, forwards their traffic, and reaches the visa
service through its own TUN. The adapter creates a utun, docks to a node,
and carries this machine's own traffic. The node role first; the adapter
subsection follows.

**macOS node constraints** (deliberate, in this release):

* **A dev/demo node** — the adapters and the visa service stay on Linux;
  functional parity with Linux is the bar, not throughput. No launchd
  service; `ph` is started by hand from a terminal.
* **`sudo` is required** — creating a utun needs root, same as the TUN on
  Linux.
* **A single, unbatched datapath worker** — the macOS `posix_unbatched`
  engine forces one worker (`new_mq` rejects more). Wildcard and
  multi-homed binds are allowed (unix pktinfo), unlike the Windows node.
  Measured single-worker numbers are in the test document below.
* **One `ph` instance per user without `--control-path`**: the default
  control path is derived from the owner alone, so a node and an adapter
  for the same user on one host need explicit `--control-path`s to coexist
  ([zipline#169](https://github.com/org-zpr/zl-zipline/issues/169)).

**Addressing.** The node creates the utun through `TunCtl` and applies its
ZPR address with `ifconfig <utun> inet6 <addr>/32 alias`. The alias alone
installs the on-link `fd5a:5052::/32` route via the utun — no explicit
route is needed; the kernel does it as part of the alias (verified in the
first end-to-end run, 2026-10-02). No manual `ifconfig` or `route` step is
required before starting the node.

**Firewall.** The application firewall was **not exercised** in the first
end-to-end run — it was disabled on the test Mac
(`socketfilterfw --getglobalstate`: State = 0) and left off by choice.
`/usr/libexec/ApplicationFirewall/socketfilterfw` is the knob to check if
inbound UDP on the dock port or TCP 8183 (the VSS listener) is blocked on
a Mac where the firewall is on; no tested command set exists yet.

The hand-run, end-to-end verification of the macOS node (a Mac forwarding
real traffic between Linux adapters and hosting the visa service's support
service) is
[`integration-test/macos-node-test.md`](../integration-test/macos-node-test.md);
run it whenever a change touches the macOS node path. There is no automated
macOS end-to-end tier.

### macOS adapter

`sudo ph adapter -c x.toml`, same TOML schema as Linux (see the adapter
examples above). `tun_if`, when set, must be of the form `utunN`; left
unset, the kernel picks the name. No TUN pre-creation is needed or
possible — `ph` creates the utun itself through `TunCtl`, and the known
Linux pre-creation workaround does not apply.

**macOS adapter constraints** (deliberate, in this release — verified
against the code, not copied from the node list):

* **A dev/demo adapter** — functional parity with Linux is the bar, not
  throughput. No launchd service; `ph` is started by hand from a terminal.
* **`sudo` is required** — creating a utun needs root, same as the node
  role (`TunCtl::new_mq` goes through the same `PF_SYSTEM` control
  socket).
* **A single, unbatched datapath worker** — the one-worker limit is in
  `new_mq` itself (`concurrency` must be 1 on macOS) and in the platform
  default, so it binds the adapter role exactly as it does the node;
  the engine is the same `posix_unbatched`.
* **IPv6 ZPR addresses only** — `TunCtl::add_address` (and `add_route`)
  return `Unsupported` for IPv4 on macOS; the ZPR internal network is
  IPv6 (`fd5a:5052::/32`).
* **One adapter per host** — at startup, and again at every link
  activation, the adapter refuses to run when `fd5a:5052::/32` already
  routes to another live interface
  ([zipline#101](https://github.com/org-zpr/zl-zipline/issues/101)).
  This also means a node and an adapter cannot share a Mac.
* **One `ph` instance per user without `--control-path`**: the default
  control path is derived from the owner alone
  ([zipline#169](https://github.com/org-zpr/zl-zipline/issues/169)).

**Addressing.** Unlike the node, the adapter does not self-address at
startup: the utun is created **unaddressed**
([zipline#161](https://github.com/org-zpr/zl-zipline/issues/161)), and
when the dock link activates with a granted ZPR address, the activation
sequence in `link_state.rs` applies it via `TunCtl::add_address`
(`ifconfig <utun> inet6 <addr>/32 alias`) and then ensures the internal-
network route via `TunCtl::add_route` (`/sbin/route -n add -inet6
fd5a:5052::/32 -interface <utun>` — idempotent: a route already present
is verified to run via this utun and replaced if not,
[zipline#100](https://github.com/org-zpr/zl-zipline/issues/100)). On
macOS the `/32` alias alone already installs the on-link route (verified
in the node's first end-to-end run, 2026-10-02), so the explicit
`add_route` is normally a no-op safety net. No manual `ifconfig` or
`route` step is required.

**Firewall (provisional).** The adapter run has not yet exercised the
application firewall — these notes are derived from the node-role
findings and stay provisional until the adapter checklist's firewall item
is executed (zipline#174). The adapter *originates* its dock (outbound
UDP), so docking is expected to work with the firewall on; the exposed
piece is inbound traffic through the established flow and ZPR-internal
services the Mac answers. `/usr/libexec/ApplicationFirewall/socketfilterfw`
is the knob if anything is blocked; rules key on the executable's path,
so allow the copy of `ph` the run actually starts.

The hand-run, end-to-end verification of the macOS adapter (a Mac docking
to a Linux node and carrying real traffic both ways) is
[`integration-test/macos-adapter-test.md`](../integration-test/macos-adapter-test.md);
run it whenever a change touches the macOS adapter path. Its first
execution — and the firewall findings above — is tracked as
[zipline#174](https://github.com/org-zpr/zl-zipline/issues/174).


## Certificate and peer verification reference

### Local certificate (`certificate_file` / `name`)

| Role | `certificate_file` | `name` | Behavior |
|------|-------------------|--------|-----------|
| node | required | ignored | Provided cert is used; node name comes from the cert CN |
| adapter | present | optional | Provided cert is used; CN comes from the cert where needed |
| adapter | absent | required | Self-signed cert is generated with CN from `name` |
| adapter | absent | absent | Config validation fails |

For adapters, CLI `--name` overrides `[adapter].name` in the config file.

### Peer certificate verification (`ca_file`)

| `ca_file` | Behavior |
|-----------|-----------|
| present | Peer cert signatures are verified against the CA; unverified peers are handled by link-type rules (see below) |
| absent | Peer cert signatures are not CA-verified; a warning is logged at startup and unverified peers are accepted |

Link-type rules when `ca_file` is configured:

| Link direction | Unverified peer cert | Action |
|---------------|---------------------|--------|
| Adapter → Node | Node cert unverified | Link rejected |
| Node → Node | Peer node cert unverified | Link rejected |
| Node → Adapter | Adapter cert unverified | Link accepted with a warning |

### Special peers (visa service adapter)

The visa service adapter is recognized as "special" by the node **only** when
the adapter presents a CA-verified certificate claiming the visa-service DN.
This means:

- The **node** must configure `ca_file` (to verify the VS adapter's cert).
- The **VS adapter** must present a CA-signed `certificate_file` (not a self-signed cert).

Without both conditions, the VS adapter connects as an ordinary adapter and
visa-service traffic is not routed to it.
