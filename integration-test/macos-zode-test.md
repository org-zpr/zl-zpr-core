# macOS Zode test

Hand-run, end-to-end verification that `ph zode` on macOS joins a ZPRnet
and carries real traffic. The **Mac is a Zode** (CN `zb`) that dials a relay
Zode on the Linux host; the relay hosts the visa service. There is no
automated macOS CI that carries real traffic (master-plan decision M5), so
run this whenever a change touches the macOS datapath (utun creation and
self-addressing through `TunCtl`, the `posix_unbatched` engine, the control
socket, shutdown).

It exercises:

* utun creation and the Zode's self-addressing
  (`ifconfig <utun> inet6 <addr>/32 alias`, which also puts
  `fd5a:5052::/32` on-link);
* a wildcard bind with no advertised address: the Zode reports its initial
  link's current local address to the visa service (zl-zipline#230);
* joining through the relay, and the visa service reaching the Zode's VSS
  over the utun;
* logging a person in on the Zode with `ph-cli` over the unix socket
  (section 3, zl-zipline#233);
* Ctrl-C shutdown that leaves no stale utun behind.

Two machines:

* **Linux host** — runs the relay Zode, valkey and the visa service, all in
  the host's network namespace, inside the integration-test Docker image
  with `--network host`. It uses `lib/zode_funcs.sh` and the Zode netns test
  fixtures.
* **Mac** (Apple Silicon or Intel) — runs `ph zode` under `sudo` from a
  terminal. It must reach the Linux host's LAN address directly; the
  commands below use `192.168.0.212`, the test lab's.

The keys and certificates come from `integration-test/pregen` and are
**test-only fixtures** — do not reuse them outside a private test network.

```
   Linux host (docker, host network)            Mac
  ┌──────────────────────────────────┐        ┌────────────────────────┐
  │ ph zode (relay), TUN zrelay      │  UDP   │ ph zode (zb)           │
  │   fd5a:5052::2, vs.zpr           │◀─:5000─┤  self_addr 0.0.0.0:5000│
  │   advertised 192.168.0.212:5000  │        │  initial link: relay   │
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

Mac:

* `ph` and `ph-cli` built on the Mac: `make` at the `zl-zpr-core` repository
  root (plain `cargo build -p ph -p ph-cli` works too). Nothing else — there
  is no wintun analogue; `utun` devices are in-kernel and `ph` creates them
  through a `PF_SYSTEM` control socket. Creation requires root, hence
  `sudo` below.
* If the Mac's application firewall is enabled (System Settings → Network →
  Firewall), expect it to interfere with the VSS listener (TCP 8183). The
  link needs nothing: zb dials out. The command-line tool is
  `/usr/libexec/ApplicationFirewall/socketfilterfw`; the expected fix, if
  one is needed, is to allow the binary **the test actually runs** — the
  copy in `~/zpr-zode` that section 2 starts, not the build-tree
  `target/debug/ph` (the firewall keys rules on the executable's path):

  ```sh
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ~/zpr-zode/ph
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ~/zpr-zode/ph
  ```

  Record in Findings whether it was needed.

## 1. Linux side: the relay and the visa service

The relay runs in the host's network namespace, so the Mac reaches it at
the host's LAN address. The relay hosts the visa service (zl-zipline#229):
the relay's TUN carries its own address and `vs.zpr`, and valkey and `vs`
run in the same namespace, started after the relay.

The fixture policy `pregen/zodes-login.zplc` gives the relay the substrate
address `10.2.0.1:5000`, gives zb none, and names a fake identity provider
on `127.0.0.1:9000` for section 3. Copy `pregen` to a scratch directory,
point both at the host's LAN address, and compile it. From the
`zl-zpr-core` root:

```sh
export WORK=$(mktemp -d /tmp/zpr-zode.XXXX)
cp -r integration-test/pregen "$WORK/pregen" && cd "$WORK/pregen"
sed -i -e 's/i0 = "10.2.0.1:5000"/i0 = "192.168.0.212:5000"/' \
  -e 's|https://127.0.0.1:9000|https://192.168.0.212:9443|' zodes-login.zplc
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
RELAY_IP=192.168.0.212      # the host as the Mac sees it
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
create_actor_key_and_cert ca zb      # the Mac Zode's identity
```

Leave this shell open: section 3 starts the fake identity provider in it,
and section 4 tears it down.

## 2. Mac side: a Zode with a wildcard address

Copy `ph` and `ph-cli` to a working directory such as `~/zpr-zode`, with
`ca.crt`, `zb.crt` and `zb.key` from `$WORK/run` and
`pregen/zb-rsa-key.pem`.

zb runs on the default config: no `--self-addr`, so it binds the wildcard
`0.0.0.0:5000`, and no `--advertised-substrate-addr`. On every VS-API
`connect` and `open` it reports its initial link's current local address
with `self_addr`'s port, so the address follows the network.
Network-change runs (moving the Mac's address) are tracked in
[zl-zipline#263](https://github.com/org-zpr/zl-zipline/issues/263).

```sh
cd ~/zpr-zode
sudo ./ph zode -l all=INFO --initial-link relay@192.168.0.212:5000 \
  --tun-if utun9 --zpr-addr fd5a:5052::3 \
  --ca-file ca.crt --certificate-file zb.crt -k zb.key \
  --auth-private-key zb-rsa-key.pem
```

`--tun-if` on macOS must be of the form `utunN`; `utun9` is arbitrary but
high enough not to collide with the system's own utuns. Left out, the
kernel picks the name.

Leave it running and open a **second terminal** for the checks. Run
`ph-cli` there **not under sudo**: `sudo ph zode` binds
`/var/run/zpr/<SUDO_UID>/control.sock`, owned by you, and `sudo ph-cli`
(uid 0) would look in `/var/run/zpr/0/`.

**Expected:**

* zb: `Using packet I/O engine posix_unbatched`; `dock listening on
  0.0.0.0:5000`; `reporting substrate address the initial link's local
  address at each connect/open, port 5000 (wildcard self_addr) to the visa
  service`; `Started Zode link with 192.168.0.212:5000 as the dialer`;
  `installed bootstrap visas [...] bound to the link`; `node access granted
  to visa service`; `registered VSS`; `received topology update`. No
  startup error. `WARN startup: Unable to enable ingress packet steering:
  packet steering not supported on this OS` is expected on macOS.
* `ifconfig utun9` shows `fd5a:5052::3 prefixlen 32`;
  `netstat -rn -f inet6 | grep fd5a:5052` shows `fd5a:5052::/32` on
  `utun9`.
* `netstat -an -p udp` shows `*.5000`; `./ph-cli link show` shows one link,
  `192.168.0.212:5000 (Active)`; `./ph-cli counters` answers.
* relay.log: `Started Zode link with <Mac IP>:5000 as the answerer`, then
  `handed bootstrap visas [...] to "zb"`. The relay's topology goes from
  `peer unset, ... peer cn "zb"` to `peer <Mac IP>:5000, ... peer cn "zb"`:
  the visa service holds zb's real LAN address.
* `ping6 -c 5 fd5a:5052::1` (the visa service, through the relay): 5/5.

## 3. Log in on the Zode (zl-zipline#233)

A person logs in on the Zode with `ph-cli`, and the Zode's own actor gains
the user's OIDC attributes until `ph-cli logout`. This section checks that
on macOS: the admin RPC `login` over the unix socket, the visa-service
nonce, and the agent callback to `ph-cli`. The policy from section 1 lets
zb reach the relay (`fd5a:5052::2`) only while the user `user-zb` is logged
in.

Setup, beyond sections 1 and 2:

* **The fake IdP on the Linux host's address**, with a server certificate
  for that IP signed by section 1's IdP CA. In the container shell, in
  `$WORK/run`:

  ```sh
  HOST_IP=192.168.0.212
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

* **macOS must trust the IdP CA** for `ph-cli` to reach the IdP: `ph-cli`
  uses the system trust store (the System keychain). Copy `idp-ca.crt` from
  `$WORK/run` to `~/zpr-zode` (never `idp-ca.key`). This is a change to the
  test host; section 4 undoes it:

  ```sh
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain ~/zpr-zode/idp-ca.crt
  ```

  Without it, the login stops at the IdP with `IdpUnreachable` (exit 4),
  after the nonce and the agent callback have run.

On the Mac, **as yourself, not under sudo** (so `ph-cli` can open the
browser), in `~/zpr-zode`:

```sh
./ph-cli login-status            # State: logged out
./ph-cli auth-agent --no-browser # prints a URL: open it in the Mac's browser; stays resident
```

Then, from another terminal:

```sh
./ph-cli login-status            # State: logged in, Issuer, Expires in, Auth agent: registered
ping6 -c 5 fd5a:5052::2          # the relay, as the logged-in user: replies (the first may be lost)
./ph-cli logout                  # Logged out; the Zode stays connected
# Wait ~10 s: the visa service revokes the user flow's visa (vs.log, zb's log).
ping6 -c 3 fd5a:5052::2          # no replies
ping6 -c 3 fd5a:5052::1          # the visa service: still replies (the device flow)
./ph-cli logout                  # logout failed: not logged in (exit 1)
```

`ph-cli connect --no-browser` logs in the same way and exits once the
login completes, instead of staying resident as the agent.

Pass criteria: `auth-agent` prints `Logged in`; `login-status` shows the
issuer and the time left; the ping to the relay is answered while logged in
and not after `logout`, while the ping to the visa service is answered
throughout; zb's log shows `Zode login: logged in with <issuer>` and `Zode
login: logged out`, and never a token or a nonce.

## 4. Shutdown and teardown

In the terminal running `ph`, press **Ctrl-C** once. Expect `Got SIGINT;
attempting graceful shutdown`, and the process exiting on its own. Then
`ifconfig utun9` reports that the interface does not exist, and
`netstat -rn -f inet6` shows no `fd5a` route. A second start with the same
command line must come up cleanly (it re-binds the leftover
`control.sock` path).

Then undo the changes to the Mac:

```sh
# Only if section 3 trusted the IdP CA:
sudo security remove-trusted-cert -d ~/zpr-zode/idp-ca.crt
sudo security delete-certificate -c zpr-test-idp-ca /Library/Keychains/System.keychain
# Only if a socketfilterfw rule was added:
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove ~/zpr-zode/ph
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

Paste the transcript (Zode startup lines, `ph-cli` output, the
`ifconfig`/`netstat` evidence, ping output, shutdown and the post-exit
`ifconfig`) on the PR or issue the run verifies, and fill in **Findings**
below in the same PR.

Packet captures, if needed: `tcpdump -ni utun9` on the Mac;
`tcpdump -ni zrelay` on the Linux host.

## Findings

*(keep one dated subsection per run)*

### 2026-11-14 — Zode with a wildcard address (section 2, zl-zipline#230)

* Build (`zl-zpr-core`): `feature/zodes-230-2-network-change` at `81c474e`,
  the same build on the Mac and the Linux host · vs `v0.22.0-zodes.8` ·
  policy: `pregen/zodes.zplc`, relay `i0` rewritten, zplc 0.21.0
* macOS 26.5.2 (25F84), Apple Silicon, on Wi-Fi at 192.168.0.150; relay at
  192.168.0.212

| Check | Result | Evidence |
|---|---|---|
| start with the wildcard and no advertised address, then join | PASS | `dock listening on 0.0.0.0:5000` (`udp4 *.5000`); no startup error; `Using packet I/O engine posix_unbatched`; bootstrap visas installed, `node access granted`, `registered VSS`, topology received. zb `link show`: one link, `192.168.0.212:5000 (Active)`. Relay `link show`: the visa service's link plus one link, `192.168.0.150:5000 (Active)`. The relay handed zb bootstrap visas, and its topology went from `peer unset` to `peer 192.168.0.150:5000` for zb. `ping6` to the visa service: 5/5, 11-47 ms. No lab change; the application firewall is off on the test Mac. |

### 2026-11-13 — Zode login (zl-zipline#233), partial

* Build: `zl-zpr-core` `feature/zodes-233-zode-login` @ `1fa417b`, on the Mac
  (macOS 26.5.2, arm64). Linux side as in the Windows guide's run of the same
  day, advertising `192.168.0.212:5000`, with `fake-idp.py --host
  192.168.0.212`. The Mac ran Zode `zb` under sudo (`--self-addr
  0.0.0.0:5000 --advertised-substrate-addr 192.168.0.150:5000
  --initial-link relay@192.168.0.212:5000`); `ph-cli` ran as the user.
* No change to the Mac: the test CA is not trusted.
* Result: the Zode joined and the visa service connected to its VSS. Over
  the unix socket: `login-status` printed `State: logged out` (exit 0);
  `logout` printed `logout failed: not logged in` (exit 1); `connect
  --no-browser` got a visa-service nonce, ph called the agent back over the
  socket, and the agent's discovery request reached the fake IdP, which
  logged `TLSV1_ALERT_UNKNOWN_CA`; `ph-cli` printed `login failed:
  IdpUnreachable("HTTP error talking to the IdP: …")` and exited 4.
  `login-status` then showed that `Last failure`. A completed login was not
  reached: it needs the CA trusted.
