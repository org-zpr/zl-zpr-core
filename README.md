# zpr-core

Core ZPR components: the packet handler that runs a Zode (a ZPR node that
carries its own actor), the command-line tool that controls it, and the end-to-end tests that stand
up a whole ZPRnet.

Roadmap and backlog: [current iteration](https://github.com/orgs/org-zpr/projects/1/views/3),
[roadmap](https://github.com/orgs/org-zpr/projects/3/views/8).

> **Pre-release.** This repository is in active, early-stage development.
> Breaking changes land without notice, the end-to-end security features are
> not all implemented yet, and these binaries are not for production use.


## What is here

* **`ph`**, the packet handler (`adapter/ph`). One binary, one role:
  `ph zode` runs a Zode, which carries its host's own traffic over a TUN
  interface and links to other Zodes. A relay Zode (`--relay true`) hosts
  the visa service and accepts links; every other Zode dials its relay over
  its initial link (`--initial-link`).
* **`ph-cli`**, the control tool (`adapter/cli`). Talks to a running `ph`
  over its control socket to start and stop links, log a user in, read
  counters, and capture packets.
* **`integration-test/`**, shell scripts that build a real ZPRnet on network
  namespaces and drive traffic through it. See [Running](#running).

`libnode2` (the node implementation) and `adapter/admin-api` (the control
protocol) are libraries `ph` is built from.

## What is not here

A ZPRnet needs more than this repository:

* **A running visa service**, `vs`, from the
  [zpr-visaservice repository](https://github.com/org-zpr/zpr-visaservice).
  Nothing connects without it: every link is authorized by a visa it issues.
  It needs Valkey (or Redis) at runtime.
* **A compiled policy**, produced by `zplc` from the
  [zpr-compiler repository](https://github.com/org-zpr/zpr-compiler).
  The visa service evaluates it.

The **`zpr-dev-context`** repository, checked out beside this one, holds
what spans repositories: the system overview and terminology, the security
model, the wire protocols, and the compatible build sets. Start with its
`docs/SYSTEM_OVERVIEW.md` if ZPR is new to you.


## Building

Prerequisites: a stable Rust toolchain, `make`, `capnproto` (the `capnp`
binary), and `libpcap-dev` for `ph-cli`.

```sh
sudo apt install build-essential make capnproto libpcap-dev   # Debian/Ubuntu
```

Dependencies are pulled from other ZPR repositories over HTTPS. While those
are private, tell Git to use your SSH credentials for them:

```sh
git config --global url.git@github.com:.insteadOf https://github.com/
```

Then:

```sh
make          # build everything; binaries land in target/debug
make test     # unit tests
make help     # the other targets
```

Each workspace member also has its own `Makefile`, so a single component can
be built alone.


## Running

`ph` needs root: it creates a TUN interface and its control socket lives
under `/var/run/zpr`. `ph-cli` does not; when `ph` is started with `sudo`,
the socket is handed to the invoking user.

```sh
sudo ./target/debug/ph zode -c relay.toml --relay true            # on the relay host
sudo ./target/debug/ph zode -c zode.toml --initial-link relay@10.1.0.8:5000   # on each other host
./target/debug/ph-cli link show                                   # as yourself, no sudo
```

Getting to that point takes keys, certificates, a policy, and a
configuration file for each Zode. [`docs/SETUP.md`](docs/SETUP.md) walks through all of
it by hand and ends with a reference for the control socket and certificate
verification.

`ph zode` also runs on Windows 10/11: `ph.exe zode -c zode.toml` from an
elevated (Administrator) console, with the signed `wintun.dll` from
[wintun.net](https://www.wintun.net) next to `ph.exe`. `ph-cli.exe` talks to
it over a named pipe instead of the unix socket. It runs on macOS too, under
`sudo`, as on Linux. The end-to-end walkthroughs, each against a relay Zode
on a Linux host, are
[`integration-test/windows-zode-test.md`](integration-test/windows-zode-test.md)
and [`integration-test/macos-zode-test.md`](integration-test/macos-zode-test.md).

### Integration tests

`integration-test/` runs the same setup end to end, with no hand
configuration. The scripts need root for network namespaces, so the default
path runs them in a privileged Docker container:

```sh
make integration-test-docker                                   # every test
make -C integration-test docker-test TEST=zode-ping-test.sh    # one test
```

With passwordless `sudo` on a Linux host, each script also runs directly:

```sh
integration-test/zode-ping-test.sh
```

Either way the scripts look next to themselves for binaries from the other
repositories: `vs`, `vs-admin`, and `zpr-attr-server` from the visa service,
`zpdump` from the compiler, and `valkey-server` unless `VALKEY_SERVER_BIN`
points elsewhere. Symlinks are fine. `fake-idp-smoke-test.sh` needs neither
root nor namespaces, so run it first when an OIDC test misbehaves.


## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in ZPR by you, shall be licensed as Apache 2.0, without any additional
terms or conditions.
