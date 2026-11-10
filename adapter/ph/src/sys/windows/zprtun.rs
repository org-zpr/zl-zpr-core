//! The Wintun-backed TUN device, Windows arm (zipline#130, plan D4).
//!
//! `ZprTun` wraps the `wintun` crate (safe bindings that load the signed
//! `wintun.dll` at runtime; the DLL ships next to `ph.exe`). Packets move
//! through Wintun's ring buffers (`try_receive` / `allocate_send_packet` +
//! `send_packet`); readiness is the session's read-wait event, exposed as
//! this device's [`Waitable`] for the fastpath `WaitSet`. There is no
//! packet-info header (`PI_SIZE = 0`, see `tun_pi.rs`).
//!
//! Addresses and routes are managed by shelling out to
//! `netsh interface ipv6 add|delete|show address|route`, the same pattern
//! as `ip` on Linux and `ifconfig`/`route` on macOS. Upgrade path if netsh
//! parsing proves brittle or slow: IP Helper
//! (`CreateUnicastIpAddressEntry`, `CreateIpForwardEntry2`,
//! `GetIpForwardTable2`) via `windows-sys`, already in the dependency tree.
//!
//! Adapter lifecycle (plan open question 1, operator-approved): create a
//! fresh adapter at startup — deleting any stale adapter with our name
//! first — and delete it on graceful exit (the wintun crate closes the
//! adapter when the last Arc drops; an unclean exit leaves the adapter for
//! the next startup's stale-delete to reap).

use crate::sys::dad;
use crate::sys::linux_route;
use crate::sys::wait::{WaitHandle, Waitable};
use crate::zprtun::{ZprTunError, effective_tun_mtu};
use std::net::{IpAddr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;
use tracing::*;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::AF_INET6;

use crate::logging::targets::NET_OS;

/// The interface name used when the config does not set `tun_if`.
const DEFAULT_ADAPTER_NAME: &str = "zpr";

/// The Wintun "tunnel type" shown in adapter properties.
const TUNNEL_TYPE: &str = "ZPR";

/// Wintun ring capacity: 4 MiB (power of two within
/// [`wintun::MIN_RING_CAPACITY`], [`wintun::MAX_RING_CAPACITY`]).
const RING_CAPACITY: u32 = 0x40_0000;

pub struct ZprTun {
    /// Keeps the driver loaded for the life of the device.
    _wintun: wintun::Wintun,
    /// Explicit hold on the adapter device. The `session` also holds an
    /// `Arc` to it internally; this one documents that the device outlives
    /// every session-independent user (netsh helpers address it by name
    /// while the ring may be shut down) and supplies the interface LUID for
    /// the IP Helper DAD-state query in [`ZprTun::dad_state`].
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    /// The adapter name (config `tun_if` or [`DEFAULT_ADAPTER_NAME`]), as
    /// netsh commands address it.
    name: String,
    /// Serializes netsh address/route mutations, as on macOS.
    mtx: std::sync::Mutex<()>,
}

impl From<wintun::Error> for ZprTunError {
    fn from(e: wintun::Error) -> Self {
        ZprTunError::PlatformError(e.to_string())
    }
}

impl ZprTun {
    /// Create the Wintun adapter and open its session.
    ///
    /// `concurrency` (queue count) must be 1: Wintun exposes one ring pair
    /// per session, same single-queue constraint as macOS. If `ifname` is
    /// `None` the adapter is named [`DEFAULT_ADAPTER_NAME`]. A stale
    /// adapter with our name (left by an unclean exit) is deleted before
    /// creating the fresh one (plan open question 1).
    ///
    /// The `address` parameter is accepted for signature parity with the
    /// other platforms but not applied at create time: addresses go on via
    /// [`Self::add_address`] (netsh), which the activation path calls.
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        _address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        if concurrency != 1 {
            return Err(ZprTunError::PlatformError(String::from(
                "on windows concurrency (queues) must be 1",
            )));
        }
        let name = ifname.unwrap_or_else(|| DEFAULT_ADAPTER_NAME.to_string());

        // SAFETY: loads the signed wintun.dll shipped next to ph.exe; the
        // wintun crate documents no further invariants for load().
        let wintun = unsafe { wintun::load() }
            .map_err(|e| ZprTunError::PlatformError(format!("cannot load wintun.dll: {e}")))?;

        // Delete a stale adapter with our name from an unclean previous
        // exit, so the create below starts from a clean slate.
        if let Ok(stale) = wintun::Adapter::open(&wintun, &name) {
            match Arc::try_unwrap(stale) {
                Ok(adapter) => {
                    warn!(target: NET_OS, "deleting stale Wintun adapter '{name}'");
                    if let Err(e) = adapter.delete() {
                        warn!(target: NET_OS, "could not delete stale adapter '{name}': {e}");
                    }
                }
                Err(_) => {
                    return Err(ZprTunError::PlatformError(format!(
                        "Wintun adapter '{name}' is held by another process"
                    )));
                }
            }
        }

        let adapter = wintun::Adapter::create(&wintun, &name, TUNNEL_TYPE, None)?;
        let session = Arc::new(adapter.start_session(RING_CAPACITY)?);

        let tun = ZprTun {
            _wintun: wintun,
            adapter,
            session,
            name,
            mtx: std::sync::Mutex::new(()),
        };
        // A Wintun adapter comes up at MTU 65535, far above what the overlay
        // carries; the adapter is fresh every start, so set it
        // unconditionally (zl-zipline#214).
        tun.set_mtu(effective_tun_mtu(None))?;
        Ok(vec![tun])
    }

    /// Set the IPv6 MTU of the adapter with
    /// `netsh interface ipv6 set subinterface <if> mtu=<mtu> store=active`.
    ///
    /// `wintun::Adapter::set_mtu` is not used: it sets only the IPv4
    /// subinterface, and the ZPR overlay is IPv6. `store=active` because
    /// the adapter is deleted on exit, so nothing should persist. A
    /// failure is an error: an adapter above the overlay MTU silently drops
    /// large packets, which is worse than refusing to start
    /// (zl-zipline#214).
    fn set_mtu(&self, mtu: u16) -> std::io::Result<()> {
        let _mtx = self.lock()?;
        let mtu_arg = format!("mtu={mtu}");
        let output = self
            .netsh(&["set", "subinterface", &self.name, &mtu_arg, "store=active"])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed to set MTU {mtu} on {}: {}",
                self.name,
                netsh_output_text(&output)
            )));
        }
        Ok(())
    }

    /// Receive one packet from the Wintun ring without blocking.
    ///
    /// `Ok(None)` means the ring is empty. (Consumed by the Windows
    /// batch_io engine, zipline#131.)
    pub fn try_receive(&self) -> std::io::Result<Option<wintun::Packet>> {
        self.session
            .try_receive()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Send one packet: allocate a slot in the send ring, fill it, commit.
    /// (Consumed by the Windows batch_io engine, zipline#131.)
    ///
    /// A full send ring surfaces as `WouldBlock`, the same shape as a
    /// `write(2)` on a busy unix TUN, so the fastpath's egress tally counts
    /// it as a drop instead of panicking (Wintun reports it as
    /// `ERROR_BUFFER_OVERFLOW`).
    pub fn send(&self, body: &[u8]) -> std::io::Result<()> {
        /// winerror.h `ERROR_BUFFER_OVERFLOW`: `WintunAllocateSendPacket`'s
        /// documented "send ring is full" error.
        const ERROR_BUFFER_OVERFLOW: i32 = 111;
        let len: u16 = body
            .len()
            .try_into()
            .map_err(|_| std::io::Error::other("packet exceeds the Wintun frame limit"))?;
        let mut packet = self
            .session
            .allocate_send_packet(len)
            .map_err(|e| match e {
                wintun::Error::Io(io) if io.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW) => {
                    std::io::Error::new(std::io::ErrorKind::WouldBlock, "Wintun send ring full")
                }
                e => std::io::Error::other(e.to_string()),
            })?;
        packet.bytes_mut().copy_from_slice(body);
        self.session.send_packet(packet);
        Ok(())
    }

    /// The Wintun adapter name (config `tun_if` or [`DEFAULT_ADAPTER_NAME`])
    /// (zipline#202).
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// A NOP on Windows, as on macOS: Wintun has no carrier control; the
    /// adapter's media state is managed by the driver.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }

    pub fn add_address(&self, addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
        self.add_address_impl(addr, false)
    }

    /// Add the adapter authentication address (AAA, #1410) as a valid but
    /// deprecated source (`preferredlifetime=0`), the Windows equivalent of
    /// Linux's `preferred_lft 0`: applications prefer the granted actor
    /// address, and authentication binds the AAA explicitly. A deprecated
    /// address still passes the DAD wait ([dad::DadState::Usable]).
    pub fn add_authentication_address(&self, addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
        self.add_address_impl(addr, true)
    }

    /// Shared body of [Self::add_address] and
    /// [Self::add_authentication_address].
    fn add_address_impl(&self, addr: IpAddr, authentication: bool) -> std::io::Result<()> {
        let _mtx = self.lock()?;
        if self.has_address(addr)? {
            return Ok(());
        }
        let addr = require_v6("add_address", addr)?;
        let addr_text = addr.to_string();
        // netsh interface ipv6 add address <if> <addr> [preferredlifetime=0]
        let mut args = vec!["add", "address", self.name.as_str(), addr_text.as_str()];
        if authentication {
            args.push("preferredlifetime=0");
        }
        let output = self.netsh(&args).output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed to add address {addr} on {}: {}",
                self.name,
                netsh_output_text(&output)
            )));
        }
        // netsh returns while the address is still tentative (DAD, ~1 s on
        // Wintun), and binding to it in that window fails with
        // WSAEADDRNOTAVAIL — the node's VSS listener lost that race on
        // every start (zipline#162). Wait, bounded, until it is usable.
        dad::wait_until_usable(
            || self.dad_state(addr),
            dad::DAD_WAIT_TIMEOUT,
            dad::DAD_POLL_INTERVAL,
        )
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("address {addr} on {} did not become usable: {e}", self.name),
            )
        })
    }

    /// Read the duplicate-address-detection state of `addr` on this adapter
    /// through IP Helper (`GetUnicastIpAddressEntry`). IP Helper reports the
    /// state as an enum; `netsh show address` prints it as localized text,
    /// which would not parse on a non-English Windows. An address that is
    /// not (yet) on the adapter is a `NotFound` error.
    fn dad_state(&self, addr: Ipv6Addr) -> std::io::Result<dad::DadState> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        // The lookup key is (interface LUID, address).
        // SAFETY: NET_LUID_LH is a union whose every variant is a view of
        // the same 64 bits; reading `Value` reads them as a plain u64.
        row.InterfaceLuid.Value = unsafe { self.adapter.get_luid().Value };
        row.Address.Ipv6.sin6_family = AF_INET6;
        row.Address.Ipv6.sin6_addr.u.Byte = addr.octets();
        // SAFETY: `row` is a valid, initialized MIB_UNICASTIPADDRESS_ROW
        // that outlives the call; the function only reads the key fields
        // and writes the rest of the row in place.
        let rc = unsafe { GetUnicastIpAddressEntry(&mut row) };
        match rc {
            NO_ERROR => Ok(dad::DadState::from_nl_dad_state(row.DadState)),
            ERROR_NOT_FOUND => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("address {addr} is not on {}", self.name),
            )),
            rc => Err(std::io::Error::from_raw_os_error(rc as i32)),
        }
    }

    pub fn clear_address(&self, addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
        let _mtx = self.lock()?;
        if !self.has_address(addr)? {
            return Ok(());
        }
        let addr = require_v6("clear_address", addr)?;
        // netsh interface ipv6 delete address <if> <addr>
        let output = self
            .netsh(&["delete", "address", &self.name, &addr.to_string()])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed to delete address {addr} on {}: {}",
                self.name,
                netsh_output_text(&output)
            )));
        }
        Ok(())
    }

    /// Reports whether `addr` is currently configured on this adapter.
    ///
    /// Reads `netsh interface ipv6 show address <if>` and looks for the
    /// address token. Does not take the device mutex, so it is safe to call
    /// either with or without it held.
    pub fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
        let addr = require_v6("has_address", addr)?;
        let output = self.netsh(&["show", "address", &self.name]).output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed to show addresses for {}: {}",
                self.name,
                netsh_output_text(&output)
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let needle = addr.to_string();
        // Token-wise search: the address appears as its own token in the
        // "Address <addr> Parameters" output; substring matching could
        // false-positive on a longer address containing ours.
        Ok(stdout
            .split_whitespace()
            .any(|token| token.eq_ignore_ascii_case(&needle)))
    }

    /// Ensure `dest/prefix_len` is routed on-link via this adapter.
    ///
    /// Idempotent: a route already present on our own interface is success.
    /// `netsh add route` fails with "The object already exists" whether the
    /// existing route targets this adapter or another one, so on failure
    /// the table is inspected; a route on another interface is replaced
    /// (delete + re-add), mirroring Linux `ip -6 route replace`.
    pub fn add_route(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        let _mtx = self.lock()?;
        let dest = require_v6("add_route", dest)?;
        let prefix = format!("{dest}/{prefix_len}");
        let output = self
            .netsh(&["add", "route", &prefix, &self.name])
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        // The add failed. If the prefix is already routed via us, done; if
        // it is routed via another interface, replace it; otherwise fail.
        let owners = self.route_owners(&prefix)?;
        if owners.is_empty() {
            return Err(std::io::Error::other(format!(
                "netsh failed to add route {prefix} on {}: {}",
                self.name,
                netsh_output_text(&output)
            )));
        }
        if owners.iter().all(|owner| owner.ifname == self.name) {
            return Ok(());
        }
        debug!(
            target: NET_OS,
            "route {prefix} exists but not (only) via {}; replacing",
            self.name
        );
        for owner in owners.iter().filter(|owner| owner.ifname != self.name) {
            let output = self
                .netsh(&["delete", "route", &prefix, &owner.ifname])
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::other(format!(
                    "netsh failed to delete stale route {prefix} on {}: {}",
                    owner.ifname,
                    netsh_output_text(&output)
                )));
            }
        }
        let output = self
            .netsh(&["add", "route", &prefix, &self.name])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed to reinstall route {prefix} on {} after deleting the stale route: {}",
                self.name,
                netsh_output_text(&output)
            )));
        }
        Ok(())
    }

    /// Report another interface already carrying the route for
    /// `dest/prefix_len`, if any (zipline#101, Windows arm).
    ///
    /// Reads `netsh interface ipv6 show route` — unprivileged and
    /// read-only — through the shared parser in [`linux_route`], with the
    /// [`linux_route::Platform::Windows`] existence-is-liveness rule.
    pub fn route_owner_conflict(
        &self,
        dest: IpAddr,
        prefix_len: u8,
    ) -> std::io::Result<Option<String>> {
        let dest = require_v6("route_owner_conflict", dest)?;
        let owners = self.route_owners(&format!("{dest}/{prefix_len}"))?;
        Ok(
            linux_route::route_owner_conflict(&owners, &self.name, linux_route::Platform::Windows)
                .map(|conflict| conflict.ifname),
        )
    }

    /// The interfaces currently carrying `prefix`, from
    /// `netsh interface ipv6 show route`.
    fn route_owners(&self, prefix: &str) -> std::io::Result<Vec<linux_route::RouteOwner>> {
        let output = self.netsh(&["show", "route"]).output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed to show routes: {}",
                netsh_output_text(&output)
            )));
        }
        Ok(linux_route::parse_netsh_route_show(
            &String::from_utf8_lossy(&output.stdout),
            prefix,
        ))
    }

    /// A `netsh interface ipv6 <args...>` command, logged at debug like the
    /// `ip`/`ifconfig` invocations on the other platforms.
    fn netsh(&self, args: &[&str]) -> Command {
        let mut c = Command::new("netsh");
        c.arg("interface").arg("ipv6").args(args);
        debug!(target: NET_OS, "{:?}", c);
        c
    }

    fn lock(&self) -> std::io::Result<std::sync::MutexGuard<'_, ()>> {
        self.mtx
            .lock()
            .map_err(|_| std::io::Error::other("Mutex lock failed"))
    }

    /// Graceful-exit teardown (plan open question 2, operator-approved:
    /// fresh-create / stale-delete / delete-on-exit; wired per PR #51
    /// review).
    ///
    /// Shuts the Wintun session down (`WintunGetReadWaitEvent` consumers
    /// wake, blocked `receive_blocking` calls error out) so the ring
    /// quiesces before exit. The adapter device itself is deliberately NOT
    /// closed from here, for two reasons that are worth recording:
    ///
    /// - It cannot be done soundly today. `wintun::Adapter` is removed by
    ///   `WintunCloseAdapter` only when its last `Arc` drops, the `Session`
    ///   holds one of those `Arc`s, and the fastpath worker thread — which
    ///   `process::exit` kills without unwinding — waits on this session's
    ///   read event every loop iteration via [`Waitable`]. Dropping the
    ///   session or adapter out from under it would be a use-after-free of
    ///   live driver handles. (This is also why the old `delete(self)`
    ///   could never be called: it needed sole ownership of a `ZprTun`
    ///   that is `Arc`-shared with the fastpath for the process lifetime.)
    /// - It does not need to be. Wintun creates adapters via
    ///   `SwDeviceCreate` with the default handle-bound lifetime, so the
    ///   OS removes the device — and its interface-keyed netsh
    ///   address/route state — when the process's handle closes, which
    ///   happens on every exit path including `process::exit(0)`.
    ///   Destructors are irrelevant to that; the close is kernel-side.
    ///   The startup stale-adapter delete covers what remains (power
    ///   loss / crash where no handle close ran, leaving a phantom
    ///   device).
    ///
    /// Explicit in-process deletion would additionally need a fastpath
    /// worker stop signal, which no platform has (the worker loop never
    /// exits); OS handle-close semantics make it unnecessary, so this hook
    /// plus handle close implement delete-on-exit.
    pub fn teardown(&self) -> std::io::Result<()> {
        self.session
            .shutdown()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

/// The Wintun read-wait event: signaled while the receive ring is
/// non-empty, which is exactly the level semantics the `WaitSet` probes
/// rely on.
impl Waitable for ZprTun {
    fn handle(&self) -> WaitHandle<'_> {
        let event = self
            .session
            .get_read_wait_event()
            .expect("WintunGetReadWaitEvent failed");
        WaitHandle::from_event(event as _)
    }
}

/// IPv4 is unsupported on the ZPR TUN across platforms; error uniformly.
fn require_v6(what: &str, addr: IpAddr) -> std::io::Result<std::net::Ipv6Addr> {
    match addr {
        IpAddr::V6(v6) => Ok(v6),
        IpAddr::V4(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("{what} with IPv4 is not supported on windows"),
        )),
    }
}

/// netsh reports errors on stdout as often as stderr; quote both.
fn netsh_output_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}
