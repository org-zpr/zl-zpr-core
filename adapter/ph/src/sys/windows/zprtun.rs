//! The Wintun-backed TUN device, Windows arm (zipline#130, plan D4).
//!
//! `ZprTun` wraps the `wintun` crate (safe bindings that load the signed
//! `wintun.dll` at runtime; the DLL ships next to `ph.exe`). Packets move
//! through Wintun's ring buffers (`try_receive` / `allocate_send_packet` +
//! `send_packet`); readiness is the session's read-wait event, exposed as
//! this device's [`Waitable`] for the fastpath `WaitSet`. There is no
//! packet-info header (`PI_SIZE = 0`, see `tun_pi.rs`).
//!
//! Addresses are managed by shelling out to
//! `netsh interface ipv6 add|delete|show address`, the same pattern as `ip`
//! on Linux and `ifconfig` on macOS. Upgrade path if netsh parsing proves
//! brittle or slow: IP Helper (`CreateUnicastIpAddressEntry`) via
//! `windows-sys`, already in the dependency tree.
//!
//! Interface settings and the ZPR prefix (zl-zipline#297): at creation the
//! adapter's IPv6 interface gets the settings wireguard-windows uses (no
//! router discovery, no DAD, no DHCPv6 flags), and `fd5a:5052::/32` is a
//! route through the link-local next hop [`ZPR_NEXT_HOP`], not an on-link
//! prefix; every address is a /128. Windows cannot turn off neighbor
//! unreachability detection on a Wintun interface, so with an on-link prefix
//! it sent a neighbor solicitation to every peer it talked to (the visa
//! service first), and `ph` turned each one into a visa request. With the
//! routed prefix the only neighbor Windows probes is the next hop, a
//! link-local address, and `ph` never issues a visa for link-local traffic.
//!
//! Adapter lifecycle (plan open question 1, operator-approved): create a
//! fresh adapter at startup — deleting any stale adapter with our name
//! first — and delete it on graceful exit (the wintun crate closes the
//! adapter when the last Arc drops; an unclean exit leaves the adapter for
//! the next startup's stale-delete to reap).

use crate::sys::addr_hint::netsh_add_address_args;
use crate::sys::dad;
use crate::sys::wait::{WaitHandle, Waitable};
use crate::zprtun::{ZprTunError, effective_tun_mtu};
use std::net::{IpAddr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;
use tracing::*;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, GetIpInterfaceEntry, GetUnicastIpAddressEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, MIB_IPPROTO_NETMGMT, RouterDiscoveryDisabled,
};
use zpr::addrs::{ZPR_INTERNAL_NETWORK, ZPRNET_PREFIX_LEN};

use crate::logging::targets::NET_OS;

/// The interface name used when the config does not set `tun_if`.
const DEFAULT_ADAPTER_NAME: &str = "zpr";

/// The Wintun "tunnel type" shown in adapter properties.
const TUNNEL_TYPE: &str = "ZPR";

/// The next hop of the ZPR prefix route on the adapter (zl-zipline#297).
///
/// Nothing answers this address: a Wintun interface is layer 3, so Windows
/// sends routed packets into the ring without resolving a link-layer
/// address. Windows does probe it with neighbor solicitations, but they are
/// link-local, and `ph` discards link-local traffic before it asks for a
/// visa (`do_request_tether_id` in `adapter_manager_worker.rs`).
const ZPR_NEXT_HOP: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

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
    /// the IP Helper calls ([`ZprTun::luid`]).
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    /// The adapter name (config `tun_if` or [`DEFAULT_ADAPTER_NAME`]), as
    /// netsh commands address it.
    name: String,
    /// Serializes netsh address mutations, as on macOS.
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
    /// The adapter's IPv6 interface is configured before any address goes
    /// on: DAD and router discovery off ([`apply_zpr_interface_settings`]),
    /// the ZPR prefix routed through [`ZPR_NEXT_HOP`], and the MTU. A
    /// failure in any of them fails the start: an adapter without them
    /// sends the host's neighbor solicitations to the visa service
    /// (zl-zipline#297), or drops large packets (zl-zipline#214).
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
        tun.configure_ipv6_interface()?;
        tun.add_zpr_prefix_route()?;
        // A Wintun adapter comes up at MTU 65535, far above what the overlay
        // carries; the adapter is fresh every start, so set it
        // unconditionally (zl-zipline#214).
        tun.set_mtu(effective_tun_mtu(None))?;
        Ok(vec![tun])
    }

    /// The adapter's interface LUID, the key of every IP Helper call.
    fn luid(&self) -> NET_LUID_LH {
        // SAFETY: NET_LUID_LH is a union whose every variant is a view of
        // the same 64 bits; reading `Value` reads them as a plain u64. (The
        // wintun crate has its own windows-sys version of the type, so the
        // value is copied across rather than the struct.)
        NET_LUID_LH {
            Value: unsafe { self.adapter.get_luid().Value },
        }
    }

    /// Read the adapter's IPv6 interface row, apply
    /// [`apply_zpr_interface_settings`], and write it back, through IP
    /// Helper (`GetIpInterfaceEntry`, `SetIpInterfaceEntry`). The settings
    /// are not persistent; the adapter is fresh every start.
    fn configure_ipv6_interface(&self) -> std::result::Result<(), ZprTunError> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        // SAFETY: `row` is a valid MIB_IPINTERFACE_ROW that outlives the
        // call; the function only writes default values into it.
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = AF_INET6;
        row.InterfaceLuid = self.luid();
        // SAFETY: `row` is initialized and outlives the call; the function
        // reads the key (Family, InterfaceLuid) and fills the rest in place.
        let rc = unsafe { GetIpInterfaceEntry(&mut row) };
        self.check_win32("GetIpInterfaceEntry", rc)?;
        apply_zpr_interface_settings(&mut row);
        // SAFETY: `row` is the row Windows just returned, with only the
        // fields above changed; it outlives the call.
        let rc = unsafe { SetIpInterfaceEntry(&mut row) };
        self.check_win32("SetIpInterfaceEntry", rc)
    }

    /// Add the route `fd5a:5052::/32` via [`ZPR_NEXT_HOP`] on the adapter
    /// through IP Helper (`CreateIpForwardEntry2`); see the module doc for
    /// why the prefix is routed rather than on-link. The adapter is fresh
    /// every start, so the route never exists yet.
    fn add_zpr_prefix_route(&self) -> std::result::Result<(), ZprTunError> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        // SAFETY: `row` is a valid MIB_IPFORWARD_ROW2 that outlives the
        // call; the function only writes default values into it.
        unsafe { InitializeIpForwardEntry(&mut row) };
        zpr_prefix_route(&mut row, self.luid());
        // SAFETY: `row` is initialized and outlives the call, which only
        // reads it.
        let rc = unsafe { CreateIpForwardEntry2(&row) };
        self.check_win32("CreateIpForwardEntry2", rc)
    }

    /// Turn the Win32 return code `rc` of the IP Helper call `call` into a
    /// result that names the call, the adapter and the error.
    fn check_win32(&self, call: &str, rc: u32) -> std::result::Result<(), ZprTunError> {
        if rc == NO_ERROR {
            return Ok(());
        }
        Err(ZprTunError::PlatformError(format!(
            "{call} failed on {}: Win32 error {rc} ({})",
            self.name,
            std::io::Error::from_raw_os_error(rc as i32)
        )))
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

    /// Add `addr` to the adapter as a /128 and wait until it is usable.
    ///
    /// `prefix_len` is not used on Windows: the ZPR prefix is a route that
    /// [`Self::new_mq`] installs, not an on-link prefix of the address
    /// (zl-zipline#297). The parameter keeps the signature the same on
    /// every platform.
    pub fn add_address(&self, addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
        self.add_address_impl(addr, false)
    }

    /// Add the adapter authentication address (AAA, #1410) as a valid but
    /// deprecated source (`preferredlifetime=0`), the Windows equivalent of
    /// Linux's `preferred_lft 0`: applications prefer the granted actor
    /// address, and authentication binds the AAA explicitly. A deprecated
    /// address still passes the DAD wait ([dad::DadState::Usable]). Like
    /// [Self::add_address], it is a /128 and `prefix_len` is not used.
    pub fn add_authentication_address(&self, addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
        self.add_address_impl(addr, true)
    }

    /// Shared body of [Self::add_address] and
    /// [Self::add_authentication_address].
    ///
    /// The address goes on as a /128 (`netsh_add_address_args`); the rest
    /// of the ZPR prefix, the DNS Zode and the visa service included, is
    /// reached through the route [`Self::new_mq`] installs (zl-zipline#297).
    fn add_address_impl(&self, addr: IpAddr, authentication: bool) -> std::io::Result<()> {
        let _mtx = self.lock()?;
        if self.has_address(addr)? {
            return Ok(());
        }
        let addr = require_v6("add_address", addr)?;
        // netsh interface ipv6 add address <if> <addr>/128 [preferredlifetime=0]
        let args = netsh_add_address_args(&self.name, &IpAddr::V6(addr), authentication);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.netsh(&args).output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "netsh failed to add address {addr} on {}: {}",
                self.name,
                netsh_output_text(&output)
            )));
        }
        // Binding to an address that is not usable yet fails with
        // WSAEADDRNOTAVAIL; the node's VSS listener lost that race on every
        // start while DAD ran (zipline#162). DAD is off now
        // (`DadTransmits = 0`), so the address is usable on the first read.
        // The bounded wait stays as a guard against an address Windows has
        // not shown yet, or a host policy that turns DAD back on.
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
        // The lookup key is (interface LUID, address).
        let mut row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceLuid: self.luid(),
            ..Default::default()
        };
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

/// The Wintun read-wait event. It is an **auto-reset** Event (wintun
/// `api/session.c`): the driver sets it once per ring append, and the wait
/// that reports it consumes it. It is not signaled "while the ring is
/// non-empty", so the TUN read batch re-arms it whenever a batch may have
/// left packets in the ring (`batch_io::windows_unbatched::read_ring_batch`,
/// zl-zipline#292).
impl Waitable for ZprTun {
    fn handle(&self) -> WaitHandle<'_> {
        let event = self
            .session
            .get_read_wait_event()
            .expect("WintunGetReadWaitEvent failed");
        WaitHandle::from_event(event as _)
    }
}

/// Set the IPv6 interface fields that wireguard-windows sets on its Wintun
/// adapters (`tunnel/addressconfig.go`), so Windows sends no router
/// solicitations, runs no duplicate-address detection, and asks for no
/// DHCPv6 (zl-zipline#297):
///
/// - `RouterDiscoveryBehavior` disabled: there is no IPv6 router on the
///   ZPR link, so router solicitations only add traffic.
/// - `DadTransmits` 0: an address added to the adapter is usable at once
///   (no tentative window, zipline#162), and Windows sends no DAD neighbor
///   solicitations or unsolicited neighbor advertisements.
/// - `ManagedAddressConfigurationSupported` and
///   `OtherStatefulConfigurationSupported` false: no DHCPv6.
/// - `SitePrefixLength` at most 128: Windows can report a stale value above
///   128, and `SetIpInterfaceEntry` rejects the row with it
///   (ERROR_INVALID_PARAMETER).
///
/// Neighbor unreachability detection is left on: Windows rejects
/// `UseNeighborUnreachabilityDetection = FALSE` on a Wintun interface with
/// ERROR_INVALID_PARAMETER. The routed ZPR prefix ([`zpr_prefix_route`])
/// keeps its probes off the visa service. IPv6 only: `ph` puts no IPv4 on
/// the adapter.
fn apply_zpr_interface_settings(row: &mut MIB_IPINTERFACE_ROW) {
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.DadTransmits = 0;
    row.ManagedAddressConfigurationSupported = false;
    row.OtherStatefulConfigurationSupported = false;
    row.SitePrefixLength = row.SitePrefixLength.min(128);
}

/// Fill `row` with the route `ZPR_INTERNAL_NETWORK/ZPRNET_PREFIX_LEN`
/// (`fd5a:5052::/32`) via [`ZPR_NEXT_HOP`] on the interface `luid`, as a
/// static route (`MIB_IPPROTO_NETMGMT`). `row` comes from
/// `InitializeIpForwardEntry`, whose defaults (lifetimes, metric) stay.
fn zpr_prefix_route(row: &mut MIB_IPFORWARD_ROW2, luid: NET_LUID_LH) {
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte = ZPR_INTERNAL_NETWORK.octets();
    row.DestinationPrefix.PrefixLength = ZPRNET_PREFIX_LEN;
    row.NextHop.Ipv6.sin6_family = AF_INET6;
    row.NextHop.Ipv6.sin6_addr.u.Byte = ZPR_NEXT_HOP.octets();
    row.Protocol = MIB_IPPROTO_NETMGMT;
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        MIB_IPPROTO_NETMGMT, RouterDiscoveryDisabled, RouterDiscoveryEnabled,
    };

    /// The raw bytes of an IP Helper row, so a test can check that a
    /// function changed only the fields it names. The windows-sys rows have
    /// no `PartialEq` (they hold unions), and `Default` zeroes them, padding
    /// included.
    fn bytes_of<T: Copy>(row: &T) -> Vec<u8> {
        // SAFETY: `row` is a valid, initialized `T` that outlives the slice;
        // the slice covers exactly its `size_of::<T>()` bytes and is copied
        // out before the borrow ends.
        unsafe {
            std::slice::from_raw_parts((row as *const T).cast::<u8>(), size_of::<T>()).to_vec()
        }
    }

    /// A row as Windows reports it for a fresh Wintun adapter (planning
    /// read-back on the VM): router discovery on, one DAD transmit, NUD on.
    fn fresh_interface_row() -> MIB_IPINTERFACE_ROW {
        MIB_IPINTERFACE_ROW {
            Family: AF_INET6,
            RouterDiscoveryBehavior: RouterDiscoveryEnabled,
            DadTransmits: 1,
            ManagedAddressConfigurationSupported: true,
            OtherStatefulConfigurationSupported: true,
            UseNeighborUnreachabilityDetection: true,
            SupportsNeighborDiscovery: true,
            BaseReachableTime: 30_000,
            RetransmitTime: 1_000,
            NlMtu: 1_400,
            SitePrefixLength: 64,
            ..Default::default()
        }
    }

    #[test]
    fn zpr_interface_settings_turn_off_dad_and_router_discovery() {
        let mut row = fresh_interface_row();
        apply_zpr_interface_settings(&mut row);

        assert_eq!(row.RouterDiscoveryBehavior, RouterDiscoveryDisabled);
        assert_eq!(row.DadTransmits, 0);
        assert!(!row.ManagedAddressConfigurationSupported);
        assert!(!row.OtherStatefulConfigurationSupported);
        // NUD stays on: Windows rejects turning it off on Wintun.
        assert!(row.UseNeighborUnreachabilityDetection);

        // Every other field is as it was.
        let mut expected = fresh_interface_row();
        expected.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        expected.DadTransmits = 0;
        expected.ManagedAddressConfigurationSupported = false;
        expected.OtherStatefulConfigurationSupported = false;
        assert_eq!(bytes_of(&row), bytes_of(&expected));
    }

    #[test]
    fn zpr_interface_settings_clamp_site_prefix_length() {
        let mut row = fresh_interface_row();
        row.SitePrefixLength = 200;
        apply_zpr_interface_settings(&mut row);
        assert_eq!(row.SitePrefixLength, 128);

        let mut row = fresh_interface_row();
        row.SitePrefixLength = 64;
        apply_zpr_interface_settings(&mut row);
        assert_eq!(row.SitePrefixLength, 64);
    }

    #[test]
    fn zpr_prefix_route_is_fd5a_5052_32_via_fe80_1() {
        let luid = NET_LUID_LH {
            Value: 0x1234_5678_9abc,
        };
        let mut row = MIB_IPFORWARD_ROW2::default();
        zpr_prefix_route(&mut row, luid);

        // SAFETY: NET_LUID_LH and SOCKADDR_INET are unions whose variants
        // view the same bytes; `zpr_prefix_route` filled the IPv6 views.
        unsafe {
            assert_eq!(row.InterfaceLuid.Value, 0x1234_5678_9abc);
            assert_eq!(row.DestinationPrefix.Prefix.si_family, AF_INET6);
            assert_eq!(
                Ipv6Addr::from(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte),
                "fd5a:5052::".parse::<Ipv6Addr>().unwrap()
            );
            assert_eq!(row.NextHop.si_family, AF_INET6);
            assert_eq!(
                Ipv6Addr::from(row.NextHop.Ipv6.sin6_addr.u.Byte),
                "fe80::1".parse::<Ipv6Addr>().unwrap()
            );
        }
        assert_eq!(row.DestinationPrefix.PrefixLength, 32);
        assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
    }
}
