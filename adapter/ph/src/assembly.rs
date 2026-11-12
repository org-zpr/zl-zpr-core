use crate::adapter_tables;
use crate::address_pool::AddressPool;
use crate::capture_worker::CaptureWorker;
use crate::counters::*;
use crate::flow_control::FlowControl;
use crate::km_cert_exchange::KmCertExchange;
use crate::km_multiplexor::KmState;
use crate::km_noise;
use crate::link_state::{LinkEvent, LinkStateError, LinkType, ZodeEnd};
use crate::mgmt;
use crate::mgmt_processor_worker;
use crate::peer_table;
use crate::peer_table::PeerInsertError;
use crate::prelude::*;
use crate::queues::*;
use crate::special_peers::SpecialPeerName;
use crate::tun_ctl::TunCtl;
use crate::visa_table;
use crate::zdp::TerminateReason;
use crate::zdpr_worker;
use km_noise::NoiseKeypair;
use rcu;
use std::collections::HashMap;
use std::fmt::{Error, Formatter};
use std::net::IpAddr;
use std::num::NonZero;
use std::result::Result;
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::targets::Targets;
#[allow(unused_imports)]
use tracing_subscriber::{Layer, Registry, filter, fmt, reload};
use x25519_dalek::ReusableSecret;
use zpr::addrs::{VISA_SERVICE_ADDR, ZPRNET_PREFIX_LEN};
use zpr::vsapi_types::{AuthServicesList, ConnectRequest};
use zpr_utils::net_defs::{IpAddress, ScopedIpAddr, SocketAddrExt};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PhMode {
    Node,
    Adapter,
}

/// The build-identity string reported by this assembly, e.g. on the
/// mgmt-channel version TLV: `<pkg-version> (<git describe>)` (zipline#64).
pub const VERSION: &'static str = build_info::BUILD_VERSION;

/// Interface to full assembly of all stages.
///
/// This is the "public interface" that all stages of the system use to talk
/// to each other (via queues), and to shared resources (e.g. the buffer stack).
///
/// All queues and shared resources here should be bounded, so that
/// backpressure can flow from any processing stage all the way back to the
/// kernel network ingest queues, and that service time of any packet
/// transiting the system is not permitted to grow indefinitely under
/// pressure.
///
/// The intention is that there are no hidden unbounded queues in the system
/// (such as a mutex held over a blocking operation).  If a resource is
/// highly contended resulting in a bottleneck, that should result in some
/// visible queue becoming full.

pub struct Assembly {
    pub actor_rejected: std::sync::atomic::AtomicBool,
    pub ph_mode: PhMode,
    pub topology_config: config::TopologyConfig,

    pub mgmt_substrate_egress: MgmtSubstrateEgress,
    pub actor_output_requeue: ActorOutputRequeue,

    pub vsconn: Option<libnode::vsconn::VSConnHandle>, // present only on nodes
    pub vs_auth_services: std::sync::RwLock<AuthServicesList>, // present only on nodes, may be empty, managed by visa service
    pub deferred_vs_connect: Mutex<Option<(LinkId, IpAddress, ConnectRequest)>>, // present only on nodes, the VS adapter's connect request and self-granted address, held until the node has VSAPI access
    /// Node only (zipline#121): true while an in-place self re-authentication
    /// against the visa service is in flight. A VSS `requestAuthentication`
    /// naming this node's own address while set is coalesced into the running
    /// attempt instead of queueing a second one; the spawned re-auth task
    /// clears it when the attempt resolves either way.
    pub self_reauth_in_flight: std::sync::atomic::AtomicBool,

    pub visa_table: std::sync::RwLock<visa_table::VisaTable>, // Only for nodes

    /// The links the visa service last pushed with `setTopology`. Its
    /// `peer_cn`s are the peers this Zode accepts on Zode links
    /// (zl-zipline#220); NodeToNode link start (#222) reads it too.
    pub topology: std::sync::RwLock<Vec<zpr::vsapi_types::Link>>,

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: Counters,

    pub tun_ctl: Box<dyn TunCtl + Send>,

    pub peer_table: peer_table::PeerTable,

    // Adapter tables
    pub elt: adapter_tables::EndpointLookupTable,
    pub dlt: adapter_tables::DockLookupTable,

    pub mgmt_dispatch_factory: MgmtDispatchFactory,
    pub mgmt_hairpin_dispatch: MgmtHairpinDispatch,
    pub adapter_manager_factory: AdapterManagerFactory,
    pub km_state: KmState,

    pub self_noise_keypair: Option<NoiseKeypair>,
    pub a2a_dh_keypair: ReusableSecret,
    pub certx: Option<KmCertExchange>,
    pub system_start_time: std::time::Instant,
    pub address_pool: std::sync::Mutex<Option<AddressPool>>, // Nodes only (and required for nodes)

    /// Note that zpr addressed in config are not our real ZPR addresses until we are granted a ZPR address.
    /// If there is a static ZPR address present in the configuration it is set here in main.
    /// Various get_ and set_ functions are defined for this below.
    pub config: rcu::RcuBox<config::Config>,
    /// The operator-configured ZPR address demand as it stood at startup
    /// (`--zpr-addr` / `zpr_addr`), frozen at construction (zipline#83).
    /// Empty means "accept whatever the fabric assigns". This is what the
    /// granted-address mismatch check compares against. (Since #1410 an
    /// adapter's granted address lives on its actor, not in
    /// `config.zpr_addr`; the frozen copy keeps the check independent of
    /// any later config change.)
    pub configured_zpr_addr_demand: Vec<IpAddr>,
    /// A fatal, unrecoverable error signalled from a worker (zipline#83:
    /// the granted-ZPR-address mismatch). Set via
    /// [`Self::signal_fatal_error`]; main watches [`Self::fatal_notify`] and
    /// exits non-zero with this message on stderr.
    pub fatal_error: Mutex<Option<String>>,
    /// Wakes main's fatal-error watcher (see [`Self::signal_fatal_error`]).
    pub fatal_notify: tokio::sync::Notify,
    pub logging: Mutex<HashMap<String, String>>,
    pub reload_handle:
        reload::Handle<filter::Filtered<fmt::Layer<Registry>, Targets, Registry>, Registry>,
}

/// What went wrong in [`Assembly::ensure_local_zpr_addrs_on_tun`], split by
/// remediation (PR #61 review): an address failure is fixed with the
/// platform's add-address command, a visa-service route failure with its
/// add-route command, and a route owned by another live interface means a
/// co-resident ZPR instance already carries visa-service traffic — starting
/// anyway would steal its route (the Windows `add_route` deletes other
/// owners), so the node refuses to start instead. The node branch of
/// `main.rs` matches on this to print the remediation that actually fits.
#[derive(Debug, thiserror::Error)]
pub enum SelfAddressError {
    /// A node ZPR address could not be inspected on, or applied to, the
    /// TUN device.
    #[error("could not apply node ZPR address {addr}: {source}")]
    Address {
        addr: IpAddr,
        #[source]
        source: std::io::Error,
    },
    /// The visa-service /128 host route could not be installed.
    #[error("could not install the visa-service host route {VISA_SERVICE_ADDR}/128: {source}")]
    VsRoute {
        #[source]
        source: std::io::Error,
    },
    /// Another live interface already owns the visa-service host route —
    /// a second ZPR instance on this host. Installing ours would steal it.
    #[error(
        "the visa-service host route {VISA_SERVICE_ADDR}/128 already routes to interface \
         {owner} — another ZPR node or adapter on this host owns visa-service traffic; \
         refusing to take it over"
    )]
    VsRouteConflict { owner: String },
}

impl Assembly {
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {
        match self.ph_mode {
            PhMode::Node => self.shutdown_node().await,
            PhMode::Adapter => self.shutdown_adapter().await,
        }
        // Tear the TUN device down last, after the peers are gone
        // (zipline#130): on Windows this quiesces the Wintun session; the
        // unix TUNs are process-scoped and their teardown is a no-op.
        // Best-effort — the process is exiting either way.
        if let Err(e) = self.tun_ctl.teardown() {
            error!(target: STARTUP, "TUN teardown failed during shutdown: {e}");
        }
    }

    // The node quickly sends Terminate Indications
    async fn shutdown_node(self: &Arc<Self>) {
        if matches!(self.ph_mode, PhMode::Node) {
            let mut join_set = tokio::task::JoinSet::new();

            let vs_peer = self
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);

            self.peer_table.for_each(|(peer_id, peer)| {
                if Some(peer_id) != vs_peer && !peer.is_internal() {
                    // This should be a short block and must be blocked on,
                    // otherwise the messages won't get sent
                    let spawn_self = self.clone();
                    join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
                }
            });

            join_set.join_all().await;

            if let Some(vs_peer) = vs_peer {
                self.reset_peer(vs_peer.get()).await;
            }
        }
    }

    // The adapter sends a more policy Terminate Request.
    async fn shutdown_adapter(self: &Arc<Self>) {
        let mut join_set = tokio::task::JoinSet::new();

        self.peer_table.for_each(|(peer_id, peer)| {
            if peer.is_internal() {
                return;
            }

            if let Err(e) = peer
                .link_state_machine
                .process_event(self, LinkEvent::Close(TerminateReason::Shutdown))
            {
                error!(target: PEER_MGMT, "Failed to nicely close peer {}: {e}", self.formatted_link_id(peer_id.get()));
                // So try harder...
                let spawn_self = self.clone();
                join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
            }
        });
        join_set.join_all().await;

        let mut npeers = self.peer_table.len() - 1; // - 1 accounts for local actor
        info!(
            target: PEER_MGMT,
            "Waiting for {} peer{} to disconnect...",
            npeers,
            if npeers == 1 { "" } else { "s" }
        );
        while npeers > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            npeers = self.peer_table.len() - 1; // - 1 accounts for local actor
        }
    }

    /// Disconnect all non-internal, non-vs adapters.
    /// Used in a node context when (for example) we loose all state with the visa service.
    ///
    /// Does not remove visas related to the adapter/peer.
    pub async fn disconnect_adapters(self: &Arc<Self>) {
        if matches!(self.ph_mode, PhMode::Node) {
            let mut join_set = tokio::task::JoinSet::new();
            let vs_peer = self
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
            self.peer_table.for_each(|(peer_id, peer)| {
                if Some(peer_id) != vs_peer && !peer.is_internal() {
                    // This should be a short block and must be blocked on,
                    // otherwise the messages won't get sent
                    let spawn_self = self.clone();
                    join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
                }
            });
            join_set.join_all().await;
        }
    }

    #[allow(dead_code)]
    pub fn is_link_ready(&self, id: LinkId) -> bool {
        match self.peer_table.get(id) {
            Some(peer) => peer.link_state_machine.is_ready(),
            None => false,
        }
    }

    pub fn adapter_owns_address(&self, addr: IpAddress) -> bool {
        self.peer_table.get(DOCK_LINK_ID).is_some_and(|peer| {
            peer.link_state_machine.is_ready()
                && (peer.actor_auth.owns_address(&addr)
                    || peer.link_state_machine.aaa_address() == Some(addr))
        })
    }

    /// Get a copy of the local ZPR addresses. May be empty on an adapter until we
    /// have been granted a ZPR address.
    pub fn get_local_zpr_addrs_std(&self) -> Vec<IpAddr> {
        if self.ph_mode == PhMode::Adapter {
            self.peer_table
                .get(DOCK_LINK_ID)
                .map(|p| {
                    p.actor_auth
                        .addresses()
                        .into_iter()
                        .map(Into::into)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            self.config.get().zpr_addr.clone()
        }
    }

    /// Record `msg` as a fatal, unrecoverable error and wake main's watcher
    /// (see main.rs): the process exits non-zero with the message on stderr
    /// (zipline#83). The first message wins — a later signal keeps the
    /// original text but still notifies, so main wakes regardless of
    /// ordering.
    pub fn signal_fatal_error(&self, msg: String) {
        {
            let mut fatal = self.fatal_error.lock().unwrap();
            if fatal.is_none() {
                *fatal = Some(msg);
            }
        }
        self.fatal_notify.notify_one();
    }

    /// The recorded fatal error, if any (see [`Self::signal_fatal_error`]).
    pub fn get_fatal_error(&self) -> Option<String> {
        self.fatal_error.lock().unwrap().clone()
    }

    /// Node only: the "dock address" is the first local ZPR address.
    ///
    /// In unlikely event that the node has no local ZPR addresses, this returns the
    /// all zeros IPv6 addr.
    ///
    /// TODO: In the future we may want to keep track of the nodes dock address
    /// in a more static way to avoid taking the read lock since we need this
    /// value on every visa request.
    pub fn get_local_dock_addr(&self) -> IpAddr {
        let lza = &self.config.get().zpr_addr;
        if lza.is_empty() {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            lza[0]
        }
    }

    /// Returns the local ZPR addresses which we believe we own but which are
    /// *not* actually configured on the TUN device.  An empty vector means the
    /// TUN device agrees with us.
    ///
    /// ph does not always own the addressing of its TUN device: on Linux an
    /// IPv6 ZPR address cannot be set at device-creation time, so a node's
    /// address is configured out of band and `zpr_addr` merely asserts what is
    /// expected to be there.  When the two disagree nothing fails directly --
    /// the node instead binds services to an address it does not have and
    /// emits packets from a source address it has not claimed -- so callers
    /// use this to turn that silent misconfiguration into a loud one.
    ///
    /// This deliberately reads the *current* address set via
    /// [`Self::get_local_zpr_addrs_std`] rather than the startup
    /// configuration, so it remains correct for an address that is assigned or
    /// reassigned at run time (as an adapter's is today: its address is the
    /// one granted to its actor).  Re-run it after any such change.
    ///
    /// Addresses the platform cannot inspect are reported as present: a check
    /// that cannot see the truth must not manufacture a failure.  The same
    /// applies to an unexpected error, which is logged and skipped.
    pub fn local_zpr_addrs_missing_from_tun(&self) -> Vec<IpAddr> {
        self.get_local_zpr_addrs_std()
            .into_iter()
            .filter(|addr| match self.tun_ctl.has_address(*addr) {
                Ok(present) => !present,
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => false,
                Err(e) => {
                    warn!(target: NET_OS, "cannot determine whether {addr} is configured on the TUN device: {e}");
                    false
                }
            })
            .collect()
    }

    /// Node self-addressing (zipline#159, decision N3 of the Windows node
    /// plan): apply each local ZPR address this node believes it owns to the
    /// TUN device, and make the visa service's well-known address reachable
    /// through it where the address alone does not.
    ///
    /// Idempotent: an address the device already carries is left untouched,
    /// so hand-configured setups and the integration scripts' out-of-band
    /// `ip addr add` see no change — for them `has_address` is true and
    /// nothing is called. An address the platform cannot inspect
    /// (`ErrorKind::Unsupported`) is skipped, exactly as
    /// [`Self::local_zpr_addrs_missing_from_tun`] treats it: a helper that
    /// cannot see the truth must not act on it. Any other failure — from the
    /// inspection, from `add_address`, or from the visa-service route install
    /// — is propagated as a [`SelfAddressError`] naming which step failed, so
    /// the node branch of `main.rs` can print the matching manual remediation
    /// before exiting rather than run misaddressed.
    ///
    /// Reads the *current* address set via [`Self::get_local_zpr_addrs_std`],
    /// the same source as the missing-address check that runs after it.
    /// Node use only: adapter addressing belongs to link activation
    /// (`link_state.rs`), which this deliberately does not touch (N2).
    pub fn ensure_local_zpr_addrs_on_tun(&self) -> Result<(), SelfAddressError> {
        // On Windows the visa-service host route is required: `netsh
        // interface ipv6 add address` takes no prefix length (see
        // `sys/windows/zprtun.rs::add_address`), so the address is installed
        // as a /128 and never makes the ZPR internal network on-link. On
        // Linux and macOS `add_address` applies `ZPRNET_PREFIX_LEN`, which
        // puts the whole internal network — the visa service included —
        // on-link, so no route is needed and none is installed.
        self.ensure_local_zpr_addrs_on_tun_impl(cfg!(windows))
    }

    /// The platform-independent body of [`Self::ensure_local_zpr_addrs_on_tun`],
    /// with the one platform fact — whether on-link reachability of the visa
    /// service needs an explicit host route — passed in so both arms are
    /// unit-testable everywhere.
    fn ensure_local_zpr_addrs_on_tun_impl(
        &self,
        vs_route_needed: bool,
    ) -> Result<(), SelfAddressError> {
        for addr in self.get_local_zpr_addrs_std() {
            match self.tun_ctl.has_address(addr) {
                Ok(true) => {}
                Ok(false) => {
                    info!(target: NET_OS, "applying node ZPR address {addr}/{ZPRNET_PREFIX_LEN} to the TUN device");
                    self.tun_ctl
                        .add_address(addr, ZPRNET_PREFIX_LEN)
                        .map_err(|source| SelfAddressError::Address { addr, source })?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                    debug!(target: NET_OS, "cannot inspect {addr} on this platform; leaving it alone: {e}");
                }
                Err(source) => return Err(SelfAddressError::Address { addr, source }),
            }
        }
        if vs_route_needed {
            // PR #61 review (P1): the Windows `add_route` is
            // replacement-oriented — it deletes every owner on another
            // interface before adding its own. Installing over a live
            // owner would silently steal a co-resident ZPR instance's
            // visa-service traffic, and our exit would leave that instance
            // routeless. So probe ownership first and refuse to start on a
            // conflict, exactly as adapter activation does for the
            // internal-network route (zipline#101). Per the same ruling, a
            // probe that cannot run means "unknown", not "conflict" — warn
            // and continue to the install.
            match self.tun_ctl.route_owner_conflict(VISA_SERVICE_ADDR, 128) {
                Ok(None) => {}
                Ok(Some(owner)) => {
                    return Err(SelfAddressError::VsRouteConflict { owner });
                }
                Err(e) => {
                    warn!(target: NET_OS, "could not check the owner of the visa-service host route {VISA_SERVICE_ADDR}/128: {e}; continuing");
                }
            }
            // A /128 host route: the narrowest statement of what the node
            // needs — "the visa service is on-link via the TUN" — without
            // claiming the whole internal network, which is the adapter
            // activation path's decision to make, not ours (N2).
            self.tun_ctl
                .add_route(VISA_SERVICE_ADDR, 128)
                .map_err(|source| SelfAddressError::VsRoute { source })?;
        }
        Ok(())
    }

    pub fn process_link_state_event(
        self: &Arc<Self>,
        id: LinkId,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        let Some(peer) = self.peer_table.get(id) else {
            return Err(LinkStateError::NotFound(id));
        };
        peer.link_state_machine.process_event(self, event)
    }

    fn add_peer(
        self: &Arc<Self>,
        link_type: LinkType,
        peer_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        self.add_peer_mapped(link_type, peer_addr, interface_addr, true)
    }

    /// [Assembly::add_peer], mapping the peer's substrate address to the new
    /// link only if `map` (see [peer_table::VacantPeerTableEntry::insert_unmapped]).
    fn add_peer_mapped(
        self: &Arc<Self>,
        link_type: LinkType,
        peer_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
        map: bool,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        let entry = self.peer_table.vacant_entry()?;

        let worker_config = mgmt_processor_worker::Config {
            link_id: entry.key(),
        };

        let peer_state =
            peer_table::PeerState::new(entry.key(), link_type, *peer_addr, *interface_addr, |q| {
                mgmt_processor_worker::launch(worker_config, self.clone(), q)
            });

        let link_id = if map {
            entry.insert(peer_state)
        } else {
            entry.insert_unmapped(peer_state)
        };

        tokio::task::spawn_local(zdpr_worker::launch(self.clone(), link_id.get()));

        Ok(link_id)
    }

    /// Caled from `LinkStateWrapper::complete_close`.`
    /// Also drops visas related to the peer.
    pub fn drop_peer(self: &Arc<Self>, link_id: LinkId) {
        let vs_link_id = self
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_link_id.is_some() && link_id == vs_link_id.unwrap().get() {
            debug!(target: PEER_MGMT, "Removing peer {} [VISA SERVICE]", self.formatted_link_id(link_id));
        } else {
            debug!(target: PEER_MGMT, "Removing peer {}", self.formatted_link_id(link_id));
        }
        if self.ph_mode == PhMode::Node {
            // Revoke visas under the write lock, but hold the withdrawn
            // entries until the lock is released: the send path takes the
            // peer's `zdpr_send` mutex, which must never nest under the
            // visa-table lock (and `unbind_stream` itself re-acquires the
            // visa-table lock, which is why it is not usable here).
            let withdrawn = self
                .visa_table
                .write()
                .unwrap()
                .revoke_for_link(link_id, &self.peer_table);

            // Withdraw each revoked stream from the *surviving* peers so
            // they drop their egress bindings and re-request visas instead
            // of blackholing traffic on dead streams (zipline#21). The
            // dying link's own entries are skipped — that peer is gone.
            self.withdraw_streams(withdrawn, Some(link_id));
        }
        self.peer_table.remove(link_id);
        info!(target: PEER_MGMT, "Removed peer {}", self.formatted_link_id(link_id));
    }

    /// Withdraw the given forwarding entries from the peers still bound to
    /// them by sending each one a `StreamIdWithdrawal` — "the stream id YOU
    /// send with has been withdrawn" — because `entry.1` is the tether id
    /// the receiving adapter holds in its *outbound* ELT, not an id in its
    /// inbound DLT (which is what UnbindEgressStreamIndication's handler
    /// removes from). Shared by `drop_peer` (zipline#21) and
    /// `visa_mgmt::handle_revocation` (zipline#85).
    ///
    /// `excluded_link` names a dying link whose own entries must be skipped
    /// (that peer is gone) — `drop_peer` passes it. Entries whose link has
    /// already left the peer table are skipped as well.
    ///
    /// Lock ordering (zipline#9): call this only AFTER releasing the
    /// visa-table write lock — the send path takes the peer's `zdpr_send`
    /// mutex, which must never nest under it.
    ///
    /// Note the expiry path (`VisaTable::handle_expirations`) deliberately
    /// does not notify: both ends share the visa expiry and eject on their
    /// own clocks, and a peer that sends early gets UnknownStreamId and
    /// re-requests.
    pub(crate) fn withdraw_streams(
        &self,
        withdrawn: Vec<ForwardingEntry>,
        excluded_link: Option<LinkId>,
    ) {
        for entry in withdrawn {
            if Some(entry.0) == excluded_link || self.peer_table.get(entry.0).is_none() {
                continue;
            }
            mgmt::requests::send_stream_id_withdrawal(self, entry.0, entry.1).enqueue();
        }
    }

    /// Part of graceful shutdown (or administrative link shutdown).
    ///
    /// Reset peer at given link.
    ///
    /// Calls down to `LinkStateWrapper::reset` which will ultimately end up calling back
    /// here to [Assembly::drop_peer].
    pub async fn reset_peer(self: &Arc<Self>, link_id: LinkId) {
        let vs_link_id = self
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_link_id.is_some() && link_id == vs_link_id.unwrap().get() {
            if let Some(vsconn) = self.vsconn.as_ref() {
                if let Err(e) = vsconn.stop(true).await {
                    error!(target: PEER_MGMT, "stop command to VSConn failed: {e}");
                } else {
                    // Let VSConn runloop process/send the command.
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        if let Some(peer) = self.peer_table.get(link_id) {
            peer.link_state_machine.reset(self).await;
        }
    }

    /// Add a tether to the peer table.
    ///
    /// `auto_start` controls whether the link starts (fires
    /// `LinkEvent::Start`, Inactive -> Keying) immediately. Adapters started
    /// with `--auto-connect=false` pass `false` (zipline#28): the peer is
    /// still created — so ph-cli has a link to target — but it idles in
    /// Inactive until a `startLink` RPC wakes it. Everything else passes
    /// `true`, today's behaviour.
    pub fn start_tether(
        self: &Arc<Self>,
        adapter_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
        link_type: LinkType,
        auto_start: bool,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        assert!(matches!(
            link_type,
            LinkType::NodeToAdapter | LinkType::AdapterToNode
        ));
        debug!(target: PEER_MGMT, "Starting tether with {adapter_addr} connected to {interface_addr}");
        let peer_id = self.add_peer(link_type, adapter_addr, interface_addr)?;

        let Some(peer) = self.peer_table.get(peer_id.get()) else {
            // Peer is gone already
            return Ok(peer_id);
        };

        if !auto_start {
            info!(target: PEER_MGMT, "Tether with {adapter_addr} created idle (auto-connect off).  Assigned ID {}", self.formatted_link_id(peer_id.get()));
            return Ok(peer_id);
        }

        if let Err(e) = peer
            .link_state_machine
            .process_event(self, LinkEvent::Start)
        {
            error!(target: PEER_MGMT, "{} failed to start with error {e}.  Resetting", self.formatted_link_id(peer_id.get()));
            peer.link_state_machine
                .process_event(self, LinkEvent::Error)
                .expect("This shouldn't error!");
            return Err(PeerInsertError::FailedToStart(e.to_string()));
        } else {
            info!(target: PEER_MGMT, "Successfully started tether with {adapter_addr}.  Assigned ID {}", self.formatted_link_id(peer_id.get()));
        }

        return Ok(peer_id);
    }

    /// Add a Zode-to-Zode link to `peer` and start it (zl-zipline#250).
    /// `end` says whether this Zode dialed it, and for which CN, or answers
    /// a peer's dial. A link that fails to start leaves no peer entry.
    pub fn start_zode_link(
        self: &Arc<Self>,
        peer: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
        end: ZodeEnd,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        debug!(target: PEER_MGMT, "Starting Zode link with {peer} on {interface_addr} as {end:?}");
        let peer_id = self.add_peer(LinkType::NodeToNode, peer, interface_addr)?;
        self.start_added_zode_link(peer_id, end)?;
        info!(target: PEER_MGMT, "Started Zode link with {peer}.  Assigned ID {}", self.formatted_link_id(peer_id.get()));
        Ok(peer_id)
    }

    /// Answer a new Zode handshake from the substrate address of the
    /// established Zode link `established` (ZODE_LINKS.md rule 5, gate g78
    /// q5): typically the owner restarted on its fixed port and dialed
    /// again. The new link keys alongside the established one, which keeps
    /// the address until the new peer's CN is verified at `KeyingDone`.
    pub fn answer_zode_redial(
        self: &Arc<Self>,
        established: LinkId,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        let Some((peer, interface_addr)) = self
            .peer_table
            .inspect(established, |p| (p.substrate_addr, p.interface_addr))
        else {
            return Err(PeerInsertError::FailedToStart(
                "established link is gone".into(),
            ));
        };
        info!(target: PEER_MGMT, "New Zode handshake from {peer}, the address of {}; keying it alongside", self.formatted_link_id(established));
        let peer_id = self.add_peer_mapped(LinkType::NodeToNode, &peer, &interface_addr, false)?;
        self.start_added_zode_link(peer_id, ZodeEnd::Answerer)?;
        Ok(peer_id)
    }

    /// Set the Zode end of the just-added link `peer_id` and fire `Start`.
    /// On failure the peer entry is dropped, so nothing of the link remains.
    fn start_added_zode_link(
        self: &Arc<Self>,
        peer_id: NonZero<LinkId>,
        end: ZodeEnd,
    ) -> Result<(), PeerInsertError> {
        let started = match self.peer_table.get(peer_id.get()) {
            Some(peer) => peer.link_state_machine.set_zode_end(end).and_then(|()| {
                peer.link_state_machine
                    .process_event(self, LinkEvent::Start)
            }),
            None => return Ok(()),
        };
        if let Err(e) = started {
            error!(target: PEER_MGMT, "{} failed to start: {e}.  Dropping it", self.formatted_link_id(peer_id.get()));
            self.drop_peer(peer_id.get());
            return Err(PeerInsertError::FailedToStart(e.to_string()));
        }
        Ok(())
    }

    /// Dial this Zode's initial link, if it has one (zl-zipline#250): the
    /// relay it reaches the network through. Called once at startup.
    ///
    /// This is one attempt. Redialing with backoff after a failed attempt or
    /// a lost link (ZODE_LINKS.md rule 11) is the per-link record's job,
    /// which the core-lifecycle part of #250 adds on top of this.
    pub fn dial_initial_link(self: &Arc<Self>) {
        let config = self.config.get();
        let Some(link) = config.initial_link.clone() else {
            return;
        };
        // The local address the kernel uses to reach the relay is the
        // interface address its packets will arrive on. Probe from our IP
        // with an ephemeral port: the substrate sockets hold our port. Keep
        // the rest of the address, including an IPv6 scope.
        let mut probe_from = config.self_addr;
        probe_from.set_port(0);
        let interface_addr = match crate::sys::substrate::resolve_local_addr(probe_from, link.addr)
        {
            Ok(local) => local.scoped_ip(),
            Err(e) => {
                error!(target: PEER_MGMT, "cannot route to initial link {} at {}: {e}", link.cn, link.addr);
                return;
            }
        };
        let end = ZodeEnd::Dialer {
            peer_cn: link.cn.clone(),
        };
        if let Err(e) = self.start_zode_link(&link.addr, &interface_addr, end) {
            error!(target: PEER_MGMT, "cannot start initial link {} at {}: {e}", link.cn, link.addr);
        }
    }

    /// Temporary? function to find a link based on the actor address
    pub fn find_egress_link(&self, actor_addr: IpAddress) -> Option<NonZero<LinkId>> {
        // First check the local actor addresses to see if it's a locally-destined packet
        if self
            .get_local_zpr_addrs_std()
            .iter()
            .any(|addr| IpAddress::new_from_std(addr) == actor_addr)
        {
            return Some(NonZero::new(LOCAL_ACTOR_LINK_ID).unwrap());
        }

        // Check peer actor addresses to see if one of them matches
        self.peer_table
            .find(|(_id, peer)| {
                peer.actor_auth.owns_address(&actor_addr)
                    || peer.link_state_machine.aaa_address() == Some(actor_addr)
            })
            .map(|(id, _peer)| id)
    }

    // Formats link IDs for display purposes
    pub fn format_link_id(&self, link_id: LinkId, f: &mut Formatter<'_>) -> Result<(), Error> {
        match link_id {
            0 => f.write_str("unknown link")?,
            1 => f.write_str("adapter link")?,
            2 => f.write_str("dock link")?,
            _ => write!(f, "link {}", link_id)?,
        }
        Ok(())
    }

    /// Returns a formatted string for the given link ID
    pub fn formatted_link_id(&self, link_id: LinkId) -> impl std::fmt::Display {
        std::fmt::from_fn(move |f| self.format_link_id(link_id, f))
    }
}

#[cfg(any(test, feature = "fuzzing"))]
pub mod test {

    use super::*;
    use crate::config::TopologyConfig;
    use crate::packet_queue;
    use crate::two_way_queue;
    use tokio::sync::mpsc;

    #[allow(dead_code)]
    #[derive(Default)]
    pub struct TestAssemblyBuilder {
        pub ph_mode: Option<PhMode>,
        pub topology_config: Option<TopologyConfig>,
        pub local_zpr_addresses: Option<Vec<IpAddr>>,
        pub mgmt_substrate_egress: Option<MgmtSubstrateEgress>,
        pub actor_output_requeue: Option<ActorOutputRequeue>,
        pub vsconn: Option<Option<libnode::vsconn::VSConnHandle>>,
        pub visa_table: Option<visa_table::VisaTable>,
        pub capture_queue: Option<Capture>,
        pub capture_worker: Option<CaptureWorker>,
        pub flow_control: Option<FlowControl>,
        pub counters: Option<Counters>,
        pub tun_ctl: Option<Box<dyn TunCtl + Send>>,
        pub peer_table: Option<peer_table::PeerTable>,
        pub elt: Option<adapter_tables::EndpointLookupTable>,
        pub dlt: Option<adapter_tables::DockLookupTable>,
        pub mgmt_dispatch_factory: Option<MgmtDispatchFactory>,
        pub mgmt_hairpin_dispatch: Option<MgmtHairpinDispatch>,
        pub adapter_manager_factory: Option<AdapterManagerFactory>,
        pub km_state: Option<KmState>,
        pub self_noise_keypair: Option<crate::km_noise::NoiseKeypair>,
        pub certx: Option<crate::km_cert_exchange::KmCertExchange>,
        pub system_start_time: Option<std::time::Instant>,
        pub config: Option<rcu::RcuBox<config::Config>>,
        pub logging: Option<Mutex<HashMap<String, String>>>,
        pub reload_handle: Option<
            reload::Handle<filter::Filtered<fmt::Layer<Registry>, Targets, Registry>, Registry>,
        >,
    }

    #[allow(dead_code)]
    struct DummyTunCtlImpl;
    impl TunCtl for DummyTunCtlImpl {
        fn name(&self) -> String {
            "tun-dummy".to_string()
        }
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn add_authentication_address(
            &self,
            _addr: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn has_address(&self, _addr: IpAddr) -> std::io::Result<bool> {
            Ok(true)
        }
        fn add_route(&self, _dest: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn route_owner_conflict(
            &self,
            _dest: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<Option<String>> {
            Ok(None)
        }
    }

    /// A `TunCtl` which reports exactly the addresses it was constructed with,
    /// so tests can model a TUN device that disagrees with our configuration.
    #[cfg(test)]
    struct FakeTunCtl {
        addresses: Vec<IpAddr>,
    }

    #[cfg(test)]
    impl TunCtl for FakeTunCtl {
        fn name(&self) -> String {
            "tun-fake".to_string()
        }
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        /// The AAA is just another address to this double.
        fn add_authentication_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            self.add_address(addr, prefix_len)
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
            Ok(self.addresses.contains(&addr))
        }
        fn add_route(&self, _dest: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn route_owner_conflict(
            &self,
            _dest: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<Option<String>> {
            Ok(None)
        }
    }

    /// A `TunCtl` recording every `add_route` call, so tests can assert the
    /// link-activation route install (zipline#88). With `fail_routes` set,
    /// `add_route` fails instead, modelling a TUN whose routing table cannot
    /// be updated — the fail-fast/warn-and-continue split's test double.
    /// With `conflict` set, `route_owner_conflict` reports that interface
    /// as the live owner of the queried route (zipline#101). With
    /// `late_conflict` set, only probes after the first report it — the
    /// concurrent-activation race, where the other adapter's carrier-up
    /// lands between our pre-install probe and the post-carrier re-check.
    /// `carriers` logs every `set_carrier` call so tests can assert an
    /// adapter that backed off did not leave its carrier up. `addresses`
    /// is the set of addresses on the TUN: `add_address` adds to it,
    /// `clear_address` removes from it and `has_address` reports it, so
    /// tests can see what an activation left behind (zipline#157).
    #[cfg(test)]
    pub struct RecordingTunCtl {
        pub routes: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
        pub fail_routes: bool,
        /// With this set, `add_address` fails — modelling a host where the
        /// granted ZPR address cannot be set on the TUN (e.g. EPERM,
        /// zipline#157).
        pub fail_addresses: bool,
        pub conflict: Option<String>,
        pub late_conflict: Option<String>,
        pub probes: Arc<std::sync::atomic::AtomicUsize>,
        pub carriers: Arc<std::sync::Mutex<Vec<bool>>>,
        pub teardowns: Arc<std::sync::atomic::AtomicUsize>,
        pub addresses: Arc<std::sync::Mutex<Vec<IpAddr>>>,
    }

    #[cfg(test)]
    impl RecordingTunCtl {
        /// A recording instance plus the shared log the test asserts on.
        pub fn new(fail_routes: bool) -> (Self, Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) {
            let routes = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    routes: routes.clone(),
                    fail_routes,
                    fail_addresses: false,
                    conflict: None,
                    late_conflict: None,
                    probes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    carriers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    teardowns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    addresses: Arc::new(std::sync::Mutex::new(Vec::new())),
                },
                routes,
            )
        }

        /// A recording instance whose `add_address` fails — the zipline#157
        /// scenario: the granted ZPR address cannot be set on the TUN
        /// (e.g. EPERM), a local failure that will not clear on reconnect.
        pub fn with_failing_addresses() -> (Self, Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) {
            let (mut tun_ctl, routes) = Self::new(false);
            tun_ctl.fail_addresses = true;
            (tun_ctl, routes)
        }

        /// A recording instance whose `route_owner_conflict` names
        /// `owner_if` as the conflicting live owner (zipline#101).
        pub fn with_conflict(owner_if: &str) -> (Self, Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) {
            let (mut tun_ctl, routes) = Self::new(false);
            tun_ctl.conflict = Some(owner_if.to_string());
            (tun_ctl, routes)
        }

        /// A recording instance whose `route_owner_conflict` reports no
        /// conflict on the first probe and names `owner_if` on every later
        /// one — the zipline#101 concurrent-activation race: the other
        /// adapter's route was `linkdown` (filtered) at the pre-install
        /// probe and its carrier came up before ours did.
        pub fn with_late_conflict(
            owner_if: &str,
        ) -> (Self, Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) {
            let (mut tun_ctl, routes) = Self::new(false);
            tun_ctl.late_conflict = Some(owner_if.to_string());
            (tun_ctl, routes)
        }
    }

    #[cfg(test)]
    impl TunCtl for RecordingTunCtl {
        fn name(&self) -> String {
            "tun-recording".to_string()
        }
        fn set_carrier(&self, carrier: bool) -> std::io::Result<()> {
            self.carriers.lock().unwrap().push(carrier);
            Ok(())
        }
        fn add_address(&self, addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            if self.fail_addresses {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "RecordingTunCtl: add_address deliberately failing (EPERM)",
                ));
            }
            self.addresses.lock().unwrap().push(addr);
            Ok(())
        }
        /// Always succeeds: `fail_addresses` models the *granted* ZPR
        /// address failing (zipline#157), not the AAA installed at Hello.
        fn add_authentication_address(
            &self,
            _addr: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_address(&self, addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            self.addresses.lock().unwrap().retain(|a| *a != addr);
            Ok(())
        }
        fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
            Ok(self.addresses.lock().unwrap().contains(&addr))
        }
        fn add_route(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            if self.fail_routes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "RecordingTunCtl: add_route deliberately failing",
                ));
            }
            self.routes.lock().unwrap().push((dest, prefix_len));
            Ok(())
        }
        fn route_owner_conflict(
            &self,
            _dest: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<Option<String>> {
            let probe = self
                .probes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(conflict) = &self.conflict {
                return Ok(Some(conflict.clone()));
            }
            if probe > 0 {
                if let Some(late) = &self.late_conflict {
                    return Ok(Some(late.clone()));
                }
            }
            Ok(None)
        }
        fn teardown(&self) -> std::io::Result<()> {
            self.teardowns
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// Builds a test assembly whose local ZPR addresses are `zpr_addr` and
    /// whose TUN device carries `on_tun`.
    #[cfg(test)]
    fn assembly_with_addrs(zpr_addr: &[&str], on_tun: &[&str]) -> Assembly {
        let parse = |v: &[&str]| -> Vec<IpAddr> { v.iter().map(|a| a.parse().unwrap()).collect() };
        let config = config::Config {
            zpr_addr: parse(zpr_addr),
            ..Default::default()
        };
        create_assembly(TestAssemblyBuilder {
            ph_mode: Some(PhMode::Node),
            config: Some(rcu::RcuBox::new(config)),
            tun_ctl: Some(Box::new(FakeTunCtl {
                addresses: parse(on_tun),
            })),
            ..Default::default()
        })
    }

    /// Regression test for a node configured with `fd5a:5052:90de::1` while its
    /// TUN device actually carried `fd5a:5052:90de::2`.  The node bound its VSS
    /// listener to an address it did not have and sourced visa-service traffic
    /// from an address it had not claimed, which its own bind check then denied
    /// -- with no indication of why.
    #[test]
    fn detects_local_zpr_addr_absent_from_tun() {
        let asm = assembly_with_addrs(&["fd5a:5052:90de::1"], &["fd5a:5052:90de::2"]);
        assert_eq!(
            asm.local_zpr_addrs_missing_from_tun(),
            vec!["fd5a:5052:90de::1".parse::<IpAddr>().unwrap()]
        );
    }

    /// A TUN device carrying the configured address (among others) is not a
    /// mismatch.
    #[test]
    fn accepts_local_zpr_addr_present_on_tun() {
        let asm = assembly_with_addrs(&["fd5a:5052:90de::1"], &["fd5a:5052:90de::1", "fe80::1"]);
        assert!(asm.local_zpr_addrs_missing_from_tun().is_empty());
    }

    /// Every configured address must be present, not just the first.
    #[test]
    fn detects_partially_configured_local_zpr_addrs() {
        let asm = assembly_with_addrs(
            &["fd5a:5052:90de::1", "fd5a:5052:90de::7"],
            &["fd5a:5052:90de::1"],
        );
        assert_eq!(
            asm.local_zpr_addrs_missing_from_tun(),
            vec!["fd5a:5052:90de::7".parse::<IpAddr>().unwrap()]
        );
    }

    /// An adapter which has not yet been granted an address has nothing to
    /// check, and must not be reported as misconfigured.
    #[test]
    fn no_local_zpr_addrs_is_not_a_mismatch() {
        let asm = assembly_with_addrs(&[], &["fd5a:5052:90de::2"]);
        assert!(asm.local_zpr_addrs_missing_from_tun().is_empty());
    }

    /// A `TunCtl` for the node self-addressing helper (zipline#159): reports
    /// exactly the addresses it was constructed with, records every
    /// `add_address` and `add_route` call, and can be made to fail
    /// `add_address` or report addresses as uninspectable, so tests can
    /// assert exactly what `ensure_local_zpr_addrs_on_tun` did.
    #[cfg(test)]
    struct SelfAddressTunCtl {
        on_tun: Vec<IpAddr>,
        added: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
        routes: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
        fail_add_address: bool,
        inspect_unsupported: bool,
        /// With this set, `add_route` fails — modelling a routing table the
        /// visa-service host route cannot be installed into (PR #61 review).
        fail_add_route: bool,
        /// With this set, `route_owner_conflict` names this interface as the
        /// live owner of any queried route — modelling a second node on the
        /// same host already carrying the visa-service /128 (PR #61 review).
        vs_route_owner: Option<String>,
        /// With this set, `route_owner_conflict` fails — modelling a routing
        /// table that cannot be queried, which means "unknown", not
        /// "conflict" (zipline#101 ruling).
        probe_fails: bool,
    }

    #[cfg(test)]
    impl SelfAddressTunCtl {
        /// An instance whose device already carries `on_tun`, plus the
        /// shared logs of `add_address` and `add_route` calls the test
        /// asserts on.
        #[allow(clippy::type_complexity)]
        fn new(
            on_tun: &[&str],
        ) -> (
            Self,
            Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
            Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
        ) {
            let added = Arc::new(std::sync::Mutex::new(Vec::new()));
            let routes = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    on_tun: on_tun.iter().map(|a| a.parse().unwrap()).collect(),
                    added: added.clone(),
                    routes: routes.clone(),
                    fail_add_address: false,
                    inspect_unsupported: false,
                    fail_add_route: false,
                    vs_route_owner: None,
                    probe_fails: false,
                },
                added,
                routes,
            )
        }
    }

    #[cfg(test)]
    impl TunCtl for SelfAddressTunCtl {
        fn name(&self) -> String {
            "tun-self-address".to_string()
        }
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            if self.fail_add_address {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "SelfAddressTunCtl: add_address deliberately failing (EPERM)",
                ));
            }
            self.added.lock().unwrap().push((addr, prefix_len));
            Ok(())
        }
        /// The AAA is just another address to this double.
        fn add_authentication_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            self.add_address(addr, prefix_len)
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
            if self.inspect_unsupported {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "SelfAddressTunCtl: has_address deliberately unsupported",
                ));
            }
            Ok(self.on_tun.contains(&addr))
        }
        fn add_route(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            if self.fail_add_route {
                return Err(std::io::Error::other(
                    "SelfAddressTunCtl: add_route deliberately failing",
                ));
            }
            self.routes.lock().unwrap().push((dest, prefix_len));
            Ok(())
        }
        fn route_owner_conflict(
            &self,
            _dest: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<Option<String>> {
            if self.probe_fails {
                return Err(std::io::Error::other(
                    "SelfAddressTunCtl: route_owner_conflict deliberately failing",
                ));
            }
            Ok(self.vs_route_owner.clone())
        }
    }

    /// Builds a node-mode test assembly around the given `TunCtl`, with
    /// `zpr_addr` as its configured local ZPR addresses (zipline#159).
    #[cfg(test)]
    fn assembly_with_tun_ctl(zpr_addr: &[&str], tun_ctl: Box<dyn TunCtl + Send>) -> Assembly {
        let config = config::Config {
            zpr_addr: zpr_addr.iter().map(|a| a.parse().unwrap()).collect(),
            ..Default::default()
        };
        create_assembly(TestAssemblyBuilder {
            ph_mode: Some(PhMode::Node),
            config: Some(rcu::RcuBox::new(config)),
            tun_ctl: Some(tun_ctl),
            ..Default::default()
        })
    }

    /// zipline#159: an address the TUN does not carry is applied by the
    /// node itself, exactly once, with the ZPR network prefix length.
    #[test]
    fn node_self_addressing_applies_missing_address() {
        let (tun_ctl, added, _routes) = SelfAddressTunCtl::new(&[]);
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        asm.ensure_local_zpr_addrs_on_tun().unwrap();
        assert_eq!(
            *added.lock().unwrap(),
            vec![(
                "fd5a:5052:90de::1".parse::<IpAddr>().unwrap(),
                zpr::addrs::ZPRNET_PREFIX_LEN
            )]
        );
    }

    /// zipline#159: an address already on the TUN — a hand-configured
    /// device, or the integration scripts' out-of-band `ip addr add` — is
    /// left untouched: the helper is idempotent.
    #[test]
    fn node_self_addressing_skips_present_address() {
        let (tun_ctl, added, _routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        asm.ensure_local_zpr_addrs_on_tun().unwrap();
        assert!(added.lock().unwrap().is_empty());
    }

    /// zipline#159: only the missing addresses of a partially configured
    /// set are applied.
    #[test]
    fn node_self_addressing_applies_only_missing_addresses() {
        let (tun_ctl, added, _routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        let asm = assembly_with_tun_ctl(
            &["fd5a:5052:90de::1", "fd5a:5052:90de::7"],
            Box::new(tun_ctl),
        );
        asm.ensure_local_zpr_addrs_on_tun().unwrap();
        assert_eq!(
            *added.lock().unwrap(),
            vec![(
                "fd5a:5052:90de::7".parse::<IpAddr>().unwrap(),
                zpr::addrs::ZPRNET_PREFIX_LEN
            )]
        );
    }

    /// zipline#159: an `add_address` failure (e.g. EPERM) is propagated to
    /// the caller, which exits rather than run misaddressed — as an
    /// [`SelfAddressError::Address`], so `main.rs` prints the add-address
    /// remediation (PR #61 review).
    #[test]
    fn node_self_addressing_propagates_add_address_error() {
        let (mut tun_ctl, added, _routes) = SelfAddressTunCtl::new(&[]);
        tun_ctl.fail_add_address = true;
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        let err = asm.ensure_local_zpr_addrs_on_tun().unwrap_err();
        assert!(
            matches!(err, SelfAddressError::Address { .. }),
            "an add_address failure must surface as the Address variant: {err}"
        );
        assert!(added.lock().unwrap().is_empty());
    }

    /// zipline#159: an address the platform cannot inspect is skipped, not
    /// applied and not an error — the same treatment
    /// `local_zpr_addrs_missing_from_tun` gives it.
    #[test]
    fn node_self_addressing_skips_uninspectable_address() {
        let (mut tun_ctl, added, _routes) = SelfAddressTunCtl::new(&[]);
        tun_ctl.inspect_unsupported = true;
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        asm.ensure_local_zpr_addrs_on_tun().unwrap();
        assert!(added.lock().unwrap().is_empty());
    }

    /// zipline#159: where the platform needs it (Windows, whose
    /// `netsh add address` ignores the prefix length), a /128 host route to
    /// the visa service's well-known address is installed via the TUN.
    #[test]
    fn node_self_addressing_installs_vs_host_route_where_needed() {
        let (tun_ctl, _added, routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        asm.ensure_local_zpr_addrs_on_tun_impl(true).unwrap();
        assert_eq!(
            *routes.lock().unwrap(),
            vec![(zpr::addrs::VISA_SERVICE_ADDR, 128)]
        );
    }

    /// zipline#159: where the address itself makes the ZPR internal network
    /// on-link (Linux, macOS), no route is installed — hand-configured
    /// routing is untouched.
    #[test]
    fn node_self_addressing_adds_no_route_where_address_is_onlink() {
        let (tun_ctl, _added, routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        asm.ensure_local_zpr_addrs_on_tun_impl(false).unwrap();
        assert!(routes.lock().unwrap().is_empty());
    }

    /// PR #61 review (P1): a visa-service host route already owned by
    /// another live interface — a second ZPR node or adapter on the same
    /// host — must not be stolen. The Windows `add_route` deletes every
    /// owner on another interface before adding its own, so installing
    /// ours would silently redirect the first instance's visa-service
    /// traffic and leave it routeless when we exit. The helper refuses
    /// (the node declines to start), naming the owning interface, and no
    /// route call is made.
    #[test]
    fn node_self_addressing_refuses_to_steal_vs_route() {
        let (mut tun_ctl, _added, routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        tun_ctl.vs_route_owner = Some("Ethernet 2".to_string());
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        let err = asm.ensure_local_zpr_addrs_on_tun_impl(true).unwrap_err();
        assert!(
            err.to_string().contains("Ethernet 2"),
            "the error must name the owning interface: {err}"
        );
        assert!(
            routes.lock().unwrap().is_empty(),
            "no route may be installed over another instance's"
        );
    }

    /// PR #61 review (P1), zipline#101 ruling: an ownership probe that
    /// cannot run means "unknown", not "conflict" — the route is still
    /// installed, exactly as the adapter activation path treats it.
    #[test]
    fn node_self_addressing_vs_route_probe_error_is_not_a_conflict() {
        let (mut tun_ctl, _added, routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        tun_ctl.probe_fails = true;
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        asm.ensure_local_zpr_addrs_on_tun_impl(true).unwrap();
        assert_eq!(
            *routes.lock().unwrap(),
            vec![(zpr::addrs::VISA_SERVICE_ADDR, 128)]
        );
    }

    /// PR #61 review (P2): a failure installing the visa-service route is
    /// reported as exactly that — not as an address failure, whose
    /// remediation (`netsh ... add address`) would leave the missing /128
    /// route unresolved and startup failing again.
    #[test]
    fn node_self_addressing_reports_route_failure_as_route_failure() {
        let (mut tun_ctl, _added, _routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        tun_ctl.fail_add_route = true;
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        let err = asm.ensure_local_zpr_addrs_on_tun_impl(true).unwrap_err();
        assert!(
            err.to_string().contains("visa-service"),
            "the error must identify the visa-service route, not the address: {err}"
        );
    }

    /// zipline#159: the public entry point resolves the route decision from
    /// the platform — the visa-service host route exists exactly on Windows.
    #[test]
    fn node_self_addressing_route_matches_platform() {
        let (tun_ctl, _added, routes) = SelfAddressTunCtl::new(&["fd5a:5052:90de::1"]);
        let asm = assembly_with_tun_ctl(&["fd5a:5052:90de::1"], Box::new(tun_ctl));
        asm.ensure_local_zpr_addrs_on_tun().unwrap();
        let expected = if cfg!(windows) { 1 } else { 0 };
        assert_eq!(routes.lock().unwrap().len(), expected);
    }

    impl TestAssemblyBuilder {
        #[allow(dead_code)] // unused by the `ph` bin, which compiles this module but not the fuzz harness
        pub fn new() -> Self {
            Self::default()
        }
    }

    /// Test assembly able to key an AdapterToNode link: `process_start`
    /// hands the link to the key manager, which needs a noise keypair and a
    /// certificate exchange.
    #[cfg(test)]
    fn keyable_adapter_assembly() -> Arc<Assembly> {
        let mut builder = TestAssemblyBuilder::new();
        builder.self_noise_keypair = Some(crate::km_noise::NoiseKeypair::generate());
        builder.certx = Some(crate::km_cert_exchange::KmCertExchange::new(None, None));
        Arc::new(create_assembly(builder))
    }

    #[cfg(test)]
    fn tether_addrs() -> (SubstrateAddr, ScopedIpAddr) {
        (
            SubstrateAddr::from(([127, 0, 0, 1], 9000)),
            ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2).into()),
        )
    }

    /// Graceful shutdown must tear the TUN device down after the peers are
    /// dropped (zipline#130, PR #51 review): the signal path ends in
    /// `process::exit(0)`, which skips destructors, so on Windows an
    /// unwired teardown orphans the Wintun adapter and its netsh
    /// address/route state until a later startup reaps them.
    #[tokio::test]
    async fn test_shutdown_tears_down_tun() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (tun_ctl, _routes) = RecordingTunCtl::new(false);
                let teardowns = tun_ctl.teardowns.clone();
                let mut builder = TestAssemblyBuilder::default();
                // Node mode: shutdown_node over an empty peer table
                // returns immediately (adapter mode's disconnect wait
                // assumes the local actor peer exists).
                builder.ph_mode = Some(PhMode::Node);
                builder.tun_ctl = Some(Box::new(tun_ctl));
                let asm = Arc::new(create_assembly(builder));
                asm.shutdown().await;
                assert_eq!(
                    teardowns.load(std::sync::atomic::Ordering::SeqCst),
                    1,
                    "graceful shutdown must call TunCtl::teardown exactly once"
                );
            })
            .await
    }

    /// `start_tether` with `auto_start = false` (zipline#28: adapter started
    /// with `--auto-connect=false`) must create the tether peer — so ph-cli
    /// has a link to target — but leave it Inactive: no keying, no auth
    /// attempt. The `LinkEvent::Start` that the `startLink` RPC fires must
    /// then wake it into Keying, exactly like a restarted link.
    #[tokio::test]
    async fn test_start_tether_without_auto_start_idles_until_start_event() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let asm = keyable_adapter_assembly();
                // Mirror main.rs adapter startup: local actor peer first, so
                // the tether lands at DOCK_LINK_ID.
                assert_eq!(
                    asm.peer_table.insert_internal_peer().get(),
                    zpr::packet_info::LOCAL_ACTOR_LINK_ID
                );
                let (peer_sa, if_addr) = tether_addrs();
                let dsid = asm
                    .start_tether(&peer_sa, &if_addr, LinkType::AdapterToNode, false)
                    .unwrap();
                assert_eq!(dsid.get(), zpr::packet_info::DOCK_LINK_ID);

                let peer = asm.peer_table.get(dsid.get()).unwrap();
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    crate::link_state::LinkState::Inactive,
                    "idle-mode tether must stay Inactive at startup"
                );

                // What admin_worker::start_link fires on `ph-cli connect`.
                asm.process_link_state_event(dsid.get(), LinkEvent::Start)
                    .unwrap();
                assert_eq!(
                    asm.peer_table
                        .get(dsid.get())
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    crate::link_state::LinkState::Keying,
                    "startLink must wake the idle tether"
                );
            })
            .await
    }

    /// `auto_start = true` is today's behaviour: the tether starts keying
    /// immediately.
    #[tokio::test]
    async fn test_start_tether_with_auto_start_keys_immediately() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let asm = keyable_adapter_assembly();
                let (peer_sa, if_addr) = tether_addrs();
                let dsid = asm
                    .start_tether(&peer_sa, &if_addr, LinkType::AdapterToNode, true)
                    .unwrap();
                assert_eq!(
                    asm.peer_table
                        .get(dsid.get())
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    crate::link_state::LinkState::Keying
                );
            })
            .await
    }

    /// Link keys for a test Zode named `cn`: a Noise keypair and a
    /// certificate exchange that holds a certificate for it from `ca` and
    /// trusts `ca` (zl-zipline#250).
    #[cfg(test)]
    pub fn zode_link_keys(ca: &crate::pki::TestCa, cn: &str) -> (NoiseKeypair, KmCertExchange) {
        let keypair = NoiseKeypair::generate();
        let validity =
            x509_cert::time::Validity::from_now(std::time::Duration::from_secs(3600)).unwrap();
        let certx = KmCertExchange::new(
            Some(ca.issue(cn, &keypair, validity)),
            Some(ca.cert.clone()),
        );
        (keypair, certx)
    }

    /// zl-zipline#250: a Zode with an initial link dials it at startup, as
    /// the dialer expecting the relay's CN.
    #[cfg(test)]
    #[tokio::test(start_paused = true)]
    async fn test_dial_initial_link_starts_a_dialed_zode_link() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let ca = crate::pki::TestCa::new("zode-ca");
                let (keypair, certx) = zode_link_keys(&ca, "b.zpr");
                let mut cfg = config::Config::default();
                cfg.zpr_addr = vec!["fd5a:5052::2".parse().unwrap()];
                cfg.self_addr = "127.0.0.1:0".parse().unwrap();
                cfg.initial_link =
                    Some(config::InitialLink::parse_cli("relay.zpr@127.0.0.1:7010").unwrap());
                let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                    ph_mode: Some(PhMode::Node),
                    self_noise_keypair: Some(keypair),
                    certx: Some(certx),
                    config: Some(rcu::RcuBox::new(cfg)),
                    ..TestAssemblyBuilder::new()
                }));
                asm.dial_initial_link();
                let (_, peer) = asm
                    .peer_table
                    .find(|(_, p)| p.substrate_addr == SubstrateAddr::from(([127, 0, 0, 1], 7010)))
                    .expect("the initial link was dialed");
                let fsm = &peer.link_state_machine;
                assert_eq!(fsm.get_link_type(), LinkType::NodeToNode);
                assert_eq!(fsm.get_state(), crate::link_state::LinkState::Keying);
                assert_eq!(
                    fsm.zode_end(),
                    Some(&crate::link_state::ZodeEnd::Dialer {
                        peer_cn: "relay.zpr".to_owned()
                    })
                );
            })
            .await
    }

    #[allow(dead_code)] // unused by the `ph` bin, which compiles this module but not the fuzz harness
    pub fn create_assembly(builder: TestAssemblyBuilder) -> Assembly {
        let ph_mode = builder.ph_mode.unwrap_or(PhMode::Adapter);
        let topology_config = builder.topology_config.unwrap_or_default();
        let mgmt_substrate_egress = builder
            .mgmt_substrate_egress
            .unwrap_or_else(|| MgmtSubstrateEgress::new(packet_queue::packet_queue(1).0));
        let actor_output_requeue = builder
            .actor_output_requeue
            .unwrap_or_else(|| ActorOutputRequeue::new(Vec::new()));
        let vsconn = builder.vsconn.unwrap_or(None);
        let visa_table = std::sync::RwLock::new(
            builder
                .visa_table
                .unwrap_or_else(|| visa_table::VisaTable::new()),
        );
        let capture_queue = builder.capture_queue.unwrap_or_else(|| {
            let (cq_inq, _cq_outq) = crate::queues::capture_queue(1);
            cq_inq
        });
        let capture_worker = builder
            .capture_worker
            .unwrap_or_else(|| CaptureWorker::new());
        let flow_control = builder.flow_control.unwrap_or_else(|| FlowControl::new());
        let counters = builder.counters.unwrap_or_default();
        let tun_ctl = builder.tun_ctl.unwrap_or_else(|| Box::new(DummyTunCtlImpl));
        let peer_table = builder
            .peer_table
            .unwrap_or_else(|| peer_table::PeerTable::new());
        let elt = builder
            .elt
            .unwrap_or_else(|| adapter_tables::EndpointLookupTable::new());
        let dlt = builder
            .dlt
            .unwrap_or_else(|| adapter_tables::DockLookupTable::new());
        let mgmt_dispatch_factory = builder.mgmt_dispatch_factory.unwrap_or_else(|| {
            let (md_inq_factory, _md_outq) = two_way_queue::two_way_queue(1);
            MgmtDispatchFactory::new(md_inq_factory)
        });
        let mgmt_hairpin_dispatch = builder.mgmt_hairpin_dispatch.unwrap_or_else(|| {
            let (mhd_inq, _mhd_outq) = mpsc::channel(1);
            MgmtHairpinDispatch::new(mhd_inq)
        });
        let adapter_manager_factory = builder.adapter_manager_factory.unwrap_or_else(|| {
            let (am_inq_factory, _am_outq) = two_way_queue::two_way_queue(1);
            AdapterManagerFactory::new(am_inq_factory)
        });
        let km_state = builder.km_state.unwrap_or_else(|| {
            let (km_sig_tx, _km_sig_rx) = mpsc::channel(1);
            let (km_tx, _km_rx) = mpsc::channel(1);
            KmState::new(km_tx, km_sig_tx)
        });
        let config = builder.config.unwrap_or_else(|| {
            let config = <config::Config as std::default::Default>::default();
            rcu::RcuBox::new(config)
        });
        let configured_zpr_addr_demand = config.get().zpr_addr.clone();
        let logging = builder
            .logging
            .unwrap_or_else(|| Mutex::new(HashMap::default()));
        let reload_handle = builder.reload_handle.unwrap_or_else(|| {
            let (_reload_layer, reload_handle) =
                reload::Layer::new(fmt::layer().with_filter(Targets::new()));
            reload_handle
        });

        Assembly {
            actor_rejected: std::sync::atomic::AtomicBool::new(false),
            ph_mode,
            topology_config,
            mgmt_substrate_egress,
            actor_output_requeue,
            vsconn,
            visa_table,
            topology: Default::default(),
            vs_auth_services: std::sync::RwLock::new(AuthServicesList::default()),
            deferred_vs_connect: Mutex::new(None),
            self_reauth_in_flight: std::sync::atomic::AtomicBool::new(false),
            capture_queue,
            capture_worker,
            flow_control,
            counters,
            tun_ctl,
            peer_table,
            elt,
            dlt,
            mgmt_dispatch_factory,
            mgmt_hairpin_dispatch,
            adapter_manager_factory,
            km_state,
            self_noise_keypair: builder.self_noise_keypair,
            a2a_dh_keypair: ReusableSecret::random(),
            certx: builder.certx,
            system_start_time: std::time::Instant::now(),
            address_pool: std::sync::Mutex::new(None),
            configured_zpr_addr_demand,
            config,
            fatal_error: Mutex::new(None),
            fatal_notify: tokio::sync::Notify::new(),
            logging,
            reload_handle,
        }
    }

    #[cfg(test)]
    mod drop_peer_notify {
        //! Tests for zipline#21: revoking visas for a dying link must
        //! withdraw the streams from *surviving* peers by sending them an
        //! `UnbindEgressStreamIndication`; expiry deliberately does not.

        use super::*;
        use crate::forwarding_tables::PftPep;
        use crate::packet_queue;
        use crate::peer_table::test::create_dummy_peer_state;
        use crate::visa_table::VisaTable;
        use crate::visa_table::tests::{
            ALREADY_EXPIRED, never_expires, new_vsapi_visa_tcp_default,
        };
        use crate::zdp;
        use std::net::Ipv4Addr;
        use zpr_utils::net_defs;

        /// Build a Node-mode assembly whose mgmt substrate egress queue we
        /// can read back, plus two dummy peers, and one visa (id >=
        /// MIN_VISA_ID) with forwarding entries on both links.
        ///
        /// Returns (asm, egress queue receiver, link_a, link_b, tether_a, tether_b).
        fn setup_two_link_visa() -> (
            Arc<Assembly>,
            packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
            LinkId,
            LinkId,
            StreamId,
            StreamId,
        ) {
            let (egress_tx, egress_rx) = packet_queue::packet_queue(8);

            let mut builder = TestAssemblyBuilder::new();
            builder.ph_mode = Some(PhMode::Node);
            builder.visa_table = Some(VisaTable::new());
            builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(egress_tx));
            let asm = Arc::new(create_assembly(builder));

            let entry_a = asm.peer_table.vacant_entry().unwrap();
            let key_a = entry_a.key();
            let link_a = entry_a
                .insert(create_dummy_peer_state(
                    key_a,
                    LinkType::Internal,
                    SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                    net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
                ))
                .get();

            let entry_b = asm.peer_table.vacant_entry().unwrap();
            let key_b = entry_b.key();
            let link_b = entry_b
                .insert(create_dummy_peer_state(
                    key_b,
                    LinkType::Internal,
                    SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 3, 4)), 443),
                    net_defs::ScopedIpAddr::V4(Ipv4Addr::new(2, 2, 3, 5)),
                ))
                .get();

            let visa_id = 3000;
            let mut visa_table = asm.visa_table.write().unwrap();
            let v = new_vsapi_visa_tcp_default(visa_id as u64, never_expires());
            let _ = visa_table.insert_visa(v);

            let peer_a = asm.peer_table.get(link_a).unwrap();
            let tether_a = peer_a
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link_a, 1),
                    visa_id,
                })
                .unwrap();
            visa_table
                .link_forwarding_entry(visa_id, ForwardingEntry(link_a, tether_a))
                .unwrap();

            let peer_b = asm.peer_table.get(link_b).unwrap();
            let tether_b = peer_b
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link_b, 1),
                    visa_id,
                })
                .unwrap();
            visa_table
                .link_forwarding_entry(visa_id, ForwardingEntry(link_b, tether_b))
                .unwrap();

            drop(visa_table);
            drop(peer_a);
            drop(peer_b);

            (asm, egress_rx, link_a, link_b, tether_a, tether_b)
        }

        fn try_recv_packet(
            rx: &mut packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
        ) -> Option<crate::packet::Packet> {
            let buf = vec![0u8; config::PACKET_BUFFER_SIZE].into_boxed_slice();
            match rx.try_recv(buf) {
                Ok(pkt) => Some(pkt),
                Err(packet_queue::TryRecvError::Empty(_)) => None,
                Err(err) => panic!("unexpected queue error: {err:?}"),
            }
        }

        /// Dropping a peer must send `StreamIdWithdrawal` for each withdrawn
        /// forwarding entry on a *surviving* link — naming the stream id
        /// (PFT tether id) that surviving peer sends with — and nothing for
        /// entries on the dying link itself. StreamIdWithdrawal (not
        /// UnbindEgressStreamIndication) because the id lives in the
        /// receiving adapter's *outbound* ELT, keyed by tether id, not in
        /// its inbound DLT (zipline#21).
        #[tokio::test]
        async fn test_drop_peer_sends_stream_id_withdrawal_to_surviving_peer() {
            let (asm, mut egress_rx, link_a, link_b, _tether_a, tether_b) = setup_two_link_visa();

            asm.drop_peer(link_a);

            let pkt = try_recv_packet(&mut egress_rx)
                .expect("expected a StreamIdWithdrawal for the surviving peer");
            assert_eq!(pkt.metadata().egress_link_id, link_b);

            let (base_hdr, rest) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
            let packet_type = base_hdr.packet_type;
            assert_eq!(packet_type, zdp::ZdpPacketType::StreamIdWithdrawal);

            let (_mgmt_hdr, rest) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();
            let (per_flow_hdr, _rest) = zdp::ZdpPerFlowHeader::ref_from_prefix(rest).unwrap();
            let stream_id: u32 = per_flow_hdr.stream_id.into();
            assert_eq!(stream_id, tether_b);

            // Exactly one indication: the entry on the dying link must NOT
            // produce a send (that peer is gone).
            assert!(
                try_recv_packet(&mut egress_rx).is_none(),
                "no indication may be sent for the dying link's own entry"
            );
        }

        /// VS-pushed revocation (`visa_mgmt::handle_revocation`) must send
        /// `StreamIdWithdrawal` to every peer holding a forwarding entry for
        /// the revoked visa — one per live-link entry, each naming that
        /// link's tether id — so bound peers drop their egress bindings and
        /// re-request visas instead of blackholing traffic (zipline#85).
        #[tokio::test]
        async fn test_handle_revocation_sends_stream_id_withdrawal_to_bound_peers() {
            let (asm, mut egress_rx, link_a, link_b, tether_a, tether_b) = setup_two_link_visa();

            // setup_two_link_visa inserts the visa with id 3000.
            crate::visa_mgmt::handle_revocation(&asm, 3000).unwrap();

            let mut got = Vec::new();
            while let Some(pkt) = try_recv_packet(&mut egress_rx) {
                let egress_link = pkt.metadata().egress_link_id;
                let (base_hdr, rest) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
                assert_eq!(
                    base_hdr.packet_type,
                    zdp::ZdpPacketType::StreamIdWithdrawal,
                    "only StreamIdWithdrawal may be enqueued by handle_revocation"
                );
                let (_mgmt_hdr, rest) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();
                let (per_flow_hdr, _rest) = zdp::ZdpPerFlowHeader::ref_from_prefix(rest).unwrap();
                let stream_id: u32 = per_flow_hdr.stream_id.into();
                got.push((egress_link, stream_id));
            }
            got.sort_unstable();

            let mut expected = vec![(link_a, tether_a), (link_b, tether_b)];
            expected.sort_unstable();
            assert_eq!(
                got, expected,
                "exactly one StreamIdWithdrawal per live-link forwarding entry, \
                 each naming that link's tether id"
            );
        }

        /// Visa expiry must NOT notify peers: both ends hold the same expiry
        /// and eject on their own clocks; an early-sending peer gets
        /// UnknownStreamId and re-requests, unlike the revocation case.
        #[tokio::test]
        async fn test_handle_expirations_does_not_notify_peers() {
            let (egress_tx, mut egress_rx) = packet_queue::packet_queue(8);

            let mut builder = TestAssemblyBuilder::new();
            builder.ph_mode = Some(PhMode::Node);
            builder.visa_table = Some(VisaTable::new());
            builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(egress_tx));
            let asm = Arc::new(create_assembly(builder));

            let entry = asm.peer_table.vacant_entry().unwrap();
            let key = entry.key();
            let link_id = entry
                .insert(create_dummy_peer_state(
                    key,
                    LinkType::Internal,
                    SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                    net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
                ))
                .get();

            let visa_id = 3000;
            let mut visa_table = asm.visa_table.write().unwrap();
            // Already expired
            let v = new_vsapi_visa_tcp_default(visa_id as u64, ALREADY_EXPIRED);
            let _ = visa_table.insert_visa(v);

            let peer = asm.peer_table.get(link_id).unwrap();
            let tether_id = peer
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link_id, 1),
                    visa_id,
                })
                .unwrap();
            visa_table
                .link_forwarding_entry(visa_id, ForwardingEntry(link_id, tether_id))
                .unwrap();

            visa_table.handle_expirations(&asm.peer_table);
            assert!(!visa_table.table.contains_key(&visa_id));
            assert_eq!(peer.pft.len(), 0);
            drop(visa_table);

            assert!(
                try_recv_packet(&mut egress_rx).is_none(),
                "expiry must not emit any unbind indication"
            );
        }
    }
}
