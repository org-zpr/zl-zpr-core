//! Zode links: who owns a link, and which keyed peers a Zode accepts
//! (docs/ZODE_LINKS.md rules 1-5, zl-zipline#250).
//!
//! A link between two Zodes has exactly one **owner**, the only end that
//! ever dials it (rules 1 and 2). That is what keeps a pair of Zodes at one
//! link without races or tie-breaks:
//!
//! - this Zode's configured initial link is always owned by this Zode, even
//!   when the relay also appears in the topology ("Kinds of link");
//! - a relay owns nothing and never dials (rule 4);
//! - otherwise the end with the lower ZPR address owns a topology link.
//!
//! Keyed peers are checked once their certificate CN is known, at
//! `KeyingDone` (rules 3 and 4): a dialer accepts only the CN it dialed for,
//! and an answerer accepts only a peer in its current topology that owns the
//! link. A relay's ownership rule makes every topology peer the owner, so the
//! same check covers it.
//!
//! The lifecycle of each link lives in a per-peer record
//! ([crate::zode_link_record]); this module keeps the records in a
//! [ZodeLinkTable] and drives them: it feeds them the connection events from
//! `link_state` and `setTopology`, and performs the dials, closes and timers
//! they ask for (rules 6-13).
//!
//! Contract for #251 and #252: everything tied to one connection (stream
//! bindings, bootstrap visas) hangs off that connection's peer-table entry,
//! so dropping the entry on loss clears it (rule 9). Records hold only the
//! connection's id.

use crate::assembly::Assembly;
use crate::config::Config;
use crate::link_state::{LinkEvent, LinkType, ZodeEnd};
use crate::prelude::*;
use crate::zdp::TerminateReason;
use crate::zode_link_record::{Action, Event, Kind, LinkRecord, Timer, system_jitter};
use libnode::error::VSApiError;
use std::collections::{HashMap, VecDeque};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Mutex;
use thiserror::Error;

/// The end of a Zode link that owns it: the only end that dials it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    ThisZode,
    Peer,
}

/// Why the owner of a Zode link cannot be decided. Such a link is invalid:
/// it is refused and logged, never guessed at.
#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum OwnerError {
    /// Both ends claim the same ZPR address, so neither is the lower.
    #[error("both ends have ZPR address {0}")]
    EqualAddresses(IpAddr),
    /// This Zode has no ZPR address configured (a node always has one).
    #[error("this Zode has no ZPR address")]
    NoSelfAddress,
}

/// Which end owns a link between ZPR addresses `self_addr` and `peer_addr`
/// by address order alone: the lower address. Addresses compare as 128-bit
/// unsigned integers, an IPv4 address as its IPv4-mapped IPv6 form.
pub fn owner_of(self_addr: IpAddr, peer_addr: IpAddr) -> Result<Owner, OwnerError> {
    let (ours, theirs) = (address_order_key(self_addr), address_order_key(peer_addr));
    if ours == theirs {
        return Err(OwnerError::EqualAddresses(self_addr));
    }
    Ok(if ours < theirs {
        Owner::ThisZode
    } else {
        Owner::Peer
    })
}

/// The 128-bit integer an address is ordered by (IPv4 as IPv4-mapped IPv6).
fn address_order_key(addr: IpAddr) -> u128 {
    let v6 = match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    u128::from(v6)
}

/// Who owns this Zode's link to the peer whose certificate CN is `peer_cn`
/// and whose ZPR address is `peer_addr`. The one ownership rule used
/// everywhere; see the module comment. This Zode's own address is
/// `zpr_addr[0]`, the address it authenticates with.
pub fn link_owner(config: &Config, peer_cn: &str, peer_addr: IpAddr) -> Result<Owner, OwnerError> {
    if config
        .initial_link
        .as_ref()
        .is_some_and(|link| link.cn == peer_cn)
    {
        return Ok(Owner::ThisZode);
    }
    if config.relay {
        return Ok(Owner::Peer);
    }
    let self_addr = *config.zpr_addr.first().ok_or(OwnerError::NoSelfAddress)?;
    owner_of(self_addr, peer_addr)
}

/// Why a keyed Zode link is refused. Each is logged with the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Keying produced no verified certificate CN.
    NoVerifiedCn,
    /// This Zode dialed for one CN and the peer presented another.
    WrongCn { dialed: String },
    /// The peer's CN is not in this Zode's current topology (rule 3).
    UnknownCn,
    /// The peer is in the topology, but this Zode owns the link, so the
    /// peer should not have dialed it (rule 3).
    PeerIsNotOwner,
    /// The link's owner cannot be decided.
    Owner(OwnerError),
}

impl Display for Refusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoVerifiedCn => write!(f, "no verified certificate CN"),
            Refusal::WrongCn { dialed } => write!(f, "dialed for CN {dialed:?}, got another"),
            Refusal::UnknownCn => write!(f, "unknown CN"),
            Refusal::PeerIsNotOwner => write!(f, "peer is not the owner"),
            Refusal::Owner(e) => write!(f, "invalid link: {e}"),
        }
    }
}

/// Decide whether to keep a keyed Zode link whose peer presented the
/// verified certificate CN `peer_cn`, with this Zode at `end` of the link
/// (rules 3 and 4). Runs at `KeyingDone`, when the CN is first known.
pub fn check_keyed_peer(
    asm: &Assembly,
    end: &ZodeEnd,
    peer_cn: Option<&str>,
) -> Result<(), Refusal> {
    let peer_cn = peer_cn
        .filter(|cn| !cn.is_empty())
        .ok_or(Refusal::NoVerifiedCn)?;
    match end {
        ZodeEnd::Dialer { peer_cn: dialed } if dialed == peer_cn => Ok(()),
        ZodeEnd::Dialer { peer_cn: dialed } => Err(Refusal::WrongCn {
            dialed: dialed.clone(),
        }),
        ZodeEnd::Answerer => {
            let peer_addr = asm
                .topology
                .read()
                .unwrap()
                .iter()
                .find(|link| link.peer_cn == peer_cn)
                .map(|link| link.zpr_addr)
                .ok_or(Refusal::UnknownCn)?;
            match link_owner(&asm.config.get(), peer_cn, peer_addr) {
                Ok(Owner::Peer) => Ok(()),
                Ok(Owner::ThisZode) => Err(Refusal::PeerIsNotOwner),
                Err(e) => Err(Refusal::Owner(e)),
            }
        }
    }
}

/// Rule 5: the inbound link `link_id`, just accepted from the peer with
/// certificate CN `peer_cn`, replaces every other link to that peer. Each old
/// link is dropped with all its state, and `link_id` takes over the peer's
/// substrate address if an old link held it (a same-address redial, gate g78
/// q5). Leaves exactly one link to the peer.
pub fn replace_established_links(asm: &Arc<Assembly>, link_id: LinkId, peer_cn: &str) {
    let mut replaced = Vec::new();
    asm.peer_table.for_each(|(id, peer)| {
        if id.get() != link_id
            && peer.link_state_machine.get_link_type() == LinkType::NodeToNode
            && peer.verified_peer_cn().as_deref() == Some(peer_cn)
        {
            replaced.push(id.get());
        }
    });
    // A same-address handshake accepted for another peer displaces the link
    // that held the address: it goes too, rather than staying Active while
    // its packets reach this link.
    let displaced = asm
        .peer_table
        .inspect(link_id, |p| (p.substrate_addr, p.interface_addr))
        .and_then(|(sa, iface)| asm.peer_table.lookup_peer(&sa, &iface))
        .map(|id| id.get())
        .filter(|id| *id != link_id && !replaced.contains(id));
    replaced.extend(displaced);
    for old in replaced {
        info!(target: LINK_STATE, "{} replaces {} to peer CN {peer_cn:?}; dropping the old link",
            asm.formatted_link_id(link_id), asm.formatted_link_id(old));
        if let Some(peer) = asm.peer_table.get(old) {
            peer.link_state_machine.drop_replaced(asm);
        }
    }
    asm.peer_table.map_substrate_addr(link_id);
}

/// This Zode's link records, one per peer certificate CN: its initial link
/// and every link in its current topology.
#[derive(Default)]
pub struct ZodeLinkTable {
    inner: Mutex<TableInner>,
    /// Set when the link-state report must be sent again; see
    /// [run_link_state_reporter].
    report_pending: std::sync::atomic::AtomicBool,
    /// Wakes the reporter after [ZodeLinkTable::request_report].
    report_wakeup: tokio::sync::Notify,
}

#[derive(Default)]
struct TableInner {
    /// Records by peer CN, each with the serial it was inserted under.
    records: HashMap<String, (u64, LinkRecord)>,
    /// The next record serial. A timer carries its record's serial, so a
    /// timer armed for a record that was since removed and re-added is
    /// ignored.
    next_serial: u64,
}

impl ZodeLinkTable {
    /// A copy of the record for `peer_cn`, if there is one.
    pub fn record(&self, peer_cn: &str) -> Option<LinkRecord> {
        let inner = self.inner.lock().unwrap();
        inner.records.get(peer_cn).map(|(_, r)| r.clone())
    }

    /// Ask for a fresh link-state report: a reported state changed, or the
    /// VS-API session (re)connected. Bursts of requests coalesce into one
    /// send.
    pub fn request_report(&self) {
        self.report_pending
            .store(true, std::sync::atomic::Ordering::Release);
        self.report_wakeup.notify_one();
    }

    /// Whether a report has been asked for and not yet sent.
    #[cfg(test)]
    pub fn report_pending(&self) -> bool {
        self.report_pending
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// This Zode's link-state snapshot for `reportLinkStates`, by peer CN:
    /// every link that has an outcome ("Reporting summary"). A link still
    /// in its first window, a non-owner's link that was never up, and an
    /// initial link that was never up have none and are not listed; a link
    /// removed from the topology has no record. `failed` is listed only
    /// while the owner's record is Failed ("Reporting contract").
    pub fn snapshot(&self) -> Vec<zpr::vsapi_types::LinkStateReport> {
        use crate::zode_link_record::Outcome;
        use zpr::vsapi_types::{LinkState, LinkStateReport};
        let inner = self.inner.lock().unwrap();
        let mut reports: Vec<LinkStateReport> = inner
            .records
            .iter()
            .filter_map(|(cn, (_, record))| {
                let state = match record.outcome? {
                    Outcome::Up => LinkState::Up,
                    Outcome::Down => LinkState::Down,
                    Outcome::Failed => LinkState::Failed,
                };
                Some(LinkStateReport {
                    peer_cn: cn.clone(),
                    state,
                })
            })
            .collect();
        reports.sort_by(|a, b| a.peer_cn.cmp(&b.peer_cn));
        reports
    }

    /// Insert `record` for `peer_cn`, replacing any older one.
    fn insert(&self, peer_cn: &str, record: LinkRecord) {
        let mut inner = self.inner.lock().unwrap();
        inner.next_serial += 1;
        let serial = inner.next_serial;
        inner.records.insert(peer_cn.to_owned(), (serial, record));
    }

    /// Test-only: put a topology record for `peer_cn` in `state`, served by
    /// connection `link_id`, without walking the lifecycle.
    #[cfg(test)]
    pub fn test_put(
        &self,
        peer_cn: &str,
        state: crate::zode_link_record::RecordState,
        link_id: Option<LinkId>,
    ) {
        let dial_addr = SocketAddr::from(([127, 0, 0, 9], 5000));
        let mut record = LinkRecord::new(Kind::Topology, Owner::Peer, dial_addr, system_jitter);
        record.state = state;
        record.link_id = link_id;
        self.insert(peer_cn, record);
    }

    /// The CN of the record whose current connection is `link_id`.
    fn peer_cn_of_link(&self, link_id: LinkId) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner
            .records
            .iter()
            .find(|(_, (_, r))| r.link_id == Some(link_id))
            .map(|(cn, _)| cn.clone())
    }

    /// Feed `event` to the record for `peer_cn`. `serial`, if given, must be
    /// the record's (a timer's check). Returns the record's actions, its
    /// serial and its dial address; `None` if there is no such record.
    fn feed(
        &self,
        peer_cn: &str,
        serial: Option<u64>,
        event: Event,
    ) -> Option<(Vec<Action>, u64, SocketAddr)> {
        let mut inner = self.inner.lock().unwrap();
        let (record_serial, record) = inner.records.get_mut(peer_cn)?;
        if serial.is_some_and(|s| s != *record_serial) {
            return None;
        }
        let now = tokio::time::Instant::now().into_std();
        let before = record.outcome;
        let actions = record.handle(event, now);
        let (serial, dial_addr, changed) =
            (*record_serial, record.dial_addr, record.outcome != before);
        drop(inner);
        if changed {
            self.request_report();
        }
        Some((actions, serial, dial_addr))
    }
}

/// Feed `event` to the record for `peer_cn` and perform what it asks, until
/// nothing is left. The table lock is never held while acting, because a
/// dial or close re-enters this module (a failed start drops a peer).
fn drive(asm: &Arc<Assembly>, peer_cn: &str, serial: Option<u64>, event: Event) {
    let mut pending = VecDeque::from([event]);
    let mut serial = serial;
    while let Some(event) = pending.pop_front() {
        let Some((actions, record_serial, dial_addr)) = asm.zode_links.feed(peer_cn, serial, event)
        else {
            return;
        };
        serial = Some(record_serial);
        for action in actions {
            match action {
                Action::Dial => pending.push_back(match dial(asm, peer_cn, dial_addr) {
                    Some(link_id) => Event::Dialed(link_id),
                    None => Event::DialFailed,
                }),
                Action::Close(link_id) => close_link(asm, link_id, "the link-up window ended"),
                Action::Arm {
                    timer,
                    after,
                    clock,
                } => arm(asm, peer_cn, record_serial, timer, after, clock),
            }
        }
    }
}

/// Dial the peer `peer_cn` at `dial_addr` as the owner. Returns the new
/// connection, or `None` (logged) if no attempt could start.
fn dial(asm: &Arc<Assembly>, peer_cn: &str, dial_addr: SocketAddr) -> Option<LinkId> {
    let interface_addr =
        match crate::assembly::dial_interface(asm.config.get().self_addr, dial_addr) {
            Ok(interface_addr) => interface_addr,
            Err(e) => {
                warn!(target: LINK_STATE, "cannot route to Zode {peer_cn:?} at {dial_addr}: {e}");
                return None;
            }
        };
    // One connection per substrate address: an older connection there (one
    // still closing) must go first. The record retries.
    if let Some(other) = asm.peer_table.lookup_peer(&dial_addr, &interface_addr) {
        warn!(target: LINK_STATE, "not dialing Zode {peer_cn:?} at {dial_addr}: {} still holds the address", asm.formatted_link_id(other.get()));
        return None;
    }
    let end = ZodeEnd::Dialer {
        peer_cn: peer_cn.to_owned(),
    };
    match asm.start_zode_link(&dial_addr, &interface_addr, end) {
        Ok(link_id) => Some(link_id.get()),
        Err(e) => {
            warn!(target: LINK_STATE, "cannot dial Zode {peer_cn:?} at {dial_addr}: {e}");
            None
        }
    }
}

/// Close the connection `link_id`, logging `why`.
fn close_link(asm: &Arc<Assembly>, link_id: LinkId, why: &str) {
    info!(target: LINK_STATE, "closing {}: {why}", asm.formatted_link_id(link_id));
    if let Err(e) = asm.process_link_state_event(link_id, LinkEvent::Close(TerminateReason::Reset))
    {
        debug!(target: LINK_STATE, "close of {} not needed: {e}", asm.formatted_link_id(link_id));
    }
}

/// Fire `timer` for the record `peer_cn` (serial `serial`) after `after`.
fn arm(
    asm: &Arc<Assembly>,
    peer_cn: &str,
    serial: u64,
    timer: Timer,
    after: std::time::Duration,
    clock: u64,
) {
    let asm = asm.clone();
    let peer_cn = peer_cn.to_owned();
    tokio::task::spawn_local(async move {
        tokio::time::sleep(after).await;
        drive(&asm, &peer_cn, Some(serial), Event::Timer { timer, clock });
    });
}

/// Start this Zode's initial link, if it has one (rule 11): create its
/// record and dial. Called once at startup; the record redials from then on.
pub fn start_initial_link(asm: &Arc<Assembly>) {
    let Some(link) = asm.config.get().initial_link.clone() else {
        return;
    };
    info!(target: LINK_STATE, "dialing initial link {:?} at {}", link.cn, link.addr);
    asm.zode_links.insert(
        &link.cn,
        LinkRecord::new(Kind::Initial, Owner::ThisZode, link.addr, system_jitter),
    );
    drive(asm, &link.cn, None, Event::Start);
}

/// Apply the topology just stored in `asm.topology` (rules 12 and 13):
///
/// - a link that left it is closed and its record forgotten;
/// - every link in it is started: the owner dials a new, failed or down
///   link once more (rule 6), an up link is left alone, and the non-owner
///   waits;
/// - a link whose owner cannot be decided (equal addresses) is logged and
///   skipped, and the rest is applied;
/// - the initial link's record is never touched: when the relay is also in
///   the topology, the initial-link rule wins.
///
/// Connections this Zode answered that the acceptance rules now refuse are
/// closed too ([close_refused_zode_links]).
pub fn apply_topology(asm: &Arc<Assembly>) {
    let config = asm.config.get();
    let initial_cn = config.initial_link.as_ref().map(|link| link.cn.clone());
    let mut wanted: HashMap<String, (Owner, SocketAddr)> = HashMap::new();
    for link in asm.topology.read().unwrap().iter() {
        if Some(&link.peer_cn) == initial_cn.as_ref() {
            continue;
        }
        match link_owner(&config, &link.peer_cn, link.zpr_addr) {
            Ok(owner) => {
                let dial_addr = SocketAddr::new(link.peer.addr, link.peer.port);
                wanted.insert(link.peer_cn.clone(), (owner, dial_addr));
            }
            Err(e) => {
                warn!(target: LINK_STATE, "skipping topology link {} to {:?}: {e}", link.link_id, link.peer_cn);
            }
        }
    }

    let mut closes = Vec::new();
    // Whether a forgotten record was listed in the report: if so, the next
    // snapshot leaves it out (rule 12) and must be sent.
    let mut unlisted = false;
    {
        let mut inner = asm.zode_links.inner.lock().unwrap();
        // Rule 12: forget topology links that left the topology. A record
        // whose owner changed is replaced, which is the same thing.
        inner.records.retain(|cn, (_, record)| {
            let keep = record.kind == Kind::Initial
                || wanted
                    .get(cn)
                    .is_some_and(|(owner, _)| *owner == record.owner);
            if !keep {
                info!(target: LINK_STATE, "Zode link to {cn:?} left the topology; forgetting it");
                closes.extend(record.link_id);
                unlisted |= record.outcome.is_some();
            }
            keep
        });
        for (cn, (_, dial_addr)) in &wanted {
            if let Some((_, record)) = inner.records.get_mut(cn) {
                record.dial_addr = *dial_addr;
            }
        }
    }
    if unlisted {
        asm.zode_links.request_report();
    }
    for link_id in closes {
        close_link(asm, link_id, "its peer left the topology");
    }
    for (cn, (owner, dial_addr)) in wanted {
        if asm.zode_links.record(&cn).is_none() {
            asm.zode_links.insert(
                &cn,
                LinkRecord::new(Kind::Topology, owner, dial_addr, system_jitter),
            );
        }
        drive(asm, &cn, None, Event::Start);
    }
    close_refused_zode_links(asm);

    if let Some(cn) = initial_link_missing_from_topology(&config, &asm.topology.read().unwrap()) {
        warn!(target: LINK_STATE,
            "the topology has no entry for the initial link's CN {cn:?}: F1 cannot reach the relay through it; the policy must peer this Zode with its relay");
    }
}

/// The CN of this Zode's initial link if `topology` has no entry for it,
/// else `None` (also when there is no initial link). F1 (zl-zipline#251)
/// finds the relay as an egress only through its topology entry, so a
/// missing one means nothing can be forwarded to the relay. That is a
/// policy error, which `apply_topology` only logs: there is no fallback.
fn initial_link_missing_from_topology<'c>(
    config: &'c Config,
    topology: &[zpr::vsapi_types::Link],
) -> Option<&'c str> {
    let cn = config.initial_link.as_ref()?.cn.as_str();
    (!topology.iter().any(|link| link.peer_cn == cn)).then_some(cn)
}

/// How long the reporter waits after the first report request before it
/// sends, so a burst of link changes goes out as one snapshot.
pub const REPORT_COALESCE: std::time::Duration = std::time::Duration::from_millis(100);

/// The most snapshots the reporter queues behind a send that is still in
/// flight. Past it, the newest snapshot replaces the last queued one.
pub const REPORT_QUEUE_MAX: usize = 32;

/// Send this Zode's link-state snapshot whenever one is asked for
/// ([ZodeLinkTable::request_report]), with `send` (in production,
/// `VSConnHandle::report_link_states`). Requests within [REPORT_COALESCE] of
/// each other coalesce into one snapshot. Runs for the life of the node.
///
/// Taking snapshots and sending them are two loops joined by a queue, so a
/// send that waits on the visa service (up to the RPC timeout) never merges
/// the snapshots taken meanwhile: each one is sent, in order. That matters
/// for the visa service's "new failure" rule (ZODE_LINKS.md "Reporting
/// contract"): failed -> retry (not listed) -> failed must arrive as three
/// snapshots, not two `failed` ones. A failed send is logged; the next change
/// or VS-API registration asks for a fresh snapshot.
pub async fn run_link_state_reporter<F, Fut>(asm: Arc<Assembly>, send: F)
where
    F: Fn(Vec<zpr::vsapi_types::LinkStateReport>) -> Fut,
    Fut: std::future::Future<Output = Result<(), VSApiError>>,
{
    // Both loops run on this one task (`join!` below), so a RefCell is
    // enough. `queued` wakes the sender; a wake-up sent while it is busy is
    // kept as a permit, so none is lost.
    let queue = std::cell::RefCell::new(VecDeque::new());
    let queued = tokio::sync::Notify::new();

    let take_snapshots = async {
        loop {
            asm.zode_links.report_wakeup.notified().await;
            tokio::time::sleep(REPORT_COALESCE).await;
            if asm
                .zode_links
                .report_pending
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                let snapshot = asm.zode_links.snapshot();
                let mut queue = queue.borrow_mut();
                // ponytail: a stall longer than REPORT_QUEUE_MAX snapshots
                // merges the newest changes into the last queued snapshot,
                // so transitions inside that tail can be lost. Bounded
                // memory wins over that corner; each send is bounded by the
                // RPC timeout, so only a long run of stalls gets there.
                if queue.len() >= REPORT_QUEUE_MAX {
                    queue.pop_back();
                }
                queue.push_back(snapshot);
                drop(queue);
                queued.notify_one();
            }
        }
    };

    let send_snapshots = async {
        loop {
            // Take the next snapshot without holding the borrow across the
            // await below.
            let next = queue.borrow_mut().pop_front();
            let Some(snapshot) = next else {
                queued.notified().await;
                continue;
            };
            let summary: Vec<String> = snapshot
                .iter()
                .map(|r| format!("{}={:?}", r.peer_cn, r.state))
                .collect();
            match send(snapshot).await {
                Ok(()) => {
                    info!(target: LINK_STATE, "reported Zode link states to the visa service: [{}]", summary.join(", "))
                }
                // No VS-API session (always the case on a Zode other than the
                // visa service's own until zl-zipline#252): VSConn refuses the
                // call locally, so nothing goes on the wire. The session's
                // (re)connect asks for a fresh report.
                Err(e @ (VSApiError::ConnClosed | VSApiError::CommandFailed(_))) => {
                    debug!(target: LINK_STATE, "link-state report not sent, no VS-API session: {e}")
                }
                // The call reached the visa service and failed: worth a
                // warning. The next change or reconnect sends a fresh snapshot.
                Err(e) => warn!(target: LINK_STATE, "link-state report failed: {e}"),
            }
        }
    };

    tokio::join!(take_snapshots, send_snapshots);
}

/// The Zode connection `link_id` went Active with its peer's CN verified
/// (rules 7 and 8).
pub fn link_up(asm: &Arc<Assembly>, link_id: LinkId) {
    let Some(peer_cn) = asm
        .peer_table
        .get(link_id)
        .and_then(|p| p.verified_peer_cn())
    else {
        return;
    };
    drive(asm, &peer_cn, None, Event::Up(link_id));
}

/// The Zode connection `link_id` closed and its peer entry was dropped
/// (rules 9-11). Its record, if it still tracks it, goes down, fails or
/// redials.
pub fn link_dropped(asm: &Arc<Assembly>, link_id: LinkId) {
    if let Some(peer_cn) = asm.zode_links.peer_cn_of_link(link_id) {
        drive(asm, &peer_cn, None, Event::Closed(link_id));
    }
}

/// Close every Zode connection this Zode answered that the acceptance rules
/// would now refuse (rule 3), for example because its peer left the
/// topology. Connections this Zode dialed are closed through their records.
pub fn close_refused_zode_links(asm: &Arc<Assembly>) {
    let mut to_close = Vec::new();
    asm.peer_table.for_each(|(link_id, peer)| {
        let fsm = &peer.link_state_machine;
        let keyed = fsm.get_link_type() == LinkType::NodeToNode
            && matches!(
                fsm.get_state(),
                crate::link_state::LinkState::Helloing | crate::link_state::LinkState::Active
            );
        if keyed
            && fsm.zode_end() == Some(&ZodeEnd::Answerer)
            && check_keyed_peer(asm, &ZodeEnd::Answerer, peer.verified_peer_cn().as_deref())
                .is_err()
        {
            to_close.push(link_id.get());
        }
    });
    for link_id in to_close {
        close_link(asm, link_id, "the acceptance rules now refuse its peer");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::config::InitialLink;
    use crate::peer_table::test::topology_link_at;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The lower address owns: IPv6 against IPv6, IPv4 against IPv4, and
    /// IPv4 (as IPv4-mapped IPv6, `::ffff:a.b.c.d`) against IPv6. Equal
    /// addresses decide nothing.
    #[test]
    fn test_owner_of() {
        assert_eq!(owner_of(ip("fd5a::1"), ip("fd5a::2")), Ok(Owner::ThisZode));
        assert_eq!(owner_of(ip("fd5a::2"), ip("fd5a::1")), Ok(Owner::Peer));
        assert_eq!(
            owner_of(ip("10.0.0.1"), ip("10.0.0.2")),
            Ok(Owner::ThisZode)
        );
        assert_eq!(owner_of(ip("10.0.0.2"), ip("10.0.0.1")), Ok(Owner::Peer));
        // ::ffff:10.0.0.1 is below fd5a::1 and above ::1.
        assert_eq!(owner_of(ip("10.0.0.1"), ip("fd5a::1")), Ok(Owner::ThisZode));
        assert_eq!(owner_of(ip("10.0.0.1"), ip("::1")), Ok(Owner::Peer));
        assert_eq!(
            owner_of(ip("10.0.0.1"), ip("::ffff:10.0.0.1")),
            Err(OwnerError::EqualAddresses(ip("10.0.0.1")))
        );
        assert_eq!(
            owner_of(ip("fd5a::1"), ip("fd5a::1")),
            Err(OwnerError::EqualAddresses(ip("fd5a::1")))
        );
    }

    /// A Zode config with ZPR address `self_addr`.
    fn zode_config(self_addr: &str) -> Config {
        Config {
            zpr_addr: vec![ip(self_addr)],
            ..Config::default()
        }
    }

    /// F1 (zl-zipline#251): an endpoint whose topology lacks its initial
    /// link's CN cannot reach its relay, so `apply_topology` warns. The check
    /// names the missing CN; with the CN present, or with no initial link,
    /// there is nothing to warn about.
    #[test]
    fn test_initial_link_missing_from_topology() {
        let mut config = zode_config("fd5a::5");
        let relay_entry = [topology_link_at("relay", ip("fd5a::1"))];
        let other_entry = [topology_link_at("b", ip("fd5a::9"))];
        assert_eq!(
            initial_link_missing_from_topology(&config, &other_entry),
            None
        );

        config.initial_link = Some(InitialLink::parse_cli("relay@10.0.0.9:5000").unwrap());
        assert_eq!(
            initial_link_missing_from_topology(&config, &other_entry),
            Some("relay")
        );
        assert_eq!(
            initial_link_missing_from_topology(&config, &[]),
            Some("relay")
        );
        assert_eq!(
            initial_link_missing_from_topology(&config, &relay_entry),
            None
        );
    }

    /// The ownership matrix: the initial link wins over address order, a
    /// relay owns nothing, and otherwise the lower address owns.
    #[test]
    fn test_link_owner() {
        let config = zode_config("fd5a::5");
        assert_eq!(link_owner(&config, "b", ip("fd5a::9")), Ok(Owner::ThisZode));
        assert_eq!(link_owner(&config, "b", ip("fd5a::1")), Ok(Owner::Peer));
        assert_eq!(
            link_owner(&config, "b", ip("fd5a::5")),
            Err(OwnerError::EqualAddresses(ip("fd5a::5")))
        );

        // The initial link's relay sits at a lower address, and is in the
        // topology too: this Zode still owns the link to it.
        let mut config = zode_config("fd5a::5");
        config.initial_link = Some(InitialLink::parse_cli("relay@10.0.0.9:5000").unwrap());
        assert_eq!(
            link_owner(&config, "relay", ip("fd5a::1")),
            Ok(Owner::ThisZode)
        );
        assert_eq!(link_owner(&config, "b", ip("fd5a::1")), Ok(Owner::Peer));

        // A relay owns nothing, whatever the address order.
        let mut config = zode_config("fd5a::1");
        config.relay = true;
        assert_eq!(link_owner(&config, "b", ip("fd5a::9")), Ok(Owner::Peer));

        assert_eq!(
            link_owner(&Config::default(), "b", ip("fd5a::9")),
            Err(OwnerError::NoSelfAddress)
        );
    }

    /// A Zode assembly with `config` and a topology of (CN, ZPR address)
    /// links.
    fn zode(config: Config, topology: &[(&str, &str)]) -> Assembly {
        let asm = create_assembly(TestAssemblyBuilder {
            ph_mode: Some(crate::assembly::PhMode::Node),
            config: Some(rcu::RcuBox::new(config)),
            ..TestAssemblyBuilder::new()
        });
        *asm.topology.write().unwrap() = topology
            .iter()
            .map(|(cn, addr)| topology_link_at(cn, ip(addr)))
            .collect();
        asm
    }

    /// The KeyingDone matrix for an answering Zode at fd5a::5 (rule 3).
    #[test]
    fn test_check_keyed_peer_answerer() {
        let asm = zode(
            zode_config("fd5a::5"),
            &[
                ("lower", "fd5a::1"),
                ("higher", "fd5a::9"),
                ("same", "fd5a::5"),
            ],
        );
        let answer = |cn| check_keyed_peer(&asm, &ZodeEnd::Answerer, cn);
        assert_eq!(answer(Some("lower")), Ok(()), "the peer owns the link");
        assert_eq!(answer(Some("higher")), Err(Refusal::PeerIsNotOwner));
        assert_eq!(answer(Some("stranger")), Err(Refusal::UnknownCn));
        assert_eq!(
            answer(Some("same")),
            Err(Refusal::Owner(OwnerError::EqualAddresses(ip("fd5a::5"))))
        );
        assert_eq!(answer(None), Err(Refusal::NoVerifiedCn));
        assert_eq!(answer(Some("")), Err(Refusal::NoVerifiedCn));
    }

    /// A relay accepts any peer in its topology, whatever the address
    /// order, and nothing else (rule 4).
    #[test]
    fn test_check_keyed_peer_relay() {
        let mut config = zode_config("fd5a::1");
        config.relay = true;
        let asm = zode(config, &[("b", "fd5a::9")]);
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("b")),
            Ok(())
        );
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("c")),
            Err(Refusal::UnknownCn)
        );
    }

    /// An endpoint owns its initial link, so a dial from its relay is
    /// refused, whether or not the relay is also in its topology.
    #[test]
    fn test_check_keyed_peer_endpoint_refuses_its_relay() {
        let mut config = zode_config("fd5a::9");
        config.initial_link = Some(InitialLink::parse_cli("relay@10.0.0.9:5000").unwrap());
        let asm = zode(config.clone(), &[("relay", "fd5a::1")]);
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("relay")),
            Err(Refusal::PeerIsNotOwner)
        );
        let asm = zode(config, &[]);
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("relay")),
            Err(Refusal::UnknownCn)
        );
    }

    /// A dialer accepts exactly the CN it dialed for, topology or not.
    #[test]
    fn test_check_keyed_peer_dialer() {
        let asm = zode(zode_config("fd5a::5"), &[]);
        let dialer = ZodeEnd::Dialer {
            peer_cn: "relay".to_owned(),
        };
        assert_eq!(check_keyed_peer(&asm, &dialer, Some("relay")), Ok(()));
        assert_eq!(
            check_keyed_peer(&asm, &dialer, Some("other")),
            Err(Refusal::WrongCn {
                dialed: "relay".to_owned()
            })
        );
        assert_eq!(
            check_keyed_peer(&asm, &dialer, None),
            Err(Refusal::NoVerifiedCn)
        );
    }

    // ---- the driver: records, connections and setTopology (rules 6-13) ----

    use crate::link_state::LinkState;
    use crate::zode_link_record::{Outcome, RecordState};
    use std::time::Duration;
    use tokio::task::LocalSet;

    /// The substrate egress queue a driver test keeps open.
    type EgressRx = crate::packet_queue::Receiver<{ crate::config::PACKET_BUFFER_SIZE }>;

    /// A Zode named `self_cn` at ZPR address `self_addr`, bound to
    /// 127.0.0.1, with CA-signed link keys. `initial_link`, if given, is
    /// its initial link.
    fn driven_zode(
        self_addr: &str,
        self_cn: &str,
        initial_link: Option<&str>,
    ) -> (Arc<Assembly>, EgressRx) {
        let (egress_tx, egress_rx) = crate::packet_queue::packet_queue(256);
        let ca = crate::pki::TestCa::new("zode-ca");
        let (keypair, certx) = crate::assembly::test::zode_link_keys(&ca, self_cn);
        let mut config = zode_config(self_addr);
        config.self_addr = "127.0.0.1:0".parse().unwrap();
        config.initial_link = initial_link.map(|spec| InitialLink::parse_cli(spec).unwrap());
        let asm = Arc::new(create_assembly(TestAssemblyBuilder {
            ph_mode: Some(crate::assembly::PhMode::Node),
            self_noise_keypair: Some(keypair),
            certx: Some(certx),
            config: Some(rcu::RcuBox::new(config)),
            mgmt_substrate_egress: Some(crate::queues::MgmtSubstrateEgress::new(egress_tx)),
            ..TestAssemblyBuilder::new()
        }));
        (asm, egress_rx)
    }

    /// A topology link to `cn` at ZPR address `addr`, dialed at
    /// 127.0.0.1:`port`.
    fn peer(cn: &str, addr: &str, port: u16) -> zpr::vsapi_types::Link {
        let mut link = topology_link_at(cn, ip(addr));
        link.peer = zpr::vsapi_types::SockAddr {
            addr: ip("127.0.0.1"),
            port,
        };
        link
    }

    /// Store `links` as the topology and apply it, as `setTopology` does.
    fn set_topology(asm: &Arc<Assembly>, links: Vec<zpr::vsapi_types::Link>) {
        *asm.topology.write().unwrap() = links;
        apply_topology(asm);
    }

    /// The Zode connections in the peer table.
    fn zode_connections(asm: &Arc<Assembly>) -> Vec<LinkId> {
        let mut ids = Vec::new();
        asm.peer_table.for_each(|(id, p)| {
            if p.link_state_machine.get_link_type() == LinkType::NodeToNode {
                ids.push(id.get());
            }
        });
        ids
    }

    /// Bring the Zode connection `link_id` up as if keying verified `cn`
    /// and Hello completed.
    fn bring_up(asm: &Arc<Assembly>, link_id: LinkId, cn: &str) {
        crate::peer_table::test::set_verified_peer_cn(asm, link_id, cn);
        asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
            .unwrap();
        let dialer = asm
            .peer_table
            .get(link_id)
            .unwrap()
            .link_state_machine
            .is_zode_dialer();
        let hello = if dialer {
            LinkEvent::ReceivedHelloResponse {
                status: crate::zdp::ResponseCode::Success,
                aaa_address: None,
                oidc_idps: None,
                vs_bootstrap: false,
            }
        } else {
            LinkEvent::ReceivedHelloRequest
        };
        asm.process_link_state_event(link_id, hello).unwrap();
        assert_eq!(
            asm.peer_table
                .get(link_id)
                .unwrap()
                .link_state_machine
                .get_state(),
            LinkState::Active
        );
    }

    /// An inbound connection from `cn`, keyed and up, on a fresh port.
    fn answered_up(asm: &Arc<Assembly>, cn: &str, port: u16) -> LinkId {
        let iface = zpr_utils::net_defs::ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let id = asm
            .start_zode_link(
                &SubstrateAddr::from(([127, 0, 0, 1], port)),
                &iface,
                ZodeEnd::Answerer,
            )
            .unwrap()
            .get();
        bring_up(asm, id, cn);
        id
    }

    /// Let spawned work (cleanup, timers due now) run.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    /// The record for `cn`.
    fn record_of(asm: &Arc<Assembly>, cn: &str) -> LinkRecord {
        asm.zode_links.record(cn).expect("a record")
    }

    /// Rules 1 and 6: a new topology link this Zode owns is dialed once,
    /// as the dialer for the peer's CN.
    #[tokio::test(start_paused = true)]
    async fn test_owner_dials_a_new_topology_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                set_topology(&asm, vec![peer("b", "fd5a::20", 7101)]);
                let record = record_of(&asm, "b");
                assert_eq!(record.owner, Owner::ThisZode);
                assert!(matches!(record.state, RecordState::Dialing { .. }));
                let link_id = record.link_id.unwrap();
                assert_eq!(zode_connections(&asm), vec![link_id]);
                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(
                    peer.substrate_addr,
                    SubstrateAddr::from(([127, 0, 0, 1], 7101))
                );
                assert_eq!(
                    peer.link_state_machine.zode_end(),
                    Some(&ZodeEnd::Dialer {
                        peer_cn: "b".to_owned()
                    })
                );
            })
            .await
    }

    /// Rules 2 and 8: the non-owner never dials; it goes up when the
    /// owner's connection is accepted, and is never failed.
    #[tokio::test(start_paused = true)]
    async fn test_non_owner_waits_and_goes_up_on_accept() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                set_topology(&asm, vec![peer("b", "fd5a::9", 7102)]);
                assert_eq!(record_of(&asm, "b").state, RecordState::Idle);
                assert!(zode_connections(&asm).is_empty());
                tokio::time::sleep(Duration::from_secs(30)).await;
                assert!(
                    zode_connections(&asm).is_empty(),
                    "the non-owner never dials"
                );
                assert_eq!(record_of(&asm, "b").outcome, None);

                let link_id = answered_up(&asm, "b", 7202);
                let record = record_of(&asm, "b");
                assert_eq!(record.state, RecordState::Up);
                assert_eq!(record.link_id, Some(link_id));
            })
            .await
    }

    /// Rules 6 and 7: the owner's connection goes Active, so the link is up.
    #[tokio::test(start_paused = true)]
    async fn test_owner_link_goes_up() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                set_topology(&asm, vec![peer("b", "fd5a::20", 7103)]);
                let link_id = record_of(&asm, "b").link_id.unwrap();
                bring_up(&asm, link_id, "b");
                assert_eq!(record_of(&asm, "b").state, RecordState::Up);
                assert_eq!(record_of(&asm, "b").outcome, Some(Outcome::Up));
            })
            .await
    }

    /// Rule 6: a link that never comes up is redialed about once a second
    /// inside the window, then reported failed with nothing left behind,
    /// and nothing dials it again.
    #[tokio::test(start_paused = true)]
    async fn test_owner_link_fails_after_the_window() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                set_topology(&asm, vec![peer("b", "fd5a::20", 7104)]);
                let first = record_of(&asm, "b").link_id.unwrap();
                // The first attempt times out keying (2 s) and closes; the
                // owner redials inside the window.
                tokio::time::sleep(Duration::from_millis(4200)).await;
                let redialed = record_of(&asm, "b").link_id;
                assert!(
                    redialed.is_some_and(|id| id != first),
                    "redialed inside the window"
                );
                tokio::time::sleep(Duration::from_millis(1000)).await;
                let record = record_of(&asm, "b");
                assert_eq!(record.state, RecordState::Failed);
                assert_eq!(record.outcome, Some(Outcome::Failed));
                assert_eq!(record.link_id, None);
                tokio::time::sleep(Duration::from_secs(5)).await;
                assert!(
                    zode_connections(&asm).is_empty(),
                    "the aborted attempt is gone"
                );
                tokio::time::sleep(Duration::from_secs(60)).await;
                assert!(
                    zode_connections(&asm).is_empty(),
                    "nothing redials a failed link"
                );
            })
            .await
    }

    /// Rules 9 and 10: losing an up topology link takes it down on the
    /// owner and on the non-owner. Nothing redials, and nothing references
    /// the lost connection: not the peer table, not key management, not the
    /// record.
    #[tokio::test(start_paused = true)]
    async fn test_lost_topology_link_goes_down_on_both_ends() {
        LocalSet::new()
            .run_until(async {
                let (owner, _e1) = driven_zode("fd5a::10", "a", None);
                set_topology(&owner, vec![peer("b", "fd5a::20", 7105)]);
                let dialed = record_of(&owner, "b").link_id.unwrap();
                bring_up(&owner, dialed, "b");

                let (non_owner, _e2) = driven_zode("fd5a::20", "b", None);
                set_topology(&non_owner, vec![peer("a", "fd5a::10", 7205)]);
                let answered = answered_up(&non_owner, "a", 7305);

                let ends = [(&owner, "b", dialed), (&non_owner, "a", answered)];
                for (asm, _, link_id) in ends {
                    asm.process_link_state_event(link_id, LinkEvent::Close(TerminateReason::Reset))
                        .unwrap();
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                for (asm, cn, link_id) in ends {
                    let record = record_of(asm, cn);
                    assert_eq!(record.state, RecordState::Down);
                    assert_eq!(record.outcome, Some(Outcome::Down));
                    assert_eq!(record.link_id, None);
                    assert!(asm.peer_table.get(link_id).is_none());
                    assert!(asm.peer_table.clone_km_manager(link_id).is_none());
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
                for (asm, _, _) in ends {
                    assert!(zode_connections(asm).is_empty(), "nobody redials (rule 10)");
                }
            })
            .await
    }

    /// Rule 12: a link that leaves the topology is closed and forgotten,
    /// whatever its state: up, dialing, failed or down.
    #[tokio::test(start_paused = true)]
    async fn test_removed_link_is_closed_and_forgotten() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                set_topology(
                    &asm,
                    vec![
                        peer("up", "fd5a::21", 7106),
                        peer("dialing", "fd5a::22", 7107),
                    ],
                );
                let up = record_of(&asm, "up").link_id.unwrap();
                bring_up(&asm, up, "up");
                let dialing = record_of(&asm, "dialing").link_id.unwrap();
                set_topology(&asm, vec![]);
                assert!(asm.zode_links.record("up").is_none());
                assert!(asm.zode_links.record("dialing").is_none());
                tokio::time::sleep(Duration::from_secs(2)).await;
                assert!(asm.peer_table.get(up).is_none());
                assert!(asm.peer_table.get(dialing).is_none());

                // Failed and down records are forgotten too.
                set_topology(&asm, vec![peer("f", "fd5a::23", 7108)]);
                tokio::time::sleep(Duration::from_secs(10)).await;
                assert_eq!(record_of(&asm, "f").state, RecordState::Failed);
                set_topology(&asm, vec![]);
                assert!(asm.zode_links.record("f").is_none());
                tokio::time::sleep(Duration::from_secs(10)).await;
                assert!(zode_connections(&asm).is_empty());
            })
            .await
    }

    /// Rule 13: every setTopology retries the failed and down links it
    /// still contains, once, and leaves an up link alone; the non-owner
    /// does nothing.
    #[tokio::test(start_paused = true)]
    async fn test_repeat_topology_retries_failed_and_down_once() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                let links = vec![
                    peer("failed", "fd5a::21", 7109),
                    peer("down", "fd5a::22", 7110),
                    peer("up", "fd5a::23", 7111),
                    peer("waits", "fd5a::9", 7112),
                ];
                set_topology(&asm, links.clone());
                let down = record_of(&asm, "down").link_id.unwrap();
                bring_up(&asm, down, "down");
                let up = record_of(&asm, "up").link_id.unwrap();
                bring_up(&asm, up, "up");
                asm.process_link_state_event(down, LinkEvent::Close(TerminateReason::Reset))
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(10)).await;
                assert_eq!(record_of(&asm, "failed").state, RecordState::Failed);
                assert_eq!(record_of(&asm, "down").state, RecordState::Down);

                set_topology(&asm, links);
                for cn in ["failed", "down"] {
                    let record = record_of(&asm, cn);
                    assert!(
                        matches!(record.state, RecordState::Dialing { .. }),
                        "{cn} retried"
                    );
                    assert!(record.link_id.is_some());
                }
                assert_eq!(
                    record_of(&asm, "up").link_id,
                    Some(up),
                    "the up link is untouched"
                );
                assert_eq!(record_of(&asm, "up").state, RecordState::Up);
                assert_eq!(record_of(&asm, "waits").state, RecordState::Idle);
                assert_eq!(
                    zode_connections(&asm).len(),
                    3,
                    "two retries plus the up link"
                );
            })
            .await
    }

    /// The issue's "topology removal and re-add": a link removed and then
    /// proposed again is dialed again, and exactly one connection remains.
    #[tokio::test(start_paused = true)]
    async fn test_removed_then_readded_link_is_dialed_again() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                set_topology(&asm, vec![peer("b", "fd5a::20", 7113)]);
                let first = record_of(&asm, "b").link_id.unwrap();
                bring_up(&asm, first, "b");
                set_topology(&asm, vec![]);
                tokio::time::sleep(Duration::from_secs(2)).await;
                set_topology(&asm, vec![peer("b", "fd5a::20", 7113)]);
                let second = record_of(&asm, "b").link_id.unwrap();
                assert_ne!(second, first);
                bring_up(&asm, second, "b");
                assert_eq!(zode_connections(&asm), vec![second]);
            })
            .await
    }

    /// One link per pair: when both Zodes receive the topology naming each
    /// other, only the owner (the lower address) dials.
    #[tokio::test(start_paused = true)]
    async fn test_simultaneous_topology_dials_from_the_owner_only() {
        LocalSet::new()
            .run_until(async {
                let (a, _e1) = driven_zode("fd5a::10", "a", None);
                let (b, _e2) = driven_zode("fd5a::20", "b", None);
                set_topology(&a, vec![peer("b", "fd5a::20", 7114)]);
                set_topology(&b, vec![peer("a", "fd5a::10", 7214)]);
                assert_eq!(zode_connections(&a).len(), 1);
                assert!(zode_connections(&b).is_empty());
            })
            .await
    }

    /// The walkthrough "the owner restarts": its new connection replaces
    /// the non-owner's old one (rule 5), the record follows it, and one
    /// link remains, up.
    #[tokio::test(start_paused = true)]
    async fn test_owner_restart_leaves_one_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::20", "b", None);
                set_topology(&asm, vec![peer("a", "fd5a::10", 7115)]);
                let old = answered_up(&asm, "a", 7215);
                let new = answered_up(&asm, "a", 7216);
                settle().await;
                assert_eq!(zode_connections(&asm), vec![new]);
                let record = record_of(&asm, "a");
                assert_eq!(record.state, RecordState::Up);
                assert_eq!(record.link_id, Some(new));
                assert!(asm.peer_table.get(old).is_none());
            })
            .await
    }

    /// A topology entry whose owner cannot be decided (both ends claim the
    /// same ZPR address) is skipped, and the rest is applied.
    #[tokio::test(start_paused = true)]
    async fn test_equal_address_entry_is_skipped() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                set_topology(
                    &asm,
                    vec![peer("twin", "fd5a::10", 7116), peer("b", "fd5a::20", 7117)],
                );
                assert!(asm.zode_links.record("twin").is_none());
                assert!(asm.zode_links.record("b").is_some());
            })
            .await
    }

    /// Rule 11: the initial link is dialed at startup and redialed with
    /// backoff after each failed attempt; it is never failed.
    #[tokio::test(start_paused = true)]
    async fn test_initial_link_redials_until_it_comes_up() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::20", "b", Some("relay@127.0.0.1:7118"));
                start_initial_link(&asm);
                let first = record_of(&asm, "relay").link_id.unwrap();
                // The attempt times out keying, closes, and is redialed.
                tokio::time::sleep(Duration::from_secs(5)).await;
                let record = record_of(&asm, "relay");
                assert_ne!(record.state, RecordState::Failed);
                let again = record.link_id.expect("redialed");
                assert_ne!(again, first);
                bring_up(&asm, again, "relay");
                assert_eq!(record_of(&asm, "relay").state, RecordState::Up);
            })
            .await
    }

    /// The issue's "initial-link close": the relay closes the endpoint's
    /// initial link; the endpoint goes down, redials, and ends with exactly
    /// one link. A topology without the relay never closes it (rule 12
    /// does not apply to the initial link).
    #[tokio::test(start_paused = true)]
    async fn test_initial_link_close_redials_to_one_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::20", "b", Some("relay@127.0.0.1:7119"));
                start_initial_link(&asm);
                let first = record_of(&asm, "relay").link_id.unwrap();
                bring_up(&asm, first, "relay");
                set_topology(&asm, vec![]);
                assert_eq!(record_of(&asm, "relay").state, RecordState::Up);

                asm.process_link_state_event(
                    first,
                    LinkEvent::ReceivedTerminateLink(TerminateReason::Reset),
                )
                .unwrap();
                settle().await;
                assert_eq!(record_of(&asm, "relay").state, RecordState::Down);
                tokio::time::sleep(crate::zode_link_record::INITIAL_LINK_BACKOFF_MIN).await;
                let second = record_of(&asm, "relay").link_id.expect("redialed");
                bring_up(&asm, second, "relay");
                assert_eq!(zode_connections(&asm), vec![second]);
            })
            .await
    }

    /// The initial-link rule wins when the relay is also in the topology:
    /// the endpoint keeps its initial record and dials the configured
    /// address, not the topology's.
    #[tokio::test(start_paused = true)]
    async fn test_initial_link_in_topology_keeps_the_initial_rule() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::20", "b", Some("relay@127.0.0.1:7120"));
                start_initial_link(&asm);
                set_topology(&asm, vec![peer("relay", "fd5a::1", 7999)]);
                let record = record_of(&asm, "relay");
                assert_eq!(record.kind, Kind::Initial);
                assert_eq!(record.dial_addr, "127.0.0.1:7120".parse().unwrap());
                assert_eq!(zode_connections(&asm).len(), 1);
            })
            .await
    }

    // ---- link-state reporting ("Reporting summary", "Reporting contract") ----

    use zpr::vsapi_types::{LinkState as Reported, LinkStateReport};

    /// The snapshot as (CN, state) pairs.
    fn listed(asm: &Arc<Assembly>) -> Vec<(String, Reported)> {
        asm.zode_links
            .snapshot()
            .into_iter()
            .map(|r| (r.peer_cn, r.state))
            .collect()
    }

    /// One case per row of the design's reporting summary: owner up,
    /// failed, down and first window; non-owner never up, up, down; the
    /// initial link never up, up, down; a removed link.
    #[tokio::test(start_paused = true)]
    async fn test_snapshot_follows_the_reporting_summary() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", Some("relay@127.0.0.1:7130"));
                start_initial_link(&asm);
                set_topology(
                    &asm,
                    vec![
                        peer("o-up", "fd5a::21", 7131),
                        peer("o-failed", "fd5a::22", 7132),
                        peer("o-down", "fd5a::23", 7133),
                        peer("n-never", "fd5a::1", 7134),
                        peer("n-up", "fd5a::2", 7135),
                        peer("n-down", "fd5a::3", 7136),
                        peer("removed", "fd5a::24", 7137),
                    ],
                );
                assert!(
                    listed(&asm).is_empty(),
                    "nothing is listed in the first window"
                );
                assert!(
                    listed(&asm).iter().all(|(cn, _)| cn != "relay"),
                    "an initial link never up is not listed"
                );
                let relay = record_of(&asm, "relay").link_id.expect("dialing the relay");
                bring_up(&asm, relay, "relay");

                for cn in ["o-up", "o-down", "removed"] {
                    let id = record_of(&asm, cn).link_id.unwrap();
                    bring_up(&asm, id, cn);
                }
                answered_up(&asm, "n-up", 7235);
                let n_down = answered_up(&asm, "n-down", 7236);

                // "removed" leaves the topology; the others are already up or
                // dialing, so the repeat leaves them as they are.
                let mut topology = asm.topology.read().unwrap().clone();
                topology.retain(|l| l.peer_cn != "removed");
                set_topology(&asm, topology);

                for id in [record_of(&asm, "o-down").link_id.unwrap(), n_down] {
                    asm.process_link_state_event(id, LinkEvent::Close(TerminateReason::Reset))
                        .unwrap();
                }
                tokio::time::sleep(Duration::from_secs(6)).await;

                assert_eq!(
                    listed(&asm),
                    vec![
                        ("n-down".to_owned(), Reported::Down),
                        ("n-up".to_owned(), Reported::Up),
                        ("o-down".to_owned(), Reported::Down),
                        ("o-failed".to_owned(), Reported::Failed),
                        ("o-up".to_owned(), Reported::Up),
                        ("relay".to_owned(), Reported::Up),
                    ]
                );
            })
            .await
    }

    /// Reporting contract: a failed link that a new setTopology retries is
    /// not listed while it retries, and is listed failed again when the
    /// retry fails; each change asks for a report.
    #[tokio::test(start_paused = true)]
    async fn test_snapshot_failed_retry_unlisted_then_failed() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                let links = vec![peer("b", "fd5a::20", 7138)];
                set_topology(&asm, links.clone());
                tokio::time::sleep(Duration::from_secs(6)).await;
                assert_eq!(listed(&asm), vec![("b".to_owned(), Reported::Failed)]);
                asm.zode_links
                    .report_pending
                    .store(false, std::sync::atomic::Ordering::Release);

                set_topology(&asm, links);
                assert!(listed(&asm).is_empty(), "a retrying link is not listed");
                assert!(
                    asm.zode_links.report_pending(),
                    "failed -> not listed is a change"
                );
                asm.zode_links
                    .report_pending
                    .store(false, std::sync::atomic::Ordering::Release);

                tokio::time::sleep(Duration::from_secs(6)).await;
                assert_eq!(listed(&asm), vec![("b".to_owned(), Reported::Failed)]);
                assert!(
                    asm.zode_links.report_pending(),
                    "not listed -> failed is a change"
                );
            })
            .await
    }

    /// A send that blocks (the RPC waits up to its timeout) must not merge
    /// the snapshots taken meanwhile: failed -> retry (not listed) -> failed
    /// while the first send is in flight still reaches the visa service as
    /// three snapshots, in order, so it sees the second failure as new
    /// ("Reporting contract"; core#107 review).
    #[tokio::test(start_paused = true)]
    async fn test_reporter_keeps_snapshots_taken_during_a_blocked_send() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                let sent: std::rc::Rc<std::cell::RefCell<Vec<Vec<LinkStateReport>>>> =
                    Default::default();
                let release = std::rc::Rc::new(tokio::sync::Notify::new());
                let (log, gate) = (sent.clone(), release.clone());
                tokio::task::spawn_local(run_link_state_reporter(asm.clone(), move |reports| {
                    log.borrow_mut().push(reports);
                    // Only the first send blocks, until the test releases it.
                    let wait = (log.borrow().len() == 1).then(|| gate.clone());
                    async move {
                        if let Some(gate) = wait {
                            gate.notified().await;
                        }
                        Ok(())
                    }
                }));

                let links = vec![peer("b", "fd5a::20", 7142)];
                set_topology(&asm, links.clone());
                tokio::time::sleep(
                    crate::zode_link_record::LINK_UP_WINDOW + Duration::from_secs(1),
                )
                .await;
                // The first send ([b=failed]) is now blocked. Retry and fail
                // again while it is.
                set_topology(&asm, links);
                tokio::time::sleep(REPORT_COALESCE * 3).await;
                tokio::time::sleep(
                    crate::zode_link_record::LINK_UP_WINDOW + Duration::from_secs(1),
                )
                .await;
                release.notify_one();
                tokio::time::sleep(REPORT_COALESCE * 3).await;

                let failed = vec![LinkStateReport {
                    peer_cn: "b".to_owned(),
                    state: Reported::Failed,
                }];
                assert_eq!(*sent.borrow(), vec![failed.clone(), Vec::new(), failed]);
            })
            .await
    }

    /// While a send is stalled, the queue of snapshots taken meanwhile is
    /// bounded: past [REPORT_QUEUE_MAX] the newest snapshot replaces the
    /// last queued one, so a long stall cannot grow memory without limit
    /// (core#107 review).
    #[tokio::test(start_paused = true)]
    async fn test_reporter_queue_is_bounded_while_a_send_stalls() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                let sent = std::rc::Rc::new(std::cell::Cell::new(0usize));
                let release = std::rc::Rc::new(tokio::sync::Notify::new());
                let (count, gate) = (sent.clone(), release.clone());
                tokio::task::spawn_local(run_link_state_reporter(asm.clone(), move |_| {
                    count.set(count.get() + 1);
                    let wait = (count.get() == 1).then(|| gate.clone());
                    async move {
                        if let Some(gate) = wait {
                            gate.notified().await;
                        }
                        Ok(())
                    }
                }));

                for _ in 0..(REPORT_QUEUE_MAX * 3) {
                    asm.zode_links.request_report();
                    tokio::time::sleep(REPORT_COALESCE * 2).await;
                }
                release.notify_one();
                tokio::time::sleep(REPORT_COALESCE * 2).await;
                assert_eq!(sent.get(), 1 + REPORT_QUEUE_MAX);
            })
            .await
    }

    /// The reporter sends one snapshot per burst of changes, and sends again
    /// on the next request (a VS-API reconnect asks for one). A failed send
    /// is only logged.
    #[tokio::test(start_paused = true)]
    async fn test_reporter_coalesces_and_resends() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = driven_zode("fd5a::10", "a", None);
                let sent: std::rc::Rc<std::cell::RefCell<Vec<Vec<LinkStateReport>>>> =
                    Default::default();
                let log = sent.clone();
                tokio::task::spawn_local(run_link_state_reporter(asm.clone(), move |reports| {
                    log.borrow_mut().push(reports);
                    async { Err(VSApiError::ConnClosed) }
                }));

                set_topology(&asm, vec![peer("b", "fd5a::9", 7139)]);
                // Three answered links from b in a row (each replaces the
                // last, rule 5): one burst of changes.
                for port in [7239, 7240, 7241] {
                    answered_up(&asm, "b", port);
                }
                tokio::time::sleep(REPORT_COALESCE * 3).await;
                assert_eq!(sent.borrow().len(), 1, "one burst, one send");
                assert_eq!(
                    sent.borrow()[0],
                    vec![LinkStateReport {
                        peer_cn: "b".to_owned(),
                        state: Reported::Up
                    }]
                );

                asm.zode_links.request_report();
                tokio::time::sleep(REPORT_COALESCE * 3).await;
                assert_eq!(sent.borrow().len(), 2, "a reconnect sends again");
                assert!(!asm.zode_links.report_pending());
            })
            .await
    }
}
