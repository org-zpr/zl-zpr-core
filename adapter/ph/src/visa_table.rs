//! Visa Table

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::peer_table;
use crate::prelude::*;
use crate::tc;

use chrono::{DateTime, Utc};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zpr::addrs::{VISA_SERVICE_ADDR, VISA_SERVICE_PORT};
use zpr::five_tuple_lookup_table::FiveTupleLookupTable;
use zpr::vsapi_types;
use zpr::vsapi_types::{HasFiveTuple, VsapiFiveTuple};
use zpr_utils::net_defs::IpAddress;

// TODO: Figure out correct value for this visa expiration
const VS_VISAS_DURATION: Duration = Duration::from_secs(60 * 60 * 24); // 24 hours

// TODO: This is a placeholder.  We need this in the visa struct but at the time when
// we are creating these we don't have access to a valid configuration ID.
const VS_VISAS_CONFIG_ID: i64 = 100;

#[derive(Debug, Error)]
pub enum VisaTableError {
    #[error("Visa {0} Not Found")]
    NotFound(VisaId),
    #[error("Failed to parse visa field {0}")]
    ParseError(&'static str),
    #[error("Could not find destination {0}")]
    DestNotFound(IpAddress),
    #[error("Failed to insert visa into table")]
    InsertError,
    #[error("Visa {0} is forward-only and forwarding is off on this node")]
    ForwardingDisabled(VisaId),
}

/// A granted visa as this Zode holds it.
///
/// **Visas are immutable** (core tenet, ZODE_LINKS.md): once inserted, a
/// visa is never changed. Every field is private and set once in
/// [Visa::new], and nothing hands out `&mut Visa`: the visa table keeps its
/// visas in a private map and gives out only shared references. State that
/// belongs to a stream binding lives beside the visa, in
/// [VisaTable]'s binding table.
#[derive(Clone, Debug)]
pub struct Visa {
    /// The visa exactly as the visa service granted it.
    visa: vsapi_types::Visa,
    /// The flow the visa admits, from its dock PEP. `None` for a
    /// forward-only visa, which has no dock PEP: it only carries an
    /// already-bound stream from one node link to the next, so it must
    /// never match a new flow (zl-zipline#219).
    ftuple: Option<VsapiFiveTuple>,
    /// The forwarding PEP's next hop, or UNSPECIFIED if the visa has none.
    next_hop: IpAddress,
}

/// One stream bound over this Zode under a visa (F3, zl-zipline#251).
///
/// `ingress` is the link the requestor bound over and the stream ID this
/// Zode gave it, which is also the key of the PFT entry on that link.
/// `egress` is the next hop's link and the stream ID the next hop gave this
/// Zode, which is where that PFT entry forwards to. Recording both sides
/// lets the loss of either link find, and revoke, every visa bound over it.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamBinding {
    pub ingress: ForwardingEntry,
    pub egress: ForwardingEntry,
}

impl std::fmt::Debug for StreamBinding {
    /// `link:stream -> link:stream`, ingress first.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.ingress.0, self.ingress.1, self.egress.0, self.egress.1
        )
    }
}

/// Struct for the visa timeout queue
pub struct VisaTimeout {
    pub id: VisaId,
    pub expiration: DateTime<Utc>,
}

// Visas should sort with soonest expiration first
impl Ord for VisaTimeout {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .expiration
            .cmp(&self.expiration)
            .then_with(|| other.id.cmp(&self.id))
    }
}

impl PartialOrd for VisaTimeout {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for VisaTimeout {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.expiration == other.expiration
    }
}

impl Eq for VisaTimeout {}

impl Visa {
    /// Wrap a visa from the visa service, checking that its shape matches
    /// its type. The visa service is a trust boundary, so a malformed visa
    /// is an error, never a panic:
    ///
    /// - a full visa must have a dock PEP; its forwarding PEP is optional
    ///   (an ingress node has one, an egress node does not);
    /// - a forward-only visa must have no dock PEP, and a forwarding PEP
    ///   with a specified next hop.
    pub fn new(visa: vsapi_types::Visa) -> Result<Self, VisaTableError> {
        let ftuple = match visa.visa_type {
            vsapi_types::VisaType::Full => {
                let Some(dock_pep) = visa.dock_pep.as_ref() else {
                    return Err(VisaTableError::ParseError("dock_pep"));
                };
                Some(dock_pep.get_five_tuple())
            }
            vsapi_types::VisaType::ForwardOnly => {
                if visa.dock_pep.is_some() {
                    return Err(VisaTableError::ParseError("dock_pep"));
                }
                match visa.fwd_pep.as_ref() {
                    Some(fwd_pep) if !fwd_pep.next_hop.is_unspecified() => None,
                    _ => return Err(VisaTableError::ParseError("fwd_pep")),
                }
            }
        };
        let next_hop = visa
            .fwd_pep
            .as_ref()
            .map(|p| p.next_hop.into())
            .unwrap_or_default();
        Ok(Self {
            visa,
            ftuple,
            next_hop,
        })
    }

    /// The visa exactly as the visa service granted it.
    pub fn visa(&self) -> &vsapi_types::Visa {
        &self.visa
    }

    // Return true if the visa matches the given traffic description (given in the
    // form of a FiveTuple).
    //
    // Visa may have wildcards.  Eg, a visa with zero for a source port will match
    // any traffic five_tuple source port value.
    //
    // A forward-only visa matches no traffic.
    pub fn match_traffic(&self, five_tuple: &FiveTuple) -> bool {
        self.get_tc().is_some_and(|tc| tc.classify_5t(five_tuple))
    }

    /// The traffic classifier for the flow this visa admits, which an
    /// adapter needs to bind it. `None` for a forward-only visa: it has no
    /// flow, so it can only join two node links.
    pub fn get_tc(&self) -> Option<tc::Ip5TupleTc> {
        self.ftuple.map(|ftuple| tc::Ip5TupleTc::new(ftuple.into()))
    }

    /// Get the ingress A2A DH public key from the visa, if present.
    /// Keys are 32 bytes long, so we attempt to convert the key slice to a 32-byte array
    pub fn get_ingress_a2a_dh_pubkey(&self) -> Option<x25519_dalek::PublicKey> {
        let key = &self.visa.dock_pep.as_ref()?.session_key.ingress_key;
        <[u8; 32]>::try_from(key.as_slice())
            .ok()
            .map(x25519_dalek::PublicKey::from)
    }

    /// Get the egress A2A DH public key from the visa, if present
    /// Keys are 32 bytes long, so we attempt to convert the key slice to a 32-byte array
    pub fn get_egress_a2a_dh_pubkey(&self) -> Option<x25519_dalek::PublicKey> {
        let key = &self.visa.dock_pep.as_ref()?.session_key.egress_key;
        <[u8; 32]>::try_from(key.as_slice())
            .ok()
            .map(x25519_dalek::PublicKey::from)
    }
}

/// The visas this Zode holds, and the streams bound under them.
///
/// The binding table exists for the core tenet that **visas are
/// immutable** (ZODE_LINKS.md): what a bind records goes in `bindings`,
/// beside the visa, never in it. [VisaTable::bind] is the only writer that
/// adds a binding, and [VisaTable::revoke_no_rebuild] (behind revocation,
/// expiry and link loss) the only one that removes bindings, together with
/// their PFT entries. Both run under the one visa-table lock.
///
/// #252's J11 (supersede and rebind) adds one more writer under that same
/// lock: a `rebind(old, new)` that moves a binding from the old visa ID to
/// the new one and swaps the `visa_id` of its ingress PFT entry. It
/// replaces the visa by a new one; it never edits either.
pub struct VisaTable {
    /// Granted visas by ID. Private, so no `&mut Visa` escapes.
    table: HashMap<VisaId, Visa>,
    /// Stream bindings by visa ID (F3, zl-zipline#251).
    bindings: HashMap<VisaId, Vec<StreamBinding>>,
    pub timeout_queue: BinaryHeap<VisaTimeout>,
    pub lookup_table: FiveTupleLookupTable,
}

impl VisaTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            bindings: HashMap::new(),
            timeout_queue: BinaryHeap::new(),
            lookup_table: FiveTupleLookupTable::new(),
        }
    }

    /// Create table and populate with two visas to allow for 2-way comms with the
    /// VS-API.
    ///
    /// TODO: Note that the first thing the visa service does after connecting is
    /// hand over visas just like this.  So we should have logic somewhere to get
    /// rid of these.  Maybe?  We might need them again if for example we loose
    /// contact with visa service and the visas it gives us expire.
    pub fn new_with_vs_visas(node_addr: &IpAddr) -> Self {
        // Right away the node wants to reach out to the visa service. So we need visas to match:
        //  1) NODEADDR/any-port -> VISA_SERVICE/VS_PORT
        //  2) VISA_SERVICE/VS_PORT -> NODEADDR/any-port (TODO: not great, really needs to check this is non-syn)

        // Node ZPR address must be IPv6, right?
        let node_zpr_addr = match node_addr {
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
            IpAddr::V6(addr) => addr.clone(),
        };

        // TODO: This is crazy since VS is always IPv6
        let vs_zpr_addr = match VISA_SERVICE_ADDR {
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
            IpAddr::V6(addr) => addr,
        };

        let expires_ms = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + VS_VISAS_DURATION)
            .as_millis() as i64;

        let node2vs = make_tcp_visa(
            1,
            &node_zpr_addr,
            0,
            &vs_zpr_addr,
            VISA_SERVICE_PORT,
            VS_VISAS_CONFIG_ID,
            expires_ms,
        );
        let vs2node = make_tcp_visa(
            2,
            &vs_zpr_addr,
            VISA_SERVICE_PORT,
            &node_zpr_addr,
            0,
            VS_VISAS_CONFIG_ID,
            expires_ms,
        );

        let mut visa_table = Self::new();
        visa_table
            .insert_visa(node2vs)
            .expect("Failed to insert node->vs visa into table");
        visa_table
            .insert_visa(vs2node)
            .expect("Failed to insert visa->node visa into table");

        visa_table.rebuild_lookup_table();

        visa_table
    }

    /// Insert a visa from the visa service into the table.
    ///
    /// A visa ID always names the same visa (operator, g88 q4): if this
    /// Zode already holds `visa.issuer_id`, the incoming visa is dropped and
    /// the insert succeeds, idempotently. The two visas' contents are never
    /// compared. That check comes first, so a duplicate leaves no side
    /// effects: no parse, no lookup-table rewrite, no second timeout entry,
    /// and the held visa keeps its bindings (the tenet: visas are immutable).
    pub fn insert_visa(&mut self, visa: vsapi_types::Visa) -> Result<VisaId, VisaTableError> {
        let visa_id = visa.issuer_id;
        if self.table.contains_key(&visa_id) {
            debug!(target: VISA_MGMT, "visa {visa_id} is already held; dropping the duplicate");
            return Ok(visa_id);
        }

        let expiration = DateTime::from(visa.expires);

        info!(target: VISA_MGMT,
            "Visa inserted into VisaTable ID: {visa_id}, Type: {:?}, Expiration: {}",
            visa.visa_type, expiration.format("%y-%m-%d %H:%M:%S"));

        let visa = Visa::new(visa)?;

        let timeout = VisaTimeout {
            id: visa_id,
            expiration: expiration,
        };
        // Only a visa with a five-tuple goes in the lookup table: a
        // forward-only visa must never match a new flow.
        if let Some(ftuple) = visa.ftuple {
            self.lookup_table.insert_visa(visa_id, ftuple);
        }
        self.table.insert(visa_id, visa);
        self.timeout_queue.push(timeout);

        Ok(visa_id)
    }

    /// The visa with ID `visa_id`, if this Zode holds it. Read-only: a
    /// granted visa is never changed.
    pub fn get(&self, visa_id: VisaId) -> Option<&Visa> {
        self.table.get(&visa_id)
    }

    /// Whether this Zode holds the visa `visa_id`.
    pub fn contains(&self, visa_id: VisaId) -> bool {
        self.table.contains_key(&visa_id)
    }

    /// How many visas this Zode holds.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether this Zode holds no visa.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Record a stream bound under the visa `visa_id` (F3, zl-zipline#251).
    /// The only writer that adds a binding; the visa itself is untouched.
    /// Fails with [VisaTableError::NotFound] if the visa is not held.
    pub fn bind(&mut self, visa_id: VisaId, binding: StreamBinding) -> Result<(), VisaTableError> {
        if !self.table.contains_key(&visa_id) {
            error!(target: VISA_MGMT, "cannot bind a stream to visa {visa_id}, which is not held");
            return Err(VisaTableError::NotFound(visa_id));
        }
        self.bindings.entry(visa_id).or_default().push(binding);
        Ok(())
    }

    /// The streams bound under the visa `visa_id`, if any.
    pub fn bindings(&self, visa_id: VisaId) -> &[StreamBinding] {
        self.bindings.get(&visa_id).map_or(&[], Vec::as_slice)
    }

    /// The visas with a stream bound over `link_id`, on either side.
    ///
    /// ponytail: a scan of every binding; a by-link index if link loss
    /// with very many bindings shows up in profiles.
    pub fn visas_bound_over(&self, link_id: LinkId) -> Vec<VisaId> {
        self.bindings
            .iter()
            .filter(|(_, bindings)| {
                bindings
                    .iter()
                    .any(|b| b.ingress.0 == link_id || b.egress.0 == link_id)
            })
            .map(|(visa_id, _)| *visa_id)
            .collect()
    }

    /// Match traffic to a visa. Returns all matching visa IDs.
    pub fn match_traffic(&self, five_tuple: &FiveTuple) -> Option<VisaId> {
        self.lookup_table
            .find_match(VsapiFiveTuple::from(*five_tuple))
    }

    /// Revoke (or otherwise remove) a visa.
    ///
    /// Returns the withdrawn forwarding entries (empty if the visa was
    /// already gone) so callers may notify affected peers.
    pub fn revoke(
        &mut self,
        peer_table: &peer_table::PeerTable,
        visa_id: VisaId,
    ) -> Result<Vec<ForwardingEntry>, VisaTableError> {
        // The only error from `revoke_no_rebuild` is a HashMap::remove miss. If the visa
        // is gone we consider it "revoked".
        let withdrawn = self
            .revoke_no_rebuild(peer_table, visa_id)
            .unwrap_or_default();
        self.rebuild_lookup_table();

        Ok(withdrawn)
    }

    /// Remove every expired visa from the table.
    ///
    /// Returns the withdrawn forwarding entries. Unlike revocation
    /// ([`Self::revoke_for_link`] via `Assembly::drop_peer`), expiry
    /// deliberately does NOT notify peers: both ends of a flow hold the same
    /// visa expiry and eject on their own clocks, and a peer that sends
    /// early (clock skew) gets `UnknownStreamId` and re-requests a visa —
    /// unlike the revocation case, where the surviving peer's binding would
    /// otherwise never die. Callers that want to notify anyway have the
    /// returned entries to do it with.
    pub fn handle_expirations(
        &mut self,
        peer_table: &peer_table::PeerTable,
    ) -> Vec<ForwardingEntry> {
        let current_time = Utc::now();
        let mut withdrawn = Vec::new();
        while self
            .timeout_queue
            .peek()
            .map_or(false, |entry| entry.expiration < current_time)
        {
            let timeout_entry = self.timeout_queue.pop().unwrap();
            // Ignore if the visa was not found, since it might have been previously revoked
            if let Ok(entries) = self.revoke_no_rebuild(peer_table, timeout_entry.id) {
                withdrawn.extend(entries);
            }
        }
        self.rebuild_lookup_table();
        withdrawn
    }

    /// Revoke every visa with a stream bound over `link_id`, on the ingress
    /// **or** the egress side (F3, zl-zipline#251): losing either side of
    /// a binding revokes the visa locally, so no PFT entry is left pointing
    /// at the dead link ID, which the slab may hand out again. At the Zode
    /// where a flow starts, the next packet then finds no visa and asks for
    /// one (F6).
    ///
    /// Returns the ingress entries of every revoked binding (on surviving
    /// links too) so the caller can withdraw those streams from adapters
    /// (`Assembly::withdraw_streams`, which skips the lost link and Zode
    /// links, F5). The caller sends OUTSIDE the visa-table lock: this runs
    /// under the table's write lock, and the send path takes the peer's
    /// `zdpr_send` mutex, which must never nest under it (zipline#9).
    ///
    /// Visas with IDs below `MIN_VISA_ID` (this node's own visas to and from
    /// the visa service) are not affected.
    ///
    /// The whole visa is revoked even if it has bindings on other links: a
    /// partly cleaned visa could forward traffic over a stale route.
    pub fn revoke_for_link(
        &mut self,
        link_id: LinkId,
        peer_table: &peer_table::PeerTable,
    ) -> Vec<ForwardingEntry> {
        let to_revoke: Vec<VisaId> = self
            .visas_bound_over(link_id)
            .into_iter()
            .filter(|visa_id| *visa_id >= config::MIN_VISA_ID)
            .collect();
        let mut withdrawn = Vec::new();
        if !to_revoke.is_empty() {
            info!(target: VISA_MGMT, "ejecting {} visa(s) for removed link {link_id}", to_revoke.len());
            for visa_id in to_revoke {
                if let Ok(entries) = self.revoke_no_rebuild(peer_table, visa_id) {
                    withdrawn.extend(entries);
                }
            }
            self.rebuild_lookup_table();
        }
        withdrawn
    }

    /// Rebuild the five-tuple lookup table from the visas in the table.
    ///
    /// Only visas with a five-tuple are added: a forward-only visa has none
    /// and must never match a new flow (zl-zipline#219).
    fn rebuild_lookup_table(&mut self) {
        let five_tuples: HashMap<VisaId, VsapiFiveTuple> = self
            .table
            .iter()
            .filter_map(|(visa_id, visa)| visa.ftuple.map(|ftuple| (*visa_id, ftuple)))
            .collect();
        self.lookup_table = FiveTupleLookupTable::new();
        self.lookup_table.add_hash_to_table(&five_tuples);
    }

    /// Remove the visa `visa_id` and its bindings, and the PFT entry of each
    /// binding. The only path that removes bindings: revocation, expiry and
    /// link loss all come here.
    ///
    /// Returns each binding's ingress entry: the link the requestor bound
    /// over and the stream ID it sends with, which is all a withdrawal to
    /// that requestor needs.
    fn revoke_no_rebuild(
        &mut self,
        peer_table: &peer_table::PeerTable,
        visa_id: VisaId,
    ) -> Result<Vec<ForwardingEntry>, VisaTableError> {
        if self.table.remove(&visa_id).is_none() {
            return Err(VisaTableError::NotFound(visa_id));
        }
        let withdrawn: Vec<ForwardingEntry> = self
            .bindings
            .remove(&visa_id)
            .unwrap_or_default()
            .into_iter()
            .map(|binding| binding.ingress)
            .collect();
        for entry in &withdrawn {
            peer_table.remove_route(entry.clone());
        }
        info!(target: VISA_MGMT, "Revoked visa {visa_id}");
        Ok(withdrawn)
    }

    /// Given a visa ID, look up the visa and return the next hop address.
    /// If visa is not found or does not have a next hop address, return an error.
    pub fn get_visa_next_hop_addr(&self, visa_id: VisaId) -> Result<IpAddress, VisaTableError> {
        let visa = self
            .table
            .get(&visa_id)
            .ok_or(VisaTableError::NotFound(visa_id))?;

        if visa.next_hop != IpAddress::UNSPECIFIED {
            return Ok(visa.next_hop);
        }
        // No forwarding PEP: the flow ends at its destination. `Visa::new`
        // guarantees a forward-only visa has a next hop, so only a full
        // visa (which always has a five-tuple) gets here.
        visa.ftuple
            .map(|ftuple| IpAddress::from(ftuple.dest_addr))
            .ok_or(VisaTableError::ParseError("fwd_pep"))
    }
}

fn make_tcp_visa(
    visa_id: u64,
    source: &Ipv6Addr,
    source_port: u16,
    dest: &Ipv6Addr,
    dest_port: u16,
    configuration: i64,
    expiration_ms: i64,
) -> vsapi_types::Visa {
    let tcp_pepargs = vsapi_types::TcpUdpPep {
        source_port: source_port,
        dest_port: dest_port,
        endpoint: vsapi_types::EndpointT::Any,
    };
    let dur = Duration::from_millis(expiration_ms as u64);

    let dock_pep = vsapi_types::DockPep {
        source_addr: (*source).into(),
        dest_addr: (*dest).into(),
        session_key: vsapi_types::KeySet::default(),
        pep: vsapi_types::DockPepType::TCP(tcp_pepargs),
    };

    vsapi_types::Visa {
        issuer_id: visa_id,
        config: configuration,
        expires: UNIX_EPOCH + dur,
        visa_type: vsapi_types::VisaType::Full,
        dock_pep: Some(dock_pep),
        fwd_pep: None,
        cons: None,
        // A node's own visas to and from the visa service are installed
        // locally and never arrive by StreamIdRequest, so they have no
        // previous hop (zl-zipline#245).
        prev_hop: None,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::forwarding_tables::PftPep;
    use crate::link_state::LinkType;
    use crate::peer_table::test::create_dummy_peer_state;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use zpr::packet_info::{L3Type, SubstrateAddr};
    use zpr_utils::net_defs;
    use zpr_utils::net_defs::ip_number;

    /// A visa expiry that will not arrive during a test run.  Deliberately
    /// not `DateTime::<Utc>::MAX_UTC`: Windows `SystemTime` (a FILETIME) cannot
    /// represent that, and the conversion panics.
    pub fn never_expires() -> SystemTime {
        SystemTime::now() + Duration::from_secs(100 * 365 * 24 * 60 * 60)
    }

    /// A visa expiry already in the past.  `UNIX_EPOCH` rather than
    /// `DateTime::<Utc>::MIN_UTC`, for the same Windows reason as `never_expires`.
    pub const ALREADY_EXPIRED: SystemTime = UNIX_EPOCH;

    /// Create a new vsapi_types::Visa, only having to specify the id and the expiration
    pub fn new_vsapi_visa_tcp_default(issuer_id: u64, expires: SystemTime) -> vsapi_types::Visa {
        vsapi_types::Visa::new(
            issuer_id,
            1,
            expires,
            [0; 4].into(),
            [0; 4].into(),
            vsapi_types::DockPepType::TCP(vsapi_types::TcpUdpPep {
                source_port: 0,
                dest_port: 0,
                endpoint: vsapi_types::EndpointT::Any,
            }),
            vsapi_types::KeySet::default(),
            None,
        )
    }

    /// Create a forward-only vsapi_types::Visa, as the visa service issues to
    /// an intermediary node on a path: no dock PEP, and a forwarding PEP
    /// naming the next node (zl-zipline#219).
    pub fn new_vsapi_visa_forward_only(
        issuer_id: u64,
        expires: SystemTime,
        next_hop: IpAddr,
    ) -> vsapi_types::Visa {
        vsapi_types::Visa {
            issuer_id,
            config: 1,
            expires,
            visa_type: vsapi_types::VisaType::ForwardOnly,
            dock_pep: None,
            fwd_pep: Some(vsapi_types::FwdPep {
                next_hop,
                style: vsapi_types::FwdPepStyle::OneWay,
            }),
            cons: None,
            prev_hop: None,
        }
    }

    /// A binding whose ingress is stream `tether` on `link`, forwarding to
    /// stream 1 on the same link: the tests that use it care about one
    /// link only.
    pub fn binding_on(link: LinkId, tether: StreamId) -> StreamBinding {
        StreamBinding {
            ingress: ForwardingEntry(link, tether),
            egress: ForwardingEntry(link, 1),
        }
    }

    /// A ZPR address used as the next hop of forward-only visas in tests.
    fn next_hop_addr() -> IpAddr {
        "fd5a:5052:8::99".parse().unwrap()
    }

    /// A five-tuple for a TCP flow, used to probe the lookup table.
    fn tcp_tuple(src: &str, dst: &str, dst_port: u16) -> FiveTuple {
        FiveTuple {
            src_address: IpAddress::new_from_std_v6(&src.parse().unwrap()),
            dst_address: IpAddress::new_from_std_v6(&dst.parse().unwrap()),
            l3_type: L3Type::Ipv6,
            l4_protocol: ip_number::TCP,
            src_port: 20345,
            dst_port,
        }
    }

    /// Add a dummy peer to the assembly's peer table and return its link ID.
    fn add_dummy_peer(asm: &Assembly, last_octet: u8) -> LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let key = entry.key();
        entry
            .insert(create_dummy_peer_state(
                key,
                LinkType::Internal,
                SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, last_octet)), 443),
                net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 4, last_octet)),
            ))
            .get()
    }

    /// Insert a full TCP visa client -> service:80 that the lookup table
    /// must keep matching while forward-only visas come and go.
    fn insert_full_visa(visa_table: &mut VisaTable, visa_id: u64) -> FiveTuple {
        let client: Ipv6Addr = "fd5a:5052:8::1".parse().unwrap();
        let service: Ipv6Addr = "fd5a:5052:8::10".parse().unwrap();
        let expires_ms = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            + Duration::from_secs(3600))
        .as_millis() as i64;
        let visa = make_tcp_visa(visa_id, &client, 0, &service, 80, 100, expires_ms);
        visa_table.insert_visa(visa).unwrap();
        tcp_tuple("fd5a:5052:8::1", "fd5a:5052:8::10", 80)
    }

    /// A forward-only visa is stored and resolves to its forwarding PEP's
    /// next hop, but it has no five-tuple, so it must never match a new
    /// flow -- not even one that would match an all-wildcard visa.
    #[test]
    fn test_forward_only_visa_is_stored_but_never_matches_traffic() {
        let mut visa_table = VisaTable::new();
        let visa_id = visa_table
            .insert_visa(new_vsapi_visa_forward_only(
                5000,
                never_expires(),
                next_hop_addr(),
            ))
            .expect("a well-formed forward-only visa must be accepted");

        assert!(visa_table.table.contains_key(&visa_id));
        assert_eq!(
            visa_table.get_visa_next_hop_addr(visa_id).unwrap(),
            IpAddress::new_from_std(&next_hop_addr())
        );
        assert_eq!(visa_table.match_traffic(&FiveTuple::default()), None);
        assert_eq!(
            visa_table.match_traffic(&tcp_tuple("fd5a:5052:8::1", "fd5a:5052:8::99", 80)),
            None
        );
        assert!(visa_table.table[&visa_id].get_tc().is_none());
    }

    /// Revocation, expiry and link loss remove a forward-only visa and
    /// withdraw its forwarding entries. Each removal rebuilds the lookup
    /// table, which must still match the surviving full visa.
    #[tokio::test] // tokio: create_dummy_peer_state spawns a dummy task
    async fn test_forward_only_visa_removal_paths() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));
        let link_a = add_dummy_peer(&asm, 1);
        let peer_a = asm.peer_table.get(link_a).unwrap();
        let mut visa_table = asm.visa_table.write().unwrap();
        let full_tuple = insert_full_visa(&mut visa_table, 4000);

        // Insert a forward-only visa with one forwarding entry on link A.
        let mut add_fwd_only = |visa_id: VisaId, expires: SystemTime| {
            visa_table
                .insert_visa(new_vsapi_visa_forward_only(
                    visa_id,
                    expires,
                    next_hop_addr(),
                ))
                .unwrap();
            let tether = peer_a
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link_a, 1),
                    visa_id,
                })
                .unwrap();
            visa_table
                .bind(visa_id, binding_on(link_a, tether))
                .unwrap();
            tether
        };
        let tether_revoked = add_fwd_only(5001, never_expires());
        let _ = add_fwd_only(5002, ALREADY_EXPIRED);
        let _ = add_fwd_only(5003, never_expires());
        assert_eq!(peer_a.pft.len(), 3);

        // Revocation returns the withdrawn entry.
        let withdrawn = visa_table.revoke(&asm.peer_table, 5001).unwrap();
        assert!(withdrawn == vec![ForwardingEntry(link_a, tether_revoked)]);
        assert!(!visa_table.table.contains_key(&5001));
        assert_eq!(visa_table.match_traffic(&full_tuple), Some(4000));

        // Expiry.
        visa_table.handle_expirations(&asm.peer_table);
        assert!(!visa_table.table.contains_key(&5002));
        assert_eq!(visa_table.match_traffic(&full_tuple), Some(4000));

        // Link loss.
        visa_table.revoke_for_link(link_a, &asm.peer_table);
        assert!(!visa_table.table.contains_key(&5003));
        assert_eq!(visa_table.match_traffic(&full_tuple), Some(4000));
        assert_eq!(peer_a.pft.len(), 0);
    }

    /// A visa whose shape does not match its type is refused with an error,
    /// never a panic: these come from the visa service, a trust boundary.
    #[test]
    fn test_malformed_visas_are_refused() {
        let mut visa_table = VisaTable::new();

        let mut full_without_dock = new_vsapi_visa_tcp_default(6001, never_expires());
        full_without_dock.dock_pep = None;

        let mut fwd_only_without_fwd =
            new_vsapi_visa_forward_only(6002, never_expires(), next_hop_addr());
        fwd_only_without_fwd.fwd_pep = None;

        let fwd_only_unspecified_next_hop =
            new_vsapi_visa_forward_only(6003, never_expires(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));

        let mut fwd_only_with_dock = new_vsapi_visa_tcp_default(6004, never_expires());
        fwd_only_with_dock.visa_type = vsapi_types::VisaType::ForwardOnly;
        fwd_only_with_dock.fwd_pep = Some(vsapi_types::FwdPep {
            next_hop: next_hop_addr(),
            style: vsapi_types::FwdPepStyle::OneWay,
        });

        for visa in [
            full_without_dock,
            fwd_only_without_fwd,
            fwd_only_unspecified_next_hop,
            fwd_only_with_dock,
        ] {
            let id = visa.issuer_id;
            assert!(
                matches!(
                    visa_table.insert_visa(visa),
                    Err(VisaTableError::ParseError(_))
                ),
                "visa {id} must be refused"
            );
        }
        assert!(visa_table.table.is_empty());
        assert!(visa_table.timeout_queue.is_empty());
    }

    #[test]
    fn test_timeouts() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));

        let one_second = std::time::Duration::from_secs(1);
        let visa1 = 12345;
        let visa2 = 67890;
        let visa3 = 234;
        let mut visa_table = asm.visa_table.write().unwrap();
        let v1 = new_vsapi_visa_tcp_default(visa1 as u64, ALREADY_EXPIRED); // An element that will timeout immediately
        let v2 = new_vsapi_visa_tcp_default(visa2 as u64, never_expires()); // An element that won't timeout
        let v3 = new_vsapi_visa_tcp_default(visa3 as u64, (Utc::now() + one_second).into()); // An element that will time out in a second
        let _ = visa_table.insert_visa(v1);
        let _ = visa_table.insert_visa(v2);
        let _ = visa_table.insert_visa(v3); // An element that will time out in a second

        assert_eq!(3, visa_table.table.len());
        assert_eq!(3, visa_table.timeout_queue.len());
        assert_eq!(true, visa_table.table.contains_key(&visa1));
        assert_eq!(true, visa_table.table.contains_key(&visa2));
        assert_eq!(true, visa_table.table.contains_key(&visa3));

        visa_table.handle_expirations(&asm.peer_table);

        assert_eq!(2, visa_table.table.len());
        assert_eq!(2, visa_table.timeout_queue.len());
        assert_eq!(false, visa_table.table.contains_key(&visa1));
        assert_eq!(true, visa_table.table.contains_key(&visa2));
        assert_eq!(true, visa_table.table.contains_key(&visa3));

        std::thread::sleep(one_second);

        visa_table.handle_expirations(&asm.peer_table);

        assert_eq!(1, visa_table.table.len());
        assert_eq!(1, visa_table.timeout_queue.len());
        assert_eq!(false, visa_table.table.contains_key(&visa1));
        assert_eq!(true, visa_table.table.contains_key(&visa2));
        assert_eq!(false, visa_table.table.contains_key(&visa3));

        assert!(visa_table.revoke(&asm.peer_table, visa2).is_ok());

        assert_eq!(0, visa_table.table.len());
        assert_eq!(1, visa_table.timeout_queue.len());
        assert_eq!(false, visa_table.table.contains_key(&visa1));
        assert_eq!(false, visa_table.table.contains_key(&visa2));
        assert_eq!(false, visa_table.table.contains_key(&visa3));
    }

    #[tokio::test] // must be tokio::test because we create a dummy task in create_dummy_peer_state()
    async fn test_remove_forwarding_entries() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));
        let entry = asm.peer_table.vacant_entry().unwrap();
        let entry_key = entry.key();
        let link_id = entry
            .insert(create_dummy_peer_state(
                entry_key,
                LinkType::Internal,
                SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
            ))
            .get();

        let one_second = std::time::Duration::from_secs(1);
        let visa1 = 12345;
        let visa2 = 986;
        let pep1 = PftPep {
            next_hop: ForwardingEntry(link_id, 1),
            visa_id: visa1,
        };

        let pep2 = PftPep {
            next_hop: ForwardingEntry(link_id, 2),
            visa_id: visa2,
        };

        let peer_state = asm
            .peer_table
            .get(link_id)
            .expect("Failed to get peer_state");

        let tether_id1 = peer_state.pft.insert(pep1).expect("Failed to insert PEP");

        let tether_id2 = peer_state.pft.insert(pep2).expect("Failed to insert PEP");
        assert_eq!(2, peer_state.pft.len());

        let mut visa_table = asm.visa_table.write().unwrap();
        let v1 = new_vsapi_visa_tcp_default(visa1 as u64, never_expires()); // An element that won't timeout
        let v2 = new_vsapi_visa_tcp_default(visa2 as u64, (Utc::now() + one_second).into()); // An element that will time out in a second
        let _ = visa_table.insert_visa(v1);
        let _ = visa_table.insert_visa(v2);
        assert!(
            visa_table
                .bind(visa1, binding_on(link_id, tether_id1))
                .is_ok()
        );
        assert!(
            visa_table
                .bind(visa2, binding_on(link_id, tether_id2))
                .is_ok()
        );

        std::thread::sleep(one_second);

        visa_table.handle_expirations(&asm.peer_table);
        assert_eq!(1, peer_state.pft.len());

        assert!(visa_table.revoke(&asm.peer_table, visa1).is_ok());
        assert_eq!(0, peer_state.pft.len());
    }

    #[tokio::test]
    async fn test_revoke_for_link_revokes_matching_visa() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));

        let entry = asm.peer_table.vacant_entry().unwrap();
        let entry_key = entry.key();
        let link_a = entry
            .insert(create_dummy_peer_state(
                entry_key,
                LinkType::Internal,
                SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
            ))
            .get();

        let visa_id = 1000;
        let mut visa_table = asm.visa_table.write().unwrap();
        let v = new_vsapi_visa_tcp_default(visa_id as u64, never_expires());
        let _ = visa_table.insert_visa(v);

        let peer_state = asm.peer_table.get(link_a).unwrap();
        let pep = PftPep {
            next_hop: ForwardingEntry(link_a, 1),
            visa_id,
        };
        let tether_id = peer_state.pft.insert(pep).unwrap();
        visa_table
            .bind(visa_id, binding_on(link_a, tether_id))
            .unwrap();

        visa_table.revoke_for_link(link_a, &asm.peer_table);

        assert!(!visa_table.table.contains_key(&visa_id));
        assert_eq!(peer_state.pft.len(), 0);
    }

    #[tokio::test]
    async fn test_revoke_for_link_spares_unrelated_visa() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
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

        let visa_id = 200;
        let mut visa_table = asm.visa_table.write().unwrap();
        let v = new_vsapi_visa_tcp_default(visa_id as u64, never_expires());
        let _ = visa_table.insert_visa(v);

        let peer_b = asm.peer_table.get(link_b).unwrap();
        let pep = PftPep {
            next_hop: ForwardingEntry(link_b, 1),
            visa_id,
        };
        let tether_id = peer_b.pft.insert(pep).unwrap();
        visa_table
            .bind(visa_id, binding_on(link_b, tether_id))
            .unwrap();

        visa_table.revoke_for_link(link_a, &asm.peer_table);

        assert!(visa_table.table.contains_key(&visa_id));
        assert_eq!(peer_b.pft.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_for_link_full_revocation_across_links() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
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
        let pep_a = PftPep {
            next_hop: ForwardingEntry(link_a, 1),
            visa_id,
        };
        let tether_a = peer_a.pft.insert(pep_a).unwrap();
        visa_table
            .bind(visa_id, binding_on(link_a, tether_a))
            .unwrap();

        let peer_b = asm.peer_table.get(link_b).unwrap();
        let pep_b = PftPep {
            next_hop: ForwardingEntry(link_b, 1),
            visa_id,
        };
        let tether_b = peer_b.pft.insert(pep_b).unwrap();
        visa_table
            .bind(visa_id, binding_on(link_b, tether_b))
            .unwrap();

        visa_table.revoke_for_link(link_a, &asm.peer_table);

        assert!(!visa_table.table.contains_key(&visa_id));
        assert_eq!(peer_a.pft.len(), 0);
        assert_eq!(peer_b.pft.len(), 0);
    }

    /// Revoking for a link must hand back every withdrawn forwarding entry —
    /// including those on *surviving* links — so the caller can notify those
    /// peers (zipline#21). The caller filters out the dying link's own entry.
    #[tokio::test]
    async fn test_revoke_for_link_returns_surviving_link_entries() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
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
        let pep_a = PftPep {
            next_hop: ForwardingEntry(link_a, 1),
            visa_id,
        };
        let tether_a = peer_a.pft.insert(pep_a).unwrap();
        visa_table
            .bind(visa_id, binding_on(link_a, tether_a))
            .unwrap();

        let peer_b = asm.peer_table.get(link_b).unwrap();
        let pep_b = PftPep {
            next_hop: ForwardingEntry(link_b, 1),
            visa_id,
        };
        let tether_b = peer_b.pft.insert(pep_b).unwrap();
        visa_table
            .bind(visa_id, binding_on(link_b, tether_b))
            .unwrap();

        let withdrawn = visa_table.revoke_for_link(link_a, &asm.peer_table);

        assert_eq!(withdrawn.len(), 2);
        assert!(withdrawn.contains(&ForwardingEntry(link_a, tether_a)));
        assert!(
            withdrawn.contains(&ForwardingEntry(link_b, tether_b)),
            "the surviving link's entry must be returned so its peer can be notified"
        );
    }

    #[tokio::test]
    async fn test_revoke_for_link_rebuilds_lookup_table() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
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

        let client1_addr: Ipv6Addr = "fd5a:5052:8::1".parse().unwrap();
        let client2_addr: Ipv6Addr = "fd5a:5052:8::2".parse().unwrap();
        let service_addr: Ipv6Addr = "fd5a:5052:8::10".parse().unwrap();

        let expires_ms = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            + Duration::from_secs(3600))
        .as_millis() as i64;

        let visa1_raw = make_tcp_visa(4000, &client1_addr, 0, &service_addr, 80, 100, expires_ms);
        let visa2_raw = make_tcp_visa(4001, &client2_addr, 0, &service_addr, 80, 100, expires_ms);

        let mut visa_table = asm.visa_table.write().unwrap();
        let visa1_id = visa_table.insert_visa(visa1_raw).unwrap();
        let visa2_id = visa_table.insert_visa(visa2_raw).unwrap();

        let peer_a = asm.peer_table.get(link_a).unwrap();
        let pep_a = PftPep {
            next_hop: ForwardingEntry(link_a, 1),
            visa_id: visa1_id,
        };
        let tether_a = peer_a.pft.insert(pep_a).unwrap();
        visa_table
            .bind(visa1_id, binding_on(link_a, tether_a))
            .unwrap();

        let peer_b = asm.peer_table.get(link_b).unwrap();
        let pep_b = PftPep {
            next_hop: ForwardingEntry(link_b, 1),
            visa_id: visa2_id,
        };
        let tether_b = peer_b.pft.insert(pep_b).unwrap();
        visa_table
            .bind(visa2_id, binding_on(link_b, tether_b))
            .unwrap();

        visa_table.revoke_for_link(link_a, &asm.peer_table);

        let visa1_tuple = FiveTuple {
            src_address: IpAddress::new_from_std_v6(&client1_addr),
            dst_address: IpAddress::new_from_std_v6(&service_addr),
            l3_type: L3Type::Ipv6,
            l4_protocol: ip_number::TCP,
            src_port: 20345,
            dst_port: 80,
        };
        let visa2_tuple = FiveTuple {
            src_address: IpAddress::new_from_std_v6(&client2_addr),
            dst_address: IpAddress::new_from_std_v6(&service_addr),
            l3_type: L3Type::Ipv6,
            l4_protocol: ip_number::TCP,
            src_port: 20346,
            dst_port: 80,
        };

        assert_eq!(visa_table.match_traffic(&visa1_tuple), None);
        assert_eq!(visa_table.match_traffic(&visa2_tuple), Some(visa2_id));
    }

    /// Tenet (ZODE_LINKS.md): visas are immutable. Binding streams under a
    /// visa leaves the stored visa exactly as granted; the bindings live
    /// beside it.
    #[test]
    fn test_binding_leaves_the_visa_unchanged() {
        let mut visa_table = VisaTable::new();
        let granted = new_vsapi_visa_forward_only(5100, never_expires(), next_hop_addr());
        visa_table.insert_visa(granted.clone()).unwrap();
        let bindings = [
            StreamBinding {
                ingress: ForwardingEntry(1, 10),
                egress: ForwardingEntry(2, 20),
            },
            StreamBinding {
                ingress: ForwardingEntry(3, 30),
                egress: ForwardingEntry(2, 21),
            },
        ];
        for binding in &bindings {
            visa_table.bind(5100, binding.clone()).unwrap();
        }

        assert_eq!(visa_table.get(5100).unwrap().visa(), &granted);
        assert_eq!(visa_table.bindings(5100), &bindings);
    }

    /// A binding needs a held visa.
    #[test]
    fn test_bind_to_an_unknown_visa_is_refused() {
        let mut visa_table = VisaTable::new();
        let binding = StreamBinding {
            ingress: ForwardingEntry(1, 10),
            egress: ForwardingEntry(2, 20),
        };
        assert!(matches!(
            visa_table.bind(5101, binding),
            Err(VisaTableError::NotFound(5101))
        ));
        assert!(visa_table.bindings(5101).is_empty());
    }

    /// g88 q4 (operator): a visa ID always names the same visa. Inserting
    /// an ID already held succeeds and drops the incoming visa unread: the
    /// held visa, its bindings, its lookup entry and its single timeout
    /// entry are unchanged, even when the incoming visa differs or would
    /// not even parse.
    #[test]
    fn test_inserting_a_held_visa_id_is_an_idempotent_no_op() {
        let mut visa_table = VisaTable::new();
        let full_tuple = insert_full_visa(&mut visa_table, 5200);
        let granted = visa_table.get(5200).unwrap().visa().clone();
        let binding = StreamBinding {
            ingress: ForwardingEntry(1, 10),
            egress: ForwardingEntry(2, 20),
        };
        visa_table.bind(5200, binding.clone()).unwrap();

        let mut malformed = new_vsapi_visa_tcp_default(5200, ALREADY_EXPIRED);
        malformed.dock_pep = None;
        let different = new_vsapi_visa_forward_only(5200, ALREADY_EXPIRED, next_hop_addr());
        for incoming in [different, malformed] {
            assert_eq!(visa_table.insert_visa(incoming).unwrap(), 5200);
        }

        assert_eq!(visa_table.get(5200).unwrap().visa(), &granted);
        assert_eq!(visa_table.bindings(5200), &[binding]);
        assert_eq!(visa_table.timeout_queue.len(), 1);
        assert_eq!(visa_table.match_traffic(&full_tuple), Some(5200));
    }

    /// F3 (zl-zipline#251): losing the egress side of a binding revokes the
    /// visa too, and removes the ingress PFT entry that forwarded to the
    /// lost link. The ingress entry is returned so its requestor can be
    /// told.
    #[tokio::test] // tokio: create_dummy_peer_state spawns a dummy task
    async fn test_revoke_for_link_revokes_on_the_egress_side() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));
        let link_a = add_dummy_peer(&asm, 1);
        let link_b = add_dummy_peer(&asm, 2);
        let mut visa_table = asm.visa_table.write().unwrap();
        visa_table
            .insert_visa(new_vsapi_visa_forward_only(
                5300,
                never_expires(),
                next_hop_addr(),
            ))
            .unwrap();
        let peer_a = asm.peer_table.get(link_a).unwrap();
        let tether = peer_a
            .pft
            .insert(PftPep {
                next_hop: ForwardingEntry(link_b, 42),
                visa_id: 5300,
            })
            .unwrap();
        visa_table
            .bind(
                5300,
                StreamBinding {
                    ingress: ForwardingEntry(link_a, tether),
                    egress: ForwardingEntry(link_b, 42),
                },
            )
            .unwrap();

        let withdrawn = visa_table.revoke_for_link(link_b, &asm.peer_table);

        assert!(withdrawn == vec![ForwardingEntry(link_a, tether)]);
        assert!(!visa_table.contains(5300));
        assert!(visa_table.bindings(5300).is_empty());
        assert_eq!(peer_a.pft.len(), 0);
    }

    /// Revocation and expiry remove a visa's bindings with it, so a visa
    /// granted again later under the same ID starts with none.
    #[tokio::test] // tokio: create_dummy_peer_state spawns a dummy task
    async fn test_revoke_and_expiry_remove_bindings() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));
        let link = add_dummy_peer(&asm, 1);
        let mut visa_table = asm.visa_table.write().unwrap();
        for (visa_id, expires) in [(5400, never_expires()), (5401, ALREADY_EXPIRED)] {
            visa_table
                .insert_visa(new_vsapi_visa_tcp_default(visa_id, expires))
                .unwrap();
            let tether = asm
                .peer_table
                .get(link)
                .unwrap()
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link, 1),
                    visa_id,
                })
                .unwrap();
            visa_table.bind(visa_id, binding_on(link, tether)).unwrap();
        }

        visa_table.revoke(&asm.peer_table, 5400).unwrap();
        visa_table.handle_expirations(&asm.peer_table);

        for visa_id in [5400, 5401] {
            assert!(visa_table.bindings(visa_id).is_empty());
            visa_table
                .insert_visa(new_vsapi_visa_tcp_default(visa_id, never_expires()))
                .unwrap();
            assert!(visa_table.bindings(visa_id).is_empty());
        }
    }

    #[test]
    fn test_match_traffic() {
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = Arc::new(create_assembly(builder));

        let mut visa_table = asm.visa_table.write().unwrap();

        let client1_addr: Ipv6Addr = "fd5a:5052:8::1".parse().unwrap();
        let client2_addr: Ipv6Addr = "fd5a:5052:8::2".parse().unwrap();
        let service_addr: Ipv6Addr = "fd5a:5052:8::10".parse().unwrap();

        let expires_ms = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            + Duration::from_millis(10000))
        .as_millis() as i64;

        let visa1 = make_tcp_visa(1000, &client1_addr, 0, &service_addr, 80, 100, expires_ms);
        let visa2 = make_tcp_visa(1001, &client2_addr, 0, &service_addr, 80, 100, expires_ms);
        let v1 = new_vsapi_visa_tcp_default(12345, never_expires());
        let _ = visa_table.insert_visa(v1);

        let vid = visa_table.insert_visa(visa1).unwrap();
        assert_eq!(vid, 1000);
        let vid = visa_table.insert_visa(visa2).unwrap();
        assert_eq!(vid, 1001);

        let traffic = FiveTuple {
            src_address: IpAddress::new_from_std_v6(&client1_addr),
            dst_address: IpAddress::new_from_std_v6(&service_addr),
            l3_type: L3Type::Ipv6,
            l4_protocol: ip_number::TCP,
            src_port: 20345,
            dst_port: 80,
        };
        let matched = visa_table.match_traffic(&traffic);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap(), 1000);
    }
}
