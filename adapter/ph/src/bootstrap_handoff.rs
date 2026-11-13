//! The bootstrap-visa hand-off (zl-zipline#252, ZODE_LINKS.md
//! "Joining through the relay", J4 and rule 9).
//!
//! A joining Zode has no VS-API session, so it cannot ask the visa service
//! for the visas that would let it open one. When the joiner's initial link
//! comes up, its relay asks the visa service for them on the joiner's
//! behalf (J2, J3) and gets two pairs back: the relay's own copies, which it
//! installs, and the joiner's copies, which it hands over in a ZDP
//! `Bootstrap Visas` message (type 146) right after Hello (J4).
//!
//! Each pair is the joiner's VS-API flow in both directions:
//! - **forward**: `joiner:0 -> vs.zpr:VSAPI`, TCP, a full visa. The
//!   joiner's copy forwards to the relay (`fwdPep.nextHop`).
//! - **reverse**: `vs.zpr:VSAPI -> joiner:0`, TCP, a full visa. The joiner
//!   is its egress, so its copy has no forwarding PEP.
//!
//! The joiner trusts a hand-off only as far as it must ([check_handoff]).
//! It accepts one only on its initial link, after Hello, with no VS-API
//! session yet, and only exactly its own two VS-API visas, unexpired. A
//! relay that lies can then affect only the joiner's VS-API flow, which it
//! carries anyway.
//!
//! **Bound to the link (rule 9).** The installed visas are recorded on the
//! link's peer-table entry ([HandoffRecord]); `Assembly::drop_peer` revokes
//! them when the link is lost, so nothing learned over a dead link
//! survives. Every return to the relay is a new join with fresh visas
//! (rule 11a).
//!
//! **The joiner's egress before topology** (coordinator call). Until the
//! joiner's first `setTopology` names its relay, F1 has no topology entry
//! to find the relay by. The forward visa's next hop is the relay's ZPR
//! address, so it is held on the record as the initial link's peer address
//! ([pre_topology_relay_cn]) until that `setTopology` arrives
//! ([topology_names_relay]); after that, never again, even across
//! redials. It is the one exception to F1's "address from
//! topology", and it is never taken from Hello.
//!
//! **Visas are immutable** (core tenet). Installing a visa ID this Zode
//! already holds is an idempotent no-op ([VisaTable::insert_visa]); such a
//! visa was not learned over this link, so it is not recorded on it.
//!
//! [VisaTable::insert_visa]: crate::visa_table::VisaTable::insert_visa

use crate::link_state::{LinkState, LinkType};
use crate::peer_table::PeerTable;
use crate::prelude::*;
use crate::visa_table::VisaTable;
use std::net::IpAddr;
use std::time::SystemTime;
use zpr::addrs::{VISA_SERVICE_ADDR, VISA_SERVICE_PORT};
use zpr::vsapi_types::{DockPepType, Visa, VisaType};
use zpr_utils::net_defs::IpAddress;

/// How many visas a hand-off carries: the joiner's VS-API flow in each
/// direction.
pub const HANDOFF_VISA_COUNT: usize = 2;

/// Why a hand-off was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HandoffError {
    /// The message body is not a well-formed hand-off.
    #[error("malformed Bootstrap Visas message")]
    Malformed,
    /// The link the hand-off arrived on is gone.
    #[error("the link is gone")]
    LinkGone,
    /// Hand-offs travel on Zode links only.
    #[error("not a Zode link")]
    NotZodeLink,
    /// The link is not Active: a hand-off is never part of Hello.
    #[error("the link is not Active (a hand-off never comes inside Hello)")]
    NotActive,
    /// The peer's verified CN is not this Zode's configured initial-link
    /// CN (or this Zode has no initial link).
    #[error("not from this Zode's initial link")]
    NotInitialLink,
    /// This Zode already has a VS-API session, so it needs no bootstrap
    /// visas.
    #[error("this Zode already has a VS-API session")]
    SessionUp,
    /// A hand-off carries exactly [HANDOFF_VISA_COUNT] visas.
    #[error("the hand-off carries {0} visas, not {HANDOFF_VISA_COUNT}")]
    WrongCount(usize),
    /// The visa ID is below `MIN_VISA_ID`, the range of a node's own
    /// visas, which the visa service never issues.
    #[error("visa {0} has a reserved ID")]
    ReservedId(VisaId),
    /// The two visas are not exactly one forward and one reverse VS-API
    /// visa for this Zode, with distinct IDs.
    #[error("the visas are not exactly this Zode's forward and reverse VS-API visas")]
    WrongShape,
    /// The visa has expired.
    #[error("visa {0} has expired")]
    Expired(VisaId),
    /// This link already has its hand-off: there is one per link.
    #[error("this link already has a hand-off")]
    AlreadyHandedOff,
    /// The visa table refused the visa.
    #[error("could not install visa {0}")]
    InstallFailed(VisaId),
}

/// Encode a hand-off body: a count byte, then for each visa a big-endian
/// u16 length followed by the packed Cap'n Proto `Visa`.
///
/// Fails with [HandoffError::Malformed] only if a packed visa does not fit
/// the u16 length.
// Used by the relay's hand-off, which comes with zl-zipline#252's relay
// half (t206); until then only the tests encode.
#[allow(dead_code)]
pub fn encode(visas: &[Visa; HANDOFF_VISA_COUNT]) -> Result<Vec<u8>, HandoffError> {
    let mut body = vec![HANDOFF_VISA_COUNT as u8];
    for visa in visas {
        let packed = crate::tlv::pack_visa(visa);
        let len = u16::try_from(packed.len()).map_err(|_| HandoffError::Malformed)?;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&packed);
    }
    Ok(body)
}

/// Decode a hand-off body written by [encode]. Refuses a count other than
/// [HANDOFF_VISA_COUNT], a length running past the end, a malformed visa
/// (including an expiry this node cannot hold) and trailing bytes. The
/// bytes come from the peer: nothing here panics.
pub fn decode(body: &[u8]) -> Result<Vec<Visa>, HandoffError> {
    let (&count, mut rest) = body.split_first().ok_or(HandoffError::Malformed)?;
    if count as usize != HANDOFF_VISA_COUNT {
        return Err(HandoffError::WrongCount(count as usize));
    }
    let mut visas = Vec::with_capacity(HANDOFF_VISA_COUNT);
    for _ in 0..HANDOFF_VISA_COUNT {
        let (len, after_len) = rest
            .split_first_chunk::<2>()
            .ok_or(HandoffError::Malformed)?;
        let len = u16::from_be_bytes(*len) as usize;
        if after_len.len() < len {
            return Err(HandoffError::Malformed);
        }
        let (packed, after_visa) = after_len.split_at(len);
        visas.push(crate::tlv::unpack_visa(packed).ok_or(HandoffError::Malformed)?);
        rest = after_visa;
    }
    if !rest.is_empty() {
        return Err(HandoffError::Malformed);
    }
    Ok(visas)
}

/// What [check_handoff] knows about the link a hand-off arrived on and
/// about this Zode, gathered by the caller so the check itself is pure.
#[derive(Debug, Clone)]
pub struct HandoffContext<'a> {
    /// The link's type: only a Zode link qualifies.
    pub link_type: LinkType,
    /// The link's state: only Active qualifies.
    pub link_state: LinkState,
    /// The peer's verified certificate CN, if keying verified one.
    pub peer_cn: Option<&'a str>,
    /// This Zode's configured initial-link CN, if it has an initial link.
    pub initial_link_cn: Option<&'a str>,
    /// Whether this Zode already has a VS-API session.
    pub vs_session_up: bool,
    /// This Zode's own ZPR address (`zpr_addr[0]`), the one the visa
    /// service mints its VS-API visas for.
    pub own_addr: Option<IpAddr>,
    /// The time to judge expiry against.
    pub now: SystemTime,
}

/// The joiner's strict checks on a hand-off (J4), in order:
///
/// 1. it arrived on a Zode link ([HandoffError::NotZodeLink]),
/// 2. which is Active, so never inside Hello ([HandoffError::NotActive]),
/// 3. whose peer's verified CN is this Zode's initial-link CN
///    ([HandoffError::NotInitialLink]);
/// 4. this Zode has no VS-API session yet ([HandoffError::SessionUp]);
/// 5. it carries exactly two visas ([HandoffError::WrongCount]),
/// 6. neither with a reserved ID ([HandoffError::ReservedId]),
/// 7. which are exactly one forward and one reverse VS-API visa for this
///    Zode, with distinct IDs ([HandoffError::WrongShape]),
/// 8. and neither has expired ([HandoffError::Expired]).
///
/// An expiry out of the range this node can hold never gets here: [decode]
/// refuses it ([crate::tlv::unpack_visa]).
///
/// Returns the visas as `[forward, reverse]`, whatever order they came in.
pub fn check_handoff(
    ctx: &HandoffContext,
    visas: Vec<Visa>,
) -> Result<[Visa; HANDOFF_VISA_COUNT], HandoffError> {
    if ctx.link_type != LinkType::NodeToNode {
        return Err(HandoffError::NotZodeLink);
    }
    if ctx.link_state != LinkState::Active {
        return Err(HandoffError::NotActive);
    }
    if ctx.peer_cn.is_none() || ctx.peer_cn != ctx.initial_link_cn {
        return Err(HandoffError::NotInitialLink);
    }
    if ctx.vs_session_up {
        return Err(HandoffError::SessionUp);
    }
    let [first, second] = <[Visa; HANDOFF_VISA_COUNT]>::try_from(visas)
        .map_err(|visas| HandoffError::WrongCount(visas.len()))?;
    if let Some(low) = [&first, &second]
        .into_iter()
        .find(|visa| visa.issuer_id < config::MIN_VISA_ID)
    {
        return Err(HandoffError::ReservedId(low.issuer_id));
    }
    let own_addr = ctx.own_addr.ok_or(HandoffError::WrongShape)?;
    let pair = if is_forward(&first, own_addr) && is_reverse(&second, own_addr) {
        [first, second]
    } else if is_forward(&second, own_addr) && is_reverse(&first, own_addr) {
        [second, first]
    } else {
        return Err(HandoffError::WrongShape);
    };
    // Two IDs for two visas: an ID always names one visa.
    if pair[0].issuer_id == pair[1].issuer_id {
        return Err(HandoffError::WrongShape);
    }
    if let Some(stale) = pair.iter().find(|visa| visa.expires <= ctx.now) {
        return Err(HandoffError::Expired(stale.issuer_id));
    }
    Ok(pair)
}

/// The flow a full TCP visa admits, from its dock PEP, as `(source,
/// source port, destination, destination port)`. `None` for any other
/// visa.
fn full_tcp_flow(visa: &Visa) -> Option<(IpAddr, u16, IpAddr, u16)> {
    if visa.visa_type != VisaType::Full {
        return None;
    }
    let dock = visa.dock_pep.as_ref()?;
    let DockPepType::TCP(tcp) = &dock.pep else {
        return None;
    };
    Some((
        dock.source_addr,
        tcp.source_port,
        dock.dest_addr,
        tcp.dest_port,
    ))
}

/// Is `visa` the joiner's forward VS-API visa: full TCP from `own_addr`,
/// any port, to `vs.zpr:VSAPI`, forwarding to a next hop (its relay) that
/// is neither unspecified nor `own_addr`?
fn is_forward(visa: &Visa, own_addr: IpAddr) -> bool {
    let flow_ok = full_tcp_flow(visa) == Some((own_addr, 0, VISA_SERVICE_ADDR, VISA_SERVICE_PORT));
    let hop_ok = visa
        .fwd_pep
        .as_ref()
        .is_some_and(|fwd| !fwd.next_hop.is_unspecified() && fwd.next_hop != own_addr);
    flow_ok && hop_ok
}

/// Is `visa` the joiner's reverse VS-API visa: full TCP from `vs.zpr:VSAPI`
/// to `own_addr`, any port, with no forwarding PEP (the joiner is its
/// egress)?
fn is_reverse(visa: &Visa, own_addr: IpAddr) -> bool {
    full_tcp_flow(visa) == Some((VISA_SERVICE_ADDR, VISA_SERVICE_PORT, own_addr, 0))
        && visa.fwd_pep.is_none()
}

/// What a Zode link's peer-table entry records about its bootstrap visas
/// (`PeerState::bootstrap_handoff`). There is at most one per link.
#[derive(Debug, Default)]
pub struct HandoffRecord {
    /// The visas installed for this link that this Zode did not already
    /// hold. Revoked when the link is lost (rule 9).
    visa_ids: Vec<VisaId>,
    /// Joiner only: the relay's ZPR address, from the forward visa's next
    /// hop. F1 uses it for the initial link until a `setTopology` names the
    /// relay ([topology_names_relay] clears it).
    relay_addr: Option<IpAddress>,
}

/// Install `visas` and record them on Zode link `link_id`'s peer entry, so
/// that losing the link revokes them (rule 9). `relay_addr` is the joiner's
/// relay address before topology (see the module documentation); a relay
/// installing its own copies passes `None`.
///
/// All or nothing: if the visa table refuses one visa, the ones this call
/// added are revoked again. A visa ID already held is left as it is and not
/// recorded (the tenet: an ID always names the same visa). Fails with
/// [HandoffError::AlreadyHandedOff] if the link already has a record.
///
/// The caller has checked the visas. This takes the visa-table write lock,
/// then the peer entry's record mutex (the same order as
/// [revoke_for_lost_link]), and never sends.
pub fn install_bound_to_link(
    asm: &Assembly,
    link_id: LinkId,
    visas: &[Visa],
    relay_addr: Option<IpAddress>,
) -> Result<(), HandoffError> {
    let mut visa_table = asm.visa_table.write().unwrap();
    let peer = asm.peer_table.get(link_id).ok_or(HandoffError::LinkGone)?;
    let mut record = peer.bootstrap_handoff.lock().unwrap();
    if record.is_some() {
        return Err(HandoffError::AlreadyHandedOff);
    }
    let mut added = Vec::with_capacity(visas.len());
    for visa in visas {
        let visa_id = visa.issuer_id;
        let held = visa_table.contains(visa_id);
        if let Err(e) = visa_table.insert_visa(visa.clone()) {
            warn!(target: VISA_MGMT, "{}: bootstrap visa {visa_id} refused by the visa table: {e}", asm.formatted_link_id(link_id));
            for added_id in added {
                // Nothing is bound to a visa installed a moment ago.
                let _ = visa_table.revoke(&asm.peer_table, added_id);
            }
            return Err(HandoffError::InstallFailed(visa_id));
        }
        if !held {
            added.push(visa_id);
        }
    }
    info!(target: VISA_MGMT, "{}: installed bootstrap visas {added:?} bound to the link", asm.formatted_link_id(link_id));
    *record = Some(HandoffRecord {
        visa_ids: added,
        relay_addr,
    });
    Ok(())
}

/// Joiner side: accept the `Bootstrap Visas` message `body` that arrived on
/// link `link_id`. Decodes it, runs [check_handoff], installs both visas
/// bound to the link with the forward visa's next hop as the relay's
/// address, and publishes the link on `Assembly::bootstrap_handoff` for the
/// VS-API worker (J5).
///
/// Runs on the node's LocalSet, like `Assembly::drop_peer`, and does not
/// await, so the link cannot be dropped between the checks and the install.
pub fn accept(asm: &Assembly, link_id: LinkId, body: &[u8]) -> Result<(), HandoffError> {
    let visas = decode(body)?;
    let config = asm.config.get();
    let checked = {
        let peer = asm.peer_table.get(link_id).ok_or(HandoffError::LinkGone)?;
        let fsm = &peer.link_state_machine;
        let peer_cn = peer.verified_peer_cn();
        let ctx = HandoffContext {
            link_type: fsm.get_link_type(),
            link_state: fsm.get_state(),
            peer_cn: peer_cn.as_deref(),
            initial_link_cn: config.initial_link.as_ref().map(|link| link.cn.as_str()),
            vs_session_up: asm.vs_session_up.load(std::sync::atomic::Ordering::Acquire),
            own_addr: config.zpr_addr.first().copied(),
            now: SystemTime::now(),
        };
        check_handoff(&ctx, visas)?
    };
    // check_handoff guarantees the forward visa's next hop. Once a
    // topology has named the relay, F1 alone decides: no address is held.
    let relay_addr = checked[0]
        .fwd_pep
        .as_ref()
        .map(|fwd| IpAddress::new_from_std(&fwd.next_hop))
        .filter(|_| !relay_named_by_topology(asm));
    install_bound_to_link(asm, link_id, &checked, relay_addr)?;
    asm.bootstrap_handoff.send_replace(Some(link_id));
    Ok(())
}

/// Rule 9: revoke the bootstrap visas recorded on link `link_id`'s peer
/// entry, and drop the record. Called by `Assembly::drop_peer` under the
/// visa-table write lock, before the entry leaves the peer table. Returns
/// the withdrawn forwarding entries, which the caller handles after it
/// releases the lock (zipline#9).
pub fn revoke_for_lost_link(
    visa_table: &mut VisaTable,
    peer_table: &PeerTable,
    link_id: LinkId,
) -> Vec<ForwardingEntry> {
    let Some(record) = peer_table
        .get(link_id)
        .and_then(|peer| peer.bootstrap_handoff.lock().unwrap().take())
    else {
        return Vec::new();
    };
    let mut withdrawn = Vec::new();
    for visa_id in record.visa_ids {
        // A visa already revoked (expired, or bound over this link and so
        // revoked by `revoke_for_link`) yields nothing.
        withdrawn.extend(visa_table.revoke(peer_table, visa_id).unwrap_or_default());
    }
    withdrawn
}

/// The joiner's egress before topology: the initial-link CN, if `addr` is
/// the relay address a hand-off recorded on the initial link's current
/// connection, and no topology has named the relay yet.
/// `Assembly::find_zode_egress_link` asks this only when no topology entry
/// has `addr`, and then checks the link as it does any other (up record,
/// Active, verified CN).
pub fn pre_topology_relay_cn(asm: &Assembly, addr: IpAddress) -> Option<String> {
    if relay_named_by_topology(asm) {
        return None;
    }
    let relay_cn = asm.config.get().initial_link.as_ref()?.cn.clone();
    let link_id = asm.zode_links.record(&relay_cn)?.link_id?;
    let peer = asm.peer_table.get(link_id)?;
    let held = peer.bootstrap_handoff.lock().unwrap().as_ref()?.relay_addr;
    (held == Some(addr)).then_some(relay_cn)
}

/// Whether a `setTopology` has named this Zode's relay
/// (`Assembly::relay_named_by_topology`, set by [topology_names_relay]).
fn relay_named_by_topology(asm: &Assembly) -> bool {
    asm.relay_named_by_topology
        .load(std::sync::atomic::Ordering::Acquire)
}

/// A `setTopology` named the relay `relay_cn` at `topology_addr`: from now
/// on, for the life of this node and across redials, F1 alone decides. So
/// remember that, and forget the relay address the hand-off recorded on
/// the initial link. If the two differ, the topology wins, with a warning.
/// Called by `zode_links::apply_topology`.
pub fn topology_names_relay(asm: &Assembly, relay_cn: &str, topology_addr: IpAddr) {
    asm.relay_named_by_topology
        .store(true, std::sync::atomic::Ordering::Release);
    let Some(link_id) = asm.zode_links.record(relay_cn).and_then(|r| r.link_id) else {
        return;
    };
    let Some(peer) = asm.peer_table.get(link_id) else {
        return;
    };
    let mut record = peer.bootstrap_handoff.lock().unwrap();
    let Some(held) = record.as_mut().and_then(|r| r.relay_addr.take()) else {
        return;
    };
    if held != IpAddress::new_from_std(&topology_addr) {
        warn!(target: LINK_STATE,
            "{}: the topology puts relay {relay_cn:?} at {topology_addr}, not {held} as its bootstrap hand-off said; using the topology",
            asm.formatted_link_id(link_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zode_links::tests::{bring_up, driven_zode, record_of, set_topology};
    use std::time::Duration;
    use tokio::task::LocalSet;
    use zpr::vsapi_types::{DockPep, EndpointT, FwdPep, FwdPepStyle, KeySet, TcpUdpPep};

    /// The joiner's own ZPR address.
    const OWN: &str = "fd5a:5052::b";
    /// The relay's ZPR address.
    const RELAY: &str = "fd5a:5052::2";
    /// The joiner's forward and reverse visa IDs.
    const FWD_ID: VisaId = 9001;
    const REV_ID: VisaId = 9002;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// An expiry well in the future, at whole milliseconds (visas carry
    /// their expiry at millisecond precision, so a round trip keeps it).
    fn later() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000)
    }

    /// A full TCP visa `id` from `src:sport` to `dst:dport`, forwarding to
    /// `next_hop` if given.
    fn tcp_visa(
        id: VisaId,
        (src, sport): (IpAddr, u16),
        (dst, dport): (IpAddr, u16),
        next_hop: Option<IpAddr>,
    ) -> Visa {
        Visa {
            issuer_id: id,
            config: 0,
            expires: later(),
            visa_type: VisaType::Full,
            dock_pep: Some(DockPep {
                source_addr: src,
                dest_addr: dst,
                session_key: KeySet::default(),
                pep: DockPepType::TCP(TcpUdpPep {
                    source_port: sport,
                    dest_port: dport,
                    endpoint: EndpointT::Any,
                }),
            }),
            fwd_pep: next_hop.map(|next_hop| FwdPep {
                next_hop,
                style: FwdPepStyle::OneWay,
            }),
            cons: None,
            prev_hop: None,
        }
    }

    /// The joiner's forward VS-API visa, as the visa service mints it.
    fn forward() -> Visa {
        tcp_visa(
            FWD_ID,
            (ip(OWN), 0),
            (VISA_SERVICE_ADDR, VISA_SERVICE_PORT),
            Some(ip(RELAY)),
        )
    }

    /// The joiner's reverse VS-API visa, as the visa service mints it.
    fn reverse() -> Visa {
        let mut visa = tcp_visa(
            REV_ID,
            (VISA_SERVICE_ADDR, VISA_SERVICE_PORT),
            (ip(OWN), 0),
            None,
        );
        visa.prev_hop = Some(ip(RELAY));
        visa
    }

    /// A context in which the hand-off of `[forward(), reverse()]` passes.
    fn good_ctx() -> HandoffContext<'static> {
        HandoffContext {
            link_type: LinkType::NodeToNode,
            link_state: LinkState::Active,
            peer_cn: Some("relay"),
            initial_link_cn: Some("relay"),
            vs_session_up: false,
            own_addr: Some(ip(OWN)),
            now: SystemTime::now(),
        }
    }

    /// Check `[first, second]` in [good_ctx].
    fn check_pair(first: Visa, second: Visa) -> Result<[Visa; 2], HandoffError> {
        check_handoff(&good_ctx(), vec![first, second])
    }

    // ---- codec ----

    #[test]
    fn test_codec_round_trip() {
        let body = encode(&[forward(), reverse()]).unwrap();
        assert_eq!(body[0], 2, "the count byte");
        assert_eq!(decode(&body).unwrap(), vec![forward(), reverse()]);
    }

    /// Every malformed body is refused: empty, cut short, a length past the
    /// end, a count of 1 or 3, trailing bytes, garbage instead of a visa.
    #[test]
    fn test_decode_refuses_malformed_bodies() {
        let body = encode(&[forward(), reverse()]).unwrap();
        let first_len = u16::from_be_bytes([body[1], body[2]]) as usize;

        assert_eq!(decode(&[]), Err(HandoffError::Malformed), "empty");
        assert_eq!(decode(&[2]), Err(HandoffError::Malformed), "no visas");
        assert_eq!(
            decode(&[2, 0]),
            Err(HandoffError::Malformed),
            "half a length"
        );
        assert_eq!(
            decode(&body[..body.len() - 1]),
            Err(HandoffError::Malformed),
            "short buffer"
        );
        let mut bad_len = body.clone();
        bad_len[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(decode(&bad_len), Err(HandoffError::Malformed), "bad length");
        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(
            decode(&trailing),
            Err(HandoffError::Malformed),
            "trailing bytes"
        );
        let mut garbage = body.clone();
        for b in &mut garbage[3..3 + first_len] {
            *b = 0xff;
        }
        assert_eq!(
            decode(&garbage),
            Err(HandoffError::Malformed),
            "garbage visa"
        );

        // A count of 1 or 3 is refused, even with that many visas behind it.
        let one = forward_only_body(&[forward()]);
        assert_eq!(decode(&one), Err(HandoffError::WrongCount(1)));
        let three = forward_only_body(&[forward(), reverse(), forward()]);
        assert_eq!(decode(&three), Err(HandoffError::WrongCount(3)));
        assert_eq!(decode(&[0]), Err(HandoffError::WrongCount(0)));
    }

    /// A body in the hand-off format with any number of visas, for the
    /// count tests ([encode] takes exactly two).
    fn forward_only_body(visas: &[Visa]) -> Vec<u8> {
        let mut body = vec![visas.len() as u8];
        for visa in visas {
            let packed = crate::tlv::pack_visa(visa);
            body.extend_from_slice(&(packed.len() as u16).to_be_bytes());
            body.extend_from_slice(&packed);
        }
        body
    }

    // ---- check_handoff: one negative per refusal ----

    /// The good hand-off passes, in either order, as [forward, reverse].
    #[test]
    fn test_check_accepts_the_pair_in_either_order() {
        assert_eq!(check_pair(forward(), reverse()), Ok([forward(), reverse()]));
        assert_eq!(check_pair(reverse(), forward()), Ok([forward(), reverse()]));
    }

    #[test]
    fn test_check_refuses_a_link_that_is_not_a_zode_link() {
        for link_type in [
            LinkType::NodeToAdapter,
            LinkType::AdapterToNode,
            LinkType::Internal,
        ] {
            let ctx = HandoffContext {
                link_type,
                ..good_ctx()
            };
            assert_eq!(
                check_handoff(&ctx, vec![forward(), reverse()]),
                Err(HandoffError::NotZodeLink)
            );
        }
    }

    /// Never inside Hello: any state but Active is refused.
    #[test]
    fn test_check_refuses_a_link_that_is_not_active() {
        for link_state in [LinkState::Keying, LinkState::Helloing, LinkState::Closing] {
            let ctx = HandoffContext {
                link_state,
                ..good_ctx()
            };
            assert_eq!(
                check_handoff(&ctx, vec![forward(), reverse()]),
                Err(HandoffError::NotActive)
            );
        }
    }

    /// Only the configured initial link's CN qualifies: another CN, no
    /// verified CN, or no initial link at all is refused.
    #[test]
    fn test_check_refuses_a_peer_that_is_not_the_initial_link() {
        let cases = [
            (Some("stranger"), Some("relay")),
            (None, Some("relay")),
            (Some("relay"), None),
            (None, None),
        ];
        for (peer_cn, initial_link_cn) in cases {
            let ctx = HandoffContext {
                peer_cn,
                initial_link_cn,
                ..good_ctx()
            };
            assert_eq!(
                check_handoff(&ctx, vec![forward(), reverse()]),
                Err(HandoffError::NotInitialLink),
                "peer {peer_cn:?}, initial link {initial_link_cn:?}"
            );
        }
    }

    #[test]
    fn test_check_refuses_once_a_vs_session_is_up() {
        let ctx = HandoffContext {
            vs_session_up: true,
            ..good_ctx()
        };
        assert_eq!(
            check_handoff(&ctx, vec![forward(), reverse()]),
            Err(HandoffError::SessionUp)
        );
    }

    #[test]
    fn test_check_refuses_other_than_two_visas() {
        assert_eq!(
            check_handoff(&good_ctx(), vec![]),
            Err(HandoffError::WrongCount(0))
        );
        assert_eq!(
            check_handoff(&good_ctx(), vec![forward()]),
            Err(HandoffError::WrongCount(1))
        );
        assert_eq!(
            check_handoff(&good_ctx(), vec![forward(), reverse(), forward()]),
            Err(HandoffError::WrongCount(3))
        );
    }

    /// An ID in a node's own range (below `MIN_VISA_ID`) is refused: the
    /// visa service never issues one, and a node's self-granted VS-API
    /// visas live there.
    #[test]
    fn test_check_refuses_a_reserved_id() {
        let mut low = reverse();
        low.issuer_id = config::MIN_VISA_ID - 1;
        assert_eq!(
            check_pair(forward(), low),
            Err(HandoffError::ReservedId(config::MIN_VISA_ID - 1))
        );
    }

    /// Anything but exactly one forward and one reverse VS-API visa for
    /// this Zode is refused.
    #[test]
    fn test_check_refuses_the_wrong_five_tuples() {
        let vs = (VISA_SERVICE_ADDR, VISA_SERVICE_PORT);
        let own = (ip(OWN), 0);
        let relay = Some(ip(RELAY));
        let other = ip("fd5a:5052::99");
        let mut udp = forward();
        if let Some(DockPep {
            pep: DockPepType::TCP(tcp),
            ..
        }) = udp.dock_pep.clone()
        {
            udp.dock_pep.as_mut().unwrap().pep = DockPepType::UDP(tcp);
        }
        let mut forward_only = forward();
        forward_only.visa_type = VisaType::ForwardOnly;
        let mut unspecified_hop = forward();
        unspecified_hop.fwd_pep.as_mut().unwrap().next_hop = ip("::");
        let mut no_dock = forward();
        no_dock.dock_pep = None;

        let wrong_forwards = [
            (
                "another port at the VS",
                tcp_visa(FWD_ID, own, (VISA_SERVICE_ADDR, 80), relay),
            ),
            ("another source", tcp_visa(FWD_ID, (other, 0), vs, relay)),
            (
                "a fixed source port",
                tcp_visa(FWD_ID, (ip(OWN), 4000), vs, relay),
            ),
            (
                "another destination",
                tcp_visa(FWD_ID, own, (other, VISA_SERVICE_PORT), relay),
            ),
            ("no next hop", tcp_visa(FWD_ID, own, vs, None)),
            (
                "its own address as next hop",
                tcp_visa(FWD_ID, own, vs, Some(ip(OWN))),
            ),
            ("an unspecified next hop", unspecified_hop),
            ("UDP", udp),
            ("forward-only", forward_only),
            ("no dock PEP", no_dock),
        ];
        for (what, visa) in wrong_forwards {
            assert_eq!(
                check_pair(visa, reverse()),
                Err(HandoffError::WrongShape),
                "forward with {what}"
            );
        }

        let wrong_reverses = [
            ("a next hop", tcp_visa(REV_ID, vs, own, relay)),
            (
                "another destination",
                tcp_visa(REV_ID, vs, (other, 0), None),
            ),
            (
                "a fixed destination port",
                tcp_visa(REV_ID, vs, (ip(OWN), 4000), None),
            ),
            (
                "another source port",
                tcp_visa(REV_ID, (VISA_SERVICE_ADDR, 80), own, None),
            ),
        ];
        for (what, visa) in wrong_reverses {
            assert_eq!(
                check_pair(forward(), visa),
                Err(HandoffError::WrongShape),
                "reverse with {what}"
            );
        }

        // Two of one kind, and a pair sharing one ID.
        assert_eq!(
            check_pair(forward(), forward()),
            Err(HandoffError::WrongShape)
        );
        let mut twin = reverse();
        twin.issuer_id = FWD_ID;
        assert_eq!(check_pair(forward(), twin), Err(HandoffError::WrongShape));
    }

    #[test]
    fn test_check_refuses_an_expired_visa() {
        let mut stale = reverse();
        stale.expires = SystemTime::now() - Duration::from_secs(1);
        assert_eq!(
            check_pair(forward(), stale),
            Err(HandoffError::Expired(REV_ID))
        );
    }

    /// Review round 1 (Copilot): a wire expiry this node cannot hold
    /// (`u64::MAX` ms: past Windows' `SystemTime` and chrono's range) is
    /// refused while decoding, before anything converts it. Built from the
    /// Cap'n Proto message directly, since no `SystemTime` can carry it.
    #[test]
    fn test_decode_refuses_an_out_of_range_expiry() {
        use zpr::write_to::WriteTo;
        let mut builder =
            capnp::message::TypedBuilder::<zpr::vsapi::v1::visa::Owned>::new_default();
        let mut root = builder.init_root();
        forward().write_to(&mut root);
        root.set_expiration(u64::MAX);
        let mut far = Vec::new();
        capnp::serialize_packed::write_message(&mut far, builder.borrow_inner()).unwrap();
        let rev = crate::tlv::pack_visa(&reverse());

        let mut body = vec![2];
        for packed in [&far, &rev] {
            body.extend_from_slice(&(packed.len() as u16).to_be_bytes());
            body.extend_from_slice(packed);
        }
        assert_eq!(decode(&body), Err(HandoffError::Malformed));
    }

    // ---- install, rule 9 and egress (t202) ----

    /// A joiner at [OWN] whose initial link to `relay` is up. Returns the
    /// assembly and the initial link's connection.
    fn joiner(port: u16) -> (Arc<Assembly>, LinkId, crate::zode_links::tests::EgressRx) {
        let (asm, egress) = driven_zode(OWN, "b", Some(&format!("relay@127.0.0.1:{port}")));
        crate::zode_links::start_initial_link(&asm);
        let link = record_of(&asm, "relay").link_id.unwrap();
        bring_up(&asm, link, "relay");
        (asm, link, egress)
    }

    /// The good hand-off's body.
    fn good_body() -> Vec<u8> {
        encode(&[forward(), reverse()]).unwrap()
    }

    fn holds(asm: &Assembly, visa_id: VisaId) -> bool {
        asm.visa_table.read().unwrap().contains(visa_id)
    }

    /// J4: the joiner installs both visas from its relay, records them on
    /// the link, and tells the VS-API worker which link carries them.
    #[tokio::test(start_paused = true)]
    async fn test_accept_installs_both_visas_bound_to_the_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7301);
                accept(&asm, link, &good_body()).unwrap();
                assert!(holds(&asm, FWD_ID) && holds(&asm, REV_ID));
                assert_eq!(*asm.bootstrap_handoff.borrow(), Some(link));
                // One hand-off per link: a second is refused.
                assert_eq!(
                    accept(&asm, link, &good_body()),
                    Err(HandoffError::AlreadyHandedOff)
                );
            })
            .await
    }

    /// A refused hand-off installs nothing and signals nothing.
    #[tokio::test(start_paused = true)]
    async fn test_refused_handoff_installs_nothing() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7302);
                asm.vs_session_up
                    .store(true, std::sync::atomic::Ordering::Release);
                assert_eq!(
                    accept(&asm, link, &good_body()),
                    Err(HandoffError::SessionUp)
                );
                asm.vs_session_up
                    .store(false, std::sync::atomic::Ordering::Release);
                let mut stale = reverse();
                stale.expires = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
                let body = encode(&[forward(), stale]).unwrap();
                assert_eq!(
                    accept(&asm, link, &body),
                    Err(HandoffError::Expired(REV_ID))
                );
                assert_eq!(accept(&asm, link, &[2, 0]), Err(HandoffError::Malformed));
                assert!(!holds(&asm, FWD_ID) && !holds(&asm, REV_ID));
                assert_eq!(*asm.bootstrap_handoff.borrow(), None);
                assert!(
                    asm.find_egress_link(IpAddress::new_from_std(&ip(RELAY)))
                        .is_none(),
                    "no relay address without a hand-off"
                );
            })
            .await
    }

    /// Rule 9: losing the initial link revokes both bootstrap visas and
    /// clears the hand-off signal.
    #[tokio::test(start_paused = true)]
    async fn test_link_loss_revokes_the_bootstrap_visas() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7303);
                accept(&asm, link, &good_body()).unwrap();
                asm.drop_peer(link);
                assert!(!holds(&asm, FWD_ID) && !holds(&asm, REV_ID));
                assert_eq!(*asm.bootstrap_handoff.borrow(), None);
            })
            .await
    }

    /// A visa ID the joiner already holds is left alone (the tenet), and so
    /// not revoked with the link: it was not learned over it.
    #[tokio::test(start_paused = true)]
    async fn test_a_held_visa_is_not_bound_to_the_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7304);
                asm.visa_table
                    .write()
                    .unwrap()
                    .insert_visa(reverse())
                    .unwrap();
                accept(&asm, link, &good_body()).unwrap();
                asm.drop_peer(link);
                assert!(!holds(&asm, FWD_ID));
                assert!(holds(&asm, REV_ID), "the held visa survives the link");
            })
            .await
    }

    /// Before topology, F1 finds the relay by the forward visa's next hop,
    /// over the initial link only; another address finds nothing.
    #[tokio::test(start_paused = true)]
    async fn test_relay_egress_before_topology() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7305);
                let relay = IpAddress::new_from_std(&ip(RELAY));
                assert_eq!(
                    asm.find_egress_link(relay),
                    None,
                    "nothing before the hand-off"
                );
                accept(&asm, link, &good_body()).unwrap();
                assert_eq!(asm.find_egress_link(relay).map(|l| l.get()), Some(link));
                let other = IpAddress::new_from_std(&ip("fd5a:5052::77"));
                assert_eq!(asm.find_egress_link(other), None);
                // Once the link is gone, so is the address.
                asm.drop_peer(link);
                assert_eq!(asm.find_egress_link(relay), None);
            })
            .await
    }

    /// The relay address is held only on the initial link: another up Zode
    /// link with an install of its own does not answer for it.
    #[tokio::test(start_paused = true)]
    async fn test_relay_egress_is_only_the_initial_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _link, _egress) = joiner(7306);
                let other =
                    crate::peer_table::test::insert_up_zode_link(&asm, "c", ip("fd5a:5052::c"));
                install_bound_to_link(
                    &asm,
                    other,
                    &[forward(), reverse()],
                    Some(IpAddress::new_from_std(&ip(RELAY))),
                )
                .unwrap();
                let relay = IpAddress::new_from_std(&ip(RELAY));
                assert_eq!(asm.find_egress_link(relay), None);
            })
            .await
    }

    /// Local Codex review: a hand-off that arrives when the topology already
    /// names the relay (a redial after the joiner had topology) does not
    /// bring the pre-topology address back; the topology still decides.
    #[tokio::test(start_paused = true)]
    async fn test_handoff_after_topology_does_not_override_it() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7308);
                let moved = ip("fd5a:5052::3");
                set_topology(
                    &asm,
                    vec![crate::peer_table::test::topology_link_at("relay", moved)],
                );
                accept(&asm, link, &good_body()).unwrap();
                assert_eq!(
                    asm.find_egress_link(IpAddress::new_from_std(&ip(RELAY))),
                    None
                );
                assert_eq!(
                    asm.find_egress_link(IpAddress::new_from_std(&moved))
                        .map(|l| l.get()),
                    Some(link)
                );
            })
            .await
    }

    /// Local Codex review: once a topology has named the relay, a later
    /// hand-off never brings the pre-topology address back, even after a
    /// topology without the relay and a redial.
    #[tokio::test(start_paused = true)]
    async fn test_topology_naming_the_relay_ends_the_exception_for_good() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7309);
                let relay = IpAddress::new_from_std(&ip(RELAY));
                set_topology(
                    &asm,
                    vec![crate::peer_table::test::topology_link_at(
                        "relay",
                        ip(RELAY),
                    )],
                );
                set_topology(&asm, vec![]);
                asm.drop_peer(link);
                // The initial link redials with backoff (rule 11).
                let again = loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if let Some(id) = record_of(&asm, "relay").link_id {
                        break id;
                    }
                };
                bring_up(&asm, again, "relay");
                accept(&asm, again, &good_body()).unwrap();
                assert_eq!(asm.find_egress_link(relay), None);
            })
            .await
    }

    /// After a `setTopology` that names the relay, the topology address is
    /// used and the hand-off's is forgotten, even if they differ.
    #[tokio::test(start_paused = true)]
    async fn test_topology_wins_over_the_handoff_address() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, _egress) = joiner(7307);
                accept(&asm, link, &good_body()).unwrap();
                let moved = ip("fd5a:5052::3");
                set_topology(
                    &asm,
                    vec![crate::peer_table::test::topology_link_at("relay", moved)],
                );
                assert_eq!(
                    asm.find_egress_link(IpAddress::new_from_std(&moved))
                        .map(|l| l.get()),
                    Some(link)
                );
                assert_eq!(
                    asm.find_egress_link(IpAddress::new_from_std(&ip(RELAY))),
                    None,
                    "the hand-off address is forgotten"
                );
                // A later topology without the relay does not bring it back.
                set_topology(&asm, vec![]);
                assert_eq!(
                    asm.find_egress_link(IpAddress::new_from_std(&ip(RELAY))),
                    None
                );
            })
            .await
    }
}
