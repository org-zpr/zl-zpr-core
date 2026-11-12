//! Bootstrap-visa hand-off from the relay to a joining Zode (zl-zipline#222).
//!
//! A Zode that has just joined has no VS-API session, so it cannot ask the
//! visa service for the visas that would let it open one. The visa service
//! (zl-zipline#221) therefore mints the joiner's own copies of its two VSAPI
//! bootstrap visas -- joiner to `vs.zpr` and the reply -- and sends them to
//! the relay inside the topology entry (`Link.visas`) that names the joiner.
//! The relay hands them to the joiner over the joiner's link in a
//! `BootstrapVisas` management message, sent after Hello completes and
//! never inside it.
//!
//! This departs from the Zodes plan §5.6 wording ("the relay never hands
//! visas to the endpoint"). Stream binding matches a visa by its visa-service
//! ID at every hop, so the joiner must hold the visa service's own copies;
//! visas it granted itself would never match the relay's. The operator chose
//! the hand-off on pd gate g60.
//!
//! The joiner trusts the hand-off only as far as it has to. It accepts one
//! only when all of these hold:
//! - it arrives on a keyed (Helloing or Active) Zode link whose verified
//!   certificate CN is one of this Zode's configured initial links (its
//!   relay);
//! - this Zode has no VS-API session yet;
//! - it carries at most [MAX_HANDOFF_VISAS] visas;
//! - each visa is exactly this Zode's VSAPI flow: a full TCP visa from one
//!   of its own ZPR addresses (any port) to `vs.zpr` on the VSAPI port, or
//!   the reply from `vs.zpr` back to it.
//!
//! A relay that lies can then affect only the joiner's own VSAPI flow, which
//! it carries anyway. The relay, for its part, only ever sends a topology
//! entry's visas to the link whose verified CN equals that entry's `peerCn`.

use crate::assembly::Assembly;
use crate::link_state::{LinkState, LinkType};
use crate::mgmt::core;
use crate::prelude::*;
use crate::visa_mgmt;
use crate::zdp;
use bytes::{Buf, BufMut};
use std::net::IpAddr;
use zpr::addrs::{VISA_SERVICE_ADDR, VISA_SERVICE_PORT};
use zpr::vsapi_types::{DockPepType, Visa, VisaType};
use zpr::write_to::WriteTo;
use zpr_utils::net_defs::IpAddress;

/// The most visas one hand-off may carry: the VSAPI flow and its reply.
pub const MAX_HANDOFF_VISAS: usize = 2;

/// Why a joiner refused a hand-off.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum HandoffError {
    #[error("hand-off is not on a Zode link")]
    NotZodeLink,
    #[error("hand-off arrived before keying completed")]
    NotKeyed,
    #[error("hand-off is not from one of this Zode's initial links")]
    NotInitialLink,
    #[error("this Zode already has a VS-API session")]
    SessionUp,
    #[error("hand-off carries {0} visas; at most {MAX_HANDOFF_VISAS} are allowed")]
    TooMany(usize),
    #[error("visa {0} is not this Zode's VSAPI flow")]
    WrongShape(u64),
    #[error("malformed hand-off message")]
    Malformed,
}

/// Encode `visas` as a hand-off message body: a count byte, then for each
/// visa a big-endian u16 length followed by its packed Cap'n Proto encoding.
pub fn encode(visas: &[Visa]) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_u8(visas.len() as u8);
    for visa in visas {
        let mut builder =
            capnp::message::TypedBuilder::<zpr::vsapi::v1::visa::Owned>::new_default();
        visa.write_to(&mut builder.init_root());
        let mut packed = Vec::new();
        capnp::serialize_packed::write_message(&mut packed, builder.borrow_inner())
            .expect("writing to a Vec cannot fail");
        out.put_u16(packed.len() as u16);
        out.put_slice(&packed);
    }
    out
}

/// Decode a hand-off message body written by [encode].
pub fn decode(mut buf: &[u8]) -> Result<Vec<Visa>, HandoffError> {
    if buf.remaining() < 1 {
        return Err(HandoffError::Malformed);
    }
    let count = buf.get_u8() as usize;
    let mut visas = Vec::with_capacity(count.min(MAX_HANDOFF_VISAS + 1));
    for _ in 0..count {
        if buf.remaining() < 2 {
            return Err(HandoffError::Malformed);
        }
        let len = buf.get_u16() as usize;
        if buf.remaining() < len {
            return Err(HandoffError::Malformed);
        }
        let (packed, rest) = buf.split_at(len);
        buf = rest;
        let reader =
            capnp::serialize_packed::read_message(packed, capnp::message::ReaderOptions::new())
                .map_err(|_| HandoffError::Malformed)?;
        let typed = capnp::message::TypedReader::<_, zpr::vsapi::v1::visa::Owned>::new(reader);
        let root = typed.get().map_err(|_| HandoffError::Malformed)?;
        visas.push(Visa::try_from(root).map_err(|_| HandoffError::Malformed)?);
    }
    Ok(visas)
}

/// Is `visa` exactly this Zode's VSAPI flow, or its reply? `own_addrs` are
/// this Zode's ZPR addresses. The Zode's own port is the wildcard 0, the
/// way the visa service mints these visas.
fn is_own_vsapi_visa(visa: &Visa, own_addrs: &[IpAddr]) -> bool {
    let Some(dock) = &visa.dock_pep else {
        return false;
    };
    let DockPepType::TCP(tcp) = &dock.pep else {
        return false;
    };
    if visa.visa_type != VisaType::Full {
        return false;
    }
    let to_vs = own_addrs.contains(&dock.source_addr)
        && tcp.source_port == 0
        && dock.dest_addr == VISA_SERVICE_ADDR
        && tcp.dest_port == VISA_SERVICE_PORT;
    // On the reply this Zode is the egress end: there is no next hop.
    let from_vs = dock.source_addr == VISA_SERVICE_ADDR
        && tcp.source_port == VISA_SERVICE_PORT
        && own_addrs.contains(&dock.dest_addr)
        && tcp.dest_port == 0
        && visa.fwd_pep.is_none();
    to_vs || from_vs
}

/// Joiner side: check a hand-off that arrived on `link_id` and install its
/// visas. See the module documentation for the checks.
///
/// The forward visa's next hop is the relay's ZPR address. Before the first
/// topology arrives the initial link has no peer address, so this records
/// that next hop on the link; the next topology update overwrites it.
pub fn accept(asm: &Arc<Assembly>, link_id: LinkId, visas: Vec<Visa>) -> Result<(), HandoffError> {
    let peer = asm
        .peer_table
        .get(link_id)
        .ok_or(HandoffError::NotZodeLink)?;
    let fsm = &peer.link_state_machine;
    if fsm.get_link_type() != LinkType::NodeToNode {
        return Err(HandoffError::NotZodeLink);
    }
    // The peer's CN is verified at keying. The relay sends once its side is
    // Active, which can reach us before its HelloResponse does, so a
    // Helloing link is as good as an Active one here.
    if !matches!(fsm.get_state(), LinkState::Helloing | LinkState::Active) {
        return Err(HandoffError::NotKeyed);
    }
    let from_initial_link = peer.verified_peer_cn().is_some_and(|cn| {
        asm.config
            .get()
            .initial_links
            .iter()
            .any(|link| link.cn == cn)
    });
    if !from_initial_link {
        return Err(HandoffError::NotInitialLink);
    }
    if asm.vs_session_up.load(std::sync::atomic::Ordering::Acquire) {
        return Err(HandoffError::SessionUp);
    }
    if visas.len() > MAX_HANDOFF_VISAS {
        return Err(HandoffError::TooMany(visas.len()));
    }
    let own_addrs = asm.get_local_zpr_addrs_std();
    if let Some(bad) = visas.iter().find(|v| !is_own_vsapi_visa(v, &own_addrs)) {
        return Err(HandoffError::WrongShape(bad.issuer_id));
    }

    for visa in visas {
        if fsm.zode_peer_addr().is_none() {
            if let Some(fwd) = &visa.fwd_pep {
                fsm.set_zode_peer_addr(Some(IpAddress::new_from_std(&fwd.next_hop)));
            }
        }
        let visa_id = visa.issuer_id;
        match visa_mgmt::insert_visa(asm, visa) {
            Ok(_) => {
                info!(target: VISA_MGMT, "{} installed handed-off bootstrap visa {visa_id}", asm.formatted_link_id(link_id))
            }
            Err(e) => {
                warn!(target: VISA_MGMT, "{} could not install handed-off bootstrap visa {visa_id}: {e:?}", asm.formatted_link_id(link_id))
            }
        }
    }
    Ok(())
}

/// The bootstrap visas the stored topology holds for the peer whose
/// verified CN is `cn`: only that entry's `Link.visas`, never another's.
pub fn topology_visas_for_cn(asm: &Assembly, cn: &str) -> Vec<Visa> {
    if cn.is_empty() {
        return Vec::new();
    }
    asm.topology
        .read()
        .unwrap()
        .iter()
        .filter(|link| link.peer_cn == cn)
        .flat_map(|link| link.visas.iter().cloned())
        .collect()
}

/// Relay side: if `link_id` is an Active Zode link and the topology holds
/// bootstrap visas for its verified peer CN, hand them to the peer. Called
/// when a Zode link goes Active and again after topology updates; the
/// joiner ignores repeats once it has its VS-API session.
pub fn send(asm: &Arc<Assembly>, link_id: LinkId) {
    let Some(peer) = asm.peer_table.get(link_id) else {
        return;
    };
    let fsm = &peer.link_state_machine;
    if fsm.get_link_type() != LinkType::NodeToNode || fsm.get_state() != LinkState::Active {
        return;
    }
    let Some(cn) = peer.verified_peer_cn() else {
        return;
    };
    let visas = topology_visas_for_cn(asm, &cn);
    if visas.is_empty() {
        return;
    }
    drop(peer);
    info!(target: VISA_MGMT, "{} handing {} bootstrap visa(s) to {cn}", asm.formatted_link_id(link_id), visas.len());
    let mut pkt = core::new_heap_packet();
    pkt.put(encode(&visas).as_slice());
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::BootstrapVisas, pkt).enqueue();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InitialLink;
    use crate::peer_table::test::{insert_zode_peer_with_verified_cn, topology_link};
    use std::time::{Duration, SystemTime};
    use tokio::task::LocalSet;
    use zpr::vsapi_types::{DockPep, EndpointT, FwdPep, KeySet, TcpUdpPep};

    const OWN: &str = "fd5a:5052::b";
    const RELAY: &str = "fd5a:5052::2";

    /// A full TCP visa from `src:sport` to `dst:dport`, forwarding to
    /// `next_hop` if given.
    fn tcp_visa(
        id: u64,
        src: &str,
        sport: u16,
        dst: &str,
        dport: u16,
        next_hop: Option<&str>,
    ) -> Visa {
        Visa {
            issuer_id: id,
            config: 0,
            // Whole seconds: visas carry their expiry at millisecond precision.
            expires: SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
            visa_type: VisaType::Full,
            dock_pep: Some(DockPep {
                source_addr: src.parse().unwrap(),
                dest_addr: dst.parse().unwrap(),
                session_key: KeySet::default(),
                pep: DockPepType::TCP(TcpUdpPep {
                    source_port: sport,
                    dest_port: dport,
                    endpoint: EndpointT::Any,
                }),
            }),
            fwd_pep: next_hop.map(|h| FwdPep {
                next_hop: h.parse().unwrap(),
                style: zpr::vsapi_types::FwdPepStyle::OneWay,
            }),
            cons: None,
            prev_hop: None,
        }
    }

    /// The two visas the visa service mints for a joiner at `OWN`. The
    /// joiner is the egress of the reply, so its copy of the reply visa names
    /// the relay as previous hop (zl-zipline#245); the round trip below
    /// shows the hand-off keeps it, which gap 7 needs.
    fn vsapi_pair() -> Vec<Visa> {
        let vs = VISA_SERVICE_ADDR.to_string();
        let mut reply = tcp_visa(9002, &vs, VISA_SERVICE_PORT, OWN, 0, None);
        reply.prev_hop = Some(RELAY.parse().unwrap());
        vec![
            tcp_visa(9001, OWN, 0, &vs, VISA_SERVICE_PORT, Some(RELAY)),
            reply,
        ]
    }

    /// A joiner at `OWN` whose initial link is to `relay.zpr`, with an
    /// Active Zode link to a peer whose verified CN is `peer_cn`.
    fn joiner(peer_cn: &str) -> (Arc<Assembly>, LinkId) {
        let asm = crate::assembly::test::zode_assembly_with_ca("b.zpr");
        let mut cfg = (*asm.config.get()).clone();
        cfg.zpr_addr = vec![OWN.parse().unwrap()];
        cfg.initial_links = vec![InitialLink::new("relay.zpr", "10.9.9.9:5000").unwrap()];
        asm.config.write(cfg);
        let link = insert_zode_peer_with_verified_cn(&asm, peer_cn, LinkState::Active);
        (asm, link)
    }

    fn installed(asm: &Assembly, id: u64) -> bool {
        asm.visa_table.read().unwrap().table.contains_key(&id)
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let visas = vsapi_pair();
        assert_eq!(decode(&encode(&visas)).unwrap(), visas);
        assert_eq!(decode(&[]), Err(HandoffError::Malformed));
        assert_eq!(decode(&[1, 0, 9]), Err(HandoffError::Malformed));
    }

    /// The joiner installs its VSAPI pair from its relay, and learns the
    /// relay's ZPR address from the forward visa's next hop.
    #[tokio::test]
    async fn test_accepts_vsapi_pair_from_initial_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, link) = joiner("relay.zpr");
                accept(&asm, link, vsapi_pair()).unwrap();
                assert!(installed(&asm, 9001) && installed(&asm, 9002));
                let relay = IpAddress::new_from_std(&RELAY.parse().unwrap());
                assert_eq!(
                    asm.peer_table
                        .get(link)
                        .unwrap()
                        .link_state_machine
                        .zode_peer_addr(),
                    Some(relay)
                );
                assert_eq!(asm.find_egress_link(relay).map(|l| l.get()), Some(link));
            })
            .await
    }

    #[tokio::test]
    async fn test_refuses_link_that_is_not_an_initial_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, link) = joiner("stranger.zpr");
                assert_eq!(
                    accept(&asm, link, vsapi_pair()),
                    Err(HandoffError::NotInitialLink)
                );
                assert!(!installed(&asm, 9001));
            })
            .await
    }

    #[tokio::test]
    async fn test_refuses_once_vs_session_is_up() {
        LocalSet::new()
            .run_until(async {
                let (asm, link) = joiner("relay.zpr");
                asm.vs_session_up
                    .store(true, std::sync::atomic::Ordering::Release);
                assert_eq!(
                    accept(&asm, link, vsapi_pair()),
                    Err(HandoffError::SessionUp)
                );
                assert!(!installed(&asm, 9001));
            })
            .await
    }

    #[tokio::test]
    async fn test_refuses_more_than_two_visas() {
        LocalSet::new()
            .run_until(async {
                let (asm, link) = joiner("relay.zpr");
                let mut visas = vsapi_pair();
                visas.push(vsapi_pair().remove(0));
                assert_eq!(accept(&asm, link, visas), Err(HandoffError::TooMany(3)));
                assert!(!installed(&asm, 9001));
            })
            .await
    }

    /// Anything but this Zode's own VSAPI flow is refused, and nothing from
    /// the hand-off is installed.
    #[tokio::test]
    async fn test_refuses_wrong_five_tuple() {
        LocalSet::new()
            .run_until(async {
                let vs = VISA_SERVICE_ADDR.to_string();
                let wrong = [
                    tcp_visa(1, OWN, 0, &vs, 80, Some(RELAY)),
                    tcp_visa(2, "fd5a:5052::99", 0, &vs, VISA_SERVICE_PORT, Some(RELAY)),
                    tcp_visa(3, OWN, 0, "fd5a:5052::77", VISA_SERVICE_PORT, Some(RELAY)),
                    tcp_visa(4, &vs, VISA_SERVICE_PORT, OWN, 0, Some(RELAY)),
                    tcp_visa(5, &vs, VISA_SERVICE_PORT, "fd5a:5052::99", 0, None),
                ];
                for visa in wrong {
                    let (asm, link) = joiner("relay.zpr");
                    let id = visa.issuer_id;
                    let visas = vec![vsapi_pair().remove(0), visa];
                    assert_eq!(accept(&asm, link, visas), Err(HandoffError::WrongShape(id)));
                    assert!(
                        !installed(&asm, 9001),
                        "nothing installed for wrong visa {id}"
                    );
                }
            })
            .await
    }

    /// The relay sends the hand-off once its side is Active, and ZDP-R may
    /// deliver it before this side has the HelloResponse (Copilot review on
    /// zl-zpr-core#104). The peer's CN was verified at keying, so a
    /// hand-off on a Helloing link is accepted; one before keying finishes
    /// is refused.
    #[tokio::test]
    async fn test_accepts_while_helloing_refuses_before_keying() {
        LocalSet::new()
            .run_until(async {
                let (asm, link) = joiner("relay.zpr");
                let fsm = |asm: &Arc<Assembly>, state| {
                    asm.peer_table
                        .get(link)
                        .unwrap()
                        .link_state_machine
                        .test_set_state(state)
                };
                fsm(&asm, LinkState::Keying);
                assert_eq!(
                    accept(&asm, link, vsapi_pair()),
                    Err(HandoffError::NotKeyed)
                );
                fsm(&asm, LinkState::Helloing);
                accept(&asm, link, vsapi_pair()).unwrap();
                assert!(installed(&asm, 9001) && installed(&asm, 9002));
            })
            .await
    }

    /// The relay hands a peer only the visas of the topology entry that
    /// names that peer's CN.
    #[test]
    fn test_relay_sends_only_the_matching_entrys_visas() {
        let asm = crate::assembly::test::zode_assembly_with_ca("relay.zpr");
        let mut a = topology_link("a.zpr");
        a.visas = vec![vsapi_pair().remove(0)];
        let mut b = topology_link("b.zpr");
        b.visas = vec![vsapi_pair().remove(1)];
        *asm.topology.write().unwrap() = vec![a, b];
        let ids: Vec<u64> = topology_visas_for_cn(&asm, "b.zpr")
            .iter()
            .map(|v| v.issuer_id)
            .collect();
        assert_eq!(ids, [9002]);
        assert!(topology_visas_for_cn(&asm, "").is_empty());
    }
}
