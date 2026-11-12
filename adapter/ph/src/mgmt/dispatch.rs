//! Code which handles dispatching management packets from fastpath.

use super::core;
use crate::counters::{ManagementCounterType, ManagementCounters};
use crate::km_multiplexor;
use crate::link_state::{LinkState, LinkType};
use crate::prelude::*;
use crate::queues;
use crate::zdp;
use crate::zdpr;
use strum::IntoEnumIterator;
use zpr_ext::std::num::NonZeroExt;
use zpr_ext::zerocopy::FromBytesExt;
use zpr_utils::net_defs;

/// Dispatch a management packet for a link that hasn't been established yet
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet_with_addr(
    asm: &Arc<Assembly>,
    peer_sa: SubstrateAddr,
    interface_addr: net_defs::ScopedIpAddr,
    pkt: &mut Packet,
) {
    match zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) {
        Ok((base_hdr, _)) if base_hdr.packet_type == zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());

            // TODO: once we have multi-node, how do we know whether this is a link or a
            // tether?

            // It is possible we are processing a queue of messages and we have already set up a
            // tether for this source.  So before trying to start a tether check if we already have one.

            let mut ingress_link_id = asm
                .peer_table
                .lookup_peer(&peer_sa, &interface_addr)
                .unwrap_or_zero();

            if ingress_link_id == LINK_ID_UNKNOWN {
                // A dialing Zode marks its first handshake message
                // (zl-zipline#222); anything else docks as an adapter.
                let started = match inbound_link_type(km_noise_message(pkt.body())) {
                    LinkType::NodeToNode => asm.start_zode_link(&peer_sa, &interface_addr, false),
                    _ => asm.start_tether(&peer_sa, &interface_addr, LinkType::NodeToAdapter, true),
                };
                let Some(i_link_id) = started.ok() else {
                    core::count_event(asm, ManagementCounterType::UnknownPeer);
                    return;
                };
                ingress_link_id = i_link_id.get();
            }

            pkt.metadata_mut().ingress_link_id = ingress_link_id;
            // The link found may be our own dial, made after fastpath queued
            // this packet: settle a crossed dial exactly as the
            // link-dispatched path does (zl-zipline#222).
            if !resolve_crossed_zode_dial(asm, pkt) {
                return;
            }
            handle_key_management(asm, pkt);
        }

        _ => {
            core::count_event(asm, ManagementCounterType::UnknownPeer);
            return;
        }
    }
}

/// The link type for a new inbound link whose first key-management message
/// is `km_msg` (zl-zipline#222): a Zode link when it opens a Zode handshake,
/// an adapter dock otherwise.
fn inbound_link_type(km_msg: &[u8]) -> LinkType {
    if crate::km_noise::starts_zode_handshake(km_msg) {
        LinkType::NodeToNode
    } else {
        LinkType::NodeToAdapter
    }
}

/// The key-management message carried in `km_body` (a KM header and its
/// payload), or an empty slice if the header is malformed or not Noise.
fn km_noise_message(km_body: &[u8]) -> &[u8] {
    match zdp::ZdpKeyManagementHeader::ref_from_prefix(km_body) {
        Ok((hdr, rest)) if hdr.is_noise() => {
            &rest[..usize::from(hdr.message_length).min(rest.len())]
        }
        _ => &[],
    }
}

/// What a Zode does with another Zode's first handshake message when it
/// arrives on a link this Zode is itself dialing (zl-zipline#222).
///
/// One substrate address pair carries one link, so when two Zodes dial each
/// other at once -- a joiner dialing its initial link while the relay dials
/// it from topology, say -- each sees the other's first message on its own
/// dialing link, and neither handshake can finish. Both ends must pick the
/// same survivor without having keyed yet.
#[derive(Debug, PartialEq, Eq)]
enum CrossedDial {
    /// Not a crossed dial: handle the message on the link as usual.
    NotCrossed,
    /// Keep our dial and drop the peer's message: the peer answers ours.
    KeepDialing,
    /// Give up our dial and answer the peer's.
    Answer,
}

/// Decide a crossed dial on a dialing Zode link in `state`. `own_cn` is our
/// certificate CN; `expected_peer_cn` the CN we dialed (from the initial
/// link or topology entry for that address), which the peer, dialing us,
/// knows as well. The dial of the Zode whose CN sorts lower survives, the
/// rule pd gate g56 q2 chose for crossed dials. A dial that is idle,
/// waiting to redial, always answers. The CN is still verified after
/// keying, so a peer that is not who we dialed is closed then.
fn crossed_dial(state: LinkState, own_cn: &str, expected_peer_cn: Option<&str>) -> CrossedDial {
    match state {
        LinkState::Inactive => CrossedDial::Answer,
        LinkState::Keying => match expected_peer_cn {
            Some(peer_cn) if own_cn < peer_cn => CrossedDial::KeepDialing,
            _ => CrossedDial::Answer,
        },
        _ => CrossedDial::NotCrossed,
    }
}

/// Apply [crossed_dial] to the key-management packet `pkt` (its ZDP base
/// header already consumed). Returns false when the packet is to be
/// dropped; when we answer, the dialing link is replaced by an answering
/// one and `pkt` is redirected to it.
fn resolve_crossed_zode_dial(asm: &Arc<Assembly>, pkt: &mut Packet) -> bool {
    if !crate::km_noise::starts_zode_handshake(km_noise_message(pkt.body())) {
        return true;
    }
    let link_id = pkt.metadata().ingress_link_id;
    let Some(peer) = asm.peer_table.get(link_id) else {
        return true;
    };
    if !peer.link_state_machine.is_zode_dialer() {
        return true;
    }
    let state = peer.link_state_machine.get_state();
    let (peer_sa, interface_addr) = (peer.substrate_addr, peer.interface_addr);
    drop(peer);

    let expected_cn = asm.expected_zode_cn(&std::net::SocketAddr::from(peer_sa));
    let own_cn = asm.own_cn().unwrap_or_default();
    match crossed_dial(state, &own_cn, expected_cn.as_deref()) {
        CrossedDial::NotCrossed => true,
        CrossedDial::KeepDialing => {
            info!(target: PEER_MGMT, "{} crossed dial with {peer_sa}: keeping ours", asm.formatted_link_id(link_id));
            false
        }
        CrossedDial::Answer => {
            info!(target: PEER_MGMT, "{} crossed dial with {peer_sa}: answering the peer's", asm.formatted_link_id(link_id));
            // Stop the dial's key manager, then drop the link; the
            // answering link takes the address pair.
            let _ = asm.peer_table.clear_security_association(link_id);
            if let Some(km) = asm.peer_table.remove_km_state(link_id) {
                km.ctok.cancel();
            }
            asm.drop_peer(link_id);
            match asm.start_zode_link(&peer_sa, &interface_addr, false) {
                Ok(answer) => {
                    pkt.metadata_mut().ingress_link_id = answer.get();
                    true
                }
                Err(e) => {
                    warn!(target: PEER_MGMT, "cannot answer a crossed dial from {peer_sa}: {e}");
                    false
                }
            }
        }
    }
}

/// Dispatch the given management packet.
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet_with_link(asm: &Arc<Assembly>, pkt: &mut Packet) {
    let Ok((base_hdr, rest)) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) else {
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    match base_hdr.packet_type {
        zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            if !resolve_crossed_zode_dial(asm, pkt) {
                return;
            }
            return handle_key_management(asm, pkt);
        }

        zdp::ZdpPacketType::Acknowledgement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            return handle_acknowledgement(asm, pkt);
        }

        zdp::ZdpPacketType::Cancel => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            return handle_cancel(asm, pkt);
        }

        zdp::ZdpPacketType::Canceled => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
            return handle_canceled(asm, pkt);
        }

        _ => (),
    }

    let (mgmt_hdr, _) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();

    let Some(peer_state) = asm.peer_table.get(pkt.metadata().ingress_link_id) else {
        core::count_event(asm, ManagementCounterType::PeerRemoved);
        return;
    };

    // expand sequence number and store in packet metadata
    let mut receiver = peer_state.zdpr_recv.lock().unwrap();
    let seq_num = mgmt_hdr.sequence_number.get();
    pkt.metadata_mut().seq_num = seq_num;

    // attempt to queue packet if processing is indicated by ZDPR
    if receiver.should_process_packet(seq_num) {
        let mgmt_pkt = Packet::new_with_existing_metadata(pkt.buffer().clone());
        match peer_state.mgmt_processor.try_enqueue_packet(mgmt_pkt) {
            Ok(()) => (),
            Err(queues::TryEnqueueError::Full(_mgmt_pkt)) => {
                // we were unable to queue the packet; treat it as if
                // we never received it (so, no ACK or updating ZDPR)
                core::count_event(asm, ManagementCounterType::QueueBackpressure);
                return;
            }
        }
    }

    // update ZDPR that we've accepted the packet
    let disp = receiver.process_packet(seq_num);
    count_zdpr_receiver_stats(&asm.counters.management, &mut receiver);
    drop(receiver);

    if disp.should_ack() {
        if disp.ack_is_canceled() {
            core::send_canceled(&asm, pkt.metadata().ingress_link_id, seq_num);
        } else {
            core::send_acknowledgement(&asm, pkt.metadata().ingress_link_id, seq_num);
        }
    }
}

fn handle_cancel(asm: &Assembly, pkt: &mut Packet) {
    let Ok(mgmt_hdr) = zdp::ZdpMgmtHeader::read_from_buf(pkt) else {
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    let seq_num = mgmt_hdr.sequence_number.get();
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
        core::count_event(asm, ManagementCounterType::PeerRemoved);
        return;
    };

    let mut receiver = peer_state.zdpr_recv.lock().unwrap();
    let disp = receiver.process_cancel(seq_num);
    count_zdpr_receiver_stats(&asm.counters.management, &mut receiver);

    if disp.should_ack() {
        if disp.ack_is_canceled() {
            core::send_canceled(&asm, pkt.metadata().ingress_link_id, seq_num);
        } else {
            core::send_acknowledgement(&asm, pkt.metadata().ingress_link_id, seq_num);
        }
    }
}

fn handle_acknowledgement(asm: &Assembly, pkt: &mut Packet) {
    handle_acknowledgement_canceled_common(asm, pkt, false)
}

fn handle_canceled(asm: &Assembly, pkt: &mut Packet) {
    handle_acknowledgement_canceled_common(asm, pkt, true)
}

fn handle_acknowledgement_canceled_common(asm: &Assembly, pkt: &mut Packet, is_canceled: bool) {
    // From dispatch's point of view, acknowledgement and cancellation of a packet are
    // identical; either way, we don't care about the referenced packet any more.
    // The only difference is ultimately to the sender/canceller, who must learn whether
    // the remote canceled or processed the packet.

    let Ok(mgmt_hdr) = zdp::ZdpMgmtHeader::read_from_buf(pkt) else {
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    let seq_num = mgmt_hdr.sequence_number.get();
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
        core::count_event(asm, ManagementCounterType::PeerRemoved);
        return;
    };
    let mut sender = peer_state.zdpr_send.lock().unwrap();

    if is_canceled {
        sender.process_canceled(seq_num);
    } else {
        sender.process_ack(seq_num);
    }
    count_zdpr_sender_stats(&asm.counters.management, &mut sender);

    // If at this point (after processing the ACK) we should not have our
    // retry timer running (because all outstanding packets have been
    // ACKed), we may be liable to restart the timer after possibly sending
    // unblocked packets.
    let old_retry_needed = sender.retry_needed();

    // We may now be unblocked and may have been blocked before;
    // try to send queued packets.
    while sender.unblock_needed() {
        let sn_pkt = sender.enqueue_next_blocked_packet();
        core::build_and_egress_packets(asm, ingress_link_id, std::iter::once(sn_pkt));
    }

    if sender.retry_needed() && !old_retry_needed {
        // We should activate / restart our retry timer.
        peer_state.zdpr_retry_timer_reset.notify_one();
    }
}

// ZPI and Base header is already gone by the time we get here.  So we expect
// to parse starting from the KeyManagement header.
fn handle_key_management(asm: &Assembly, pkt: &mut Packet) {
    let Ok(km_hdr) = zdp::ZdpKeyManagementHeader::read_from_buf(pkt) else {
        error!(target: ZDP, "KeyManagement packet arrived with unparseable header");
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    if (km_hdr.is_noise() && asm.config.get().km_impl != KM_ID_NOISE)
        || (km_hdr.is_null() && asm.config.get().km_impl != KM_ID_NULL)
    {
        error!(
            target: KEY_MGMT,
            "KeyManagement packet type does not match KM implementation - type is {}",
            km_hdr.message_type
        );
        core::count_event(asm, ManagementCounterType::OtherError);
        return;
    }

    let km_msg_len = usize::from(km_hdr.message_length);
    if pkt.remaining() < km_msg_len {
        error!(target: KEY_MGMT, "KeyManagement packet arrived with truncated payload");
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    }

    match km_multiplexor::handle_inbound_km_msg(
        asm,
        pkt.metadata().ingress_link_id,
        &pkt.body()[..km_msg_len],
    ) {
        Ok(()) => (),
        Err(e) => {
            error!(
                target: KEY_MGMT,
                "key management handling failed on {}: {e:?}",
                asm.formatted_link_id(pkt.metadata().ingress_link_id),
            );
            core::count_event(asm, ManagementCounterType::OtherError);
            return;
        }
    };
    return;
}

/// Maps a `zdpr::SenderStat` to a `CounterType`.
fn zdpr_sender_stat_to_counter(sn_stat: zdpr::SenderStat) -> ManagementCounterType {
    match sn_stat {
        zdpr::SenderStat::InvalidAck => ManagementCounterType::BadMgmtResponse,
        zdpr::SenderStat::TooOldAck => ManagementCounterType::DroppedTooOld,
        zdpr::SenderStat::DuplicateAck => ManagementCounterType::DroppedDuplicate,
        zdpr::SenderStat::TooNewAck => ManagementCounterType::DroppedTooNew,
    }
}

/// Maps a `zdpr::ReceiverStat` to a `CounterType`.
fn zdpr_receiver_stat_to_counter(sn_stat: zdpr::ReceiverStat) -> ManagementCounterType {
    match sn_stat {
        zdpr::ReceiverStat::TooOld => ManagementCounterType::DroppedTooOld,
        zdpr::ReceiverStat::Duplicate => ManagementCounterType::DroppedDuplicate,
        zdpr::ReceiverStat::TooNew => ManagementCounterType::DroppedTooNew,
        zdpr::ReceiverStat::OutOfOrder => ManagementCounterType::OutOfOrderPacket,
    }
}

/// Pulls stats delta from `zdpr::Sender` and feeds them into the global counters.
fn count_zdpr_sender_stats<Pkt>(
    mgmt_counters: &ManagementCounters,
    sender: &mut zdpr::Sender<Pkt>,
) {
    for stat in zdpr::SenderStat::iter() {
        mgmt_counters[zdpr_sender_stat_to_counter(stat)].increase_by(sender.fetch_reset_stat(stat));
    }
}

/// Pulls stats delta from `zdpr::Receiver` and feeds them into the global counters.
fn count_zdpr_receiver_stats(mgmt_counters: &ManagementCounters, receiver: &mut zdpr::Receiver) {
    for stat in zdpr::ReceiverStat::iter() {
        mgmt_counters[zdpr_receiver_stat_to_counter(stat)]
            .increase_by(receiver.fetch_reset_stat(stat));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::config::PACKET_BUFFER_SIZE;
    use crate::km_cert_exchange::KmCertExchange;
    use crate::km_noise::NoiseKeypair;
    use crate::km_testdata::test::*;
    use crate::link_state::LinkType;
    use crate::peer_table::PeerState;
    use std::net::Ipv4Addr;
    use std::num::NonZero;
    use std::sync::Arc;

    /// zl-zipline#222: a node creates a Zode link for an unknown peer whose
    /// first handshake message carries the Zode marker, and an adapter
    /// dock for anything else.
    #[test]
    fn test_inbound_link_type_from_first_handshake_message() {
        let ca = crate::pki::TestCa::new("zode-ca");
        let kp = NoiseKeypair::generate();
        let window = {
            let now = std::time::SystemTime::now();
            x509_cert::time::Validity::new(
                x509_cert::time::Time::try_from(now - std::time::Duration::from_secs(60)).unwrap(),
                x509_cert::time::Time::try_from(now + std::time::Duration::from_secs(3600))
                    .unwrap(),
            )
        };
        let certx =
            KmCertExchange::new(Some(ca.issue("a.zpr", &kp, window)), Some(ca.cert.clone()));
        let mut zode =
            crate::km_noise::KmNoise::new_zode(true, kp, crate::km::ZPIPair::new(1, 2), certx)
                .unwrap();
        let mut adapter = crate::km_noise::KmNoise::new(
            true,
            true,
            None,
            crate::km::ZPIPair::new(1, 2),
            KmCertExchange::new(None, Some(ca.cert.clone())),
        )
        .unwrap();
        use crate::km::KeyManagerStateMachine;
        let zode_msg0 = zode.reset().unwrap().unwrap();
        let adapter_msg0 = adapter.reset().unwrap().unwrap();

        assert_eq!(inbound_link_type(&zode_msg0), LinkType::NodeToNode);
        assert_eq!(inbound_link_type(&adapter_msg0), LinkType::NodeToAdapter);
        assert_eq!(inbound_link_type(&[]), LinkType::NodeToAdapter);
    }

    /// zl-zipline#222: who survives when two Zodes dial each other at once.
    /// One substrate address pair carries one link, so each Zode sees the
    /// other's first handshake message on its own dialing link. The dial of
    /// the Zode whose CN sorts lower survives (g56 q2); a Zode whose dial
    /// is idle, waiting to redial, always answers.
    #[test]
    fn test_crossed_dial_decision() {
        use crate::link_state::LinkState;
        assert_eq!(
            crossed_dial(LinkState::Keying, "relay", Some("zb")),
            CrossedDial::KeepDialing
        );
        assert_eq!(
            crossed_dial(LinkState::Keying, "zb", Some("relay")),
            CrossedDial::Answer
        );
        assert_eq!(
            crossed_dial(LinkState::Inactive, "relay", Some("zb")),
            CrossedDial::Answer
        );
        // Who we dialed is unknown: answer; the CN is still checked after keying.
        assert_eq!(
            crossed_dial(LinkState::Keying, "relay", None),
            CrossedDial::Answer
        );
        // A keyed link is not a crossed dial.
        for state in [LinkState::Helloing, LinkState::Active] {
            assert_eq!(
                crossed_dial(state, "zb", Some("relay")),
                CrossedDial::NotCrossed
            );
        }
    }

    /// A Zode's first handshake message, wrapped as the ZDP key-management
    /// packet a peer would send on link `link_id`.
    fn zode_msg0_packet(link_id: LinkId) -> Packet {
        use crate::km::KeyManagerStateMachine;
        let ca = crate::pki::TestCa::new("other-ca");
        let kp = NoiseKeypair::generate();
        let window =
            x509_cert::time::Validity::from_now(std::time::Duration::from_secs(3600)).unwrap();
        let certx = KmCertExchange::new(Some(ca.issue("peer", &kp, window)), Some(ca.cert.clone()));
        let mut noise =
            crate::km_noise::KmNoise::new_zode(true, kp, crate::km::ZPIPair::new(1, 2), certx)
                .unwrap();
        let msg0 = noise.reset().unwrap().unwrap();

        let mut pkt = core::new_heap_packet();
        let km_hdr = pkt.alloc_zeroed_header::<zdp::ZdpKeyManagementHeader>();
        km_hdr.message_type = KM_ID_NOISE.into();
        km_hdr.message_length = (msg0.len() as u16).into();
        pkt.put(&msg0[..]);
        let hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        hdr.packet_type = zdp::ZdpPacketType::KeyManagement;
        pkt.metadata_mut().ingress_link_id = link_id;
        pkt
    }

    /// Dial the topology peer "relay" from a Zode with CN `own_cn`, then
    /// deliver the relay's own first handshake message on that link.
    /// Returns the Zode's links to the relay's address afterwards, as
    /// (link id, is dialer).
    fn crossed_dial_links(own_cn: &str) -> (LinkId, Vec<(LinkId, bool)>) {
        crossed_dial_links_via(own_cn, false)
    }

    /// [crossed_dial_links], delivering the relay's message by link ID or,
    /// with `by_addr`, by substrate address (the path fastpath takes for a
    /// packet it queued before our dial existed).
    fn crossed_dial_links_via(own_cn: &str, by_addr: bool) -> (LinkId, Vec<(LinkId, bool)>) {
        use crate::peer_table::test::topology_link;
        let asm = crate::assembly::test::zode_assembly_with_ca(own_cn);
        let relay = topology_link("relay");
        let relay_sa = std::net::SocketAddr::from(relay.peer.clone());
        *asm.topology.write().unwrap() = vec![relay];
        let iface = net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 1).into());
        let dialed = asm.start_zode_link(&relay_sa, &iface, true).unwrap().get();

        let mut pkt = zode_msg0_packet(dialed);
        if by_addr {
            dispatch_mgmt_packet_with_addr(&asm, relay_sa, iface, &mut pkt);
        } else {
            dispatch_mgmt_packet_with_link(&asm, &mut pkt);
        }

        let mut links = Vec::new();
        asm.peer_table.for_each(|(id, peer)| {
            if peer.substrate_addr == relay_sa {
                links.push((id.get(), peer.link_state_machine.is_zode_dialer()));
            }
        });
        (dialed, links)
    }

    /// zl-zipline#222: a crossed dial leaves one link per address pair, and
    /// both Zodes agree which: the lower CN keeps dialing and ignores the
    /// peer's first message; the higher CN replaces its dial with a link
    /// answering the peer's. Found by zode-join-test.sh, where a relay and
    /// a joiner dialed each other and neither link ever keyed.
    #[tokio::test(flavor = "local")]
    async fn test_crossed_dial_leaves_one_link() {
        // "a" < "relay": keep our dial.
        let (dialed, links) = crossed_dial_links("a");
        assert_eq!(links, vec![(dialed, true)]);

        // "zb" > "relay": answer the relay's dial instead.
        let (_dialed, links) = crossed_dial_links("zb");
        assert_eq!(links.len(), 1, "one link to the relay: {links:?}");
        assert!(!links[0].1, "the remaining link answers the relay's dial");
    }

    /// Local Codex review on zl-zpr-core#104: a handshake fastpath queued by
    /// address before our dial existed reaches the address-dispatched path,
    /// which must settle the crossed dial the same way.
    #[tokio::test(flavor = "local")]
    async fn test_crossed_dial_leaves_one_link_via_address_path() {
        let (dialed, links) = crossed_dial_links_via("a", true);
        assert_eq!(links, vec![(dialed, true)]);

        let (_dialed, links) = crossed_dial_links_via("zb", true);
        assert_eq!(links.len(), 1, "one link to the relay: {links:?}");
        assert!(!links[0].1, "the remaining link answers the relay's dial");
    }

    // Ensure that this old issue is fixed:
    // https://github.com/org-zpr/zpr-core/issues/929
    #[tokio::test(flavor = "local")]
    async fn test_duplicate_no_tether_packet_no_crash() {
        let mut asm = create_assembly(TestAssemblyBuilder::new());
        asm.self_noise_keypair = Some(NoiseKeypair::generate());
        asm.certx = Some(KmCertExchange::new_from_pem(ADAPTER_CERT_DATA, CA_CERT_DATA).unwrap());
        let aasm = Arc::new(asm);

        let buf1 = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt1 = Packet::new(buf1, 64);

        // write ZDP base header
        let hdr = pkt1.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        hdr.packet_type = zdp::ZdpPacketType::KeyManagement;

        let buf2 = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt2 = Packet::new(buf2, 64);

        let hdr = pkt2.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        hdr.packet_type = zdp::ZdpPacketType::KeyManagement;

        let peer_sa = SubstrateAddr::from(([127, 0, 0, 1], 1234));
        let intf_addr = net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 1).into());

        dispatch_mgmt_packet_with_addr(&aasm, peer_sa, intf_addr, &mut pkt1);
        dispatch_mgmt_packet_with_addr(&aasm, peer_sa, intf_addr, &mut pkt2);

        // If we get here we didn't crash!
        assert!(true);
    }

    // Ensure we don't drop mgmt packets due to a full internal queue
    // after ZDPR-acking them.  (Old bug)
    #[tokio::test(flavor = "local")]
    async fn test_no_post_ack_queue_drops() {
        let mut tab = TestAssemblyBuilder::new();
        let (egress_send, mut egress_recv) = crate::packet_queue::packet_queue(1);
        tab.mgmt_substrate_egress = Some(crate::queues::MgmtSubstrateEgress::new(egress_send));
        let asm = Arc::new(create_assembly(tab));

        let peer_sa = SubstrateAddr::from(([127, 0, 0, 1], 1234));
        let intf_addr = net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 1).into());
        let peer_entry = asm.peer_table.vacant_entry().unwrap();
        let (mp_outq_out, mut mp_outq_in) = tokio::sync::oneshot::channel();
        let peer_state = PeerState::new(
            peer_entry.key(),
            LinkType::NodeToAdapter,
            peer_sa,
            intf_addr,
            move |q| {
                mp_outq_out.send(q).unwrap();
                std::future::pending()
            },
        );
        let mut mp_outq = mp_outq_in.try_recv().unwrap();
        let link_id = peer_entry.insert(peer_state);

        let mut num_acked = 0;

        let peer_state = asm.peer_table.get(link_id.get()).unwrap();
        let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();

        // first, check that all packets we get acks for get placed in the mgmt queue
        loop {
            // we expect not to be blocked here; we exit the loop once we no longer receive an ACK
            let zdpr::EnqueueResult::Sent(sn, pkt) =
                zdpr_send.enqueue_packet(build_discard_packet(link_id))
            else {
                panic!("test error; ZDPR window full");
            };
            set_sequence_number(sn, pkt);
            dispatch_mgmt_packet_with_link(&asm, pkt);

            // we should keep getting ACKs until the mgmt queue gets full
            let Ok(ack_pkt) = egress_recv.try_recv(Box::new([0u8; 256])) else {
                // once we're blocked, no need to keep sending packets, the test is done!
                break;
            };

            validate_packet(&ack_pkt, zdp::ZdpPacketType::Acknowledgement, sn);
            num_acked += 1;
            zdpr_send.process_ack(sn);

            // if the bug is present, we'll always get ACKs and never block
            // despite the mgmt queue filling up
            assert_eq!(
                num_acked,
                mp_outq.len(),
                "packet was acknowledged but never sent to mgmt"
            );
        }

        assert_eq!(
            num_acked,
            mp_outq.max_capacity(),
            "test error; didn't fill mgmt queue"
        );

        // drain the queue
        while let Ok(_) = mp_outq.try_recv() {}

        // finally, confirm that retrying the blocked packet results in it ending up on the queue
        assert!(zdpr_send.retry_needed());
        zdpr_send.age_retries().for_each(drop);
        for (sn, pkt) in zdpr_send.retry_packets() {
            set_sequence_number(sn, pkt);
            dispatch_mgmt_packet_with_link(&asm, pkt);
            mp_outq
                .try_recv()
                .expect("should have received retried packet on mgmt queue");
        }
    }

    fn build_discard_packet(ingress_link_id: NonZero<LinkId>) -> Packet {
        let mut pkt = core::new_heap_packet();
        pkt.metadata_mut().ingress_link_id = ingress_link_id.get();
        let _mgmt_hdr = pkt.alloc_zeroed_header::<zdp::ZdpMgmtHeader>();
        let base_hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
        base_hdr.packet_type = zdp::ZdpPacketType::Discard;
        pkt
    }

    fn set_sequence_number(sn: SeqNum, pkt: &mut Packet) {
        let (_base_hdr, rest) = zdp::ZdpBaseHeader::mut_from_prefix(pkt.body_mut()).unwrap();
        let (mgmt_hdr, _) = zdp::ZdpMgmtHeader::mut_from_prefix(rest).unwrap();
        mgmt_hdr.sequence_number = sn.into();
    }

    fn validate_packet(pkt: &Packet, expected_type: zdp::ZdpPacketType, expected_sn: SeqNum) {
        let (base_hdr, rest) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
        assert_eq!(base_hdr.packet_type, expected_type);
        let (mgmt_hdr, _) = zdp::ZdpMgmtHeader::read_from_prefix(rest).unwrap();
        assert_eq!(mgmt_hdr.sequence_number.get(), expected_sn);
    }
}
