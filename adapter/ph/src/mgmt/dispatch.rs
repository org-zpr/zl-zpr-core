//! Code which handles dispatching management packets from fastpath.

use super::core;
use crate::counters::{ManagementCounterType, ManagementCounters};
use crate::km_multiplexor;
use crate::link_state::LinkType;
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

/// Dispatch the given management packet.
///
/// This function does not block, and does not perform significant processing.
/// It merely dispatches the management packet to the correct queue.
pub fn dispatch_mgmt_packet_with_link(asm: &Assembly, pkt: &mut Packet) {
    let Ok((base_hdr, rest)) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()) else {
        core::count_event(asm, ManagementCounterType::BadStructure);
        return;
    };

    match base_hdr.packet_type {
        zdp::ZdpPacketType::KeyManagement => {
            pkt.advance(std::mem::size_of::<zdp::ZdpBaseHeader>());
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
        let asm = create_assembly(tab);

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
