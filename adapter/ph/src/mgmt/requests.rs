//! Management requests.
//!
//! No logic lives in here; this is just a simple API to send ZDP messages.

#![allow(dead_code)]

use super::core::{self, Sent};
use super::txn_mgr::TxnId;
use crate::assembly;
use crate::prelude::*;
use crate::tc;
use crate::tlv;
use crate::zdp;
use crate::{assembly::Assembly, auth};
use bytes::BufMut;
use zpr_ext::zerocopy::IntoBytesExt;
use zpr_utils::net_defs::IpAddress;

/// send a Key Management message (RFC 6.5 § 6.2.8)
pub fn send_key_management(asm: &Assembly, link_id: LinkId, km_id: KmId, payload: &[u8]) {
    let mut pkt = core::new_heap_packet();

    let km_hdr = pkt.alloc_zeroed_header::<zdp::ZdpKeyManagementHeader>();
    km_hdr.message_type = km_id.into();
    km_hdr.message_length = (payload.len() as u16).into();

    pkt.put(payload);

    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    hdr.packet_type = zdp::ZdpPacketType::KeyManagement;

    // bypass ZDPR
    let _ = asm
        .mgmt_substrate_egress
        .try_enqueue_packet(link_id, &mut pkt);
}

/// send a Discard message (RFC 6.5 § 6.3.1)
pub fn send_discard(asm: &Assembly, link_id: LinkId) -> Sent<'_> {
    let pkt = core::new_heap_packet();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt)
}

/// send an Echo Request (RFC 6.5 § 6.3.2)
pub fn send_echo_request(asm: &Assembly, link_id: LinkId) -> Sent<'_> {
    let mut pkt = core::new_heap_packet();
    pkt.alloc_zeroed_header::<zdp::ZdpEchoHeader>();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Echo, pkt)
}

/// send a Hello Request (RFC 6.5 § 6.3.4)
pub fn send_hello_request(
    asm: &Assembly,
    link_id: LinkId,
    a2a_dh_pubkey: x25519_dalek::PublicKey,
) -> Sent<'_> {
    let mut pkt = core::new_heap_packet();
    pkt.alloc_zeroed_header::<zdp::ZdpHelloRequestHeader>();
    super::helpers::put_window_size_tlv(asm, link_id, &mut pkt);
    tlv::TlvEncoding::new_actor_auth_protocol().put(&mut pkt);
    tlv::TlvEncoding::new_a2a_dh_pubkey(a2a_dh_pubkey).put(&mut pkt); //add public key to the packet
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::HelloRequest, pkt)
}

/// Send a successful HelloResponse on `link_id`. A Zode answering a Zode
/// link passes no AAA address and no identity providers (zl-zipline#250).
/// The `aaa_address` parameter stays: AAA kept unused in v1 (zodes plan
/// §5.4).
///
/// `oidc_idps` advertises off-net OIDC identity providers (one `OIDC_IDP` TLV
/// each); empty when the visa service has none configured.
pub fn send_hello_success_response<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    policy_id: i64,
    oidc_idps: &[auth::OidcIdpInfo],
    aaa_address: Option<IpAddress>,
) -> Sent<'a> {
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();
    hdr.status = zdp::ResponseCode::Success;

    // Policy ID and version are always included, even if not SUCCESS.
    tlv::TlvEncoding::new_policy_id(policy_id).put(&mut pkt);
    tlv::TlvEncoding::new_version(assembly::VERSION).put(&mut pkt);
    tlv::TlvEncoding::new_actor_auth_protocol().put(&mut pkt);

    super::helpers::put_window_size_tlv(&asm, link_id, &mut pkt);

    // Tailroom the TLVs after the IdP list still need: an AAA TLV is at most
    // 2 + 16 bytes. Keep a little extra margin.
    const HELLO_RESPONSE_TAILROOM: usize = 32;
    for idp in oidc_idps {
        match tlv::TlvEncoding::new_oidc_idp(idp) {
            Ok(enc) => {
                // Bound the aggregate: each accepted TLV can be up to 257
                // bytes, and the packet buffer is finite, so stop advertising
                // (rather than panic in put_slice) once the packet is full.
                if pkt.remaining_mut() < enc.encoded_len() + HELLO_RESPONSE_TAILROOM {
                    warn!(target: ZDP, "{}: HelloResponse - out of space, dropping OIDC IdP advertisement {} (and any after it)",
                        asm.formatted_link_id(link_id), idp.issuer);
                    break;
                }
                enc.put(&mut pkt);
            }
            Err(e) => {
                // Skip an unencodable IdP rather than fail the hello: the
                // adapter can still authenticate via any other advertised
                // mechanism.
                warn!(target: ZDP, "{}: HelloResponse - skipping OIDC IdP {}: {e}", asm.formatted_link_id(link_id), idp.issuer);
            }
        }
    }

    if let Some(aaa_addr) = aaa_address {
        tlv::TlvEncoding::new_aaa(aaa_addr).put(&mut pkt);
    }

    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::HelloResponse, pkt)
}

pub fn send_hello_error_response(
    asm: &Assembly,
    link_id: LinkId,
    status: zdp::ResponseCode,
) -> Sent<'_> {
    let mut pkt = core::new_heap_packet();
    pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>()
        .status = status;
    tlv::TlvEncoding::new_actor_auth_protocol().put(&mut pkt);
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::HelloResponse, pkt)
}

/// send a Terminate Link or Docking Session message (TODO: document)
pub fn send_terminate_link_or_docking_session<'a, 'pktbuf>(
    asm: &Assembly,
    link_id: LinkId,
    reason: zdp::TerminateReason,
) -> Sent<'_> {
    let mut pkt = core::new_heap_packet();
    pkt.push_header(&zdp::ZdpTerminateLinkOrDockingSessionHeader {
        reason_code: reason,
        data_len: 0,
    });
    core::send_non_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::TerminateLinkOrDockingSession,
        pkt,
    )
}

/// send a Bind Actor Address Request (RFC 6.5 § 6.3.11)
pub fn send_bind_actor_address_request<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    l3_type: L3Type,
    packet_body: &[u8],
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending BindActorAddressRequest with packet_body size {}", asm.formatted_link_id(link_id), packet_body.len());

    let mut req = core::new_heap_packet();
    let bind_req_hdr = req.alloc_zeroed_header::<zdp::ZdpBindActorAddressRequestHeader>();
    let endpoint_packet_length =
        std::cmp::min(config::BIND_REQUEST_MAX_PAYLOAD_LENGTH, packet_body.len());
    bind_req_hdr.l3_type = l3_type;
    bind_req_hdr
        .endpoint_packet_length
        .set(endpoint_packet_length as u16);
    req.put_slice(&packet_body[..endpoint_packet_length]);

    core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindActorAddressRequest,
        0,
        txn_id,
        req,
    )
}

pub fn send_bind_actor_address_success_response<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    tether_id: StreamId,
    tc: tc::Ip5TupleTc,
    peer_a2a_dh_pubkey: Option<&x25519_dalek::PublicKey>,
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending BindActorAddressResponse [success] for {txn_id}", asm.formatted_link_id(link_id));

    let mut rsp_pkt = core::new_heap_packet();

    zdp::ZdpBindActorAddressResponseHeader {
        status_code: zdp::ResponseCode::Success,
        info_len: 0,
    }
    .write_to_buf(&mut rsp_pkt)
    .unwrap();

    Tcst::Ip5Tuple.write_to_buf(&mut rsp_pkt).unwrap();
    tc.serialize(&mut rsp_pkt);

    // Write the peer's public key, if present, to end of the packet.
    match peer_a2a_dh_pubkey {
        Some(key) => {
            rsp_pkt.put_u16(key.as_bytes().len() as u16); // first write the length of the key as a u16
            rsp_pkt.put_slice(key.as_bytes()); // then write the key itself as a slice of bytes
        }
        None => rsp_pkt.put_u16(0),
    }
    super::core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindActorAddressResponse,
        tether_id,
        txn_id,
        rsp_pkt,
    )
}

pub fn send_bind_actor_address_error_response<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    reason: &str,
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending BindActorAddressResponse [error] for {txn_id}", asm.formatted_link_id(link_id));

    let mut rsp_pkt = core::new_heap_packet();

    let max_sz = u8::MAX as usize;
    let reason = &reason[..reason.len().min(max_sz)];
    zdp::ZdpBindActorAddressResponseHeader {
        status_code: zdp::ResponseCode::Other,
        info_len: reason.len() as u8,
    }
    .write_to_buf(&mut rsp_pkt)
    .unwrap();

    rsp_pkt.put(reason.as_bytes());

    super::core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindActorAddressResponse,
        0,
        txn_id,
        rsp_pkt,
    )
}

pub fn send_stream_id_request<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    visa_id: VisaId,
) -> Sent<'a> {
    debug!(target: ZDP, "Link {link_id}: sending StreamIdRequest for {visa_id}");

    let mut req = core::new_heap_packet();
    let bind_req_hdr = req.alloc_zeroed_header::<zdp::ZdpStreamIdRequest>();
    bind_req_hdr.visa_id = visa_id.into();

    core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::StreamIdRequest,
        0,
        txn_id,
        req,
    )
}

pub fn send_stream_id_success_response<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    tether_id: StreamId,
) -> Sent<'a> {
    debug!(target: ZDP, "Link {link_id}: sending StreamIdResponse [success] for {txn_id}");

    let mut rsp_pkt = core::new_heap_packet();

    zdp::ZdpStreamIdResponseHeader {
        status_code: zdp::ResponseCode::Success,
        info_len: 0,
    }
    .write_to_buf(&mut rsp_pkt)
    .unwrap();

    super::core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::StreamIdResponse,
        tether_id,
        txn_id,
        rsp_pkt,
    )
}

pub fn send_stream_id_error_response<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    reason: &str,
) -> Sent<'a> {
    debug!(target: ZDP, "Link {link_id}: sending StreamIdResponse [error] for {txn_id}");

    let mut rsp_pkt = core::new_heap_packet();
    let max_sz = u8::MAX as usize;
    let reason = &reason[..reason.len().min(max_sz)];
    zdp::ZdpStreamIdResponseHeader {
        status_code: zdp::ResponseCode::Other,
        info_len: reason.len() as u8,
    }
    .write_to_buf(&mut rsp_pkt)
    .unwrap();

    rsp_pkt.put(reason.as_bytes());

    super::core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::StreamIdResponse,
        0,
        txn_id,
        rsp_pkt,
    )
}

pub fn send_bind_egress_stream_request<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    tc: tc::Ip5TupleTc,
    peer_a2a_dh_pubkey: Option<&x25519_dalek::PublicKey>,
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending BindEgressStreamRequest for {tc}", asm.formatted_link_id(link_id));

    let mut req = core::new_heap_packet();
    let bind_req_hdr = req.alloc_zeroed_header::<zdp::ZdpBindEgressStreamRequestHeader>();
    bind_req_hdr.tcst = Tcst::Ip5Tuple;
    tc.serialize(&mut req);

    // Write the peer's public key, if present, to end of the packet.
    match peer_a2a_dh_pubkey {
        Some(key) => {
            req.put_u16(key.as_bytes().len() as u16); // first write the length of the key as a u16
            req.put_slice(key.as_bytes()); // then write the key itself as a slice of bytes
        }
        None => req.put_u16(0),
    }

    core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindEgressStreamRequest,
        0,
        txn_id,
        req,
    )
}

pub fn send_bind_egress_stream_success_response<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    tether_id: StreamId,
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending BindEgressStreamResponse [success] for {txn_id}", asm.formatted_link_id(link_id));

    let mut rsp_pkt = core::new_heap_packet();

    zdp::ZdpBindEgressStreamResponseHeader {
        status_code: zdp::ResponseCode::Success,
        info_len: 0,
    }
    .write_to_buf(&mut rsp_pkt)
    .unwrap();

    super::core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindEgressStreamResponse,
        tether_id,
        txn_id,
        rsp_pkt,
    )
}

pub fn send_bind_egress_stream_error_response<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    reason: &str,
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending BindEgressStreamResponse [error] for {txn_id}", asm.formatted_link_id(link_id));

    let mut rsp_pkt = core::new_heap_packet();
    let max_sz = u8::MAX as usize;
    let reason = &reason[..reason.len().min(max_sz)];
    zdp::ZdpBindEgressStreamResponseHeader {
        status_code: zdp::ResponseCode::Other,
        info_len: reason.len() as u8,
    }
    .write_to_buf(&mut rsp_pkt)
    .unwrap();

    rsp_pkt.put(reason.as_bytes());

    super::core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindEgressStreamResponse,
        0,
        txn_id,
        rsp_pkt,
    )
}

/// send a Report message (RFC 6.5 § 6.3.13)
pub fn send_report<'a>(asm: &'a Assembly, link_id: LinkId, report: &'_ str) -> Sent<'a> {
    // TODO this condition will need to be adjusted when we have complete ZPR packets
    // with the information at the end of the packet at well
    /*if packet::PACKET_BUFFER_MAX_BODY_SIZE - config::DEFAULT_MESSAGE_HEADROOM < report.len() {
        return;
    }*/  // CTP FIXME
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpReportHeader>();
    hdr.report_data_length = (report.len() as u16).into();
    pkt.put(report.as_bytes());
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Report, pkt)
}

/// send a Stream ID Withdrawal message (ZdpPacketType 5)
///
/// Node -> peer adapter, per-flow: "the stream id you send with has been
/// withdrawn; drop your egress binding". `stream_id` is the tether id the
/// receiving adapter holds in its outbound ELT (zipline#21).
pub fn send_stream_id_withdrawal<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    stream_id: StreamId,
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending StreamIdWithdrawal", asm.formatted_link_id(link_id));

    let req = core::new_heap_packet();

    core::send_per_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::StreamIdWithdrawal,
        stream_id,
        req,
    )
}

/// send an Unbind Egress Stream Indication message (ZdpPacketType 13)
///
/// Node -> its own adapter, per-flow, over the local actor link only:
/// "this Zode no longer forwards to the stream id you granted; drop it from
/// your DLT" (zl-zipline#283). `stream_id` is the DLT id the adapter
/// granted for the binding. Never sent on a Zode link (F5): the caller,
/// [crate::assembly::Assembly::unbind_local_egress], checks.
pub fn send_unbind_egress_stream_indication<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    stream_id: StreamId,
) -> Sent<'a> {
    debug!(target: ZDP, "{}: sending UnbindEgressStreamIndication", asm.formatted_link_id(link_id));

    let req = core::new_heap_packet();

    core::send_per_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::UnbindEgressStreamIndication,
        stream_id,
        req,
    )
}
