//! Handlers for management requests.
//!
//! These handlers just decode the packet and forward work to whatever
//! internal API is responsible for handling it.  There are no "smarts" in
//! this module.

use super::txn_mgr::TxnId;
use super::{adapter, node};
use crate::auth;
use crate::counters;
use crate::link_state::{LinkEvent, LinkStateError, LinkType};
use crate::peer_table::PeerType;
use crate::prelude::*;
use crate::tc;
use crate::tlv;
use crate::zdp;
use std::num::NonZero;
use thiserror::Error;
use zpr::packet_info::DOCK_LINK_ID;
use zpr_ext::zerocopy::FromBytesExt;
use zpr_utils::net_defs::IpAddress;

/// Indicates whether the mgmt message was handled successfully.
/// (It may be the case that the mgmt message itself indicates
/// failure of a remote operation; modulo a parsing issue,
/// handling such a message would still be considered successful.)
#[derive(Debug, Error)]
pub enum HandleMgmtError {
    #[error("unknown packet type: {0}")]
    UnknownType(u8),

    #[error("message not permitted")]
    MessageNotPermitted,

    #[error("bad packet structure")]
    BadStructure,

    #[error("unknown transaction")]
    UnknownTransaction,

    #[error("link state error: {0}")]
    LinkStateError(#[from] LinkStateError),

    #[error("link closed")]
    LinkClosed,

    #[error("bootstrap visa hand-off refused: {0}")]
    HandoffRefused(#[from] crate::bootstrap_handoff::HandoffError),
}

const X25519_KEY_LEN: usize = 32;

impl From<&HandleMgmtError> for counters::ManagementCounterType {
    fn from(err: &HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::BadStructure => Self::BadStructure,
            HandleMgmtError::MessageNotPermitted => Self::OtherError,
            HandleMgmtError::UnknownTransaction => Self::UnknownTransaction,
            HandleMgmtError::LinkStateError(_) => Self::OtherError,
            HandleMgmtError::LinkClosed => Self::OtherError,
            HandleMgmtError::HandoffRefused(_) => Self::BootstrapHandoffRefused,
        }
    }
}

impl From<super::core::MgmtSendError> for HandleMgmtError {
    fn from(err: super::core::MgmtSendError) -> Self {
        match err {
            super::core::MgmtSendError::LinkClosed => HandleMgmtError::LinkClosed,
        }
    }
}

impl From<adapter::InstallTetherError> for HandleMgmtError {
    fn from(err: adapter::InstallTetherError) -> Self {
        match err {
            adapter::InstallTetherError::NoSuchTransaction => HandleMgmtError::UnknownTransaction,
        }
    }
}

impl From<node::InstallTetherError> for HandleMgmtError {
    fn from(err: node::InstallTetherError) -> Self {
        match err {
            node::InstallTetherError::NoSuchTransaction => HandleMgmtError::UnknownTransaction,
            node::InstallTetherError::LinkClosed => HandleMgmtError::LinkClosed,
        }
    }
}

pub type HandleMgmtResult = Result<(), HandleMgmtError>;

/// handle a Report message (RFC 6.5 § 6.3.13)
pub async fn handle_report(_asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpReportHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    // TODO handle protocol errors i.e. if the body is shorter
    let report_data_length: usize = hdr.report_data_length.into();
    pkt.advance(std::mem::size_of::<zdp::ZdpReportHeader>());
    if pkt.body().len() >= report_data_length {
        info!(
            target: REPORTING,
            "{}: {}",
            pkt.metadata().ingress_link_id,
            std::str::from_utf8(&pkt.body()[..report_data_length]).unwrap()
        );
    }
    Ok(())
}

/// handle a Discard message (RFC 6.5 § 6.3.1)
pub async fn handle_discard(_asm: &Arc<Assembly>, pkt: Packet) -> HandleMgmtResult {
    // TODO print to debug log, when implemented
    info!(
        target: REPORTING,
        "Discard message received from {}",
        pkt.metadata().ingress_link_id
    );
    Ok(())
}

/// handle an Echo Request message (RFC 6.5 § 6.3.2)
pub async fn handle_echo_request(_asm: &Arc<Assembly>, _pkt: Packet) -> HandleMgmtResult {
    // we simply rely on the ZDPR ACK
    Ok(())
}

/// TODO: Not yet in RFC 6
///
/// Message from node requesting authentication.
/// Sends a [zdp::ZdpInitAuthenticationResponse] back.
///
pub async fn handle_init_authentication_request(
    asm: &Arc<Assembly>,
    txn: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok(hdr) = zdp::ZdpInitAuthenticationRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };
    let is_bootstrap = hdr.flags & zdp::init_authentication_flags::BOOTSTRAP_SUPPORT != 0;

    let challenge_opt: Option<auth::ZdpInitAuthenticationPayload>;

    if !valid_auth_status(hdr.status)
        || hdr.flags & !zdp::init_authentication_flags::BOOTSTRAP_SUPPORT != 0
        || (hdr.status != zdp::AuthenticationStatus::Success
            && (hdr.flags != 0 || hdr.data_len.get() != 0))
    {
        return Err(HandleMgmtError::BadStructure);
    }
    if is_bootstrap {
        if hdr.data_len.get() as usize != size_of::<auth::ZdpInitAuthenticationPayload>() {
            return Err(HandleMgmtError::BadStructure);
        }
        debug!(target: ZDP, "Received Init Authentication +bootstrap for {}", asm.formatted_link_id(ingress_link_id));

        let Ok(payload) = auth::ZdpInitAuthenticationPayload::read_from_buf(&mut pkt) else {
            return Err(HandleMgmtError::BadStructure);
        };
        challenge_opt = Some(payload);
    } else {
        if hdr.data_len.get() != 0 {
            return Err(HandleMgmtError::BadStructure);
        }
        debug!(target: ZDP, "Received Init Authentication for {} -- bootstrap not supported", asm.formatted_link_id(ingress_link_id));
        challenge_opt = None;
    }

    // Upstream #1410 carries ASA TLVs here; zipline removed ASA with the
    // BAS/OAuthRsa client (zipline#15), so any TLVs are parsed (to reject a
    // malformed body) and ignored.
    tlv::parse_from_buf(&mut pkt).map_err(|_| HandleMgmtError::BadStructure)?;
    asm.peer_table
        .get(ingress_link_id)
        .ok_or(HandleMgmtError::LinkClosed)?
        .actor_auth
        .receive_offer(
            txn,
            crate::actor_auth::AuthenticationOffer {
                status: hdr.status,
                challenge: challenge_opt,
            },
        )?;

    Ok(())
}

fn valid_auth_status(status: zdp::AuthenticationStatus) -> bool {
    matches!(
        status,
        zdp::AuthenticationStatus::Success
            | zdp::AuthenticationStatus::Rejected
            | zdp::AuthenticationStatus::Retryable
            | zdp::AuthenticationStatus::PolicyDenied
    )
}

pub async fn handle_start_authentication(
    asm: &Arc<Assembly>,
    txn: TxnId,
    pkt: Packet,
) -> HandleMgmtResult {
    if pkt.remaining() != 0 {
        return Err(HandleMgmtError::BadStructure);
    }
    asm.peer_table
        .get(pkt.metadata().ingress_link_id)
        .ok_or(HandleMgmtError::LinkClosed)?
        .actor_auth
        .start_remote(asm, txn)
}

pub async fn handle_abandon_authentication(
    asm: &Arc<Assembly>,
    txn: TxnId,
    pkt: Packet,
) -> HandleMgmtResult {
    if pkt.remaining() != 0 {
        return Err(HandleMgmtError::BadStructure);
    }
    asm.peer_table
        .get(pkt.metadata().ingress_link_id)
        .ok_or(HandleMgmtError::LinkClosed)?
        .actor_auth
        .abandon_remote(asm, txn)
}

/// Handle a Renew Authentication request (zipline#66; NOT YET IN RFC 6)
///
/// Node → adapter on an Active link: carries the fresh challenge the
/// renewed credential must bind to. Routed to the link's actor renewal
/// state ([crate::actor_renewal]).
pub async fn handle_renew_authentication_request(
    asm: &Arc<Assembly>,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok(hdr) = zdp::ZdpRenewAuthenticationRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };
    if usize::from(hdr.data_len.get()) < size_of::<auth::ZdpInitAuthenticationPayload>() {
        warn!(target: ZDP, "Received Renew Authentication with unexpected payload size {}", hdr.data_len.get());
        return Err(HandleMgmtError::BadStructure);
    }
    if pkt.remaining() < usize::from(hdr.data_len.get()) {
        warn!(target: ZDP, "packet too short for renewal challenge payload");
        return Err(HandleMgmtError::BadStructure);
    }
    let Ok(payload) = auth::ZdpInitAuthenticationPayload::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    debug!(target: ZDP, "Received Renew Authentication request for {}", asm.formatted_link_id(ingress_link_id));

    crate::actor_renewal::receive_renew_request(asm, ingress_link_id, payload)
}

/// Handle a Renew Authentication response (zipline#66; NOT YET IN RFC 6)
///
/// Adapter → node: the renewed auth blob on success, or the failure status,
/// plus the echoed challenge of the request it answers. Routed to the
/// link's actor renewal state ([crate::actor_renewal]).
pub async fn handle_renew_authentication_response(
    asm: &Arc<Assembly>,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok(hdr) = zdp::ZdpRenewAuthenticationResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };
    let challenge = hdr.challenge;
    if !valid_auth_status(hdr.status_code) {
        return Err(HandleMgmtError::BadStructure);
    }

    let result: Result<String, zdp::AuthenticationStatus>;
    if hdr.status_code == zdp::AuthenticationStatus::Success {
        let blen = hdr.blob_len.get() as usize;
        if blen == 0 {
            warn!(target: ZDP, "Received successful Renew Authentication response with no blob");
            return Err(HandleMgmtError::BadStructure);
        }
        if pkt.remaining() < blen {
            warn!(target: ZDP, "packet too short for renewal blob");
            return Err(HandleMgmtError::BadStructure);
        }
        let blob_buffer = pkt.copy_to_bytes(blen);
        match String::from_utf8(blob_buffer.into()) {
            Ok(blob) => result = Ok(blob),
            Err(_) => {
                warn!(target: ZDP, "failed to parse renewal blob as utf8");
                return Err(HandleMgmtError::BadStructure);
            }
        }
    } else {
        result = Err(hdr.status_code);
    }

    debug!(target: ZDP, "Received Renew Authentication response for {} (status {:?})",
        asm.formatted_link_id(ingress_link_id), hdr.status_code);

    crate::actor_renewal::receive_renew_response(asm, ingress_link_id, challenge, result)
}

/// handle a Terminate Link or Docking Session message (TODO: document in RFC 17)
///
/// Sends [LinkEvent::ReceivedTerminateLink] into the link state machine.
/// Sends a ZdpTerminateResponse message back to the sender.
/// Sends a [LinkEvent::SentTerminate] event into the link state machine.
pub async fn handle_terminate_link_or_docking_session(
    asm: &Arc<Assembly>,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let Ok(hdr) = zdp::ZdpTerminateLinkOrDockingSessionHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    info!(target: ZDP, "Received Terminate Link or Docking Session for {}", asm.formatted_link_id(ingress_link_id));

    asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedTerminateLink(hdr.reason_code),
    )?;

    Ok(())
}

/// handle a Hello Request (RFC 6.5 § 6.3.4)
/// Reads the hello, fire a ReceivedHelloRequest event, and then sends a response.
///
pub async fn handle_hello_request(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    if asm.ph_mode != PhMode::Node {
        warn!(target: ZDP, "{} received Hello Request but not in node mode", asm.formatted_link_id(ingress_link_id));
        return Err(HandleMgmtError::MessageNotPermitted);
    }
    debug!(target: ZDP, "Received Hello Request for {}", asm.formatted_link_id(ingress_link_id));

    let tlv_data = match tlv::parse_from_buf(&mut pkt) {
        Ok(data) => data,
        Err(_) => {
            error!(target: ZDP, "{}: Failed to parse HelloRequest TLV data", asm.formatted_link_id(ingress_link_id));
            return Err(HandleMgmtError::BadStructure);
        }
    };

    if !has_actor_auth_protocol(&tlv_data) {
        warn!(target: ZDP, "{}: incompatible actor authorization protocol", asm.formatted_link_id(ingress_link_id));
        super::requests::send_hello_error_response(
            asm,
            ingress_link_id,
            zdp::ResponseCode::UnsupportedProtocol,
        )
        .enqueue();
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    // We just emit the TLV stuff to log but only use window size and the A2A key.
    for (tlv_type, tlv_value) in &tlv_data {
        match *tlv_type {
            tlv::DataType::WINDOW_SIZE => {
                process_window_size_tlv(&asm, ingress_link_id, "HelloRequest", tlv_value)?;
            }
            tlv::DataType::A2A_DH_PUBKEY => {
                process_a2a_dh_pubkey_tlv(&asm, ingress_link_id, "HelloRequest", tlv_value)?;
            }
            _ => {
                info!(
                    "{}: HelloRequest includes ignored TLV type: {tlv_type} => {tlv_value:?}",
                    asm.formatted_link_id(ingress_link_id)
                );
            }
        }
    }

    //Warn adapter did not send key. Connection is not rejected in case of future changes
    if !tlv_data.contains_key(&tlv::DataType::A2A_DH_PUBKEY) {
        warn!(target: ZDP, "{}: HelloRequest did not include A2A_DH_PUBKEY", asm.formatted_link_id(ingress_link_id));
    }
    asm.process_link_state_event(ingress_link_id, LinkEvent::ReceivedHelloRequest)?;

    Ok(())
}

/// Handle a Bootstrap Visas message (ZDP 146, zl-zipline#252 J4): the
/// relay handing this joining Zode its two bootstrap visas. Installed only
/// if every check in [crate::bootstrap_handoff::check_handoff] passes.
///
/// A refusal is logged and returned as an error, which the management
/// processor counts (`BootstrapHandoffRefused`) and turns into a link
/// error that closes the link: the strict handler-error convention of
/// #251 (gate g88 q2). On the initial link the joiner then redials with
/// backoff, and the new link brings a fresh hand-off (rule 11a).
pub async fn handle_bootstrap_visas(asm: &Arc<Assembly>, pkt: Packet) -> HandleMgmtResult {
    let link_id = pkt.metadata().ingress_link_id;
    crate::bootstrap_handoff::accept(asm, link_id, pkt.body()).map_err(|e| {
        warn!(target: ZDP, "{}: refused a bootstrap visa hand-off: {e}; closing the link", asm.formatted_link_id(link_id));
        HandleMgmtError::from(e)
    })
}

pub async fn handle_hello_response(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let link_id = pkt.metadata().ingress_link_id;
    let event = parse_hello_response(asm, link_id, &mut pkt)?;
    asm.process_link_state_event(link_id, event)?;
    Ok(())
}

/// Parse a HelloResponse body into the [LinkEvent::ReceivedHelloResponse] to
/// raise: status code, optional AAA address, and any advertised OIDC identity
/// providers (OIDC_IDP TLVs, JSON [auth::OidcIdpInfo] each; a TLV with bad
/// JSON is warned about and skipped). On a Zode link, a response carrying
/// any of those TLVs yields a [LinkEvent::Close] instead.
fn parse_hello_response(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    pkt: &mut Packet,
) -> Result<LinkEvent, HandleMgmtError> {
    let Ok(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let status = hdr.status;
    debug!(target: ZDP, "{}: received HelloResponse, status: {status:?}", asm.formatted_link_id(link_id));

    // Following status are the TLVs.
    // A tlv has a type (number) and a value.
    let tlv_data = match tlv::parse_from_buf(pkt) {
        Ok(data) => data,
        Err(e) => {
            error!(target: ZDP, "{}: HelloResponse - failed to parse TLVs: {:?}", asm.formatted_link_id(link_id), e);
            return Err(HandleMgmtError::BadStructure);
        }
    };

    if !has_actor_auth_protocol(&tlv_data) {
        warn!(target: ZDP, "{}: incompatible actor authorization protocol", asm.formatted_link_id(link_id));
        return Err(HandleMgmtError::MessageNotPermitted);
    }
    // zl-zipline#250 (gaps 5 and 6): a Zode answers Hello with none of the
    // TLVs an adapter dock gets. Refuse their mere presence on a Zode link,
    // before the tolerant decoding below can skip an undecodable one: the
    // event becomes a close.
    let zode_link = asm
        .peer_table
        .inspect(link_id, |p| {
            p.link_state_machine.get_link_type() == LinkType::NodeToNode
        })
        .unwrap_or(false);
    let adapter_tlvs = [
        tlv::DataType::AAA,
        tlv::DataType::OIDC_IDP,
        tlv::DataType::VS_BOOTSTRAP_LINK,
    ]
    .iter()
    .any(|t| tlv_data.contains_key(t));
    if zode_link && adapter_tlvs {
        warn!(target: ZDP, "{}: refusing a Zode HelloResponse that carries AAA, OIDC_IDP or VS_BOOTSTRAP_LINK; closing", asm.formatted_link_id(link_id));
        return Ok(LinkEvent::Close(zdp::TerminateReason::Other));
    }
    let vs_bootstrap = match tlv_data.get(&tlv::DataType::VS_BOOTSTRAP_LINK) {
        None => false,
        Some(values) if matches!(values.as_slice(), [tlv::TlvValue::U16(1)]) => true,
        _ => return Err(HandleMgmtError::BadStructure),
    };
    let mut aaa_address: Option<IpAddress> = None;
    let mut oidc_idps = Vec::<auth::OidcIdpInfo>::new();

    for (tlv_type, tlv_value) in &tlv_data {
        match tlv_type {
            &tlv::DataType::VERSION => {
                info!(target: ZDP, "{}: HelloResponse - peer version is : {}", asm.formatted_link_id(link_id), tlv_value[0]);
            }
            &tlv::DataType::WINDOW_SIZE => {
                process_window_size_tlv(&asm, link_id, "HelloResponse", tlv_value)?;
            }
            &tlv::DataType::POLICY_ID => {
                info!(target: ZDP, "{}: HelloResponse - peer policy ID is : {}", asm.formatted_link_id(link_id), tlv_value[0]);
            }
            &tlv::DataType::AAA => {
                for aaa_entry in tlv_value {
                    if aaa_address.is_some() {
                        warn!(target: ZDP, "{}: HelloResponse includes multiple AAA addresses", asm.formatted_link_id(link_id));
                        return Err(HandleMgmtError::BadStructure);
                    }
                    match aaa_entry {
                        tlv::TlvValue::Ipv4Addr(ipa) => {
                            info!(target: ZDP, "{}: HelloResponse includes AAA address:{ipa}", asm.formatted_link_id(link_id));
                            aaa_address = Some(IpAddress::new_from_std_v4(ipa));
                        }
                        tlv::TlvValue::Ipv6Addr(ipa) => {
                            info!(target: ZDP, "{}: HelloResponse includes AAA address:{ipa}", asm.formatted_link_id(link_id));
                            aaa_address = Some(IpAddress::new_from_std_v6(ipa));
                        }
                        _ => {
                            warn!(target: ZDP, "{}: HelloResponse AAA value type is wrong: {aaa_entry:?}", asm.formatted_link_id(link_id));
                            return Err(HandleMgmtError::BadStructure);
                        }
                    }
                }
            }
            &tlv::DataType::OIDC_IDP => {
                for idp_entry in tlv_value {
                    match idp_entry {
                        tlv::TlvValue::Str(json) => {
                            match serde_json::from_str::<auth::OidcIdpInfo>(json) {
                                Ok(idp) => {
                                    info!(target: ZDP, "{}: HelloResponse includes OIDC IdP: {}", asm.formatted_link_id(link_id), idp.issuer);
                                    oidc_idps.push(idp);
                                }
                                Err(e) => {
                                    // Tolerate a bad advertisement rather than
                                    // failing the whole hello.
                                    warn!(target: ZDP, "{}: HelloResponse OIDC_IDP has invalid JSON, skipping: {e}", asm.formatted_link_id(link_id));
                                }
                            }
                        }
                        _ => {
                            warn!(target: ZDP, "{}: HelloResponse OIDC_IDP value type is wrong: {idp_entry:?}", asm.formatted_link_id(link_id));
                            return Err(HandleMgmtError::BadStructure);
                        }
                    }
                }
            }
            _ => {
                info!(target: ZDP, "{}: HelloResponse includes ignored TLV type: {tlv_type}, continuing", asm.formatted_link_id(link_id));
            }
        }
    }

    if aaa_address.is_none() {
        // Pretty sure only happens if node has no AAA pool from VS yet.
        // Not an issue unless this adapter needs to talk to an authentication service.
        warn!(target: ZDP, "{}: HelloResponse did not include AAA", asm.formatted_link_id(link_id));
    }

    let maybe_oidc_idps = if oidc_idps.is_empty() {
        None
    } else {
        Some(oidc_idps)
    };

    Ok(LinkEvent::ReceivedHelloResponse {
        status,
        aaa_address,
        oidc_idps: maybe_oidc_idps,
        vs_bootstrap,
    })
}

fn has_actor_auth_protocol(data: &std::collections::HashMap<u8, Vec<tlv::TlvValue>>) -> bool {
    matches!(
        data.get(&tlv::DataType::ACTOR_AUTH_PROTOCOL)
            .map(Vec::as_slice),
        Some([tlv::TlvValue::U16(tlv::ACTOR_AUTH_PROTOCOL_VERSION)])
    )
}

fn process_window_size_tlv(
    asm: &Assembly,
    link_id: LinkId,
    message_name: &str,
    tlv_value: &[tlv::TlvValue],
) -> HandleMgmtResult {
    for window_size_entry in tlv_value {
        match window_size_entry {
            tlv::TlvValue::U16(window_size) => {
                if *window_size < 1 {
                    warn!(target: ZDP, "{}: {message_name} window size is invalid: {window_size}", asm.formatted_link_id(link_id));
                } else {
                    info!(target: ZDP, "{}: Applying window size {window_size} from {message_name}", asm.formatted_link_id(link_id));
                    asm.peer_table.inspect(link_id, |ps| {
                        ps.zdpr_send
                            .lock()
                            .unwrap()
                            .adjust_window_size(*window_size as usize)
                    });
                }
            }
            _ => {
                warn!(target: ZDP, "{}: {message_name} window size type is wrong: {window_size_entry:?}", asm.formatted_link_id(link_id));
                return Err(HandleMgmtError::BadStructure);
            }
        }
    }
    Ok(())
}

fn process_a2a_dh_pubkey_tlv(
    asm: &Assembly,
    link_id: LinkId,
    message_name: &str,
    tlv_value: &[tlv::TlvValue],
) -> HandleMgmtResult {
    for entry in tlv_value {
        match entry {
            tlv::TlvValue::X25519PubKey(pubkey) => {
                info!(target: ZDP, "{}: Applying A2A_DH_PUBKEY from {message_name}", asm.formatted_link_id(link_id));
                asm.peer_table.inspect(link_id, |ps| {
                    ps.a2a_dh_pubkey.write(Some(*pubkey));
                });
            }
            _ => {
                warn!(target: ZDP, "{}: {message_name} A2A_DH_PUBKEY value type is wrong: {entry:?}", asm.formatted_link_id(link_id));
                return Err(HandleMgmtError::BadStructure);
            }
        }
    }
    Ok(())
}

/// Handle the AcquireZprAddressRequest (TODO: Not yet in RFC 6)
///
/// This message is from an adapter to a node.  Or in the future from
/// a joining node to an existing node.
///
/// This request must include an authentication blob from the
/// adapter.
///
/// In the future we (node/vs) will assign a ZPR address to the adapter
/// after verifying authentication.  During a transition period to full
/// authentication we permit the adapter to send us an address it wants
/// to have and if authentication succeeds, we just send that address
/// back (in the grant message).
///
/// The authentication blob may come from bootstrap auth or from real
/// auth-service auth.
///
pub async fn handle_acquire_zpr_address_request(
    asm: &Arc<Assembly>,
    txn: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok((actor_addresses, blob)) = parse_acquire_zpr_address_request(&mut pkt) else {
        error!(target: ZDP, "{} Failed to parse Acquire Zpr Address Request message", asm.formatted_link_id(ingress_link_id));
        return Err(HandleMgmtError::BadStructure);
    };

    // Now we can do our async prcessing of the acquire which will involve talking to
    // the visa service.

    debug!(target: ZDP, "{}: received Acquire ZPR Address Request for link with addresses {:?}", asm.formatted_link_id(ingress_link_id), actor_addresses);

    asm.peer_table
        .get(ingress_link_id)
        .ok_or(HandleMgmtError::LinkClosed)?
        .actor_auth
        .acquire_remote(asm, txn, actor_addresses, blob)?;

    Ok(())
}

/// Handle the GrantZprAddressRequest (TODO: Not yet in RFC 6)
///
/// This message comes from a node post verification of the authentication blob
/// which we get in an Acquire message.
///
/// Routes the transaction's outcome to the independent actor controller.
pub async fn handle_grant_zpr_address_request(
    asm: &Arc<Assembly>,
    txn: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let (status, addresses) = match parse_grant_zpr_address_request(&mut pkt)? {
        Ok(addresses) => (zdp::AuthenticationStatus::Success, addresses),
        Err(status) => (status, Vec::new()),
    };
    asm.peer_table
        .get(ingress_link_id)
        .ok_or(HandleMgmtError::LinkClosed)?
        .actor_auth
        .receive_grant(txn, status, addresses)?;

    Ok(())
}

/// Returns tuple of (actor_addresses, blob)
/// The addresses are left the address requested by the adapter. This is left over from
/// the older register-actor-address.  Until we are actually assigning addresses we
/// will honor the senders request.
///
/// The blob is a base64 encoded json object.
fn parse_acquire_zpr_address_request(
    pkt: &mut Packet,
) -> Result<(Option<Vec<IpAddress>>, String), HandleMgmtError> {
    let Ok(hdr) = zdp::ZdpAcquireZprAddressHeader::read_from_buf(pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };
    if hdr.addr_count > 1 || !matches!(hdr.ip_version, L3Type::Ipv4 | L3Type::Ipv6) {
        return Err(HandleMgmtError::BadStructure);
    }

    // In memmory:
    //     header
    //     blob
    //     actor addresses (optional)

    let blob: String;
    let blen = hdr.blob_len.get() as usize;
    if blen == 0 {
        // BLOB must be sent!
        error!(target: ZDP, "Received AcquireZprAddressRequest with no blob");
        return Err(HandleMgmtError::BadStructure);
    } else {
        if pkt.remaining() < blen {
            warn!(target: ZDP, "packet too short for blob");
            return Err(HandleMgmtError::BadStructure);
        }
        let blob_buffer = pkt.copy_to_bytes(blen);
        match String::from_utf8(blob_buffer.into()) {
            Ok(b) => {
                blob = b;
            }
            Err(_) => {
                warn!(target: ZDP, "failed to parse blob as utf8");
                return Err(HandleMgmtError::BadStructure);
            }
        }
    }

    let actor_addresses: Option<Vec<IpAddress>>;
    if hdr.addr_count > 0 {
        let bytes_needed = match hdr.ip_version {
            L3Type::Ipv4 => 4 * hdr.addr_count as usize,
            L3Type::Ipv6 => 16 * hdr.addr_count as usize,
            _ => {
                warn!(target: ZDP, "invalid ip_version field");
                return Err(HandleMgmtError::BadStructure);
            }
        };
        if pkt.remaining() < bytes_needed {
            warn!(target: ZDP, "packet too short for addresses");
            return Err(HandleMgmtError::BadStructure);
        }
        let mut addrs = Vec::new();
        for _ in 0..hdr.addr_count {
            let addr: IpAddress;
            match hdr.ip_version {
                L3Type::Ipv4 => {
                    let Ok(addr_bytes) = <[u8; 4]>::read_from_buf(pkt) else {
                        return Err(HandleMgmtError::BadStructure);
                    };
                    addr = addr_bytes.into();
                }
                L3Type::Ipv6 => {
                    let Ok(addr_bytes) = <[u8; 16]>::read_from_buf(pkt) else {
                        return Err(HandleMgmtError::BadStructure);
                    };
                    addr = addr_bytes.into();
                }
                _ => {
                    panic!("already handled this error above")
                }
            }
            addrs.push(addr);
        }
        actor_addresses = Some(addrs);
    } else {
        actor_addresses = None;
    }
    if pkt.remaining() != 0 {
        return Err(HandleMgmtError::BadStructure);
    }
    Ok((actor_addresses, blob))
}

/// The grant is a message from a node to an adapter (future: or to a joining node).
/// In includes the address (or addresses) we have been assigned to use.
fn parse_grant_zpr_address_request(
    pkt: &mut Packet,
) -> Result<Result<Vec<IpAddress>, zdp::AuthenticationStatus>, HandleMgmtError> {
    let Ok(hdr) = zdp::ZdpGrantZprAddressHeader::read_from_buf(pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    // In memmory:
    //     header
    //     actor addresses (optional)

    if !valid_auth_status(hdr.status_code) {
        return Err(HandleMgmtError::BadStructure);
    }
    if hdr.status_code != zdp::AuthenticationStatus::Success {
        if hdr.addr_count != 0 || pkt.remaining() != 0 {
            return Err(HandleMgmtError::BadStructure);
        }
        warn!(target: ZDP, "Received Grant Zpr Address Request with non-success status code {:?}", hdr.status_code);
        return Ok(Err(hdr.status_code));
    }
    if hdr.addr_count != 1 {
        return Err(HandleMgmtError::BadStructure);
    }

    let mut actor_addresses = Vec::new();
    let bytes_needed = match hdr.ip_version {
        L3Type::Ipv4 => 4 * hdr.addr_count as usize,
        L3Type::Ipv6 => 16 * hdr.addr_count as usize,
        _ => {
            warn!(target: ZDP, "invalid ip_version field");
            return Err(HandleMgmtError::BadStructure);
        }
    };
    if pkt.remaining() < bytes_needed {
        warn!(target: ZDP, "packet too short for addresses");
        return Err(HandleMgmtError::BadStructure);
    }
    for _ in 0..hdr.addr_count {
        let addr: IpAddress;
        match hdr.ip_version {
            L3Type::Ipv4 => {
                let Ok(addr_bytes) = <[u8; 4]>::read_from_buf(pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                addr = addr_bytes.into();
            }
            L3Type::Ipv6 => {
                let Ok(addr_bytes) = <[u8; 16]>::read_from_buf(pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                addr = addr_bytes.into();
            }
            _ => {
                return Err(HandleMgmtError::BadStructure);
            }
        }
        actor_addresses.push(addr);
    }
    if pkt.remaining() != 0 {
        return Err(HandleMgmtError::BadStructure);
    }
    Ok(Ok(actor_addresses))
}

/// handle a Bind Actor Address Request (RFC 6.5 § 6.3.11)
pub async fn handle_bind_actor_address_request(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpBindActorAddressRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let l3_type = hdr.l3_type;

    let endpoint_packet_length = hdr.endpoint_packet_length.get() as usize;
    if endpoint_packet_length > pkt.len() {
        return Err(HandleMgmtError::BadStructure);
    }

    // drop any garbage after the packet body
    pkt.shrink_by(pkt.len() - endpoint_packet_length);

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    // must come from an adapter
    let peer_type = peer_type_by_id(&asm, ingress_link_id);
    if !matches!(peer_type, PeerType::Adapter) {
        error!(target: ZDP, "{}: received BindActorAddress message on {peer_type} link", ingress_link_id);
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    debug!(target: ZDP, "{}: handlers.handle_bind_actor_address_request", asm.formatted_link_id(ingress_link_id.get()));

    node::bind_actor_address(asm, ingress_link_id, txn_id, l3_type, pkt.body());

    Ok(())
}

pub async fn handle_stream_id_request(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let Ok(req) = zdp::ZdpStreamIdRequest::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let visa_id = req.visa_id.get();

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    // must come from a node
    let peer_type = peer_type_by_id(&asm, ingress_link_id);
    if !matches!(peer_type, PeerType::Node) {
        error!(target: ZDP, "{}: received StreamIdRequest message on {peer_type} link", ingress_link_id);
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    debug!(
        target: ZDP,
        "Link {}: handlers.handle_stream_id_request -- visa_id {}",
        ingress_link_id.get(), visa_id
    );

    node::request_stream(asm, ingress_link_id, txn_id, visa_id);

    Ok(())
}

pub async fn handle_bind_egress_stream_request(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpBindEgressStreamRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    if !matches!(hdr.tcst, Tcst::Ip5Tuple) {
        warn!(target: ZDP, "{}: unsupported TCST {}", asm.formatted_link_id(pkt.metadata().ingress_link_id), hdr.tcst.0);
        return Err(HandleMgmtError::BadStructure);
    }

    let Ok(tc) = tc::Ip5TupleTc::deserialize(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    if pkt.remaining() < size_of::<u16>() {
        return Err(HandleMgmtError::BadStructure);
    }

    let key_len = pkt.get_u16() as usize;

    // deserialize the peer's A2A DH public key if present
    let peer_a2a_dh_pubkey = if key_len == 0 {
        None
    } else {
        if pkt.remaining() < key_len {
            return Err(HandleMgmtError::BadStructure);
        }

        let Ok(key_bytes) = <[u8; X25519_KEY_LEN]>::try_from(&pkt.body()[..key_len]) else {
            return Err(HandleMgmtError::BadStructure);
        };

        Some(x25519_dalek::PublicKey::from(key_bytes))
    };

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    // must come from a dock
    let peer_type = peer_type_by_id(&asm, ingress_link_id);
    if !matches!(peer_type, PeerType::Dock) {
        error!(target: ZDP, "{}: received BindEgressStream message on {peer_type} link", ingress_link_id);
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    debug!(
        target: ZDP,
        "{}: handlers.handle_bind_egress_stream_request -- five_tuple {}",
        asm.formatted_link_id(ingress_link_id.get()), tc.five_tuple()
    );

    adapter::bind_egress_stream(asm, ingress_link_id, txn_id, tc, peer_a2a_dh_pubkey);

    Ok(())
}

pub async fn handle_bind_actor_address_response(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(HandleMgmtError::LinkClosed);
    };

    let Some(txn) = peer_state.txn_mgr.get(txn_id) else {
        return Err(HandleMgmtError::UnknownTransaction);
    };

    let Ok(hdr) = zdp::ZdpBindActorAddressResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    match hdr.status_code {
        zdp::ResponseCode::Success => {
            let stream_id = pkt.metadata().ingress_stream_id;

            let Ok(tcst) = Tcst::read_from_buf(&mut pkt) else {
                return Err(HandleMgmtError::BadStructure);
            };

            if !matches!(tcst, Tcst::Ip5Tuple) {
                warn!(target: ZDP, "{}: unsupported TCST {}", asm.formatted_link_id(pkt.metadata().ingress_link_id), tcst.0);
                return Err(HandleMgmtError::BadStructure);
            }

            let Ok(tc) = tc::Ip5TupleTc::deserialize(&mut pkt) else {
                return Err(HandleMgmtError::BadStructure);
            };

            if pkt.remaining() < size_of::<u16>() {
                return Err(HandleMgmtError::BadStructure);
            }

            let key_len = pkt.get_u16() as usize;

            // deserialize the peer's A2A DH public key if present
            let peer_a2a_dh_pubkey = if key_len == 0 {
                None
            } else {
                if pkt.remaining() < key_len {
                    return Err(HandleMgmtError::BadStructure);
                }

                let Ok(key_bytes) = <[u8; X25519_KEY_LEN]>::try_from(&pkt.body()[..key_len]) else {
                    return Err(HandleMgmtError::BadStructure);
                };

                Some(x25519_dalek::PublicKey::from(key_bytes))
            };

            adapter::install_tether(&asm, &txn, stream_id, tc, peer_a2a_dh_pubkey)?;
            Ok(())
        }

        zdp::ResponseCode::Other => {
            if hdr.info_len as usize > pkt.remaining() {
                return Err(HandleMgmtError::BadStructure);
            }

            let Ok(msg) = std::str::from_utf8(&pkt.body()[..hdr.info_len as usize]) else {
                return Err(HandleMgmtError::BadStructure);
            };

            adapter::deny_tether(&asm, &txn, msg)?;
            Ok(())
        }

        _ => Err(HandleMgmtError::BadStructure),
    }
}

pub async fn handle_stream_id_response(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(HandleMgmtError::LinkClosed);
    };

    let Some(txn) = peer_state.txn_mgr.get(txn_id) else {
        return Err(HandleMgmtError::UnknownTransaction);
    };

    let Ok(hdr) = zdp::ZdpStreamIdResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    match hdr.status_code {
        zdp::ResponseCode::Success => {
            let stream_id = pkt.metadata().ingress_stream_id;

            node::install_tether(&asm, NonZero::new(link_id).unwrap(), &txn, stream_id)?;
            Ok(())
        }

        zdp::ResponseCode::Other => {
            if hdr.info_len as usize > pkt.remaining() {
                return Err(HandleMgmtError::BadStructure);
            }

            let Ok(msg) = std::str::from_utf8(&pkt.body()[..hdr.info_len as usize]) else {
                return Err(HandleMgmtError::BadStructure);
            };

            node::deny_tether(&asm, NonZero::new(link_id).unwrap(), &txn, msg)?;
            Ok(())
        }

        _ => Err(HandleMgmtError::BadStructure),
    }
}

pub async fn handle_bind_egress_stream_response(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(HandleMgmtError::LinkClosed);
    };

    let Some(txn) = peer_state.txn_mgr.get(txn_id) else {
        return Err(HandleMgmtError::UnknownTransaction);
    };

    let Ok(hdr) = zdp::ZdpBindActorAddressResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    match hdr.status_code {
        zdp::ResponseCode::Success => {
            let stream_id = pkt.metadata().ingress_stream_id;

            node::install_tether(&asm, NonZero::new(link_id).unwrap(), &txn, stream_id)?;
            Ok(())
        }

        zdp::ResponseCode::Other => {
            if hdr.info_len as usize > pkt.remaining() {
                return Err(HandleMgmtError::BadStructure);
            }

            let Ok(msg) = std::str::from_utf8(&pkt.body()[..hdr.info_len as usize]) else {
                return Err(HandleMgmtError::BadStructure);
            };

            node::deny_tether(&asm, NonZero::new(link_id).unwrap(), &txn, msg)?;
            Ok(())
        }

        _ => Err(HandleMgmtError::BadStructure),
    }
}

/// Handle an Unbind Egress Stream Indication (ZdpPacketType 13).
///
/// Only an adapter accepts it, from its node: the node no longer sends on
/// the stream, so the adapter removes it from its DLT. A node refuses it
/// from everyone:
///
/// - from a Zode, by F5 (zl-zipline#251): Zode links carry no teardown
///   messages. A refusal closes the link (gate g88 q2).
/// - from an adapter or the local actor (gate g88 q3): no core component
///   sends it, and F4 lists the only causes of teardown (expiry, a visa
///   service revocation, a lost link).
pub async fn handle_unbind_indication(asm: &Arc<Assembly>, pkt: Packet) -> HandleMgmtResult {
    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    let link_type = match asm.peer_table.get(ingress_link_id.get()) {
        Some(peer_state) => peer_state.link_state_machine.get_link_type(),
        None => {
            return Err(HandleMgmtError::LinkClosed);
        }
    };

    match (link_type, ingress_link_id.get()) {
        (LinkType::NodeToAdapter, _) | (LinkType::Internal, LOCAL_ACTOR_LINK_ID) => {
            // We are the node; an adapter (or the local actor) does not
            // unbind streams with us.
            warn!(
                target: ZDP,
                "{}: refusing UnbindEgressStreamIndication from an adapter or the local actor: F4 lists the only teardown causes",
                asm.formatted_link_id(ingress_link_id.get())
            );
            return Err(HandleMgmtError::MessageNotPermitted);
        }
        (LinkType::AdapterToNode, _) | (LinkType::Internal, DOCK_LINK_ID) => {
            // We are the adapter
            debug!(
                target: ZDP,
                "{}: unbind egress stream, adapter -> node",
                asm.formatted_link_id(ingress_link_id.get())
            );
            // Remove from DLT
            adapter::unbind_stream(asm, ingress_link_id, pkt.metadata().ingress_stream_id);
        }
        (LinkType::NodeToNode, _) => {
            return Err(refuse_zode_teardown(
                asm,
                ingress_link_id,
                zdp::ZdpPacketType::UnbindEgressStreamIndication,
            ));
        }
        (LinkType::Internal, _) => {
            error!(
                target: ZDP,
                "{}: internal",
                asm.formatted_link_id(ingress_link_id.get())
            );
            return Err(HandleMgmtError::MessageNotPermitted);
        }
    }

    Ok(())
}

/// handle a Stream ID Withdrawal message (ZdpPacketType 5)
///
/// Sent by a node whose visa was revoked: "the stream id you send with has
/// been withdrawn; drop your egress binding" (zipline#21). On the adapter
/// side the withdrawn id is the tether id held in the *outbound* ELT, so
/// the ELT entry is removed by tether id; the next outbound packet for that
/// flow then misses the ELT and triggers a fresh visa request.
pub async fn handle_stream_id_withdrawal(asm: &Arc<Assembly>, pkt: Packet) -> HandleMgmtResult {
    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    let link_type = match asm.peer_table.get(ingress_link_id.get()) {
        Some(peer_state) => peer_state.link_state_machine.get_link_type(),
        None => {
            return Err(HandleMgmtError::LinkClosed);
        }
    };

    match (link_type, ingress_link_id.get()) {
        (LinkType::AdapterToNode, _) | (LinkType::Internal, DOCK_LINK_ID) => {
            // We are the adapter: our node withdrew a stream id we send with.
            let stream_id = pkt.metadata().ingress_stream_id;
            debug!(
                target: ZDP,
                "{}: stream id withdrawal, node -> adapter",
                asm.formatted_link_id(ingress_link_id.get())
            );
            // Remove the outbound (ELT) entry bound to that tether id.
            match asm.elt.remove_by_tether_id(stream_id) {
                Some(five_tuple) => {
                    debug!(
                        target: FLOW_MGMT,
                        "{}: withdrew stream {stream_id}, removed ELT entry for {five_tuple}",
                        asm.formatted_link_id(ingress_link_id.get())
                    );
                }
                None => {
                    warn!(
                        target: FLOW_MGMT,
                        "{}: stream id withdrawal for {stream_id} matched no ELT entry",
                        asm.formatted_link_id(ingress_link_id.get())
                    );
                }
            }
        }
        (LinkType::NodeToAdapter, _) | (LinkType::Internal, LOCAL_ACTOR_LINK_ID) => {
            // We are the node; adapters do not withdraw stream ids from us.
            debug!(
                target: ZDP,
                "{}: adapter -> node not permitted",
                asm.formatted_link_id(ingress_link_id.get())
            );
            return Err(HandleMgmtError::MessageNotPermitted);
        }
        (LinkType::NodeToNode, _) => {
            return Err(refuse_zode_teardown(
                asm,
                ingress_link_id,
                zdp::ZdpPacketType::StreamIdWithdrawal,
            ));
        }
        (LinkType::Internal, _) => {
            error!(
                target: ZDP,
                "{}: internal",
                asm.formatted_link_id(ingress_link_id.get())
            );
            return Err(HandleMgmtError::MessageNotPermitted);
        }
    }

    Ok(())
}

/// Refuse a teardown message (`packet_type`, ZDP type 5 or 13) that
/// arrived on Zode link `link_id`, by F5 (zl-zipline#251): Zode links carry
/// no teardown messages; the visa service tears bindings down. Logs the
/// refusal and returns the error the handler fails with, which closes the
/// link and counts it (gate g88 q2).
fn refuse_zode_teardown(
    asm: &Assembly,
    link_id: NonZero<LinkId>,
    packet_type: zdp::ZdpPacketType,
) -> HandleMgmtError {
    warn!(
        target: ZDP,
        "{}: refusing {packet_type:?}: F5: Zode links carry no teardown messages",
        asm.formatted_link_id(link_id.get())
    );
    HandleMgmtError::MessageNotPermitted
}

fn peer_type_by_id(asm: &Assembly, link_id: NonZero<LinkId>) -> PeerType {
    asm.peer_table
        .inspect(link_id.get(), |ps| ps.peer_type())
        .unwrap_or(PeerType::Unknown)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::mgmt::core;
    use zpr_ext::zerocopy::IntoBytesExt;

    /// A HelloResponse carrying an OIDC_IDP TLV must yield a
    /// ReceivedHelloResponse event carrying the decoded IdP list.
    #[tokio::test]
    async fn test_hello_response_parses_oidc_idp_tlv() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));

        let idp = auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string(), "email".to_string()],
            allow_offline_access: true,
        };

        // Build the HelloResponse body: header, then the OIDC_IDP TLV.
        let mut pkt = core::new_heap_packet();
        let hdr = zdp::ZdpHelloResponseHeader {
            status: zdp::ResponseCode::Success,
        };
        hdr.write_to_buf(&mut pkt).unwrap();
        // #1410: every HelloResponse must carry the protocol capability.
        tlv::TlvEncoding::new_actor_auth_protocol().put(&mut pkt);
        tlv::TlvEncoding::new_oidc_idp(&idp).unwrap().put(&mut pkt);

        let event = parse_hello_response(&asm, 7, &mut pkt).unwrap();
        match event {
            LinkEvent::ReceivedHelloResponse {
                status, oidc_idps, ..
            } => {
                assert_eq!(status, zdp::ResponseCode::Success);
                assert_eq!(oidc_idps, Some(vec![idp]));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    /// zl-zipline#250 review round 1: a Zode link refuses a HelloResponse
    /// that carries adapter TLVs even when they do not decode, such as an
    /// OIDC_IDP advertisement with invalid JSON; the link closes.
    #[tokio::test(start_paused = true)]
    async fn test_zode_hello_response_with_undecodable_idp_closes_the_link() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (egress_tx, _egress_rx) = crate::packet_queue::packet_queue(64);
                let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                    mgmt_substrate_egress: Some(crate::queues::MgmtSubstrateEgress::new(egress_tx)),
                    ..TestAssemblyBuilder::new()
                }));
                let link_id = crate::peer_table::test::insert_zode_peer_with_verified_cn(
                    &asm,
                    "b.zpr",
                    crate::link_state::LinkState::Helloing,
                );
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .set_zode_end(crate::link_state::ZodeEnd::Dialer {
                        peer_cn: "b.zpr".to_owned(),
                    })
                    .unwrap();

                let mut pkt = core::new_heap_packet();
                zdp::ZdpHelloResponseHeader {
                    status: zdp::ResponseCode::Success,
                }
                .write_to_buf(&mut pkt)
                .unwrap();
                tlv::TlvEncoding::new_actor_auth_protocol().put(&mut pkt);
                // An OIDC_IDP TLV (type, length, value) whose JSON is invalid.
                let bad_json = b"{not json";
                pkt.put_slice(&[tlv::DataType::OIDC_IDP, bad_json.len() as u8]);
                pkt.put_slice(bad_json);
                pkt.metadata_mut().ingress_link_id = link_id;

                let _ = handle_hello_response(&asm, pkt).await;
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    crate::link_state::LinkState::Closing
                );
            })
            .await
    }

    /// A node assembly whose initial link is to `relay.zpr`, with a Zode
    /// link to `relay.zpr` in `state`. Returns it and the link.
    fn joiner_with_link_in(state: crate::link_state::LinkState) -> (Arc<Assembly>, LinkId) {
        let (egress_tx, _egress_rx) = crate::packet_queue::packet_queue(64);
        let mut config = crate::config::Config::default();
        config.zpr_addr = vec!["fd5a:5052::b".parse().unwrap()];
        config.initial_link =
            Some(crate::config::InitialLink::parse_cli("relay.zpr@10.9.9.9:5000").unwrap());
        let asm = Arc::new(create_assembly(TestAssemblyBuilder {
            ph_mode: Some(crate::assembly::PhMode::Node),
            config: Some(rcu::RcuBox::new(config)),
            mgmt_substrate_egress: Some(crate::queues::MgmtSubstrateEgress::new(egress_tx)),
            ..TestAssemblyBuilder::new()
        }));
        let link_id =
            crate::peer_table::test::insert_zode_peer_with_verified_cn(&asm, "relay.zpr", state);
        (asm, link_id)
    }

    /// zl-zipline#252 (J4, regression test kept from core#104): a bootstrap
    /// visa carried inside a HelloResponse is never installed, even on a
    /// joiner's link to its relay. Only the Bootstrap Visas message after
    /// Hello can carry one.
    #[tokio::test(start_paused = true)]
    async fn test_bootstrap_visa_inside_hello_is_not_installed() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (asm, link_id) = joiner_with_link_in(crate::link_state::LinkState::Helloing);
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .set_zode_end(crate::link_state::ZodeEnd::Dialer {
                        peer_cn: "relay.zpr".to_owned(),
                    })
                    .unwrap();

                let visa = crate::visa_table::tests::new_vsapi_visa_tcp_default(
                    4242,
                    crate::visa_table::tests::never_expires(),
                );
                let mut pkt = core::new_heap_packet();
                zdp::ZdpHelloResponseHeader {
                    status: zdp::ResponseCode::Success,
                }
                .write_to_buf(&mut pkt)
                .unwrap();
                tlv::TlvEncoding::new_actor_auth_protocol().put(&mut pkt);
                tlv::TlvEncoding::new_bootstrap_visa(visa).put(&mut pkt);
                pkt.metadata_mut().ingress_link_id = link_id;

                let _ = handle_hello_response(&asm, pkt).await;
                assert!(
                    !asm.visa_table.read().unwrap().contains(4242),
                    "a visa inside Hello must not be installed"
                );
            })
            .await
    }

    /// zl-zipline#252: a refused Bootstrap Visas message is an error the
    /// management processor counts as `BootstrapHandoffRefused` and turns
    /// into a link error (the strict handler-error convention). Here the
    /// body is cut short.
    #[tokio::test(start_paused = true)]
    async fn test_refused_bootstrap_visas_is_a_counted_handler_error() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (asm, link_id) = joiner_with_link_in(crate::link_state::LinkState::Helloing);
                let mut pkt = core::new_heap_packet();
                pkt.put_slice(&[2, 0]);
                pkt.metadata_mut().ingress_link_id = link_id;
                let err = handle_bootstrap_visas(&asm, pkt).await.unwrap_err();
                assert!(matches!(
                    err,
                    HandleMgmtError::HandoffRefused(
                        crate::bootstrap_handoff::HandoffError::Malformed
                    )
                ));
                assert_eq!(
                    counters::ManagementCounterType::from(&err),
                    counters::ManagementCounterType::BootstrapHandoffRefused
                );
            })
            .await
    }

    /// A ~3 KB blob (JWT plus a self-signed blob in a JSON array) must fit
    /// through a management packet built the way
    /// send_acquire_zpr_address_request builds it, and parse back intact.
    #[test]
    fn test_acquire_zpr_address_request_3kb_blob_roundtrip() {
        let blob = "A".repeat(3 * 1024);

        // Build exactly like requests::send_acquire_zpr_address_request.
        let mut req = core::new_heap_packet();
        let hdr = zdp::ZdpAcquireZprAddressHeader {
            blob_len: (blob.len() as u16).into(),
            ip_version: L3Type::Ipv6,
            addr_count: 0,
        };
        hdr.write_to_buf(&mut req).unwrap();
        req.put_slice(blob.as_bytes());

        let (addrs, parsed_blob) = parse_acquire_zpr_address_request(&mut req).unwrap();
        assert!(addrs.is_none());
        assert_eq!(parsed_blob, blob);
    }

    /// A StreamIdWithdrawal received by the adapter (over its node link)
    /// must remove the ELT entry whose tether id matches the withdrawn
    /// stream id, so the next outbound packet misses the ELT and triggers a
    /// fresh visa request instead of sending on the revoked stream
    /// (zipline#21).
    #[tokio::test]
    async fn test_handle_stream_id_withdrawal_removes_elt_entry_by_tether_id() {
        use crate::adapter_tables::EltPep;
        use crate::defs::FiveTuple;
        use crate::mgmt::txn_mgr::TxnMgr;
        use crate::peer_table::test::create_dummy_peer_state;
        use std::net::{IpAddr, Ipv4Addr};
        use zpr::packet_info::{CompressionMode, SubstrateAddr};
        use zpr_utils::net_defs;

        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));

        // A peer that looks like our node (adapter -> node link).
        let entry = asm.peer_table.vacant_entry().unwrap();
        let key = entry.key();
        let link_id = entry
            .insert(create_dummy_peer_state(
                key,
                LinkType::AdapterToNode,
                SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
            ))
            .get();

        // An Active ELT entry bound to tether id 42.
        let five_tuple = FiveTuple {
            src_port: 4242,
            ..FiveTuple::default()
        };
        let txn_mgr = Arc::new(TxnMgr::new());
        let txn = txn_mgr.try_open().unwrap();
        asm.elt
            .insert_pending(five_tuple, core::new_heap_packet(), &txn)
            .unwrap();
        asm.elt
            .set_active(
                &five_tuple,
                EltPep::new(CompressionMode::default(), 42, None),
            )
            .unwrap();

        // A withdrawal for stream id 42 arriving on that link.
        let mut pkt = core::new_heap_packet();
        pkt.metadata_mut().ingress_link_id = link_id;
        pkt.metadata_mut().ingress_stream_id = 42;

        handle_stream_id_withdrawal(&asm, pkt).await.unwrap();

        assert!(
            asm.elt.get(&five_tuple).is_none(),
            "stale ELT entry must be removed"
        );
    }
}

/// F5 (zl-zipline#251): Zode links carry no teardown messages. A Stream ID
/// Withdrawal (type 5) or an Unbind Egress Stream Indication (type 13)
/// arriving on one is refused, which closes the link; a type 13 from an
/// adapter or the local actor is refused too (gate g88 q3).
#[cfg(test)]
mod teardown_test {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::forwarding_tables::PftPep;
    use crate::link_state::LinkState;
    use crate::mgmt::core;

    type EgressRx = crate::packet_queue::Receiver<{ crate::config::PACKET_BUFFER_SIZE }>;

    /// A Node-mode assembly whose management egress we can read back.
    fn node() -> (Arc<Assembly>, EgressRx) {
        let (egress_tx, egress_rx) = crate::packet_queue::packet_queue(8);
        let asm = Arc::new(create_assembly(TestAssemblyBuilder {
            ph_mode: Some(crate::assembly::PhMode::Node),
            mgmt_substrate_egress: Some(crate::queues::MgmtSubstrateEgress::new(egress_tx)),
            ..TestAssemblyBuilder::new()
        }));
        (asm, egress_rx)
    }

    /// Give link `link` a PFT entry and return its stream ID.
    fn bind_stream(asm: &Assembly, link: LinkId) -> StreamId {
        asm.peer_table
            .get(link)
            .unwrap()
            .pft
            .insert(PftPep::new(ForwardingEntry(link, 1), 3000))
            .unwrap()
    }

    /// A per-flow management packet for `stream` as the handlers see it:
    /// arrived on `link`, with the headers already read.
    fn arriving(link: LinkId, stream: StreamId) -> Packet {
        let mut pkt = core::new_heap_packet();
        pkt.metadata_mut().ingress_link_id = link;
        pkt.metadata_mut().ingress_stream_id = stream;
        pkt
    }

    /// Both teardown types on an Active Zode link are refused, and the
    /// link's forwarding entry is untouched.
    #[tokio::test]
    async fn test_teardown_messages_on_zode_link_are_refused() {
        let (asm, _egress_rx) = node();
        let zode = crate::peer_table::test::insert_zode_peer_with_verified_cn(
            &asm,
            "b.zpr",
            LinkState::Active,
        );
        let stream = bind_stream(&asm, zode);

        assert!(matches!(
            handle_stream_id_withdrawal(&asm, arriving(zode, stream)).await,
            Err(HandleMgmtError::MessageNotPermitted)
        ));
        assert!(matches!(
            handle_unbind_indication(&asm, arriving(zode, stream)).await,
            Err(HandleMgmtError::MessageNotPermitted)
        ));
        assert_eq!(asm.peer_table.get(zode).unwrap().pft.len(), 1);
    }

    /// Gate g88 q2: the refusal goes through the strict handler-error path,
    /// so a teardown message from a Zode closes the link. Each type is sent
    /// as a real management packet through the link's processor.
    #[tokio::test(flavor = "local")]
    async fn test_teardown_message_on_zode_link_closes_it() {
        for packet_type in [
            zdp::ZdpPacketType::StreamIdWithdrawal,
            zdp::ZdpPacketType::UnbindEgressStreamIndication,
        ] {
            let (asm, mut egress_rx) = node();
            let zode = crate::peer_table::test::insert_zode_peer_with_verified_cn(
                &asm,
                "b.zpr",
                LinkState::Active,
            );
            let stream = bind_stream(&asm, zode);

            // Build the packet the way a sender would, and take it off the
            // egress queue as the received packet.
            core::send_per_flow_mgmt(&asm, zode, packet_type, stream, core::new_heap_packet())
                .enqueue();
            let buf = vec![0u8; crate::config::PACKET_BUFFER_SIZE].into_boxed_slice();
            let Ok(mut pkt) = egress_rx.try_recv(buf) else {
                panic!("the packet is on the egress queue");
            };
            pkt.metadata_mut().ingress_link_id = zode;

            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(crate::queues::MgmtProcessorMessage::Packet(pkt))
                .await
                .unwrap();
            drop(tx);
            crate::mgmt_processor_worker::launch(
                crate::mgmt_processor_worker::Config {
                    link_id: NonZero::new(zode).unwrap(),
                },
                asm.clone(),
                rx,
            )
            .await;

            let state = asm
                .peer_table
                .get(zode)
                .map(|p| p.link_state_machine.get_state());
            assert_ne!(state, Some(LinkState::Active), "{packet_type:?}");
            assert_eq!(asm.peer_table.get(zode).map_or(0, |p| p.pft.len()), 1);
        }
    }

    /// Gate g88 q3: a node refuses an Unbind Egress Stream Indication from
    /// an adapter, as it refuses a withdrawal from one. No core component
    /// sends it, and F4 lists the only causes of teardown. The adapter's
    /// forwarding entry is untouched.
    #[tokio::test]
    async fn test_unbind_indication_from_adapter_is_refused() {
        let (asm, _egress_rx) = node();
        let adapter = crate::peer_table::test::insert_peer_with_verified_cn(
            &asm,
            LinkType::NodeToAdapter,
            "adapter",
            LinkState::Active,
        );
        let stream = bind_stream(&asm, adapter);

        assert!(matches!(
            handle_unbind_indication(&asm, arriving(adapter, stream)).await,
            Err(HandleMgmtError::MessageNotPermitted)
        ));
        assert_eq!(asm.peer_table.get(adapter).unwrap().pft.len(), 1);
    }

    /// Gate g88 q3: the same refusal for an Unbind Egress Stream Indication
    /// on the local actor link.
    #[tokio::test(flavor = "local")]
    async fn test_unbind_indication_from_local_actor_is_refused() {
        let (asm, _egress_rx) = node();
        let local_actor = asm.peer_table.insert_internal_peer().get();
        assert_eq!(local_actor, zpr::packet_info::LOCAL_ACTOR_LINK_ID);
        let stream = bind_stream(&asm, local_actor);

        assert!(matches!(
            handle_unbind_indication(&asm, arriving(local_actor, stream)).await,
            Err(HandleMgmtError::MessageNotPermitted)
        ));
        assert_eq!(asm.peer_table.get(local_actor).unwrap().pft.len(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zpr_ext::zerocopy::IntoBytesExt;

    #[test]
    fn authentication_evidence_is_bounded_by_actual_packet_capacity() {
        use super::super::{core, requests};
        use std::net::IpAddr;
        for addresses in [
            Vec::new(),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()],
            vec!["::1".parse::<IpAddr>().unwrap()],
        ] {
            let address_len = addresses
                .first()
                .map_or(0, |address| if address.is_ipv4() { 4 } else { 16 });
            let max_blob = core::new_heap_packet().remaining_mut()
                - size_of::<zdp::ZdpAcquireZprAddressHeader>()
                - address_len;
            let blob = vec![b'A'; max_blob];
            assert!(requests::validate_acquire_zpr_address_request(&addresses, &blob).is_ok());
            assert!(
                requests::validate_acquire_zpr_address_request(
                    &addresses,
                    &vec![b'A'; max_blob + 1]
                )
                .is_err()
            );
            let asm = crate::assembly::test::create_assembly(
                crate::assembly::test::TestAssemblyBuilder::new(),
            );
            requests::send_acquire_zpr_address_request(&asm, 3, 42, &addresses, Some(&blob))
                .enqueue();
        }
        assert!(requests::validate_acquire_zpr_address_request(&[], &[]).is_err());
        assert!(
            requests::validate_acquire_zpr_address_request(
                &["::1".parse().unwrap(); 2],
                b"evidence"
            )
            .is_err()
        );
    }

    fn acquire(count: u8, blob: &[u8], addresses: &[u8]) -> Packet {
        let mut pkt = super::super::core::new_heap_packet();
        zdp::ZdpAcquireZprAddressHeader {
            blob_len: (blob.len() as u16).into(),
            ip_version: L3Type::Ipv6,
            addr_count: count,
        }
        .write_to_buf(&mut pkt)
        .unwrap();
        pkt.put_slice(blob);
        pkt.put_slice(addresses);
        pkt
    }

    fn grant(status: zdp::AuthenticationStatus, count: u8, addresses: &[u8]) -> Packet {
        let mut pkt = super::super::core::new_heap_packet();
        zdp::ZdpGrantZprAddressHeader {
            status_code: status,
            ip_version: L3Type::Ipv6,
            addr_count: count,
        }
        .write_to_buf(&mut pkt)
        .unwrap();
        pkt.put_slice(addresses);
        pkt
    }

    #[test]
    fn acquire_requires_evidence_and_at_most_one_address() {
        assert!(parse_acquire_zpr_address_request(&mut acquire(0, b"evidence", &[])).is_ok());
        let address = [1; 16];
        assert!(parse_acquire_zpr_address_request(&mut acquire(1, b"evidence", &address)).is_ok());
        for mut invalid in [
            acquire(0, b"", &[]),
            acquire(2, b"evidence", &[1; 32]),
            acquire(1, b"evidence", &[1; 15]),
            acquire(0, b"evidence", &[1]),
        ] {
            assert!(parse_acquire_zpr_address_request(&mut invalid).is_err());
        }
    }

    #[test]
    fn grant_requires_exact_status_and_address_shape() {
        use zdp::AuthenticationStatus as Status;
        assert!(
            parse_grant_zpr_address_request(&mut grant(Status::Success, 1, &[1; 16]))
                .unwrap()
                .is_ok()
        );
        for status in [Status::Rejected, Status::Retryable, Status::PolicyDenied] {
            assert_eq!(
                parse_grant_zpr_address_request(&mut grant(status, 0, &[]))
                    .unwrap()
                    .unwrap_err(),
                status
            );
            assert!(parse_grant_zpr_address_request(&mut grant(status, 1, &[1; 16])).is_err());
        }
        for mut invalid in [
            grant(Status::Success, 0, &[]),
            grant(Status::Success, 2, &[1; 32]),
            grant(Status::Success, 1, &[1; 15]),
            grant(Status::Success, 1, &[1; 17]),
            grant(Status(255), 0, &[]),
        ] {
            assert!(parse_grant_zpr_address_request(&mut invalid).is_err());
        }
    }

    #[test]
    fn hello_capability_requires_one_supported_version() {
        let mut data = std::collections::HashMap::new();
        assert!(!has_actor_auth_protocol(&data));
        data.insert(
            tlv::DataType::ACTOR_AUTH_PROTOCOL,
            vec![tlv::TlvValue::U16(1)],
        );
        assert!(has_actor_auth_protocol(&data));
        data.insert(
            tlv::DataType::ACTOR_AUTH_PROTOCOL,
            vec![tlv::TlvValue::U16(2)],
        );
        assert!(!has_actor_auth_protocol(&data));
        data.insert(
            tlv::DataType::ACTOR_AUTH_PROTOCOL,
            vec![tlv::TlvValue::U16(1); 2],
        );
        assert!(!has_actor_auth_protocol(&data));
    }
}
