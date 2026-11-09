use crate::auth::AuthBlob;
use crate::link_state::LinkStateError;
use crate::prelude::*;
use crate::visa_table;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use libnode::claims;
use libnode::error::VSApiError;
use std::net::IpAddr;
use std::num::NonZero;
use zpr::vsapi_types::{self, DisconnectNotice, DisconnectReason};
use zpr_utils::net_defs::IpAddress;

/// Register the visa service adapter with the visa service, now that the node can reach it.
pub async fn send_deferred_vs_connect(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    assigned_addr: IpAddress,
    connect_req: vsapi_types::ConnectRequest,
) -> Result<(), VSApiError> {
    let conn = asm
        .vsconn
        .as_ref()
        .unwrap()
        .authorize_connect(connect_req)
        .await?;

    if IpAddress::new_from_std(&conn.zpr_addr) != assigned_addr {
        return Err(VSApiError::CommandFailed(format!(
            "visa service granted {} to the visa service adapter, which is already assigned {assigned_addr}",
            conn.zpr_addr
        )));
    }

    record_auth_expires(asm, link_id, conn.auth_expires);

    info!(target: VISA_MGMT, "{}: visa service adapter registered with the visa service as {}",
        asm.formatted_link_id(link_id), conn.zpr_addr);
    Ok(())
}

/// Store the authentication expiry the VS reported in a `Connection`
/// response on the link's actor, converting the wire's epoch seconds and
/// computing the renewal deadline from the configured lead (zipline#45).
pub fn record_auth_expires(asm: &Arc<Assembly>, link_id: LinkId, auth_expires_epoch_secs: u64) {
    let Some(peer) = asm.peer_table.get(link_id) else {
        return;
    };
    let expires = std::time::UNIX_EPOCH + std::time::Duration::from_secs(auth_expires_epoch_secs);
    peer.actor_auth.renewal.set_auth_expires(
        std::time::SystemTime::now(),
        expires,
        asm.config.get().auth_renewal_lead,
    );
}

/// Ask the visa service to authorize an actor connection. The caller
/// (ActorAuthorization on the node) owns the result: it grants or refuses
/// the address and records the authentication expiry (#1410).
pub async fn authorize_connect(
    asm: &Arc<Assembly>,
    connect_req: vsapi_types::ConnectRequest,
) -> Result<vsapi_types::Connection, VSApiError> {
    asm.vsconn
        .as_ref()
        .ok_or(VSApiError::ConnClosed)?
        .authorize_connect(connect_req)
        .await
}

/// Map a failed visa service authorization to the status reported to the
/// adapter in the Grant.
///
/// Explicit credential denials are [AuthenticationStatus::Rejected] and a
/// policy that admits no endpoint is [AuthenticationStatus::PolicyDenied]
/// (zipline#12); both are terminal on the adapter. Everything else -- a
/// closed connection, a timeout, an internal or temporarily-unavailable
/// visa service -- is [AuthenticationStatus::Retryable] (#1410).
///
/// [AuthenticationStatus::Rejected]: crate::zdp::AuthenticationStatus::Rejected
/// [AuthenticationStatus::PolicyDenied]: crate::zdp::AuthenticationStatus::PolicyDenied
/// [AuthenticationStatus::Retryable]: crate::zdp::AuthenticationStatus::Retryable
pub fn authorization_error_status(err: &VSApiError) -> crate::zdp::AuthenticationStatus {
    use crate::zdp::AuthenticationStatus;
    use vsapi_types::ErrorCode;
    match err {
        VSApiError::AuthFailed(_) => AuthenticationStatus::Rejected,
        VSApiError::CodedError(e) if e.code == ErrorCode::PolicyDenied => {
            AuthenticationStatus::PolicyDenied
        }
        VSApiError::CodedError(e)
            if matches!(
                e.code,
                ErrorCode::AuthRequired
                    | ErrorCode::InvalidSignature
                    | ErrorCode::AuthError
                    | ErrorCode::ParamError
                    | ErrorCode::InvalidOperation
                    | ErrorCode::NotFound
            ) =>
        {
            AuthenticationStatus::Rejected
        }
        _ => AuthenticationStatus::Retryable,
    }
}

/// Creates a ConnectRequest, unless none is necessary because the link is
/// to the visa service itself.
///
/// `addr` is either UNSPECIFIED or an address requested by the client adapter.
/// If it is a specified address we pass it as the "zpr.addr" claim.
///
/// All `blobs` are forwarded to the visa service, in order.
pub fn build_connect_request(
    asm: &Arc<Assembly>,
    addr: IpAddress,
    blobs: &[AuthBlob],
    a2a_dh_public_key: Option<x25519_dalek::PublicKey>,
) -> Result<vsapi_types::ConnectRequest, LinkStateError> {
    build_connect_request_from_parts(addr, blobs, a2a_dh_public_key, asm.get_local_dock_addr())
}

/// Assembly-free core of [build_connect_request], for testability.
fn build_connect_request_from_parts(
    addr: IpAddress,
    blobs: &[AuthBlob],
    a2a_dh_public_key: Option<x25519_dalek::PublicKey>,
    substrate_addr: IpAddr,
) -> Result<vsapi_types::ConnectRequest, LinkStateError> {
    let vsapi_blobs = vsapi_blobs(blobs)?;

    let mut request_claims = Vec::new();
    if addr != IpAddress::UNSPECIFIED {
        request_claims.push(vsapi_types::Claim {
            key: claims::key::ZPR_ADDR.into(),
            value: addr.to_string(),
        });
    }
    // The CN claim always comes from the AuthBlob certificate, never from the
    // SA cert: the SA cert only validates the node-adapter link, while the
    // AuthBlob cert authenticates an actor to the VS (and multiple actors may
    // sit behind one adapter, so the two CNs must be independent). Only a
    // SelfSigned blob carries a CN; OIDC identity comes from the ID token, so
    // it contributes no CN claim.
    if let Some(ss) = blobs.iter().find_map(|blob| match blob {
        AuthBlob::SelfSigned(ss) => Some(ss),
        _ => None,
    }) {
        request_claims.push(vsapi_types::Claim {
            key: claims::key::CN.into(),
            value: ss.cn.clone(),
        });
    }

    //stuff key into a vsapi_types::PublicKey so it can be sent in the connect request
    let a2a_dh_public_key = a2a_dh_public_key
        .map(|key| vsapi_types::PublicKey::new(key.as_bytes()))
        .unwrap_or_else(|| vsapi_types::PublicKey::new(&[]));

    let connect_req = vsapi_types::ConnectRequest {
        blobs: vsapi_blobs,
        claims: request_claims,
        substrate_addr,
        dock_interface: 0,
        a2a_dh_public_key,
    };
    Ok(connect_req)
}

/// Convert the adapter's [AuthBlob]s to VS-API blobs, in order. Used for
/// both `authorize_connect` and the renewal `reauthorize` (zipline#122).
///
/// Malformed base64 is an error rather than an empty field (#1410). The OIDC
/// nonce the ID token must carry is derived from the blob's challenge; the
/// caller has already verified that challenge, so the nonce is derived from
/// authenticated bytes.
pub fn vsapi_blobs(blobs: &[AuthBlob]) -> Result<Vec<vsapi_types::AuthBlob>, LinkStateError> {
    let invalid = |what: &str, err: base64::DecodeError| {
        LinkStateError::InvalidOperation(format!("invalid actor {what}: {err}"))
    };
    blobs
        .iter()
        .map(|blob| match blob {
            AuthBlob::SelfSigned(ss) => Ok(vsapi_types::AuthBlob::SS(vsapi_types::SelfSignedBlob {
                alg: vsapi_types::ChallengeAlg::RsaSha256Pkcs1v15,
                challenge: BASE64_STANDARD
                    .decode(&ss.challenge)
                    .map_err(|e| invalid("challenge", e))?,
                cn: ss.cn.clone(),
                timestamp: ss.ts,
                signature: BASE64_STANDARD
                    .decode(&ss.sig)
                    .map_err(|e| invalid("signature", e))?,
            })),
            AuthBlob::Oidc(oidc) => {
                let challenge: [u8; 48] = BASE64_STANDARD
                    .decode(&oidc.challenge)
                    .map_err(|e| invalid("challenge", e))?
                    .try_into()
                    .map_err(|_| {
                        LinkStateError::InvalidOperation("invalid actor challenge length".into())
                    })?;
                Ok(vsapi_types::AuthBlob::Oidc(vsapi_types::OidcBlob {
                    issuer: oidc.issuer.clone(),
                    id_token: oidc.id_token.clone(),
                    nonce: crate::auth::oidc_nonce_for_challenge(&challenge),
                }))
            }
        })
        .collect()
}

/// This uses "RemoteDisconnect" as the reason passed to the visa service.
pub async fn actor_disconnect(asm: Arc<Assembly>, addr: IpAddress) {
    let notice = DisconnectNotice {
        zpr_addr: Some(addr.into()),
        reason: DisconnectReason::RemoteDisconnect,
    };
    match asm.vsconn.as_ref().unwrap().notify_disconnect(notice).await {
        Err(e) => {
            warn!(target: VISA_MGMT, "Failed to disconnect actor {addr} with error {e:?}")
        }
        Ok(()) => debug!(target: VISA_MGMT, "Successfully disconnected actor {addr}"),
    }
}

/// Insert visa into table.
///
/// A visa whose next hop has no egress link yet is still stored, with a
/// warning. The VS legitimately sends such visas -- e.g. a bootstrap visa for
/// a policy-declared peer node that has not linked up yet -- and the egress
/// link is resolved again at forwarding time (see [get_egress_link_for_visa]),
/// so the visa becomes usable once the link comes up.
pub fn insert_visa(
    asm: &Assembly,
    visa: vsapi_types::Visa,
) -> Result<VisaId, visa_table::VisaTableError> {
    if visa.visa_type != vsapi_types::VisaType::Full {
        panic!("Forward only visas not yet supported")
    }
    let dest_addr = visa.dock_pep.as_ref().unwrap().dest_addr;
    let next_hop = visa
        .fwd_pep
        .as_ref()
        .map(|p| p.next_hop)
        .unwrap_or(dest_addr);
    if asm.find_egress_link(next_hop.into()).is_none() {
        warn!(target: VISA_MGMT,
            "visa {}: no egress link to next hop {next_hop} yet; storing it anyway", visa.issuer_id);
    }
    let visa_id = asm.visa_table.write().unwrap().insert_visa(visa)?;
    Ok(visa_id)
}

/// Given a visa ID, look up the visa in our table to find the destination address
/// then use that to find an egress link.
pub fn get_egress_link_for_visa(
    asm: &Assembly,
    visa_id: VisaId,
) -> Result<NonZero<LinkId>, visa_table::VisaTableError> {
    let addr = asm
        .visa_table
        .read()
        .unwrap()
        .get_visa_next_hop_addr(visa_id)?;
    let Some(link_id) = asm.find_egress_link(addr) else {
        return Err(visa_table::VisaTableError::DestNotFound(addr));
    };
    Ok(link_id)
}

pub fn handle_revocation(
    asm: &Assembly,
    visa_id: VisaId,
) -> Result<(), visa_table::VisaTableError> {
    // Revoke under the write lock, but hold the withdrawn forwarding
    // entries until the lock is released, then withdraw each stream from
    // the peers still bound to it — same rule and same helper as
    // `Assembly::drop_peer` (zipline#21, zipline#85): the send path must
    // never nest under the visa-table lock.
    let withdrawn = asm
        .visa_table
        .write()
        .unwrap()
        .revoke(&asm.peer_table, visa_id)?;

    asm.withdraw_streams(withdrawn, None);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{self, BLOB_TYPE_OIDC, BLOB_TYPE_SS, ZdpOidcBlob, ZdpSelfSignedBlob};
    use crate::zdp::AuthenticationStatus;
    use zpr::vsapi_types::{ApiResponseError, ErrorCode};

    /// A pushed visa whose next hop has no egress link yet (e.g. a bootstrap
    /// visa for a policy-declared peer node that has not linked up) must
    /// still be stored. Rejecting it makes the VS retry the push forever and
    /// blocks every visa queued behind it; the egress link is looked up again
    /// at forwarding time by `get_egress_link_for_visa`.
    #[test]
    fn test_insert_visa_without_egress_link_is_stored() {
        use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
        use crate::visa_table::VisaTable;
        use crate::visa_table::tests::{never_expires, new_vsapi_visa_tcp_default};

        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = create_assembly(builder);

        let visa_id = 4242;
        // No peers exist, so the visa's destination has no egress link.
        let visa = new_vsapi_visa_tcp_default(visa_id, never_expires());
        assert!(
            asm.find_egress_link(visa.dock_pep.as_ref().unwrap().dest_addr.into())
                .is_none()
        );

        let inserted = insert_visa(&asm, visa).expect("visa without egress link must be accepted");
        assert_eq!(inserted, visa_id as VisaId);
        assert!(
            asm.visa_table
                .read()
                .unwrap()
                .get_visa_next_hop_addr(inserted)
                .is_ok(),
            "visa must be stored in the visa table"
        );
        // Forwarding still refuses it until a link to the next hop exists.
        assert!(matches!(
            get_egress_link_for_visa(&asm, inserted),
            Err(visa_table::VisaTableError::DestNotFound(_))
        ));
    }

    /// Explicit denials are terminal and kept distinct from service failures
    /// (#1410); a policy that admits no endpoint is reported as PolicyDenied
    /// so ph-cli can say so (zipline#12).
    #[test]
    fn test_authorization_error_status_mapping() {
        let coded = |code| VSApiError::CodedError(ApiResponseError::new_code_msg(code, "x"));
        for code in [
            ErrorCode::AuthRequired,
            ErrorCode::InvalidSignature,
            ErrorCode::AuthError,
            ErrorCode::ParamError,
            ErrorCode::InvalidOperation,
            ErrorCode::NotFound,
        ] {
            assert_eq!(
                authorization_error_status(&coded(code.clone())),
                AuthenticationStatus::Rejected,
                "{code:?}"
            );
        }
        assert_eq!(
            authorization_error_status(&VSApiError::AuthFailed("denied".into())),
            AuthenticationStatus::Rejected
        );
        assert_eq!(
            authorization_error_status(&coded(ErrorCode::PolicyDenied)),
            AuthenticationStatus::PolicyDenied
        );
        for err in [
            coded(ErrorCode::TemporarilyUnavailable),
            coded(ErrorCode::Internal),
            coded(ErrorCode::QuotaExceeded),
            VSApiError::ConnClosed,
            VSApiError::Timeout("service".into()),
            VSApiError::CommandFailed("nope".into()),
        ] {
            assert_eq!(
                authorization_error_status(&err),
                AuthenticationStatus::Retryable,
                "{err:?}"
            );
        }
    }

    #[test]
    fn test_build_connect_request_two_blobs_maps_oidc_with_nonce() {
        let challenge = [5u8; 48];
        let ss = ZdpSelfSignedBlob {
            blob_type: BLOB_TYPE_SS.to_string(),
            ts: 4242,
            cn: "adapter.cn.zpr".to_string(),
            challenge: BASE64_STANDARD.encode(challenge),
            sig: BASE64_STANDARD.encode([6u8; 16]),
        };
        let oidc = ZdpOidcBlob {
            blob_type: BLOB_TYPE_OIDC.to_string(),
            issuer: "https://accounts.google.com".to_string(),
            id_token: "eyJ.header.payload".to_string(),
            challenge: BASE64_STANDARD.encode(challenge),
        };
        let blobs = vec![AuthBlob::SelfSigned(ss), AuthBlob::Oidc(oidc)];

        let req = build_connect_request_from_parts(
            IpAddress::UNSPECIFIED,
            &blobs,
            None,
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        )
        .unwrap();

        assert_eq!(req.blobs.len(), 2);
        match &req.blobs[1] {
            vsapi_types::AuthBlob::Oidc(o) => {
                assert_eq!(o.issuer, "https://accounts.google.com");
                assert_eq!(o.id_token, "eyJ.header.payload");
                assert_eq!(o.nonce, auth::oidc_nonce_for_challenge(&challenge));
            }
            other => panic!("expected vsapi Oidc blob second, got {other:?}"),
        }
        match &req.blobs[0] {
            vsapi_types::AuthBlob::SS(s) => assert_eq!(s.cn, "adapter.cn.zpr"),
            other => panic!("expected vsapi SS blob first, got {other:?}"),
        }

        // The CN claim comes from the SS blob only: exactly one CN claim.
        let cn_claims: Vec<_> = req
            .claims
            .iter()
            .filter(|c| c.key == claims::key::CN)
            .collect();
        assert_eq!(cn_claims.len(), 1);
        assert_eq!(cn_claims[0].value, "adapter.cn.zpr");
    }

    /// Malformed evidence must be refused, not forwarded with empty or
    /// zeroed fields (#1410): bad base64 in an SS challenge or signature, or
    /// an OIDC challenge that is not exactly 48 bytes.
    #[test]
    fn test_vsapi_blobs_rejects_malformed_evidence() {
        let ss = |challenge: &str, sig: &str| {
            AuthBlob::SelfSigned(ZdpSelfSignedBlob {
                blob_type: BLOB_TYPE_SS.to_string(),
                ts: 1,
                cn: "adapter.cn.zpr".to_string(),
                challenge: challenge.to_string(),
                sig: sig.to_string(),
            })
        };
        let oidc = |challenge: String| {
            AuthBlob::Oidc(ZdpOidcBlob {
                blob_type: BLOB_TYPE_OIDC.to_string(),
                issuer: "https://idp.test".to_string(),
                id_token: "t".to_string(),
                challenge,
            })
        };
        let good = BASE64_STANDARD.encode([5u8; 48]);
        assert!(vsapi_blobs(&[ss(&good, &good), oidc(good.clone())]).is_ok());
        for bad in [
            ss("not base64!", &good),
            ss(&good, "not base64!"),
            oidc("not base64!".to_string()),
            oidc(BASE64_STANDARD.encode([5u8; 47])),
        ] {
            assert!(vsapi_blobs(&[bad]).is_err());
        }
    }
}
