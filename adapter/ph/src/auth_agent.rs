//! Zipline: out-of-band actor authentication through the AuthAgent (ph-cli),
//! and the adapter's production of actor authentication evidence.
//!
//! Upstream #1410 runs actor authorization in [crate::actor_auth] after the
//! link is Active, and authenticates with a bootstrap key or the legacy
//! BAS/OAuthRsa HTTPS service. Zipline removed BAS (zipline#15) and
//! authenticates users with OIDC through an AuthAgent that ph-cli registers
//! on the link with startLink (zipline#13/#14). This module holds that
//! zipline-only machinery so [crate::actor_auth] only needs small hooks:
//!
//! - [AuthFailureReason]: why an attempt failed, as reported to ph-cli.
//! - [OidcCredentialRequest] / [AuthAgentHandle]: the bridge to the agent.
//! - [produce_evidence]: the adapter's answer to an InitAuthentication
//!   challenge (OIDC via the agent, plus a self-signed device leg when a
//!   bootstrap key is configured; or a device-only bootstrap blob).

use crate::auth::{self, AuthBlob, ZdpInitAuthenticationPayload};
use crate::prelude::*;

use base64::prelude::*;
use std::net::IpAddr;

/// Why an actor authentication attempt failed, as reported to ph-cli.
///
/// ph-cli parses the Debug spelling of this type from showLink's
/// `Last auth failure:` line (adapter/cli/src/oidc.rs) and maps it onto
/// `connect` exit codes, so renaming a variant is a CLI-visible change.
#[allow(dead_code)] // some variants are only constructed in some deployments
#[derive(Clone, Debug, PartialEq, strum::IntoStaticStr)]
pub enum AuthFailureReason {
    /// OIDC required but startLink registered no AuthAgent.
    NoAgent,
    /// The agent returned access_denied: the user refused the login.
    UserDeclined,
    /// The user did not complete the login within OIDC_USER_INTERACTION_TIMEOUT.
    InteractionTimeout,
    /// Discovery/token endpoint failure (not an authentication problem).
    IdpUnreachable(String),
    AgentError(String),
    /// The visa service refused the credentials (Grant status Rejected).
    VisaServiceRejected(String),
    /// Login worked, but no join policy admits this endpoint (Grant status
    /// PolicyDenied).
    PolicyDenied,
    /// The authentication backend is temporarily unavailable, or no
    /// authentication method is available to this adapter.
    AuthUnavailable,
    DeviceBlobRejected,
    /// The adapter could not produce acceptable evidence: the bootstrap key
    /// could not sign the challenge, or the evidence cannot be sent (too
    /// large, or more than one configured address). Local and persistent.
    LocalAuthError(String),
    /// The link failed before (or without) an authentication verdict — e.g.
    /// a handshake timeout in Helloing — and, with auto-connect off, no
    /// restart is coming (zipline#28). Recorded on the close path so ph-cli
    /// `connect` sees the permanently Inactive link as this attempt's
    /// terminal outcome instead of polling it as Pending forever. Carries
    /// the TerminateReason's Debug spelling.
    LinkFailed(String),
    /// The fabric granted a ZPR address differing from the configured
    /// `--zpr-addr` / `zpr_addr` (zipline#83): the configured address is a
    /// demand, not a request, so the adapter refuses to run on the granted
    /// one and exits non-zero. Carries both address sets so `ph-cli link
    /// show` names them.
    GrantedAddressMismatch {
        requested: Vec<IpAddr>,
        granted: Vec<IpAddr>,
    },
    /// A local activation step failed after authentication succeeded —
    /// setting the granted ZPR address on the TUN, installing the
    /// internal-network route on a dynamic grant, or a route-owner
    /// conflict (zipline#157). Local and non-transient (e.g. EPERM will
    /// not clear on reconnect), so it is fatal for this connect request.
    /// Carries the failure text, which names the failed step.
    ActivationFailed(String),
}

impl AuthFailureReason {
    /// Whether this failure ends actor authorization until the operator
    /// retries (`ph-cli connect`, i.e. startLink) or the adapter restarts.
    ///
    /// Upstream #1410 retries transient failures with backoff and latches
    /// explicit rejections. Zipline keeps that split when the adapter
    /// reconnects on its own, but with auto-connect off (zipline#28) every
    /// connect is operator-initiated, so every failure is terminal: an
    /// automatic retry would re-prompt the user in a browser nobody asked
    /// for.
    pub fn is_terminal(&self, auto_connect: bool) -> bool {
        if !auto_connect {
            return true;
        }
        match self {
            Self::InteractionTimeout
            | Self::IdpUnreachable(_)
            | Self::AgentError(_)
            | Self::AuthUnavailable
            | Self::LinkFailed(_) => false,
            Self::NoAgent
            | Self::UserDeclined
            | Self::VisaServiceRejected(_)
            | Self::PolicyDenied
            | Self::DeviceBlobRejected
            | Self::LocalAuthError(_)
            | Self::GrantedAddressMismatch { .. }
            | Self::ActivationFailed(_) => true,
        }
    }

    /// The reason recorded when the node refuses a Grant with `status`.
    pub fn from_grant_status(status: crate::zdp::AuthenticationStatus) -> Self {
        use crate::zdp::AuthenticationStatus;
        match status {
            AuthenticationStatus::PolicyDenied => Self::PolicyDenied,
            AuthenticationStatus::Retryable => Self::AuthUnavailable,
            AuthenticationStatus::Rejected => {
                Self::VisaServiceRejected("visa service rejected authentication".to_string())
            }
            other => Self::VisaServiceRejected(format!("grant failed with status {other:?}")),
        }
    }
}

/// A single credential request forwarded to the out-of-band AuthAgent
/// (ph-cli). The admin worker bridges these onto the Cap'n Proto client it
/// received in startLink.
pub struct OidcCredentialRequest {
    /// The advertised identity provider to authenticate against.
    pub idp: auth::OidcIdpInfo,
    /// OIDC nonce derived from the link challenge
    /// ([auth::oidc_nonce_for_challenge]).
    pub nonce: String,
    /// `false` means "satisfy from a stored refresh token or fail"; the agent
    /// must never open a browser on a non-interactive request.
    pub interactive: bool,
    /// `Ok(id_token)` on success, otherwise the failure reason.
    pub reply: tokio::sync::oneshot::Sender<Result<String, AuthFailureReason>>,
}

/// Handle to the AuthAgent registered for a link via startLink.
pub type AuthAgentHandle = tokio::sync::mpsc::UnboundedSender<OidcCredentialRequest>;

/// Node side: the OIDC identity providers to advertise in HelloResponse
/// (zipline#12) — one [auth::OidcIdpInfo] per auth service the visa service
/// lists with `stype == OidcAuthentication` that carries a client config.
pub fn advertised_oidc_idps(asm: &Assembly, link_id: LinkId) -> Vec<auth::OidcIdpInfo> {
    use zpr::vsapi_types::ServiceT;

    let svclist = asm.vs_auth_services.read().unwrap();
    if !svclist.is_valid() {
        return Vec::new();
    }
    svclist
        .services
        .iter()
        .filter(|service| service.stype == ServiceT::OidcAuthentication)
        .filter_map(|service| {
            let Some(cfg) = &service.oidc else {
                warn!(target: LINK_STATE, "{}: HelloResponse - OIDC service {} has no client config",
                    asm.formatted_link_id(link_id), service.service_id);
                return None;
            };
            debug!(target: LINK_STATE, "{}: HelloResponse - adding OIDC IdP: {}",
                asm.formatted_link_id(link_id), cfg.issuer);
            Some(auth::OidcIdpInfo {
                issuer: cfg.issuer.clone(),
                client_id: cfg.client_id.clone(),
                client_secret: cfg.client_secret.clone(),
                scopes: cfg.scopes.clone(),
                allow_offline_access: cfg.allow_offline_access,
            })
        })
        .collect()
}

/// Ask `agent` for an OIDC ID token bound to `challenge` and wrap it in an
/// OIDC blob. Waits at most `timeout`; an elapsed wait is
/// [AuthFailureReason::InteractionTimeout]. Dropping the returned future
/// drops the reply receiver, which the agent bridge observes and uses to
/// cancel the in-flight RPC.
pub async fn request_oidc_blob(
    agent: &AuthAgentHandle,
    idp: auth::OidcIdpInfo,
    challenge: &[u8; 48],
    interactive: bool,
    timeout: std::time::Duration,
) -> Result<auth::ZdpOidcBlob, AuthFailureReason> {
    let issuer = idp.issuer.clone();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = OidcCredentialRequest {
        idp,
        nonce: auth::oidc_nonce_for_challenge(challenge),
        interactive,
        reply: reply_tx,
    };
    if agent.send(request).is_err() {
        // The agent went away (ph-cli disconnected).
        return Err(AuthFailureReason::NoAgent);
    }
    let id_token = match tokio::time::timeout(timeout, reply_rx).await {
        Ok(Ok(result)) => result?,
        // The bridge dropped the reply without answering.
        Ok(Err(_)) => {
            return Err(AuthFailureReason::AgentError(
                "AuthAgent dropped the request".to_string(),
            ));
        }
        Err(_elapsed) => return Err(AuthFailureReason::InteractionTimeout),
    };
    Ok(auth::ZdpOidcBlob {
        blob_type: auth::BLOB_TYPE_OIDC.to_string(),
        issuer,
        id_token,
        challenge: BASE64_STANDARD.encode(challenge),
    })
}

/// Produce the adapter's actor authentication evidence for an
/// InitAuthentication offer (zipline#13).
///
/// - An advertised OIDC IdP means the network wants user authentication:
///   run it through the AuthAgent (interactive, bounded by
///   [config::OIDC_USER_INTERACTION_TIMEOUT]), adding a self-signed device
///   leg first when a bootstrap key is configured. With no agent registered
///   the adapter falls back to device-only bootstrap if it can, and
///   otherwise fails with [AuthFailureReason::NoAgent].
/// - Otherwise, when the node supports bootstrap and a key is configured,
///   the evidence is a single self-signed blob.
/// - Otherwise there is no way to authenticate: [AuthFailureReason::AuthUnavailable].
///   (The legacy BAS/OAuthRsa fallback was removed in zipline#15.)
///
/// Returns at least one blob on success; the caller encodes them with
/// [auth::encode_blobs] and records [auth::blob_namespaces].
pub async fn produce_evidence(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    bootstrap_supported: bool,
    challenge: Option<&ZdpInitAuthenticationPayload>,
    oidc_idps: &[auth::OidcIdpInfo],
    agent: Option<AuthAgentHandle>,
) -> Result<Vec<AuthBlob>, AuthFailureReason> {
    let cfg = asm.config.get();
    debug!(target: LINK_STATE, "{} producing actor evidence (bootstrap_supported: {bootstrap_supported}, bootstrap_configured: {}, oidc_idps: {}, agent: {})",
        asm.formatted_link_id(link_id), cfg.bootstrap.is_some(), oidc_idps.len(), agent.is_some());

    if let Some(idp) = oidc_idps.first() {
        let challenge = challenge.ok_or_else(|| {
            AuthFailureReason::AgentError("node offered no challenge to bind a login to".into())
        })?;
        if let Some(agent) = agent {
            // Bootstrap key configured -> the SS (device) leg rides along.
            let mut blobs = Vec::new();
            if let Some(bs) = cfg.bootstrap.as_ref() {
                let ss_blob = bs
                    .authenticate_blob(challenge)
                    .map_err(|e| AuthFailureReason::LocalAuthError(e.to_string()))?;
                blobs.push(AuthBlob::SelfSigned(ss_blob));
            }
            let oidc_blob = request_oidc_blob(
                &agent,
                idp.clone(),
                &challenge.challenge_bytes(),
                true,
                config::OIDC_USER_INTERACTION_TIMEOUT,
            )
            .await?;
            blobs.push(AuthBlob::Oidc(oidc_blob));
            return Ok(blobs);
        }
        if cfg.bootstrap.is_none() {
            warn!(target: LINK_STATE, "{} OIDC IdP advertised but no AuthAgent registered and no bootstrap key", asm.formatted_link_id(link_id));
            return Err(AuthFailureReason::NoAgent);
        }
        // No agent but a bootstrap key exists: fall through to the
        // device-only bootstrap path, exactly as before OIDC.
    }

    match (bootstrap_supported, cfg.bootstrap.as_ref(), challenge) {
        (true, Some(bs), Some(challenge)) => {
            let ss_blob = bs
                .authenticate_blob(challenge)
                .map_err(|e| AuthFailureReason::LocalAuthError(e.to_string()))?;
            Ok(vec![AuthBlob::SelfSigned(ss_blob)])
        }
        _ => {
            warn!(target: LINK_STATE, "{} no actor authentication method is available (no OIDC IdP advertised, no usable bootstrap key)", asm.formatted_link_id(link_id));
            Err(AuthFailureReason::AuthUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zdp::AuthenticationStatus;

    /// With auto-connect off every failure is terminal; with it on, only
    /// explicit denials and local, non-transient failures are (#1410 split).
    #[test]
    fn test_failure_classification() {
        let transient = [
            AuthFailureReason::InteractionTimeout,
            AuthFailureReason::IdpUnreachable("x".into()),
            AuthFailureReason::AgentError("x".into()),
            AuthFailureReason::AuthUnavailable,
            AuthFailureReason::LinkFailed("x".into()),
        ];
        let terminal = [
            AuthFailureReason::NoAgent,
            AuthFailureReason::UserDeclined,
            AuthFailureReason::VisaServiceRejected("x".into()),
            AuthFailureReason::PolicyDenied,
            AuthFailureReason::DeviceBlobRejected,
            AuthFailureReason::LocalAuthError("x".into()),
            AuthFailureReason::ActivationFailed("x".into()),
        ];
        for reason in transient.iter().chain(terminal.iter()) {
            assert!(
                reason.is_terminal(false),
                "{reason:?} with auto-connect off"
            );
        }
        for reason in &transient {
            assert!(!reason.is_terminal(true), "{reason:?}");
        }
        for reason in &terminal {
            assert!(reason.is_terminal(true), "{reason:?}");
        }
    }

    /// Each refused Grant status maps to the reason ph-cli reports.
    #[test]
    fn test_reason_from_grant_status() {
        assert_eq!(
            AuthFailureReason::from_grant_status(AuthenticationStatus::PolicyDenied),
            AuthFailureReason::PolicyDenied
        );
        assert_eq!(
            AuthFailureReason::from_grant_status(AuthenticationStatus::Retryable),
            AuthFailureReason::AuthUnavailable
        );
        assert!(matches!(
            AuthFailureReason::from_grant_status(AuthenticationStatus::Rejected),
            AuthFailureReason::VisaServiceRejected(_)
        ));
    }

    /// The challenge bytes are nonce || ctime || hmac, in that order.
    #[test]
    fn test_challenge_bytes_layout() {
        let payload = ZdpInitAuthenticationPayload {
            nonce: [1; 8],
            ctime: 0x0203_0405_0607_0809u64.into(),
            hmac: [7; 32],
        };
        let bytes = payload.challenge_bytes();
        assert_eq!(&bytes[0..8], &[1; 8]);
        assert_eq!(&bytes[8..16], &payload.ctime.to_bytes());
        assert_eq!(&bytes[16..48], &[7; 32]);
    }

    /// A reply the agent never sends within the bound is an interaction
    /// timeout; a dropped reply is an agent error; a closed agent is NoAgent.
    #[tokio::test]
    async fn test_request_oidc_blob_failures() {
        let idp = auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "c".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: true,
        };
        let challenge = [3u8; 48];

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let hold = tokio::spawn(async move {
            let req: OidcCredentialRequest = rx.recv().await.unwrap();
            // Hold the reply sender past the timeout.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            drop(req);
        });
        let r = request_oidc_blob(
            &tx,
            idp.clone(),
            &challenge,
            true,
            std::time::Duration::from_millis(20),
        )
        .await;
        assert_eq!(r.unwrap_err(), AuthFailureReason::InteractionTimeout);
        hold.await.unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let req: OidcCredentialRequest = rx.recv().await.unwrap();
            drop(req.reply);
        });
        let r = request_oidc_blob(
            &tx,
            idp.clone(),
            &challenge,
            true,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(matches!(r.unwrap_err(), AuthFailureReason::AgentError(_)));

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();
        drop(rx);
        let r = request_oidc_blob(
            &tx,
            idp,
            &challenge,
            true,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert_eq!(r.unwrap_err(), AuthFailureReason::NoAgent);
    }

    /// A successful reply becomes an OIDC blob bound to the challenge, and
    /// the request carries the challenge-derived nonce and interactivity.
    #[tokio::test]
    async fn test_request_oidc_blob_success() {
        let idp = auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "c".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: true,
        };
        let challenge = [4u8; 48];
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let expected_nonce = auth::oidc_nonce_for_challenge(&challenge);
        tokio::spawn(async move {
            let req: OidcCredentialRequest = rx.recv().await.unwrap();
            assert_eq!(req.nonce, expected_nonce);
            assert!(!req.interactive);
            req.reply.send(Ok("id.token.here".to_string())).unwrap();
        });
        let blob = request_oidc_blob(
            &tx,
            idp,
            &challenge,
            false,
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(blob.issuer, "https://idp.test");
        assert_eq!(blob.id_token, "id.token.here");
        assert_eq!(blob.challenge, BASE64_STANDARD.encode(challenge));
    }

    /// A minimal advertised OIDC identity provider.
    fn test_idp() -> auth::OidcIdpInfo {
        auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: false,
        }
    }

    /// A test assembly, optionally with the test bootstrap key configured.
    fn assembly(bootstrap: bool) -> Arc<Assembly> {
        use crate::assembly::test::{TestAssemblyBuilder, create_assembly};

        let mut cfg = <config::Config as std::default::Default>::default();
        if bootstrap {
            let mut keypath = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            keypath.push("tests");
            keypath.push("data");
            keypath.push("rsa-key.pem");
            cfg.bootstrap = Some(auth::RsaBootstrapAuth::new("test.cn.zpr", &keypath).unwrap());
        }
        Arc::new(create_assembly(TestAssemblyBuilder {
            config: Some(rcu::RcuBox::new(cfg)),
            ..TestAssemblyBuilder::new()
        }))
    }

    /// An InitAuthentication challenge whose nonce bytes are `tag`.
    fn challenge(tag: u8) -> ZdpInitAuthenticationPayload {
        ZdpInitAuthenticationPayload {
            nonce: [tag; 8],
            ctime: 424242u64.into(),
            hmac: [9u8; 32],
        }
    }

    /// An advertised IdP with no registered agent and no bootstrap key
    /// cannot authenticate: `NoAgent` (zipline#13). With a bootstrap key the
    /// adapter falls back to device-only evidence, exactly as before OIDC.
    #[tokio::test]
    async fn test_no_agent_with_idp_fails_unless_bootstrap_fallback() {
        let asm = assembly(false);
        let r = produce_evidence(
            &asm,
            DOCK_LINK_ID,
            true,
            Some(&challenge(1)),
            &[test_idp()],
            None,
        )
        .await;
        assert_eq!(r.unwrap_err(), AuthFailureReason::NoAgent);

        let asm = assembly(true);
        let blobs = produce_evidence(
            &asm,
            DOCK_LINK_ID,
            true,
            Some(&challenge(1)),
            &[test_idp()],
            None,
        )
        .await
        .unwrap();
        assert!(matches!(&blobs[..], [AuthBlob::SelfSigned(_)]), "{blobs:?}");
    }

    /// With no IdP advertised and no usable bootstrap path (no key, or a
    /// node without bootstrap support) there is no way to authenticate:
    /// `AuthUnavailable`. The BAS fallback was removed in zipline#15.
    #[tokio::test]
    async fn test_no_method_is_auth_unavailable() {
        let r = produce_evidence(
            &assembly(false),
            DOCK_LINK_ID,
            true,
            Some(&challenge(1)),
            &[],
            None,
        )
        .await;
        assert_eq!(r.unwrap_err(), AuthFailureReason::AuthUnavailable);
        let r = produce_evidence(
            &assembly(true),
            DOCK_LINK_ID,
            false,
            Some(&challenge(1)),
            &[],
            None,
        )
        .await;
        assert_eq!(r.unwrap_err(), AuthFailureReason::AuthUnavailable);
    }

    /// An agent that accepts the request but never answers (the user never
    /// completes the login) fails the attempt with `InteractionTimeout`
    /// once `OIDC_USER_INTERACTION_TIMEOUT` elapses — not before. Replaces
    /// zipline's in-link WaitForUserAuth timeout test.
    #[tokio::test(start_paused = true)]
    async fn test_silent_agent_times_out_with_interaction_timeout() {
        let asm = assembly(false);
        let (agent, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
        let started = tokio::time::Instant::now();
        let (payload, idps) = (challenge(1), [test_idp()]);
        let attempt =
            produce_evidence(&asm, DOCK_LINK_ID, true, Some(&payload), &idps, Some(agent));
        // Hold every request (and its reply sender) without answering.
        let hold = async {
            let mut held = Vec::new();
            while let Some(req) = agent_rx.recv().await {
                held.push(req);
            }
        };
        let r = tokio::select! {
            r = attempt => r,
            _ = hold => unreachable!("the agent channel stays open"),
        };
        assert_eq!(r.unwrap_err(), AuthFailureReason::InteractionTimeout);
        assert!(started.elapsed() >= config::OIDC_USER_INTERACTION_TIMEOUT);
    }

    /// A reconnect within the lifetime of a previously issued ID token still
    /// asks the agent for an INTERACTIVE login bound to the new challenge:
    /// a cached token cannot carry the fresh challenge-bound nonce the
    /// connect path requires. Avoiding the re-prompt would need a
    /// protocol/VS design change, closed as wontfix in zipline#166
    /// (docs/OIDC.md, "Design decisions"); this pins the intended behavior.
    #[tokio::test]
    async fn test_reconnect_within_token_lifetime_rerequests_interaction() {
        let asm = assembly(false);
        let (agent, mut agent_rx) = tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();
        let answer = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Some(req) = agent_rx.recv().await {
                seen.push((req.nonce.clone(), req.interactive));
                let _ = req.reply.send(Ok("STILL.VALID.TOKEN".to_string()));
            }
            seen
        });
        for tag in [1, 2] {
            produce_evidence(
                &asm,
                DOCK_LINK_ID,
                true,
                Some(&challenge(tag)),
                &[test_idp()],
                Some(agent.clone()),
            )
            .await
            .unwrap();
        }
        drop(agent);
        let seen = answer.await.unwrap();
        assert_eq!(seen.len(), 2);
        for (tag, (nonce, interactive)) in [1, 2].into_iter().zip(seen) {
            assert!(
                interactive,
                "a reconnect is a new connect bound to a new challenge, so \
                 it re-requests interaction (zipline#157 problem 2, zipline#166)"
            );
            assert_eq!(
                nonce,
                auth::oidc_nonce_for_challenge(&challenge(tag).challenge_bytes())
            );
        }
    }
}
