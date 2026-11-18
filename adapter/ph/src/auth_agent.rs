//! Zipline: out-of-band authentication through the AuthAgent (ph-cli).
//!
//! ph-cli registers an AuthAgent with a Zode's `login` (zl-zipline#233);
//! the Zode asks it for OIDC ID tokens out of band. This module holds that
//! zipline-only machinery:
//!
//! - [AuthFailureReason]: why an attempt failed, as reported to ph-cli.
//! - [OidcCredentialRequest] / [AuthAgentHandle]: the bridge to the agent.
//! - [request_id_token]: one bounded request for an ID token.

use crate::auth;
use crate::prelude::*;

/// Why an actor authentication attempt failed, as reported to ph-cli.
///
/// A failed `login` answers with the Debug spelling of this type, which
/// ph-cli maps onto `connect` exit codes (adapter/cli/src/oidc.rs), so
/// renaming a variant is a CLI-visible change.
#[allow(dead_code)] // some variants are only constructed in some deployments
#[derive(Clone, Debug, PartialEq, strum::IntoStaticStr)]
pub enum AuthFailureReason {
    /// OIDC required but no AuthAgent is registered.
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
    /// A Zode's own login (zl-zipline#233): the node's VS-API session was
    /// replaced (a reconnect, a visa-service restart, a rejoin or a K2
    /// re-authentication), and the visa service dropped the login with it.
    SessionReplaced,
    /// A Zode's own login (zl-zipline#233): it expired without a successful
    /// silent renewal, so ph logged the user out.
    LoginExpired,
}

impl AuthFailureReason {
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
    /// The OIDC nonce: derived from the link challenge
    /// ([auth::oidc_nonce_for_challenge]) for a docked actor, or minted by
    /// the visa service for a Zode's own login (zl-zipline#233).
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
    oidc_idps(asm, &asm.formatted_link_id(link_id).to_string())
}

/// Node side: one [auth::OidcIdpInfo] per auth service the visa service
/// lists with `stype == OidcAuthentication` that carries a client config.
/// `context` names what they are for in the log: a link, or a Zode's own
/// login (zl-zipline#233).
pub fn oidc_idps(asm: &Assembly, context: &str) -> Vec<auth::OidcIdpInfo> {
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
                warn!(target: LINK_STATE, "{context}: OIDC service {} has no client config",
                    service.service_id);
                return None;
            };
            debug!(target: LINK_STATE, "{context}: OIDC IdP: {}", cfg.issuer);
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

/// Ask `agent` for an OIDC ID token from `idp` bound to `nonce`. Waits at
/// most `timeout`; an elapsed wait is [AuthFailureReason::InteractionTimeout].
/// A gone agent is [AuthFailureReason::NoAgent]. Dropping the returned
/// future drops the reply receiver, which the agent bridge observes and uses
/// to cancel the in-flight RPC.
pub async fn request_id_token(
    agent: &AuthAgentHandle,
    idp: auth::OidcIdpInfo,
    nonce: String,
    interactive: bool,
    timeout: std::time::Duration,
) -> Result<String, AuthFailureReason> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = OidcCredentialRequest {
        idp,
        nonce,
        interactive,
        reply: reply_tx,
    };
    if agent.send(request).is_err() {
        // The agent went away (ph-cli disconnected).
        return Err(AuthFailureReason::NoAgent);
    }
    match tokio::time::timeout(timeout, reply_rx).await {
        Ok(Ok(result)) => result,
        // The bridge dropped the reply without answering.
        Ok(Err(_)) => Err(AuthFailureReason::AgentError(
            "AuthAgent dropped the request".to_string(),
        )),
        Err(_elapsed) => Err(AuthFailureReason::InteractionTimeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zdp::AuthenticationStatus;

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
        let payload = auth::ZdpInitAuthenticationPayload {
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
    async fn test_request_id_token_failures() {
        let idp = auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "c".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: true,
        };
        let nonce = "nonce".to_string();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let hold = tokio::spawn(async move {
            let req: OidcCredentialRequest = rx.recv().await.unwrap();
            // Hold the reply sender past the timeout.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            drop(req);
        });
        let r = request_id_token(
            &tx,
            idp.clone(),
            nonce.clone(),
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
        let r = request_id_token(
            &tx,
            idp.clone(),
            nonce.clone(),
            true,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(matches!(r.unwrap_err(), AuthFailureReason::AgentError(_)));

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();
        drop(rx);
        let r = request_id_token(
            &tx,
            idp,
            nonce.clone(),
            true,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert_eq!(r.unwrap_err(), AuthFailureReason::NoAgent);
    }
}
