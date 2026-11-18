//! Single-actor authorization, independent of the encrypted dock link.
//!
//! The node side of a dock authorizes the docked actor with the visa
//! service. Zipline hooks (search "zipline"): evidence is an array of
//! blobs; failures are recorded as a typed [AuthFailureReason] for ph-cli;
//! and authentication renewal state lives in [ActorAuthorization::renewal]
//! ([crate::actor_renewal]).

use crate::actor_renewal::RenewalState;
use crate::auth::{self, AuthBlob};
use crate::auth_agent::{AuthAgentHandle, AuthFailureReason};
use crate::link_state::LinkType;
use crate::mgmt::handlers::{HandleMgmtError, HandleMgmtResult};
use crate::mgmt::txn_mgr::TxnId;
use crate::prelude::*;
use crate::special_peers::SpecialPeerName;
use crate::zdp::AuthenticationStatus;
use crate::{mgmt, visa_mgmt};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use zerocopy::IntoBytes;
use zpr::vsapi_types::Connection;
use zpr_utils::net_defs::IpAddress;

/// Where the node side of a dock is in authorizing its docked actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorState {
    WaitingForLink,
    AwaitingEvidence,
    Authorizing,
    Authorized,
}

struct ActorData {
    state: ActorState,
    generation: u64,
    remote_txn: Option<TxnId>,
    challenge: Option<auth::ZdpInitAuthenticationPayload>,
    reason: Option<String>,
    /// Zipline: the AuthAgent able to renew this actor's authentication.
    agent: Option<AuthAgentHandle>,
    /// Zipline: why the most recent attempt failed, for showLink/ph-cli.
    /// Survives link teardown; cleared when the operator retries.
    last_failure: Option<AuthFailureReason>,
}

pub struct ActorAuthorization {
    id: LinkId,
    link_type: LinkType,
    data: Mutex<ActorData>,
    addresses: rcu::RcuBox<Vec<IpAddress>>,
    /// Zipline: authentication expiry and renewal (zipline#45/#66/#122).
    pub renewal: RenewalState,
}

impl ActorAuthorization {
    pub fn new(id: LinkId, link_type: LinkType) -> Self {
        Self {
            id,
            link_type,
            data: Mutex::new(ActorData {
                state: ActorState::WaitingForLink,
                generation: 0,
                remote_txn: None,
                challenge: None,
                reason: None,
                agent: None,
                last_failure: None,
            }),
            addresses: rcu::RcuBox::new(Vec::new()),
            renewal: RenewalState::new(),
        }
    }

    /// Zipline: register (or replace) the AuthAgent for this actor.
    #[cfg_attr(not(test), allow(dead_code))] // #234: deleted by core-node-auth
    pub fn set_auth_agent(&self, agent: AuthAgentHandle) {
        self.data.lock().unwrap().agent = Some(agent);
    }

    /// Zipline: clear the AuthAgent slot, but only if it still holds
    /// `handle`'s channel (zipline#45): the bridge for a dead capnp client
    /// must not clobber a NEWER agent registered after it. Returns true if
    /// the slot was cleared.
    pub fn clear_auth_agent_if(&self, handle: &AuthAgentHandle) -> bool {
        let mut data = self.data.lock().unwrap();
        if data
            .agent
            .as_ref()
            .is_some_and(|current| current.same_channel(handle))
        {
            data.agent = None;
            return true;
        }
        false
    }

    /// Zipline: the registered AuthAgent, if any.
    pub fn auth_agent(&self) -> Option<AuthAgentHandle> {
        self.data.lock().unwrap().agent.clone()
    }

    /// Zipline: record why authentication failed, for showLink / ph-cli.
    pub fn record_failure(&self, reason: AuthFailureReason) {
        let mut data = self.data.lock().unwrap();
        data.reason = Some(format!("{reason:?}"));
        data.last_failure = Some(reason);
    }

    /// Zipline: the most recent recorded failure, if any.
    #[cfg(test)]
    pub fn last_failure(&self) -> Option<AuthFailureReason> {
        self.data.lock().unwrap().last_failure.clone()
    }

    /// The actor state machine's current state.
    #[cfg(test)]
    pub fn state(&self) -> ActorState {
        self.data.lock().unwrap().state
    }

    pub fn addresses(&self) -> Vec<IpAddress> {
        self.addresses.get().clone()
    }

    pub fn owns_address(&self, addr: &IpAddress) -> bool {
        self.addresses.get().contains(addr)
    }

    pub fn add_internal_address(&self, addr: IpAddress) {
        assert_eq!(self.link_type, LinkType::Internal);
        self.addresses
            .update(|old| {
                let mut addresses = old.clone();
                addresses.push(addr);
                Some(addresses)
            })
            .unwrap();
    }

    /// Test-only: pretend this actor was authorized as `addresses`, without
    /// running the exchange.
    #[cfg(test)]
    pub fn test_set_addresses(&self, addresses: Vec<IpAddress>) {
        self.set_addresses(addresses);
    }

    fn set_addresses(&self, addresses: Vec<IpAddress>) {
        self.addresses.update(|_| Some(addresses.clone())).unwrap();
    }

    pub fn start_remote(&self, asm: &Arc<Assembly>, txn: TxnId) -> HandleMgmtResult {
        self.require_node_link(asm)?;
        let peer = asm
            .peer_table
            .get(self.id)
            .ok_or(HandleMgmtError::LinkClosed)?;
        let mut data = self.data.lock().unwrap();
        if data.remote_txn.is_some() || !self.addresses.get().is_empty() {
            return Err(HandleMgmtError::MessageNotPermitted);
        }
        let challenge = auth::ZdpInitAuthenticationPayload::new(&peer.auth_key);
        data.generation = data.generation.wrapping_add(1);
        data.state = ActorState::AwaitingEvidence;
        data.remote_txn = Some(txn);
        data.challenge = Some(challenge.clone());
        drop(data);
        mgmt::requests::send_init_authentication_request(
            asm,
            self.id,
            txn,
            AuthenticationStatus::Success,
            crate::zdp::init_authentication_flags::BOOTSTRAP_SUPPORT,
            challenge,
        )
        .enqueue();
        Ok(())
    }

    pub fn abandon_remote(&self, asm: &Arc<Assembly>, txn: TxnId) -> HandleMgmtResult {
        self.require_node_link(asm)?;
        let mut data = self.data.lock().unwrap();
        if data.state != ActorState::AwaitingEvidence || data.remote_txn != Some(txn) {
            return Err(HandleMgmtError::UnknownTransaction);
        }
        data.remote_txn = None;
        data.challenge = None;
        data.state = ActorState::WaitingForLink;
        Ok(())
    }

    fn require_node_link(&self, asm: &Assembly) -> HandleMgmtResult {
        if self.link_type != LinkType::NodeToAdapter || !asm.is_link_ready(self.id) {
            return Err(HandleMgmtError::MessageNotPermitted);
        }
        Ok(())
    }

    pub fn acquire_remote(
        self: &Arc<Self>,
        asm: &Arc<Assembly>,
        txn: TxnId,
        addrs: Option<Vec<IpAddress>>,
        blob: String,
    ) -> HandleMgmtResult {
        let peer = asm
            .peer_table
            .get(self.id)
            .ok_or(HandleMgmtError::LinkClosed)?;
        self.require_node_link(asm)?;
        if addrs.as_ref().is_some_and(|addresses| addresses.len() > 1) {
            return Err(HandleMgmtError::BadStructure);
        }
        let (generation, challenge) = {
            let mut data = self.data.lock().unwrap();
            if data.state != ActorState::AwaitingEvidence || data.remote_txn != Some(txn) {
                return Err(HandleMgmtError::UnknownTransaction);
            }
            data.state = ActorState::Authorizing;
            (
                data.generation,
                data.challenge
                    .take()
                    .ok_or(HandleMgmtError::MessageNotPermitted)?,
            )
        };
        let requested_addr = addrs
            .and_then(|a| a.first().copied())
            .unwrap_or(IpAddress::UNSPECIFIED);
        // Zipline: evidence is an array of blobs — a self-signed device leg
        // and/or an OIDC user leg (zipline#12/#122).
        let blobs = match auth::decode_blobs(&blob) {
            Ok(blobs) => blobs,
            Err(err) => {
                warn!(target: LINK_STATE, "{}: invalid actor evidence: {err}", asm.formatted_link_id(self.id));
                return self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Rejected,
                    None,
                );
            }
        };
        if let Err(err) = verify_evidence(&blobs, &challenge, &peer.auth_key) {
            warn!(target: LINK_STATE, "{}: actor challenge verification failed: {err}", asm.formatted_link_id(self.id));
            return self.finish_remote(asm, generation, txn, AuthenticationStatus::Rejected, None);
        }
        // Zipline: remember what the actor proved, for renewal (zipline#45/#122).
        if let Some(oidc) = blobs.iter().find_map(|b| match b {
            AuthBlob::Oidc(oidc) => Some(oidc),
            _ => None,
        }) {
            crate::actor_renewal::stash_identity(asm, self.id, &self.renewal, oidc);
        }
        self.renewal.set_namespaces(auth::blob_namespaces(&blobs));
        let req = match visa_mgmt::build_connect_request(
            asm,
            requested_addr,
            &blobs,
            *peer.a2a_dh_pubkey.get(),
        ) {
            Ok(req) => req,
            Err(err) => {
                warn!(target: LINK_STATE, "{}: invalid actor authorization request: {err}", asm.formatted_link_id(self.id));
                return self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Rejected,
                    None,
                );
            }
        };
        let is_vs = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
            .is_some_and(|id| id.get() == self.id);
        if is_vs {
            // The VS adapter authenticates with its device key only.
            if requested_addr == IpAddress::UNSPECIFIED
                || !blobs.iter().all(|b| matches!(b, AuthBlob::SelfSigned(_)))
            {
                return self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Rejected,
                    None,
                );
            }
            *asm.deferred_vs_connect.lock().unwrap() = Some((self.id, requested_addr, req));
            return self.finish_remote(
                asm,
                generation,
                txn,
                AuthenticationStatus::Success,
                Some(requested_addr),
            );
        }
        let actor = self.clone();
        let asm = asm.clone();
        let worker_asm = asm.clone();
        let handle = tokio::task::spawn_local(async move {
            let result = visa_mgmt::authorize_connect(&worker_asm, req).await;
            actor
                .authorization_result(&worker_asm, generation, txn, result)
                .await;
        });
        // Keep in-flight VS work alive on link loss so late success can be deregistered.
        let _ = handle;
        Ok(())
    }

    async fn authorization_result(
        &self,
        asm: &Arc<Assembly>,
        generation: u64,
        txn: TxnId,
        result: Result<Connection, libnode::error::VSApiError>,
    ) {
        let current = {
            let data = self.data.lock().unwrap();
            data.generation == generation
                && data.remote_txn == Some(txn)
                && data.state == ActorState::Authorizing
        };
        match result {
            Ok(conn) if !current => {
                visa_mgmt::actor_disconnect(asm.clone(), IpAddress::new_from_std(&conn.zpr_addr))
                    .await;
            }
            Ok(conn) => {
                let addr = IpAddress::new_from_std(&conn.zpr_addr);
                if !conn.zpr_addr.is_ipv6() || conn.zpr_addr.is_unspecified() {
                    error!(target: LINK_STATE, "{}: VS returned an invalid actor address", asm.formatted_link_id(self.id));
                    visa_mgmt::actor_disconnect(asm.clone(), addr).await;
                    self.report_finish(asm, generation, txn, AuthenticationStatus::Retryable, None);
                } else if let Err(err) = self
                    .finish_remote(
                        asm,
                        generation,
                        txn,
                        AuthenticationStatus::Success,
                        Some(addr),
                    )
                    .inspect(|()| {
                        // Zipline: start the renewal window (zipline#45).
                        visa_mgmt::record_auth_expires(asm, self.id, conn.auth_expires)
                    })
                {
                    warn!(target: LINK_STATE, "{}: actor link closed before registration could be committed: {err}", asm.formatted_link_id(self.id));
                    visa_mgmt::actor_disconnect(asm.clone(), addr).await;
                }
            }
            Err(err) if current => {
                warn!(target: LINK_STATE, "{}: VS actor authorization failed: {err}", asm.formatted_link_id(self.id));
                let status = visa_mgmt::authorization_error_status(&err);
                self.report_finish(asm, generation, txn, status, None);
            }
            Err(err) => {
                warn!(target: LINK_STATE, "{}: abandoned VS authorization failed: {err}", asm.formatted_link_id(self.id));
            }
        }
    }

    fn report_finish(
        &self,
        asm: &Arc<Assembly>,
        generation: u64,
        txn: TxnId,
        status: AuthenticationStatus,
        addr: Option<IpAddress>,
    ) {
        if let Err(err) = self.finish_remote(asm, generation, txn, status, addr) {
            error!(target: LINK_STATE, "{}: cannot complete actor authorization: {err}", asm.formatted_link_id(self.id));
        }
    }

    fn finish_remote(
        &self,
        asm: &Arc<Assembly>,
        generation: u64,
        txn: TxnId,
        status: AuthenticationStatus,
        addr: Option<IpAddress>,
    ) -> HandleMgmtResult {
        let mut data = self.data.lock().unwrap();
        if data.generation != generation || data.remote_txn != Some(txn) {
            return Err(HandleMgmtError::UnknownTransaction);
        }
        data.remote_txn = None;
        data.challenge = None;
        data.state = if status == AuthenticationStatus::Success {
            ActorState::Authorized
        } else {
            ActorState::WaitingForLink
        };
        if let Some(addr) = addr {
            self.set_addresses(vec![addr]);
        }
        drop(data);
        let addrs: Vec<IpAddr> = addr.into_iter().map(Into::into).collect();
        mgmt::requests::send_grant_zpr_address_request(asm, self.id, txn, status, &addrs).enqueue();
        Ok(())
    }

    pub fn link_down(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let mut data = self.data.lock().unwrap();
        data.generation = data.generation.wrapping_add(1);
        data.remote_txn = None;
        data.challenge = None;
        data.state = ActorState::WaitingForLink;
        let mut work = tokio::task::JoinSet::new();
        if self.link_type == LinkType::NodeToAdapter {
            let is_vs = asm
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
                .is_some_and(|id| id.get() == self.id);
            if !is_vs {
                for addr in self.addresses() {
                    work.spawn_local(visa_mgmt::actor_disconnect(asm.clone(), addr));
                }
            }
        }
        self.set_addresses(Vec::new());
        // Zipline: a new link session starts a new renewal window.
        self.renewal.reset();
        work
    }
}

/// Zipline: check every blob of an actor's evidence against the challenge
/// this node issued for the exchange. Each blob must be bound byte-for-byte
/// to that challenge (#1410) and its challenge must HMAC-verify with the
/// link's auth key and be fresh: [auth::MAX_BLOB_AGE_SECONDS] for a
/// self-signed blob, the longer OIDC window for an OIDC blob, whose
/// challenge was issued before the user completed the browser flow.
/// Identity itself is verified by the visa service.
fn verify_evidence(
    blobs: &[AuthBlob],
    challenge: &auth::ZdpInitAuthenticationPayload,
    key: &[u8; auth::AUTH_KEY_SIZE_BYTES],
) -> Result<(), auth::AuthError> {
    let expected = BASE64_STANDARD.encode(challenge.as_bytes());
    for blob in blobs {
        let bound = match blob {
            AuthBlob::SelfSigned(ss) => &ss.challenge,
            AuthBlob::Oidc(oidc) => &oidc.challenge,
        };
        if *bound != expected {
            return Err(auth::AuthError::FormatError(
                "evidence is bound to a different challenge".into(),
            ));
        }
        match blob {
            AuthBlob::SelfSigned(ss) => {
                ss.verify_blob_challenge(key, auth::MAX_BLOB_AGE_SECONDS)?
            }
            AuthBlob::Oidc(oidc) => {
                oidc.verify_challenge(key)?;
            }
        }
    }
    Ok(())
}

impl fmt::Display for ActorAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.data.lock().unwrap();
        writeln!(f, "  Actor state: {:?}", data.state)?;
        writeln!(f, "  Actor addresses: {:?}", &*self.addresses.get())?;
        if let Some(reason) = &data.reason {
            writeln!(f, "  Actor failure: {reason}")?;
        }
        // Zipline: ph-cli `connect` parses this line (adapter/cli/src/oidc.rs).
        if let Some(failure) = &data.last_failure {
            writeln!(f, "  Last auth failure: {failure:?}")?;
        }
        drop(data);
        write!(f, "{}", self.renewal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use tokio::task::LocalSet;

    fn actor() -> Arc<ActorAuthorization> {
        Arc::new(ActorAuthorization::new(
            DOCK_LINK_ID,
            LinkType::NodeToAdapter,
        ))
    }

    #[tokio::test]
    async fn acquire_without_peer_preserves_pending_authentication() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = Arc::new(ActorAuthorization::new(3, LinkType::NodeToAdapter));
        let challenge = auth::ZdpInitAuthenticationPayload::new(&[42; 32]);
        {
            let mut data = actor.data.lock().unwrap();
            data.state = ActorState::AwaitingEvidence;
            data.generation = 1;
            data.remote_txn = Some(42);
            data.challenge = Some(challenge.clone());
        }

        assert!(matches!(
            actor.acquire_remote(&asm, 42, None, String::new()),
            Err(HandleMgmtError::LinkClosed)
        ));

        let data = actor.data.lock().unwrap();
        assert_eq!(data.state, ActorState::AwaitingEvidence);
        assert_eq!(data.generation, 1);
        assert_eq!(data.remote_txn, Some(42));
        assert_eq!(
            data.challenge.as_ref().unwrap().as_bytes(),
            challenge.as_bytes()
        );
    }

    #[tokio::test]
    async fn stale_node_completion_cannot_install_an_address() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = ActorAuthorization::new(3, LinkType::NodeToAdapter);
        {
            let mut data = actor.data.lock().unwrap();
            data.remote_txn = Some(42);
            data.generation = 1;
            data.state = ActorState::Authorizing;
        }
        assert!(actor.link_down(&asm).is_empty());
        assert!(
            actor
                .finish_remote(
                    &asm,
                    1,
                    42,
                    AuthenticationStatus::Success,
                    Some("::42".parse::<IpAddr>().unwrap().into()),
                )
                .is_err()
        );
        assert!(actor.addresses().is_empty());
    }

    /// Insert a peer of `link_type` into the table and return its link id.
    /// Its auth key is the dummy peer key, `[42; 32]`.
    fn add_peer(asm: &Arc<Assembly>, link_type: LinkType) -> LinkId {
        use crate::peer_table::test::create_dummy_peer_state;
        use std::net::Ipv4Addr;
        use zpr_utils::net_defs::ScopedIpAddr;

        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let peer = create_dummy_peer_state(
            link_id,
            link_type,
            SubstrateAddr::from(([127, 0, 0, 1], 9000 + link_id.get() as u16)),
            ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        );
        entry.insert(peer).get()
    }

    /// A challenge HMAC'd with `key` and issued `age_secs` ago.
    fn aged_challenge(key: &[u8; 32], age_secs: u64) -> auth::ZdpInitAuthenticationPayload {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut payload = auth::ZdpInitAuthenticationPayload {
            nonce: [age_secs as u8; 8],
            ctime: (now - age_secs).into(),
            hmac: [0; 32],
        };
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(&payload.nonce);
        hasher.update(&payload.ctime.to_bytes());
        payload.hmac = hasher.finalize().into();
        payload
    }

    /// A self-signed blob claiming to answer `payload`. Its signature is
    /// never checked by the node (the visa service verifies identity).
    fn ss_blob(payload: &auth::ZdpInitAuthenticationPayload) -> AuthBlob {
        AuthBlob::SelfSigned(auth::ZdpSelfSignedBlob {
            blob_type: auth::BLOB_TYPE_SS.to_string(),
            ts: 0,
            cn: "test.cn.zpr".to_string(),
            challenge: BASE64_STANDARD.encode(payload.as_bytes()),
            sig: String::new(),
        })
    }

    /// An OIDC blob claiming to answer `payload`.
    fn oidc_blob(payload: &auth::ZdpInitAuthenticationPayload) -> AuthBlob {
        AuthBlob::Oidc(auth::ZdpOidcBlob {
            blob_type: auth::BLOB_TYPE_OIDC.to_string(),
            issuer: "https://idp.test".to_string(),
            id_token: "tok".to_string(),
            challenge: BASE64_STANDARD.encode(payload.as_bytes()),
        })
    }

    /// Node-side evidence check (#1410 + zipline#12/#122): every blob of
    /// the array must be bound byte-for-byte to the challenge this node
    /// issued — a different, even validly HMAC'd and fresh, challenge is
    /// refused — and must HMAC-verify with the link key.
    #[test]
    fn test_verify_evidence_requires_exact_issued_challenge() {
        let key = [42u8; 32];
        let issued = aged_challenge(&key, 0);
        let other = auth::ZdpInitAuthenticationPayload::new(&key);
        assert_ne!(issued.as_bytes(), other.as_bytes());

        verify_evidence(&[ss_blob(&issued), oidc_blob(&issued)], &issued, &key)
            .expect("blobs bound to the issued challenge verify");
        for blobs in [
            vec![ss_blob(&other)],
            vec![oidc_blob(&other)],
            // One mis-bound leg spoils the whole array.
            vec![ss_blob(&issued), oidc_blob(&other)],
            vec![ss_blob(&other), oidc_blob(&issued)],
        ] {
            assert!(
                verify_evidence(&blobs, &issued, &key).is_err(),
                "evidence bound to another challenge must be refused: {blobs:?}"
            );
        }

        // A challenge HMAC'd with another link's key fails the HMAC check
        // even when it is the one "issued".
        let foreign = aged_challenge(&[7u8; 32], 0);
        assert!(matches!(
            verify_evidence(&[ss_blob(&foreign)], &foreign, &key),
            Err(auth::AuthError::InvalidHmac)
        ));
        assert!(matches!(
            verify_evidence(&[oidc_blob(&foreign)], &foreign, &key),
            Err(auth::AuthError::InvalidHmac)
        ));
    }

    /// The freshness windows differ by blob type: a self-signed blob must
    /// answer within [auth::MAX_BLOB_AGE_SECONDS], an OIDC blob within the
    /// longer [auth::MAX_OIDC_BLOB_AGE_SECONDS], because its challenge was
    /// issued before the user completed the browser flow (zipline#12).
    #[test]
    fn test_verify_evidence_age_window_depends_on_blob_type() {
        let key = [42u8; 32];
        // Past the SS window but inside the OIDC one.
        let middle = aged_challenge(&key, auth::MAX_BLOB_AGE_SECONDS + 10);
        assert!(auth::MAX_BLOB_AGE_SECONDS + 10 < auth::MAX_OIDC_BLOB_AGE_SECONDS);
        assert!(matches!(
            verify_evidence(&[ss_blob(&middle)], &middle, &key),
            Err(auth::AuthError::ChallengeTooOld)
        ));
        verify_evidence(&[oidc_blob(&middle)], &middle, &key)
            .expect("an OIDC blob may answer within the OIDC window");

        // Past the OIDC window too.
        let stale = aged_challenge(&key, auth::MAX_OIDC_BLOB_AGE_SECONDS + 10);
        assert!(matches!(
            verify_evidence(&[oidc_blob(&stale)], &stale, &key),
            Err(auth::AuthError::ChallengeTooOld)
        ));
    }

    /// ph-cli `connect` parses showLink's `Last auth failure: {:?}` line
    /// (adapter/cli/src/oidc.rs) and maps the Debug spelling of
    /// [AuthFailureReason] onto exit codes, so the line's exact format is a
    /// CLI contract. It is absent until a failure is recorded.
    #[test]
    fn test_display_prints_last_auth_failure_for_ph_cli() {
        let actor = actor();
        let text = format!("{actor}");
        assert!(text.contains("  Actor state: WaitingForLink\n"), "{text}");
        assert!(!text.contains("Last auth failure"), "{text}");

        actor.record_failure(AuthFailureReason::PolicyDenied);
        assert!(
            format!("{actor}").contains("\n  Last auth failure: PolicyDenied\n"),
            "{actor}"
        );
        actor.record_failure(AuthFailureReason::VisaServiceRejected("bad token".into()));
        assert!(
            format!("{actor}")
                .contains("  Last auth failure: VisaServiceRejected(\"bad token\")\n"),
            "{actor}"
        );
    }

    /// zipline#45 (C2): clearing the AuthAgent slot only clears the handle
    /// it was asked about — the bridge for a dead capnp client must not
    /// clobber a NEWER agent registered after it.
    #[test]
    fn test_clear_auth_agent_if_only_clears_matching_handle() {
        let actor = actor();
        let (agent1, _rx1) = tokio::sync::mpsc::unbounded_channel();
        let (agent2, _rx2) = tokio::sync::mpsc::unbounded_channel();

        // agent1 registers, then its admin connection dies: cleared.
        actor.set_auth_agent(agent1.clone());
        assert!(actor.auth_agent().is_some());
        assert!(actor.clear_auth_agent_if(&agent1));
        assert!(actor.auth_agent().is_none());

        // agent1 re-registers, then agent2 replaces it. agent1's stale
        // cleanup must NOT clobber agent2.
        actor.set_auth_agent(agent1.clone());
        actor.set_auth_agent(agent2.clone());
        assert!(!actor.clear_auth_agent_if(&agent1));
        assert!(
            actor.auth_agent().unwrap().same_channel(&agent2),
            "stale bridge cleanup clobbered the newer agent"
        );
    }

    /// N2 (zipline#122), node side: a verified AcquireZprAddress records the
    /// namespace set of its blobs, which a later renewal must match.
    #[tokio::test]
    async fn test_node_acquire_records_namespace_set() {
        use crate::auth::AuthNamespace;
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_peer(&asm, LinkType::NodeToAdapter);
                let peer = asm.peer_table.get(link_id).unwrap();
                peer.link_state_machine.test_set_active();
                let actor = peer.actor_auth.clone();
                drop(peer);

                // The node issued a challenge HMAC'd with the link's auth
                // key and awaits the actor's evidence.
                let challenge = auth::ZdpInitAuthenticationPayload::new(&[42u8; 32]);
                {
                    let mut data = actor.data.lock().unwrap();
                    data.state = ActorState::AwaitingEvidence;
                    data.remote_txn = Some(42);
                    data.challenge = Some(challenge.clone());
                }
                let blob_str = auth::encode_blobs(&[ss_blob(&challenge), oidc_blob(&challenge)]);

                // NOTE: no yields after the call — the authorize task the
                // acquire path spawns toward the (absent) VS must not run.
                actor.acquire_remote(&asm, 42, None, blob_str).unwrap();
                assert_eq!(
                    actor.renewal.namespaces(),
                    Some([AuthNamespace::Device, AuthNamespace::User].into()),
                    "the node must record the verified blob set's namespaces"
                );
                assert_eq!(actor.state(), ActorState::Authorizing);
            })
            .await
    }

    /// Node side: evidence bound to anything but the issued challenge is
    /// rejected before it reaches the visa service, and records nothing for
    /// renewal.
    #[tokio::test]
    async fn test_node_acquire_rejects_evidence_for_another_challenge() {
        LocalSet::new()
            .run_until(async {
                // The rejection is sent to the adapter: keep egress open.
                let (egress_tx, _egress_rx) = crate::packet_queue::packet_queue(8);
                let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                    mgmt_substrate_egress: Some(crate::queues::MgmtSubstrateEgress::new(egress_tx)),
                    ..TestAssemblyBuilder::new()
                }));
                let link_id = add_peer(&asm, LinkType::NodeToAdapter);
                let peer = asm.peer_table.get(link_id).unwrap();
                peer.link_state_machine.test_set_active();
                let actor = peer.actor_auth.clone();
                drop(peer);

                let issued = auth::ZdpInitAuthenticationPayload::new(&[42u8; 32]);
                let replayed = auth::ZdpInitAuthenticationPayload::new(&[42u8; 32]);
                {
                    let mut data = actor.data.lock().unwrap();
                    data.state = ActorState::AwaitingEvidence;
                    data.remote_txn = Some(42);
                    data.challenge = Some(issued);
                }
                let blob_str = auth::encode_blobs(&[oidc_blob(&replayed)]);
                actor.acquire_remote(&asm, 42, None, blob_str).unwrap();
                assert_eq!(actor.renewal.namespaces(), None);
                assert_eq!(actor.state(), ActorState::WaitingForLink);
                assert!(actor.addresses().is_empty());
            })
            .await
    }
}
