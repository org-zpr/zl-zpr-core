//! Single-actor authorization, independent of the encrypted dock link.
//!
//! Zipline hooks (search "zipline"): actor evidence comes from
//! [crate::auth_agent] (OIDC via the AuthAgent, or bootstrap) instead of the
//! BAS/OAuthRsa service; evidence is an array of blobs; grant activation
//! runs the host checks in [crate::actor_activation]; failures are recorded
//! as a typed [AuthFailureReason] for ph-cli; and authentication renewal
//! state lives in [ActorAuthorization::renewal] ([crate::actor_renewal]).

use crate::actor_renewal::RenewalState;
use crate::auth::{self, AuthBlob};
use crate::auth_agent::{AuthAgentHandle, AuthFailureReason};
use crate::counters::ManagementCounterType;
use crate::link_state::LinkType;
use crate::mgmt::handlers::{HandleMgmtError, HandleMgmtResult};
use crate::mgmt::txn_mgr::{TxnHandle, TxnId};
use crate::prelude::*;
use crate::special_peers::SpecialPeerName;
use crate::zdp::AuthenticationStatus;
use crate::{mgmt, visa_mgmt};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use zerocopy::IntoBytes;
use zpr::addrs::ZPRNET_PREFIX_LEN;
use zpr::vsapi_types::Connection;
use zpr_utils::net_defs::IpAddress;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorState {
    WaitingForLink,
    RequestingAuthentication,
    AwaitingEvidence,
    Authenticating,
    AcquiringAddress,
    Authorizing,
    AbandoningAuthentication,
    RetryBackoff,
    Rejected,
    Authorized,
}

/// The node's answer to StartAuthentication. Upstream #1410 also carries an
/// ASA service offer; zipline advertises OIDC IdPs in HelloResponse instead
/// (zipline#12/#15).
pub struct AuthenticationOffer {
    pub status: AuthenticationStatus,
    pub challenge: Option<auth::ZdpInitAuthenticationPayload>,
}

enum Reply {
    Offer(AuthenticationOffer),
    Grant(AuthenticationStatus, Vec<IpAddress>),
}

struct ActorData {
    state: ActorState,
    generation: u64,
    txn: Option<TxnHandle>,
    remote_txn: Option<TxnId>,
    challenge: Option<auth::ZdpInitAuthenticationPayload>,
    reply: Option<oneshot::Sender<Reply>>,
    worker: Option<tokio::task::AbortHandle>,
    reason: Option<String>,
    installed_address: Option<IpAddress>,
    /// Zipline: the AuthAgent ph-cli registered with startLink (adapter).
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
                txn: None,
                remote_txn: None,
                challenge: None,
                reply: None,
                worker: None,
                reason: None,
                installed_address: None,
                agent: None,
                last_failure: None,
            }),
            addresses: rcu::RcuBox::new(Vec::new()),
            renewal: RenewalState::new(),
        }
    }

    /// Zipline: register (or replace) the AuthAgent for this actor. Set by
    /// the admin worker's startLink handler.
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
    pub fn last_failure(&self) -> Option<AuthFailureReason> {
        self.data.lock().unwrap().last_failure.clone()
    }

    /// Zipline: the operator asked to retry (startLink, i.e. `ph-cli
    /// connect`): forget the previous attempt's failure and lift the
    /// rejection latch. Upstream #1410 only lifts the latch on restart.
    pub fn operator_retry(&self, asm: &Assembly) {
        asm.actor_rejected.store(false, Ordering::Release);
        let mut data = self.data.lock().unwrap();
        data.last_failure = None;
        data.reason = None;
        if data.state == ActorState::Rejected {
            data.state = ActorState::WaitingForLink;
        }
    }

    /// The actor state machine's current state.
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

    pub fn link_ready(self: &Arc<Self>, asm: &Arc<Assembly>) {
        if self.link_type != LinkType::AdapterToNode {
            return;
        }
        let mut data = self.data.lock().unwrap();
        // Suppress duplicate readiness notifications within this link session.
        // link_down takes the handle before aborting, so reconnect does not wait for cancellation.
        if data
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            return;
        }
        data.generation = data.generation.wrapping_add(1);
        if asm.actor_rejected.load(Ordering::Acquire) {
            data.state = ActorState::Rejected;
            return;
        }
        let actor = self.clone();
        let asm = asm.clone();
        data.worker = Some(
            tokio::task::spawn_local(async move {
                actor.run(&asm).await;
            })
            .abort_handle(),
        );
    }

    fn prepare_reply(&self, txn: &TxnHandle, state: ActorState) -> oneshot::Receiver<Reply> {
        let (tx, rx) = oneshot::channel();
        let mut data = self.data.lock().unwrap();
        data.state = state;
        data.txn = Some(txn.clone());
        data.reply = Some(tx);
        rx
    }

    async fn run(self: &Arc<Self>, asm: &Arc<Assembly>) {
        let mut backoff = config::ACTOR_AUTH_RETRY_INITIAL;
        loop {
            let Some(peer) = asm.peer_table.get(self.id) else {
                return;
            };
            let txn = peer.txn_mgr.open().await;
            drop(peer);
            let reply = self.prepare_reply(&txn, ActorState::RequestingAuthentication);
            if mgmt::requests::send_start_authentication(asm, self.id, txn.id())
                .await
                .is_err()
            {
                return;
            }
            let offer = match reply.await {
                Ok(Reply::Offer(offer)) => offer,
                Err(_) => {
                    debug!(target: LINK_STATE, "{}: actor exchange closed while awaiting an authentication offer", asm.formatted_link_id(self.id));
                    return;
                }
                Ok(Reply::Grant(_, _)) => {
                    error!(target: LINK_STATE, "{}: actor exchange received an address grant instead of an authentication offer", asm.formatted_link_id(self.id));
                    return;
                }
            };
            // Zipline: failures carry a typed reason (for ph-cli) and are
            // classified terminal vs. retryable by AuthFailureReason.
            let failure = if offer.status == AuthenticationStatus::Success {
                self.data.lock().unwrap().state = ActorState::Authenticating;
                match self.authenticate(asm, &offer).await {
                    Ok(blob) => {
                        let requested = asm.config.get().zpr_addr.clone();
                        let reply = self.prepare_reply(&txn, ActorState::AcquiringAddress);
                        if mgmt::requests::send_acquire_zpr_address_request(
                            asm,
                            self.id,
                            txn.id(),
                            &requested,
                            Some(blob.as_bytes()),
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        match reply.await {
                            Ok(Reply::Grant(status, addresses))
                                if status == AuthenticationStatus::Success =>
                            {
                                self.install_address(asm, addresses[0]);
                                return;
                            }
                            Ok(Reply::Grant(status, _)) => {
                                warn!(target: LINK_STATE, "{}: node returned {status:?} for actor authorization", asm.formatted_link_id(self.id));
                                AuthFailureReason::from_grant_status(status)
                            }
                            Err(_) => {
                                debug!(target: LINK_STATE, "{}: actor exchange closed while awaiting an address grant", asm.formatted_link_id(self.id));
                                return;
                            }
                            Ok(Reply::Offer(_)) => {
                                error!(target: LINK_STATE, "{}: actor exchange received an authentication offer instead of an address grant", asm.formatted_link_id(self.id));
                                return;
                            }
                        }
                    }
                    Err(reason) => {
                        warn!(target: LINK_STATE, "{}: actor authentication failed: {reason:?}", asm.formatted_link_id(self.id));
                        self.begin_abandonment(asm, &reason);
                        if mgmt::requests::send_abandon_authentication(asm, self.id, txn.id())
                            .acked()
                            .await
                            .is_err()
                        {
                            return;
                        }
                        reason
                    }
                }
            } else {
                warn!(target: LINK_STATE, "{}: node returned {:?} for authentication start", asm.formatted_link_id(self.id), offer.status);
                AuthFailureReason::from_grant_status(offer.status)
            };
            self.record_failure(failure.clone());
            {
                let mut data = self.data.lock().unwrap();
                data.txn = None;
                data.reply = None;
            }
            drop(txn);
            if failure.is_terminal(asm.config.get().auto_connect) {
                asm.actor_rejected.store(true, Ordering::Release);
                self.data.lock().unwrap().state = ActorState::Rejected;
                asm.counters.management[ManagementCounterType::ActorAuthorizationRejected]
                    .increment();
                warn!(target: LINK_STATE, "{}: actor authorization rejected ({failure:?}); run `ph-cli connect` or restart the adapter to retry", asm.formatted_link_id(self.id));
                return;
            }
            self.data.lock().unwrap().state = ActorState::RetryBackoff;
            asm.counters.management[ManagementCounterType::ActorAuthorizationRetry].increment();
            warn!(target: LINK_STATE, "{}: actor authorization temporarily unavailable; retrying after backoff", asm.formatted_link_id(self.id));
            let mut random = [0u8; 2];
            aws_lc_rs::rand::fill(&mut random).expect("retry jitter entropy");
            let (delay, next) = retry_delay(backoff, u16::from_be_bytes(random));
            tokio::time::sleep(delay).await;
            backoff = next;
        }
    }

    /// Latch a terminal denial and record the failure reason, then enter
    /// AbandoningAuthentication. Both must happen BEFORE the worker awaits
    /// the Abandon ACK: link loss during that wait aborts the worker, and
    /// must neither undo an explicit denial (#1410) nor lose the reason
    /// ph-cli `connect` reports (zipline).
    fn begin_abandonment(&self, asm: &Assembly, reason: &AuthFailureReason) {
        if reason.is_terminal(asm.config.get().auto_connect) {
            asm.actor_rejected.store(true, Ordering::Release);
        }
        self.record_failure(reason.clone());
        self.data.lock().unwrap().state = ActorState::AbandoningAuthentication;
    }

    /// Zipline: produce this actor's evidence for `offer` with
    /// [crate::auth_agent::produce_evidence] (OIDC via the AuthAgent and/or
    /// a bootstrap device blob), record the authority namespaces it proves
    /// for renewal, and return the encoded blob array. Replaces upstream
    /// #1410's bootstrap/BAS-over-AAA `authenticate`: BAS was removed in
    /// zipline#15 and the OIDC flow runs in ph-cli, not over AAA.
    async fn authenticate(
        &self,
        asm: &Arc<Assembly>,
        offer: &AuthenticationOffer,
    ) -> Result<String, AuthFailureReason> {
        let oidc_idps = asm
            .peer_table
            .get(self.id)
            .map(|peer| peer.link_state_machine.oidc_idps())
            .unwrap_or_default();
        // The node only sends a challenge when it supports bootstrap.
        let blobs = crate::auth_agent::produce_evidence(
            asm,
            self.id,
            offer.challenge.is_some(),
            offer.challenge.as_ref(),
            &oidc_idps,
            self.auth_agent(),
        )
        .await?;
        let blob = auth::encode_blobs(&blobs);
        mgmt::requests::validate_acquire_zpr_address_request(
            &asm.config.get().zpr_addr,
            blob.as_bytes(),
        )
        .map_err(|e| AuthFailureReason::LocalAuthError(format!("evidence cannot be sent: {e}")))?;
        self.renewal.set_namespaces(auth::blob_namespaces(&blobs));
        Ok(blob)
    }

    fn install_address(&self, asm: &Arc<Assembly>, addr: IpAddress) {
        let mut data = self.data.lock().unwrap();
        data.txn = None;
        // TODO(#938): TUN subprocess I/O blocks the LocalSet while holding ActorData.
        // Zipline: activation adds the host checks of zipline#83/#88/#101
        // around installing the address; every failure is fatal for this
        // connect request (zipline#157), so the rejection is latched.
        let owned = match crate::actor_activation::activate_granted_address(asm, self.id, addr) {
            Ok(owned) => owned,
            Err(reason) => {
                error!(target: LINK_STATE, "{}: cannot activate authorized actor address: {reason:?}", asm.formatted_link_id(self.id));
                asm.actor_rejected.store(true, Ordering::Release);
                data.state = ActorState::Rejected;
                data.reason = Some(format!("{reason:?}"));
                data.last_failure = Some(reason);
                drop(data);
                // The node has committed this registration. Link teardown reconciles it.
                if let Err(err) =
                    asm.process_link_state_event(self.id, crate::link_state::LinkEvent::Error)
                {
                    error!(target: LINK_STATE, "cannot close link after address installation failure: {err}");
                }
                return;
            }
        };
        data.installed_address = owned.then_some(addr);
        data.state = ActorState::Authorized;
        data.reason = None;
        data.last_failure = None;
        self.set_addresses(vec![addr]);
        asm.counters.management[ManagementCounterType::ActorAuthorizationSuccess].increment();
        info!(target: LINK_STATE, "{}: actor authorized as {addr}", asm.formatted_link_id(self.id));
    }

    pub fn receive_offer(&self, txn: TxnId, offer: AuthenticationOffer) -> HandleMgmtResult {
        self.deliver_reply(
            txn,
            ActorState::RequestingAuthentication,
            Reply::Offer(offer),
        )
    }

    pub fn receive_grant(
        &self,
        txn: TxnId,
        status: AuthenticationStatus,
        addresses: Vec<IpAddress>,
    ) -> HandleMgmtResult {
        if (status == AuthenticationStatus::Success && addresses.len() != 1)
            || (status != AuthenticationStatus::Success && !addresses.is_empty())
        {
            return Err(HandleMgmtError::BadStructure);
        }
        self.deliver_reply(
            txn,
            ActorState::AcquiringAddress,
            Reply::Grant(status, addresses),
        )
    }

    fn deliver_reply(&self, txn: TxnId, state: ActorState, reply: Reply) -> HandleMgmtResult {
        let mut data = self.data.lock().unwrap();
        if self.link_type != LinkType::AdapterToNode
            || data.state != state
            || data.txn.as_ref().map(TxnHandle::id) != Some(txn)
        {
            return Err(HandleMgmtError::UnknownTransaction);
        }
        data.reply
            .take()
            .ok_or(HandleMgmtError::UnknownTransaction)?
            .send(reply)
            .map_err(|_| HandleMgmtError::UnknownTransaction)
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
        if let Some(worker) = data.worker.take() {
            worker.abort();
        }
        data.reply = None;
        data.txn = None;
        data.remote_txn = None;
        data.challenge = None;
        data.state = ActorState::WaitingForLink;
        if let Some(addr) = data.installed_address.take() {
            // TODO(#938): TUN subprocess I/O blocks the LocalSet while holding ActorData.
            if let Err(err) = asm.tun_ctl.clear_address(addr.into(), ZPRNET_PREFIX_LEN) {
                error!(target: LINK_STATE, "{}: cannot clear actor address: {err}", asm.formatted_link_id(self.id));
            }
        }
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
        if self.link_type == LinkType::AdapterToNode {
            asm.elt.clear();
            asm.dlt.clear();
        }
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

fn retry_delay(backoff: Duration, random: u16) -> (Duration, Duration) {
    let backoff = backoff.min(config::ACTOR_AUTH_RETRY_MAX);
    let jitter = Duration::from_millis(u64::from(random) % 250);
    (
        (backoff + jitter).min(config::ACTOR_AUTH_RETRY_MAX),
        (backoff * 2).min(config::ACTOR_AUTH_RETRY_MAX),
    )
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
    use crate::mgmt::txn_mgr::TxnMgr;
    use crate::tun_ctl::TunCtl;
    use tokio::task::LocalSet;

    fn actor() -> Arc<ActorAuthorization> {
        Arc::new(ActorAuthorization::new(
            DOCK_LINK_ID,
            LinkType::AdapterToNode,
        ))
    }

    fn offer() -> AuthenticationOffer {
        AuthenticationOffer {
            status: AuthenticationStatus::Success,
            challenge: Some(auth::ZdpInitAuthenticationPayload::new(&[42; 32])),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transaction_spans_offer_and_delayed_grant() {
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let unrelated = mgr.open().await;
        let offer_rx = actor.prepare_reply(&txn, ActorState::RequestingAuthentication);
        assert!(actor.receive_offer(unrelated.id(), offer()).is_err());
        actor.receive_offer(txn.id(), offer()).unwrap();
        assert!(matches!(offer_rx.await.unwrap(), Reply::Offer(_)));
        let mut grant_rx = actor.prepare_reply(&txn, ActorState::AcquiringAddress);
        tokio::time::advance(Duration::from_secs(600)).await;
        assert!(matches!(
            grant_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(
            actor.data.lock().unwrap().state,
            ActorState::AcquiringAddress
        );
        assert_eq!(actor.data.lock().unwrap().txn.as_ref().unwrap(), &txn);
        let address: IpAddress = "::42".parse::<IpAddr>().unwrap().into();
        actor
            .receive_grant(txn.id(), AuthenticationStatus::Success, vec![address])
            .unwrap();
        assert!(matches!(
            grant_rx.await.unwrap(),
            Reply::Grant(AuthenticationStatus::Success, _)
        ));
    }

    #[tokio::test]
    async fn invalid_grant_does_not_consume_reply() {
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let rx = actor.prepare_reply(&txn, ActorState::AcquiringAddress);
        assert!(
            actor
                .receive_grant(txn.id(), AuthenticationStatus::Success, Vec::new())
                .is_err()
        );
        assert!(
            actor
                .receive_grant(
                    txn.id(),
                    AuthenticationStatus::Rejected,
                    vec![IpAddress::UNSPECIFIED],
                )
                .is_err()
        );
        actor
            .receive_grant(txn.id(), AuthenticationStatus::Retryable, Vec::new())
            .unwrap();
        assert!(matches!(
            rx.await.unwrap(),
            Reply::Grant(AuthenticationStatus::Retryable, _)
        ));
    }

    #[tokio::test]
    async fn teardown_releases_transaction_and_rejects_stale_reply() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let id = txn.id();
        let reply = actor.prepare_reply(&txn, ActorState::RequestingAuthentication);
        drop(txn);
        assert!(mgr.get(id).is_some());
        let generation = actor.data.lock().unwrap().generation;
        assert!(actor.link_down(&asm).is_empty());
        assert!(mgr.get(id).is_none());
        assert!(reply.await.is_err());
        assert!(actor.receive_offer(id, offer()).is_err());
        assert_ne!(actor.data.lock().unwrap().generation, generation);
    }

    #[tokio::test]
    async fn actor_transaction_remains_reserved_across_allocator_wraparound() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let id = txn.id();
        let _reply = actor.prepare_reply(&txn, ActorState::AcquiringAddress);
        drop(txn);
        for _ in 0..u16::MAX {
            let unrelated = mgr.try_open().unwrap();
            assert_ne!(unrelated.id(), id);
        }
        assert!(mgr.try_open().is_none());
        actor.link_down(&asm);
        assert_eq!(mgr.try_open().unwrap().id(), id);
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

    #[tokio::test]
    async fn rejection_latch_survives_link_reconnect() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = actor();
        asm.actor_rejected.store(true, Ordering::Release);
        actor.link_down(&asm);
        actor.link_ready(&asm);
        let data = actor.data.lock().unwrap();
        assert_eq!(data.state, ActorState::Rejected);
        assert!(data.worker.is_none());
        assert!(data.txn.is_none());
    }

    #[tokio::test]
    async fn reconnect_starts_worker_before_previous_cancellation_completes() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let actor = actor();
                let previous = tokio::task::spawn_local(std::future::pending::<()>());
                actor.data.lock().unwrap().worker = Some(previous.abort_handle());

                actor.link_down(&asm);
                assert!(!previous.is_finished());
                assert!(actor.data.lock().unwrap().worker.is_none());
                let generation = actor.data.lock().unwrap().generation;

                actor.link_ready(&asm);
                let data = actor.data.lock().unwrap();
                assert_ne!(data.generation, generation);
                assert!(
                    data.worker
                        .as_ref()
                        .is_some_and(|worker| !worker.is_finished())
                );
                assert!(!previous.is_finished());
            })
            .await;
    }

    #[test]
    fn retry_backoff_and_jitter_have_a_hard_cap() {
        let mut backoff = config::ACTOR_AUTH_RETRY_INITIAL;
        for _ in 0..20 {
            let (delay, next) = retry_delay(backoff, 249);
            assert!(delay >= backoff);
            assert!(delay <= config::ACTOR_AUTH_RETRY_MAX);
            assert_eq!(next, (backoff * 2).min(config::ACTOR_AUTH_RETRY_MAX));
            backoff = next;
        }
        assert_eq!(retry_delay(backoff, 249), (backoff, backoff));
    }

    #[derive(Default)]
    struct TunState {
        addresses: Vec<IpAddr>,
        additions: usize,
        removals: usize,
        /// With this set, `add_address` fails (EPERM), as on a host where
        /// the granted address cannot be set (zipline#157).
        fail_add: bool,
    }

    struct RecordingTun(Arc<Mutex<TunState>>);

    impl TunCtl for RecordingTun {
        fn name(&self) -> String {
            "tun-recording".to_string()
        }
        fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
            Ok(self.0.lock().unwrap().addresses.contains(&addr))
        }
        fn set_carrier(&self, _: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, addr: IpAddr, _: u8) -> std::io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.fail_add {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            state.additions += 1;
            state.addresses.push(addr);
            Ok(())
        }
        fn add_authentication_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            self.add_address(addr, prefix_len)
        }
        fn clear_address(&self, addr: IpAddr, _: u8) -> std::io::Result<()> {
            let mut state = self.0.lock().unwrap();
            state.removals += 1;
            state.addresses.retain(|a| *a != addr);
            Ok(())
        }
        /// Routes always install; this double only tracks addresses.
        fn add_route(&self, _: IpAddr, _: u8) -> std::io::Result<()> {
            Ok(())
        }
        /// No other interface ever owns the ZPR internal network here.
        fn route_owner_conflict(&self, _: IpAddr, _: u8) -> std::io::Result<Option<String>> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn teardown_preserves_external_addresses_and_removes_owned_addresses() {
        let address: IpAddr = "fd5a:5052::42".parse().unwrap();
        for external in [false, true] {
            let tun = Arc::new(Mutex::new(TunState {
                addresses: if external { vec![address] } else { Vec::new() },
                ..TunState::default()
            }));
            let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                tun_ctl: Some(Box::new(RecordingTun(tun.clone()))),
                ..TestAssemblyBuilder::new()
            }));
            let actor = actor();
            actor.install_address(&asm, address.into());
            assert!(actor.owns_address(&address.into()));
            assert_eq!(actor.data.lock().unwrap().state, ActorState::Authorized);
            assert_eq!(tun.lock().unwrap().additions, usize::from(!external));
            actor.link_down(&asm);
            assert!(!actor.owns_address(&address.into()));
            let tun = tun.lock().unwrap();
            assert_eq!(tun.addresses.contains(&address), external);
            assert_eq!(tun.removals, usize::from(!external));
        }
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

    /// The bootstrap key shipped with the tests, as `cn` "test.cn.zpr".
    fn test_bootstrap() -> auth::RsaBootstrapAuth {
        let mut keypath = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keypath.push("tests");
        keypath.push("data");
        keypath.push("rsa-key.pem");
        auth::RsaBootstrapAuth::new("test.cn.zpr", &keypath).unwrap()
    }

    /// A test assembly with the bootstrap key configured.
    fn assembly_with_bootstrap() -> Arc<Assembly> {
        let mut cfg = <config::Config as std::default::Default>::default();
        cfg.bootstrap = Some(test_bootstrap());
        Arc::new(create_assembly(TestAssemblyBuilder {
            config: Some(rcu::RcuBox::new(cfg)),
            ..TestAssemblyBuilder::new()
        }))
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

    /// An AuthAgent that answers every credential request with `id_token`.
    fn answering_agent(id_token: &'static str) -> AuthAgentHandle {
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::auth_agent::OidcCredentialRequest>();
        tokio::task::spawn_local(async move {
            while let Some(req) = rx.recv().await {
                let _ = req.reply.send(Ok(id_token.to_string()));
            }
        });
        tx
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

    /// `startLink` (ph-cli connect) is an explicit operator retry: it lifts
    /// #1410's actor rejection latch, clears the previous attempt's
    /// recorded failure (so `connect` never reports a stale reason against
    /// the new attempt), and leaves Rejected, so the next link-ready runs
    /// the actor again. Replaces zipline's "Start clears the previous auth
    /// failure": the automatic restart must NOT clear it, since the
    /// zipline#157 restart suppression keys on the recorded reason.
    #[tokio::test]
    async fn test_operator_retry_lifts_latch_and_clears_failure() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let actor = actor();
                actor.record_failure(AuthFailureReason::UserDeclined);
                asm.actor_rejected.store(true, Ordering::Release);
                actor.link_ready(&asm);
                assert_eq!(actor.state(), ActorState::Rejected);

                actor.operator_retry(&asm);
                assert!(!asm.actor_rejected.load(Ordering::Acquire));
                assert_eq!(actor.last_failure(), None);
                assert!(!format!("{actor}").contains("failure"));
                assert_eq!(actor.state(), ActorState::WaitingForLink);

                // The next link-ready starts a fresh attempt.
                actor.link_ready(&asm);
                assert!(actor.data.lock().unwrap().worker.is_some());
            })
            .await
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

    /// zipline#157: a local activation failure after a successful grant
    /// (here: EPERM setting the granted address) is fatal for this connect
    /// request. The actor records `ActivationFailed` for ph-cli, latches the
    /// rejection, holds no address, and the link is closed (the close path
    /// then suppresses the reconnect; see the link_state tests).
    /// The failure reason must be recorded BEFORE the worker waits for the
    /// Abandon ACK: if the link drops during that wait, link_down aborts the
    /// worker, and a reason recorded only afterwards would be lost — leaving
    /// the latched actor with no `Last auth failure:` for ph-cli `connect`
    /// to report (Codex review of the #1410 merge).
    #[tokio::test]
    async fn test_failure_reason_survives_link_loss_during_abandonment() {
        LocalSet::new()
            .run_until(async {
                let mut cfg = <config::Config as std::default::Default>::default();
                cfg.auto_connect = false;
                let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                    config: Some(rcu::RcuBox::new(cfg)),
                    ..TestAssemblyBuilder::new()
                }));
                let link_id = add_peer(&asm, LinkType::AdapterToNode);
                let actor = asm.peer_table.get(link_id).unwrap().actor_auth.clone();

                // The worker's state just before it awaits the Abandon ACK.
                actor.begin_abandonment(&asm, &AuthFailureReason::UserDeclined);
                assert_eq!(actor.state(), ActorState::AbandoningAuthentication);
                assert_eq!(actor.last_failure(), Some(AuthFailureReason::UserDeclined));
                assert!(asm.actor_rejected.load(Ordering::Acquire));

                // The link drops mid-abandonment: the reason and latch survive.
                actor.link_down(&asm).detach_all();
                assert_eq!(actor.last_failure(), Some(AuthFailureReason::UserDeclined));
                actor.link_ready(&asm);
                assert_eq!(actor.state(), ActorState::Rejected);
            })
            .await
    }

    #[tokio::test]
    async fn test_install_address_failure_is_recorded_latched_and_closes_link() {
        LocalSet::new()
            .run_until(async {
                let tun = Arc::new(Mutex::new(TunState {
                    fail_add: true,
                    ..TunState::default()
                }));
                let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                    tun_ctl: Some(Box::new(RecordingTun(tun.clone()))),
                    ..TestAssemblyBuilder::new()
                }));
                let link_id = add_peer(&asm, LinkType::AdapterToNode);
                let peer = asm.peer_table.get(link_id).unwrap();
                peer.link_state_machine.test_set_active();
                let actor = peer.actor_auth.clone();
                drop(peer);

                let granted: IpAddr = "fd5a:5052::42".parse().unwrap();
                actor.install_address(&asm, granted.into());

                match actor.last_failure() {
                    Some(AuthFailureReason::ActivationFailed(msg)) => assert!(
                        msg.contains("failed to set ZPR address"),
                        "the recorded failure must name the failed step: {msg}"
                    ),
                    other => panic!("expected ActivationFailed, got {other:?}"),
                }
                assert!(actor.addresses().is_empty());
                assert!(tun.lock().unwrap().addresses.is_empty());
                let state = asm
                    .peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .get_state();
                assert_eq!(state, crate::link_state::LinkState::Closing);
                // The close reset the actor for the next link session, but
                // the latch holds: that session goes straight to Rejected.
                assert!(asm.actor_rejected.load(Ordering::Acquire));
                actor.link_ready(&asm);
                assert_eq!(actor.state(), ActorState::Rejected);
            })
            .await
    }

    /// N2 (zipline#122), adapter side: evidence with an OIDC user leg and a
    /// bootstrap device leg records both namespaces, which renewal answers
    /// with one blob per namespace.
    #[tokio::test]
    async fn test_adapter_auth_success_records_namespace_set() {
        use crate::auth::AuthNamespace;
        LocalSet::new()
            .run_until(async {
                let asm = assembly_with_bootstrap();
                let link_id = add_peer(&asm, LinkType::AdapterToNode);
                let peer = asm.peer_table.get(link_id).unwrap();
                peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                peer.actor_auth.set_auth_agent(answering_agent("tok"));
                let actor = peer.actor_auth.clone();
                drop(peer);

                let blob = actor.authenticate(&asm, &offer()).await.unwrap();
                assert_eq!(auth::decode_blobs(&blob).unwrap().len(), 2);
                assert_eq!(
                    actor.renewal.namespaces(),
                    Some([AuthNamespace::Device, AuthNamespace::User].into()),
                    "SS + OIDC authentication must record both namespaces"
                );
            })
            .await
    }

    /// N2 (zipline#122), adapter side: the device-only bootstrap path (no
    /// OIDC IdP advertised) records {Device}.
    #[tokio::test]
    async fn test_adapter_bootstrap_only_auth_records_device_namespace() {
        use crate::auth::AuthNamespace;
        LocalSet::new()
            .run_until(async {
                let asm = assembly_with_bootstrap();
                let link_id = add_peer(&asm, LinkType::AdapterToNode);
                let actor = asm.peer_table.get(link_id).unwrap().actor_auth.clone();

                actor.authenticate(&asm, &offer()).await.unwrap();
                assert_eq!(
                    actor.renewal.namespaces(),
                    Some([AuthNamespace::Device].into()),
                    "bootstrap-only authentication must record the device namespace"
                );
            })
            .await
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
                let ss = test_bootstrap().authenticate_blob(&challenge).unwrap();
                let blob_str =
                    auth::encode_blobs(&[AuthBlob::SelfSigned(ss), oidc_blob(&challenge)]);

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
