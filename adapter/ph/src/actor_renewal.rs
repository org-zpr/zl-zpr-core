//! Zipline: renewal of an authorized actor's authentication (zipline#45,
//! zipline#66, zipline#122).
//!
//! Upstream #1410 leaves "authorization renewal/expiry enforcement" as
//! follow-on work. Zipline implements it on top of #1410's
//! [crate::actor_auth::ActorAuthorization]: the per-actor state lives in a
//! [RenewalState] owned by the actor, and the logic lives here.
//!
//! Node side:
//! - The visa service reports when the actor's authentication expires
//!   ([RenewalState::set_auth_expires]). Each successful keep-alive on the
//!   link is a renewal tick ([maybe_renew]); once the renewal deadline
//!   passes, the node asks the adapter for a renewed credential with a ZDP
//!   RenewAuthenticationRequest carrying a fresh challenge
//!   ([send_credential_request]), verifies the answer
//!   ([receive_renew_response]) and submits it to the visa service with
//!   `reauthorize`.
//! - The visa service can also ask for a re-auth at once, e.g. after a
//!   policy change ([request_renewal_now]).
//!
//! Adapter side: [receive_renew_request] answers with one blob per
//! authority namespace the actor authenticated with — a self-signed device
//! leg and/or an OIDC user leg obtained NON-interactively from the AuthAgent.
//!
//! A failed renewal never tears the link down; the existing expiry is left
//! to the visa service's sweep.

use crate::auth::{self, AuthBlob};
use crate::auth_agent::{self, AuthFailureReason};
use crate::link_state::{LinkState, LinkType};
use crate::mgmt;
use crate::mgmt::handlers::{HandleMgmtError, HandleMgmtResult};
use crate::prelude::*;
use crate::zdp::AuthenticationStatus;

use base64::prelude::*;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// What [request_renewal_now] did with an on-demand renewal request
/// (Codex review, zl-zpr-core#45): the VSS dispatcher's ack counts a
/// re-auth as underway only when an attempt was actually started
/// (`Accepted`) or is already outstanding (`Coalesced`); an `Ignored`
/// request — wrong link type, or a link that left `Active` during shutdown
/// while still holding its actor address — started nothing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RenewalStart {
    /// A new renewal attempt was started (RenewAuthenticationRequest sent).
    Accepted,
    /// An attempt is already in flight; this request coalesced onto it.
    Coalesced,
    /// The state guard refused: no attempt is underway for this request.
    Ignored,
}

/// The identity an actor originally authenticated with, stashed at auth
/// time so silent renewal (zipline#45) can re-prove against the SAME
/// issuer. On renewal failure the adapter/user reconnects and re-picks from
/// the then-advertised providers, so this is never updated in place.
#[derive(Clone, Debug)]
pub struct RenewalIdentity {
    /// The advertised IdP (issuer, client config) the original OIDC blob
    /// named. Resolved from the node's auth-services list at auth time.
    pub idp: auth::OidcIdpInfo,
    /// The challenge-derived OIDC nonce ([auth::oidc_nonce_for_challenge])
    /// bound into the original credential. Reused verbatim on the renewal
    /// blob because the VS ignores the nonce on the reauthorize path and
    /// there is no empty-string special case on the wire. It cannot be
    /// checked against the renewed id_token in any case: OIDC Core §12.2
    /// says a refresh-grant id_token SHOULD NOT carry a nonce claim, and
    /// MUST match the original only if it does — absent or original, never
    /// fresh.
    pub nonce: String,
}

/// The effective renewal lead for a granted authentication lifetime:
/// the configured lead clamped to half the lifetime, so short
/// `expiration_seconds` values still renew ahead of expiry by a workable
/// margin instead of the lead swallowing the whole window (zipline#45).
pub fn renewal_lead(configured: Duration, granted_lifetime: Duration) -> Duration {
    configured.min(granted_lifetime / 2)
}

/// The instant renewal becomes due for an authentication granted at
/// `granted_at` and expiring at `auth_expires`:
/// `auth_expires - renewal_lead(configured, lifetime)`.
/// An already-past (or zero-length) expiry yields a deadline that is never
/// in the future, so renewal is due immediately.
pub fn renewal_deadline(
    granted_at: SystemTime,
    auth_expires: SystemTime,
    configured_lead: Duration,
) -> SystemTime {
    let lifetime = auth_expires
        .duration_since(granted_at)
        .unwrap_or(Duration::ZERO);
    let lead = renewal_lead(configured_lead, lifetime);
    auth_expires.checked_sub(lead).unwrap_or(auth_expires)
}

/// Floor for one silent-renewal attempt's wait on the AuthAgent: even with
/// (nearly) no window left, give a healthy agent a moment to answer from its
/// refresh-token cache instead of a zero-length wait.
pub const RENEWAL_ATTEMPT_TIMEOUT_FLOOR: Duration = Duration::from_secs(5);

/// How long ONE silent-renewal attempt may wait: half the time remaining
/// before `auth_expires`, clamped between [RENEWAL_ATTEMPT_TIMEOUT_FLOOR]
/// and the agent bridge's own per-call bound
/// ([config::OIDC_USER_INTERACTION_TIMEOUT]). Bounding by the remaining
/// window means a hung request cannot pin `in_flight` past the point where
/// a retry could still succeed against the current authentication — half,
/// so at least one full retry fits in the window left (PR #14 review).
pub fn renewal_attempt_timeout(now: SystemTime, auth_expires: SystemTime) -> Duration {
    let remaining = auth_expires.duration_since(now).unwrap_or(Duration::ZERO);
    (remaining / 2).clamp(
        RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        config::OIDC_USER_INTERACTION_TIMEOUT,
    )
}

/// Mutable renewal bookkeeping, guarded by [RenewalState::data].
#[derive(Default)]
struct RenewalData {
    /// Nodes only: when the docked actor's authentication expires, from the
    /// VS `Connection` response. None until authorized.
    auth_expires: Option<SystemTime>,
    /// Nodes only: the precomputed instant renewal becomes due; see
    /// [renewal_deadline].
    deadline: Option<SystemTime>,
    /// Nodes only: the issuer/nonce identity the actor originally
    /// authenticated with. None on device-only actors.
    identity: Option<RenewalIdentity>,
    /// The authority namespace set the actor authenticated with
    /// (zipline#122), recorded on both sides of the hop. The node requires a
    /// renewal reply's set to EQUAL it; the adapter builds its renewal blob
    /// array from it. None until authenticated.
    namespaces: Option<BTreeSet<auth::AuthNamespace>>,
    /// Nodes only: a renewal attempt is underway; suppresses further
    /// attempts until it completes (one attempt per due tick at most).
    in_flight: bool,
    /// Nodes only: the challenge minted for the in-flight ZDP renewal
    /// request. The response must echo exactly these bytes; taken on
    /// completion or attempt timeout.
    challenge: Option<[u8; 48]>,
    /// Adapters only: the task awaiting the AuthAgent's answer to the
    /// current renewal request. A new request supersedes it: the node only
    /// retries after abandoning its previous attempt, so the old task is
    /// aborted — dropping its reply receiver, which the agent bridge
    /// observes and uses to cancel the in-flight RPC (PR #17 review).
    adapter_task: Option<tokio::task::AbortHandle>,
    /// Nodes only: the one-shot "renewal due but nothing can renew it"
    /// warning has fired for the current authentication window.
    no_agent_warned: bool,
}

/// Per-actor renewal state, owned by [crate::actor_auth::ActorAuthorization].
pub struct RenewalState {
    /// Process-unique instance id: distinguishes this actor from a later one
    /// that reuses the same peer-table slot after teardown. Asynchronous
    /// completions carry the uid they were spawned under and are discarded
    /// when the looked-up actor's uid differs (PR #14 review).
    uid: u64,
    data: Mutex<RenewalData>,
}

impl RenewalState {
    pub fn new() -> Self {
        static NEXT_UID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            uid: NEXT_UID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            data: Mutex::new(RenewalData::default()),
        }
    }

    /// Record the actor's authentication expiry from a VS `Connection`
    /// response and precompute the renewal deadline from the configured
    /// lead. `granted_at` anchors the lifetime the half-lifetime clamp is
    /// computed against (normally "now"). Resets the per-window bookkeeping
    /// so a fresh grant warns and retries anew.
    pub fn set_auth_expires(
        &self,
        granted_at: SystemTime,
        auth_expires: SystemTime,
        configured_lead: Duration,
    ) {
        let deadline = renewal_deadline(granted_at, auth_expires, configured_lead);
        let mut data = self.data.lock().unwrap();
        data.auth_expires = Some(auth_expires);
        data.deadline = Some(deadline);
        data.in_flight = false;
        data.no_agent_warned = false;
    }

    /// The actor's authentication expiry, if the VS has reported one.
    #[cfg(test)]
    pub fn auth_expires(&self) -> Option<SystemTime> {
        self.data.lock().unwrap().auth_expires
    }

    /// Stash the issuer/nonce identity the actor authenticated with.
    pub fn set_identity(&self, identity: RenewalIdentity) {
        self.data.lock().unwrap().identity = Some(identity);
    }

    /// The stored renewal identity, if the actor authenticated via OIDC.
    #[cfg(test)]
    pub fn identity(&self) -> Option<RenewalIdentity> {
        self.data.lock().unwrap().identity.clone()
    }

    /// Record the authority namespace set the actor authenticated with.
    pub fn set_namespaces(&self, namespaces: BTreeSet<auth::AuthNamespace>) {
        self.data.lock().unwrap().namespaces = Some(namespaces);
    }

    /// The recorded authority namespace set, if the actor has authenticated.
    pub fn namespaces(&self) -> Option<BTreeSet<auth::AuthNamespace>> {
        self.data.lock().unwrap().namespaces.clone()
    }

    /// Forget everything about the current actor session. Called when the
    /// link goes down: on an adapter the actor object outlives the link, and
    /// a new session must not inherit the old one's namespaces or tasks.
    pub fn reset(&self) {
        let mut data = self.data.lock().unwrap();
        if let Some(task) = data.adapter_task.take() {
            task.abort();
        }
        *data = RenewalData::default();
    }

    /// Stash the challenge minted for an in-flight renewal request.
    fn stash_challenge(&self, challenge: [u8; 48]) {
        self.data.lock().unwrap().challenge = Some(challenge);
    }

    /// Take the stashed challenge only if it still equals `challenge`, so a
    /// stale timeout or response cannot clobber a LATER attempt's challenge.
    /// True means this attempt was the in-flight one and has been consumed.
    fn take_challenge_if(&self, challenge: &[u8; 48]) -> bool {
        let mut data = self.data.lock().unwrap();
        if data.challenge.as_ref() == Some(challenge) {
            data.challenge = None;
            return true;
        }
        false
    }

    /// Clear the in-flight flag after a failed attempt so the next due tick
    /// may retry.
    fn clear_in_flight(&self) {
        self.data.lock().unwrap().in_flight = false;
    }

    #[cfg(test)]
    pub fn test_challenge(&self) -> Option<[u8; 48]> {
        self.data.lock().unwrap().challenge
    }

    #[cfg(test)]
    pub fn test_no_agent_warned(&self) -> bool {
        self.data.lock().unwrap().no_agent_warned
    }

    #[cfg(test)]
    pub fn test_in_flight(&self) -> bool {
        self.data.lock().unwrap().in_flight
    }
}

impl std::fmt::Display for RenewalState {
    /// The renewal picture for showLink (zipline#45); prints nothing until
    /// the visa service has reported an expiry.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = self.data.lock().unwrap();
        let Some(expires) = data.auth_expires else {
            return Ok(());
        };
        match expires.duration_since(SystemTime::now()) {
            Ok(remaining) => write!(f, "  Auth expires: in {remaining:?}")?,
            Err(_) => write!(f, "  Auth expires: EXPIRED")?,
        }
        if data.in_flight {
            write!(f, " (renewal in progress)")?;
        }
        writeln!(f)
    }
}

/// A renewal attempt ended in failure: warn, record the reason on the actor
/// for showLink, and clear the in-flight flag so the next due tick may retry.
fn finish_failure(asm: &Arc<Assembly>, link_id: LinkId, reason: AuthFailureReason) {
    warn!(target: LINK_STATE, "{}: silent re-authentication failed: {reason:?}", asm.formatted_link_id(link_id));
    if let Some(peer) = asm.peer_table.get(link_id) {
        peer.actor_auth.renewal.clear_in_flight();
        peer.actor_auth.record_failure(reason);
    }
}

/// Look up the actor for `link_id`, but only if it is still the instance
/// identified by `uid` (the peer-table slot may have been reused).
fn current_peer(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    uid: u64,
) -> Option<crate::peer_table::PeerTableEntryGuard<'_>> {
    asm.peer_table
        .get(link_id)
        .filter(|peer| peer.actor_auth.renewal.uid == uid)
}

/// One renewal tick (zipline#45), piggybacked on each successful keep-alive
/// response. No-op until the renewal deadline passes; then, per tick:
/// - nothing able to renew (no OIDC identity stashed, or no AuthAgent on a
///   non-node link): warn ONCE per authentication window and record
///   [AuthFailureReason::NoAgent]; no repeated warnings, no attempts.
/// - on a node link with no local agent: ask the adapter over ZDP
///   ([send_credential_request]); the AuthAgent lives on the adapter side.
/// - with a local agent: at most one in-flight attempt at a time — a
///   non-interactive credential request bound to the ORIGINAL issuer and
///   nonce, then `vsconn.reauthorize`. Success refreshes the expiry; any
///   failure warns, records the reason, and lets the next due tick retry.
pub fn maybe_renew(asm: &Arc<Assembly>, link_id: LinkId) {
    let Some(peer) = asm.peer_table.get(link_id) else {
        return;
    };
    let actor = &peer.actor_auth;
    let link_type = peer.link_state_machine.get_link_type();
    let agent = actor.auth_agent();

    let (identity, auth_expires) = {
        let mut data = actor.renewal.data.lock().unwrap();
        let Some(deadline) = data.deadline else {
            return; // never authorized via the VS: nothing to renew
        };
        if SystemTime::now() < deadline || data.in_flight {
            return;
        }
        let nothing_can_renew =
            data.identity.is_none() || (agent.is_none() && link_type != LinkType::NodeToAdapter);
        if nothing_can_renew {
            if !data.no_agent_warned {
                data.no_agent_warned = true;
                drop(data);
                actor.record_failure(AuthFailureReason::NoAgent);
                warn!(target: LINK_STATE,
                    "{}: authentication expires soon but no AuthAgent is available to renew it; the actor must reconnect to re-authenticate",
                    asm.formatted_link_id(link_id));
            }
            return;
        }
        data.in_flight = true;
        // A renewal deadline implies set_auth_expires ran: present.
        let auth_expires = data.auth_expires.unwrap();
        if agent.is_none() {
            // R8 (zipline#66): the AuthAgent registers on the ADAPTER's side
            // of the hop, so ask the adapter for a renewed credential.
            drop(data);
            drop(peer);
            send_credential_request(asm, link_id, auth_expires);
            return;
        }
        (data.identity.clone().unwrap(), auth_expires)
    };
    let agent = agent.expect("checked above");
    let uid = actor.renewal.uid;
    drop(peer);

    // Bound the wait by the remaining authentication window so a hung
    // agent cannot pin in_flight past expiry (PR #14 review).
    let attempt_timeout = renewal_attempt_timeout(SystemTime::now(), auth_expires);
    let task_asm = asm.clone();
    tokio::task::spawn_local(async move {
        // The renewal reuses the original nonce (see RenewalIdentity), so
        // ask for a token and build the VS blob directly rather than through
        // a challenge-bound ZdpOidcBlob.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = auth_agent::OidcCredentialRequest {
            idp: identity.idp.clone(),
            nonce: identity.nonce.clone(),
            interactive: false, // renewal must never open a browser
            reply: reply_tx,
        };
        if agent.send(request).is_err() {
            // The bridge task is gone (its admin connection died): clear the
            // stale registration (C2).
            if let Some(peer) = current_peer(&task_asm, link_id, uid) {
                peer.actor_auth.clear_auth_agent_if(&agent);
                drop(peer);
                finish_failure(
                    &task_asm,
                    link_id,
                    AuthFailureReason::AgentError("AuthAgent bridge is gone".to_string()),
                );
            }
            return;
        }
        let id_token = match tokio::time::timeout(attempt_timeout, reply_rx).await {
            Ok(Ok(Ok(id_token))) => id_token,
            Ok(Ok(Err(reason))) => {
                if current_peer(&task_asm, link_id, uid).is_some() {
                    finish_failure(&task_asm, link_id, reason);
                }
                return;
            }
            Ok(Err(_)) | Err(_) => {
                if current_peer(&task_asm, link_id, uid).is_some() {
                    finish_failure(
                        &task_asm,
                        link_id,
                        AuthFailureReason::AgentError(format!(
                            "renewal attempt failed or timed out after {attempt_timeout:?}"
                        )),
                    );
                }
                return;
            }
        };
        let blobs = vec![zpr::vsapi_types::AuthBlob::Oidc(
            zpr::vsapi_types::OidcBlob {
                issuer: identity.idp.issuer,
                id_token,
                nonce: identity.nonce,
            },
        )];
        submit_reauthorize(&task_asm, link_id, uid, blobs).await;
    });
}

/// Submit renewed credential blob(s) to the VS in ONE `reauthorize` call
/// (zipline#122, K3/K4) and settle the attempt: refreshed expiry (clearing
/// in-flight) on success, recorded failure (clearing in-flight) otherwise.
async fn submit_reauthorize(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    uid: u64,
    blobs: Vec<zpr::vsapi_types::AuthBlob>,
) {
    let actor_addr = {
        let Some(peer) = current_peer(asm, link_id, uid) else {
            return; // link torn down, or slot reused by a new link
        };
        peer.actor_auth.addresses().first().cloned()
    };
    let Some(vsconn) = asm.vsconn.as_ref() else {
        finish_failure(
            asm,
            link_id,
            AuthFailureReason::AgentError("no visa service connection for renewal".to_string()),
        );
        return;
    };
    let Some(actor_addr) = actor_addr else {
        finish_failure(
            asm,
            link_id,
            AuthFailureReason::AgentError("no actor address to renew".to_string()),
        );
        return;
    };

    let req = zpr::vsapi_types::ReauthRequest {
        zpr_addr: std::net::IpAddr::from(actor_addr),
        blobs,
    };
    let result = vsconn.reauthorize(req).await;
    let Some(peer) = current_peer(asm, link_id, uid) else {
        return;
    };
    match result {
        Ok(conn) => {
            let expires = std::time::UNIX_EPOCH + Duration::from_secs(conn.auth_expires);
            info!(target: LINK_STATE, "{}: silently re-authenticated; new expiry {expires:?}", asm.formatted_link_id(link_id));
            // Restarts the renewal window and clears the in-flight/warned
            // bookkeeping.
            peer.actor_auth.renewal.set_auth_expires(
                SystemTime::now(),
                expires,
                asm.config.get().auth_renewal_lead,
            );
        }
        Err(e) => {
            drop(peer);
            finish_failure(
                asm,
                link_id,
                AuthFailureReason::VisaServiceRejected(e.to_string()),
            );
        }
    }
}

/// N2 (zipline#122), node side: start an on-demand credential renewal
/// toward the docked adapter NOW, regardless of any deadline — the visa
/// service asked for a re-auth under a new policy, which is orthogonal to
/// expiry-driven renewal. Requires an Active [LinkType::NodeToAdapter]
/// link; coalesces onto an in-flight attempt
/// ([RenewalStart::Coalesced]) and otherwise sends the request exactly as
/// the deadline path does. The VSS dispatcher
/// (`vss_worker::process_request_authentication`) counts only
/// [RenewalStart::Accepted] / [RenewalStart::Coalesced] in its ack.
pub fn request_renewal_now(asm: &Arc<Assembly>, link_id: LinkId) -> RenewalStart {
    let Some(peer) = asm.peer_table.get(link_id) else {
        return RenewalStart::Ignored;
    };
    if peer.link_state_machine.get_link_type() != LinkType::NodeToAdapter {
        warn!(target: LINK_STATE, "{}: on-demand renewal requested on a non-node link; ignoring", asm.formatted_link_id(link_id));
        return RenewalStart::Ignored;
    }
    if peer.link_state_machine.get_state() != LinkState::Active {
        warn!(target: LINK_STATE, "{}: on-demand renewal requested on a non-Active link; ignoring", asm.formatted_link_id(link_id));
        return RenewalStart::Ignored;
    }

    let auth_expires = {
        let mut data = peer.actor_auth.renewal.data.lock().unwrap();
        if data.in_flight {
            debug!(target: LINK_STATE, "{}: on-demand renewal coalesced onto the in-flight attempt", asm.formatted_link_id(link_id));
            return RenewalStart::Coalesced;
        }
        data.in_flight = true;
        // Bound the attempt by the remaining authentication window when one
        // is known. With non-expiring bootstrap auth there may be none: fall
        // back to a window that yields the bridge's own per-call bound.
        data.auth_expires
            .unwrap_or_else(|| SystemTime::now() + 2 * config::OIDC_USER_INTERACTION_TIMEOUT)
    };
    drop(peer);
    send_credential_request(asm, link_id, auth_expires);
    RenewalStart::Accepted
}

/// R8 (zipline#66), node side: ask the adapter for a renewed credential
/// over ZDP. Mints a fresh challenge exactly as InitAuthentication does (so
/// [auth::oidc_nonce_for_challenge] applies unchanged), stashes it for the
/// response to be verified against, sends a RenewAuthenticationRequest, and
/// bounds the wait by [renewal_attempt_timeout] so a lost response cannot
/// pin `in_flight` past the point a retry could still succeed.
///
/// The caller has already set `in_flight`.
fn send_credential_request(asm: &Arc<Assembly>, link_id: LinkId, auth_expires: SystemTime) {
    let Some(peer) = asm.peer_table.get(link_id) else {
        return;
    };
    let payload = auth::ZdpInitAuthenticationPayload::new(&peer.auth_key);
    let challenge = payload.challenge_bytes();
    peer.actor_auth.renewal.stash_challenge(challenge);
    let uid = peer.actor_auth.renewal.uid;
    drop(peer);

    mgmt::requests::send_renew_authentication_request(asm, link_id, payload).enqueue();

    // If the response never arrives, fail this attempt so the next due tick
    // can retry while auth is still valid. Guarded by the challenge bytes (a
    // completed or newer attempt has taken or replaced them) and the uid.
    let task_asm = asm.clone();
    let attempt_timeout = renewal_attempt_timeout(SystemTime::now(), auth_expires);
    tokio::task::spawn_local(async move {
        tokio::time::sleep(attempt_timeout).await;
        let Some(peer) = current_peer(&task_asm, link_id, uid) else {
            return;
        };
        if peer.actor_auth.renewal.take_challenge_if(&challenge) {
            drop(peer);
            finish_failure(
                &task_asm,
                link_id,
                AuthFailureReason::AgentError(format!(
                    "renewal credential request timed out after {attempt_timeout:?}"
                )),
            );
        }
    });
}

/// R8 (zipline#66) / N2 (zipline#122), adapter side: the node asked for a
/// renewed credential. Answer with one blob per namespace the actor
/// authenticated with (K4): the SS (device) leg signs the fresh challenge
/// with the bootstrap key synchronously; the OIDC (user) leg goes through
/// the registered AuthAgent with `interactive: false`. If any required leg
/// is unproducible — no bootstrap key, no agent, no advertised IdP, agent
/// failure — the answer is [AuthenticationStatus::Retryable] with no blob
/// rather than a partial set, so the node records why renewal is impossible.
pub fn receive_renew_request(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    payload: auth::ZdpInitAuthenticationPayload,
) -> HandleMgmtResult {
    let peer = asm
        .peer_table
        .get(link_id)
        .ok_or(HandleMgmtError::LinkClosed)?;
    // Renewal runs on an Active link with an authorized actor.
    if peer.link_state_machine.get_link_type() != LinkType::AdapterToNode
        || peer.link_state_machine.get_state() != LinkState::Active
    {
        return Err(HandleMgmtError::MessageNotPermitted);
    }
    let actor = peer.actor_auth.clone();
    let idp = peer.link_state_machine.oidc_idps().into_iter().next();
    drop(peer);

    // Assembled before any answer so every response — success or failure —
    // echoes it for correlation on the node side (PR #17 review).
    let challenge = payload.challenge_bytes();
    let refuse = |why: &str| {
        info!(target: LINK_STATE, "{}: {why}; answering renewal as unavailable", asm.formatted_link_id(link_id));
        mgmt::requests::send_renew_authentication_response(
            asm,
            link_id,
            AuthenticationStatus::Retryable,
            &challenge,
            &[],
        )
        .enqueue();
        Ok(())
    };

    // A new request supersedes any still-outstanding agent call: the node
    // only retries after abandoning its previous attempt.
    if let Some(task) = actor.renewal.data.lock().unwrap().adapter_task.take() {
        debug!(target: LINK_STATE, "{}: a new renewal request supersedes the outstanding one; cancelling it", asm.formatted_link_id(link_id));
        task.abort();
    }

    // Which legs to produce: one blob per namespace the actor authenticated
    // with. An actor with no recorded set is treated as user-only, the
    // pre-zipline#122 OIDC behavior.
    let namespaces = actor
        .renewal
        .namespaces()
        .unwrap_or_else(|| [auth::AuthNamespace::User].into());
    let need_oidc = namespaces.contains(&auth::AuthNamespace::User);

    let ss_blob = if namespaces.contains(&auth::AuthNamespace::Device) {
        let signed = asm
            .config
            .get()
            .bootstrap
            .as_ref()
            .map(|bs| bs.authenticate_blob(&payload));
        match signed {
            Some(Ok(blob)) => Some(AuthBlob::SelfSigned(blob)),
            Some(Err(e)) => {
                warn!(target: LINK_STATE, "{}: failed to sign the renewal challenge: {e:?}", asm.formatted_link_id(link_id));
                return refuse("device leg required but the bootstrap key cannot sign it");
            }
            None => return refuse("device leg required but no bootstrap key is configured"),
        }
    } else {
        None
    };

    if !need_oidc {
        // Device-only: every leg is in hand, answer synchronously.
        let blob = auth::encode_blobs(&[ss_blob.expect("device namespace holds here")]);
        mgmt::requests::send_renew_authentication_response(
            asm,
            link_id,
            AuthenticationStatus::Success,
            &challenge,
            blob.as_bytes(),
        )
        .enqueue();
        return Ok(());
    }

    let (Some(agent), Some(idp)) = (actor.auth_agent(), idp) else {
        return refuse("no AuthAgent or advertised IdP can produce the user leg");
    };

    let task_asm = asm.clone();
    let task_actor = actor.clone();
    let task = tokio::task::spawn_local(async move {
        // The bridge bounds each call by OIDC_USER_INTERACTION_TIMEOUT and
        // answers or drops the reply either way; this bound is a backstop.
        let outcome = auth_agent::request_oidc_blob(
            &agent,
            idp,
            &challenge,
            false, // renewal must never open a browser
            config::OIDC_USER_INTERACTION_TIMEOUT,
        )
        .await;
        let (status, blob) = match outcome {
            Ok(oidc_blob) => {
                // The SS leg (when required) rides alongside the OIDC leg,
                // both bound to the same echoed challenge (K4).
                let mut blobs: Vec<AuthBlob> = ss_blob.into_iter().collect();
                blobs.push(AuthBlob::Oidc(oidc_blob));
                (AuthenticationStatus::Success, auth::encode_blobs(&blobs))
            }
            Err(reason) => {
                if reason == AuthFailureReason::NoAgent {
                    // The bridge task is gone: clear the stale slot (C2).
                    task_actor.clear_auth_agent_if(&agent);
                }
                warn!(target: LINK_STATE, "{}: AuthAgent could not renew the credential: {reason:?}", task_asm.formatted_link_id(link_id));
                (AuthenticationStatus::Retryable, String::new())
            }
        };
        mgmt::requests::send_renew_authentication_response(
            &task_asm,
            link_id,
            status,
            &challenge,
            blob.as_bytes(),
        )
        .enqueue();
    });
    // Remember the wait task so the NEXT request can cancel it. Aborting an
    // already-finished task is a no-op, so a stale handle here is harmless.
    actor.renewal.data.lock().unwrap().adapter_task = Some(task.abort_handle());
    Ok(())
}

/// R8 (zipline#66) / N2 (zipline#122), node side: the adapter answered the
/// renewal request. Verify the returned blob array against the stashed
/// challenge — the namespace set must EQUAL the set the actor
/// authenticated with, with one blob per namespace, and every blob must
/// HMAC-verify with this link's auth key and be bound byte-for-byte to the
/// minted challenge — then send ALL verified legs in one `reauthorize`
/// (never `authorizeConnect`). The link stays Active throughout.
pub fn receive_renew_response(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    echoed_challenge: [u8; 48],
    result: Result<String, AuthenticationStatus>,
) -> HandleMgmtResult {
    let peer = asm
        .peer_table
        .get(link_id)
        .ok_or(HandleMgmtError::LinkClosed)?;
    if peer.link_state_machine.get_link_type() != LinkType::NodeToAdapter
        || peer.link_state_machine.get_state() != LinkState::Active
    {
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    // Correlate before consuming: only a response to the CURRENT attempt may
    // take the stash. A delayed answer to an abandoned attempt must not
    // consume a newer attempt's challenge and be recorded as its failure
    // (PR #17 review).
    if !peer.actor_auth.renewal.take_challenge_if(&echoed_challenge) {
        debug!(target: LINK_STATE, "{}: discarding renewal response that answers no outstanding request", asm.formatted_link_id(link_id));
        return Ok(());
    }
    let challenge = echoed_challenge;
    let uid = peer.actor_auth.renewal.uid;
    let key = peer.auth_key;
    let expected = peer
        .actor_auth
        .renewal
        .namespaces()
        .unwrap_or_else(|| [auth::AuthNamespace::User].into());
    let expected_issuer = peer
        .actor_auth
        .renewal
        .data
        .lock()
        .unwrap()
        .identity
        .as_ref()
        .map(|identity| identity.idp.issuer.clone());
    drop(peer);

    let fail = |why: String| {
        finish_failure(asm, link_id, AuthFailureReason::AgentError(why));
        Ok(())
    };

    let blob_str = match result {
        Ok(blob_str) => blob_str,
        Err(AuthenticationStatus::Retryable) => {
            finish_failure(asm, link_id, AuthFailureReason::AuthUnavailable);
            return Ok(());
        }
        Err(status) => return fail(format!("adapter answered renewal with {status:?}")),
    };
    let blobs = match auth::decode_blobs(&blob_str) {
        Ok(blobs) => blobs,
        Err(e) => return fail(format!("invalid renewal blob: {e}")),
    };

    // ONE blob per namespace (Codex review, zl-zpr-core#45 P1): the set
    // comparison alone cannot see a duplicate, and the issuer pin below
    // examines only one OIDC blob.
    let got = auth::blob_namespaces(&blobs);
    if blobs.len() != got.len() {
        return fail(format!(
            "renewal blob array carries a duplicate namespace ({} blobs, {} namespaces)",
            blobs.len(),
            got.len()
        ));
    }
    if got != expected {
        return fail(format!(
            "renewal blob namespace set {got:?} does not match the authenticated set {expected:?}"
        ));
    }

    // Per-blob checks: HMAC/age, plus byte-for-byte equality with THIS
    // attempt's challenge. The SS leg is held to the OIDC freshness window,
    // not MAX_BLOB_AGE_SECONDS (zl-zpr-core#45 P2): on a combined
    // Device+User renewal both legs share a challenge minted before the
    // agent's permitted wait. Replay is prevented by the byte equality.
    for blob in &blobs {
        let (verified, blob_challenge) = match blob {
            AuthBlob::SelfSigned(ss) => (
                ss.verify_blob_challenge(&key, auth::MAX_OIDC_BLOB_AGE_SECONDS)
                    .is_ok(),
                &ss.challenge,
            ),
            AuthBlob::Oidc(oidc) => (oidc.verify_challenge(&key).is_ok(), &oidc.challenge),
        };
        if !verified {
            return fail("renewal blob challenge failed verification".to_string());
        }
        if BASE64_STANDARD.decode(blob_challenge).unwrap_or_default() != challenge {
            return fail("renewal blob is bound to a different challenge".to_string());
        }
    }

    // A renewed OIDC leg must come from the issuer the actor originally
    // authenticated with (same guard as stash_identity).
    if let Some(oidc) = blobs.iter().find_map(|b| match b {
        AuthBlob::Oidc(oidc) => Some(oidc),
        _ => None,
    }) {
        if expected_issuer.as_deref() != Some(oidc.issuer.as_str()) {
            return fail(format!(
                "renewed credential from unexpected issuer {}",
                oidc.issuer
            ));
        }
    }

    let vst_blobs = match crate::visa_mgmt::vsapi_blobs(&blobs) {
        Ok(vst_blobs) => vst_blobs,
        Err(e) => return fail(e.to_string()),
    };
    let task_asm = asm.clone();
    tokio::task::spawn_local(async move {
        submit_reauthorize(&task_asm, link_id, uid, vst_blobs).await;
    });
    Ok(())
}

/// Node side: store the OIDC identity (the issuer's advertised client
/// config plus the challenge-derived nonce) an actor is authenticating
/// with, so silent renewal re-proves against the SAME issuer. A blob naming
/// an issuer the VS no longer advertises just means renewal will not be
/// possible. The caller has verified the blob's challenge.
pub fn stash_identity(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    renewal: &RenewalState,
    oidc_blob: &auth::ZdpOidcBlob,
) {
    let Some(idp) = auth_agent::advertised_oidc_idps(asm, link_id)
        .into_iter()
        .find(|idp| idp.issuer == oidc_blob.issuer)
    else {
        warn!(target: LINK_STATE,
            "{}: OIDC issuer {} is not in the advertised auth services; silent renewal will not be available",
            asm.formatted_link_id(link_id), oidc_blob.issuer);
        return;
    };
    let challenge: [u8; 48] = BASE64_STANDARD
        .decode(&oidc_blob.challenge)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0u8; 48]);
    let nonce = auth::oidc_nonce_for_challenge(&challenge);
    renewal.set_identity(RenewalIdentity { idp, nonce });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::peer_table;
    use crate::zdp::ZdpPacketType;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::task::LocalSet;
    use zpr_utils::net_defs;

    /// The observable management egress queue of a test assembly.
    type Egress = crate::packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>;

    /// A test assembly whose management substrate egress is observable (the
    /// returned receiver sees every packet the code under test sends), with
    /// `config` if given.
    fn assembly_with_observable_egress(config: Option<config::Config>) -> (Arc<Assembly>, Egress) {
        let (egress_tx, egress_rx) = crate::packet_queue::packet_queue(8);
        let mut builder = TestAssemblyBuilder::new();
        builder.mgmt_substrate_egress = Some(crate::queues::MgmtSubstrateEgress::new(egress_tx));
        builder.config = config.map(rcu::RcuBox::new);
        (Arc::new(create_assembly(builder)), egress_rx)
    }

    /// A config carrying the test bootstrap key (CN `test.cn.zpr`), so the
    /// adapter can sign the SS (device) leg.
    fn bootstrap_config() -> config::Config {
        let mut config = <config::Config as std::default::Default>::default();
        config.bootstrap = Some(bootstrap());
        config
    }

    /// The test bootstrap key, for signing SS blobs by hand.
    fn bootstrap() -> auth::RsaBootstrapAuth {
        let mut keypath = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keypath.push("tests");
        keypath.push("data");
        keypath.push("rsa-key.pem");
        auth::RsaBootstrapAuth::new("test.cn.zpr", &keypath).unwrap()
    }

    /// Insert a peer of `link_type` in `state` and return its link id. Each
    /// call gets a distinct substrate port: the peer table rejects duplicate
    /// substrate addresses. The dummy peer's auth key is `[42; 32]`.
    fn add_peer(asm: &Arc<Assembly>, link_type: LinkType, state: LinkState) -> LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let ps = peer_table::test::create_dummy_peer_state(
            link_id,
            link_type,
            SubstrateAddr::from(([127, 0, 0, 1], 9000 + link_id.get() as u16)),
            net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 2).into()),
        );
        let link_id = entry.insert(ps).get();
        asm.peer_table
            .get(link_id)
            .unwrap()
            .link_state_machine
            .test_set_state(state);
        link_id
    }

    /// An Active adapter-side (AdapterToNode) peer.
    fn add_adapter_peer(asm: &Arc<Assembly>) -> LinkId {
        add_peer(asm, LinkType::AdapterToNode, LinkState::Active)
    }

    /// An Active node-side (NodeToAdapter) peer.
    fn add_node_peer(asm: &Arc<Assembly>) -> LinkId {
        add_peer(asm, LinkType::NodeToAdapter, LinkState::Active)
    }

    /// A fixed challenge payload. The adapter side does not verify the HMAC
    /// (the node minted it), so arbitrary bytes are fine.
    fn test_challenge_payload() -> auth::ZdpInitAuthenticationPayload {
        auth::ZdpInitAuthenticationPayload {
            nonce: [7u8; 8],
            ctime: 424242u64.into(),
            hmac: [9u8; 32],
        }
    }

    /// The payload whose challenge bytes are `challenge`.
    fn payload_of(challenge: &[u8; 48]) -> auth::ZdpInitAuthenticationPayload {
        auth::ZdpInitAuthenticationPayload {
            nonce: challenge[0..8].try_into().unwrap(),
            ctime: u64::from_be_bytes(challenge[8..16].try_into().unwrap()).into(),
            hmac: challenge[16..48].try_into().unwrap(),
        }
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

    /// The renewal identity the node stashes for an actor that
    /// authenticated with [test_idp].
    fn test_identity() -> RenewalIdentity {
        RenewalIdentity {
            idp: test_idp(),
            nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
        }
    }

    /// An OIDC blob from `issuer` bound to `challenge`.
    fn oidc_blob(issuer: &str, id_token: &str, challenge: &[u8; 48]) -> AuthBlob {
        AuthBlob::Oidc(auth::ZdpOidcBlob {
            blob_type: auth::BLOB_TYPE_OIDC.to_string(),
            issuer: issuer.to_string(),
            id_token: id_token.to_string(),
            challenge: BASE64_STANDARD.encode(challenge),
        })
    }

    /// Mark the actor's renewal as due (deadline in the past) while its
    /// authentication stays valid for another `valid_for`.
    fn make_renewal_due(renewal: &RenewalState, valid_for: Duration) {
        let now = SystemTime::now();
        renewal.set_auth_expires(
            now - Duration::from_secs(600),
            now + valid_for,
            Duration::from_secs(300),
        );
    }

    /// Pop one packet off the observable egress queue, or None if empty.
    fn try_recv_egress(rx: &mut Egress) -> Option<Packet> {
        rx.try_recv(vec![0u8; config::PACKET_BUFFER_SIZE].into_boxed_slice())
            .ok()
    }

    /// Yield until a packet egresses (the adapter answers from a task).
    async fn recv_egress(rx: &mut Egress) -> Option<Packet> {
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if let Some(pkt) = try_recv_egress(rx) {
                return Some(pkt);
            }
        }
        None
    }

    /// Yield until the actor's renewal attempt is no longer in flight (the
    /// node completes it from a task).
    async fn settle(asm: &Arc<Assembly>, link_id: LinkId) {
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if !asm
                .peer_table
                .get(link_id)
                .unwrap()
                .actor_auth
                .renewal
                .test_in_flight()
            {
                return;
            }
        }
    }

    /// The challenge carried by a RenewAuthenticationRequest packet.
    /// body: [0]=type, [1]=excess, [2..10]=seq, [10..12]=data_len,
    /// [12..60]=challenge (nonce || ctime || hmac).
    fn request_challenge(pkt: &Packet) -> [u8; 48] {
        assert_eq!(
            pkt.body()[0],
            ZdpPacketType::RenewAuthenticationRequest.0,
            "expected a RenewAuthenticationRequest"
        );
        pkt.body()[12..60].try_into().unwrap()
    }

    /// A decoded RenewAuthenticationResponse packet: status, echoed
    /// challenge, and the blobs it carries (empty when it carries none).
    /// body: [0]=type, [1]=excess, [2..10]=seq, [10]=status,
    /// [11..13]=blob_len, [13..61]=echoed challenge, [61..]=blob.
    fn decode_response(pkt: &Packet) -> (AuthenticationStatus, [u8; 48], Vec<AuthBlob>) {
        let body = pkt.body();
        assert_eq!(
            body[0],
            ZdpPacketType::RenewAuthenticationResponse.0,
            "expected a RenewAuthenticationResponse"
        );
        let blob_len = u16::from_be_bytes([body[11], body[12]]) as usize;
        let blobs = if blob_len == 0 {
            Vec::new()
        } else {
            let blob_str = std::str::from_utf8(&body[61..61 + blob_len]).expect("utf8 blob");
            auth::decode_blobs(blob_str).expect("valid blob encoding")
        };
        (
            AuthenticationStatus(body[10]),
            body[13..61].try_into().unwrap(),
            blobs,
        )
    }

    /// Assert the node's renewal completion reached the `reauthorize` step:
    /// the test assembly has no VS connection, so completion ends in exactly
    /// this recorded failure. Any verification failure would have recorded a
    /// different one.
    fn assert_reached_reauthorize(asm: &Arc<Assembly>, link_id: LinkId) {
        match asm
            .peer_table
            .get(link_id)
            .unwrap()
            .actor_auth
            .last_failure()
        {
            Some(AuthFailureReason::AgentError(msg)) => assert!(
                msg.contains("no visa service connection"),
                "expected the reauthorize-step failure, got: {msg}"
            ),
            other => panic!("expected AgentError(no visa service connection), got {other:?}"),
        }
    }

    /// Assert the node recorded an AgentError whose text contains `needle`.
    fn assert_agent_error(asm: &Arc<Assembly>, link_id: LinkId, needle: &str) {
        match asm
            .peer_table
            .get(link_id)
            .unwrap()
            .actor_auth
            .last_failure()
        {
            Some(AuthFailureReason::AgentError(msg)) => assert!(
                msg.contains(needle),
                "expected an AgentError containing {needle:?}, got: {msg}"
            ),
            other => panic!("expected AgentError({needle}), got {other:?}"),
        }
    }

    /// `renewal_lead` clamps the configured lead to half the granted
    /// lifetime, so short `expiration_seconds` values still renew ahead of
    /// expiry by a workable margin (zipline#45).
    #[test]
    fn test_renewal_lead_clamps_to_half_lifetime() {
        let configured = Duration::from_secs(300);
        // Long lifetime: the configured lead stands.
        assert_eq!(
            renewal_lead(configured, Duration::from_secs(3600)),
            configured
        );
        // Lifetime of exactly 2x the lead: still the configured lead.
        assert_eq!(
            renewal_lead(configured, Duration::from_secs(600)),
            configured
        );
        // Short lifetime: clamped to half.
        assert_eq!(
            renewal_lead(configured, Duration::from_secs(120)),
            Duration::from_secs(60)
        );
        // Zero lifetime: zero lead (due at expiry, i.e. immediately).
        assert_eq!(renewal_lead(configured, Duration::ZERO), Duration::ZERO);
    }

    /// `renewal_deadline` is `auth_expires - effective lead`; an
    /// already-past expiry is due immediately (deadline not in the future).
    #[test]
    fn test_renewal_deadline_including_past_expiry() {
        let configured = Duration::from_secs(300);
        let now = SystemTime::now();

        // 1h lifetime: deadline is expiry minus the full 300s lead.
        let expires = now + Duration::from_secs(3600);
        assert_eq!(
            renewal_deadline(now, expires, configured),
            expires - Duration::from_secs(300)
        );

        // 120s lifetime: lead clamps to 60s.
        let expires = now + Duration::from_secs(120);
        assert_eq!(
            renewal_deadline(now, expires, configured),
            expires - Duration::from_secs(60)
        );

        // Expiry already in the past: lifetime saturates to zero, so the
        // deadline equals the (past) expiry — renewal is due immediately.
        let expires = now - Duration::from_secs(10);
        let deadline = renewal_deadline(now, expires, configured);
        assert_eq!(deadline, expires);
        assert!(deadline <= now, "past expiry must be due immediately");
    }

    /// PR #14 review: one silent-renewal attempt waits at most half the time
    /// remaining before expiry — clamped between the 5 s floor and the 300 s
    /// interaction timeout — so a hung attempt can always be retried while
    /// the current authentication is still valid.
    #[test]
    fn test_renewal_attempt_timeout_bounded_by_remaining_window() {
        let now = SystemTime::now();
        // Plenty of window: capped at the bridge's own per-call bound.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(3600)),
            config::OIDC_USER_INTERACTION_TIMEOUT,
        );
        // 600 s remaining (the default-lead case that motivated the review
        // finding): half the window, leaving room for a retry before expiry.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(600)),
            Duration::from_secs(300),
        );
        // 60 s remaining: 30 s, again half.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(60)),
            Duration::from_secs(30),
        );
        // Nearly (or already) expired: the floor keeps a healthy agent
        // answerable instead of a zero-length wait.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(4)),
            RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        );
        assert_eq!(
            renewal_attempt_timeout(now, now - Duration::from_secs(10)),
            RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        );
    }

    /// `auth_expires` round-trips through [RenewalState] (zipline#45):
    /// unset until authorized, then reads back what was set.
    #[test]
    fn test_auth_expires_round_trip() {
        let state = RenewalState::new();
        assert_eq!(state.auth_expires(), None);
        let now = SystemTime::now();
        let expires = now + Duration::from_secs(3600);
        state.set_auth_expires(now, expires, Duration::from_secs(300));
        assert_eq!(state.auth_expires(), Some(expires));
    }

    /// N2 (zipline#122) step 1: the authenticated namespace set round-trips
    /// through [RenewalState] — None until recorded.
    #[test]
    fn test_authenticated_namespaces_round_trip() {
        let state = RenewalState::new();
        assert_eq!(
            state.namespaces(),
            None,
            "no namespace set before authentication"
        );
        let set: BTreeSet<auth::AuthNamespace> =
            [auth::AuthNamespace::Device, auth::AuthNamespace::User].into();
        state.set_namespaces(set.clone());
        assert_eq!(state.namespaces(), Some(set));
    }

    /// The renewal identity (original issuer + challenge-derived nonce)
    /// round-trips through [RenewalState].
    #[test]
    fn test_renewal_identity_round_trip() {
        let state = RenewalState::new();
        assert!(state.identity().is_none());
        let challenge = [3u8; 48];
        state.set_identity(RenewalIdentity {
            idp: test_idp(),
            nonce: auth::oidc_nonce_for_challenge(&challenge),
        });
        let stored = state.identity().expect("identity must be stored");
        assert_eq!(stored.idp.issuer, "https://idp.test");
        assert_eq!(stored.nonce, auth::oidc_nonce_for_challenge(&challenge));
    }

    /// N2 (zipline#122) step 2: [request_renewal_now] on an Active
    /// NodeToAdapter link sends a RenewAuthenticationRequest immediately —
    /// no deadline needed — and a second call while the attempt is in
    /// flight is coalesced (no second request).
    #[tokio::test]
    async fn test_request_renewal_now_sends_request_and_coalesces() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                // No renewal deadline, no renewal identity: a device-only
                // actor never has either, and the on-demand path must not
                // require them.
                assert_eq!(request_renewal_now(&asm, link_id), RenewalStart::Accepted);
                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    peer.actor_auth.renewal.test_in_flight(),
                    "an on-demand request must mark the renewal in flight"
                );
                let pkt = try_recv_egress(&mut egress_rx)
                    .expect("an on-demand renewal request must be sent");
                assert_eq!(pkt.metadata().egress_link_id, link_id);
                request_challenge(&pkt);

                // While in flight: coalesced, no second packet.
                assert_eq!(request_renewal_now(&asm, link_id), RenewalStart::Coalesced);
                assert!(
                    try_recv_egress(&mut egress_rx).is_none(),
                    "a second on-demand request while in flight must be coalesced"
                );
            })
            .await
    }

    /// N2 (zipline#122) step 2: [request_renewal_now] requires an Active
    /// NodeToAdapter link — an adapter-side link and an inactive node link
    /// both send nothing and claim nothing ([RenewalStart::Ignored]).
    #[tokio::test]
    async fn test_request_renewal_now_requires_active_node_to_adapter() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);

                // Adapter-side link, Active: wrong link type.
                let adapter_link = add_adapter_peer(&asm);
                assert_eq!(
                    request_renewal_now(&asm, adapter_link),
                    RenewalStart::Ignored
                );
                assert!(
                    !asm.peer_table
                        .get(adapter_link)
                        .unwrap()
                        .actor_auth
                        .renewal
                        .test_in_flight(),
                    "an adapter-side link must not start an on-demand renewal"
                );

                // Node-side link still Helloing: wrong state.
                let node_link = add_peer(&asm, LinkType::NodeToAdapter, LinkState::Helloing);
                assert_eq!(request_renewal_now(&asm, node_link), RenewalStart::Ignored);
                assert!(
                    !asm.peer_table
                        .get(node_link)
                        .unwrap()
                        .actor_auth
                        .renewal
                        .test_in_flight(),
                    "a non-Active link must not start an on-demand renewal"
                );

                assert!(
                    try_recv_egress(&mut egress_rx).is_none(),
                    "neither call may send a packet"
                );
            })
            .await
    }

    /// R8 (zipline#66): on a node link whose renewal is due, with the
    /// renewal identity stashed but NO local AuthAgent — the combination the
    /// production paths actually produce, since the agent registers on the
    /// ADAPTER's side — the keep-alive tick ([maybe_renew]) must send a
    /// RenewAuthenticationRequest toward the adapter instead of taking the
    /// one-shot NoAgent warning path.
    #[tokio::test]
    async fn test_due_renewal_on_node_link_without_agent_sends_zdp_request() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.renewal.set_identity(test_identity());
                    // Renewal due but the authentication itself still valid
                    // for another minute.
                    make_renewal_due(&peer.actor_auth.renewal, Duration::from_secs(60));
                }

                maybe_renew(&asm, link_id);

                let peer = asm.peer_table.get(link_id).unwrap();
                // Must NOT give up with the NoAgent warning: the adapter may
                // well have an agent, and asking it is this issue's point.
                assert!(
                    !peer.actor_auth.renewal.test_no_agent_warned(),
                    "node tick took the NoAgent warning path instead of asking the adapter"
                );
                assert!(
                    peer.actor_auth.last_failure().is_none(),
                    "node tick recorded a failure instead of asking the adapter"
                );
                assert!(
                    peer.actor_auth.renewal.test_in_flight(),
                    "the ZDP credential request must mark the renewal in flight"
                );

                // ...and must emit a RenewAuthenticationRequest on the link.
                let pkt = try_recv_egress(&mut egress_rx)
                    .expect("a renewal credential request must be sent toward the adapter");
                assert_eq!(pkt.metadata().egress_link_id, link_id);
                let challenge = request_challenge(&pkt);
                assert_eq!(
                    peer.actor_auth.renewal.test_challenge(),
                    Some(challenge),
                    "the sent challenge must be stashed for verification"
                );
            })
            .await
    }

    /// R8 (zipline#66) step 3: an Active adapter link with a registered
    /// AuthAgent that receives a RenewAuthenticationRequest forwards exactly
    /// one `OidcCredentialRequest { interactive: false }` to the agent and
    /// returns the resulting blob in a Success RenewAuthenticationResponse
    /// that echoes the request's challenge. The link never leaves Active.
    #[tokio::test]
    async fn test_adapter_renew_request_asks_agent_and_answers_with_blob() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_adapter_peer(&asm);
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    peer.actor_auth.set_auth_agent(agent_tx);
                }

                let challenge_payload = test_challenge_payload();
                let challenge = challenge_payload.challenge_bytes();
                receive_renew_request(&asm, link_id, challenge_payload).unwrap();
                tokio::task::yield_now().await; // the agent is asked from a task

                // Exactly one non-interactive request, bound to the
                // advertised IdP and the challenge-derived nonce.
                let req = agent_rx.try_recv().expect("agent must be called once");
                assert!(
                    !req.interactive,
                    "renewal must never open a browser (interactive must be false)"
                );
                assert_eq!(req.idp.issuer, "https://idp.test");
                assert_eq!(req.nonce, auth::oidc_nonce_for_challenge(&challenge));
                assert!(agent_rx.try_recv().is_err(), "a second agent call was made");

                // The agent answers; the response goes out with the blob.
                req.reply.send(Ok("renewed-id-token".to_string())).unwrap();
                let pkt = recv_egress(&mut egress_rx)
                    .await
                    .expect("a RenewAuthenticationResponse must be sent");
                assert_eq!(pkt.metadata().egress_link_id, link_id);
                let (status, echoed, blobs) = decode_response(&pkt);
                assert_eq!(status, AuthenticationStatus::Success);
                assert_eq!(
                    echoed, challenge,
                    "the response must echo the request's challenge"
                );
                match &blobs[..] {
                    [AuthBlob::Oidc(oidc)] => {
                        assert_eq!(oidc.id_token, "renewed-id-token");
                        assert_eq!(oidc.issuer, "https://idp.test");
                        assert_eq!(
                            oidc.challenge,
                            BASE64_STANDARD.encode(challenge),
                            "the blob must be bound to the node's challenge"
                        );
                    }
                    other => panic!("expected one OIDC blob, got {other:?}"),
                }
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Active
                );
            })
            .await
    }

    /// R8 (zipline#66) step 3: an adapter link WITHOUT a registered agent
    /// answers a RenewAuthenticationRequest with
    /// [AuthenticationStatus::Retryable] (formerly AuthUnavailable) instead
    /// of dropping the packet, and stays Active.
    #[tokio::test]
    async fn test_adapter_renew_request_without_agent_answers_retryable() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_adapter_peer(&asm); // no agent, no IdP

                receive_renew_request(&asm, link_id, test_challenge_payload()).unwrap();

                let pkt = try_recv_egress(&mut egress_rx)
                    .expect("an agentless adapter must still answer");
                let (status, echoed, blobs) = decode_response(&pkt);
                assert_eq!(status, AuthenticationStatus::Retryable);
                assert_eq!(echoed, test_challenge_payload().challenge_bytes());
                assert!(blobs.is_empty());
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Active,
                    "answering must not perturb the link"
                );
            })
            .await
    }

    /// Codex P1 (PR #17, thread 1): a second RenewAuthenticationRequest on
    /// the same link supersedes the first — the node only retries after
    /// abandoning its previous attempt, so the adapter must cancel the
    /// superseded agent call (drop its reply channel, which the serial
    /// bridge observes via `reply.closed()`) instead of leaving it to run
    /// for up to OIDC_USER_INTERACTION_TIMEOUT while retries queue behind
    /// it.
    #[tokio::test]
    async fn test_adapter_second_renew_request_cancels_superseded_agent_call() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_adapter_peer(&asm);
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    peer.actor_auth.set_auth_agent(agent_tx);
                }

                // Attempt A: the agent receives the call and sits on it
                // (a hung or slow AuthAgent).
                receive_renew_request(&asm, link_id, test_challenge_payload()).unwrap();
                tokio::task::yield_now().await;
                let req_a = agent_rx.try_recv().expect("first agent call");
                assert!(
                    !req_a.reply.is_closed(),
                    "attempt A's reply channel must be open while A is current"
                );

                // The node abandoned A (its attempt timeout fired) and
                // retried: attempt B's request arrives on the same link.
                let payload_b = auth::ZdpInitAuthenticationPayload {
                    nonce: [8u8; 8],
                    ctime: 434343u64.into(),
                    hmac: [10u8; 32],
                };
                receive_renew_request(&asm, link_id, payload_b).unwrap();
                tokio::task::yield_now().await;
                let _req_b = agent_rx.try_recv().expect("second agent call");

                // The superseded call must be cancelled: aborting the wait
                // task drops its reply receiver, which tells the bridge to
                // drop the in-flight RPC and service the next request.
                let mut closed = false;
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                    if req_a.reply.is_closed() {
                        closed = true;
                        break;
                    }
                }
                assert!(
                    closed,
                    "the superseded renewal call must be cancelled so the \
                     serial bridge can service the retry"
                );
            })
            .await
    }

    /// N2 (zipline#122) step 4: an adapter whose actor authenticated
    /// device-only ({Device} recorded) answers a RenewAuthenticationRequest
    /// synchronously with a Success response carrying ONE SS blob bound to
    /// the echoed challenge — no AuthAgent involved.
    #[tokio::test]
    async fn test_adapter_renew_request_device_only_answers_with_ss_no_agent() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) =
                    assembly_with_observable_egress(Some(bootstrap_config()));
                let link_id = add_adapter_peer(&asm);
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .actor_auth
                    .renewal
                    .set_namespaces([auth::AuthNamespace::Device].into());
                // no agent, no IdP: an SS-only actor needs neither

                let challenge_payload = test_challenge_payload();
                let challenge = challenge_payload.challenge_bytes();
                receive_renew_request(&asm, link_id, challenge_payload).unwrap();

                let pkt = try_recv_egress(&mut egress_rx)
                    .expect("a device-only adapter must answer synchronously");
                let (status, _, blobs) = decode_response(&pkt);
                assert_eq!(status, AuthenticationStatus::Success);
                match &blobs[..] {
                    [AuthBlob::SelfSigned(ss)] => {
                        assert_eq!(ss.cn, "test.cn.zpr");
                        assert_eq!(
                            ss.challenge,
                            BASE64_STANDARD.encode(challenge),
                            "the SS blob must be bound to the node's challenge"
                        );
                    }
                    other => panic!("device-only means exactly one SS blob, got {other:?}"),
                }
            })
            .await
    }

    /// N2 (zipline#122) step 4: an adapter whose actor authenticated with
    /// SS+OIDC ({Device, User} recorded) but has NO AuthAgent cannot
    /// produce every leg, so it answers Retryable — never a partial set.
    #[tokio::test]
    async fn test_adapter_renew_request_ss_oidc_without_agent_answers_retryable() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) =
                    assembly_with_observable_egress(Some(bootstrap_config()));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.renewal.set_namespaces(
                        [auth::AuthNamespace::Device, auth::AuthNamespace::User].into(),
                    );
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    // bootstrap key present, but NO agent: the user leg is
                    // unproducible, so the whole answer is Retryable.
                }

                receive_renew_request(&asm, link_id, test_challenge_payload()).unwrap();

                let pkt = try_recv_egress(&mut egress_rx).expect("the adapter must still answer");
                let (status, _, blobs) = decode_response(&pkt);
                assert_eq!(
                    status,
                    AuthenticationStatus::Retryable,
                    "an unproducible leg must fail the WHOLE answer (no partial set)"
                );
                assert!(blobs.is_empty(), "no partial blob set may be sent");
            })
            .await
    }

    /// N2 (zipline#122) step 4: an SS+OIDC adapter WITH an agent answers a
    /// Success response whose blob array carries BOTH legs, each bound to
    /// the echoed challenge.
    #[tokio::test]
    async fn test_adapter_renew_request_ss_oidc_with_agent_answers_both_legs() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) =
                    assembly_with_observable_egress(Some(bootstrap_config()));
                let link_id = add_adapter_peer(&asm);
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.renewal.set_namespaces(
                        [auth::AuthNamespace::Device, auth::AuthNamespace::User].into(),
                    );
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    peer.actor_auth.set_auth_agent(agent_tx);
                }

                let challenge_payload = test_challenge_payload();
                let challenge_b64 = BASE64_STANDARD.encode(challenge_payload.challenge_bytes());
                receive_renew_request(&asm, link_id, challenge_payload).unwrap();
                tokio::task::yield_now().await;

                let req = agent_rx.try_recv().expect("agent must be called once");
                assert!(!req.interactive);
                req.reply.send(Ok("renewed-id-token".to_string())).unwrap();

                let pkt = recv_egress(&mut egress_rx)
                    .await
                    .expect("a RenewAuthenticationResponse must be sent");
                let (status, _, blobs) = decode_response(&pkt);
                assert_eq!(status, AuthenticationStatus::Success);
                assert_eq!(blobs.len(), 2, "SS+OIDC means exactly two blobs");
                let ss = blobs
                    .iter()
                    .find_map(|b| match b {
                        AuthBlob::SelfSigned(ss) => Some(ss),
                        _ => None,
                    })
                    .expect("the array must carry the SS leg");
                assert_eq!(ss.cn, "test.cn.zpr");
                assert_eq!(ss.challenge, challenge_b64);
                let oidc = blobs
                    .iter()
                    .find_map(|b| match b {
                        AuthBlob::Oidc(oidc) => Some(oidc),
                        _ => None,
                    })
                    .expect("the array must carry the OIDC leg");
                assert_eq!(oidc.id_token, "renewed-id-token");
                assert_eq!(oidc.issuer, "https://idp.test");
                assert_eq!(oidc.challenge, challenge_b64);
            })
            .await
    }

    /// R8 (zipline#66) step 4: a RenewAuthenticationResponse whose blob is
    /// bound to the node's outstanding challenge (HMAC-verified with this
    /// link's auth key) completes the renewal: the challenge is consumed and
    /// the completion path (reauthorize) is invoked — reaching it proves
    /// blob decoding, HMAC verification, challenge equality and issuer
    /// pinning all passed. The link stays Active throughout, and the
    /// in-flight flag is cleared by the completion.
    #[tokio::test]
    async fn test_node_renew_response_with_valid_blob_reaches_reauthorize() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.renewal.set_identity(test_identity());
                    make_renewal_due(&peer.actor_auth.renewal, Duration::from_secs(60));
                }

                // The due tick sends the request and stashes the challenge.
                maybe_renew(&asm, link_id);
                let challenge = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );

                // The adapter answers with a blob bound to that challenge.
                let blob = auth::encode_blobs(&[oidc_blob(
                    "https://idp.test",
                    "renewed-id-token",
                    &challenge,
                )]);
                receive_renew_response(&asm, link_id, challenge, Ok(blob)).unwrap();
                settle(&asm, link_id).await;

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    !peer.actor_auth.renewal.test_in_flight(),
                    "completion must clear the in-flight flag"
                );
                assert!(peer.actor_auth.renewal.test_challenge().is_none());
                assert_reached_reauthorize(&asm, link_id);
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Active,
                    "the link must stay Active through a renewal round-trip"
                );
            })
            .await
    }

    /// R8 (zipline#66) step 4: a response whose blob is bound to a DIFFERENT
    /// challenge than the outstanding one is rejected — failure recorded,
    /// in-flight cleared (so the next due tick retries), link still Active,
    /// and the existing expiry left to the sweep.
    #[tokio::test]
    async fn test_node_renew_response_with_wrong_challenge_is_rejected() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                let expires = {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.renewal.set_identity(test_identity());
                    make_renewal_due(&peer.actor_auth.renewal, Duration::from_secs(60));
                    peer.actor_auth.renewal.auth_expires()
                };

                maybe_renew(&asm, link_id);
                // The outstanding challenge, echoed by the (well-behaved)
                // adapter on its response header.
                let outstanding = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );

                // A blob correctly HMAC'd with this link's auth key but
                // bound to a DIFFERENT challenge.
                let other =
                    auth::ZdpInitAuthenticationPayload::new(&[42u8; auth::AUTH_KEY_SIZE_BYTES])
                        .challenge_bytes();
                let blob = auth::encode_blobs(&[oidc_blob(
                    "https://idp.test",
                    "renewed-id-token",
                    &other,
                )]);
                receive_renew_response(&asm, link_id, outstanding, Ok(blob)).unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    !peer.actor_auth.renewal.test_in_flight(),
                    "a rejected response must clear in-flight so the next tick retries"
                );
                assert_agent_error(&asm, link_id, "different challenge");
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Active,
                    "link must stay Active"
                );
                assert_eq!(
                    peer.actor_auth.renewal.auth_expires(),
                    expires,
                    "a failed renewal leaves the existing expiry to the sweep"
                );
            })
            .await
    }

    /// R8 (zipline#66) step 4: a Retryable (formerly AuthUnavailable)
    /// response records [AuthFailureReason::AuthUnavailable], clears
    /// in-flight, and leaves the link Active with its expiry intact.
    #[tokio::test]
    async fn test_node_renew_response_retryable_records_auth_unavailable() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                let expires = {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.renewal.set_identity(test_identity());
                    make_renewal_due(&peer.actor_auth.renewal, Duration::from_secs(60));
                    peer.actor_auth.renewal.auth_expires()
                };

                maybe_renew(&asm, link_id);
                let outstanding = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );
                receive_renew_response(
                    &asm,
                    link_id,
                    outstanding,
                    Err(AuthenticationStatus::Retryable),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(!peer.actor_auth.renewal.test_in_flight());
                assert_eq!(
                    peer.actor_auth.last_failure(),
                    Some(AuthFailureReason::AuthUnavailable)
                );
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
                assert_eq!(peer.actor_auth.renewal.auth_expires(), expires);
            })
            .await
    }

    /// Codex P1 (PR #17, thread 2): attempt A times out, attempt B starts,
    /// and A's DELAYED response then arrives. The stale response must not
    /// consume (or fail against) B's challenge: B's attempt stays in
    /// flight, and B's own valid response still completes the renewal.
    /// Without correlation, A's response is recorded as B's failure and
    /// B's valid response is discarded as unsolicited.
    #[tokio::test]
    async fn test_node_stale_renew_response_does_not_consume_new_attempts_challenge() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let renewal = &peer.actor_auth.renewal;
                renewal.set_identity(test_identity());
                make_renewal_due(renewal, Duration::from_secs(60));

                // Attempt A: request sent, challenge A stashed.
                maybe_renew(&asm, link_id);
                let challenge_a =
                    request_challenge(&try_recv_egress(&mut egress_rx).expect("attempt A request"));

                // A's attempt timeout fires — exactly what the spawned timer
                // in send_credential_request does: take its challenge and
                // fail the attempt.
                assert!(renewal.take_challenge_if(&challenge_a));
                finish_failure(
                    &asm,
                    link_id,
                    AuthFailureReason::AgentError(
                        "renewal credential request timed out (test)".to_string(),
                    ),
                );

                // Attempt B on the next due tick: fresh challenge stashed.
                // (Its request packet may sit in the ZDP-R send window
                // behind unacked attempt A — the transport is not under
                // test — so read the challenge from the stash.)
                maybe_renew(&asm, link_id);
                assert!(renewal.test_in_flight());
                let challenge_b = renewal
                    .test_challenge()
                    .expect("attempt B must stash its challenge");
                assert_ne!(
                    challenge_a, challenge_b,
                    "attempts must mint fresh challenges"
                );

                // A's DELAYED response arrives while B is in flight. Its
                // blob is well-formed and HMAC-valid — just bound to A.
                let blob_a = auth::encode_blobs(&[oidc_blob(
                    "https://idp.test",
                    "stale-id-token",
                    &challenge_a,
                )]);
                receive_renew_response(&asm, link_id, challenge_a, Ok(blob_a)).unwrap();

                // The stale response must be discarded: B stays in flight.
                assert!(
                    renewal.test_in_flight(),
                    "a stale response from a timed-out attempt must not fail the newer attempt"
                );
                assert_eq!(renewal.test_challenge(), Some(challenge_b));

                // B's own valid response still completes the renewal —
                // reaching reauthorize proves B's challenge was still
                // stashed and verified.
                let blob_b = auth::encode_blobs(&[oidc_blob(
                    "https://idp.test",
                    "renewed-id-token",
                    &challenge_b,
                )]);
                receive_renew_response(&asm, link_id, challenge_b, Ok(blob_b)).unwrap();
                drop(peer);
                settle(&asm, link_id).await;
                assert!(
                    !asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .actor_auth
                        .renewal
                        .test_in_flight(),
                    "B's valid response must complete the attempt"
                );
                assert_reached_reauthorize(&asm, link_id);
            })
            .await
    }

    /// N2 (zipline#122) step 5: a renewal response whose blob set does not
    /// EQUAL the namespace set the actor authenticated with is rejected —
    /// here the actor authenticated SS+OIDC but the reply carries only the
    /// OIDC leg. Failure recorded, in-flight cleared, link Active.
    #[tokio::test]
    async fn test_node_renew_response_set_mismatch_is_rejected() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.renewal.set_namespaces(
                        [auth::AuthNamespace::Device, auth::AuthNamespace::User].into(),
                    );
                    peer.actor_auth.renewal.set_identity(test_identity());
                }

                request_renewal_now(&asm, link_id);
                let challenge = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );

                // Only the OIDC leg comes back: {User} != {Device, User}.
                let blob = auth::encode_blobs(&[oidc_blob(
                    "https://idp.test",
                    "renewed-id-token",
                    &challenge,
                )]);
                receive_renew_response(&asm, link_id, challenge, Ok(blob)).unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    !peer.actor_auth.renewal.test_in_flight(),
                    "a rejected response must clear in-flight so the next tick retries"
                );
                assert_agent_error(&asm, link_id, "namespace");
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Active,
                    "link must stay Active"
                );
            })
            .await
    }

    /// N2 (zipline#122) step 5: an SS blob bound to a DIFFERENT challenge
    /// than the outstanding one is rejected even though the wire header
    /// echoes the right challenge and the blob's own HMAC is valid.
    #[tokio::test]
    async fn test_node_renew_response_wrong_challenge_ss_is_rejected() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .actor_auth
                    .renewal
                    .set_namespaces([auth::AuthNamespace::Device].into());

                request_renewal_now(&asm, link_id);
                let outstanding = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );

                // An SS blob whose embedded challenge is a DIFFERENT one,
                // HMAC-valid with this link's auth key.
                let other =
                    auth::ZdpInitAuthenticationPayload::new(&[42u8; auth::AUTH_KEY_SIZE_BYTES]);
                let ss = bootstrap().authenticate_blob(&other).unwrap();
                let blob = auth::encode_blobs(&[AuthBlob::SelfSigned(ss)]);
                receive_renew_response(&asm, link_id, outstanding, Ok(blob)).unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(!peer.actor_auth.renewal.test_in_flight());
                assert_agent_error(&asm, link_id, "different challenge");
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
            })
            .await
    }

    /// N2 (zipline#122) step 5: a valid SS answer on a device-only actor
    /// passes every check and reaches the reauthorize step.
    #[tokio::test]
    async fn test_node_renew_response_valid_ss_reaches_reauthorize() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth
                        .test_set_addresses(vec![net_defs::IpAddress::new_from_std(
                            &"10.9.8.7".parse::<IpAddr>().unwrap(),
                        )]);
                    peer.actor_auth
                        .renewal
                        .set_namespaces([auth::AuthNamespace::Device].into());
                }

                request_renewal_now(&asm, link_id);
                let challenge = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );

                // The adapter signs the outstanding challenge.
                let ss = bootstrap()
                    .authenticate_blob(&payload_of(&challenge))
                    .unwrap();
                let blob = auth::encode_blobs(&[AuthBlob::SelfSigned(ss)]);
                receive_renew_response(&asm, link_id, challenge, Ok(blob)).unwrap();
                settle(&asm, link_id).await;

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    !peer.actor_auth.renewal.test_in_flight(),
                    "completion must clear the in-flight flag"
                );
                assert_reached_reauthorize(&asm, link_id);
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
            })
            .await
    }

    /// N2 (zipline#122) step 5: a valid SS+OIDC answer on an actor that
    /// authenticated with both namespaces passes the set check and both
    /// per-blob checks and reaches the reauthorize step.
    #[tokio::test]
    async fn test_node_renew_response_valid_ss_oidc_reaches_reauthorize() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth
                        .test_set_addresses(vec![net_defs::IpAddress::new_from_std(
                            &"10.9.8.7".parse::<IpAddr>().unwrap(),
                        )]);
                    peer.actor_auth.renewal.set_namespaces(
                        [auth::AuthNamespace::Device, auth::AuthNamespace::User].into(),
                    );
                    peer.actor_auth.renewal.set_identity(test_identity());
                }

                request_renewal_now(&asm, link_id);
                let challenge = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );

                let ss = bootstrap()
                    .authenticate_blob(&payload_of(&challenge))
                    .unwrap();
                let blob = auth::encode_blobs(&[
                    AuthBlob::SelfSigned(ss),
                    oidc_blob("https://idp.test", "renewed-id-token", &challenge),
                ]);
                receive_renew_response(&asm, link_id, challenge, Ok(blob)).unwrap();
                settle(&asm, link_id).await;

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(!peer.actor_auth.renewal.test_in_flight());
                assert_reached_reauthorize(&asm, link_id);
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
            })
            .await
    }

    /// Codex review (zl-zpr-core#45, P2): a combined Device+User renewal
    /// whose noninteractive agent answers after the 120-second SS window
    /// but within the permitted 300-second agent wait must still verify.
    /// The SS leg is bound to the SAME minted challenge as the OIDC leg,
    /// and that challenge is issued before the agent wait, so on the
    /// renewal path the SS leg must be held to the OIDC freshness window
    /// (which covers the wait) — replay is already prevented by exact
    /// byte-equality with the single outstanding stashed challenge.
    #[tokio::test]
    async fn test_node_renew_response_combined_ss_leg_survives_agent_wait() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);

                // Mint a challenge whose ctime is 150 s in the past — the
                // agent took 150 s to answer, allowed by the 300 s bound,
                // beyond MAX_BLOB_AGE_SECONDS (120 s) but within
                // MAX_OIDC_BLOB_AGE_SECONDS (330 s). HMAC-keyed with the
                // dummy peer's auth key, and stashed as the outstanding
                // attempt exactly as send_credential_request does.
                let key = [42u8; auth::AUTH_KEY_SIZE_BYTES];
                let ctime = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 150;
                let nonce = [9u8; 8];
                let be_time = ctime.to_be_bytes();
                let mut hasher = blake3::Hasher::new_keyed(&key);
                hasher.update(&nonce);
                hasher.update(&be_time);
                let hmac = hasher.finalize();
                let mut challenge = [0u8; 48];
                challenge[0..8].copy_from_slice(&nonce);
                challenge[8..16].copy_from_slice(&be_time);
                challenge[16..48].copy_from_slice(hmac.as_bytes());
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    let renewal = &peer.actor_auth.renewal;
                    renewal.set_namespaces(
                        [auth::AuthNamespace::Device, auth::AuthNamespace::User].into(),
                    );
                    renewal.set_identity(test_identity());
                    renewal.stash_challenge(challenge);
                    renewal.data.lock().unwrap().in_flight = true;
                }

                let ss = bootstrap()
                    .authenticate_blob(&payload_of(&challenge))
                    .unwrap();
                let blob = auth::encode_blobs(&[
                    AuthBlob::SelfSigned(ss),
                    oidc_blob("https://idp.test", "renewed-id-token", &challenge),
                ]);
                receive_renew_response(&asm, link_id, challenge, Ok(blob)).unwrap();
                settle(&asm, link_id).await;

                // Reaching the reauthorize step proves the SS leg's
                // 150-second-old challenge was NOT rejected as too old.
                assert!(
                    !asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .actor_auth
                        .renewal
                        .test_in_flight()
                );
                assert_reached_reauthorize(&asm, link_id);
            })
            .await
    }

    /// N2 (zipline#122) step 5: the ph-blob -> VS-API blob conversion used
    /// for a renewal reply ([crate::visa_mgmt::vsapi_blobs]) maps the SS leg
    /// (cn/challenge/signature/timestamp) and the OIDC leg
    /// (issuer/id_token/challenge-derived nonce) faithfully — the
    /// ReauthRequest carries every leg (the "one ReauthRequest with all
    /// blobs" half of K3/K4 that the no-vsconn tests above cannot observe).
    #[test]
    fn test_vsapi_blobs_for_renewal_maps_both_legs() {
        use zpr::vsapi_types as vst;
        let challenge = [5u8; 48];
        let blobs = vec![
            AuthBlob::SelfSigned(auth::ZdpSelfSignedBlob {
                blob_type: auth::BLOB_TYPE_SS.to_string(),
                ts: 12345,
                cn: "test.cn.zpr".to_string(),
                challenge: BASE64_STANDARD.encode(challenge),
                sig: BASE64_STANDARD.encode([2u8; 16]),
            }),
            oidc_blob("https://idp.test", "tok", &challenge),
        ];

        let vst_blobs = crate::visa_mgmt::vsapi_blobs(&blobs).unwrap();
        assert_eq!(vst_blobs.len(), 2, "every leg must be forwarded");
        match &vst_blobs[0] {
            vst::AuthBlob::SS(ss) => {
                assert_eq!(ss.cn, "test.cn.zpr");
                assert_eq!(ss.timestamp, 12345);
                assert_eq!(ss.challenge, challenge.to_vec());
                assert_eq!(ss.signature, vec![2u8; 16]);
            }
            other => panic!("expected SS first, got {other:?}"),
        }
        match &vst_blobs[1] {
            vst::AuthBlob::Oidc(oidc) => {
                assert_eq!(oidc.issuer, "https://idp.test");
                assert_eq!(oidc.id_token, "tok");
                assert_eq!(oidc.nonce, auth::oidc_nonce_for_challenge(&challenge));
            }
            other => panic!("expected Oidc second, got {other:?}"),
        }
    }

    /// Codex review (zl-zpr-core#45, P1): a renewal reply carrying TWO OIDC
    /// blobs — the first from the pinned issuer, the second from another —
    /// must be rejected outright. The namespace SET comparison cannot see
    /// the duplicate (both collapse to `{User}`), every blob is bound to
    /// the same echoed challenge so the per-blob checks pass, and the
    /// issuer pin examines only the FIRST OIDC blob while `vsapi_blobs`
    /// would forward both credentials to the visa service. One blob per
    /// namespace is the rule.
    #[tokio::test]
    async fn test_node_renew_response_duplicate_oidc_blobs_rejected() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress(None);
                let link_id = add_node_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth
                        .renewal
                        .set_namespaces([auth::AuthNamespace::User].into());
                    peer.actor_auth.renewal.set_identity(test_identity());
                }

                request_renewal_now(&asm, link_id);
                let challenge = request_challenge(
                    &try_recv_egress(&mut egress_rx).expect("request must be sent"),
                );

                // Both blobs echo the correct challenge; only the first names
                // the pinned issuer. The second must not ride along.
                let blob = auth::encode_blobs(&[
                    oidc_blob("https://idp.test", "renewed-id-token", &challenge),
                    oidc_blob("https://evil.example", "forged-id-token", &challenge),
                ]);
                receive_renew_response(&asm, link_id, challenge, Ok(blob)).unwrap();
                settle(&asm, link_id).await;

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(!peer.actor_auth.renewal.test_in_flight());
                assert_agent_error(&asm, link_id, "duplicate");
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
            })
            .await
    }

    /// R8 (zipline#66) step 4: a response with no outstanding request (no
    /// stashed challenge — completed, timed out, or never sent) is discarded
    /// without touching the renewal state.
    #[tokio::test]
    async fn test_node_unsolicited_renew_response_is_discarded() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_node_peer(&asm);

                receive_renew_response(&asm, link_id, [3u8; 48], Ok("not-even-base64".to_string()))
                    .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    peer.actor_auth.last_failure().is_none(),
                    "an unsolicited response must not record a failure"
                );
                assert!(!peer.actor_auth.renewal.test_in_flight());
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
            })
            .await
    }

    /// C4 (zipline#45): a due renewal tick with NO AuthAgent registered
    /// warns exactly once per authentication window and records
    /// [AuthFailureReason::NoAgent]; later due ticks are silent no-ops.
    #[tokio::test]
    async fn test_renewal_tick_without_agent_warns_once() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let actor = &peer.actor_auth;

                // Renewal overdue: the expiry is already in the past.
                let past = SystemTime::now() - Duration::from_secs(10);
                actor.renewal.set_auth_expires(
                    past - Duration::from_secs(600),
                    past,
                    Duration::from_secs(300),
                );

                maybe_renew(&asm, link_id);
                assert!(actor.renewal.test_no_agent_warned());
                assert_eq!(actor.last_failure(), Some(AuthFailureReason::NoAgent));

                // Second due tick: no new failure is recorded (warned flag
                // holds), and nothing is attempted. (operator_retry is the
                // production way to clear the recorded failure.)
                actor.operator_retry(&asm);
                maybe_renew(&asm, link_id);
                assert!(
                    actor.last_failure().is_none(),
                    "no-agent warning repeated on a later tick"
                );
                assert!(!actor.renewal.test_in_flight());
            })
            .await
    }

    /// C4 (zipline#45): a renewal tick before the deadline attempts nothing,
    /// even with an agent registered.
    #[tokio::test]
    async fn test_renewal_tick_before_deadline_is_noop() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                peer.actor_auth.set_auth_agent(agent_tx);
                peer.actor_auth.renewal.set_identity(test_identity());
                // Expires an hour out with a 300s lead: not due yet.
                let now = SystemTime::now();
                peer.actor_auth.renewal.set_auth_expires(
                    now,
                    now + Duration::from_secs(3600),
                    Duration::from_secs(300),
                );

                maybe_renew(&asm, link_id);
                tokio::task::yield_now().await;
                assert!(!peer.actor_auth.renewal.test_in_flight());
                assert!(
                    agent_rx.try_recv().is_err(),
                    "agent was called before the renewal deadline"
                );
            })
            .await
    }

    /// C4 (zipline#45): a due tick with a registered agent sends exactly ONE
    /// non-interactive credential request bound to the ORIGINAL issuer and
    /// the stored challenge-derived nonce; while that attempt is in flight,
    /// further due ticks do not send another.
    #[tokio::test]
    async fn test_renewal_tick_sends_one_noninteractive_request() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                peer.actor_auth.set_auth_agent(agent_tx);
                peer.actor_auth.renewal.set_identity(test_identity());
                let past = SystemTime::now() - Duration::from_secs(1);
                peer.actor_auth.renewal.set_auth_expires(
                    past - Duration::from_secs(600),
                    past,
                    Duration::from_secs(300),
                );
                drop(peer);

                maybe_renew(&asm, link_id);
                tokio::task::yield_now().await;
                let req = agent_rx.try_recv().expect("agent must be called once");
                assert!(
                    !req.interactive,
                    "renewal must never open a browser (interactive must be false)"
                );
                assert_eq!(req.idp.issuer, "https://idp.test");
                assert_eq!(req.nonce, test_identity().nonce);

                // In flight: the next due tick must not send a second call.
                maybe_renew(&asm, link_id);
                tokio::task::yield_now().await;
                assert!(
                    agent_rx.try_recv().is_err(),
                    "second agent call while a renewal attempt is in flight"
                );
            })
            .await
    }

    /// PR #14 review: an AuthAgent that never answers must not pin the
    /// in-flight flag past the authentication window. The attempt times out
    /// (bounded by the remaining window), records a failure, and the next
    /// due tick retries.
    #[tokio::test(start_paused = true)]
    async fn test_hung_renewal_attempt_times_out_and_next_tick_retries() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.set_auth_agent(agent_tx);
                    peer.actor_auth.renewal.set_identity(test_identity());
                    // Renewal overdue with ~20 s of validity left: the
                    // attempt timeout must be ~10 s, far below the 300 s
                    // bridge bound.
                    make_renewal_due(&peer.actor_auth.renewal, Duration::from_secs(20));
                }

                maybe_renew(&asm, link_id);
                // Let the spawned attempt task send its request and
                // register its timeout timer before advancing the clock.
                for _ in 0..10 {
                    tokio::task::yield_now().await;
                }
                // The agent hangs: hold the request (and its reply sender)
                // without ever answering.
                let hung_req = agent_rx.try_recv().expect("agent must be called");
                assert!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .actor_auth
                        .renewal
                        .test_in_flight()
                );

                // Well past the bounded attempt timeout, but well short of
                // the 300 s bridge bound the review flagged.
                tokio::time::advance(Duration::from_secs(30)).await;
                settle(&asm, link_id).await;
                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    !peer.actor_auth.renewal.test_in_flight(),
                    "hung attempt still in flight after the remaining-window timeout"
                );
                assert!(matches!(
                    peer.actor_auth.last_failure(),
                    Some(AuthFailureReason::AgentError(_))
                ));
                drop(peer);

                // The next due tick retries while auth is still valid.
                maybe_renew(&asm, link_id);
                for _ in 0..10 {
                    tokio::task::yield_now().await;
                }
                assert!(
                    agent_rx.try_recv().is_ok(),
                    "next due tick must retry after a timed-out attempt"
                );
                drop(hung_req);
            })
            .await
    }

    /// PR #14 review: a renewal task that outlives its link must not act on
    /// a NEW link that reused the same peer-table id. The task carries the
    /// old actor's [RenewalState] uid; when the current occupant of the id
    /// has a different uid, the outcome must be discarded instead of pushing
    /// the old actor's renewal result onto the new link's state. The uid
    /// mismatch is driven directly through [submit_reauthorize] (the call
    /// the task spawned by [maybe_renew] makes with the agent's token): the
    /// RCU slab defers slot reclamation, so a unit test cannot force a real
    /// id reuse without draining the epoch machinery.
    #[tokio::test]
    async fn test_stale_renewal_reply_after_link_id_reuse_is_discarded() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let current_uid = asm.peer_table.get(link_id).unwrap().actor_auth.renewal.uid;
                let token = |id_token: &str| {
                    vec![zpr::vsapi_types::AuthBlob::Oidc(
                        zpr::vsapi_types::OidcBlob {
                            issuer: "https://idp.test".to_string(),
                            id_token: id_token.to_string(),
                            nonce: test_identity().nonce,
                        },
                    )]
                };

                // A stale task from the closed PREVIOUS occupant of this id
                // delivers a renewed credential for the old actor.
                submit_reauthorize(&asm, link_id, current_uid.wrapping_add(1), token("stale"))
                    .await;
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    assert!(
                        peer.actor_auth.last_failure().is_none(),
                        "stale renewal task from the closed link wrote a failure onto the new link"
                    );
                    assert!(
                        !peer.actor_auth.renewal.test_in_flight(),
                        "stale renewal task perturbed the new link's in-flight flag"
                    );
                    assert_eq!(
                        peer.actor_auth.renewal.auth_expires(),
                        None,
                        "stale renewal task overwrote the new link's auth expiry"
                    );
                }

                // Control: the SAME call with the matching uid is acted on
                // (the test assembly has no vsconn, so it ends in a recorded
                // failure) — proving the uid guard, not something else,
                // discarded the stale call above.
                submit_reauthorize(&asm, link_id, current_uid, token("current")).await;
                assert_reached_reauthorize(&asm, link_id);
            })
            .await
    }

    /// C4 (zipline#45): a failed attempt records the reason, clears the
    /// in-flight flag, and the NEXT due tick retries (one attempt per tick).
    #[tokio::test]
    async fn test_renewal_failure_records_reason_and_next_tick_retries() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth.set_auth_agent(agent_tx);
                    peer.actor_auth.renewal.set_identity(test_identity());
                    let past = SystemTime::now() - Duration::from_secs(1);
                    peer.actor_auth.renewal.set_auth_expires(
                        past - Duration::from_secs(600),
                        past,
                        Duration::from_secs(300),
                    );
                }

                // Attempt 1: the agent answers with a failure.
                maybe_renew(&asm, link_id);
                tokio::task::yield_now().await;
                let req = agent_rx.try_recv().expect("agent must be called");
                req.reply
                    .send(Err(AuthFailureReason::IdpUnreachable(
                        "refresh failed".to_string(),
                    )))
                    .unwrap();
                settle(&asm, link_id).await;
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    assert!(
                        !peer.actor_auth.renewal.test_in_flight(),
                        "failure must clear in-flight"
                    );
                    assert!(matches!(
                        peer.actor_auth.last_failure(),
                        Some(AuthFailureReason::IdpUnreachable(_))
                    ));
                }

                // Attempt 2 on the next due tick.
                maybe_renew(&asm, link_id);
                tokio::task::yield_now().await;
                assert!(
                    agent_rx.try_recv().is_ok(),
                    "registered-but-failing agent must be retried once per due tick"
                );
            })
            .await
    }

    /// A stale timeout or response must not consume a newer attempt's
    /// challenge: only an exact match is taken, and only once.
    #[test]
    fn test_take_challenge_if_only_matches_current() {
        let state = RenewalState::new();
        state.stash_challenge([1; 48]);
        assert!(!state.take_challenge_if(&[2; 48]));
        assert!(state.take_challenge_if(&[1; 48]));
        assert!(!state.take_challenge_if(&[1; 48]));
    }

    /// A fresh grant restarts the window: in-flight and warned flags clear.
    #[test]
    fn test_set_auth_expires_resets_window_bookkeeping() {
        let state = RenewalState::new();
        {
            let mut data = state.data.lock().unwrap();
            data.in_flight = true;
            data.no_agent_warned = true;
        }
        let now = SystemTime::now();
        state.set_auth_expires(now, now + Duration::from_secs(60), Duration::from_secs(10));
        assert_eq!(state.auth_expires(), Some(now + Duration::from_secs(60)));
        assert!(!state.test_in_flight());
        assert!(!state.test_no_agent_warned());
    }

    /// Link teardown forgets the session and cancels the adapter's task.
    #[tokio::test]
    async fn test_reset_clears_session_and_aborts_task() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let state = RenewalState::new();
                state.set_namespaces([auth::AuthNamespace::Device].into());
                state.stash_challenge([9; 48]);
                let task = tokio::task::spawn_local(std::future::pending::<()>());
                state.data.lock().unwrap().adapter_task = Some(task.abort_handle());
                state.reset();
                assert!(state.namespaces().is_none());
                assert!(state.test_challenge().is_none());
                assert!(task.await.unwrap_err().is_cancelled());
            })
            .await;
    }

    /// Distinct actors get distinct uids, so a completion for a torn-down
    /// actor cannot be applied to a new one in the same slot.
    #[test]
    fn test_uids_are_unique() {
        assert_ne!(RenewalState::new().uid, RenewalState::new().uid);
    }
}
