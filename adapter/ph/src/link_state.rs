use crate::auth;
use crate::counters::ManagementCounterType;
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::mgmt;
use crate::pki;
use crate::prelude::*;
use crate::sample_ring::SampleRing;
use crate::zdp::{ResponseCode, TerminateReason};

use std::fmt::{Display, Formatter};
use std::num::NonZero;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;
use zpr::addrs::ZPRNET_PREFIX_LEN;
use zpr_utils::net_defs::IpAddress;

/// Encrypted link lifecycle.
///
/// Zipline additions to upstream #1410's link layer (search "zipline#"):
/// OIDC IdP advertisement in Hello (zipline#12), keep-alive miss tolerance
/// (zipline#113), the node keying timeout (zipline#173), and a fresh ZDP-R
/// session per Start.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkState {
    Inactive,
    Keying,
    Helloing,
    Closing,
    Resetting,
    Active,
    Error,
}

#[derive(Clone, Debug)]
pub struct HelloResponse {
    pub status: ResponseCode,
    pub aaa_address: Option<IpAddress>,
    /// Zipline (zipline#12): OIDC IdPs the node advertised. Replaces
    /// upstream's ASA list, removed with BAS in zipline#15.
    pub oidc_idps: Option<Vec<auth::OidcIdpInfo>>,
    pub vs_bootstrap: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug, strum::IntoStaticStr)]
pub enum LinkEvent {
    Start,
    KeyingDone,
    ReceivedHelloRequest,
    ReceivedHelloResponse {
        status: ResponseCode,
        aaa_address: Option<IpAddress>,
        oidc_idps: Option<Vec<auth::OidcIdpInfo>>,
        vs_bootstrap: bool,
    },

    ReceivedKeepAliveResponse,
    ReceivedTerminateLink(TerminateReason),
    ReceivedTerminateAck,
    Close(TerminateReason),
    CloseDone,
    Error,
    Timeout {
        logical_clock: u64,
    },
}

#[derive(Error, Debug)]
pub enum LinkStateError {
    #[error("Got unexpected event {1} on state {0:?}")]
    UnexpectedTransition(LinkState, &'static str),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    #[error("Link {0} does not exist in peer table")]
    NotFound(LinkId),
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkType {
    Internal,
    /// A link between two Zodes (zl-zipline#220, #250). Both ends verify the
    /// other's CA-signed certificate, the dialer says Hello, and neither end
    /// hands out an AAA address. Which end this Zode is lives in [ZodeEnd].
    NodeToNode,
}

/// Which end of a Zode (NodeToNode) link this Zode is (zl-zipline#250). Set
/// once, before the link starts; see [LinkStateWrapper::set_zode_end].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZodeEnd {
    /// This Zode dialed the link. Keying is accepted only if the peer's
    /// verified certificate carries `peer_cn`, the CN it dialed for.
    Dialer { peer_cn: String },
    /// The peer dialed this Zode. Keying is accepted only under the
    /// acceptance rules (ZODE_LINKS.md rules 3 and 4).
    Answerer,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LinkStatus {
    Up,
    Down,
}

/// Lives in a [LinkStateWrapper]
pub struct LinkData {
    echo_success: u64, // Echo requests received response
    echo_timeout: u64, // Echo requests timed out
    // TODO: configurable keep-alive period
    // For now, keep-alives are attempted every 3 seconds
    // Assuming no loss, 100 samples will store 5 minutes of latency data
    latency_data: SampleRing<Duration, 100>,
    installed_aaa: bool,
}

impl LinkData {
    pub fn new() -> Self {
        Self {
            echo_success: 0,
            echo_timeout: 0,
            latency_data: SampleRing::new(Duration::ZERO),
            installed_aaa: false,
        }
    }
}

pub struct LinkStateMachine {
    id: LinkId,
    state: LinkState,
    status: LinkStatus,
    ready: Arc<AtomicBool>,
    silent: bool,

    last_state_change: Instant,
    /// used to prevent A/B/A errors with timeouts
    logical_clock: u64,
    timeout_handle: Option<tokio::task::AbortHandle>,
    /// Counter available for use by states which wish to count timeouts.
    /// Reset to 0 on any state transition.
    timeout_count: usize,
    /// Handle to an outstanding echo/keepalive task; used only during Active.
    /// Instant is time at which the echo was sent.
    echo_handle: Option<(Instant, tokio::task::AbortHandle)>,
    /// Consecutive keep-alive misses on this Active session (zipline#113).
    /// Incremented when an outstanding echo times out, reset by a keep-alive
    /// response (and on entering Active); the link is only torn down when it
    /// reaches [config::KEEP_ALIVE_MAX_MISSES].
    keep_alive_misses: u32,
    shutting_down: bool, // only ever goes from False -> True once
}

impl LinkStateMachine {
    pub fn new(link_id: LinkId) -> Self {
        Self {
            id: link_id,
            state: LinkState::Inactive,
            status: LinkStatus::Down,
            ready: Arc::new(AtomicBool::new(false)),
            silent: false,
            last_state_change: std::time::Instant::now(),
            logical_clock: 0,
            timeout_handle: None,
            timeout_count: 0,
            echo_handle: None,
            keep_alive_misses: 0,
            shutting_down: false,
        }
    }

    pub fn set_state(&mut self, new_state: LinkState) {
        if new_state != self.state {
            debug!(target: LINK_STATE, "Link {} state transition {:?} => {:?}", self.id, self.state, new_state);
        }
        self.state = new_state;
        self.ready.store(
            self.status == LinkStatus::Up && new_state == LinkState::Active,
            Ordering::Release,
        );
        self.last_state_change = std::time::Instant::now();
        self.cancel_timeout();
        self.timeout_count = 0;
    }

    /// Schedule the given callback to be invoked asynchronously after the
    /// specified duration.
    ///
    /// The callback will be passed the logical clock at which time the
    /// timeout was set, and, after obtaining a lock on the state machine,
    /// the callback should compare this value to the current logical clock
    /// to determine whether it is still valid.
    ///
    /// Any existing callback is cancelled as with `cancel_timeout()`.
    ///
    /// The timeout will be canceled automatically at the next state change.
    /// (Note that any call to `set_state()` will cancel the timeout, even
    /// if the state does not actually change.)
    pub fn set_timeout_callback(
        &mut self,
        duration: std::time::Duration,
        callback: impl FnOnce(u64) + Send + 'static,
    ) {
        // cancel old timeout if present
        self.cancel_timeout();

        // launch new timeout tied to the current (new) logical clock
        let logical_clock = self.logical_clock;
        let jh = tokio::task::spawn_local(async move {
            tokio::time::sleep(duration).await;
            callback(logical_clock);
        });

        // store new timeout handle
        self.timeout_handle = Some(jh.abort_handle());
    }

    /// Try to cancel any existing timeout.
    ///
    /// Any existing callback may or may not be invoked at a later time.  It
    /// is the responsibility of the callback to ensure atomic behavior by
    /// comparing the logical clock as detailed in `set_timeout_callback()`.
    pub fn cancel_timeout(&mut self) {
        // request to abort existing timeout task if present
        self.timeout_handle.take().inspect(|h| h.abort());
        // increment logical clock to avoid duplicate timeouts
        self.logical_clock = self.logical_clock.wrapping_add(1);
    }
}

pub struct LinkStateWrapper {
    pub id: LinkId, // set at constructor, never changes.
    link_type: LinkType,
    locked_fsm: Mutex<LinkStateMachine>,
    pub locked_data: Mutex<LinkData>,
    // Shared with the FSM so every state transition publishes fastpath readiness.
    ready: Arc<AtomicBool>,
    aaa_address: rcu::RcuBox<Option<IpAddress>>,
    /// NodeToNode only: which end of the link this Zode is (zl-zipline#250).
    zode_end: std::sync::OnceLock<ZodeEnd>,
    /// Internal links _may_ be associated with another internal link
    /// representing its remote side.
    pub internal_peer_id: Option<NonZero<LinkId>>,
}

impl LinkStateWrapper {
    pub fn new(new_id: LinkId, new_link_type: LinkType) -> Self {
        let mut lsm = LinkStateMachine::new(new_id);

        if matches!(new_link_type, LinkType::Internal) {
            // Internal links are always up and active, that is, `is_ready()`.
            lsm.status = LinkStatus::Up;
            lsm.set_state(LinkState::Active);
        }

        Self {
            id: new_id,
            link_type: new_link_type,
            ready: lsm.ready.clone(),
            aaa_address: rcu::RcuBox::new(None),
            locked_fsm: Mutex::new(lsm),
            locked_data: Mutex::new(LinkData::new()),
            zode_end: std::sync::OnceLock::new(),
            internal_peer_id: None,
        }
    }

    pub fn is_internal(&self) -> bool {
        matches!(self.link_type, LinkType::Internal)
    }

    /// Get the link's current state
    pub fn get_state(&self) -> LinkState {
        self.locked_fsm.lock().unwrap().state
    }

    /// Fastpath-readable readiness, published by every FSM state transition.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn get_link_type(&self) -> LinkType {
        self.link_type
    }

    /// Record which end of a Zode link this Zode is (zl-zipline#250). Only
    /// for a NodeToNode link, and only once: the end never changes.
    pub fn set_zode_end(&self, end: ZodeEnd) -> Result<(), LinkStateError> {
        if self.link_type != LinkType::NodeToNode {
            return Err(LinkStateError::InvalidOperation(format!(
                "a {:?} link has no Zode end",
                self.link_type
            )));
        }
        self.zode_end.set(end).map_err(|_| {
            LinkStateError::InvalidOperation("the Zode end of a link is set only once".into())
        })
    }

    /// Which end of this Zode link this Zode is; `None` for other link types.
    pub fn zode_end(&self) -> Option<&ZodeEnd> {
        self.zode_end.get()
    }

    /// Whether this is a Zode link this Zode dialed.
    pub fn is_zode_dialer(&self) -> bool {
        matches!(self.zode_end(), Some(ZodeEnd::Dialer { .. }))
    }

    /// Read the assigned AAA without taking the link-data mutex.
    pub fn aaa_address(&self) -> Option<IpAddress> {
        *self.aaa_address.get()
    }

    /// Test-only: force the FSM into a state without walking the transitions.
    #[cfg(test)]
    pub fn test_set_state(&self, state: LinkState) {
        self.locked_fsm.lock().unwrap().set_state(state);
    }

    /// Test-only: put the link in Keying as `Start` does (status Up),
    /// without handing it to a key manager.
    #[cfg(test)]
    pub fn test_set_keying(&self) {
        let mut fsm = self.locked_fsm.lock().unwrap();
        fsm.status = LinkStatus::Up;
        fsm.set_state(LinkState::Keying);
    }

    /// Test-only: bring the link Up and Active (so `is_ready()` holds)
    /// without walking keying and Hello.
    #[cfg(test)]
    pub fn test_set_active(&self) {
        let mut fsm = self.locked_fsm.lock().unwrap();
        fsm.status = LinkStatus::Up;
        fsm.set_state(LinkState::Active);
    }

    /// Test-only: the FSM's current logical clock, for synthesizing a
    /// `LinkEvent::Timeout` that `process_timeout` accepts as current.
    #[cfg(test)]
    pub fn test_logical_clock(&self) -> u64 {
        self.locked_fsm.lock().unwrap().logical_clock
    }

    /// Answer the dialer's HelloRequest on a Zode link this Zode answered.
    /// Only the answering end of a Zode link expects a HelloRequest.
    fn process_hello_request(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        if self.zode_end() != Some(&ZodeEnd::Answerer) || locked_fsm.state != LinkState::Helloing {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloRequest",
            ));
        }
        // zl-zipline#250: a Zode link carries no AAA address, no identity
        // providers and no bootstrap flag. The peer is known by its
        // CN-checked certificate, and its ZPR address comes from the
        // topology, never from Hello.
        mgmt::requests::send_hello_success_response(asm, self.id, 0, &[], None).enqueue();
        self.run_active_zode(asm, locked_fsm)
    }

    /// Take an AAA address for a new link from the pool the visa service
    /// configured, or `None` when it has configured none. The caller hands
    /// it to [Self::install_aaa] or [Self::process_assigned_aaa], so that
    /// link cleanup gives it back.
    // AAA kept unused in v1 (zl-zpr-dev-context docs/ZODE_LINKS.md,
    // Design decisions, "AAA kept, unused")
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn allocate_aaa(asm: &Assembly) -> Option<IpAddress> {
        asm.address_pool.lock().unwrap().as_mut().map(|pool| {
            let aaa = pool.get_aaa_address();
            debug!(target: LINK_STATE, "allocated AAA {aaa}; {} active reservations", pool.len());
            aaa
        })
    }

    fn process_hello_response(
        &self,
        asm: &Arc<Assembly>,
        response: HelloResponse,
    ) -> Result<(), LinkStateError> {
        if response.status != ResponseCode::Success {
            warn!(target: LINK_STATE, "{}: Hello failed: {:?}", asm.formatted_link_id(self.id), response.status);
            return self.initiate_close(asm, TerminateReason::Other);
        }
        let locked_fsm = self.locked_fsm.lock().unwrap();
        // Only the Zode that dialed a Zode link sends a HelloRequest, so
        // only it expects a HelloResponse.
        if !self.is_zode_dialer() || locked_fsm.state != LinkState::Helloing {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloResponse",
            ));
        }
        // zl-zipline#250 (gaps 5 and 6): a Zode answers Hello with nothing
        // an adapter dock would get. A peer that offers an AAA address,
        // identity providers or the visa-service bootstrap flag is not
        // behaving as a Zode, so the link is refused.
        if response.aaa_address.is_some() || response.oidc_idps.is_some() || response.vs_bootstrap {
            warn!(target: LINK_STATE, "{}: refusing a Zode HelloResponse that carries an AAA address, identity providers or the bootstrap flag; closing",
                asm.formatted_link_id(self.id));
            drop(locked_fsm);
            return self.initiate_close(asm, TerminateReason::Other);
        }
        self.run_active_zode(asm, locked_fsm)
    }

    /// Install `aaa` on the TUN interface as this link's authentication
    /// address and remember it, so link cleanup clears it again. An address
    /// the interface already carried is not ours to clear, so
    /// `installed_aaa` is set only when this link added it.
    // AAA kept unused in v1 (zl-zpr-dev-context docs/ZODE_LINKS.md,
    // Design decisions, "AAA kept, unused")
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn install_aaa(
        &self,
        asm: &Arc<Assembly>,
        aaa: IpAddress,
    ) -> Result<(), LinkStateError> {
        self.process_assigned_aaa(asm, aaa)?;
        let exists = asm
            .tun_ctl
            .has_address(aaa.into())
            .map_err(|e| LinkStateError::InvalidOperation(format!("inspect AAA: {e}")))?;
        asm.tun_ctl
            .add_authentication_address(aaa.into(), ZPRNET_PREFIX_LEN)
            .map_err(|e| LinkStateError::InvalidOperation(format!("configure AAA: {e}")))?;
        // A repeated install finds the address this link already added:
        // keep owning it.
        self.locked_data.lock().unwrap().installed_aaa |= !exists;
        Ok(())
    }

    /// Schedule a `Timeout` event to occur after the specified duration.
    ///
    /// Any existing timeout is canceled atomically.
    ///
    /// The timeout will also be canceled automatically and atomically at the next state change.
    ///
    /// The timeout may be cancelled manually using `LinkStateMachine::cancel_timeout()`.
    /// It will be cancelled atomically.
    fn set_timeout(
        &self,
        asm: &Arc<Assembly>,
        locked_fsm: &mut MutexGuard<'_, LinkStateMachine>,
        duration: std::time::Duration,
    ) {
        let link_id = self.id;
        let task_asm = asm.clone();
        locked_fsm.set_timeout_callback(duration, move |logical_clock| {
            if let Err(e) =
                task_asm.process_link_state_event(link_id, LinkEvent::Timeout { logical_clock })
            {
                error!(target: LINK_STATE, "error handling timeout: {e}");
            }
        });
    }

    pub fn process_event(
        &self,
        asm: &Arc<Assembly>,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        match event {
            LinkEvent::ReceivedKeepAliveResponse | LinkEvent::Timeout { .. } => {
                trace!(target: LINK_STATE, "{}: *EVENT* {event:?}", asm.formatted_link_id(self.id))
            }

            _ => {
                debug!(target: LINK_STATE, "{}: *EVENT* {event:?}", asm.formatted_link_id(self.id))
            }
        }

        match event {
            LinkEvent::Start => self.process_start(asm),
            LinkEvent::KeyingDone => self.process_keying_done(asm),
            LinkEvent::ReceivedHelloRequest => self.process_hello_request(asm),
            LinkEvent::ReceivedHelloResponse {
                status,
                aaa_address,
                oidc_idps,
                vs_bootstrap,
            } => self.process_hello_response(
                asm,
                HelloResponse {
                    status,
                    aaa_address,
                    oidc_idps,
                    vs_bootstrap,
                },
            ),

            LinkEvent::ReceivedKeepAliveResponse => self.process_keep_alive_response(asm),
            LinkEvent::ReceivedTerminateLink(code) => self.process_terminate_link(asm, code),
            LinkEvent::ReceivedTerminateAck => self.process_terminate_ack(asm),
            LinkEvent::Close(code) => self.initiate_close(asm, code),
            LinkEvent::CloseDone => Ok(self.complete_close(asm)),
            LinkEvent::Error => self.process_error_response(asm),
            LinkEvent::Timeout { logical_clock } => self.process_timeout(asm, logical_clock),
        }
    }

    /// Start an inactive Zode link
    /// Transitions from Inactive -> Keying
    /// Will trigger key management messages to be sent if this Zode dialed
    /// the link
    fn process_start(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        assert!(self.id != LINK_ID_UNKNOWN);
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Inactive {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "Start",
            ));
        }

        locked_fsm.status = LinkStatus::Up;
        locked_fsm.set_state(LinkState::Keying);

        // A Start also begins a fresh ZDP-R session: the peer restarts its
        // sequence numbers at 0 for every attempt, and carrying a previous
        // attempt's sequence numbers and receive window into this one would
        // have each side silently discard the other's traffic.
        if let Some(peer) = asm.peer_table.get(link_id) {
            peer.reset_zdpr_session();
        }

        info!(target: LINK_STATE, "{} started.  Keying in progress", asm.formatted_link_id(link_id));

        match self.link_type {
            LinkType::NodeToNode => {
                // zl-zipline#250: the dialer initiates keying, and both ends
                // demand a CA-signed certificate (#220). A Zode without link
                // keys or a CA certificate fails closed.
                let Some(end) = self.zode_end() else {
                    error!(target: LINK_STATE, "{} is a Zode link with no Zode end set; cannot start it", asm.formatted_link_id(link_id));
                    locked_fsm.set_state(LinkState::Error);
                    return Err(LinkStateError::InvalidOperation("Zode end not set".into()));
                };
                let dialer = matches!(end, ZodeEnd::Dialer { .. });
                // The ZPIs this end asks its peer to use: the same split as
                // an adapter (the dialer) and a node (the answerer).
                let zpis = if dialer {
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 5, 6)
                } else {
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 3, 4)
                };
                let (Some(keypair), Some(certx)) =
                    (asm.self_noise_keypair.clone(), asm.certx.clone())
                else {
                    error!(target: LINK_STATE, "{} has no link keys; cannot start a Zode link", asm.formatted_link_id(link_id));
                    locked_fsm.set_state(LinkState::Error);
                    return Err(LinkStateError::InvalidOperation("no link keys".into()));
                };
                if let Err(e) =
                    km_multiplexor::add_zode_link(asm, link_id, dialer, zpis, keypair, certx)
                {
                    error!(target: LINK_STATE, "{} cannot start a Zode link: {e:?}", asm.formatted_link_id(link_id));
                    locked_fsm.set_state(LinkState::Error);
                    return Err(LinkStateError::InvalidOperation(format!("{e:?}")));
                }
                // Bound keying on both ends: a dialer whose peer never
                // answers, and an answerer whose dialer went away.
                self.set_timeout(asm, &mut locked_fsm, config::ZODE_KEYING_TIMEOUT);
                Ok(())
            }
            LinkType::Internal => {
                error!(target: LINK_STATE, "Coding error: internal link state machine should not be controlled");
                Err(LinkStateError::InvalidOperation("coding error".into()))
            }
        }
    }

    /// The Key Manager sends in the [LinkEvent::KeyingDone] event when it is done with initial keying.
    /// Transitions from Keying -> Helloing
    /// Will trigger a Hello to be sent if this Zode dialed the link
    fn process_keying_done(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Keying {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "KeyingDone",
            ));
        }

        let Some(peer_state) = asm.peer_table.get(link_id) else {
            return Err(LinkStateError::NotFound(link_id));
        };

        let Some(sa) = peer_state.get_established_transport_association() else {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "KeyingDone when SA not established",
            ));
        };

        // zl-zipline#220, #250: a Zode link is checked once the peer's CN
        // is known, and refused with a logged reason.
        //
        // An inbound Zode link that passes replaces any established link to
        // the same peer (ZODE_LINKS.md rule 5), once the guards below are
        // released.
        let mut replaces_links_to: Option<String> = None;
        if self.link_type == LinkType::NodeToNode {
            let peer_cn = peer_state.verified_peer_cn();
            let verdict = match self.zode_end() {
                Some(end) => crate::zode_links::check_keyed_peer(asm, end, peer_cn.as_deref())
                    .map_err(|refusal| refusal.to_string()),
                None => Err("Zode end not set".to_string()),
            };
            if let Err(reason) = verdict {
                warn!(target: LINK_STATE, "{} refusing Zode link with peer CN {peer_cn:?}: {reason}; closing", asm.formatted_link_id(link_id));
                drop(sa);
                drop(peer_state);
                drop(locked_fsm);
                // The refused link gives up the peer's address now, not
                // when it finishes closing: that waits up to
                // DEFAULT_TERMINATE_TIMEOUT for a Terminate ack the peer
                // often cannot send (it has already dropped its SA), and
                // the owner's redial from the same address (rule 6) must
                // start a new link meanwhile rather than reach this one
                // (gate g120).
                asm.peer_table.unmap_substrate_addr(link_id);
                return self.initiate_close(asm, TerminateReason::Reset);
            }
            info!(target: LINK_STATE, "{} accepted Zode link with peer CN {peer_cn:?}", asm.formatted_link_id(link_id));
            if self.zode_end() == Some(&ZodeEnd::Answerer) {
                replaces_links_to = peer_cn;
            }
        }

        if let Some(ref peer_cert) = sa.peer_cert {
            let cert = peer_cert.get_cert();
            if peer_cert.is_verified() {
                info!(target: LINK_STATE, "{} has verified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            } else {
                warn!(target: LINK_STATE, "{} has unverified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            }
        }

        drop(sa);
        drop(peer_state);

        debug!(target: LINK_STATE, "{} finished keying.  Starting hello", asm.formatted_link_id(link_id));

        locked_fsm.set_state(LinkState::Helloing);

        // The Zode that dialed a Zode link issues the hello
        if self.is_zode_dialer() {
            // Grab public key from keypair to send in hello request
            let pubkey = x25519_dalek::PublicKey::from(&asm.a2a_dh_keypair);
            mgmt::requests::send_hello_request(asm, self.id, pubkey).enqueue();
            self.set_timeout(asm, &mut locked_fsm, config::ZODE_HELLO_TIMEOUT);
            debug!(
                target: LINK_STATE,
                "{} sent HelloRequest.  Waiting for other side to respond.", asm.formatted_link_id(link_id)
            );
        } else if self.link_type == LinkType::NodeToNode {
            // The answering Zode waits for the dialer's HelloRequest, and
            // bounds the wait so a peer that keys and goes quiet cannot hold
            // the link open (zl-zipline#250).
            self.set_timeout(asm, &mut locked_fsm, config::ZODE_HELLO_TIMEOUT);
        }
        drop(locked_fsm);
        if let Some(peer_cn) = replaces_links_to {
            crate::zode_links::replace_established_links(asm, link_id, &peer_cn);
        }
        // Otherwise we wait for the peer to say Hello
        Ok(())
    }

    /// Record `aaa_addr` as this link's AAA address, so that link cleanup
    /// gives it back to the pool. Does not generate an error.
    // AAA kept unused in v1 (zl-zpr-dev-context docs/ZODE_LINKS.md,
    // Design decisions, "AAA kept, unused")
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn process_assigned_aaa(
        &self,
        _asm: &Arc<Assembly>,
        aaa_addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        // Just keep track of this for cleanup later.
        let link_id = self.id;
        debug!(target: LINK_STATE, "Link {link_id} assigned AAA address {aaa_addr}");
        // Writers share the data lock so cleanup can atomically take AAA ownership.
        let _data = self.locked_data.lock().unwrap();
        self.aaa_address.write(Some(aaa_addr));
        Ok(())
    }

    fn process_error_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        asm.counters.management[ManagementCounterType::PeerHandshakeFailure].increment();
        warn!(target: LINK_STATE, "{}: bringup failed at state {:?}",
            asm.formatted_link_id(link_id),
            self.locked_fsm.lock().unwrap().state);

        self.initiate_close(&asm, TerminateReason::Other)
    }

    fn process_timeout(
        &self,
        asm: &Arc<Assembly>,
        logical_clock: u64,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if logical_clock != locked_fsm.logical_clock {
            // timeout was for some earlier state & we won the task abort race; ignore
            return Ok(());
        }

        // handle the timeout...
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToNode, LinkState::Keying | LinkState::Helloing) => {
                // Timeout here means we give up on the link.
                error!(target: LINK_STATE, "{}: timed out in state {:?}", asm.formatted_link_id(self.id), locked_fsm.state);
                locked_fsm.set_state(LinkState::Error);
                drop(locked_fsm);
                return self.initiate_close(asm, TerminateReason::RequestTimedOut);
            }

            (_, LinkState::Active) => {
                if let Some((_start_time, echo_handle)) = locked_fsm.echo_handle.take() {
                    // There was an outstanding echo, and we've timed out: a
                    // consecutive keep-alive miss (zipline#113). Only tear
                    // the link down when the tolerance is exhausted; until
                    // then, log the miss and immediately try another echo.
                    echo_handle.abort();
                    self.locked_data.lock().unwrap().echo_timeout += 1;
                    locked_fsm.keep_alive_misses += 1;
                    if locked_fsm.keep_alive_misses >= config::KEEP_ALIVE_MAX_MISSES {
                        // This is also how a Zode notices that its own
                        // substrate address went away (a network change,
                        // zl-zipline#230): the keep-alive declares the
                        // initial link down, and the Zode redials it from
                        // its new address. We could switch to OS-specific
                        // operations (address or route change notifications)
                        // to detect the link down sooner if we want to in
                        // the future.
                        error!(target: LINK_STATE, "{} failed to respond to keep-alive messages", asm.formatted_link_id(self.id));
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        return self.initiate_close(asm, TerminateReason::RequestTimedOut);
                    }
                    warn!(target: LINK_STATE, "{} missed keep-alive {} of {}",
                        asm.formatted_link_id(self.id),
                        locked_fsm.keep_alive_misses,
                        config::KEEP_ALIVE_MAX_MISSES);
                }

                // No outstanding echo (or a tolerated miss): send a new one.
                let link_id = self.id;
                let task_asm = asm.clone();
                let jh = tokio::task::spawn_local(async move {
                    match mgmt::requests::send_echo_request(&task_asm, link_id)
                        .acked()
                        .await
                    {
                        Ok(()) => {
                            // success! poke the state machine
                            // ignore any errors, that just means we've left Active and are already shutting down the link
                            let _ = task_asm.process_link_state_event(
                                link_id,
                                LinkEvent::ReceivedKeepAliveResponse,
                            );
                        }

                        // ignore link closed, we are already shutting down
                        Err(mgmt::core::MgmtSendError::LinkClosed) => (),
                    }
                });

                // store new echo handle and kick off timeout
                locked_fsm.echo_handle = Some((Instant::now(), jh.abort_handle()));
                self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_TIMEOUT);
                drop(locked_fsm);

                // Housekeeping on the keep-alive tick (zl-zipline#274,
                // g184 q7): the expiry sweep, rate-limited across all
                // links. Outside the FSM lock: it takes the visa-table
                // lock and sends withdrawals.
                crate::visa_mgmt::sweep_expired_visas_if_due(asm);
                Ok(())
            }

            (_, LinkState::Closing) => {
                // This is a timeout while we are waiting for a terminate response post initiate close.
                // Now we finish the job,
                debug!(target: LINK_STATE, "{} received timeout waiting on terminate response, shutting down link", asm.formatted_link_id(self.id));
                drop(locked_fsm);
                self.clean_up_link_state(asm).detach_all();
                Ok(())
            }

            (_, _) => Err(LinkStateError::InvalidOperation(format!(
                "Ignoring unexpected timeout in state {:?}",
                locked_fsm.state
            ))),
        }
    }

    /// Initiate the shutdown of the link
    /// Transitions to Closing from any running state
    /// Generates a Terminate Request packet
    /// Sets a timeout in case we do not get a terminate response.
    fn initiate_close(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        if matches!(self.link_type, LinkType::Internal) {
            return Err(LinkStateError::InvalidOperation(
                "cannot shutdown internal link".to_owned(),
            ));
        }

        let link_id = self.id;
        info!(target: LINK_STATE,"Initiating shutdown on {}", asm.formatted_link_id(link_id));

        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if matches!(reason, TerminateReason::Shutdown) {
            locked_fsm.shutting_down = true;
        }
        self.continue_close(asm, locked_fsm, reason)
    }

    /// Continue shutdown of the link: enter Closing and send the Terminate.
    fn continue_close(
        &self,
        asm: &Arc<Assembly>,
        mut locked_fsm: MutexGuard<LinkStateMachine>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        locked_fsm.set_state(LinkState::Closing);

        // If this timeout fires, we end up going to `clean_up_link_state`.
        // If we get a response to our terminate we also go to `clean_up_link_state`.
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_TERMINATE_TIMEOUT);
        drop(locked_fsm);
        let task_asm = asm.clone();
        let ingress_link_id = self.id;
        tokio::task::spawn_local(async move {
            let acked = mgmt::requests::send_terminate_link_or_docking_session(
                &task_asm,
                ingress_link_id,
                reason,
            )
            .acked();
            match acked.await {
                // FIXME why do we never get an ACK?
                Ok(()) => {
                    let _ = task_asm
                        .process_link_state_event(ingress_link_id, LinkEvent::ReceivedTerminateAck);
                }
                Err(mgmt::core::MgmtSendError::LinkClosed) => (),
            }
        });
        Ok(())
    }

    /// Tear down link state.
    /// This sends notice to the visa service that we have lost an actor.
    /// Sends a CloseDone event (which triggers [LinkStateWrapper::complete_close])
    fn clean_up_link_state(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let link_id = self.id;
        let mut join_set = tokio::task::JoinSet::new();

        let locked_fsm = self.locked_fsm.lock().unwrap();

        match locked_fsm.state {
            LinkState::Closing | LinkState::Resetting => {
                drop(locked_fsm);
                info!(target: LINK_STATE, "{} is clearing its state", asm.formatted_link_id(link_id));
                let mut link_data = self.locked_data.lock().unwrap();
                let aaa = self.aaa_address();
                self.aaa_address.write(None);
                if let Some(aaa_addr) = aaa {
                    if link_data.installed_aaa {
                        if let Err(err) = asm
                            .tun_ctl
                            .clear_address(aaa_addr.into(), ZPRNET_PREFIX_LEN)
                        {
                            error!(target: LINK_STATE, "cannot clear AAA address: {err}");
                        }
                    }
                    if let Some(pool) = asm.address_pool.lock().unwrap().as_mut() {
                        match pool.release_address(aaa_addr) {
                            Ok(_) => {
                                debug!(target: LINK_STATE, "{} released AAA address {aaa_addr}", asm.formatted_link_id(link_id))
                            }
                            Err(e) => {
                                error!(target: LINK_STATE, "Failed to release AAA address {aaa_addr}: {e:?}")
                            }
                        };
                    }
                }
                link_data.installed_aaa = false;
                drop(link_data);

                asm.peer_table.clear_peer_state(link_id);

                let task_asm = asm.clone();
                join_set.spawn_local(async move {
                    // NOTE: Any mgmt messages MUST have been sent before this is called
                    km_multiplexor::drop_link(&task_asm, link_id).await;

                    if let Err(e) = task_asm.process_link_state_event(link_id, LinkEvent::CloseDone)
                    {
                        error!(target: LINK_STATE, "Error shutting down {}: {e:?}", task_asm.formatted_link_id(link_id));
                    }
                });
            }
            _ => {
                // Unexpcted call.
                warn!(target: LINK_STATE, "cannot clean_up_link_state in state {:?}", locked_fsm.state);
            }
        }
        join_set
    }

    /// Complete a link shutdown, upon receiving a terminate request or response
    /// Transitions from Closing to Inactive
    /// Generates no packets
    fn complete_close(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        info!(target: LINK_STATE, "Shutting down {}", asm.formatted_link_id(link_id));
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (locked_fsm.state, self.link_type) {
            // zl-zipline#250: a closed Zode link drops its peer entry on
            // both ends, which clears everything tied to it (ZODE_LINKS.md
            // rule 9). It never restarts itself: only its owner redials.
            (LinkState::Closing, LinkType::NodeToNode) | (LinkState::Resetting, _) => {
                // Clear whole peer out
                drop(locked_fsm);
                asm.drop_peer(link_id);
                return;
            }
            (LinkState::Closing, _) => {
                locked_fsm.silent = false;
                locked_fsm.set_state(LinkState::Inactive);
                info!(target: LINK_STATE, "{} has fully shut down", asm.formatted_link_id(link_id));
                // No link type restarts itself any more: a Zode link is
                // redialed only by its owner. The peer stays Inactive unless
                // ph is shutting down.
                if locked_fsm.shutting_down {
                    drop(locked_fsm);
                    asm.drop_peer(link_id); // buh bye!
                }
            }
            _ => {
                error!(
                    target: LINK_STATE,
                    "{} tried to close from state {:?}",
                    asm.formatted_link_id(link_id),
                    locked_fsm.state
                );
            }
        }
    }

    /// Reset the link, shutting it down and wiping its configuration
    /// Instead of transitioning, the state machine will be destroyed
    /// Sends a Terminate Indication
    pub async fn reset(&self, asm: &Arc<Assembly>) {
        let _ = self.begin_reset(asm).join_all().await;
    }

    /// Drop this Zode link because a newly accepted link to the same peer
    /// replaces it (ZODE_LINKS.md rule 5). Its state is cleared now; its
    /// key manager and peer entry go when the returned cleanup completes.
    pub fn drop_replaced(&self, asm: &Arc<Assembly>) {
        self.begin_reset(asm).detach_all();
    }

    /// Start a reset: tell the peer, enter Resetting and clear the link's
    /// state. Returns the cleanup tasks, which end with the peer dropped.
    fn begin_reset(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Resetting {} from state {:?}",
            asm.formatted_link_id(link_id),
            self.locked_fsm.lock().unwrap().state
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Resetting);
        mgmt::requests::send_terminate_link_or_docking_session(
            asm,
            link_id,
            TerminateReason::Reset,
        )
        .enqueue();
        self.clean_up_link_state(asm)
    }

    /// Handle a terminate link acknowledgement.
    /// This means we sent a terminate request and set a timeout. Timeout is cancelled here
    /// before we proceed with shutting down the link.
    fn process_terminate_ack(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,"Received terminate response for {}", asm.formatted_link_id(link_id));
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match locked_fsm.state {
            LinkState::Closing => {
                locked_fsm.cancel_timeout();
                drop(locked_fsm);
                self.clean_up_link_state(asm).detach_all();
                Ok(())
            }
            _ => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedTerminateAck",
            )),
        }
    }

    /// Peer has sent a terminate-link message.
    /// May generate an RPC message (over TUN) to the visa service.
    /// Peer has shut down or shutting down so don't expect it to be there anymore.
    ///
    /// Returns Ok unless this is in a state that cannot handle this message.
    fn process_terminate_link(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Received terminate for {} with reason {:?}", asm.formatted_link_id(link_id), reason
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Closing);
        self.clean_up_link_state(asm).detach_all();
        Ok(())
    }

    pub fn process_keep_alive_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if !matches!(locked_fsm.state, LinkState::Active) {
            // we only expect keep alives responses in Active
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedKeepAliveResponse",
            ));
        }

        let Some((start_time, _echo_handle)) = locked_fsm.echo_handle.take() else {
            // we do not have an outstanding echo request
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedKeepAliveResponse",
            ));
        };

        // we got a successful echo response, track it
        locked_fsm.keep_alive_misses = 0; // zipline#113: a response resets the miss tolerance
        let mut link_data = self.locked_data.lock().unwrap();
        link_data.echo_success += 1;
        link_data
            .latency_data
            .add(Instant::now().duration_since(start_time));
        drop(link_data);

        // delay before kicking off next echo request
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_PERIOD);
        drop(locked_fsm);

        Ok(())
    }

    /// Common code to enter the `Active` state and kick off our keepalive mechanism
    /// Enter Active on a Zode link, then tell its link record the link is
    /// up (zl-zipline#250, rules 7 and 8) once the FSM lock is released.
    fn run_active_zode(
        &self,
        asm: &Arc<Assembly>,
        locked_fsm: MutexGuard<'_, LinkStateMachine>,
    ) -> Result<(), LinkStateError> {
        self.run_active(asm, locked_fsm)?;
        crate::zode_links::link_up(asm, self.id);
        Ok(())
    }

    fn run_active(
        &self,
        asm: &Arc<Assembly>,
        mut locked_fsm: MutexGuard<'_, LinkStateMachine>,
    ) -> Result<(), LinkStateError> {
        locked_fsm.set_state(LinkState::Active);
        asm.counters.management[ManagementCounterType::PeerHandshakeSuccess].increment();
        debug!(target: LINK_STATE, "{} entering active state", asm.formatted_link_id(self.id));

        // kick off our keepalive mechanism
        locked_fsm.echo_handle.take().inspect(|(_, h)| h.abort()); // should already be None (indicating no echo outstanding) but let's be sure
        locked_fsm.keep_alive_misses = 0; // fresh Active session, fresh tolerance (zipline#113)
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_TIMEOUT);

        Ok(())
    }
}

impl Display for LinkStateWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: This doesn't print link ID because the caller is printing link ID
        // followed by substrate addr, which is out of scope for this display function
        write!(f, "  Type: {:?}\n", self.link_type)?;

        write!(f, "{}", self.locked_fsm.lock().unwrap())?;
        if self.get_state() == LinkState::Active {
            write!(f, "{}", self.locked_data.lock().unwrap())?;
        }
        Ok(())
    }
}

impl Display for LinkStateMachine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: Format time since last state change better
        write!(
            f,
            "  State: {:?} (for {:?})\n",
            self.state,
            Instant::now().duration_since(self.last_state_change)
        )?;
        write!(f, "  Status: {:?}\n", self.status)
    }
}

impl Display for LinkData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (total, count) = self.latency_data.get_total_and_count();
        let average = if count > 0 {
            total.div_f64(count as f64)
        } else {
            Duration::ZERO
        };

        write!(f, "  Echo stats:\n")?;
        write!(f, "    Successes: {}\n", self.echo_success)?;
        write!(f, "    Timeouts: {}\n", self.echo_timeout)?;
        write!(
            f,
            "    Latency: Min {:?}, Max {:?}, Avg {average:?}\n",
            self.latency_data.get_min(),
            self.latency_data.get_max(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::task::LocalSet;

    #[test]
    fn readiness_tracks_all_link_states() {
        let link = LinkStateWrapper::new(3, LinkType::NodeToNode);
        assert!(!link.is_ready());
        assert!(LinkStateWrapper::new(1, LinkType::Internal).is_ready());

        for state in [
            LinkState::Inactive,
            LinkState::Keying,
            LinkState::Helloing,
            LinkState::Closing,
            LinkState::Resetting,
            LinkState::Error,
        ] {
            {
                let mut fsm = link.locked_fsm.lock().unwrap();
                fsm.status = LinkStatus::Up;
                fsm.set_state(LinkState::Active);
            }
            assert!(link.is_ready());
            link.locked_fsm.lock().unwrap().set_state(state);
            assert!(!link.is_ready(), "unexpected readiness in {state:?}");
        }

        {
            let mut fsm = link.locked_fsm.lock().unwrap();
            fsm.status = LinkStatus::Down;
            fsm.set_state(LinkState::Active);
        }
        assert!(!link.is_ready());
    }

    /// A `TunCtl` whose addresses live in a shared list, so a test can see
    /// what `install_aaa` and link cleanup did to the TUN. An AAA goes on
    /// the TUN only as an authentication address: a plain `add_address`
    /// fails the test.
    struct AaaTunCtl(Arc<Mutex<Vec<std::net::IpAddr>>>);

    impl crate::tun_ctl::TunCtl for AaaTunCtl {
        fn name(&self) -> String {
            "tun-aaa".to_string()
        }
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, addr: std::net::IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            panic!("{addr} added as a plain address; an AAA is an authentication address");
        }
        fn add_authentication_address(
            &self,
            addr: std::net::IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<()> {
            self.0.lock().unwrap().push(addr);
            Ok(())
        }
        fn clear_address(&self, addr: std::net::IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            self.0.lock().unwrap().retain(|a| *a != addr);
            Ok(())
        }
        fn has_address(&self, addr: std::net::IpAddr) -> std::io::Result<bool> {
            Ok(self.0.lock().unwrap().contains(&addr))
        }
    }

    /// `install_aaa` puts the AAA on the TUN and records it, and link
    /// cleanup clears it again, even after a repeated install; an AAA the
    /// TUN already carried is not ours, so cleanup leaves it in place.
    #[tokio::test(flavor = "local")]
    async fn install_aaa_is_cleared_by_cleanup_only_when_it_added_it() {
        let aaa_ip: std::net::IpAddr = "fd5a:5052:0:aaa::1".parse().unwrap();
        for already_on_tun in [false, true] {
            let tun = Arc::new(Mutex::new(if already_on_tun {
                vec![aaa_ip]
            } else {
                Vec::new()
            }));
            let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                tun_ctl: Some(Box::new(AaaTunCtl(tun.clone()))),
                ..TestAssemblyBuilder::new()
            }));
            let link = LinkStateWrapper::new(3, LinkType::NodeToNode);
            link.install_aaa(&asm, aaa_ip.into()).unwrap();
            // A repeated install must not forget that this link added it.
            link.install_aaa(&asm, aaa_ip.into()).unwrap();
            assert_eq!(link.aaa_address(), Some(aaa_ip.into()));
            assert!(tun.lock().unwrap().contains(&aaa_ip));

            link.test_set_state(LinkState::Closing);
            let _ = link.clean_up_link_state(&asm);
            assert_eq!(link.aaa_address(), None);
            assert_eq!(tun.lock().unwrap().contains(&aaa_ip), already_on_tun);
        }
    }

    /// AAA kept unused in v1 (zl-zpr-dev-context docs/ZODE_LINKS.md,
    /// Design decisions, "AAA kept, unused"): `install_aaa` puts the AAA on
    /// the TUN through `TunCtl::add_authentication_address`, the only way
    /// [AaaTunCtl] accepts an address.
    #[tokio::test(flavor = "local")]
    async fn install_aaa_adds_an_authentication_address() {
        let aaa_ip: std::net::IpAddr = "fd5a:5052:0:aaa::1".parse().unwrap();
        let tun = Arc::new(Mutex::new(Vec::new()));
        let asm = Arc::new(create_assembly(TestAssemblyBuilder {
            tun_ctl: Some(Box::new(AaaTunCtl(tun.clone()))),
            ..TestAssemblyBuilder::new()
        }));
        let link = LinkStateWrapper::new(3, LinkType::NodeToNode);
        link.install_aaa(&asm, aaa_ip.into()).unwrap();
        assert_eq!(*tun.lock().unwrap(), vec![aaa_ip]);
    }

    /// AAA kept unused in v1 (zl-zpr-dev-context docs/ZODE_LINKS.md,
    /// Design decisions, "AAA kept, unused"): `allocate_aaa` takes nothing
    /// until the visa service has configured a pool. An AAA it takes and
    /// `process_assigned_aaa` records on a link goes back to the pool when
    /// link cleanup runs, whatever the link type: the pool holds no
    /// reservation afterwards.
    #[tokio::test(flavor = "local")]
    async fn allocated_aaa_is_given_back_by_link_cleanup() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        assert_eq!(
            LinkStateWrapper::allocate_aaa(&asm),
            None,
            "no pool, no AAA"
        );

        *asm.address_pool.lock().unwrap() = Some(
            crate::address_pool::AddressPool::new("fd5a:5052:0:aaa::/64".parse().unwrap()).unwrap(),
        );
        let reservations =
            |asm: &Assembly| asm.address_pool.lock().unwrap().as_ref().unwrap().len();
        let aaa = LinkStateWrapper::allocate_aaa(&asm).expect("an AAA from the pool");
        assert_eq!(reservations(&asm), 1);

        let link = LinkStateWrapper::new(3, LinkType::NodeToNode);
        link.process_assigned_aaa(&asm, aaa).unwrap();
        link.test_set_state(LinkState::Closing);
        let _ = link.clean_up_link_state(&asm);
        assert_eq!(link.aaa_address(), None);
        assert_eq!(reservations(&asm), 0, "cleanup gave the AAA back");
    }

    #[tokio::test]
    async fn aaa_assignment_waits_for_cleanup_ownership() {
        use std::net::IpAddr;

        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let link = LinkStateWrapper::new(3, LinkType::NodeToNode);
        let aaa = "fd5a:5052:0:aaa::1".parse::<IpAddr>().unwrap().into();
        let data = link.locked_data.lock().unwrap();
        std::thread::scope(|scope| {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let asm = &asm;
            let link = &link;
            scope.spawn(move || {
                started_tx.send(()).unwrap();
                link.process_assigned_aaa(asm, aaa).unwrap();
                done_tx.send(()).unwrap();
            });
            started_rx.recv().unwrap();
            let waited = done_rx.recv_timeout(Duration::from_millis(100)).is_err();
            let unchanged = link.aaa_address().is_none();
            drop(data);
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(waited);
            assert!(unchanged);
        });
        assert_eq!(link.aaa_address(), Some(aaa));
    }

    /// A test assembly whose links can be started: `process_start` hands
    /// the link to the key manager, which needs a noise keypair and a
    /// certificate exchange.
    fn keyable_assembly() -> Arc<Assembly> {
        Arc::new(create_assembly(TestAssemblyBuilder {
            self_noise_keypair: Some(crate::km_noise::NoiseKeypair::generate()),
            certx: Some(crate::km_cert_exchange::KmCertExchange::new(None, None)),
            ..TestAssemblyBuilder::new()
        }))
    }

    /// A keyable assembly whose stored topology names `peer_cns`
    /// (zl-zipline#220), each of which owns its link to this Zode.
    fn zode_assembly(peer_cns: &[&str]) -> Arc<Assembly> {
        use crate::peer_table::test::topology_link;
        let asm = keyable_assembly();
        let mut cfg = (*asm.config.get()).clone();
        cfg.zpr_addr = vec!["fd5a:5052::10".parse().unwrap()];
        asm.config.write(cfg);
        *asm.topology.write().unwrap() = peer_cns.iter().map(|cn| topology_link(cn)).collect();
        asm
    }

    /// zl-zipline#220: a Zode link whose verified certificate CN is not in
    /// this Zode's topology is closed at KeyingDone and never says Hello.
    #[tokio::test(start_paused = true)]
    async fn test_zode_link_cn_outside_topology_is_closed_at_keying_done() {
        LocalSet::new()
            .run_until(async {
                let asm = zode_assembly(&["relay.zpr"]);
                let link_id = zode_link_keyed(&asm, ZodeEnd::Answerer, "stranger.zpr");
                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Closing);
            })
            .await
    }

    /// zl-zipline#220: a Zode link whose verified CN is in the topology
    /// proceeds to Hello.
    #[tokio::test(start_paused = true)]
    async fn test_zode_link_cn_in_topology_proceeds_to_hello() {
        LocalSet::new()
            .run_until(async {
                let asm = zode_assembly(&["relay.zpr"]);
                let link_id = zode_link_keyed(&asm, ZodeEnd::Answerer, "relay.zpr");
                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Helloing);
            })
            .await
    }

    /// The substrate egress queue a Zode test assembly sends through.
    type EgressRx = crate::packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>;

    /// A Zode test assembly in node mode with ZPR address `fd5a:5052::10`,
    /// above the `fd5a:5052::9` of [crate::peer_table::test::topology_link],
    /// so a topology peer owns its link to it; link keys for `self_cn` signed
    /// by a fresh test CA; and an egress queue the test can read
    /// (zl-zipline#250).
    fn zode_keys_assembly(self_cn: &str) -> (Arc<Assembly>, EgressRx) {
        let (egress_tx, egress_rx) = crate::packet_queue::packet_queue(64);
        let ca = crate::pki::TestCa::new("zode-ca");
        let (keypair, certx) = crate::assembly::test::zode_link_keys(&ca, self_cn);
        let mut cfg = <config::Config as std::default::Default>::default();
        cfg.zpr_addr = vec!["fd5a:5052::10".parse().unwrap()];
        let asm = Arc::new(create_assembly(TestAssemblyBuilder {
            self_noise_keypair: Some(keypair),
            certx: Some(certx),
            config: Some(rcu::RcuBox::new(cfg)),
            mgmt_substrate_egress: Some(crate::queues::MgmtSubstrateEgress::new(egress_tx)),
            ..TestAssemblyBuilder::new()
        }));
        (asm, egress_rx)
    }

    /// The ZDP packet types waiting in the egress queue, oldest first.
    async fn sent_packet_types(egress: &mut EgressRx) -> Vec<crate::zdp::ZdpPacketType> {
        use zerocopy::FromBytes;
        tokio::task::yield_now().await;
        let mut types = Vec::new();
        loop {
            let buf = vec![0u8; config::PACKET_BUFFER_SIZE].into_boxed_slice();
            let Ok(pkt) = egress.try_recv(buf) else {
                return types;
            };
            let (hdr, _) = crate::zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
            types.push(hdr.packet_type);
        }
    }

    /// A Zode link in Keying whose established SA holds a verified
    /// certificate for `peer_cn`, as if keying had just finished, with this
    /// Zode at `end` of it.
    fn zode_link_keyed(asm: &Arc<Assembly>, end: ZodeEnd, peer_cn: &str) -> LinkId {
        let link_id = crate::peer_table::test::insert_zode_peer_with_verified_cn(
            asm,
            peer_cn,
            LinkState::Keying,
        );
        let peer = asm.peer_table.get(link_id).unwrap();
        peer.link_state_machine.set_zode_end(end).unwrap();
        peer.link_state_machine.test_set_keying();
        link_id
    }

    /// The dialer end of a Zode link to `peer_cn`.
    fn dialer(peer_cn: &str) -> ZodeEnd {
        ZodeEnd::Dialer {
            peer_cn: peer_cn.to_owned(),
        }
    }

    /// A successful HelloResponse with the given extras.
    fn hello_response(
        aaa_address: Option<IpAddress>,
        oidc_idps: Option<Vec<auth::OidcIdpInfo>>,
        vs_bootstrap: bool,
    ) -> LinkEvent {
        LinkEvent::ReceivedHelloResponse {
            status: ResponseCode::Success,
            aaa_address,
            oidc_idps,
            vs_bootstrap,
        }
    }

    /// zl-zipline#250: a Zode link starts keying on either end when this
    /// Zode has CA-signed link keys. The dialer's key manager initiates.
    #[tokio::test(start_paused = true)]
    async fn test_zode_link_start_enters_keying_on_both_ends() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                let iface =
                    zpr_utils::net_defs::ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
                let dialed = asm
                    .start_zode_link(
                        &SubstrateAddr::from(([127, 0, 0, 1], 7001)),
                        &iface,
                        dialer("b.zpr"),
                    )
                    .unwrap()
                    .get();
                let answered = asm
                    .start_zode_link(
                        &SubstrateAddr::from(([127, 0, 0, 1], 7002)),
                        &iface,
                        ZodeEnd::Answerer,
                    )
                    .unwrap()
                    .get();
                for link_id in [dialed, answered] {
                    assert_eq!(link_state_of(&asm, link_id), LinkState::Keying);
                    assert_eq!(
                        asm.peer_table
                            .get(link_id)
                            .unwrap()
                            .link_state_machine
                            .get_link_type(),
                        LinkType::NodeToNode
                    );
                }
                assert!(
                    asm.peer_table
                        .get(dialed)
                        .unwrap()
                        .link_state_machine
                        .is_zode_dialer()
                );
            })
            .await
    }

    /// zl-zipline#250 (#220 g41 q4): a Zode without a CA certificate starts
    /// no Zode link: the start fails closed and leaves no peer entry.
    #[tokio::test(start_paused = true)]
    async fn test_zode_link_start_without_ca_fails_closed() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly();
                let before = asm.peer_table.len();
                let iface =
                    zpr_utils::net_defs::ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
                assert!(
                    asm.start_zode_link(
                        &SubstrateAddr::from(([127, 0, 0, 1], 7003)),
                        &iface,
                        dialer("b.zpr"),
                    )
                    .is_err()
                );
                assert_eq!(asm.peer_table.len(), before);
            })
            .await
    }

    /// zl-zipline#250: the dialer says Hello after keying, goes Active on
    /// the answer, and starts keep-alives. Nothing AAA-related is set up.
    #[tokio::test(start_paused = true)]
    async fn test_zode_dialer_walks_keying_hello_active() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress) = zode_keys_assembly("a.zpr");
                let link_id = zode_link_keyed(&asm, dialer("b.zpr"), "b.zpr");

                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Helloing);
                assert_eq!(
                    sent_packet_types(&mut egress).await,
                    vec![crate::zdp::ZdpPacketType::HelloRequest],
                    "the dialer sends the HelloRequest"
                );

                asm.process_link_state_event(link_id, hello_response(None, None, false))
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Active);
                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(peer.link_state_machine.is_ready());
                assert!(peer.link_state_machine.aaa_address().is_none());
            })
            .await
    }

    /// zl-zipline#250 (gaps 5 and 6): a HelloResponse on a Zode link that
    /// carries an AAA address, identity providers or the visa-service
    /// bootstrap flag is refused, and the link closes.
    #[tokio::test(start_paused = true)]
    async fn test_zode_dialer_refuses_adapter_hello_response() {
        LocalSet::new()
            .run_until(async {
                let aaa = IpAddress::new_from_std(&"fd5a:5052:9::1".parse().unwrap());
                let idp = auth::OidcIdpInfo {
                    issuer: "https://idp.test".to_string(),
                    client_id: "c".to_string(),
                    client_secret: None,
                    scopes: Vec::new(),
                    allow_offline_access: false,
                };
                for response in [
                    hello_response(Some(aaa), None, false),
                    hello_response(None, None, true),
                    hello_response(None, Some(vec![idp.clone()]), false),
                ] {
                    let (asm, _egress) = zode_keys_assembly("a.zpr");
                    let link_id = zode_link_keyed(&asm, dialer("b.zpr"), "b.zpr");
                    asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                        .unwrap();
                    asm.process_link_state_event(link_id, response).unwrap();
                    assert_eq!(link_state_of(&asm, link_id), LinkState::Closing);
                }
            })
            .await
    }

    /// zl-zipline#250: the answerer waits for the dialer's HelloRequest,
    /// answers it with no AAA address, and goes Active.
    #[tokio::test(start_paused = true)]
    async fn test_zode_answerer_walks_keying_hello_active() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress) = zode_keys_assembly("a.zpr");
                *asm.topology.write().unwrap() =
                    vec![crate::peer_table::test::topology_link("b.zpr")];
                let link_id = zode_link_keyed(&asm, ZodeEnd::Answerer, "b.zpr");

                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Helloing);
                assert!(
                    sent_packet_types(&mut egress).await.is_empty(),
                    "the answerer does not say Hello first"
                );

                asm.process_link_state_event(link_id, LinkEvent::ReceivedHelloRequest)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Active);
                assert_eq!(
                    sent_packet_types(&mut egress).await,
                    vec![crate::zdp::ZdpPacketType::HelloResponse]
                );
                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(peer.link_state_machine.is_ready());
                assert!(peer.link_state_machine.aaa_address().is_none());
            })
            .await
    }

    /// zl-zipline#250: a HelloRequest is the dialer's to send; a dialer
    /// that receives one refuses it.
    #[tokio::test(start_paused = true)]
    async fn test_zode_dialer_refuses_hello_request() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                let link_id = zode_link_keyed(&asm, dialer("b.zpr"), "b.zpr");
                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert!(
                    asm.process_link_state_event(link_id, LinkEvent::ReceivedHelloRequest)
                        .is_err()
                );
                assert_eq!(link_state_of(&asm, link_id), LinkState::Helloing);
            })
            .await
    }

    /// zl-zipline#250: keying is bounded on both ends of a Zode link by
    /// ZODE_KEYING_TIMEOUT; a link still keying then closes.
    #[tokio::test(start_paused = true)]
    async fn test_zode_keying_timeout_closes_the_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                let iface =
                    zpr_utils::net_defs::ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
                let answered = asm
                    .start_zode_link(
                        &SubstrateAddr::from(([127, 0, 0, 1], 7004)),
                        &iface,
                        ZodeEnd::Answerer,
                    )
                    .unwrap()
                    .get();
                let dialed = asm
                    .start_zode_link(
                        &SubstrateAddr::from(([127, 0, 0, 1], 7005)),
                        &iface,
                        dialer("b.zpr"),
                    )
                    .unwrap()
                    .get();
                tokio::time::sleep(config::ZODE_KEYING_TIMEOUT - Duration::from_millis(100)).await;
                assert_eq!(link_state_of(&asm, answered), LinkState::Keying);
                tokio::time::sleep(Duration::from_millis(200)).await;
                for link_id in [answered, dialed] {
                    assert_ne!(
                        asm.peer_table
                            .get(link_id)
                            .map(|p| p.link_state_machine.get_state()),
                        Some(LinkState::Keying),
                        "a Zode link must not outlive its keying bound"
                    );
                }
            })
            .await
    }

    /// zl-zipline#250: the Hello exchange is bounded on both ends of a Zode
    /// link by ZODE_HELLO_TIMEOUT.
    #[tokio::test(start_paused = true)]
    async fn test_zode_hello_timeout_closes_the_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                *asm.topology.write().unwrap() =
                    vec![crate::peer_table::test::topology_link("c.zpr")];
                let dialed = zode_link_keyed(&asm, dialer("b.zpr"), "b.zpr");
                let answered = zode_link_keyed(&asm, ZodeEnd::Answerer, "c.zpr");
                for link_id in [dialed, answered] {
                    asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                        .unwrap();
                    assert_eq!(link_state_of(&asm, link_id), LinkState::Helloing);
                    fire_current_timeout(&asm, link_id);
                    assert_eq!(link_state_of(&asm, link_id), LinkState::Closing);
                }
            })
            .await
    }

    /// zl-zipline#250: a closed Zode link drops its peer entry on either
    /// end and never restarts itself: only the link's owner redials.
    #[tokio::test(start_paused = true)]
    async fn test_closed_zode_link_drops_its_peer_entry() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                let dialed = zode_link_keyed(&asm, dialer("b.zpr"), "b.zpr");
                let answered = zode_link_keyed(&asm, ZodeEnd::Answerer, "c.zpr");
                for link_id in [dialed, answered] {
                    complete_close_of(&asm, link_id);
                    assert!(asm.peer_table.get(link_id).is_none());
                }
                // Long after any holddown a restart would have waited.
                tokio::time::sleep(Duration::from_secs(10)).await;
                assert!(asm.peer_table.get(dialed).is_none());
            })
            .await
    }

    /// Complete a close of `link_id` (Closing -> CloseDone), as the
    /// terminate handshake does.
    fn complete_close_of(asm: &Arc<Assembly>, link_id: LinkId) {
        asm.peer_table
            .get(link_id)
            .unwrap()
            .link_state_machine
            .test_set_state(LinkState::Closing);
        asm.process_link_state_event(link_id, LinkEvent::CloseDone)
            .unwrap();
    }

    /// The NodeToNode links whose verified peer CN is `cn`.
    fn zode_links_to(asm: &Arc<Assembly>, cn: &str) -> Vec<LinkId> {
        let mut links = Vec::new();
        asm.peer_table.for_each(|(id, peer)| {
            if peer.link_state_machine.get_link_type() == LinkType::NodeToNode
                && peer.verified_peer_cn().as_deref() == Some(cn)
            {
                links.push(id.get());
            }
        });
        links
    }

    /// Let spawned link cleanup (key manager shutdown, CloseDone) run.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// Rule 5: an accepted inbound link from a peer that already has an
    /// established link replaces it. The old link's id is dropped from the
    /// peer table and its key-management state, and exactly one link
    /// remains.
    #[tokio::test(start_paused = true)]
    async fn test_zode_inbound_link_replaces_established_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                *asm.topology.write().unwrap() =
                    vec![crate::peer_table::test::topology_link("b.zpr")];
                let old = zode_link_keyed(&asm, ZodeEnd::Answerer, "b.zpr");
                asm.peer_table
                    .get(old)
                    .unwrap()
                    .link_state_machine
                    .test_set_active();
                let new = zode_link_keyed(&asm, ZodeEnd::Answerer, "b.zpr");

                asm.process_link_state_event(new, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, new), LinkState::Helloing);
                settle().await;
                assert!(asm.peer_table.get(old).is_none(), "the old link is gone");
                assert!(asm.peer_table.clone_km_manager(old).is_none());
                assert_eq!(zode_links_to(&asm, "b.zpr"), vec![new]);
            })
            .await
    }

    /// Rule 5 does not apply to a refused link: an inbound link that fails
    /// rule 3 leaves the established link alone.
    #[tokio::test(start_paused = true)]
    async fn test_refused_zode_link_does_not_replace_established_link() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                let old = zode_link_keyed(&asm, ZodeEnd::Answerer, "b.zpr");
                asm.peer_table
                    .get(old)
                    .unwrap()
                    .link_state_machine
                    .test_set_active();
                // b.zpr has left the topology: a new link from it is refused.
                let new = zode_link_keyed(&asm, ZodeEnd::Answerer, "b.zpr");
                asm.process_link_state_event(new, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, new), LinkState::Closing);
                settle().await;
                assert_eq!(link_state_of(&asm, old), LinkState::Active);
            })
            .await
    }

    /// The walkthrough "the higher-address Zode dials anyway": the
    /// lower-address Zode owns the link, so it refuses the dial after
    /// keying, and no second link can form.
    #[tokio::test(start_paused = true)]
    async fn test_higher_address_zode_dialing_anyway_is_refused() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                // This Zode is fd5a:5052::10; the peer is higher.
                *asm.topology.write().unwrap() = vec![crate::peer_table::test::topology_link_at(
                    "b.zpr",
                    "fd5a:5052::20".parse().unwrap(),
                )];
                let link_id = zode_link_keyed(&asm, ZodeEnd::Answerer, "b.zpr");
                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Closing);
            })
            .await
    }

    /// A dialer refuses a peer whose verified CN is not the one it dialed.
    #[tokio::test(start_paused = true)]
    async fn test_zode_dialer_refuses_a_different_cn() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                let link_id = zode_link_keyed(&asm, dialer("relay.zpr"), "impostor.zpr");
                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Closing);
            })
            .await
    }

    /// The current FSM state of `link_id`.
    fn link_state_of(asm: &Arc<Assembly>, link_id: LinkId) -> LinkState {
        asm.peer_table
            .get(link_id)
            .unwrap()
            .link_state_machine
            .get_state()
    }

    /// Deliver a Timeout event carrying the link's CURRENT logical clock,
    /// as the real timeout task does.
    fn fire_current_timeout(asm: &Arc<Assembly>, link_id: LinkId) {
        let logical_clock = asm
            .peer_table
            .get(link_id)
            .unwrap()
            .link_state_machine
            .test_logical_clock();
        asm.process_link_state_event(link_id, LinkEvent::Timeout { logical_clock })
            .unwrap();
    }

    /// A `Start` begins a fresh ZDP-R session, so it must reset the link's
    /// sender and receiver: a peer whose sequence numbers restart at 0
    /// would otherwise have every packet of the new session classified as
    /// an already-seen duplicate, dropped without processing but still
    /// acknowledged, so the link never gets past Helloing.
    #[tokio::test(start_paused = true)]
    async fn test_start_resets_zdpr_session() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress) = zode_keys_assembly("a.zpr");
                let link_id = crate::peer_table::test::insert_zode_peer_with_verified_cn(
                    &asm,
                    "b.zpr",
                    LinkState::Inactive,
                );
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .set_zode_end(dialer("b.zpr"))
                    .unwrap();

                // A previous dock attempt received the peer's first two
                // management packets, then the link was torn down.
                let generation_before = {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    let mut recv = peer.zdpr_recv.lock().unwrap();
                    assert!(recv.should_process_packet(0));
                    recv.process_packet(0);
                    recv.process_packet(1);
                    assert!(
                        !recv.should_process_packet(0),
                        "test precondition: sequence number 0 is now a duplicate"
                    );
                    drop(recv);
                    peer.zdpr_generation()
                };

                asm.process_link_state_event(link_id, LinkEvent::Start)
                    .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Keying);
                assert!(
                    peer.zdpr_recv.lock().unwrap().should_process_packet(0),
                    "stale receive window survived into the new session: the \
                     peer's restarted sequence numbers would be discarded as \
                     duplicates"
                );
                assert_ne!(
                    peer.zdpr_generation(),
                    generation_before,
                    "the new session must be distinguishable from the old one"
                );
            })
            .await
    }

    /// zipline#113: one missed keep-alive echo must NOT kill an Active link.
    /// The link tolerates consecutive misses and only goes to `Error` (and
    /// closes) on the KEEP_ALIVE_MAX_MISSES'th consecutive miss; a keep-alive
    /// response in between resets the counter. Before the fix, the FIRST
    /// timeout with an outstanding echo set `Error` and initiated the close.
    #[tokio::test]
    async fn test_keep_alive_tolerates_misses_and_resets_on_response() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = crate::peer_table::test::insert_zode_peer_with_verified_cn(
                    &asm,
                    "b.zpr",
                    LinkState::Active,
                );

                // First timeout: no echo outstanding -> sends a fresh echo.
                fire_current_timeout(&asm, link_id);
                assert_eq!(link_state_of(&asm, link_id), LinkState::Active);

                // Misses 1 and 2: echo outstanding, timeout fires. The link
                // must stay Active (tolerated) and keep echoing.
                for miss in 1..config::KEEP_ALIVE_MAX_MISSES {
                    fire_current_timeout(&asm, link_id);
                    assert_eq!(
                        link_state_of(&asm, link_id),
                        LinkState::Active,
                        "link must survive consecutive keep-alive miss {miss}"
                    );
                }

                // A keep-alive response arrives: counter resets.
                asm.process_link_state_event(link_id, LinkEvent::ReceivedKeepAliveResponse)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Active);

                // Fresh echo, then the full tolerated run of misses again —
                // proving the reset (without it the counter would hit the
                // limit early).
                fire_current_timeout(&asm, link_id);
                for miss in 1..config::KEEP_ALIVE_MAX_MISSES {
                    fire_current_timeout(&asm, link_id);
                    assert_eq!(
                        link_state_of(&asm, link_id),
                        LinkState::Active,
                        "post-reset miss {miss} must still be tolerated"
                    );
                }

                // The final consecutive miss is fatal: the link leaves Active
                // and starts closing.
                fire_current_timeout(&asm, link_id);
                assert_ne!(
                    link_state_of(&asm, link_id),
                    LinkState::Active,
                    "miss {} must close the link",
                    config::KEEP_ALIVE_MAX_MISSES
                );
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                assert!(rx.is_empty());

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_ok());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_explicit_cancel_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                sm.lock().unwrap().cancel_timeout();

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_err());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_implicit_cancel_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                sm.lock().unwrap().set_state(LinkState::Keying);

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_err());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_reschedule_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx1, rx1) = oneshot::channel();
                let (tx2, rx2) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx1);

                tokio::time::sleep(Duration::from_secs(4)).await;

                set_timeout(&sm, Duration::from_secs(5), tx2);

                tokio::time::sleep(Duration::from_secs(4)).await;

                assert!(rx1.await.is_err());
                assert!(rx2.is_empty());

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx2.await.is_ok());
            })
            .await
    }

    fn set_timeout(sm: &Arc<Mutex<LinkStateMachine>>, duration: Duration, tx: oneshot::Sender<()>) {
        let sm_cb = sm.clone();
        sm.lock()
            .unwrap()
            .set_timeout_callback(duration, move |lc| {
                if sm_cb.lock().unwrap().logical_clock != lc {
                    return;
                }
                tx.send(()).unwrap();
            });
    }
}
