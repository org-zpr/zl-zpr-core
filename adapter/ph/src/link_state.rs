use crate::auth;
use crate::auth_agent::AuthFailureReason;
use crate::counters::ManagementCounterType;
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::mgmt;
use crate::pki;
use crate::prelude::*;
use crate::sample_ring::SampleRing;
use crate::special_peers;
use crate::special_peers::SpecialPeerName;
use crate::zdp::{ResponseCode, TerminateReason};

use std::fmt::{Display, Formatter};
use std::num::NonZero;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;
use zpr::addrs::ZPRNET_PREFIX_LEN;
use zpr_utils::net_defs::IpAddress;

/// Encrypted link lifecycle; actor authorization is independent
/// ([crate::actor_auth]).
///
/// Zipline additions to upstream #1410's link layer (search "zipline#"):
/// OIDC IdP advertisement in Hello (zipline#12), keep-alive miss tolerance
/// and VSConn recycling (zipline#113), the node keying timeout
/// (zipline#173), idle mode with auto-connect off (zipline#28), no restart
/// after a fatal local activation failure (zipline#157), the renewal tick
/// (zipline#45), and a fresh ZDP-R session per Start.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkState {
    Inactive,
    Keying,
    Helloing,
    /// disconnecting from visa service; only entered for the node->VS adapter link
    Disconnecting(TerminateReason),
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
    AssignedAAA(IpAddress), // Assigned AAA address for this link
    ReceivedHelloResponse {
        status: ResponseCode,
        aaa_address: Option<IpAddress>,
        oidc_idps: Option<Vec<auth::OidcIdpInfo>>,
        vs_bootstrap: bool,
    },

    ReceivedKeepAliveResponse,
    ReceivedTerminateLink(TerminateReason),
    ReceivedTerminateAck,
    ReceivedDisconnectAck, // from visa service
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
    #[error("This operation is not supported yet")]
    OperationNotSupportedYet,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkType {
    Internal,
    AdapterToNode,
    #[allow(dead_code)]
    NodeToNode, // Currently unsupported
    NodeToAdapter,
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
    /// Zipline (zipline#12): OIDC identity providers advertised by our peer
    /// in HelloResponse, if any.
    oidc_idps: Option<Vec<auth::OidcIdpInfo>>,
    installed_aaa: bool,
}

impl LinkData {
    pub fn new() -> Self {
        Self {
            echo_success: 0,
            echo_timeout: 0,
            latency_data: SampleRing::new(Duration::ZERO),
            oidc_idps: None,
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

    /// Read the assigned AAA without taking the link-data mutex.
    pub fn aaa_address(&self) -> Option<IpAddress> {
        *self.aaa_address.get()
    }

    /// Zipline (zipline#12): the OIDC IdPs our peer advertised in Hello.
    pub fn oidc_idps(&self) -> Vec<auth::OidcIdpInfo> {
        self.locked_data
            .lock()
            .unwrap()
            .oidc_idps
            .clone()
            .unwrap_or_default()
    }

    /// Test-only: pretend a HelloResponse advertised these IdPs.
    #[cfg(test)]
    pub fn test_set_oidc_idps(&self, idps: Vec<auth::OidcIdpInfo>) {
        self.locked_data.lock().unwrap().oidc_idps = Some(idps);
    }

    /// Test-only: force the FSM into a state without walking the transitions.
    #[cfg(test)]
    pub fn test_set_state(&self, state: LinkState) {
        self.locked_fsm.lock().unwrap().set_state(state);
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

    fn process_hello_request(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        if self.link_type != LinkType::NodeToAdapter || locked_fsm.state != LinkState::Helloing {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloRequest",
            ));
        }
        let is_vs = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
            .is_some_and(|id| id.get() == self.id);
        let aaa = asm.address_pool.lock().unwrap().as_mut().map(|pool| {
            let aaa = pool.get_aaa_address();
            debug!(target: LINK_STATE, "allocated AAA {aaa}; {} active reservations", pool.len());
            aaa
        });
        if aaa.is_none() && !is_vs {
            mgmt::requests::send_hello_error_response(
                asm,
                self.id,
                ResponseCode::TemporarilyUnavailable,
            )
            .enqueue();
            drop(locked_fsm);
            return self.initiate_close(asm, TerminateReason::Other);
        }
        if let Some(aaa) = aaa {
            self.process_assigned_aaa(asm, aaa)?;
        }
        mgmt::requests::send_hello_success_response(
            asm,
            self.id,
            0,
            &crate::auth_agent::advertised_oidc_idps(asm, self.id),
            aaa,
            is_vs,
        )
        .enqueue();
        self.run_active(asm, locked_fsm)
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
        if self.link_type != LinkType::AdapterToNode || locked_fsm.state != LinkState::Helloing {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloResponse",
            ));
        }
        if response.aaa_address.is_none() && !response.vs_bootstrap {
            return Err(LinkStateError::InvalidOperation(
                "ordinary link established without AAA".into(),
            ));
        }
        {
            let mut data = self.locked_data.lock().unwrap();
            self.aaa_address.write(response.aaa_address);
            data.oidc_idps = response.oidc_idps;
        }
        if let Some(aaa) = response.aaa_address {
            let exists = asm
                .tun_ctl
                .has_address(aaa.into())
                .map_err(|e| LinkStateError::InvalidOperation(format!("inspect AAA: {e}")))?;
            asm.tun_ctl
                .add_authentication_address(aaa.into(), ZPRNET_PREFIX_LEN)
                .map_err(|e| LinkStateError::InvalidOperation(format!("configure AAA: {e}")))?;
            self.locked_data.lock().unwrap().installed_aaa = !exists;
        }
        asm.tun_ctl
            .set_carrier(true)
            .map_err(|e| LinkStateError::InvalidOperation(format!("enable AAA carrier: {e}")))?;
        self.run_active(asm, locked_fsm)?;
        if let Some(peer) = asm.peer_table.get(self.id) {
            peer.actor_auth.link_ready(asm);
        }
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
            LinkEvent::AssignedAAA(addr) => self.process_assigned_aaa(asm, addr),
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
            LinkEvent::ReceivedDisconnectAck => self.process_disconnect_ack(asm),
            LinkEvent::Close(code) => self.initiate_close(asm, code),
            LinkEvent::CloseDone => Ok(self.complete_close(asm)),
            LinkEvent::Error => self.process_error_response(asm),
            LinkEvent::Timeout { logical_clock } => self.process_timeout(asm, logical_clock),
        }
    }

    /// Start an inactive link/tether
    /// Transitions from Inactive -> Keying
    /// Will trigger key management messages to be sent if this is an adapter
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

        // A Start also begins a fresh ZDP-R session.  An adapter keeps one
        // peer table entry per link for the life of the process, but the
        // node it docks with allocates a new link -- and so a new ZDP-R
        // session, restarting at sequence number 0 -- for every attempt.
        // Carrying the previous attempt's sequence numbers and receive
        // window into this one would have each side silently discard the
        // other's traffic.
        if let Some(peer) = asm.peer_table.get(link_id) {
            peer.reset_zdpr_session();
        }

        info!(target: LINK_STATE, "{} started.  Keying in progress", asm.formatted_link_id(link_id));

        match self.link_type {
            LinkType::AdapterToNode => {
                km_multiplexor::add_adapter_link(
                    asm,
                    link_id,
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 5, 6),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                Ok(())
            }
            LinkType::NodeToNode => {
                error!(target: LINK_STATE, "Error: Node to node not supported yet");
                locked_fsm.set_state(LinkState::Error);
                Err(LinkStateError::OperationNotSupportedYet)
            }
            LinkType::NodeToAdapter => {
                km_multiplexor::add_node_link(
                    asm,
                    link_id,
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 3, 4),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                // The node is the noise responder and never re-initiates,
                // so bound how long it waits for keying to finish
                // (zipline#173). `KeyingDone` moves the FSM to Helloing,
                // and that state change cancels this timer.
                self.set_timeout(asm, &mut locked_fsm, config::NODE_KEYING_TIMEOUT);
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
    /// Will trigger a Hello to be sent if this is an adapter
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

        if let Some(ref peer_cert) = sa.peer_cert {
            let cert = peer_cert.get_cert();
            let is_verified = peer_cert.is_verified();

            // Note, keying will have failed if we requested verification (i.e. were
            // connecting to node) but the cert couldn't be verified.  So here,
            // we only need to verify the case that we are only conditionally verifying
            // (i.e., we are being connected to by a special adapter).

            if is_verified {
                info!(target: LINK_STATE, "{} has verified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            } else {
                warn!(target: LINK_STATE, "{} has unverified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            }

            let subject_der = match pki::subject_der(cert) {
                Ok(der) => der,
                Err(e) => {
                    warn!(target: LINK_STATE, "{} cannot encode certificate subject DN: {e}", asm.formatted_link_id(link_id));
                    Vec::new()
                }
            };

            if !is_verified {
                for name in special_peers::special_peer_names_from_subject_der(&subject_der) {
                    warn!(
                        target: LINK_STATE,
                        "{} presented unverified certificate claiming special peer name {name:?}; ignoring", asm.formatted_link_id(link_id)
                    );
                }
            } else {
                // assign special-peer name if this peer is special
                for name in special_peers::special_peer_names_from_subject_der(&subject_der) {
                    match asm.peer_table.assign_special_name(name, link_id) {
                        Ok(()) => {
                            info!(target: LINK_STATE, "{} assigned special name {name:?}", asm.formatted_link_id(link_id))
                        }
                        Err(_) => {
                            warn!(target: LINK_STATE, "Unable to assign {} special name {name:?}", asm.formatted_link_id(link_id))
                        }
                    }
                }
            }
        }

        // zl-zipline#220: a Zode link must lead to a peer this Zode was told
        // to link with; anything else is closed before Hello.
        if self.link_type == LinkType::NodeToNode {
            let peer_cn = peer_state.verified_peer_cn();
            if !peer_cn.as_deref().is_some_and(|cn| asm.peer_cn_allowed(cn)) {
                warn!(target: LINK_STATE, "{} peer certificate CN {peer_cn:?} is not in this Zode's topology; closing", asm.formatted_link_id(link_id));
                drop(sa);
                drop(peer_state);
                drop(locked_fsm);
                return self.initiate_close(asm, TerminateReason::Reset);
            }
        }

        debug!(target: LINK_STATE, "{} finished keying.  Starting hello", asm.formatted_link_id(link_id));

        locked_fsm.set_state(LinkState::Helloing);

        // IF this is an adapter, it's expected to issue the hello
        if self.link_type == LinkType::AdapterToNode {
            // Grab public key from keypair to send in hello request
            let pubkey = x25519_dalek::PublicKey::from(&asm.a2a_dh_keypair);
            mgmt::requests::send_hello_request(asm, self.id, pubkey).enqueue();
            self.set_timeout(asm, &mut locked_fsm, config::LINK_HELLO_TIMEOUT);
            debug!(
                target: LINK_STATE,
                "{} sent HelloRequest.  Waiting for other side to respond.", asm.formatted_link_id(link_id)
            );
        }
        // Otherwise we are a node so wait for an adapter to reach out
        Ok(())
    }

    /// This is called when we receive an AAA address assignment.
    /// Does not generate an error.
    fn process_assigned_aaa(
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
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                // Timeout here means we give up on the link.
                error!(target: LINK_STATE, "{}: timed out in state {:?}", asm.formatted_link_id(self.id), locked_fsm.state);
                locked_fsm.set_state(LinkState::Error);
                drop(locked_fsm);
                return self.initiate_close(asm, TerminateReason::RequestTimedOut);
            }

            (LinkType::NodeToAdapter, LinkState::Keying) => {
                // The adapter never completed the noise handshake within
                // NODE_KEYING_TIMEOUT (zipline#173). Drop the link: the
                // close path removes the peer entry and stops the KM, and
                // an adapter that is still alive will dock afresh.
                warn!(target: LINK_STATE, "{}: keying not completed within {:?}, closing link",
                    asm.formatted_link_id(self.id), config::NODE_KEYING_TIMEOUT);
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

    /// Nodes only. Check if this is the link to the adapter in front of the visa service
    /// and if so try to de-register this node from the VS and also stop the VSConn.
    ///
    /// If the link is still working then this can also try to send a polite
    /// "de-register" message to the visa service before we shut off our
    /// VSConn processor.
    fn maybe_disconnect_visa_service_client(
        &self,
        asm: &Arc<Assembly>,
        deregister: bool,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        if matches!(reason, TerminateReason::Shutdown) {
            locked_fsm.shutting_down = true;
        }

        if matches!(self.link_type, LinkType::NodeToAdapter) {
            let link_id = self.id;
            let vs_id = asm
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
            if vs_id.is_some() && vs_id.unwrap().get() == link_id {
                // Only a genuine shutdown stops the VSConn run loop: `Stop`
                // makes `run_with_reconnect` return permanently, after which
                // every VS API call fails `ConnClosed` forever (zipline#113).
                // A failure-driven close (keep-alive timeout, link error)
                // falls through to the ordinary close below — but VSConn's
                // current run loop must be explicitly restarted: if the
                // Cap'n Proto TCP connection survived the link flap (or the
                // failure was ZDP-only), the loop would otherwise stay
                // parked, never emit RunLoopExits/RunLoopStarts, and
                // vs_worker — gated on RunLoopStarts before it re-runs
                // register_vss — would leave the replacement link's
                // deferred_vs_connect pending forever. `restart` recycles
                // the loop without stopping the reconnect manager; if the
                // loop is already mid-dial or in its reconnect delay, the
                // command is discarded, which is fine.
                if !matches!(reason, TerminateReason::Shutdown) {
                    info!(target: LINK_STATE,
                        "{}: VS adapter link closing ({reason:?}); restarting VSConn run loop for reconnect",
                        asm.formatted_link_id(link_id));
                    if let Some(vsconn) = asm.vsconn.as_ref() {
                        let restart_hndl = vsconn.clone();
                        tokio::task::spawn_local(async move {
                            if let Err(e) = restart_hndl.restart().await {
                                // ConnClosed here means the run loop is
                                // between dials — already restarting.
                                debug!(target: LINK_STATE,
                                    "VSConn restart command not delivered (already recycling): {e}");
                            }
                        });
                    }
                } else if let Some(vsconn) = asm.vsconn.as_ref() {
                    locked_fsm.set_state(LinkState::Disconnecting(reason));

                    let task_asm = asm.clone();
                    let spawn_hndl = vsconn.clone();
                    tokio::task::spawn_local(async move {
                        debug!(target: LINK_STATE, "deregister of VS peer detected, stopping VSConn (deregister:{deregister})");
                        if let Err(e) = spawn_hndl.stop(deregister).await {
                            error!(target: LINK_STATE, "stop command to VSConn failed: {e}");
                        }
                        debug!(target: LINK_STATE, "VSConn shut down");

                        // ignore error here, it just means we've moved on to another state and got the ACK (very) late
                        let _ = task_asm
                            .process_link_state_event(link_id, LinkEvent::ReceivedDisconnectAck);
                    });

                    return Ok(());
                } // else fallthrough
            } // else fallthrough
        } // else fallthrough

        // else all the above...
        self.continue_close(asm, locked_fsm, reason)
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

        // With auto-connect off (zipline#28) a completed close is terminal:
        // the tether stays Inactive until the next startLink RPC. Every
        // failure path parks the FSM in Error before initiating the close,
        // while an operator stop arrives from a running state — so an Error
        // entry with no recorded failure (e.g. a Helloing timeout) must
        // record one here, or ph-cli's `connect` poll reads the permanently
        // Inactive link as "restart forthcoming" and hangs until its
        // deadline.
        if self.link_type == LinkType::AdapterToNode
            && !asm.config.get().auto_connect
            && self.get_state() == LinkState::Error
        {
            if let Some(peer) = asm.peer_table.get(link_id) {
                if peer.actor_auth.last_failure().is_none() {
                    peer.actor_auth
                        .record_failure(AuthFailureReason::LinkFailed(format!(
                            "link failed before authentication completed ({reason:?})"
                        )));
                }
            }
        }

        self.maybe_disconnect_visa_service_client(asm, true, reason)
    }

    fn process_disconnect_ack(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::Disconnecting(reason)) => {
                debug!(target: LINK_STATE, "{} received disconnect ack", asm.formatted_link_id(self.id));
                self.continue_close(asm, locked_fsm, reason)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited init auth ack".to_string(),
            )),
        }
    }

    /// Continue shutdown of the link.  Occurs after having disconnected
    /// from the visa service (if applicable).
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
        if let Some(peer) = asm.peer_table.get(self.id) {
            peer.actor_auth.link_down(asm).detach_all();
        }
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
                if let Some(peer) = asm.peer_table.get(link_id) {
                    join_set = peer.actor_auth.link_down(asm);
                }

                let mut link_data = self.locked_data.lock().unwrap();
                let aaa = self.aaa_address();
                self.aaa_address.write(None);
                if let Some(aaa_addr) = aaa {
                    if self.link_type == LinkType::AdapterToNode && link_data.installed_aaa {
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
                link_data.oidc_idps = None;
                link_data.installed_aaa = false;
                drop(link_data);

                asm.peer_table.clear_peer_state(link_id);

                match self.link_type {
                    LinkType::AdapterToNode => {
                        if let Err(err) = asm.tun_ctl.set_carrier(false) {
                            error!(target: LINK_STATE, "cannot disable TUN carrier: {err}");
                        }
                    }
                    LinkType::NodeToAdapter => {}
                    _ => {}
                }

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
            (LinkState::Closing, LinkType::NodeToAdapter) | (LinkState::Resetting, _) => {
                // Clear whole peer out
                drop(locked_fsm);
                asm.drop_peer(link_id);
                return;
            }
            (LinkState::Closing, _) => {
                locked_fsm.silent = false;
                locked_fsm.set_state(LinkState::Inactive);
                info!(target: LINK_STATE, "{} has fully shut down", asm.formatted_link_id(link_id));
                if !locked_fsm.shutting_down {
                    drop(locked_fsm);
                    if self.link_type == LinkType::AdapterToNode && !asm.config.get().auto_connect {
                        // With auto-connect off (zipline#28) the tether does
                        // not restart itself: it stays Inactive until the
                        // next startLink RPC (ph-cli connect / link start).
                        info!(target: LINK_STATE, "{} idle (auto-connect off); waiting for startLink", asm.formatted_link_id(link_id));
                    } else if self.link_type == LinkType::AdapterToNode
                        && fatal_activation_failure(asm, link_id)
                    {
                        // zipline#157: a local activation failure is
                        // non-transient (an EPERM will not clear on
                        // reconnect). Stay Inactive with the recorded reason;
                        // the operator re-runs `ph-cli connect` after fixing
                        // the host.
                        warn!(target: LINK_STATE, "{} not reconnecting after a fatal local activation failure; fix the host and re-run `ph-cli connect`", asm.formatted_link_id(link_id));
                    } else {
                        self.setup_restart(asm);
                    }
                } else {
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

    /// Set a timer to attempt a link restart after a holddown period
    fn setup_restart(&self, asm: &Arc<Assembly>) {
        // TODO: use timeout mechanism
        let link_id = self.id;
        let task_asm = asm.clone();
        tokio::task::spawn_local(async move {
            tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN).await;
            // zipline#157: this timer may have been scheduled by an earlier,
            // non-fatal close while a newer attempt (an operator startLink
            // during the holddown) reached a fatal local activation failure.
            // A stale Start would resume the reconnect loop the hard stop
            // was meant to end.
            if fatal_activation_failure(&task_asm, link_id) {
                info!(target: LINK_STATE, "{} skipping stale holddown restart after a fatal local activation failure", task_asm.formatted_link_id(link_id));
                return;
            }
            info!(target: LINK_STATE, "Attempting to restart {}", task_asm.formatted_link_id(link_id));
            let _ = task_asm.process_link_state_event(link_id, LinkEvent::Start);
        });
    }

    /// Reset the link, shutting it down and wiping its configuration
    /// Instead of transitioning, the state machine will be destroyed
    /// Sends a Terminate Indication
    pub async fn reset(&self, asm: &Arc<Assembly>) {
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
        let _ = self.clean_up_link_state(asm).join_all().await;
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

        // Piggyback the auth-renewal check on the keep-alive heartbeat
        // (zipline#45): every successful echo response on an Active link is
        // a renewal tick.
        crate::actor_renewal::maybe_renew(asm, self.id);

        Ok(())
    }

    /// Common code to enter the `Active` state and kick off our keepalive mechanism
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

/// zipline#157: whether the link's actor recorded a fatal local activation
/// failure, which suppresses automatic reconnects.
fn fatal_activation_failure(asm: &Assembly, link_id: LinkId) -> bool {
    asm.peer_table.get(link_id).is_some_and(|peer| {
        matches!(
            peer.actor_auth.last_failure(),
            Some(AuthFailureReason::ActivationFailed(_))
        )
    })
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

/// Close every keyed Zode link whose verified peer CN this Zode no longer
/// expects (zl-zipline#220). Called after each topology update, so removing
/// a Zode from the topology ends its links without a revocation list.
pub fn close_zode_links_outside_topology(asm: &Arc<Assembly>) {
    let mut to_close = Vec::new();
    asm.peer_table.for_each(|(link_id, peer)| {
        let fsm = &peer.link_state_machine;
        if fsm.get_link_type() == LinkType::NodeToNode
            && matches!(fsm.get_state(), LinkState::Helloing | LinkState::Active)
            && !peer
                .verified_peer_cn()
                .is_some_and(|cn| asm.peer_cn_allowed(&cn))
        {
            to_close.push(link_id.get());
        }
    });
    for link_id in to_close {
        warn!(target: LINK_STATE, "{} peer left this Zode's topology; closing", asm.formatted_link_id(link_id));
        if let Err(e) =
            asm.process_link_state_event(link_id, LinkEvent::Close(TerminateReason::Reset))
        {
            warn!(target: LINK_STATE, "{} close after topology update failed: {e}", asm.formatted_link_id(link_id));
        }
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

    fn hello_link(link_type: LinkType) -> LinkStateWrapper {
        let link = LinkStateWrapper::new(3, link_type);
        {
            let mut fsm = link.locked_fsm.lock().unwrap();
            fsm.status = LinkStatus::Up;
            fsm.set_state(LinkState::Helloing);
        }
        link
    }

    #[test]
    fn readiness_tracks_all_link_states() {
        let link = LinkStateWrapper::new(3, LinkType::AdapterToNode);
        assert!(!link.is_ready());
        assert!(LinkStateWrapper::new(1, LinkType::Internal).is_ready());

        for state in [
            LinkState::Inactive,
            LinkState::Keying,
            LinkState::Helloing,
            LinkState::Disconnecting(TerminateReason::Other),
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

    #[tokio::test]
    async fn adapter_ownership_reads_do_not_wait_for_link_mutexes() {
        use crate::peer_table::test::create_dummy_peer_state;
        use std::net::{IpAddr, Ipv4Addr};
        use zpr_utils::net_defs::ScopedIpAddr;

        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        assert!(!asm.adapter_owns_address(IpAddress::UNSPECIFIED));
        for id in 1..=DOCK_LINK_ID {
            let entry = asm.peer_table.vacant_entry().unwrap();
            assert_eq!(entry.key().get(), id);
            let peer = create_dummy_peer_state(
                entry.key(),
                LinkType::AdapterToNode,
                SubstrateAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), id.try_into().unwrap()),
                ScopedIpAddr::V4(Ipv4Addr::LOCALHOST),
            );
            entry.insert(peer);
        }
        let peer = asm.peer_table.get(DOCK_LINK_ID).unwrap();
        let link = &peer.link_state_machine;
        let aaa = "fd5a:5052:0:aaa::1".parse::<IpAddr>().unwrap().into();
        link.process_assigned_aaa(&asm, aaa).unwrap();
        assert!(!asm.adapter_owns_address(aaa));

        let mut fsm = link.locked_fsm.lock().unwrap();
        fsm.status = LinkStatus::Up;
        fsm.set_state(LinkState::Active);
        let data = link.locked_data.lock().unwrap();
        std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel();
            let asm = &asm;
            scope.spawn(move || {
                tx.send((
                    asm.adapter_owns_address(aaa),
                    asm.adapter_owns_address(IpAddress::UNSPECIFIED),
                ))
                .unwrap();
            });
            let result = rx.recv_timeout(Duration::from_secs(2));
            // Release before checking the result so a regressed reader can finish.
            drop(data);
            drop(fsm);
            assert_eq!(result.unwrap(), (true, false));
        });

        link.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Closing);
        assert_eq!(link.aaa_address(), Some(aaa));
        assert!(!asm.adapter_owns_address(aaa));
    }

    #[tokio::test]
    async fn aaa_assignment_waits_for_cleanup_ownership() {
        use std::net::IpAddr;

        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let link = LinkStateWrapper::new(3, LinkType::NodeToAdapter);
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

    #[tokio::test]
    async fn hello_activates_link_and_keepalives_before_actor_authorization() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link = hello_link(LinkType::AdapterToNode);
                let aaa = "fd5a:5052:0:aaa::1"
                    .parse::<std::net::IpAddr>()
                    .unwrap()
                    .into();
                link.process_hello_response(
                    &asm,
                    HelloResponse {
                        status: ResponseCode::Success,
                        aaa_address: Some(aaa),
                        oidc_idps: None,
                        vs_bootstrap: false,
                    },
                )
                .unwrap();
                assert!(link.is_ready());
                assert_eq!(link.aaa_address(), Some(aaa));
                assert!(link.locked_fsm.lock().unwrap().timeout_handle.is_some());
                assert!(asm.get_local_zpr_addrs_std().is_empty());
            })
            .await;
    }

    #[tokio::test]
    async fn ordinary_hello_cannot_succeed_without_aaa() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let adapter = hello_link(LinkType::AdapterToNode);
                assert!(
                    adapter
                        .process_hello_response(
                            &asm,
                            HelloResponse {
                                status: ResponseCode::Success,
                                aaa_address: None,
                                oidc_idps: None,
                                vs_bootstrap: false,
                            },
                        )
                        .is_err()
                );
                assert!(!adapter.is_ready());
                let node = hello_link(LinkType::NodeToAdapter);
                node.process_hello_request(&asm).unwrap();
                assert!(!node.is_ready());
                assert_eq!(node.get_state(), LinkState::Closing);
            })
            .await;
    }

    #[tokio::test]
    async fn only_designated_vs_bootstrap_can_establish_without_pool() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                asm.peer_table
                    .assign_special_name(SpecialPeerName::VisaServiceAdapter, 3)
                    .unwrap();
                let node = hello_link(LinkType::NodeToAdapter);
                node.process_hello_request(&asm).unwrap();
                assert!(node.is_ready());
                assert!(node.aaa_address().is_none());
                let adapter = hello_link(LinkType::AdapterToNode);
                adapter
                    .process_hello_response(
                        &asm,
                        HelloResponse {
                            status: ResponseCode::Success,
                            aaa_address: None,
                            oidc_idps: None,
                            vs_bootstrap: true,
                        },
                    )
                    .unwrap();
                assert!(adapter.is_ready());
            })
            .await;
    }

    /// Insert an adapter-side (AdapterToNode) peer into the table and return
    /// its link id. Each call gets a distinct substrate port: the peer table
    /// rejects duplicate substrate addresses.
    fn add_adapter_peer(asm: &Arc<Assembly>) -> LinkId {
        add_peer(asm, LinkType::AdapterToNode, 9000)
    }

    /// Insert a node-side (NodeToAdapter) peer and return its link id.
    fn add_node_peer(asm: &Arc<Assembly>) -> LinkId {
        add_peer(asm, LinkType::NodeToAdapter, 9500)
    }

    /// Insert a peer of `link_type` whose substrate port is `base_port`
    /// plus its link id, and return the link id.
    fn add_peer(asm: &Arc<Assembly>, link_type: LinkType, base_port: u16) -> LinkId {
        use crate::peer_table::test::create_dummy_peer_state;
        use std::net::Ipv4Addr;
        use zpr_utils::net_defs::ScopedIpAddr;

        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let peer = create_dummy_peer_state(
            link_id,
            link_type,
            SubstrateAddr::from(([127, 0, 0, 1], base_port + link_id.get() as u16)),
            ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        );
        entry.insert(peer).get()
    }

    /// A test assembly whose links can be started: `process_start` hands
    /// the link to the key manager, which needs a noise keypair and a
    /// certificate exchange. `auto_connect` sets the zipline#28 option.
    fn keyable_assembly(auto_connect: bool) -> Arc<Assembly> {
        let mut cfg = <config::Config as std::default::Default>::default();
        cfg.auto_connect = auto_connect;
        Arc::new(create_assembly(TestAssemblyBuilder {
            self_noise_keypair: Some(crate::km_noise::NoiseKeypair::generate()),
            certx: Some(crate::km_cert_exchange::KmCertExchange::new(None, None)),
            config: Some(rcu::RcuBox::new(cfg)),
            ..TestAssemblyBuilder::new()
        }))
    }

    /// A keyable assembly whose stored topology names `peer_cns` (zl-zipline#220).
    fn zode_assembly(peer_cns: &[&str]) -> Arc<Assembly> {
        use crate::peer_table::test::topology_link;
        let asm = keyable_assembly(true);
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
                let link_id = crate::peer_table::test::insert_zode_peer_with_verified_cn(
                    &asm,
                    "stranger.zpr",
                    LinkState::Keying,
                );
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
                let link_id = crate::peer_table::test::insert_zode_peer_with_verified_cn(
                    &asm,
                    "relay.zpr",
                    LinkState::Keying,
                );
                asm.process_link_state_event(link_id, LinkEvent::KeyingDone)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Helloing);
            })
            .await
    }

    /// zl-zipline#220: an empty `peer_cn` (a sender that predates peerCn)
    /// never authorises a peer, and neither does an empty certificate CN.
    #[tokio::test]
    async fn test_empty_peer_cn_never_matches() {
        let asm = zode_assembly(&[""]);
        assert!(!asm.peer_cn_allowed(""));
        let asm = zode_assembly(&["relay.zpr"]);
        assert!(asm.peer_cn_allowed("relay.zpr"));
        assert!(!asm.peer_cn_allowed(""));
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

    /// With `auto_connect = false` (zipline#28), a dropped AdapterToNode
    /// tether must NOT auto-restart: `complete_close` leaves it Inactive
    /// and no holddown timer re-fires `Start`. The next `startLink` RPC is
    /// the only way back up.
    #[tokio::test(start_paused = true)]
    async fn test_no_restart_after_close_when_auto_connect_disabled() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(false);
                let link_id = add_adapter_peer(&asm);

                complete_close_of(&asm, link_id);
                assert_eq!(link_state_of(&asm, link_id), LinkState::Inactive);

                // Advance well past the restart holddown: still Inactive.
                tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN + Duration::from_secs(1))
                    .await;
                assert_eq!(
                    link_state_of(&asm, link_id),
                    LinkState::Inactive,
                    "auto_connect=false link must wait for startLink, not self-restart"
                );
            })
            .await
    }

    /// Companion: with the default config (`auto_connect = true`) the
    /// holddown restart still happens.
    #[tokio::test(start_paused = true)]
    async fn test_restart_after_close_with_default_auto_connect() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(true);
                let link_id = add_adapter_peer(&asm);

                complete_close_of(&asm, link_id);
                assert_eq!(link_state_of(&asm, link_id), LinkState::Inactive);

                tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN + Duration::from_secs(1))
                    .await;
                assert_eq!(
                    link_state_of(&asm, link_id),
                    LinkState::Keying,
                    "default config must keep the automatic holddown restart"
                );
            })
            .await
    }

    /// With `auto_connect = false`, a manually started link that fails
    /// BEFORE authentication (here: the Helloing timeout in
    /// `process_timeout`, which records no `AuthFailureReason`) ends up
    /// permanently Inactive — terminal, since no restart is coming. The
    /// close path must record `LinkFailed` on the actor: ph-cli's `connect`
    /// poll classifies a teardown state *without* a `Last auth failure:`
    /// line as Pending (restart forthcoming) and would otherwise wait
    /// forever on a link that will never recover (zipline#28).
    #[tokio::test(start_paused = true)]
    async fn test_manual_mode_pre_auth_failure_is_terminal_not_pending() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(false);
                let link_id = add_adapter_peer(&asm);

                // A manually started attempt is stuck in Helloing; its
                // timeout fires (process_timeout gives up on the link).
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .test_set_state(LinkState::Helloing);
                fire_current_timeout(&asm, link_id);
                assert_eq!(
                    link_state_of(&asm, link_id),
                    LinkState::Closing,
                    "test precondition: the Helloing timeout initiates the close"
                );

                // The terminate handshake completes and the close finishes.
                asm.process_link_state_event(link_id, LinkEvent::CloseDone)
                    .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Inactive);
                assert!(
                    matches!(
                        peer.actor_auth.last_failure(),
                        Some(AuthFailureReason::LinkFailed(_))
                    ),
                    "terminal idle after a pre-auth failure must carry a recorded \
                     failure reason, or ph-cli connect classifies the permanently \
                     Inactive link as Pending and hangs until its deadline; got {:?}",
                    peer.actor_auth.last_failure()
                );
            })
            .await
    }

    /// The `LinkFailed` record above only fills a gap: a close after a
    /// recorded failure keeps that (more specific) reason, and with
    /// auto-connect ON nothing is recorded, since a restart is coming.
    #[tokio::test(start_paused = true)]
    async fn test_link_failed_is_recorded_only_when_terminal_and_unexplained() {
        LocalSet::new()
            .run_until(async {
                // Auto-connect off, failure already recorded: kept.
                let asm = keyable_assembly(false);
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.actor_auth
                        .record_failure(AuthFailureReason::UserDeclined);
                    peer.link_state_machine.test_set_state(LinkState::Helloing);
                }
                fire_current_timeout(&asm, link_id);
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .actor_auth
                        .last_failure(),
                    Some(AuthFailureReason::UserDeclined)
                );

                // Auto-connect on: nothing recorded.
                let asm = keyable_assembly(true);
                let link_id = add_adapter_peer(&asm);
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .test_set_state(LinkState::Helloing);
                fire_current_timeout(&asm, link_id);
                assert_eq!(link_state_of(&asm, link_id), LinkState::Closing);
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .actor_auth
                        .last_failure(),
                    None
                );
            })
            .await
    }

    /// A `Start` begins a fresh ZDP-R session, so it must reset the link's
    /// sender and receiver.
    ///
    /// An adapter keeps one peer table entry (and so one ZDP-R session) per
    /// link for the life of the process, but the node it re-docks with
    /// allocates a brand new link -- and so a brand new sender -- for every
    /// dock attempt, restarting its sequence numbers at 0.  An adapter that
    /// carried the previous attempt's receive window into the restart would
    /// classify every packet of the new session as an already-seen
    /// duplicate: dropped without processing but still acknowledged, so the
    /// node never retransmits and the link never gets past Helloing.
    #[tokio::test(start_paused = true)]
    async fn test_start_resets_zdpr_session() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(true);
                let link_id = add_adapter_peer(&asm);

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

    /// zipline#173: a node-side link whose peer never completes the noise
    /// handshake must not sit in Keying forever. Nothing here answers the
    /// responder, so the link can only leave Keying by timing out after
    /// NODE_KEYING_TIMEOUT; once it does, the close path removes the peer
    /// entry altogether.
    #[tokio::test(start_paused = true)]
    async fn test_node_link_stuck_in_keying_is_torn_down() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(true);
                let link_id = add_node_peer(&asm);

                asm.process_link_state_event(link_id, LinkEvent::Start)
                    .unwrap();
                assert_eq!(link_state_of(&asm, link_id), LinkState::Keying);

                // Just before the deadline the link is still waiting.
                let one_sec = Duration::from_secs(1);
                tokio::time::sleep(config::NODE_KEYING_TIMEOUT - one_sec).await;
                assert_eq!(
                    link_state_of(&asm, link_id),
                    LinkState::Keying,
                    "node link torn down before NODE_KEYING_TIMEOUT"
                );

                // Past the deadline plus the terminate timeout the close has
                // completed and the peer entry is gone.
                tokio::time::sleep(2 * one_sec + config::DEFAULT_TERMINATE_TIMEOUT).await;
                assert!(
                    asm.peer_table.get(link_id).is_none(),
                    "node link that never completed keying is still in the peer table \
                     (state {:?})",
                    asm.peer_table
                        .get(link_id)
                        .map(|p| p.link_state_machine.get_state())
                );
            })
            .await
    }

    /// zipline#173: the keying deadline only applies while Keying. A node
    /// link that finishes keying in time (the FSM leaves Keying, as it does
    /// on `KeyingDone`) must survive past NODE_KEYING_TIMEOUT.
    #[tokio::test(start_paused = true)]
    async fn test_node_link_keying_done_cancels_keying_timeout() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(true);
                let link_id = add_node_peer(&asm);

                asm.process_link_state_event(link_id, LinkEvent::Start)
                    .unwrap();
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .test_set_state(LinkState::Helloing);

                tokio::time::sleep(config::NODE_KEYING_TIMEOUT * 2).await;

                let peer = asm
                    .peer_table
                    .get(link_id)
                    .expect("keyed node link was torn down by the keying deadline");
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Helloing);
            })
            .await
    }

    /// zipline#157: once the actor has recorded a fatal local activation
    /// failure (`ActivationFailed`, e.g. EPERM setting the granted address),
    /// the close that follows must NOT schedule the holddown restart: a
    /// reconnect re-keys, re-prompts OIDC interactively, and the EPERM will
    /// not have cleared. The link stays Inactive with the reason recorded.
    /// (The activation failure itself is pinned in actor_auth/
    /// actor_activation tests; this is the link-level half.)
    #[tokio::test(start_paused = true)]
    async fn test_fatal_activation_failure_suppresses_reconnect() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(true);
                let link_id = add_adapter_peer(&asm);
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .actor_auth
                    .record_failure(AuthFailureReason::ActivationFailed(
                        "failed to set ZPR address: EPERM".to_owned(),
                    ));

                complete_close_of(&asm, link_id);
                assert_eq!(link_state_of(&asm, link_id), LinkState::Inactive);
                tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN + Duration::from_secs(1))
                    .await;
                assert_eq!(
                    link_state_of(&asm, link_id),
                    LinkState::Inactive,
                    "a fatal local activation failure must hard-stop the \
                     reconnect loop (zipline#157 Q1); the holddown restart \
                     re-fired Start"
                );
            })
            .await
    }

    /// zipline#157 review round 1 (Codex P1): a restart timer scheduled by
    /// an EARLIER, non-fatal close must not override a later fatal stop.
    ///
    /// Sequence: an auto-connect close completes and schedules the holddown
    /// restart; during the holddown the operator manually starts a new
    /// attempt (startLink), which reaches a fatal `ActivationFailed` and
    /// closes. The hard-stop branch in `complete_close` correctly declines
    /// to schedule a NEW timer — but the OLD timer is still pending, and an
    /// unconditional `setup_restart` task would fire it, send `Start`, and
    /// resume the reconnect loop the fatal stop was meant to end. The
    /// pending task must re-check the recorded fatal failure before
    /// starting.
    #[tokio::test(start_paused = true)]
    async fn test_stale_restart_timer_does_not_override_fatal_stop() {
        LocalSet::new()
            .run_until(async {
                let asm = keyable_assembly(true);
                let link_id = add_adapter_peer(&asm);

                // 1. A non-fatal close completes: `complete_close` leaves
                //    the link Inactive and schedules the holddown restart.
                complete_close_of(&asm, link_id);
                assert_eq!(
                    link_state_of(&asm, link_id),
                    LinkState::Inactive,
                    "test precondition: the first close parks the link Inactive"
                );

                // 2. During the holddown, the operator manually starts a
                //    new attempt (ph-cli connect -> startLink -> Start).
                tokio::time::sleep(Duration::from_secs(1)).await;
                asm.process_link_state_event(link_id, LinkEvent::Start)
                    .unwrap();
                assert_eq!(
                    link_state_of(&asm, link_id),
                    LinkState::Keying,
                    "test precondition: the manual Start begins a new attempt"
                );

                // 3. The new attempt hits a fatal local activation failure
                //    and its close completes BEFORE the old timer expires.
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .actor_auth
                    .record_failure(AuthFailureReason::ActivationFailed(
                        "failed to set ZPR address: EPERM".to_owned(),
                    ));
                complete_close_of(&asm, link_id);
                assert_eq!(link_state_of(&asm, link_id), LinkState::Inactive);

                // 4. The FIRST close's restart timer expires. It must not
                //    send Start: the link stays Inactive and the recorded
                //    fatal failure survives for showLink / ph-cli connect.
                tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN + Duration::from_secs(1))
                    .await;
                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Inactive,
                    "a restart timer scheduled before a fatal activation \
                     failure must not resume the reconnect loop \
                     (zipline#157 review round 1)"
                );
                assert!(
                    matches!(
                        peer.actor_auth.last_failure(),
                        Some(AuthFailureReason::ActivationFailed(_))
                    ),
                    "the stale restart wiped the recorded fatal failure"
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
                let link_id = add_node_peer(&asm);
                asm.peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .test_set_state(LinkState::Active);

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

    /// Build a real [libnode::vsconn::VSConn] aimed at `vs_addr`, plus a
    /// test assembly whose VS special peer is an Active NodeToAdapter link
    /// (zipline#113 recovery tests). Returns the assembly, the VS link id,
    /// and the VSConn instance (run it yourself so the test owns its task).
    /// Pass a refusing address (e.g. `127.0.0.1:1`) to keep the run loop in
    /// its dial/retry phase, or a live TLS server's address to get it parked
    /// in its command loop.
    fn assembly_with_vs_peer(
        vs_addr: std::net::SocketAddr,
    ) -> (Arc<Assembly>, LinkId, libnode::vsconn::VSConn) {
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let vsconn = libnode::vsconn::VSConn::new(
            16,
            vs_addr,
            "test-node".to_string(),
            key,
            "127.0.0.1:5000".parse().unwrap(),
        );
        // Observable egress: the close path puts a Terminate on the mgmt
        // substrate queue, which must have a live receiver.
        let (egress_tx, egress_rx) = crate::packet_queue::packet_queue(8);
        let mut builder = TestAssemblyBuilder::new();
        builder.mgmt_substrate_egress = Some(crate::queues::MgmtSubstrateEgress::new(egress_tx));
        builder.vsconn = Some(Some(vsconn.handle()));
        let asm = Arc::new(create_assembly(builder));
        // Leak the receiver so the egress queue outlives the test body.
        std::mem::forget(egress_rx);
        let link_id = add_node_peer(&asm);
        asm.peer_table
            .assign_special_name(SpecialPeerName::VisaServiceAdapter, link_id)
            .unwrap();
        asm.peer_table
            .get(link_id)
            .unwrap()
            .link_state_machine
            .test_set_state(LinkState::Active);
        (asm, link_id, vsconn)
    }

    /// zipline#113: closing the VS adapter link because of a keep-alive
    /// timeout must NOT send `VS2Command::Stop` — the VSConn run loop stays
    /// alive so it can reconnect. Before the fix, ANY close of the VS
    /// special-peer link stopped VSConn, and `run_with_reconnect` treated
    /// that clean return as a permanent shutdown (`terminated: Ok(())`),
    /// after which every VS API call failed `ConnClosed` forever.
    #[tokio::test]
    async fn test_vs_link_timeout_close_leaves_vsconn_running() {
        LocalSet::new()
            .run_until(async {
                // Nothing listens on port 1: connect is refused fast, so the
                // run loop stays in its dial/retry phase.
                let (asm, link_id, mut vsconn) =
                    assembly_with_vs_peer("127.0.0.1:1".parse().unwrap());

                let vsconn_task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_millis(200)).await
                });
                // Let the run loop start its first (refused) connect attempt.
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Keep-alive gave up on the link: close with RequestTimedOut.
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::Close(TerminateReason::RequestTimedOut),
                )
                .unwrap();

                // Give a (wrongly sent) Stop ample time to be consumed by the
                // reconnect loop: it polls the command channel while waiting.
                tokio::time::sleep(Duration::from_millis(500)).await;
                assert!(
                    !vsconn_task.is_finished(),
                    "a timeout-driven VS link close must leave the VSConn run \
                     loop alive to reconnect; it received a Stop and exited"
                );
                vsconn_task.abort();
            })
            .await
    }

    /// Companion (zipline#113): a Shutdown-reason close of the VS adapter
    /// link still stops VSConn — `Stop` stays reserved for process exit.
    #[tokio::test]
    async fn test_vs_link_shutdown_close_still_stops_vsconn() {
        LocalSet::new()
            .run_until(async {
                let (asm, link_id, mut vsconn) =
                    assembly_with_vs_peer("127.0.0.1:1".parse().unwrap());

                let vsconn_task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_millis(200)).await
                });
                tokio::time::sleep(Duration::from_millis(50)).await;

                asm.process_link_state_event(link_id, LinkEvent::Close(TerminateReason::Shutdown))
                    .unwrap();

                let res = tokio::time::timeout(Duration::from_secs(5), vsconn_task)
                    .await
                    .expect("Shutdown close must stop the VSConn run loop")
                    .expect("VSConn task panicked");
                assert!(res.is_ok(), "run_with_reconnect exits Ok on Stop: {res:?}");
            })
            .await
    }

    /// A minimal local TLS server: accepts connections, completes the TLS
    /// handshake, then holds each stream open. Enough for `VSConn::run` to
    /// get past TLS and emit `RunLoopStarts`; no Cap'n Proto traffic is
    /// exchanged. Returns the bound address. Mirrors the libnode2 test
    /// helper of the same name.
    async fn spawn_tls_holding_server() -> std::net::SocketAddr {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let chain = vec![CertificateDer::from(cert.cert.der().clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn_local(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::task::spawn_local(async move {
                    if let Ok(_tls) = acceptor.accept(sock).await {
                        // Hold the connection open; never speak.
                        std::future::pending::<()>().await;
                    }
                });
            }
        });
        addr
    }

    /// Wait (up to 5 s) for the next `RunLoopStarts` lifecycle event.
    async fn next_run_loop_start(
        lifecycle_rx: &mut tokio::sync::broadcast::Receiver<libnode::vsconn::VSConnLifecycleEvent>,
    ) -> Result<(), tokio::time::error::Elapsed> {
        use libnode::vsconn::VSConnLifecycleEvent;

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match lifecycle_rx.recv().await {
                    Ok(VSConnLifecycleEvent::RunLoopStarts) => break,
                    Ok(_) => continue,
                    Err(e) => panic!("lifecycle channel died: {e:?}"),
                }
            }
        })
        .await
    }

    /// zipline#113, Codex P1 on PR #40: when the VS adapter link closes on a
    /// failure (keep-alive timeout, ZDP-only failure) while the underlying
    /// Cap'n Proto TCP connection SURVIVES, leaving VSConn untouched is not
    /// enough — its run loop stays parked in its command loop, never emits
    /// `RunLoopExits`/`RunLoopStarts`, so `vs_worker` (gated on
    /// `RunLoopStarts`) never re-runs `register_vss` and the replacement VS
    /// link's `deferred_vs_connect` stays pending forever. The close path
    /// must explicitly restart the current run loop: this test demands a
    /// fresh `RunLoopStarts` after the failure-close.
    #[tokio::test]
    async fn test_vs_link_timeout_close_restarts_vsconn_run_loop() {
        LocalSet::new()
            .run_until(async {
                // A live TLS server, so VSConn::run reaches its command loop
                // and the TCP connection survives the link flap.
                let server_addr = spawn_tls_holding_server().await;
                let (asm, link_id, mut vsconn) = assembly_with_vs_peer(server_addr);
                let mut lifecycle_rx = vsconn.subscribe_lifecycle_events();

                let vsconn_task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_millis(50)).await
                });

                // First RunLoopStarts: the run loop is up and parked.
                next_run_loop_start(&mut lifecycle_rx)
                    .await
                    .expect("VSConn never reached its first RunLoopStarts");

                // Keep-alive gave up on the link: close with RequestTimedOut.
                // The TCP connection to the (held-open) TLS server survives.
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::Close(TerminateReason::RequestTimedOut),
                )
                .unwrap();

                // The close path must force the run loop to restart: a fresh
                // RunLoopStarts (preceded by RunLoopExits) has to arrive, or
                // vs_worker stays parked and the replacement VS link's
                // deferred authorization is never sent.
                assert!(
                    next_run_loop_start(&mut lifecycle_rx).await.is_ok(),
                    "a failure-close of the VS link with a surviving TCP \
                     connection must restart the VSConn run loop (fresh \
                     RunLoopStarts); otherwise vs_worker never re-registers \
                     and deferred_vs_connect is stuck pending"
                );

                // And the reconnect manager itself must stay alive.
                assert!(
                    !vsconn_task.is_finished(),
                    "restart must recycle the run loop, not stop run_with_reconnect"
                );
                vsconn_task.abort();
            })
            .await
    }

    /// zipline#170: tearing down an adapter's dock link must flush the
    /// adapter's flow tables. Every ELT stream id and DLT entry was issued
    /// by the node on the old docking session; a restarted node knows none
    /// of them, so a surviving ELT entry sends on a stream id the node drops
    /// (`Unknown Stream ID`) and never triggers a fresh bind. A Pending entry
    /// orphaned by the closed link would block re-binding its flow forever.
    /// Since #1410 the flush lives in `ActorAuthorization::link_down`, which
    /// the link's cleanup calls; this drives the cleanup end to end.
    #[tokio::test]
    async fn test_adapter_dock_link_cleanup_flushes_elt_and_dlt() {
        use crate::adapter_tables::{DltPep, EltPep};
        use crate::defs::FiveTuple;
        use crate::mgmt::core::new_heap_packet;
        use crate::mgmt::txn_mgr::TxnMgr;
        use zpr::packet_info::CompressionMode;

        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let txn_mgr = Arc::new(TxnMgr::new());

                // One Active ELT entry, as left behind by a completed bind.
                let active_ft = FiveTuple {
                    src_port: 1000,
                    ..FiveTuple::default()
                };
                let txn = txn_mgr.try_open().unwrap();
                asm.elt
                    .insert_pending(active_ft, new_heap_packet(), &txn)
                    .unwrap();
                asm.elt
                    .set_active(&active_ft, EltPep::new(CompressionMode::default(), 7, None))
                    .unwrap();

                // One Pending ELT entry, as left by a bind in flight at close.
                let pending_ft = FiveTuple {
                    src_port: 2000,
                    ..FiveTuple::default()
                };
                let pending_txn = txn_mgr.try_open().unwrap();
                asm.elt
                    .insert_pending(pending_ft, new_heap_packet(), &pending_txn)
                    .unwrap();

                // One DLT entry, as installed by a node's bind_egress_stream.
                let dlt_id = asm
                    .dlt
                    .insert(DltPep::new(crate::tc::Ip5TupleTc::new(active_ft), None))
                    .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                peer.link_state_machine.test_set_state(LinkState::Closing);
                let _ = peer.link_state_machine.clean_up_link_state(&asm);
                drop(peer);

                assert!(
                    asm.elt.get(&active_ft).is_none(),
                    "Active ELT entry must be flushed"
                );
                assert!(
                    asm.elt.get(&pending_ft).is_none(),
                    "Pending ELT entry must be flushed"
                );
                assert!(
                    asm.elt.lookup_pending(&pending_txn).is_err(),
                    "the flushed Pending entry's transaction must be forgotten too"
                );
                assert!(asm.dlt.get(dlt_id).is_none(), "DLT entry must be flushed");
            })
            .await
    }

    /// zipline#12: the OIDC IdPs a node advertises in HelloResponse are kept
    /// on the adapter's link for the actor's evidence, and forgotten when
    /// the link is cleaned up so a re-dock cannot use a stale list.
    #[tokio::test]
    async fn test_hello_response_oidc_idps_kept_until_cleanup() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let idp = auth::OidcIdpInfo {
                    issuer: "https://idp.test".to_string(),
                    client_id: "test-client".to_string(),
                    client_secret: None,
                    scopes: vec!["openid".to_string()],
                    allow_offline_access: false,
                };
                let peer = asm.peer_table.get(link_id).unwrap();
                let link = &peer.link_state_machine;
                {
                    let mut fsm = link.locked_fsm.lock().unwrap();
                    fsm.status = LinkStatus::Up;
                    fsm.set_state(LinkState::Helloing);
                }
                link.process_hello_response(
                    &asm,
                    HelloResponse {
                        status: ResponseCode::Success,
                        aaa_address: Some(
                            "fd5a:5052:0:aaa::1"
                                .parse::<std::net::IpAddr>()
                                .unwrap()
                                .into(),
                        ),
                        oidc_idps: Some(vec![idp.clone()]),
                        vs_bootstrap: false,
                    },
                )
                .unwrap();
                assert_eq!(link.oidc_idps().len(), 1);
                assert_eq!(link.oidc_idps()[0].issuer, idp.issuer);

                link.test_set_state(LinkState::Closing);
                let _ = link.clean_up_link_state(&asm);
                assert!(link.oidc_idps().is_empty());
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
