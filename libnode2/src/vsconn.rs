use zpr::vsapi::v1 as vsapi2;
use zpr::vsapi_types::ApiResponseError;

use aws_lc_rs::signature::RsaKeyPair;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_rustls::TlsConnector;
use tokio_util::compat::*;
use tracing::*;
use zpr_utils::rsa_sign::sign_rsa_key;

use crate::error::VSApiError;
use crate::logging::targets::VS_RPC;

use zpr::vsapi_types::{
    BootstrapVisas, ConnectRequest, ConnectType, Connection, DisconnectNotice, LinkStateReport,
    Param, ReauthRequest, VSConnectRequest, Visa, VisaDecision, VisaOp, VisaRequest, VisaResponse,
    pname,
};
use zpr::write_to::WriteTo;

/// Boxed async connect factory: given a SocketAddr, returns a future that resolves to a TcpStream.
/// The default implementation calls `tokio::net::TcpStream::connect`; tests may inject a stub.
type ConnectFn = Box<
    dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = std::io::Result<tokio::net::TcpStream>>>>,
>;

const LIFECYCLE_EVENT_BUFFER_SIZE: usize = 64;

const VSAPI_PING_INTERVAL: Duration = Duration::from_secs(5);
const VSAPI_MAX_PING_FAILURES: u32 = 2;

/// Minimum (and initial) timeout for a ping RPC call.
const PING_MIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Default timeout for a single Cap'n Proto RPC call.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for connect/challenge/authenticate — longer due to crypto.
const DEFAULT_CONNECT_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a `requestBootstrapVisas` call may take (zl-zipline#252, J7):
/// the relay closes the joiner's link if no answer comes by then. The RPC
/// itself is bounded by it, so an unanswered request holds the serial
/// command loop no longer than the relay waits for it.
pub const BOOTSTRAP_VISAS_TIMEOUT: Duration = Duration::from_secs(5);

/// 4 no error if call to VSAPI authenticate was successful.
type VSVisaResponse = Result<VisaDecision, VSApiError>;
type VSConnectResponse = Result<(), VSApiError>;
type VSRegisterVssResponse = Result<Vec<VisaOp>, VSApiError>;
type VSAuthorizeConnectResponse = Result<Connection, VSApiError>;
type VSNotifyDisconnectResponse = Result<(), VSApiError>;
type VSPingResponse = Result<(), VSApiError>;
type VSVisaIdsResponse = Result<Vec<u64>, VSApiError>;
type VSVisaByIdResponse = Result<Vec<Visa>, VSApiError>;
type VSReportLinkStatesResponse = Result<(), VSApiError>;
type VSBootstrapVisasResponse = Result<BootstrapVisas, VSApiError>;

#[derive(Debug)]
pub struct NodeConnect {
    /// Connect will fail if this does not match policy.
    pub zpr_addr: IpAddr,
    pub state: StateFlag,
    pub a2a_dh_pubkey: x25519_dalek::PublicKey, // node's own public key
}

#[derive(Debug)]
pub struct NodeOpen {
    pub state: StateFlag,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFlag {
    /// Visa service / node has no state for this connection.
    #[default]
    NoState,

    /// Visa service / node has existing state for this connection.
    HasState,
}

// The async "commands" that can be sent into the running visa service client.
#[derive(Debug)]
enum VS2Command {
    /// Stop the local vs-api run loop, optionally de-register from the visa service first.
    Stop(bool),

    /// Recycle the current run loop: exit it (emitting
    /// [VSConnLifecycleEvent::RunLoopExits]) so [VSConn::run_with_reconnect]
    /// re-dials and a fresh [VSConnLifecycleEvent::RunLoopStarts] follows.
    /// Unlike [VS2Command::Stop] this never terminates the reconnect
    /// manager. Used when the VS adapter *link* closes on a failure while
    /// the underlying Cap'n Proto TCP connection may have survived: without
    /// a restart, `vs_worker` stays parked waiting for a `RunLoopStarts`
    /// that will never come and the replacement link's deferred
    /// authorization is stuck pending (zipline#113).
    Restart,

    /// Run through the "bootstrap" connect sequence. If connect succeeds the VSHandle is kept internally.
    Connect(NodeConnect, oneshot::Sender<VSConnectResponse>),

    /// Run through the "open" sequence for an already authenticated (via [VS2Command::AuthorizeConnect]) node.
    /// If connect succeeds the VSHandle is kept internally. No `params` are required.
    Open(NodeOpen, oneshot::Sender<VSConnectResponse>),

    VisaRequest(VisaRequest, oneshot::Sender<VSVisaResponse>),

    RegisterVss(SocketAddr, oneshot::Sender<VSRegisterVssResponse>),

    AuthorizeConnect(ConnectRequest, oneshot::Sender<VSAuthorizeConnectResponse>),

    /// Re-prove an existing actor's authentication before `auth_expires`
    /// (zipline#45). Mirrors [VS2Command::AuthorizeConnect]; the VS returns
    /// an updated [Connection] with a new expiry.
    Reauthorize(ReauthRequest, oneshot::Sender<VSAuthorizeConnectResponse>),

    /// In-place node self re-authentication (zipline#121, contract K2): runs
    /// the connect → challenge → authenticate sequence again on the SAME
    /// `vs_service` bootstrap capability, deliberately bypassing the
    /// already-connected guard that [VS2Command::Connect] enforces. On
    /// success the new handle replaces the old one; on failure the old
    /// handle is kept — the visa service's re-auth deadline decides the
    /// actor's fate, not the node. The run loop handles commands serially,
    /// so at most one re-authentication is ever in flight here; the caller
    /// additionally coalesces duplicate requests (see ph's `vss_worker`).
    Reauthenticate(NodeConnect, oneshot::Sender<VSConnectResponse>),

    NotifyDisconnect(
        DisconnectNotice,
        oneshot::Sender<VSNotifyDisconnectResponse>,
    ),

    Ping(oneshot::Sender<VSPingResponse>),

    VisaIdsRequest(oneshot::Sender<VSVisaIdsResponse>),

    VisaByIdsRequest(Vec<u64>, oneshot::Sender<VSVisaByIdResponse>),

    /// Send this node's link-state snapshot, `VSHandle.reportLinkStates`
    /// (zl-zipline#250, ZODE_LINKS.md "Reporting summary").
    ReportLinkStates(
        Vec<LinkStateReport>,
        oneshot::Sender<VSReportLinkStatesResponse>,
    ),

    /// Ask for a joining Zode's bootstrap visas on its behalf,
    /// `VSHandle.requestBootstrapVisas` (zl-zipline#252, ZODE_LINKS.md J2).
    /// The `String` is the joiner's link-verified certificate CN.
    RequestBootstrapVisas(String, oneshot::Sender<VSBootstrapVisasResponse>),
}

#[derive(Debug, Clone, Copy)]
pub enum VSConnLifecycleEvent {
    /// Means we have established a network connection to the Cap'n Proto service.
    RunLoopStarts,

    /// Means that the node connect-request was successful.
    ConnectedToVsApi(StateFlag),

    /// When run loop has stopped.
    RunLoopExits,
}

pub struct VSConn {
    cmd_tx: mpsc::Sender<VS2Command>,
    cmd_rx: mpsc::Receiver<VS2Command>,
    vs_addr: SocketAddr,
    node_cn: String,
    node_private_key: RsaKeyPair,
    life_tx: broadcast::Sender<VSConnLifecycleEvent>,
    connect_fn: ConnectFn,
    /// The substrate address this node advertises to the VS (operator config;
    /// the address peers dial, which may differ from the bind address behind
    /// NAT). Sent as the `substrate_addr` param on both `connect` and `open`
    /// (the VS requires it on both). Callers must resolve a concrete,
    /// reachable address before constructing a [VSConn]: the node may have
    /// several local IPs (a wildcard bind covers all of them, present and
    /// future) but only one can be advertised, so the choice belongs to the
    /// operator, not to a socket-derived guess.
    substrate_addr: SocketAddr,
}

/// Handle for sending commands to a running [VSConn].
///
/// All async methods return [`VSApiError::ConnClosed`] in two situations:
/// - The run loop has exited (the underlying command channel is closed).
/// - A command was sent while the run loop was busy establishing a TCP
///   connection or waiting out a reconnect delay; in those windows the
///   command is discarded immediately rather than queued. Callers should
///   treat `ConnClosed` as a transient error and retry once a new
///   [`VSConnLifecycleEvent::RunLoopStarts`] event is observed.
#[derive(Clone)]
pub struct VSConnHandle {
    cmd_tx: mpsc::Sender<VS2Command>,
}

struct VSCommandState {
    vs_service: vsapi2::visa_service::Client,
    vs_handle: Option<vsapi2::v_s_handle::Client>,
}

impl VSCommandState {
    pub fn new(vs_service: vsapi2::visa_service::Client) -> Self {
        VSCommandState {
            vs_service,
            vs_handle: None,
        }
    }

    /// This is used synchronously in the command handlers to check if
    /// we are currently connected to the VS API.
    fn is_connected(&self) -> bool {
        self.vs_handle.is_some()
    }
}

impl NodeConnect {
    fn connect_type(&self) -> ConnectType {
        match self.state {
            StateFlag::NoState => ConnectType::Reset,
            StateFlag::HasState => ConnectType::Reconnect,
        }
    }
}

impl NodeOpen {
    fn connect_type(&self) -> ConnectType {
        match self.state {
            StateFlag::NoState => ConnectType::Reset,
            StateFlag::HasState => ConnectType::Reconnect,
        }
    }
}

impl VSConn {
    /// Create a new VSConn.
    ///
    /// Use [VSConn::subscribe_lifecycle_events] to get a receiver for lifecycle events such as when
    /// we connect to the VS API and when the run loop starts or exits.
    ///
    /// `buffer_size` determines how many commands can be buffered to send to the run loop before
    /// [VSConnHandle] starts blocking.
    ///
    /// `substrate_addr` is the substrate address this node advertises to the VS — the
    /// address peers dial (see the field docs). It must be concrete and reachable;
    /// there is deliberately no auto-derivation fallback.
    pub fn new(
        buffer_size: usize,
        vs_addr: SocketAddr,
        node_cn: String,
        node_private_key: RsaKeyPair,
        substrate_addr: SocketAddr,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(buffer_size);
        let (life_tx, _) = broadcast::channel(LIFECYCLE_EVENT_BUFFER_SIZE);
        VSConn {
            cmd_tx,
            cmd_rx,
            vs_addr,
            node_cn,
            node_private_key,
            life_tx,
            connect_fn: Box::new(|addr| Box::pin(tokio::net::TcpStream::connect(addr))),
            substrate_addr,
        }
    }

    /// Subscribe to recieve broadcast lifecycle events from this VSConn.
    pub fn subscribe_lifecycle_events(&self) -> broadcast::Receiver<VSConnLifecycleEvent> {
        self.life_tx.subscribe()
    }

    /// Best-effort send a lifecycle event, just log if the send fails (no receivers).
    fn send_lifecycle_event(&self, event: VSConnLifecycleEvent) {
        match self.life_tx.send(event) {
            Ok(_) => debug!(target: VS_RPC, "sent lifecycle event: {:?}", event),
            Err(e) => {
                info!(target: VS_RPC, "failed to send lifecycle event: {:?}: {:?}", event, e);
            }
        }
    }

    /// Just like [VSConn::run] but will attempt to reconnect if the connection to the VS is lost, after
    /// pausing for `reconnect_after`.
    /// Sending a [VS2Command::Stop] will break the reconnect loop and cause this to return.
    ///
    /// Note that "reconnect" here just means that we attempt to re-open the base Cap'n Proto connection.
    /// We rely on external code to call us with an API level "connect" command.  To know when reconnects
    /// and such are happening, follow the lifecycle events.
    pub async fn run_with_reconnect(
        &mut self,
        reconnect_after: Duration,
    ) -> Result<(), VSApiError> {
        loop {
            match self.run().await {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    error!(target: VS_RPC, "VSConn: run loop exited with error: {:?}", e);
                    info!(target: VS_RPC, "VSConn: reconnecting in {} seconds...", reconnect_after.as_secs());
                    let timeout = tokio::time::sleep(reconnect_after);
                    tokio::pin!(timeout);
                    // loop in case we get woken by the command channel
                    loop {
                        tokio::select! {
                            biased; // in case of tie this bias here means we prioritize Stop (first branch) if we get it.

                            cmd = self.cmd_rx.recv() => match cmd {
                                Some(VS2Command::Stop(_)) | None => {
                                    info!(target: VS_RPC, "VSConn: stop received during reconnect delay, exiting");
                                    return Ok(());
                                }
                                Some(other) => drop(other),
                            },

                            _ = &mut timeout => break,
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), VSApiError> {
        // First spin up a connection to the Capn Proto service on the VS.
        info!(target: VS_RPC, "VS RPC service connecting to {} (capnp)", self.vs_addr);

        // Interruptible TCP connect: poll cmd_rx alongside the connect future so that a Stop
        // command received while blocked in connect (e.g. during a 2-minute TCP ETIMEDOUT) causes
        // a clean exit rather than an indefinite hang.
        let sock = {
            let mut connect_fut = (self.connect_fn)(self.vs_addr);
            loop {
                tokio::select! {
                    result = &mut connect_fut => break result?,
                    cmd = self.cmd_rx.recv() => match cmd {
                        Some(VS2Command::Stop(_)) | None => {
                            info!(target: VS_RPC, "VSConn: stop received during TCP connect, exiting cleanly");
                            self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                            return Ok(());
                        }
                        // Any other command arrived before connection is established; drop it so
                        // its oneshot sender is closed and the caller receives ConnClosed.
                        Some(other) => drop(other),
                    }
                }
            }
        };
        sock.set_nodelay(true)?;

        debug!(
            target: VS_RPC,
            "advertising substrate address {} to the VS", self.substrate_addr
        );

        let connector = tls_connect();
        let tls = connector.connect(self.vs_addr.ip().into(), sock).await?;
        let (reader, writer) = tokio::io::split(tls);
        debug!(target: VS_RPC, "VS RPC service connected to {} (TLS)", self.vs_addr);

        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Client,
            capnp::message::ReaderOptions::new(),
        );

        let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);

        let vs_service: vsapi2::visa_service::Client =
            rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);

        let mut cmd_state = VSCommandState::new(vs_service);

        tokio::task::LocalSet::new()
            .run_until(async move {
                tokio::task::spawn_local(rpc_system);

                self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopStarts);
                //let mut ping_interval = tokio::time::interval(VSAPI_PING_INTERVAL);

                let ping_timeout = tokio::time::sleep(VSAPI_PING_INTERVAL);
                tokio::pin!(ping_timeout);
                let mut ping_failures = 0;

                // Then loop over commands and periodically ping.
                loop {
                    tokio::select! {
                        // If we get a command, handle it.
                        cmd = self.cmd_rx.recv() => {
                            let Some(cmd) = cmd else {
                                info!(target: VS_RPC, "VSConn: command channel closed, exiting run loop");
                                break;
                            };
                            let is_stop_cmd = matches!(cmd, VS2Command::Stop(_));
                            if let Err(e) = self.handle_command(&mut cmd_state, cmd).await {
                                error!(target: VS_RPC, "VSConn: handle_command error: {:?}", e);
                                self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                                return Err(e.into());
                            }
                            if is_stop_cmd {
                                break;
                            }
                        }

                        // If the ping interval elapses, do a ping (not implemented yet).
                        () = &mut ping_timeout => {
                            if !cmd_state.is_connected() {
                                // Not connected, just reset the ping timer.
                                ping_timeout.as_mut().reset(tokio::time::Instant::now() + VSAPI_PING_INTERVAL);
                                ping_failures = 0;
                                continue;
                            }
                            // Back off a bit if we experienced an error last time.
                            let next_ping_timeout = PING_MIN_TIMEOUT + Duration::from_secs(ping_failures as u64);
                            match self.do_ping(cmd_state.vs_handle.as_ref().unwrap(), next_ping_timeout).await {
                                Ok(_) => {
                                    trace!(target: VS_RPC, "VSConn: ping successful");
                                    ping_failures = 0;
                                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + VSAPI_PING_INTERVAL);
                                }
                                Err(e) => {
                                    ping_failures += 1;
                                    warn!(target: VS_RPC, "VSConn: ping error (count = {ping_failures}): {:?}", e);
                                    if ping_failures >= VSAPI_MAX_PING_FAILURES {
                                        error!(target: VS_RPC, "VSConn: maximum ping failures reached, exiting run loop");
                                        self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                                        return Err(VSApiError::Timeout("ping".to_string()).into());
                                    }
                                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(1));
                                }
                            }
                        }
                    }
                }

                info!(target: VS_RPC, "VSConn: exiting run loop (non-error)");
                self.send_lifecycle_event(VSConnLifecycleEvent::RunLoopExits);
                Ok::<(), VSApiError>(())
            })
            .await
    }

    pub fn handle(&self) -> VSConnHandle {
        VSConnHandle {
            cmd_tx: self.cmd_tx.clone(),
        }
    }

    async fn handle_command(
        &mut self,
        cmd_state: &mut VSCommandState,
        cmd: VS2Command,
    ) -> Result<(), VSApiError> {
        match cmd {
            VS2Command::Stop(deregister) => {
                debug!(target: VS_RPC, "VSConn: stop");
                if deregister && let Some(ref handle) = cmd_state.vs_handle {
                    let mut disconnect_request = handle.notify_disconnect_request();
                    let mut dnotice_bldr = disconnect_request.get().init_req();

                    // We are disconnecting "self" so we do not set a ZPR addr.

                    dnotice_bldr.set_reason_code(vsapi2::DisconnectReason::NodeShutdown);

                    debug!(target: VS_RPC, "VS-API -> notify_disconnect");
                    let disconnect_request_response = rpc_with_timeout(
                        "notify_disconnect",
                        DEFAULT_RPC_TIMEOUT,
                        disconnect_request.send().promise,
                    )
                    .await?;
                    let ok_or_err = disconnect_request_response.get()?.get_res()?;
                    match ok_or_err.which()? {
                        vsapi2::ok_or_error::Which::Ok(_) => {
                            info!(target: VS_RPC, "VS API notify_disconnect succeeded");
                        }
                        vsapi2::ok_or_error::Which::Error(err_obj) => {
                            let err_obj = err_obj?;
                            let err = ApiResponseError::try_from(err_obj);

                            // There is no back channel for the Stop command so we just log the error.
                            error!(
                                target: VS_RPC,
                                "VS API notify_disconnect failed: {:?}", err
                            );
                        }
                    }
                }
                Ok(())
            }

            VS2Command::Restart => {
                info!(
                    target: VS_RPC,
                    "VSConn: restart requested; recycling run loop for a fresh dial"
                );
                // Erroring out of handle_command makes the run loop emit
                // RunLoopExits and return Err, which run_with_reconnect
                // answers with a re-dial — and the re-dial's success emits
                // the fresh RunLoopStarts that un-parks vs_worker.
                Err(VSApiError::RunLoopRestart)
            }

            VS2Command::Connect(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: connect");
                let stateflag = req.state.clone();
                let resp = if cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "connect called but already connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_connect(&cmd_state.vs_service, req).await
                };

                let retval = match resp {
                    Ok(handle) => {
                        info!(target: VS_RPC, "VS API connect succeeded");
                        cmd_state.vs_handle = Some(handle);
                        self.send_lifecycle_event(VSConnLifecycleEvent::ConnectedToVsApi(
                            stateflag,
                        ));
                        Ok(())
                    }
                    Err(e) => {
                        error!(target: VS_RPC, "VS API connect failed: {:?}", e);
                        Err(e)
                    }
                };

                if let Err(e) = resp_tx.send(retval) {
                    error!(target: VS_RPC, "failed to send connect response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::Open(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: open");
                let stateflag = req.state.clone();
                let resp = if cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "open called but already connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_open(&cmd_state.vs_service, req).await
                };

                let retval = match resp {
                    Ok(handle) => {
                        info!(target: VS_RPC, "VS API open succeeded");
                        cmd_state.vs_handle = Some(handle);
                        self.send_lifecycle_event(VSConnLifecycleEvent::ConnectedToVsApi(
                            stateflag,
                        ));
                        Ok(())
                    }
                    Err(e) => {
                        error!(target: VS_RPC, "VS API open failed: {:?}", e);
                        Err(e)
                    }
                };

                if let Err(e) = resp_tx.send(retval) {
                    error!(target: VS_RPC, "failed to send open response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::VisaRequest(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: visa_request");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_visa_request(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send visa_request response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::RegisterVss(saddr, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: register_vss");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_register_vss(cmd_state.vs_handle.as_ref().unwrap(), saddr)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send register_vss response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::AuthorizeConnect(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: authorize_connect");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_authorize_connect(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send authorize_connect response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::Reauthorize(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: reauthorize");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_reauthorize(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send reauthorize response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::Reauthenticate(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: reauthenticate");
                // K2 (zipline#121): unlike Connect, this deliberately runs
                // while already connected — the whole point is to re-prove
                // ourselves on the session we already have. do_connect is
                // called on the SAME vs_service bootstrap capability; the
                // vs_handle is swapped only on success, and kept on failure
                // (the VS re-auth deadline decides, not us). Commands are
                // handled serially by this loop, so at most one
                // re-authentication is ever in flight.
                let retval = if !cmd_state.is_connected() {
                    // Never connected: nothing to re-authenticate in place.
                    Err(VSApiError::CommandFailed(
                        "reauthenticate called but not connected to VS-API".to_string(),
                    ))
                } else {
                    match self.do_connect(&cmd_state.vs_service, req).await {
                        Ok(handle) => {
                            info!(target: VS_RPC, "VS API reauthenticate succeeded; handle swapped");
                            cmd_state.vs_handle = Some(handle);
                            Ok(())
                        }
                        Err(e) => {
                            error!(
                                target: VS_RPC,
                                "VS API reauthenticate failed (keeping existing handle): {:?}", e
                            );
                            Err(e)
                        }
                    }
                };
                if let Err(e) = resp_tx.send(retval) {
                    error!(target: VS_RPC, "failed to send reauthenticate response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::NotifyDisconnect(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: notify_disconnect");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_notify_disconnect(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send notify_disconnect response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::Ping(resp_tx) => {
                debug!(target: VS_RPC, "VSConn: ping");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_ping(cmd_state.vs_handle.as_ref().unwrap(), PING_MIN_TIMEOUT)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send ping response: {:?}", e);
                }
                Ok(())
            }
            VS2Command::VisaIdsRequest(resp_tx) => {
                debug!(target: VS_RPC, "VSConn: visa_ids_request");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_visa_ids_request(cmd_state.vs_handle.as_ref().unwrap())
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send visa_ids_request response: {:?}", e);
                }
                Ok(())
            }
            VS2Command::VisaByIdsRequest(req, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: visa_by_ids_request");
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_visa_by_ids_request(cmd_state.vs_handle.as_ref().unwrap(), req)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send visa_by_ids_request response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::ReportLinkStates(reports, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: report_link_states ({} links)", reports.len());
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_report_link_states(cmd_state.vs_handle.as_ref().unwrap(), reports)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send report_link_states response: {:?}", e);
                }
                Ok(())
            }

            VS2Command::RequestBootstrapVisas(peer_cn, resp_tx) => {
                debug!(target: VS_RPC, "VSConn: request_bootstrap_visas for {peer_cn}");
                if resp_tx.is_closed() {
                    // The relay gave up waiting (J7) and closed the link:
                    // asking now would only delay the commands behind it.
                    debug!(target: VS_RPC, "VSConn: request_bootstrap_visas for {peer_cn} abandoned by its caller; not sent");
                    return Ok(());
                }
                let resp = if !cmd_state.is_connected() {
                    Err(VSApiError::CommandFailed(
                        "not connected to VS-API".to_string(),
                    ))
                } else {
                    self.do_request_bootstrap_visas(cmd_state.vs_handle.as_ref().unwrap(), &peer_cn)
                        .await
                };
                if let Err(e) = resp_tx.send(resp) {
                    error!(target: VS_RPC, "failed to send request_bootstrap_visas response: {:?}", e);
                }
                Ok(())
            }
        }
    }

    /// The `substrate_addr` param the VS requires on both `connect` and `open`.
    fn substrate_addr_param(&self) -> Param {
        Param::new_str(
            pname::SUBSTRATE_ADDR.into(),
            self.substrate_addr.to_string(),
        )
    }

    async fn do_connect(
        &self,
        vs_service: &vsapi2::visa_service::Client,
        req: NodeConnect,
    ) -> Result<vsapi2::v_s_handle::Client, VSApiError> {
        let vs_cr = VSConnectRequest {
            cn: self.node_cn.clone(),
            ctype: req.connect_type(),
            params: Some(vec![
                Param::new_ip(pname::ZPR_ADDR.into(), req.zpr_addr),
                self.substrate_addr_param(),
                // adding node's own public key as param
                Param::new_x25519_pubkey(pname::A2A_DH_PUBKEY.into(), req.a2a_dh_pubkey),
            ]),
        };

        debug!(target: VS_RPC, "VS-API -> connect (type = {:?})", vs_cr.ctype);

        let mut vs_request = vs_service.connect_request();
        let mut vscr_bldr = vs_request.get().init_req();
        vs_cr.write_to(&mut vscr_bldr);

        let vs_request_response = rpc_with_timeout(
            "connect",
            DEFAULT_CONNECT_RPC_TIMEOUT,
            vs_request.send().promise,
        )
        .await?;
        let gate_or_error = vs_request_response.get()?.get_resp()?;

        let vs_gate_svc: vsapi2::v_s_gate::Client = match gate_or_error.which()? {
            vsapi2::result::Which::Ok(vs_gate_obj) => vs_gate_obj?,
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                return Err(ApiResponseError::try_from(err_obj)?.into());
            }
        };

        // Now we have a gate we can request a challenge.
        let gate_request = vs_gate_svc.challenge_request();

        debug!(target: VS_RPC, "VS-API -> challenge");
        let gate_response = rpc_with_timeout(
            "challenge",
            DEFAULT_CONNECT_RPC_TIMEOUT,
            gate_request.send().promise,
        )
        .await?;
        let challenge = gate_response.get()?.get_challenge()?;

        let chal_data = challenge.get_bytes()?;
        let timestamp = unix_ts();

        let signed_payload = {
            let alg = challenge.get_alg()?;
            if alg != vsapi2::ChallengeAlg::RsaSha256Pkcs1v15 {
                return Err(VSApiError::CommandFailed(format!(
                    "unsupported challenge alg: {:?}",
                    alg
                )));
            }
            sign_payload(timestamp, &self.node_cn, chal_data, &self.node_private_key)
        };

        // Now authenticate with the gate.
        let mut gate_request = vs_gate_svc.authenticate_request();
        let mut auth_bldr = gate_request.get().init_cresp();
        auth_bldr.set_challenge(chal_data);
        auth_bldr.set_timestamp(timestamp);
        auth_bldr.set_bytes(&signed_payload);

        debug!(target: VS_RPC, "VS-API -> authenticate");
        let gate_response = rpc_with_timeout(
            "authenticate",
            DEFAULT_CONNECT_RPC_TIMEOUT,
            gate_request.send().promise,
        )
        .await?;
        let handle_or_error = gate_response.get()?.get_res()?;

        let vs_handle_svc: vsapi2::v_s_handle::Client = match handle_or_error.which()? {
            vsapi2::result::Which::Ok(handle_obj) => handle_obj?,
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                return Err(ApiResponseError::try_from(err_obj)?.into());
            }
        };

        // Ok we now have an authenticated handle to the VS.
        Ok(vs_handle_svc)
    }

    /// Compared to VSAPI "connect", VSAPI "open" is far simpler. The VS already knows the node
    /// (detected based on source address) is authtenticated and so a successful call just reutrns
    /// the handle directly.
    async fn do_open(
        &self,
        vs_service: &vsapi2::visa_service::Client,
        oreq: NodeOpen,
    ) -> Result<vsapi2::v_s_handle::Client, VSApiError> {
        debug!(target: VS_RPC, "VS-API -> open (type = {:?})", oreq.state);

        let req = VSConnectRequest {
            cn: self.node_cn.clone(),
            ctype: oreq.connect_type(),
            params: Some(vec![self.substrate_addr_param()]),
        };

        let mut vs_request = vs_service.open_request();
        let mut vscr_bldr = vs_request.get().init_req();
        req.write_to(&mut vscr_bldr);

        let vs_request_response = rpc_with_timeout(
            "open",
            DEFAULT_CONNECT_RPC_TIMEOUT,
            vs_request.send().promise,
        )
        .await?;

        let handle_or_error = vs_request_response.get()?.get_resp()?;

        let vs_handle_svc: vsapi2::v_s_handle::Client = match handle_or_error.which()? {
            vsapi2::result::Which::Ok(vs_handle_obj) => vs_handle_obj?,
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                return Err(ApiResponseError::try_from(err_obj)?.into());
            }
        };
        Ok(vs_handle_svc)
    }

    async fn do_visa_request(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: VisaRequest, // TODO: VisaRequest should use a PacketDesc from vs-dt, then implement write_to on it.
    ) -> Result<VisaDecision, VSApiError> {
        let mut vr_request = vs_h.visa_request_request();
        let mut vrr_bldr = vr_request.get().init_req();
        vrr_bldr.set_previous_id(0);
        let mut pd_bldr = vrr_bldr.init_packet();
        req.pdesc.write_to(&mut pd_bldr);
        let vr_response = rpc_with_timeout(
            "visa_request",
            DEFAULT_RPC_TIMEOUT,
            vr_request.send().promise,
        )
        .await?;

        let allow_deny_error: vsapi2::visa_response::Reader<'_> = vr_response.get()?.get_resp()?;
        let vr = VisaResponse::try_from(allow_deny_error)?;
        Ok(VisaDecision::try_from(vr)?)
    }

    async fn do_authorize_connect(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: ConnectRequest,
    ) -> Result<Connection, VSApiError> {
        let mut ac_request = vs_h.authorize_connect_request();
        let mut cr_bldr = ac_request.get().init_req();
        req.write_to(&mut cr_bldr);

        debug!(target: VS_RPC, "VS-API -> authorize_connect");
        let ac_response = rpc_with_timeout(
            "authorize_connect",
            DEFAULT_RPC_TIMEOUT,
            ac_request.send().promise,
        )
        .await?;
        let conn_or_error = ac_response.get()?.get_resp()?;

        match conn_or_error.which()? {
            vsapi2::result::Which::Ok(conn) => {
                let conn = conn?;
                let connection = Connection::try_from(conn)?;
                Ok(connection)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    /// Silent renewal counterpart of [Self::do_authorize_connect]
    /// (zipline#45): submits fresh auth blobs for an actor that is already
    /// docked at `req.zpr_addr`; the VS responds with an updated
    /// [Connection] carrying the new `auth_expires`.
    async fn do_reauthorize(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: ReauthRequest,
    ) -> Result<Connection, VSApiError> {
        let mut ra_request = vs_h.reauthorize_request();
        let mut rr_bldr = ra_request.get().init_req();
        req.write_to(&mut rr_bldr);

        debug!(target: VS_RPC, "VS-API -> reauthorize");
        let ra_response = rpc_with_timeout(
            "reauthorize",
            DEFAULT_RPC_TIMEOUT,
            ra_request.send().promise,
        )
        .await?;
        let conn_or_error = ra_response.get()?.get_resp()?;

        match conn_or_error.which()? {
            vsapi2::result::Which::Ok(conn) => {
                let conn = conn?;
                let connection = Connection::try_from(conn)?;
                Ok(connection)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    /// Send `reports`, this node's whole link-state snapshot, with
    /// `VSHandle.reportLinkStates` (zl-zipline#250).
    async fn do_report_link_states(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        reports: Vec<LinkStateReport>,
    ) -> Result<(), VSApiError> {
        let mut request = vs_h.report_link_states_request();
        write_link_state_reports(&reports, request.get())?;
        debug!(target: VS_RPC, "VS-API -> report_link_states");
        let response = rpc_with_timeout(
            "report_link_states",
            DEFAULT_RPC_TIMEOUT,
            request.send().promise,
        )
        .await?;
        match response.get()?.get_res()?.which()? {
            vsapi2::ok_or_error::Which::Ok(_) => Ok(()),
            vsapi2::ok_or_error::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    /// Ask for the bootstrap visas of the joining Zode whose link-verified CN
    /// is `peer_cn`, with `VSHandle.requestBootstrapVisas` (zl-zipline#252,
    /// ZODE_LINKS.md J2). The decoder already refuses any answer that is not
    /// exactly two `peer` and two `relay` visas.
    async fn do_request_bootstrap_visas(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        peer_cn: &str,
    ) -> Result<BootstrapVisas, VSApiError> {
        let mut request = vs_h.request_bootstrap_visas_request();
        request.get().set_peer_cn(peer_cn);
        debug!(target: VS_RPC, "VS-API -> request_bootstrap_visas");
        let response = rpc_with_timeout(
            "request_bootstrap_visas",
            BOOTSTRAP_VISAS_TIMEOUT,
            request.send().promise,
        )
        .await?;
        match response.get()?.get_res()?.which()? {
            vsapi2::result::Which::Ok(visas) => Ok(BootstrapVisas::try_from(visas?)?),
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    async fn do_notify_disconnect(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: DisconnectNotice,
    ) -> Result<(), VSApiError> {
        let mut nd_request = vs_h.notify_disconnect_request();
        let mut dn_bldr = nd_request.get().init_req();

        if let Some(addr) = req.zpr_addr {
            let mut addr_bldr = dn_bldr.reborrow().init_zpr_addr();
            addr.write_to(&mut addr_bldr);
        }
        dn_bldr.set_reason_code(req.reason.into());

        debug!(target: VS_RPC, "VS-API -> notify_disconnect");
        let nd_response = rpc_with_timeout(
            "notify_disconnect",
            DEFAULT_RPC_TIMEOUT,
            nd_request.send().promise,
        )
        .await?;
        let ok_or_err = nd_response.get()?.get_res()?;

        match ok_or_err.which()? {
            vsapi2::ok_or_error::Which::Ok(_) => Ok(()),
            vsapi2::ok_or_error::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    async fn do_register_vss(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        saddr: SocketAddr,
    ) -> Result<Vec<VisaOp>, VSApiError> {
        let mut rvs_request = vs_h.register_vss_request();
        let mut saddr_bldr = rvs_request.get().init_addr();
        saddr_bldr.set_port(saddr.port());

        let mut ip_bldr = saddr_bldr.init_addr();
        saddr.ip().write_to(&mut ip_bldr);

        let rvs_response = rpc_with_timeout(
            "register_vss",
            DEFAULT_RPC_TIMEOUT,
            rvs_request.send().promise,
        )
        .await?;
        let ops_or_error = rvs_response.get()?.get_res()?;

        match ops_or_error.which()? {
            vsapi2::result::Which::Ok(ops_list) => {
                let ops_list = ops_list?;
                let mut visa_ops = Vec::new();
                for i in 0..ops_list.len() {
                    let cp_visa_op = ops_list.get(i);
                    let visa_op = VisaOp::try_from(cp_visa_op)?;
                    visa_ops.push(visa_op);
                }
                Ok(visa_ops)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    async fn do_ping(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        with_timeout: Duration,
    ) -> Result<(), VSApiError> {
        trace!(target: VS_RPC, "VS-API -> ping");
        let ping_response_rdr =
            rpc_with_timeout("ping", with_timeout, vs_h.ping_request().send().promise).await?;
        match ping_response_rdr.get()?.get_res()?.which()? {
            vsapi2::ok_or_error::Which::Ok(_) => Ok(()),
            vsapi2::ok_or_error::Which::Error(err_rdr) => {
                Err(ApiResponseError::try_from(err_rdr?)?.into())
            }
        }
    }

    async fn do_visa_ids_request(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
    ) -> Result<Vec<u64>, VSApiError> {
        debug!(target: VS_RPC, "VS-API -> visa_ids_request");
        let visa_ids_reqponse_rdr = rpc_with_timeout(
            "visa_ids_request",
            DEFAULT_RPC_TIMEOUT,
            vs_h.visa_ids_request_request().send().promise,
        )
        .await?;
        let ok_or_error = visa_ids_reqponse_rdr.get()?.get_res()?;
        match ok_or_error.which()? {
            vsapi2::result::Which::Ok(ids_list_rdr) => {
                let ids: Vec<u64> = ids_list_rdr?.iter().collect();
                Ok(ids)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }

    async fn do_visa_by_ids_request(
        &self,
        vs_h: &vsapi2::v_s_handle::Client,
        req: Vec<u64>,
    ) -> Result<Vec<Visa>, VSApiError> {
        debug!(target: VS_RPC, "VS-API -> visa_by_ids_request");
        let mut visa_by_id_req = vs_h.visa_request_by_id_request();
        let mut req_builder = visa_by_id_req.get().init_req(req.len() as u32);

        for (i, id) in req.iter().enumerate() {
            req_builder.set(i as u32, *id);
        }

        let visa_by_ids_reqponse_rdr = rpc_with_timeout(
            "visa_by_ids_request",
            DEFAULT_RPC_TIMEOUT,
            visa_by_id_req.send().promise,
        )
        .await?;

        let ok_or_error = visa_by_ids_reqponse_rdr.get()?.get_res()?;
        match ok_or_error.which()? {
            vsapi2::result::Which::Ok(visa_list_rdr) => {
                let mut visas: Vec<Visa> = Vec::new();
                for visa_rdr in visa_list_rdr?.iter() {
                    visas.push(Visa::try_from(visa_rdr)?);
                }
                Ok(visas)
            }
            vsapi2::result::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Err(ApiResponseError::try_from(err_obj)?.into())
            }
        }
    }
}

impl VSConnHandle {
    // Push a command onto the command channel.
    async fn send_command(&self, cmd: VS2Command) -> Result<(), VSApiError> {
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| VSApiError::ConnClosed)
    }

    pub async fn connect(&self, req: NodeConnect) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Connect(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn open(&self, req: NodeOpen) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Open(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn stop(&self, deregister: bool) -> Result<(), VSApiError> {
        let cmd = VS2Command::Stop(deregister);
        self.send_command(cmd).await
    }

    /// Recycle the current run loop without terminating the reconnect
    /// manager: the loop exits (`RunLoopExits`), `run_with_reconnect`
    /// re-dials, and a fresh `RunLoopStarts` follows (zipline#113). Like
    /// every other command, this is discarded if it lands while the run
    /// loop is mid-dial or waiting out a reconnect delay — in those windows
    /// a restart is already in progress, so that is the desired outcome.
    pub async fn restart(&self) -> Result<(), VSApiError> {
        self.send_command(VS2Command::Restart).await
    }

    pub async fn visa_request(&self, req: VisaRequest) -> Result<VisaDecision, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::VisaRequest(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn register_vss(&self, saddr: SocketAddr) -> Result<Vec<VisaOp>, VSApiError> {
        if saddr.port() == 0 {
            return Err(VSApiError::CommandFailed(
                "cannot register VSS with port 0".to_string(),
            ));
        }
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::RegisterVss(saddr, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn authorize_connect(&self, req: ConnectRequest) -> Result<Connection, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::AuthorizeConnect(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    /// Re-prove an existing actor's authentication (zipline#45). Returns the
    /// updated [Connection]; its `auth_expires` restarts the renewal clock.
    pub async fn reauthorize(&self, req: ReauthRequest) -> Result<Connection, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Reauthorize(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    /// In-place node self re-authentication (zipline#121, contract K2):
    /// re-run connect → challenge → authenticate on the existing
    /// `vs_service` session. On success the run loop swaps in the new
    /// `vs_handle`; on failure it keeps the old one and the VS re-auth
    /// deadline decides. `Ok(())` means the node re-proved itself, not that
    /// the VS finished anything else.
    pub async fn reauthenticate(&self, req: NodeConnect) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Reauthenticate(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn notify_disconnect(&self, req: DisconnectNotice) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::NotifyDisconnect(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn ping(&self) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::Ping(resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn visa_id_request(&self) -> Result<Vec<u64>, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::VisaIdsRequest(resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    pub async fn visa_by_id_request(&self, req: Vec<u64>) -> Result<Vec<Visa>, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::VisaByIdsRequest(req, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    /// Report this node's link states to the visa service (zl-zipline#250).
    /// `reports` is the whole snapshot: a link it leaves out is one the node
    /// has nothing to say about.
    pub async fn report_link_states(
        &self,
        reports: Vec<LinkStateReport>,
    ) -> Result<(), VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::ReportLinkStates(reports, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }

    /// Ask the visa service for the bootstrap visas of a joining Zode whose
    /// link-verified certificate CN is `peer_cn` (zl-zipline#252, J2). Only the
    /// node the visa service docks on may ask. The answer holds exactly two
    /// visas for the joiner (`peer`) and two for this node (`relay`).
    pub async fn request_bootstrap_visas(
        &self,
        peer_cn: String,
    ) -> Result<BootstrapVisas, VSApiError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VS2Command::RequestBootstrapVisas(peer_cn, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSApiError::ConnClosed)?
    }
}

/// Write `reports` into a `reportLinkStates` request's parameters.
fn write_link_state_reports(
    reports: &[LinkStateReport],
    params: vsapi2::v_s_handle::report_link_states_params::Builder<'_>,
) -> Result<(), VSApiError> {
    let len = u32::try_from(reports.len())
        .map_err(|_| VSApiError::CommandFailed("too many link-state reports".to_string()))?;
    let mut list = params.init_links(len);
    for (i, report) in reports.iter().enumerate() {
        let mut entry = list.reborrow().get(i as u32);
        entry.set_peer_cn(report.peer_cn.as_str());
        entry.set_state(report.state.into());
    }
    Ok(())
}

/// Get a unix timestamp in seconds.
fn unix_ts() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Perform our node sign operation.
fn sign_payload(
    timestamp: u64,
    cn: &str,
    challenge_data: &[u8],
    private_key: &RsaKeyPair,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(cn.as_bytes());
    data.extend_from_slice(challenge_data);

    sign_rsa_key(private_key, &data)
}

/// Wrap a Cap'n Proto RPC future with a timeout, mapping errors to VSApiError.
async fn rpc_with_timeout<F, T>(
    name: &'static str,
    duration: Duration,
    fut: F,
) -> Result<T, VSApiError>
where
    F: Future<Output = Result<T, capnp::Error>>,
{
    match tokio::time::timeout(duration, fut).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(capnp_err)) => Err(capnp_err.into()),
        Err(_elapsed) => Err(VSApiError::Timeout(name.to_string())),
    }
}

#[derive(Debug)]
struct NoVerification;

// Implement the dangerous trait ServerCertVerifier NoVerification which will
// just always approve the connection
impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    }
}

// Create a dangerous connector - the verifier will always approve
// TODO decide if we want to use an actual certificate
fn tls_connect() -> TlsConnector {
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rsa::KeySize;

    impl VSConn {
        /// Construct a VSConn with a custom connect function.
        /// Intended only for unit tests that need to inject a stub TCP connector (e.g. a pending
        /// future that never resolves, to simulate a hung connection attempt).
        fn new_for_test(
            vs_addr: SocketAddr,
            node_cn: String,
            node_private_key: RsaKeyPair,
            connect_fn: ConnectFn,
        ) -> Self {
            let (cmd_tx, cmd_rx) = mpsc::channel(16);
            let (life_tx, _) = broadcast::channel(LIFECYCLE_EVENT_BUFFER_SIZE);
            VSConn {
                cmd_tx,
                cmd_rx,
                vs_addr,
                node_cn,
                node_private_key,
                life_tx,
                connect_fn,
                substrate_addr: "127.0.0.1:5000".parse().unwrap(),
            }
        }
    }

    /// zl-zipline#250: a link-state snapshot round-trips through the
    /// `reportLinkStates` parameters exactly as `do_report_link_states`
    /// writes them.
    #[test]
    fn report_link_states_capnp_builder_round_trip() {
        use zpr::vsapi_types::LinkState;
        let reports = vec![
            LinkStateReport {
                peer_cn: "a.zpr".to_string(),
                state: LinkState::Up,
            },
            LinkStateReport {
                peer_cn: "b.zpr".to_string(),
                state: LinkState::Failed,
            },
            LinkStateReport {
                peer_cn: "c.zpr".to_string(),
                state: LinkState::Down,
            },
        ];
        let mut msg = capnp::message::Builder::new_default();
        let params = msg.init_root::<vsapi2::v_s_handle::report_link_states_params::Builder>();
        write_link_state_reports(&reports, params).unwrap();
        let reader = msg
            .get_root_as_reader::<vsapi2::v_s_handle::report_link_states_params::Reader>()
            .unwrap();
        let decoded: Vec<LinkStateReport> = reader
            .get_links()
            .unwrap()
            .iter()
            .map(|r| LinkStateReport::try_from(r).unwrap())
            .collect();
        assert_eq!(decoded, reports);
    }

    /// A visa service that implements nothing: enough to build a command
    /// state that has no VS-API session.
    struct NoSessionVs;
    impl vsapi2::visa_service::Server for NoSessionVs {}

    /// With no VS-API session (the run loop is up, but `vs_handle` is
    /// unset), the run loop refuses a report locally with `CommandFailed`
    /// and sends nothing (zl-zipline#250).
    #[tokio::test]
    async fn report_link_states_without_session_is_refused_locally() {
        let mut conn = VSConn::new_for_test(
            "127.0.0.1:1".parse().unwrap(),
            "node".to_string(),
            test_key(),
            refusing_connect_fn(),
        );
        let mut cmd_state = VSCommandState::new(capnp_rpc::new_client(NoSessionVs));
        let (resp_tx, resp_rx) = oneshot::channel();
        conn.handle_command(
            &mut cmd_state,
            VS2Command::ReportLinkStates(Vec::new(), resp_tx),
        )
        .await
        .unwrap();
        assert!(matches!(
            resp_rx.await.unwrap(),
            Err(VSApiError::CommandFailed(_))
        ));
    }

    /// C3 (zipline#45): the zpr v0.27.0 `ReauthRequest` wrapper round-trips
    /// through its capnp builder exactly as `do_reauthorize` writes it —
    /// zprAddr and every auth blob survive write_to -> TryFrom intact.
    #[test]
    fn reauth_request_capnp_builder_round_trip() {
        use zpr::vsapi_types::{AuthBlob, OidcBlob};

        let req = ReauthRequest {
            zpr_addr: "10.1.2.3".parse().unwrap(),
            blobs: vec![AuthBlob::Oidc(OidcBlob {
                issuer: "https://idp.test".to_string(),
                id_token: "FAKE.JWT.TOKEN".to_string(),
                nonce: "challenge-derived-nonce".to_string(),
            })],
        };

        let mut message = capnp::message::Builder::new_default();
        let mut bldr = message.init_root::<vsapi2::reauth_request::Builder>();
        req.write_to(&mut bldr);

        let reader = bldr.into_reader();
        let decoded = ReauthRequest::try_from(reader).expect("round trip");
        assert_eq!(decoded.zpr_addr, req.zpr_addr);
        assert_eq!(decoded.blobs.len(), 1);
        match &decoded.blobs[0] {
            AuthBlob::Oidc(oidc) => {
                assert_eq!(oidc.issuer, "https://idp.test");
                assert_eq!(oidc.id_token, "FAKE.JWT.TOKEN");
                assert_eq!(oidc.nonce, "challenge-derived-nonce");
            }
            other => panic!("expected OIDC blob, got {other:?}"),
        }
    }

    fn test_key() -> RsaKeyPair {
        RsaKeyPair::generate(KeySize::Rsa2048).unwrap()
    }

    /// Connect function that always fails immediately with ConnectionRefused.
    /// Used to drive run_with_reconnect into the sleep/retry branch.
    fn refusing_connect_fn() -> ConnectFn {
        Box::new(|_addr| {
            Box::pin(async {
                Err::<tokio::net::TcpStream, _>(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "test stub",
                ))
            })
        })
    }

    /// Connect function that never resolves — simulates a TCP connect blocked waiting for a
    /// SYN-ACK that will never arrive (e.g. firewall drop / ETIMEDOUT scenario).
    fn pending_connect_fn() -> ConnectFn {
        Box::new(|_addr| Box::pin(std::future::pending::<std::io::Result<tokio::net::TcpStream>>()))
    }

    /// A minimal local TLS server: accepts one TCP connection, completes the
    /// TLS handshake, then holds the stream open. Enough for `VSConn::run`
    /// to get past TLS and emit `RunLoopStarts`; no Cap'n Proto traffic is
    /// exchanged. Returns the bound address.
    async fn spawn_tls_holding_server() -> SocketAddr {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

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

    /// zipline#113 (recovery half): after a run-loop error — here the first
    /// TCP connect being refused — `run_with_reconnect` must re-dial and,
    /// once a dial succeeds, emit `RunLoopStarts` again so `vs_worker` can
    /// re-gate and re-register with the visa service. Characterizes the
    /// reconnect machinery the keep-alive fix now relies on: it only engages
    /// because a timeout-driven VS link close no longer sends `Stop`.
    #[tokio::test]
    async fn run_loop_error_leads_to_redial_and_run_loop_starts() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let server_addr = spawn_tls_holding_server().await;

                // First dial fails (a run-loop error); later dials reach the
                // TLS server.
                let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let attempts_in_fn = attempts.clone();
                let connect_fn: ConnectFn = Box::new(move |_addr| {
                    let n = attempts_in_fn.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Box::pin(async move {
                        if n == 0 {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionRefused,
                                "first attempt refused (test stub)",
                            ))
                        } else {
                            tokio::net::TcpStream::connect(server_addr).await
                        }
                    })
                });

                let mut vsconn = test_vsconn(connect_fn);
                let mut lifecycle_rx = vsconn.subscribe_lifecycle_events();
                let handle = vsconn.handle();

                let task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_millis(50)).await
                });

                // The re-dial after the initial failure must reach
                // RunLoopStarts.
                let evt = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        match lifecycle_rx.recv().await {
                            Ok(VSConnLifecycleEvent::RunLoopStarts) => break,
                            Ok(_) => continue,
                            Err(e) => panic!("lifecycle channel died: {e:?}"),
                        }
                    }
                })
                .await;
                assert!(
                    evt.is_ok(),
                    "run_with_reconnect never re-dialed to RunLoopStarts after the initial connect error"
                );
                assert!(
                    attempts.load(std::sync::atomic::Ordering::SeqCst) >= 2,
                    "RunLoopStarts must come from a re-dial, not the failed first attempt"
                );

                // Clean exit still works from the reconnected loop.
                handle.stop(false).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect("run loop failed to stop")
                    .expect("task panicked")
                    .expect("run_with_reconnect returned an error");
            })
            .await;
    }

    fn test_vsconn(connect_fn: ConnectFn) -> VSConn {
        VSConn::new_for_test(
            "127.0.0.1:1".parse().unwrap(),
            "test-node".to_string(),
            test_key(),
            connect_fn,
        )
    }

    // ------------------------------------------------------------------
    // zipline#121 (K2): in-place self re-authentication over the existing
    // VS session. The fake visa service below implements just enough of
    // the VS-API — connect → challenge → authenticate, plus per-handle
    // ping — to observe which VSHandle serves calls after a re-auth.
    // ------------------------------------------------------------------

    /// Shared observable state of the fake visa service.
    struct FakeVsState {
        /// How many `authenticate` calls the gate has served.
        auth_calls: u32,
        /// When set, the next `authenticate` fails with AuthError (and the
        /// flag clears, so a later attempt could succeed again).
        fail_next_auth: bool,
        /// The id of the [FakeVsHandle] that served the most recent ping.
        /// Handle ids are 1-based in `authenticate` order, so after a
        /// successful re-auth a ping must arrive on id 2.
        last_ping_handle: Option<u32>,
        /// The `peerCn` of every `requestBootstrapVisas` the fake served, in
        /// order (zl-zipline#252).
        bootstrap_requests: Vec<String>,
    }

    struct FakeVs {
        state: Rc<RefCell<FakeVsState>>,
    }

    struct FakeVsGate {
        state: Rc<RefCell<FakeVsState>>,
    }

    struct FakeVsHandle {
        id: u32,
        state: Rc<RefCell<FakeVsState>>,
    }

    use std::cell::RefCell;
    use std::rc::Rc;

    impl vsapi2::visa_service::Server for FakeVs {
        async fn connect(
            self: Rc<Self>,
            _params: vsapi2::visa_service::ConnectParams,
            mut results: vsapi2::visa_service::ConnectResults,
        ) -> Result<(), capnp::Error> {
            let gate: vsapi2::v_s_gate::Client = capnp_rpc::new_client(FakeVsGate {
                state: self.state.clone(),
            });
            results.get().init_resp().set_ok(gate)?;
            Ok(())
        }
    }

    impl vsapi2::v_s_gate::Server for FakeVsGate {
        async fn challenge(
            self: Rc<Self>,
            _params: vsapi2::v_s_gate::ChallengeParams,
            mut results: vsapi2::v_s_gate::ChallengeResults,
        ) -> Result<(), capnp::Error> {
            let mut chal = results.get().init_challenge();
            chal.set_alg(vsapi2::ChallengeAlg::RsaSha256Pkcs1v15);
            chal.set_bytes(b"fake-challenge");
            Ok(())
        }

        async fn authenticate(
            self: Rc<Self>,
            _params: vsapi2::v_s_gate::AuthenticateParams,
            mut results: vsapi2::v_s_gate::AuthenticateResults,
        ) -> Result<(), capnp::Error> {
            let id = {
                let mut st = self.state.borrow_mut();
                st.auth_calls += 1;
                if st.fail_next_auth {
                    st.fail_next_auth = false;
                    let mut err = results.get().init_res().init_error();
                    ApiResponseError::new_code_msg(
                        zpr::vsapi_types::ErrorCode::AuthError,
                        "fake auth failure",
                    )
                    .write_to(&mut err);
                    return Ok(());
                }
                st.auth_calls
            };
            let handle: vsapi2::v_s_handle::Client = capnp_rpc::new_client(FakeVsHandle {
                id,
                state: self.state.clone(),
            });
            results.get().init_res().set_ok(handle)?;
            Ok(())
        }
    }

    impl vsapi2::v_s_handle::Server for FakeVsHandle {
        async fn ping(
            self: Rc<Self>,
            _params: vsapi2::v_s_handle::PingParams,
            mut results: vsapi2::v_s_handle::PingResults,
        ) -> Result<(), capnp::Error> {
            self.state.borrow_mut().last_ping_handle = Some(self.id);
            results.get().init_res().set_ok(());
            Ok(())
        }

        /// Answer for [FAKE_JOINER_CN] with [fake_bootstrap_visas]; refuse any
        /// other CN with `notFound`, as the real visa service does for a CN
        /// that is not a peer in the caller's topology (zl-zipline#252 J3).
        async fn request_bootstrap_visas(
            self: Rc<Self>,
            params: vsapi2::v_s_handle::RequestBootstrapVisasParams,
            mut results: vsapi2::v_s_handle::RequestBootstrapVisasResults,
        ) -> Result<(), capnp::Error> {
            let peer_cn = params.get()?.get_peer_cn()?.to_string()?;
            self.state
                .borrow_mut()
                .bootstrap_requests
                .push(peer_cn.clone());
            if peer_cn == SLOW_JOINER_CN {
                // Never answers within a test: the caller's bound decides.
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            if peer_cn == FAKE_JOINER_CN {
                fake_bootstrap_visas().write_to(&mut results.get().init_res().init_ok());
            } else {
                let mut err = results.get().init_res().init_error();
                ApiResponseError::new_code_msg(
                    zpr::vsapi_types::ErrorCode::NotFound,
                    "no such peer",
                )
                .write_to(&mut err);
            }
            Ok(())
        }
    }

    /// The CN the fake visa service mints bootstrap visas for.
    const FAKE_JOINER_CN: &str = "joiner.zpr";

    /// A CN the fake visa service takes a minute to answer for.
    const SLOW_JOINER_CN: &str = "slow.zpr";

    /// The answer the fake visa service gives for [FAKE_JOINER_CN]: two
    /// distinct visas in each list, so a test can check the order survives.
    fn fake_bootstrap_visas() -> BootstrapVisas {
        use zpr::vsapi_types::{DockPepType, EndpointT, KeySet, TcpUdpPep};
        let visa = |id: u64| {
            Visa::new(
                id,
                0,
                UNIX_EPOCH + Duration::from_secs(1_800_000_000),
                "10.1.1.9".parse().unwrap(),
                "10.1.1.1".parse().unwrap(),
                DockPepType::TCP(TcpUdpPep {
                    source_port: 0,
                    dest_port: 5002,
                    endpoint: EndpointT::Client,
                }),
                KeySet::default(),
                None,
            )
        };
        BootstrapVisas {
            peer: vec![visa(101), visa(102)],
            relay: vec![visa(101), visa(102)],
        }
    }

    /// Spawn the fake VS: TLS + capnp RPC, bootstrap capability is a
    /// [FakeVs]. Returns the bound address and the shared state.
    async fn spawn_fake_vs() -> (SocketAddr, Rc<RefCell<FakeVsState>>) {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let state = Rc::new(RefCell::new(FakeVsState {
            auth_calls: 0,
            fail_next_auth: false,
            last_ping_handle: None,
            bootstrap_requests: Vec::new(),
        }));

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
        let server_state = state.clone();
        tokio::task::spawn_local(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = server_state.clone();
                tokio::task::spawn_local(async move {
                    let Ok(tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let (reader, writer) = tokio::io::split(tls);
                    let network = capnp_rpc::twoparty::VatNetwork::new(
                        tokio::io::BufReader::new(reader).compat(),
                        tokio::io::BufWriter::new(writer).compat_write(),
                        capnp_rpc::rpc_twoparty_capnp::Side::Server,
                        capnp::message::ReaderOptions::new(),
                    );
                    let vs: vsapi2::visa_service::Client = capnp_rpc::new_client(FakeVs { state });
                    let rpc = capnp_rpc::RpcSystem::new(Box::new(network), Some(vs.client));
                    let _ = rpc.await;
                });
            }
        });
        (addr, state)
    }

    /// Drive a real VSConn against the fake VS through the initial connect,
    /// returning (handle, state, run-loop task). The caller re-auths.
    async fn connected_vsconn_against_fake_vs() -> (
        VSConnHandle,
        Rc<RefCell<FakeVsState>>,
        tokio::task::JoinHandle<Result<(), VSApiError>>,
    ) {
        let (vs_addr, state) = spawn_fake_vs().await;
        let mut vsconn = VSConn::new(
            16,
            vs_addr,
            "test-node".to_string(),
            test_key(),
            "127.0.0.1:5000".parse().unwrap(),
        );
        let mut lifecycle_rx = vsconn.subscribe_lifecycle_events();
        let handle = vsconn.handle();
        let task = tokio::task::spawn_local(async move {
            vsconn.run_with_reconnect(Duration::from_millis(100)).await
        });

        // Wait for the run loop, then bootstrap-connect.
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
        .expect("run loop never started against the fake VS");

        handle
            .connect(NodeConnect {
                zpr_addr: "10.1.1.1".parse().unwrap(),
                state: StateFlag::NoState,
                a2a_dh_pubkey: x25519_dalek::PublicKey::from([7u8; 32]),
            })
            .await
            .expect("initial connect against the fake VS failed");

        (handle, state, task)
    }

    /// zipline#121 K2: a successful `Reauthenticate` re-runs the
    /// connect/challenge/authenticate sequence on the existing session and
    /// swaps in the new handle — a subsequent ping is served by the second
    /// handle the fake VS minted.
    #[tokio::test]
    async fn reauthenticate_success_swaps_the_vs_handle() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (handle, state, task) = connected_vsconn_against_fake_vs().await;
                assert_eq!(state.borrow().auth_calls, 1);

                handle.ping().await.expect("ping on the original handle");
                assert_eq!(state.borrow().last_ping_handle, Some(1));

                handle
                    .reauthenticate(NodeConnect {
                        zpr_addr: "10.1.1.1".parse().unwrap(),
                        state: StateFlag::HasState,
                        a2a_dh_pubkey: x25519_dalek::PublicKey::from([7u8; 32]),
                    })
                    .await
                    .expect("reauthenticate must succeed against the fake VS");
                assert_eq!(
                    state.borrow().auth_calls,
                    2,
                    "re-auth must run the authenticate sequence exactly once more"
                );

                handle.ping().await.expect("ping after re-auth");
                assert_eq!(
                    state.borrow().last_ping_handle,
                    Some(2),
                    "after a successful re-auth the NEW handle must serve calls"
                );

                handle.stop(false).await.unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
            })
            .await;
    }

    /// zipline#121 K2: a failed `Reauthenticate` keeps the old handle — the
    /// VS deadline decides the actor's fate, the node does not tear anything
    /// down. A subsequent ping is still served by the original handle.
    #[tokio::test]
    async fn reauthenticate_failure_keeps_the_old_vs_handle() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (handle, state, task) = connected_vsconn_against_fake_vs().await;

                state.borrow_mut().fail_next_auth = true;
                let res = handle
                    .reauthenticate(NodeConnect {
                        zpr_addr: "10.1.1.1".parse().unwrap(),
                        state: StateFlag::HasState,
                        a2a_dh_pubkey: x25519_dalek::PublicKey::from([7u8; 32]),
                    })
                    .await;
                assert!(res.is_err(), "reauthenticate must report the VS rejection");
                assert_eq!(
                    state.borrow().auth_calls,
                    2,
                    "the failed re-auth still reached authenticate"
                );

                handle
                    .ping()
                    .await
                    .expect("the session must survive a failed re-auth");
                assert_eq!(
                    state.borrow().last_ping_handle,
                    Some(1),
                    "after a failed re-auth the OLD handle must still serve calls"
                );

                handle.stop(false).await.unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
            })
            .await;
    }

    /// zl-zipline#252 (t205): `request_bootstrap_visas` sends the CN as given
    /// and returns the visa service's answer, both lists in order.
    #[tokio::test]
    async fn request_bootstrap_visas_returns_the_answer() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (handle, state, task) = connected_vsconn_against_fake_vs().await;

                let answer = handle
                    .request_bootstrap_visas(FAKE_JOINER_CN.to_string())
                    .await
                    .expect("the fake VS mints for its joiner CN");
                assert_eq!(answer, fake_bootstrap_visas());
                assert_eq!(state.borrow().bootstrap_requests, vec![FAKE_JOINER_CN]);

                handle.stop(false).await.unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
            })
            .await;
    }

    /// zl-zipline#252 (J7): a bootstrap-visa request the visa service does
    /// not answer fails after [BOOTSTRAP_VISAS_TIMEOUT], not the default RPC
    /// timeout, so it holds the serial command loop no longer than the relay
    /// waits for it.
    #[tokio::test]
    async fn request_bootstrap_visas_is_bounded_by_its_own_timeout() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (handle, _state, task) = connected_vsconn_against_fake_vs().await;

                let started = tokio::time::Instant::now();
                let err = handle
                    .request_bootstrap_visas(SLOW_JOINER_CN.to_string())
                    .await
                    .expect_err("the fake VS does not answer in time");
                assert!(matches!(err, VSApiError::Timeout(_)), "got {err:?}");
                assert!(
                    started.elapsed() < BOOTSTRAP_VISAS_TIMEOUT + Duration::from_secs(2),
                    "bounded by BOOTSTRAP_VISAS_TIMEOUT, took {:?}",
                    started.elapsed()
                );

                handle.stop(false).await.unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
            })
            .await;
    }

    /// zl-zipline#252 (J7): a bootstrap-visa request whose caller has
    /// already given up (its answer would be dropped) is not sent: a stale
    /// request never delays the ones behind it.
    #[tokio::test]
    async fn request_bootstrap_visas_skips_an_abandoned_request() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (handle, state, task) = connected_vsconn_against_fake_vs().await;

                let (resp_tx, resp_rx) = oneshot::channel();
                drop(resp_rx);
                handle
                    .send_command(VS2Command::RequestBootstrapVisas(
                        SLOW_JOINER_CN.to_string(),
                        resp_tx,
                    ))
                    .await
                    .unwrap();
                handle
                    .request_bootstrap_visas(FAKE_JOINER_CN.to_string())
                    .await
                    .expect("the request behind the abandoned one is answered");
                assert_eq!(state.borrow().bootstrap_requests, vec![FAKE_JOINER_CN]);

                handle.stop(false).await.unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
            })
            .await;
    }

    /// zl-zipline#252 (t205): a visa-service refusal comes back as the coded
    /// error, so the relay can log the code and close the link (J7).
    #[tokio::test]
    async fn request_bootstrap_visas_maps_a_refusal_to_its_code() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (handle, _state, task) = connected_vsconn_against_fake_vs().await;

                let err = handle
                    .request_bootstrap_visas("stranger.zpr".to_string())
                    .await
                    .expect_err("the fake VS refuses an unknown CN");
                assert!(
                    matches!(
                        &err,
                        VSApiError::CodedError(e) if e.code == zpr::vsapi_types::ErrorCode::NotFound
                    ),
                    "expected notFound, got {err:?}"
                );

                handle.stop(false).await.unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
            })
            .await;
    }

    /// zl-zipline#252 (t205): with no VS-API session the run loop refuses a
    /// bootstrap-visa request locally and sends nothing.
    #[tokio::test]
    async fn request_bootstrap_visas_without_session_is_refused_locally() {
        let mut conn = VSConn::new_for_test(
            "127.0.0.1:1".parse().unwrap(),
            "node".to_string(),
            test_key(),
            refusing_connect_fn(),
        );
        let mut cmd_state = VSCommandState::new(capnp_rpc::new_client(NoSessionVs));
        let (resp_tx, resp_rx) = oneshot::channel();
        conn.handle_command(
            &mut cmd_state,
            VS2Command::RequestBootstrapVisas(FAKE_JOINER_CN.to_string(), resp_tx),
        )
        .await
        .unwrap();
        assert!(matches!(
            resp_rx.await.unwrap(),
            Err(VSApiError::CommandFailed(_))
        ));
    }

    /// Before fix: run_with_reconnect blocks in tokio::time::sleep(reconnect_after) even when a
    /// Stop command is already in the channel, causing a full 30-second delay.
    /// After fix: the select! between the sleep and cmd_rx delivers Stop immediately.
    #[tokio::test]
    async fn stop_during_reconnect_delay_exits_promptly() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let mut vsconn = test_vsconn(refusing_connect_fn());
                let handle = vsconn.handle();

                let task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_secs(30)).await
                });

                // Wait for the first failed connect and entry into the reconnect sleep.
                tokio::time::sleep(Duration::from_millis(50)).await;

                handle.stop(false).await.unwrap();

                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect(
                        "run_with_reconnect hung past 2s — was sleeping for 30s without the fix",
                    )
                    .expect("task panicked")
                    .expect("run_with_reconnect returned an error");
            })
            .await;
    }

    /// Before fix: run_with_reconnect → run() blocks in (connect_fn)() with no cmd_rx polling,
    /// so the Stop command is never processed until the connect times out.
    /// After fix: run() selects between the connect future and cmd_rx; Stop causes a clean exit.
    #[tokio::test]
    async fn stop_during_tcp_connect_exits_promptly() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let mut vsconn = test_vsconn(pending_connect_fn());
                let handle = vsconn.handle();

                let task = tokio::task::spawn_local(async move {
                    vsconn.run_with_reconnect(Duration::from_secs(30)).await
                });

                // Give the connect a moment to start.
                tokio::time::sleep(Duration::from_millis(50)).await;

                handle.stop(false).await.unwrap();

                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect("run_with_reconnect hung past 2s — was blocked in connect() without the fix")
                    .expect("task panicked")
                    .expect("run_with_reconnect returned an error");
            })
            .await;
    }
}
