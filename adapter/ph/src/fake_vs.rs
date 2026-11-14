//! A fake visa service for unit tests: TLS plus Cap'n Proto RPC, serving
//! just enough of the VS-API for a real [VSConn] to connect
//! (connect → challenge → authenticate), register its VSS, disconnect, ping,
//! and log its own actor in and out (`getLoginNonce`, `reauthorize`,
//! zl-zipline#233). Shared by the `vs_worker` and `zode_login` tests.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libnode::vsconn::{NodeConnect, StateFlag, VSConn, VSConnHandle, VSConnLifecycleEvent};
use tokio::sync::broadcast;
use zpr::vsapi::v1 as vsapi2;
use zpr::vsapi_types::{ApiResponseError, Connection, ErrorCode, LoginNonce, ReauthRequest};
use zpr::write_to::WriteTo;

/// How long a minted login nonce is valid unless a test says otherwise.
pub const DEFAULT_NONCE_LIFETIME: Duration = Duration::from_secs(600);

/// The authentication lifetime `reauthorize` grants unless a test says
/// otherwise.
pub const DEFAULT_AUTH_LIFETIME: Duration = Duration::from_secs(3600);

/// The CN of the node under test.
pub const NODE_CN: &str = "test-node";

/// Shared observable state of the fake visa service.
#[derive(Default)]
pub struct FakeVsState {
    /// How many `register_vss` calls arrived.
    pub register_calls: u32,
    /// Fail this many leading `register_vss` calls with Internal —
    /// the error the real VS returns when the VS→VSS visa mint denies.
    pub fail_registers: u32,
    /// When set, `notify_disconnect` fails with AuthRequired, like the
    /// real VS once it has already dropped the node (issue log).
    pub fail_notify_disconnect: bool,
    /// Set when a `register_vss` call succeeds.
    pub register_succeeded: bool,
    /// How many VS-API connections (TCP) the fake accepted.
    pub connections: u32,
    /// Every `connect`, in order: true for `reconnect`, false for
    /// `reset` (zl-zipline#252, R16).
    pub connects: Vec<bool>,
    /// When set, a `reconnect` is refused with this code (R16).
    pub refuse_reconnect: Option<zpr::vsapi_types::ErrorCode>,
    /// When set, every `authenticate` fails with AuthError.
    pub fail_auth: bool,
    /// How many `getLoginNonce` calls arrived; the nth nonce minted is
    /// `vs-nonce-<n>` (zl-zipline#233).
    pub login_nonces: u32,
    /// How long a minted login nonce is valid; [DEFAULT_NONCE_LIFETIME]
    /// when unset.
    pub nonce_lifetime: Option<Duration>,
    /// Every `reauthorize` request, in order (zl-zipline#233).
    pub reauths: Vec<ReauthRequest>,
    /// Codes to refuse the next `reauthorize` calls with, one per call, in
    /// order; once empty, `reauthorize` succeeds.
    pub reauth_errors: VecDeque<ErrorCode>,
    /// The authentication lifetime a successful `reauthorize` grants
    /// (`authExpires = now + lifetime`); [DEFAULT_AUTH_LIFETIME] when unset.
    pub auth_lifetime: Option<Duration>,
    /// How long `reauthorize` takes to answer, after recording the
    /// request; immediate when unset.
    pub reauth_delay: Option<Duration>,
}

struct FakeVs {
    state: Rc<RefCell<FakeVsState>>,
}
struct FakeVsGate {
    state: Rc<RefCell<FakeVsState>>,
}
struct FakeVsHandle {
    state: Rc<RefCell<FakeVsState>>,
}

impl vsapi2::visa_service::Server for FakeVs {
    async fn connect(
        self: Rc<Self>,
        params: vsapi2::visa_service::ConnectParams,
        mut results: vsapi2::visa_service::ConnectResults,
    ) -> Result<(), capnp::Error> {
        let req = zpr::vsapi_types::VSConnectRequest::try_from(params.get()?.get_req()?)
            .map_err(|e| capnp::Error::failed(format!("{e:?}")))?;
        let reconnect = matches!(req.ctype, zpr::vsapi_types::ConnectType::Reconnect);
        let refusal = {
            let mut st = self.state.borrow_mut();
            st.connects.push(reconnect);
            st.refuse_reconnect.clone().filter(|_| reconnect)
        };
        if let Some(code) = refusal {
            let mut err = results.get().init_resp().init_error();
            ApiResponseError::new_code_msg(code, "refusing reconnect").write_to(&mut err);
            return Ok(());
        }
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
        if self.state.borrow().fail_auth {
            let mut err = results.get().init_res().init_error();
            ApiResponseError::new_code_msg(
                zpr::vsapi_types::ErrorCode::AuthError,
                "fake auth failure",
            )
            .write_to(&mut err);
            return Ok(());
        }
        let handle: vsapi2::v_s_handle::Client = capnp_rpc::new_client(FakeVsHandle {
            state: self.state.clone(),
        });
        results.get().init_res().set_ok(handle)?;
        Ok(())
    }
}

impl vsapi2::v_s_handle::Server for FakeVsHandle {
    async fn register_vss(
        self: Rc<Self>,
        _params: vsapi2::v_s_handle::RegisterVssParams,
        mut results: vsapi2::v_s_handle::RegisterVssResults,
    ) -> Result<(), capnp::Error> {
        let mut st = self.state.borrow_mut();
        st.register_calls += 1;
        if st.register_calls <= st.fail_registers {
            let mut err = results.get().init_res().init_error();
            ApiResponseError::new_code_msg(
                zpr::vsapi_types::ErrorCode::Internal,
                "failed to initialize node VSS",
            )
            .write_to(&mut err);
        } else {
            st.register_succeeded = true;
            results.get().init_res().initn_ok(0);
        }
        Ok(())
    }

    async fn notify_disconnect(
        self: Rc<Self>,
        _params: vsapi2::v_s_handle::NotifyDisconnectParams,
        mut results: vsapi2::v_s_handle::NotifyDisconnectResults,
    ) -> Result<(), capnp::Error> {
        let fail = self.state.borrow().fail_notify_disconnect;
        if fail {
            let mut err = results.get().init_res().init_error();
            ApiResponseError::new_code_msg(
                zpr::vsapi_types::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            )
            .write_to(&mut err);
        } else {
            results.get().init_res().set_ok(());
        }
        Ok(())
    }

    async fn ping(
        self: Rc<Self>,
        _params: vsapi2::v_s_handle::PingParams,
        mut results: vsapi2::v_s_handle::PingResults,
    ) -> Result<(), capnp::Error> {
        results.get().init_res().set_ok(());
        Ok(())
    }

    /// Mint the next login nonce, `vs-nonce-<n>` (zl-zipline#233).
    async fn get_login_nonce(
        self: Rc<Self>,
        _params: vsapi2::v_s_handle::GetLoginNonceParams,
        mut results: vsapi2::v_s_handle::GetLoginNonceResults,
    ) -> Result<(), capnp::Error> {
        let nonce = {
            let mut st = self.state.borrow_mut();
            st.login_nonces += 1;
            LoginNonce {
                nonce: format!("vs-nonce-{}", st.login_nonces),
                expires_at: SystemTime::now() + st.nonce_lifetime.unwrap_or(DEFAULT_NONCE_LIFETIME),
            }
        };
        nonce.write_to(&mut results.get().init_res().init_ok());
        Ok(())
    }

    /// Record the request; refuse it with the next queued code, if any,
    /// otherwise grant the configured lifetime (zl-zipline#233).
    async fn reauthorize(
        self: Rc<Self>,
        params: vsapi2::v_s_handle::ReauthorizeParams,
        mut results: vsapi2::v_s_handle::ReauthorizeResults,
    ) -> Result<(), capnp::Error> {
        let req = ReauthRequest::try_from(params.get()?.get_req()?)
            .map_err(|e| capnp::Error::failed(format!("{e:?}")))?;
        let zpr_addr = req.zpr_addr;
        let delay = {
            let mut st = self.state.borrow_mut();
            st.reauths.push(req);
            st.reauth_delay
        };
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let (refusal, lifetime) = {
            let mut st = self.state.borrow_mut();
            (
                st.reauth_errors.pop_front(),
                st.auth_lifetime.unwrap_or(DEFAULT_AUTH_LIFETIME),
            )
        };
        if let Some(code) = refusal {
            let mut err = results.get().init_resp().init_error();
            ApiResponseError::new_code_msg(code, "fake reauthorize refusal").write_to(&mut err);
            return Ok(());
        }
        let auth_expires = (SystemTime::now() + lifetime)
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        Connection {
            zpr_addr,
            auth_expires,
        }
        .write_to(&mut results.get().init_resp().init_ok());
        Ok(())
    }
}

/// Spawn the fake VS: TLS + capnp RPC, bootstrap capability is a
/// [FakeVs]. Returns the bound address and the shared state. Mirrors
/// the libnode2 test helper (vsconn.rs).
pub async fn spawn_fake_vs(state: FakeVsState) -> (std::net::SocketAddr, Rc<RefCell<FakeVsState>>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_util::compat::*;

    let state = Rc::new(RefCell::new(state));

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let chain = vec![CertificateDer::from(cert.cert.der().clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::task::spawn_local(async move {
        while let Ok((sock, _)) = listener.accept().await {
            server_state.borrow_mut().connections += 1;
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

/// Start a real [VSConn] for [NODE_CN] against a new fake visa service in
/// `state`, with its run loop on the local set. Returns the fake's state,
/// the VSConn handle and its lifecycle receiver. Nothing has connected yet.
pub async fn start_vsconn(
    state: FakeVsState,
) -> (
    Rc<RefCell<FakeVsState>>,
    VSConnHandle,
    broadcast::Receiver<VSConnLifecycleEvent>,
) {
    let (vs_addr, state) = spawn_fake_vs(state).await;
    let mut vsconn = VSConn::new(
        16,
        vs_addr,
        NODE_CN.to_string(),
        aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("test RSA key"),
        "127.0.0.1:5000".parse().unwrap(),
    );
    let lifecycle_rx = vsconn.subscribe_lifecycle_events();
    let vs_handle = vsconn.handle();
    tokio::task::spawn_local(
        async move { vsconn.run_with_reconnect(Duration::from_millis(50)).await },
    );
    (state, vs_handle, lifecycle_rx)
}

/// Like [start_vsconn], then wait for the run loop and connect as the node
/// at `zpr_addr`, so the handle has a VS-API session.
pub async fn connected_vsconn(
    state: FakeVsState,
    zpr_addr: std::net::IpAddr,
) -> (Rc<RefCell<FakeVsState>>, VSConnHandle) {
    let (state, vs_handle, mut lifecycle_rx) = start_vsconn(state).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !matches!(
            lifecycle_rx.recv().await,
            Ok(VSConnLifecycleEvent::RunLoopStarts)
        ) {}
    })
    .await
    .expect("the run loop never started against the fake VS");
    vs_handle
        .connect(NodeConnect {
            zpr_addr,
            state: StateFlag::NoState,
            a2a_dh_pubkey: x25519_dalek::PublicKey::from([7u8; 32]),
        })
        .await
        .expect("connect against the fake VS");
    (state, vs_handle)
}

/// Wait up to `window` for `done` to hold; true if it did.
pub async fn eventually(window: Duration, mut done: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(window, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}
