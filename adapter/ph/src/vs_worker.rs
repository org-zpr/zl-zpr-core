use std::net::{IpAddr, SocketAddr};
use tokio::sync::broadcast;

use crate::prelude::*;
use crate::visa_mgmt;
use crate::vss_worker;

use libnode::error::VSApiError;
use libnode::vsconn::{NodeConnect, StateFlag, VSConnHandle, VSConnLifecycleEvent};
use zpr::vsapi_types::{DisconnectNotice, DisconnectReason, ErrorCode};

pub async fn launch(
    asm: Arc<Assembly>,
    node_zpr_addr: IpAddr,
    vss_addr: SocketAddr,
    vs_handle: VSConnHandle,
    mut lifecycle_rx: broadcast::Receiver<VSConnLifecycleEvent>,
) {
    // When launched, we have no state with the VS.
    let mut state = StateFlag::NoState;

    //derive pubkey from a2a_dh_keypair
    let a2a_dh_pubkey = x25519_dalek::PublicKey::from(&asm.a2a_dh_keypair);

    loop {
        // This acts as a gate -- waiting for runloop to start.
        wait_for_runloop_start(&mut lifecycle_rx).await;

        loop {
            // Kick off a connect request to the VS, if it succeeds, notify the VS about our VSS endpoint.
            let req = NodeConnect {
                zpr_addr: node_zpr_addr,
                state,
                a2a_dh_pubkey,
            };

            // Race the connect call against lifecycle events. We use a bool here because
            // ConnectedToVsApi can fire while connect() is still in-flight (the run loop
            // sends it before replying on the oneshot). Treating it as success avoids
            // issuing a second connect() call against an already-connected run loop.
            let connected = tokio::select! {
                res = vs_handle.connect(req) => {
                    match res {
                        Ok(()) => {
                            info!(target: STARTUP, "node access granted to visa service");
                            true
                        }
                        Err(VSApiError::CodedError(err)) if matches!(err.code, ErrorCode::OutOfSync) => {
                            state = StateFlag::NoState;
                            info!(target: STARTUP, "visa service reports out-of-sync; clearing adapters and visas");
                            asm.disconnect_adapters().await; // drops visas too
                            false
                        }
                        Err(e) => {
                            error!(target: STARTUP, "failed to get access to visa service: {e:?}");
                            false
                        }
                    }
                }

                evt = lifecycle_rx.recv() => {
                    match evt {
                        Ok(VSConnLifecycleEvent::RunLoopExits) => {
                            info!(target: STARTUP, "VSConn runloop exited; aborting connect attempts and re-gating");
                            break; // break inner connect loop, go re-gate on RunLoopStarts
                        }
                        Ok(VSConnLifecycleEvent::RunLoopStarts) => {
                            // harmless duplicate start
                            false
                        }
                        Ok(VSConnLifecycleEvent::ConnectedToVsApi(stateflag)) => {
                            // The connect() future was in-flight when this fired: the run loop
                            // already has a handle. Treat as success; do not retry connect().
                            info!(target: STARTUP, "node access granted to visa service (state = {:?})", stateflag);
                            true
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
                            false
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                            return; // ABORT entire worker
                        }
                    }
                }
            };

            if connected {
                // VSS registration snapshots both actors' A2A keys into its callback
                // visa. Register the bootstrapped VS adapter before minting that visa.
                let deferred = asm.deferred_vs_connect.lock().unwrap().take();
                if let Some((vs_link_id, assigned_addr, conn_req)) = deferred {
                    if let Err(e) = visa_mgmt::send_deferred_vs_connect(
                        &asm,
                        vs_link_id,
                        assigned_addr,
                        conn_req,
                    )
                    .await
                    {
                        panic!(
                            "{}: deferred visa service adapter connect failed: {e}",
                            asm.formatted_link_id(vs_link_id)
                        );
                    }
                }
                match vs_handle.register_vss(vss_addr).await {
                    Ok(ops) => {
                        info!(target: STARTUP, "registered VSS, received {} pending visa ops", ops.len());
                        for op in ops {
                            if let Err(e) = vss_worker::process_visaop(&asm, op) {
                                error!(target: STARTUP, "failed to process initial visa op from VS: {e:?}");
                            }
                        }

                        // Next time we connect, we have state.
                        state = StateFlag::HasState;
                        break; // Exit inner loop; go back to waiting for a state change.
                    }
                    Err(e) => {
                        error!(target: STARTUP, "failed to register VSS: {e:?}");

                        // Tell the VS we are gone (best-effort), then recycle
                        // the run loop so the retry starts from a clean dial
                        // (zipline#167). Without the restart the run loop's
                        // vs_handle stays set and every retry dies locally
                        // with CommandFailed("connect called but already
                        // connected to VS-API") — the node never re-registers.
                        let dreq = DisconnectNotice {
                            zpr_addr: None,
                            reason: DisconnectReason::LinkError,
                        };
                        if let Err(e) = vs_handle.notify_disconnect(dreq).await {
                            // A dead VS link is not a reason to kill the node:
                            // the VS has typically already dropped us (it
                            // answers AuthRequired), so there is nothing to
                            // deregister. Log and fall through to the restart.
                            error!(target: STARTUP, "error disconnecting from VS after failed registration: {e:?}");
                        }
                        if let Err(e) = vs_handle.restart().await {
                            // Discarded mid-dial or during a reconnect delay
                            // means a restart is already in progress — the
                            // desired outcome either way.
                            info!(target: STARTUP, "VSConn restart request not delivered (restart already in progress?): {e:?}");
                        }
                        // Re-gate on the fresh RunLoopStarts the re-dial emits.
                        break;
                    }
                }
            }

            // wait a second and retry.
            tokio::time::sleep(config::VSCONN_RETRY_WAIT).await;
        }
    }
}

async fn wait_for_runloop_start(lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>) {
    loop {
        match lifecycle_rx.recv().await {
            Ok(VSConnLifecycleEvent::RunLoopStarts) => return,
            Ok(_) => {
                // ignored
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
                continue; // try again
            }
            Err(broadcast::error::RecvError::Closed) => {
                error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                return; // ABORT entire worker
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use libnode::vsconn::VSConn;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;
    use tokio::task::LocalSet;
    use zpr::vsapi::v1 as vsapi2;
    use zpr::vsapi_types::ApiResponseError;
    use zpr::write_to::WriteTo;

    // ------------------------------------------------------------------
    // zipline#167 defect 2: after a failed VSS registration the node must
    // leave the VS connection reconnectable. Today the failure arm only
    // sends notify_disconnect: the run loop's `cmd_state.vs_handle` stays
    // set, so every retry's `connect` fails locally with
    // CommandFailed("connect called but already connected to VS-API") and
    // the node never re-registers — the wedge from the issue log.
    //
    // The fake VS below implements just enough of the VS-API — connect →
    // challenge → authenticate, register_vss, notify_disconnect, ping — to
    // fail registration a configurable number of times and observe whether
    // the node's retry ever reaches registration again.
    // ------------------------------------------------------------------

    /// Shared observable state of the fake visa service.
    struct FakeVsState {
        /// How many `register_vss` calls arrived.
        register_calls: u32,
        /// Fail this many leading `register_vss` calls with Internal —
        /// the error the real VS returns when the VS→VSS visa mint denies.
        fail_registers: u32,
        /// When set, `notify_disconnect` fails with AuthRequired, like the
        /// real VS once it has already dropped the node (issue log).
        fail_notify_disconnect: bool,
        /// Set when a `register_vss` call succeeds.
        register_succeeded: bool,
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
    }

    /// Spawn the fake VS: TLS + capnp RPC, bootstrap capability is a
    /// [FakeVs]. Returns the bound address and the shared state. Mirrors
    /// the libnode2 test helper (vsconn.rs).
    async fn spawn_fake_vs(
        fail_registers: u32,
        fail_notify_disconnect: bool,
    ) -> (std::net::SocketAddr, Rc<RefCell<FakeVsState>>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_util::compat::*;

        let state = Rc::new(RefCell::new(FakeVsState {
            register_calls: 0,
            fail_registers,
            fail_notify_disconnect,
            register_succeeded: false,
        }));

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

    /// Stand up the whole pair — real VSConn against the fake VS, the real
    /// `vs_worker::launch` driving it — and wait for `register_vss` to
    /// succeed. Returns whether it did within `window`, and the fake VS
    /// state for call-count assertions.
    async fn run_worker_until_registered(
        fail_registers: u32,
        fail_notify_disconnect: bool,
        window: Duration,
    ) -> (bool, Rc<RefCell<FakeVsState>>) {
        let (vs_addr, state) = spawn_fake_vs(fail_registers, fail_notify_disconnect).await;

        let mut vsconn = VSConn::new(
            16,
            vs_addr,
            "test-node".to_string(),
            aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
                .expect("test RSA key"),
            "127.0.0.1:5000".parse().unwrap(),
        );
        let lifecycle_rx = vsconn.subscribe_lifecycle_events();
        let vs_handle = vsconn.handle();
        let _vsconn_task = tokio::task::spawn_local(async move {
            vsconn.run_with_reconnect(Duration::from_millis(50)).await
        });

        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let node_zpr_addr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let vss_addr: SocketAddr = "[fd5a:5052:3000::2]:8183".parse().unwrap();
        let worker = tokio::task::spawn_local(launch(
            asm,
            node_zpr_addr,
            vss_addr,
            vs_handle,
            lifecycle_rx,
        ));

        let registered = tokio::time::timeout(window, async {
            loop {
                if state.borrow().register_succeeded {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok();

        worker.abort();
        (registered, state)
    }

    /// zipline#167 defect 2: a failed VSS registration must leave the VS
    /// connection reconnectable. The fake VS fails the first register_vss
    /// (as the real VS does when it loses the re-register race) and then
    /// accepts; the worker's retry must get past `connect` — no
    /// CommandFailed("connect called but already connected to VS-API")
    /// wedge — and register successfully.
    #[tokio::test]
    async fn test_failed_register_vss_leaves_connection_reconnectable() {
        LocalSet::new()
            .run_until(async {
                let (registered, state) =
                    run_worker_until_registered(1, false, Duration::from_secs(20)).await;
                assert!(
                    registered,
                    "after a failed register_vss the worker must recover and \
                     register again; without a run-loop restart every retry \
                     wedges on 'connect called but already connected to VS-API'"
                );
                assert!(
                    state.borrow().register_calls >= 2,
                    "recovery must be a real second registration attempt"
                );
            })
            .await;
    }

    /// zipline#167 defect 2, second half: when notify_disconnect ALSO fails
    /// (the real VS answers AuthRequired once it has dropped the node — see
    /// the issue log), the node must not panic; a dead VS link is not a
    /// reason to kill the node. It must still recycle the dial and
    /// re-register.
    #[tokio::test]
    async fn test_failed_register_vss_with_failed_disconnect_does_not_kill_node() {
        LocalSet::new()
            .run_until(async {
                let (registered, state) =
                    run_worker_until_registered(1, true, Duration::from_secs(20)).await;
                assert!(
                    registered,
                    "a failed notify_disconnect after a failed registration \
                     must not kill the worker (panic) nor leave it wedged"
                );
                assert!(state.borrow().register_calls >= 2);
            })
            .await;
    }
}
