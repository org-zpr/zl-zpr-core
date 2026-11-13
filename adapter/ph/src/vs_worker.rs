//! The node's VS-API worker: connects to the visa service, registers this
//! node's VSS, and keeps the session going across run-loop restarts.
//!
//! **Joiners** (zl-zipline#252, ZODE_LINKS.md J1-J10). A Zode with an
//! initial link runs its VS-API session over that link, on the bootstrap
//! visas its relay hands it (J4). So it connects only once a hand-off is
//! installed (J5), and any break in the session is a rejoin (J10): it ends
//! the session and closes the initial link, whose record redials (R11) for
//! a new join. The two are tied both ways: a session that breaks closes the
//! link, and a link that is lost ends the session, so the next hand-off is
//! not refused as `SessionUp` (J4).
//!
//! **The relay** (a Zode without an initial link, which hosts the visa
//! service) reaches its visa service over its self-granted VS-API pair. When
//! its session is lost it grants itself that pair again, its equivalent of
//! J10 (gate question 7).

use std::net::{IpAddr, SocketAddr};
use tokio::sync::{broadcast, watch};

use crate::prelude::*;
use crate::visa_mgmt;
use crate::vss_worker;

use libnode::error::VSApiError;
use libnode::vsconn::{NodeConnect, StateFlag, VSConnHandle, VSConnLifecycleEvent};
use zpr::vsapi_types::{DisconnectNotice, DisconnectReason, ErrorCode, VisaOp};

/// How many times a joiner sends `registerVss` while the visa service
/// answers `internal`, one [config::VSCONN_RETRY_WAIT] apart. The visa
/// service answers `internal` until both ends have reported the initial
/// link up, and the joiner's own report goes out within the reporter's
/// coalescing window of `connect`; five tries leave room for a slow
/// report. After the last, the session counts as broken (J10).
const REGISTER_VSS_ATTEMPTS: u32 = 5;

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

    // J5/J10: a Zode with an initial link runs its session over it.
    let joiner = asm.config.get().initial_link.is_some();
    let mut handoff_rx = asm.bootstrap_handoff.subscribe();
    // Set by a rejoin: only a hand-off installed after it counts (J5).
    let mut after_rejoin = false;

    loop {
        // This acts as a gate -- waiting for runloop to start.
        if !wait_for_runloop_start(&asm, node_zpr_addr, joiner, &mut lifecycle_rx).await {
            return; // ABORT entire worker
        }

        loop {
            // J5: a joiner connects only over its relay's bootstrap visas.
            if joiner {
                match wait_for_handoff(&mut handoff_rx, &mut lifecycle_rx, after_rejoin).await {
                    Wait::Done => after_rejoin = false,
                    Wait::RunLoopExited => {
                        session_lost(&asm, node_zpr_addr, joiner);
                        break; // re-gate on RunLoopStarts
                    }
                    Wait::Abort => return,
                }
            }

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
                        // R16: the visa service decides whether a reconnect
                        // is enough. If not, clear state and connect as reset.
                        Err(VSApiError::CodedError(err))
                            if err.code == ErrorCode::OutOfSync
                                || (err.code == ErrorCode::InvalidOperation
                                    && state == StateFlag::HasState) =>
                        {
                            state = StateFlag::NoState;
                            info!(target: STARTUP, "visa service refused a reconnect ({:?}); clearing adapters and visas, connecting as reset", err.code);
                            asm.disconnect_adapters().await;
                            // A reset declares no state: keep only the
                            // visas that carry the VS-API session itself.
                            let withdrawn = asm
                                .visa_table
                                .write()
                                .unwrap()
                                .retain_vs_api_visas(&asm.peer_table, &node_zpr_addr);
                            // Outside the visa-table lock (zipline#9).
                            asm.withdraw_streams(withdrawn, None);
                            false
                        }
                        Err(e) if joiner => {
                            rejoin(&asm, &vs_handle, &mut handoff_rx, &format!("connect failed: {e:?}"), true).await;
                            after_rejoin = true;
                            break; // re-gate on RunLoopStarts
                        }
                        Err(e) => {
                            error!(target: STARTUP, "failed to get access to visa service: {e:?}");
                            false
                        }
                    }
                }

                () = initial_link_lost(joiner, &mut handoff_rx) => {
                    session_lost(&asm, node_zpr_addr, joiner);
                    rejoin(&asm, &vs_handle, &mut handoff_rx, "the initial link was lost", true).await;
                    after_rejoin = true;
                    break; // re-gate on RunLoopStarts
                }

                evt = lifecycle_rx.recv() => {
                    match evt {
                        Ok(VSConnLifecycleEvent::RunLoopExits) => {
                            session_lost(&asm, node_zpr_addr, joiner);
                            info!(target: STARTUP, "VSConn runloop exited; aborting connect attempts and re-gating");
                            if joiner {
                                rejoin(&asm, &vs_handle, &mut handoff_rx, "the VS-API run loop exited", false).await;
                                after_rejoin = true;
                            }
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
                // From here a bootstrap-visa hand-off is refused (J4).
                asm.vs_session_up
                    .store(true, std::sync::atomic::Ordering::Release);
                // A fresh VS-API session gets a fresh link-state snapshot
                // (zl-zipline#250), sent before registerVss: the visa service
                // routes a joiner's VSS only over a link both ends report up
                // (zl-zipline#252).
                asm.zode_links.request_report();
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
                // J10: a joiner whose initial link is lost meanwhile stops
                // registering and rejoins at once.
                let registered = tokio::select! {
                    res = register_vss(&vs_handle, vss_addr, joiner) => Some(res),
                    () = initial_link_lost(joiner, &mut handoff_rx) => None,
                };
                let Some(registered) = registered else {
                    session_lost(&asm, node_zpr_addr, joiner);
                    rejoin(
                        &asm,
                        &vs_handle,
                        &mut handoff_rx,
                        "the initial link was lost",
                        true,
                    )
                    .await;
                    after_rejoin = true;
                    break; // re-gate on RunLoopStarts
                };
                match registered {
                    Ok(ops) => {
                        info!(target: STARTUP, "registered VSS, received {} pending visa ops", ops.len());
                        for op in ops {
                            if let Err(e) = vss_worker::process_visaop(&asm, op) {
                                error!(target: STARTUP, "failed to process initial visa op from VS: {e:?}");
                            }
                        }

                        // Next time we connect, we have state.
                        state = StateFlag::HasState;
                        if joiner {
                            // J10: stay with the session until it breaks.
                            match watch_session(
                                &asm,
                                node_zpr_addr,
                                &mut handoff_rx,
                                &mut lifecycle_rx,
                            )
                            .await
                            {
                                Wait::Done => {
                                    rejoin(
                                        &asm,
                                        &vs_handle,
                                        &mut handoff_rx,
                                        "the initial link was lost",
                                        true,
                                    )
                                    .await;
                                }
                                Wait::RunLoopExited => {
                                    rejoin(
                                        &asm,
                                        &vs_handle,
                                        &mut handoff_rx,
                                        "the VS-API run loop exited",
                                        false,
                                    )
                                    .await;
                                }
                                Wait::Abort => return,
                            }
                            after_rejoin = true;
                        }
                        break; // Exit inner loop; go back to waiting for a state change.
                    }
                    Err(e) if joiner => {
                        rejoin(
                            &asm,
                            &vs_handle,
                            &mut handoff_rx,
                            &format!("failed to register VSS: {e:?}"),
                            true,
                        )
                        .await;
                        after_rejoin = true;
                        break; // re-gate on RunLoopStarts
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

/// How a wait in this worker ended.
enum Wait {
    /// What it waited for happened.
    Done,
    /// The VSConn run loop exited first: the session is gone.
    RunLoopExited,
    /// The lifecycle channel closed: the worker must stop.
    Abort,
}

/// Register this node's VSS at `vss_addr`. A joiner retries while the visa
/// service answers `internal` ([REGISTER_VSS_ATTEMPTS]); any other node
/// tries once.
async fn register_vss(
    vs_handle: &VSConnHandle,
    vss_addr: SocketAddr,
    joiner: bool,
) -> Result<Vec<VisaOp>, VSApiError> {
    let attempts = if joiner { REGISTER_VSS_ATTEMPTS } else { 1 };
    let mut attempt = 1;
    loop {
        match vs_handle.register_vss(vss_addr).await {
            Err(VSApiError::CodedError(err))
                if err.code == ErrorCode::Internal && attempt < attempts =>
            {
                info!(target: STARTUP, "registerVss answered internal (attempt {attempt} of {attempts}); retrying");
                attempt += 1;
                tokio::time::sleep(config::VSCONN_RETRY_WAIT).await;
            }
            result => return result,
        }
    }
}

/// This node's VS-API session is gone (its run loop exited). From here a
/// bootstrap-visa hand-off is accepted again (J4). A node without an initial
/// link (the relay) grants itself its VS-API pair again, so it can always
/// reach its own visa service (gate question 7).
fn session_lost(asm: &Assembly, node_zpr_addr: IpAddr, joiner: bool) {
    asm.vs_session_up
        .store(false, std::sync::atomic::Ordering::Release);
    if joiner {
        return;
    }
    let withdrawn = asm
        .visa_table
        .write()
        .unwrap()
        .regrant_vs_visas(&asm.peer_table, &node_zpr_addr);
    // Outside the visa-table lock (zipline#9).
    asm.withdraw_streams(withdrawn, None);
    info!(target: STARTUP, "VS-API session lost; granted this node its VS-API visas again");
}

/// J10: the joiner's VS-API session broke (`why`), so it rejoins. It ends
/// the session (with `end_session`; not when the run loop already exited),
/// so the next hand-off is not refused as `SessionUp`, and closes the
/// initial link that carries the hand-off, if it is still there. The
/// initial link's record redials with backoff (R11), and the relay hands
/// off fresh bootstrap visas (J1-J6). The current hand-off is marked seen:
/// the caller then waits for one installed after this ([wait_for_handoff]).
///
/// The hand-off is read and its link closed before the session is ended:
/// `restart` may wait on VSConn's command queue, and a replacement link
/// with a new hand-off arriving meanwhile must not be taken for the old one
/// and closed (hosted review).
async fn rejoin(
    asm: &Arc<Assembly>,
    vs_handle: &VSConnHandle,
    handoff_rx: &mut watch::Receiver<Option<LinkId>>,
    why: &str,
    end_session: bool,
) {
    warn!(target: STARTUP, "VS-API session over the initial link broke ({why}); rejoining (J10)");
    asm.vs_session_up
        .store(false, std::sync::atomic::Ordering::Release);
    let handoff_link = *handoff_rx.borrow_and_update();
    if let Some(link_id) = handoff_link {
        crate::zode_links::close_link(asm, link_id, "the VS-API session over it broke (J10)");
    }
    if end_session && let Err(e) = vs_handle.restart().await {
        // Discarded mid-dial or during a reconnect delay: a fresh dial is
        // already coming, which is the point.
        info!(target: STARTUP, "VSConn restart request not delivered (restart already in progress?): {e:?}");
    }
}

/// J5: wait until a bootstrap-visa hand-off is installed. After a rejoin
/// (`after_rejoin`), only one installed since then counts: the old initial
/// link may still be closing, with its hand-off. Ends early if the VSConn
/// run loop exits.
async fn wait_for_handoff(
    handoff_rx: &mut watch::Receiver<Option<LinkId>>,
    lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>,
    after_rejoin: bool,
) -> Wait {
    let handoff = async {
        if !after_rejoin {
            // The sender lives in the Assembly, so this never fails.
            let _ = handoff_rx.wait_for(Option::is_some).await;
            return;
        }
        while handoff_rx.changed().await.is_ok() {
            if handoff_rx.borrow_and_update().is_some() {
                return;
            }
        }
    };
    tokio::select! {
        () = handoff => Wait::Done,
        wait = wait_for_run_loop_exit(lifecycle_rx) => wait,
    }
}

/// J10: watch a joiner's registered session until it breaks: until the
/// initial link that carries its hand-off is lost ([Wait::Done]) or the
/// VSConn run loop exits ([Wait::RunLoopExited]). A run-loop exit covers a
/// call answered `authRequired`: the visa service no longer serves the
/// handle, so pings fail and the run loop exits.
async fn watch_session(
    asm: &Assembly,
    node_zpr_addr: IpAddr,
    handoff_rx: &mut watch::Receiver<Option<LinkId>>,
    lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>,
) -> Wait {
    let wait = tokio::select! {
        () = initial_link_lost(true, handoff_rx) => Wait::Done,
        wait = wait_for_run_loop_exit(lifecycle_rx) => wait,
    };
    if !matches!(wait, Wait::Abort) {
        session_lost(asm, node_zpr_addr, true);
    }
    wait
}

/// J10: resolves when a joiner's initial link, the one carrying its
/// hand-off, is lost (its hand-off is cleared). Never resolves on a node
/// without an initial link.
async fn initial_link_lost(joiner: bool, handoff_rx: &mut watch::Receiver<Option<LinkId>>) {
    if !joiner {
        return std::future::pending().await;
    }
    // The sender lives in the Assembly, so this never fails.
    let _ = handoff_rx.wait_for(Option::is_none).await;
}

/// Wait for the VSConn run loop to exit ([Wait::RunLoopExited]), or for
/// the lifecycle channel to close ([Wait::Abort]).
async fn wait_for_run_loop_exit(
    lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>,
) -> Wait {
    loop {
        match lifecycle_rx.recv().await {
            Ok(VSConnLifecycleEvent::RunLoopExits) => return Wait::RunLoopExited,
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
            }
            Err(broadcast::error::RecvError::Closed) => {
                error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                return Wait::Abort;
            }
        }
    }
}

/// Wait for the VSConn run loop to (re)start. A run loop that exits
/// meanwhile ends this node's VS-API session ([session_lost]). Returns false
/// if the lifecycle channel closed.
async fn wait_for_runloop_start(
    asm: &Assembly,
    node_zpr_addr: IpAddr,
    joiner: bool,
    lifecycle_rx: &mut broadcast::Receiver<VSConnLifecycleEvent>,
) -> bool {
    loop {
        match lifecycle_rx.recv().await {
            Ok(VSConnLifecycleEvent::RunLoopStarts) => return true,
            Ok(VSConnLifecycleEvent::RunLoopExits) => session_lost(asm, node_zpr_addr, joiner),
            Ok(_) => {
                // ignored
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                error!(target: STARTUP, "lagged on VSConn lifecycle channel, skipped {skipped} events");
                continue; // try again
            }
            Err(broadcast::error::RecvError::Closed) => {
                error!(target: STARTUP, "VSConn lifecycle channel closed unexpectedly");
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::fake_vs::{FakeVsState, eventually, start_vsconn};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;
    use tokio::task::LocalSet;

    // ------------------------------------------------------------------
    // zipline#167 defect 2: after a failed VSS registration the node must
    // leave the VS connection reconnectable. Today the failure arm only
    // sends notify_disconnect: the run loop's `cmd_state.vs_handle` stays
    // set, so every retry's `connect` fails locally with
    // CommandFailed("connect called but already connected to VS-API") and
    // the node never re-registers — the wedge from the issue log.
    //
    // The fake VS ([crate::fake_vs]) implements just enough of the VS-API
    // — connect → challenge → authenticate, register_vss,
    // notify_disconnect, ping — to fail registration a configurable number
    // of times and observe whether the node's retry ever reaches
    // registration again.
    // ------------------------------------------------------------------

    /// Stand up the whole pair — real VSConn against the fake VS, the real
    /// `vs_worker::launch` driving it — and wait for `register_vss` to
    /// succeed. Returns whether it did within `window`, and the fake VS
    /// state for call-count assertions.
    /// The ZPR address of the node under test.
    const NODE_ADDR: &str = "fd5a:5052:3000::2";

    /// Start a real VSConn against a fake VS in `state`, and the real
    /// `vs_worker::launch` driving it for `asm`. Returns the fake VS state,
    /// the VSConn handle and the worker task.
    async fn start_worker(
        asm: &Arc<Assembly>,
        state: FakeVsState,
    ) -> (
        Rc<RefCell<FakeVsState>>,
        VSConnHandle,
        tokio::task::JoinHandle<()>,
    ) {
        let (state, vs_handle, lifecycle_rx) = start_vsconn(state).await;

        let node_zpr_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let vss_addr: SocketAddr = SocketAddr::new(node_zpr_addr, 8183);
        let worker = tokio::task::spawn_local(launch(
            asm.clone(),
            node_zpr_addr,
            vss_addr,
            vs_handle.clone(),
            lifecycle_rx,
        ));
        (state, vs_handle, worker)
    }

    async fn run_worker_until_registered(
        fail_registers: u32,
        fail_notify_disconnect: bool,
        window: Duration,
    ) -> (bool, Rc<RefCell<FakeVsState>>, Arc<Assembly>) {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let (state, _vs_handle, worker) = start_worker(
            &asm,
            FakeVsState {
                fail_registers,
                fail_notify_disconnect,
                ..Default::default()
            },
        )
        .await;

        let registered = eventually(window, || state.borrow().register_succeeded).await;
        // The worker asks for a link-state report right after registering.
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while !asm.zode_links.report_pending() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        worker.abort();
        (registered, state, asm)
    }

    /// zl-zipline#250: every VS-API (re)connect, once registered, asks for a
    /// fresh link-state report.
    #[tokio::test]
    async fn test_registration_requests_a_link_state_report() {
        LocalSet::new()
            .run_until(async {
                let (registered, _, asm) =
                    run_worker_until_registered(0, false, Duration::from_secs(20)).await;
                assert!(registered);
                assert!(asm.zode_links.report_pending());
            })
            .await;
    }

    /// zl-zipline#252: a node that has connected has a VS-API session, so
    /// it refuses a bootstrap-visa hand-off from then on (J4).
    #[tokio::test]
    async fn test_connecting_marks_the_vs_session_up() {
        LocalSet::new()
            .run_until(async {
                let (registered, _, asm) =
                    run_worker_until_registered(0, false, Duration::from_secs(20)).await;
                assert!(registered);
                assert!(asm.vs_session_up.load(std::sync::atomic::Ordering::Acquire));
            })
            .await;
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
                let (registered, state, _) =
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
                let (registered, state, _) =
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

    // ------------------------------------------------------------------
    // zl-zipline#252 (t207): the joiner's session over its initial link
    // (J1, J5, J10, R16) and the relay's self-granted pair.
    // ------------------------------------------------------------------

    /// A joiner at [NODE_ADDR] whose initial link to its relay is up, with
    /// its VS-API worker running against a fake VS in `state`. Returns the
    /// assembly, the initial link, the fake VS state and the VSConn handle.
    async fn start_joiner(
        state: FakeVsState,
    ) -> (
        Arc<Assembly>,
        LinkId,
        Rc<RefCell<FakeVsState>>,
        VSConnHandle,
        crate::zode_links::tests::EgressRx,
    ) {
        use crate::zode_links::tests::{bring_up, driven_zode, record_of};
        let (asm, egress) = driven_zode(NODE_ADDR, "b", Some("relay@127.0.0.1:7501"));
        crate::zode_links::start_initial_link(&asm);
        let link = record_of(&asm, "relay").link_id.unwrap();
        bring_up(&asm, link, "relay");
        let (state, vs_handle, _worker) = start_worker(&asm, state).await;
        (asm, link, state, vs_handle, egress)
    }

    /// The initial link's current connection, if it is up.
    fn initial_link_up(asm: &Arc<Assembly>) -> Option<LinkId> {
        let link = crate::zode_links::tests::record_of(asm, "relay").link_id?;
        let up = asm.peer_table.get(link).is_some_and(|peer| {
            peer.link_state_machine.get_state() == crate::link_state::LinkState::Active
        });
        up.then_some(link)
    }

    /// J10: the initial link `old` is closed, and its record dials the
    /// relay again; returns the new connection once it is there.
    async fn wait_for_redial(asm: &Arc<Assembly>, old: LinkId) -> LinkId {
        let mut redial = None;
        assert!(
            eventually(Duration::from_secs(10), || {
                redial = crate::zode_links::tests::record_of(asm, "relay")
                    .link_id
                    .filter(|link| *link != old && asm.peer_table.get(old).is_none());
                redial.is_some()
            })
            .await,
            "the initial link is closed and redialed"
        );
        redial.unwrap()
    }

    /// J5: a joiner does not connect until its relay's hand-off is
    /// installed, and then connects as `reset` (it has no state).
    #[tokio::test]
    async fn test_joiner_connects_only_after_the_handoff() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, state, _vs, _egress) = start_joiner(FakeVsState::default()).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
                assert!(
                    state.borrow().connects.is_empty(),
                    "no connect before the hand-off"
                );

                asm.bootstrap_handoff.send_replace(Some(link));
                assert!(
                    eventually(Duration::from_secs(10), || state
                        .borrow()
                        .register_succeeded)
                    .await
                );
                assert_eq!(state.borrow().connects, vec![false]);
                assert!(asm.zode_links.report_pending(), "link states reported");
            })
            .await;
    }

    /// R16: a `reconnect` the visa service refuses with `outOfSync` or
    /// `invalidOperation` is followed by a `reset`, and the node then holds
    /// no visa from before but those for its VS-API flows (hosted review).
    #[tokio::test]
    async fn test_a_refused_reconnect_connects_as_reset() {
        for code in [
            zpr::vsapi_types::ErrorCode::OutOfSync,
            zpr::vsapi_types::ErrorCode::InvalidOperation,
        ] {
            LocalSet::new()
                .run_until(async {
                    let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                    let (state, vs_handle, _worker) = start_worker(
                        &asm,
                        FakeVsState {
                            refuse_reconnect: Some(code.clone()),
                            ..Default::default()
                        },
                    )
                    .await;
                    assert!(
                        eventually(Duration::from_secs(10), || state.borrow().register_calls
                            == 1)
                        .await
                    );
                    let policy_visa = crate::visa_table::tests::new_vsapi_visa_tcp_default(
                        5000,
                        crate::visa_table::tests::never_expires(),
                    );
                    asm.visa_table
                        .write()
                        .unwrap()
                        .insert_visa(policy_visa)
                        .unwrap();
                    vs_handle.restart().await.unwrap();
                    assert!(
                        eventually(Duration::from_secs(10), || state.borrow().register_calls
                            == 2)
                        .await,
                        "registered again after {code:?}"
                    );
                    assert_eq!(state.borrow().connects, vec![false, true, false]);
                    let visa_table = asm.visa_table.read().unwrap();
                    assert!(!visa_table.contains(5000), "the reset dropped the old visa");
                    assert!(visa_table.contains(1) && visa_table.contains(2));
                })
                .await;
        }
    }

    /// J10: when the joiner's VS-API run loop exits, it closes its initial
    /// link (once), redials, and joins again over the new link's hand-off.
    /// The new link is not closed: the exit is handled exactly once.
    #[tokio::test]
    async fn test_joiner_rejoins_when_its_run_loop_exits() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, state, vs_handle, _egress) =
                    start_joiner(FakeVsState::default()).await;
                asm.bootstrap_handoff.send_replace(Some(link));
                assert!(
                    eventually(Duration::from_secs(10), || state.borrow().register_calls
                        == 1)
                    .await
                );

                vs_handle.restart().await.unwrap();
                let again = wait_for_redial(&asm, link).await;
                crate::zode_links::tests::bring_up(&asm, again, "relay");
                asm.bootstrap_handoff.send_replace(Some(again));
                assert!(
                    eventually(Duration::from_secs(10), || state.borrow().register_calls
                        == 2)
                    .await
                );
                assert_eq!(state.borrow().connects, vec![false, true], "a reconnect");
                tokio::time::sleep(Duration::from_secs(1)).await;
                assert_eq!(initial_link_up(&asm), Some(again), "the new link stays up");
            })
            .await;
    }

    /// J10: a failed `connect` closes the initial link, which redials.
    #[tokio::test]
    async fn test_joiner_rejoins_when_connect_fails() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, state, _vs, _egress) = start_joiner(FakeVsState {
                    fail_auth: true,
                    ..Default::default()
                })
                .await;
                asm.bootstrap_handoff.send_replace(Some(link));
                wait_for_redial(&asm, link).await;
                assert_eq!(state.borrow().connects.len(), 1, "no retry on the old link");
            })
            .await;
    }

    /// J10: a `registerVss` that keeps failing closes the initial link.
    #[tokio::test]
    async fn test_joiner_rejoins_when_register_vss_fails() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, state, _vs, _egress) = start_joiner(FakeVsState {
                    fail_registers: u32::MAX,
                    ..Default::default()
                })
                .await;
                asm.bootstrap_handoff.send_replace(Some(link));
                wait_for_redial(&asm, link).await;
                assert!(state.borrow().register_calls >= 1);
            })
            .await;
    }

    /// J10 the other way round: losing the initial link ends the VS-API
    /// session, so the next hand-off is not refused as `SessionUp` (J4).
    #[tokio::test]
    async fn test_losing_the_initial_link_ends_the_session() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, state, _vs, _egress) = start_joiner(FakeVsState::default()).await;
                asm.bootstrap_handoff.send_replace(Some(link));
                assert!(
                    eventually(Duration::from_secs(10), || state
                        .borrow()
                        .register_succeeded)
                    .await
                );
                assert!(asm.vs_session_up.load(std::sync::atomic::Ordering::Acquire));

                asm.drop_peer(link);
                assert!(
                    eventually(Duration::from_secs(5), || {
                        !asm.vs_session_up.load(std::sync::atomic::Ordering::Acquire)
                            && state.borrow().connections == 2
                    })
                    .await,
                    "the session ends and the run loop dials afresh"
                );
            })
            .await;
    }

    /// Local Codex review: losing the initial link while `registerVss` is
    /// still being retried ends the session at once, not after the last
    /// retry, so the redialed link's hand-off is not refused as
    /// `SessionUp`.
    #[tokio::test]
    async fn test_losing_the_initial_link_during_registration_ends_the_session() {
        LocalSet::new()
            .run_until(async {
                let (asm, link, state, _vs, _egress) = start_joiner(FakeVsState {
                    fail_registers: u32::MAX,
                    ..Default::default()
                })
                .await;
                asm.bootstrap_handoff.send_replace(Some(link));
                assert!(
                    eventually(Duration::from_secs(10), || state.borrow().register_calls
                        == 1)
                    .await
                );

                asm.drop_peer(link);
                assert!(
                    eventually(Duration::from_millis(500), || {
                        !asm.vs_session_up.load(std::sync::atomic::Ordering::Acquire)
                    })
                    .await,
                    "the session ends before the registration retries run out"
                );
            })
            .await;
    }

    /// Hosted review (Copilot): J10 closes the initial link that carries
    /// the current hand-off before it ends the session. Ending it can wait
    /// on VSConn's command queue (here full, with no run loop draining it),
    /// and the old link must already be closed by then, so a hand-off that
    /// arrives on a replacement link during the wait is never mistaken for
    /// the old one.
    #[tokio::test]
    async fn test_rejoin_closes_the_handoff_link_before_ending_the_session() {
        LocalSet::new()
            .run_until(async {
                use crate::zode_links::tests::{bring_up, driven_zode, record_of};
                let (asm, _egress) = driven_zode(NODE_ADDR, "b", Some("relay@127.0.0.1:7502"));
                crate::zode_links::start_initial_link(&asm);
                let link = record_of(&asm, "relay").link_id.unwrap();
                bring_up(&asm, link, "relay");
                asm.bootstrap_handoff.send_replace(Some(link));
                let mut handoff_rx = asm.bootstrap_handoff.subscribe();

                // A VSConn with no run loop and a one-slot queue, already full.
                let vsconn = libnode::vsconn::VSConn::new(
                    1,
                    "127.0.0.1:1".parse().unwrap(),
                    "test-node".to_string(),
                    aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
                        .expect("test RSA key"),
                    "127.0.0.1:5000".parse().unwrap(),
                );
                let vs_handle = vsconn.handle();
                vs_handle.restart().await.unwrap();

                let rejoiner = asm.clone();
                let _rejoin = tokio::task::spawn_local(async move {
                    rejoin(&rejoiner, &vs_handle, &mut handoff_rx, "test", true).await;
                });
                assert!(
                    eventually(Duration::from_secs(5), || asm
                        .peer_table
                        .get(link)
                        .is_none())
                    .await,
                    "the hand-off link is closed while ending the session waits"
                );
                drop(vsconn);
            })
            .await;
    }

    /// The relay's equivalent of J10 (gate question 7): a node without an
    /// initial link that loses its VS-API session grants itself the VS-API
    /// pair again.
    #[tokio::test]
    async fn test_a_relay_that_loses_its_session_regrants_its_vs_visas() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let (state, vs_handle, _worker) = start_worker(&asm, FakeVsState::default()).await;
                assert!(
                    eventually(Duration::from_secs(10), || state
                        .borrow()
                        .register_succeeded)
                    .await
                );
                assert!(!asm.visa_table.read().unwrap().contains(1));

                vs_handle.restart().await.unwrap();
                assert!(
                    eventually(Duration::from_secs(5), || {
                        let visa_table = asm.visa_table.read().unwrap();
                        visa_table.contains(1) && visa_table.contains(2)
                    })
                    .await
                );
            })
            .await;
    }
}
