//! Receives commands, either from the cli or from someone directly interfacing
//! with the socket, performs action based on received command
//! To avoid excess parsing, the command must not have spaces

#![allow(unused_imports)]
#![allow(dead_code)]

use crate::auth_agent::{AuthAgentHandle, AuthFailureReason, OidcCredentialRequest};
use crate::link_state::{LinkEvent, LinkState};
use crate::logging;
use crate::logging::{levels, targets};
use crate::prelude::*;
use crate::sys;
use crate::sys::control::ControlListener;
use crate::test_packet::TestPacketMetrics;
use crate::zdp::TerminateReason;
use admin_api::v1 as cli;
use cbpf_rs;
use cli::cmd_line_inter as svc;
use core::future::Future;
use hdrhistogram::Histogram;
use std::cell::RefCell;
use std::f64::consts::SQRT_2;
use std::fmt::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{BufReader, BufWriter};
use tokio::sync::oneshot::error::RecvError;
use tokio::task::JoinSet;
use tokio::time::interval;
use tokio_util::compat::*;

/// Accept control connections forever, serving the admin RPC on each.
pub async fn launch_capnp(
    asm: Arc<Assembly>,
    mut listener: ControlListener,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let stream = listener.accept().await?;

        #[cfg(not(all(unix, feature = "capnp-ancillary")))]
        let network = byte_stream_network(stream, capnp_rpc::rpc_twoparty_capnp::Side::Server);

        // FD-passing transport (zipline#142): `setCaptureFile` receives the
        // capture file's descriptor as SCM_RIGHTS ancillary data, so ph never
        // opens a user-chosen path as root. Needs the capnproto-rust fork, so
        // normal builds compile this out — see the workspace root Cargo.toml.
        #[cfg(all(unix, feature = "capnp-ancillary"))]
        let network = {
            let (reader, writer) = stream.into_split();
            Box::new(capnp_rpc::twoparty::io::VatNetwork::new_with_fds(
                capnp_futures::io::tokio::UnixFdStream::new(reader),
                capnp_futures::io::tokio::UnixFdStream::new(writer),
                1,
                capnp_rpc::rpc_twoparty_capnp::Side::Server,
                capnp::message::ReaderOptions::new(),
            ))
        };

        serve_connection(asm.clone(), network, sys::capture_supported());
    }
}

/// The two-party Cap'n Proto network over any byte stream: the control
/// channel's transport (unix socket today, named pipe on Windows) is
/// invisible above this point.
fn byte_stream_network<S>(
    stream: S,
    side: capnp_rpc::rpc_twoparty_capnp::Side,
) -> Box<capnp_rpc::twoparty::VatNetwork<Compat<BufReader<tokio::io::ReadHalf<S>>>>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    Box::new(capnp_rpc::twoparty::VatNetwork::new(
        BufReader::new(reader).compat(),
        BufWriter::new(writer).compat_write(),
        side,
        capnp::message::ReaderOptions::new(),
    ))
}

/// Serve the admin RPC on one connection's `network`, on a local task.
/// When the connection closes, any AuthAgent registered over it is
/// unregistered (zipline#45).
fn serve_connection(
    asm: Arc<Assembly>,
    network: Box<dyn capnp_rpc::VatNetwork<capnp_rpc::rpc_twoparty_capnp::Side>>,
    capture_supported: bool,
) {
    let login_agents = Rc::new(RefCell::new(Vec::new()));
    let service: svc::Client = capnp_rpc::new_client(AdminServiceImpl {
        asm: asm.clone(),
        login_agents: login_agents.clone(),
        capture_supported,
    });

    let rpc_system = capnp_rpc::RpcSystem::new(network, Some(service.clone().client));
    tokio::task::spawn_local(async move {
        let err = rpc_system.await;
        // This admin RPC connection is gone. Any AuthAgent a `login`
        // registered over it is dead too: unregister it from the Zode login
        // (zl-zipline#233), unless a newer agent has since replaced it. The
        // login itself is kept until it expires (g116 q5).
        for handle in login_agents.borrow_mut().drain(..) {
            if asm.zode_login.clear_agent_if(&handle) {
                debug!(target: RPC, "Zode login: AuthAgent unregistered (admin connection closed)");
            }
        }
        err
    });
}

/// Fill a `SuccessOrError` from a Zode-login result.
fn set_login_result(
    builder: cli::success_or_error::Builder<'_>,
    result: Result<(), crate::zode_login::LoginError>,
) {
    match result {
        Ok(()) => builder.init_success().set_none(()),
        Err(e) => builder.init_error().set_txt(e.to_string()),
    }
}

/// Run the admin RPC server until the control listener fails.
pub async fn launch(asm: Arc<Assembly>, listener: ControlListener) {
    match launch_capnp(asm.clone(), listener).await {
        Ok(()) => (),
        Err(e) => error!(target: RPC, "RPC System error: {}", e),
    };
}

/// The error `setCaptureFile` returns where capture is not supported
/// (plan D7).
fn capture_unsupported() -> capnp::Error {
    capnp::Error::unimplemented("capture is not available on this platform".to_string())
}

struct AdminServiceImpl {
    asm: Arc<Assembly>,
    /// AuthAgents a `login` registered over THIS connection (zl-zipline#233),
    /// unregistered from the Zode login when the connection drops.
    login_agents: Rc<RefCell<Vec<AuthAgentHandle>>>,
    /// Whether `setCaptureFile` may open a capture file here
    /// ([sys::capture_supported]; injected so tests can exercise the
    /// unsupported path on unix).
    capture_supported: bool,
}

impl svc::Server for AdminServiceImpl {
    async fn echo(
        self: Rc<Self>,
        _: svc::EchoParams,
        _: svc::EchoResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Echo procedure initiated");

        Ok(())
    }

    async fn reset_counters(
        self: Rc<Self>,
        _: svc::ResetCountersParams,
        _: svc::ResetCountersResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Reset counters procedure initiated");
        for value in self.asm.counters.management.values() {
            value.reset();
        }

        for fastpath in self.asm.counters.fastpaths.lock().unwrap().iter() {
            for value in fastpath.values() {
                value.reset();
            }
        }

        Ok(())
    }

    async fn counters(
        self: Rc<Self>,
        _: svc::CountersParams,
        mut results: svc::CountersResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Counters procedure initiated");
        let mut results_builder = results.get().init_counts();

        let mut counters_builder = results_builder
            .reborrow()
            .init_management()
            .init_counters(self.asm.counters.management.len() as u32);

        for (i, (key, &ref value)) in self.asm.counters.management.iter().enumerate() {
            let mut counter = counters_builder.reborrow().get(i as u32);
            counter.set_name(key.name());
            counter.set_val(value.get_count());
        }

        {
            let fastpaths = self.asm.counters.fastpaths.lock().unwrap();

            // Initialize builder for list of fastpaths
            let mut fastpaths_builder = results_builder
                .reborrow()
                .init_fastpaths(fastpaths.len() as u32);
            for (i, fastpath) in fastpaths.iter().enumerate() {
                // Initialize builder for individual fastpath and set its ID
                let mut fastpath_builder = fastpaths_builder.reborrow().get(i as u32);
                fastpath_builder.set_id(i as u32);

                // Set counters
                let mut counters_builder = fastpath_builder.init_counters(fastpath.len() as u32);
                for (i, (key, &ref value)) in fastpath.iter().enumerate() {
                    let mut counter = counters_builder.reborrow().get(i as u32);
                    counter.set_name(key.name());
                    counter.set_val(value.get_count());
                }
            }
        }

        results_builder.set_uptime_sec(self.asm.get_uptime().as_secs());
        results_builder.set_uptime_subsec_ms(self.asm.get_uptime().subsec_millis());

        Ok(())
    }

    /// Opens the capture file from an FD received as ancillary data over the
    /// FD-passing transport (zipline#142). `capture_supported` is false only
    /// off-unix, which this cfg already excludes, but the flag is still
    /// checked so tests can exercise the unsupported path.
    #[cfg(all(unix, feature = "capnp-ancillary"))]
    async fn set_capture_file(
        self: Rc<Self>,
        params: svc::SetCaptureFileParams,
        mut results: svc::SetCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Set capture file procedure initiated");
        if !self.capture_supported {
            return Err(capture_unsupported());
        }
        let capture_file = params.get()?.get_capture_file()?;
        let fd = capture_file.client.get_fd().await?;
        let results_builder = results.get().init_result();

        match fd {
            Some(fd) => {
                let owned_fd = fd.try_clone_to_owned().map_err(|e| {
                    capnp::Error::failed(format!("failed to clone capture file fd: {e}"))
                })?;
                let file = File::from(std::fs::File::from(owned_fd));
                match self.asm.capture_worker.open_capture_file(file).await {
                    Ok(()) => {
                        debug!(target: RPC, "Capture file opened");
                        results_builder.init_success().set_none(());
                    }
                    Err(err) => {
                        debug!(target: RPC, "Error opening capture file: {err}");
                        results_builder
                            .init_error()
                            .set_txt(format!("Error opening capture file: {err}").as_str());
                    }
                }
            }
            None => {
                // No descriptor arrived: the caller is not on the FD-passing
                // transport (byte-stream client, e.g. Windows ph-cli), so
                // capture is unsupported over this connection (zipline#142).
                debug!(target: RPC, "setCaptureFile: no file descriptor received");
                return Err(capnp::Error::unimplemented(
                    "no file descriptor received: setCaptureFile needs the \
                     fd-passing (capnp-ancillary) transport"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Without the FD-passing transport there is no way to hand ph a capture
    /// file — `capture.sock` is gone (zipline#142, org-zpr#1399) — so every
    /// other configuration answers Unsupported (plan D7).
    #[cfg(not(all(unix, feature = "capnp-ancillary")))]
    async fn set_capture_file(
        self: Rc<Self>,
        _: svc::SetCaptureFileParams,
        _: svc::SetCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        Err(capture_unsupported())
    }

    async fn close_capture_file(
        self: Rc<Self>,
        _: svc::CloseCaptureFileParams,
        _: svc::CloseCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        let _ = self.asm.capture_worker.close_capture_file().await;
        self.asm.flow_control.delete_program();

        Ok(())
    }

    async fn flush_capture_file(
        self: Rc<Self>,
        _: svc::FlushCaptureFileParams,
        _: svc::FlushCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Flush capture file procedure initiated");
        let _ = self.asm.capture_worker.flush_capture_file().await;

        Ok(())
    }

    async fn set_capture_program(
        self: Rc<Self>,
        params: svc::SetCaptureProgramParams,
        mut results: svc::SetCaptureProgramResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Set capture program procedure initiated");
        let programs = params.get()?.get_program()?.get_bpf_prog()?;

        let mut insn_vec = Vec::new();

        for program in programs.iter() {
            debug!(
                target: RPC,
                "Capture program values: code: {}, jt: {}, jf: {}, k: {}",
                program.get_code(),
                program.get_jt(),
                program.get_jf(),
                program.get_k()
            );
            let bpf_insn = cbpf_rs::BpfInsn {
                code: program.get_code(),
                jt: program.get_jt(),
                jf: program.get_jf(),
                k: program.get_k(),
            };
            insn_vec.push(bpf_insn);
        }

        let results_builder = results.get().init_result();

        match cbpf_rs::BpfProgram::validate(&insn_vec) {
            Ok(final_program) => {
                self.asm.flow_control.set_program(final_program);
                let mut success_builder = results_builder.init_success();
                success_builder.set_none(());
            }
            _ => {
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt("Invalid program")
            }
        }

        Ok(())
    }

    async fn delete_capture_program(
        self: Rc<Self>,
        _: svc::DeleteCaptureProgramParams,
        _: svc::DeleteCaptureProgramResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Delete capture program procedure initiated");
        self.asm.flow_control.delete_program();
        Ok(())
    }

    async fn perf_sample(
        self: Rc<Self>,
        _: svc::PerfSampleParams,
        mut results: svc::PerfSampleResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Perf sample procedure initiated");
        let mut results_builder = results.get();
        results_builder.set_result("Not currently supported");
        Ok(())
    }

    async fn show_link_summary(
        self: Rc<Self>,
        _: svc::ShowLinkSummaryParams,
        mut results: svc::ShowLinkSummaryResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Show link summary procedure initiated");
        {
            let mut peer_ids = Vec::new();
            self.asm.peer_table.for_each(|(id, peer)| {
                if !peer.is_internal() {
                    peer_ids.push(id.get())
                }
            });

            let mut results_builder = results.get().init_summary(peer_ids.len() as u32);

            for (i, id) in peer_ids.iter().enumerate() {
                results_builder.set(
                    i as u32,
                    format!("  {id}: {}", get_link_summary(&self.asm, *id)),
                );
            }
        }

        Ok(())
    }

    async fn show_link(
        self: Rc<Self>,
        params: svc::ShowLinkParams,
        mut results: svc::ShowLinkResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Show link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Show {} requested", self.asm.formatted_link_id(id));

        let mut results_builder = results.get();
        let response = match self.asm.peer_table.get(id) {
            Some(peer) => {
                let lsm = &peer.link_state_machine;

                format!(
                    "Link {id} info:\nSubstrate Address: {}\n{}{}",
                    peer.substrate_addr, lsm, peer.actor_auth,
                )
            }
            None => format!("No such link {id}\n"),
        };

        results_builder.set_result(response);

        Ok(())
    }

    async fn start_link(
        self: Rc<Self>,
        params: svc::StartLinkParams,
        mut results: svc::StartLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Start link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Start {} requested", self.asm.formatted_link_id(id));

        let results_builder = results.get().init_result();
        match self.asm.process_link_state_event(id, LinkEvent::Start) {
            Ok(_) => {
                let mut success_builder = results_builder.init_success();
                success_builder.set_none(());
            }
            Err(e) => {
                let resp = format!("Failed to start link {}: {:?}\n", id, e);
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt(resp);
            }
        }
        Ok(())
    }

    async fn stop_link(
        self: Rc<Self>,
        params: svc::StopLinkParams,
        mut results: svc::StopLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Stop link procedure initiated");
        let task_asm = self.asm.clone();
        let id = params.get()?.get_id();
        debug!(target: RPC, "Stop {} requested", self.asm.formatted_link_id(id));

        let results_builder = results.get().init_result();

        match task_asm.process_link_state_event(id, LinkEvent::Close(TerminateReason::Other)) {
            Ok(_) => {
                let mut success_builder = results_builder.init_success();
                success_builder.set_none(());
            }
            Err(e) => {
                let resp = format!("Failed to stop link {}: {:?}\n", id, e);
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt(resp);
            }
        }
        Ok(())
    }

    async fn reset_link(
        self: Rc<Self>,
        params: svc::ResetLinkParams,
        _: svc::ResetLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Reset link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Reset {} requested", self.asm.formatted_link_id(id));

        self.asm.reset_peer(id).await;
        Ok(())
    }

    async fn change_logging(
        self: Rc<Self>,
        params: svc::ChangeLoggingParams,
        mut results: svc::ChangeLoggingResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Change logging procedure initiated");
        let task_asm = self.asm.clone();
        let log_state = params.get()?.get_logs()?;
        // let log_vec: Vec<&str> = log_state.split_whitespace().collect();
        let mut applied: Vec<String> = Vec::new();
        let mut ignored: Vec<String> = Vec::new();
        for log in log_state.iter() {
            let target = log.get_level()?.to_str()?;
            let level = log.get_target()?.to_str()?;
            if targets::ALL_TARGETS.contains(&target)
                && levels::ALL_LEVELS.contains(&level.to_uppercase().as_str())
            {
                task_asm
                    .logging
                    .lock()
                    .unwrap()
                    .insert(target.to_string(), level.to_uppercase());
                applied.push(format!("{}={}", target, level));
                debug!(target: RPC, "Logging pair: {target}={level} applied");
            } else {
                ignored.push(format!("{}={}", target, level));
                debug!(target: RPC, "Logging pair: {target}={level} ignored");
            }
        }

        logging::reload_filter(&task_asm.reload_handle, &task_asm.logging.lock().unwrap());

        let mut results_builder = results.get().init_result();
        if applied.len() > 0 {
            let _ = results_builder.set_applied(applied.as_slice());
        }
        if ignored.len() > 0 {
            let _ = results_builder.set_ignored(ignored.as_slice());
        }

        Ok(())
    }

    /// `ph-cli tun` (zipline#202): the name of the TUN interface ph opened
    /// and the local ZPR addresses confirmed on it. An address ph believes it owns is reported
    /// only when `has_address` confirms it on the TUN, so a stale or
    /// not-yet-applied address is never printed; one the platform cannot
    /// inspect (`Unsupported`) is omitted and logged at debug.
    async fn get_tun_info(
        self: Rc<Self>,
        _: svc::GetTunInfoParams,
        mut results: svc::GetTunInfoResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Get TUN info");
        let asm = self.asm.clone();
        let if_name = asm.tun_ctl.name();
        let addrs: Vec<IpAddr> = asm
            .get_local_zpr_addrs_std()
            .into_iter()
            .filter(|addr| match asm.tun_ctl.has_address(*addr) {
                Ok(present) => present,
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                    debug!(target: RPC, "getTunInfo: omitting {addr}, which cannot be inspected on {if_name}: {e}");
                    false
                }
                Err(e) => {
                    debug!(target: RPC, "getTunInfo: omitting {addr}, cannot determine whether it is on {if_name}: {e}");
                    false
                }
            })
            .collect();

        let mut rb = results.get();
        let mut info = rb.reborrow().init_info();
        info.set_if_name(&if_name[..]);
        let mut list = info.init_zpr_addrs(addrs.len() as u32);
        for (i, addr) in addrs.iter().enumerate() {
            let mut entry = list.reborrow().get(i as u32);
            match addr {
                IpAddr::V4(a) => entry.set_v4(&a.octets()),
                IpAddr::V6(a) => entry.set_v6(&a.octets()),
            }
        }
        rb.init_result().init_success().set_none(());
        Ok(())
    }

    /// `ph-cli connect` / `auth-agent` on a Zode (zl-zipline#233): register
    /// the agent for this connection and log the Zode's own actor in. The
    /// agent is called back over this same connection while the call is
    /// pending; the answer comes when the login finishes.
    async fn login(
        self: Rc<Self>,
        params: svc::LoginParams,
        mut results: svc::LoginResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Zode login requested");
        let agent = spawn_auth_agent_bridge(params.get()?.get_auth_agent()?);
        self.login_agents.borrow_mut().push(agent.clone());
        let result = crate::zode_login::login(&self.asm, agent).await;
        set_login_result(results.get().init_result(), result);
        Ok(())
    }

    /// `ph-cli logout` on a Zode (zl-zipline#233).
    async fn logout(
        self: Rc<Self>,
        _: svc::LogoutParams,
        mut results: svc::LogoutResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Zode logout requested");
        let result = crate::zode_login::logout(&self.asm).await;
        set_login_result(results.get().init_result(), result);
        Ok(())
    }

    /// `ph-cli login-status` on a Zode (zl-zipline#233).
    async fn show_login(
        self: Rc<Self>,
        _: svc::ShowLoginParams,
        mut results: svc::ShowLoginResults,
    ) -> Result<(), capnp::Error> {
        results.get().set_result(self.asm.zode_login.status_text());
        Ok(())
    }
}

// This code will eventually be removed and the logic moved into perf_sample above
/// Performs a performance sample on the PH by measuring the queue depths and the
/// packet latencies throughout the system. Requires the duration of the
/// sample as well as the number of samples per second.
async fn perf_sample(_asm: &Assembly, _duration: &str, _rate: &str) -> String {
    // FIXME: There are now a dynamically allocated number of mgmt_processors...
    // this needs to be restructured to account for that fact.
    Default::default()

    /*let send_duration = Duration::new(duration.parse().unwrap(), 0);
    let begin_time = Instant::now();
    let mut send_interval = interval(Duration::new(0, 1000000000 / rate.parse::<u32>().unwrap()));

    let mut mgmt_processor_duration = Histogram::<u64>::new(1).unwrap();
    let mut mgmt_processor_depth = Histogram::<u64>::new(1).unwrap();
    let mut mgmt_processor_batch = Histogram::<u64>::new(1).unwrap();

    send_interval.tick().await;

    // Enqueue test packets at the frequency desired by the user for the
    // desired amount of time
    while begin_time.elapsed().as_secs() < send_duration.as_secs() {
        let in_processor = asm.mgmt_processor.enqueue_test_packet().await;
        record_metrics(
            in_processor,
            &mut mgmt_processor_duration,
            &mut mgmt_processor_depth,
            &mut mgmt_processor_batch,
        );

        // TODO: record metrics from TUN interface and UDP socket

        send_interval.tick().await;
    }

    // Get values at 10, 25, 50, 75, 90 quantiles for each hist as well as the mean
    let mgmt_processor = three_hists_values(
        "Management Processor",
        &mgmt_processor_duration,
        &mgmt_processor_depth,
        &mgmt_processor_batch,
    );

    format!("{mgmt_processor}")*/
}

/// Helper for perf_sample
/// Records the metrics from a single test packet to the trio of histograms
/// tracking the data from the queue that particular test packet was enqueued on
fn record_metrics(
    metrics: Result<TestPacketMetrics, RecvError>,
    hist_dur: &mut Histogram<u64>,
    hist_dep: &mut Histogram<u64>,
    hist_batch: &mut Histogram<u64>,
) {
    let _ = hist_dur.record(
        metrics
            .as_ref()
            .unwrap()
            .in_queue
            .as_nanos()
            .try_into()
            .unwrap(),
    );
    let _ = hist_dep.record(metrics.as_ref().unwrap().queue_depth.try_into().unwrap());
    let _ = hist_batch.record(metrics.as_ref().unwrap().batch_size.try_into().unwrap());
}

/// Helper for perf_sample
/// Gets the values from the trio of histograms for each queue. Returns a string with the
/// data from all three histograms
fn three_hists_values(
    hist_name: &str,
    hist_dur: &Histogram<u64>,
    hist_dep: &Histogram<u64>,
    hist_batch: &Histogram<u64>,
) -> String {
    let mut info = String::new();

    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            &format!("{hist_name} Duration"), // TODO could use en enum and a display to get the name
            "ns",
            hist_dur
        )
        .as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(&format!("{hist_name} Depth"), " packets", hist_dep).as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(&format!("{hist_name} Batch"), " packets", hist_batch).as_str()
    );
    let mean: u64 = (hist_dur.mean() / (1.0 + hist_dep.mean())) as u64;
    let _ = write!(&mut info, "{hist_name} approx packet time: {mean}ns\n\n\n");

    info
}

/// Helper for three_hists_values
/// Gets the data from a single histogram. Requires the histogram and units of
/// measurement to format the data, as well as the histogram itself.
/// Returns string with the data from one historgram.
fn values_from_hist(hist_name: &str, units: &str, hist: &Histogram<u64>) -> String {
    let ten: u64 = hist.value_at_quantile(0.10);
    let twenty_five: u64 = hist.value_at_quantile(0.25);
    let fifty: u64 = hist.value_at_quantile(0.50);
    let seventy_five: u64 = hist.value_at_quantile(0.75);
    let ninety: u64 = hist.value_at_quantile(0.90);
    let mean: f64 = hist.mean();

    let mut values = format!(
        "{} values at - 10th Quantile: {}{}, 25th Quantile: {}{},\n50th Quantile: {}{}, 75th Quantile: {}{}, 90th Quantile: {}{}, Mean: {}{}\n\n",
        hist_name,
        ten,
        units,
        twenty_five,
        units,
        fifty,
        units,
        seventy_five,
        units,
        ninety,
        units,
        mean,
        units
    );

    let mut iter = hist.iter_log(1, SQRT_2);

    let mut iter_value = iter.next();
    let mut prev_bucket = 0;

    while iter_value != None {
        let curr_bucket = iter_value.as_ref().unwrap().value_iterated_to();
        let _ = write!(
            &mut values,
            "Bucket: {}-{} | {}\n",
            prev_bucket,
            curr_bucket,
            iter_value.unwrap().count_since_last_iteration()
        );

        prev_bucket = curr_bucket;
        iter_value = iter.next();
    }

    let _ = write!(&mut values, "\n");

    values
}

/// Bridge a Cap'n Proto [cli::auth_agent::Client] onto the channel-based
/// [AuthAgentHandle] the link state machine consumes.
///
/// Cap'n Proto clients are !Send and bound to this RPC task's LocalSet, so
/// the FSM cannot hold one directly; instead it sends
/// [OidcCredentialRequest]s down an unbounded channel and this task performs
/// the actual getOidcCredential calls, mapping errors onto
/// [AuthFailureReason]. The task ends when the last sender is dropped (link
/// gone) or the RPC connection dies.
///
/// Each call's lifetime is bounded (see the Codex review on zipline#13's
/// PR): the RPC is raced against the requester abandoning the request
/// (reply receiver dropped, e.g. the link timed out and was torn down) and
/// against [config::OIDC_USER_INTERACTION_TIMEOUT] itself. Either way the
/// in-flight call is dropped — which cancels it on the wire — so a later
/// request on the same link cannot queue forever behind an abandoned one.
fn spawn_auth_agent_bridge(agent: cli::auth_agent::Client) -> AuthAgentHandle {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();

    tokio::task::spawn_local(async move {
        while let Some(mut req) = rx.recv().await {
            let mut request = agent.get_oidc_credential_request();
            {
                let mut rb = request.get();
                rb.set_issuer(&req.idp.issuer[..]);
                rb.set_client_id(&req.idp.client_id[..]);
                rb.set_client_secret(req.idp.client_secret.as_deref().unwrap_or(""));
                let mut scopes = rb.reborrow().init_scopes(req.idp.scopes.len() as u32);
                for (i, scope) in req.idp.scopes.iter().enumerate() {
                    scopes.set(i as u32, &scope[..]);
                }
                rb.set_allow_offline_access(req.idp.allow_offline_access);
                rb.set_nonce(&req.nonce[..]);
                rb.set_interactive(req.interactive);
            }

            let outcome = tokio::select! {
                // The requester stopped waiting (the link timed out or was
                // torn down). Drop the RPC — cancelling it — and move on to
                // the next queued request instead of blocking on a call
                // nobody will consume.
                _ = req.reply.closed() => {
                    debug!(target: RPC, "AuthAgent request abandoned by requester, cancelling RPC");
                    continue;
                }
                // Nobody should still be waiting past the interaction
                // timeout; cut the call loose so the bridge cannot wedge
                // even if the requester's own timer misfires.
                _ = tokio::time::sleep(config::OIDC_USER_INTERACTION_TIMEOUT) => {
                    warn!(target: RPC, "AuthAgent call exceeded the user interaction timeout, cancelling RPC");
                    Err(AuthFailureReason::InteractionTimeout)
                }
                result = request.send().promise => match result {
                    Ok(response) => match parse_agent_response(response) {
                        Ok(id_token) => Ok(id_token),
                        Err(reason) => Err(reason),
                    },
                    Err(e) => {
                        warn!(target: RPC, "AuthAgent call failed: {e}");
                        Err(AuthFailureReason::AgentError(e.to_string()))
                    }
                },
            };
            // The receiver may be gone (e.g. the link timed out); that is fine.
            let _ = req.reply.send(outcome);
        }
        debug!(target: RPC, "AuthAgent bridge shutting down");
    });

    tx
}

/// Decode a getOidcCredential response into the ID token or a failure reason.
/// The agent reports "access_denied" for a user refusal per the spec's error
/// taxonomy; anything else in the error text is an agent-side failure.
fn parse_agent_response(
    response: capnp::capability::Response<cli::auth_agent::get_oidc_credential_results::Owned>,
) -> Result<String, AuthFailureReason> {
    let results = response
        .get()
        .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?;
    let result = results
        .get_result()
        .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?;
    match result
        .which()
        .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?
    {
        cli::success_or_error::Which::Success(_) => {
            let id_token = results
                .get_id_token()
                .and_then(|t| t.to_str().map_err(|e| capnp::Error::failed(e.to_string())))
                .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?
                .to_string();
            if id_token.is_empty() {
                return Err(AuthFailureReason::AgentError(
                    "agent returned an empty id_token".to_string(),
                ));
            }
            Ok(id_token)
        }
        cli::success_or_error::Which::Error(e) => {
            let txt = e
                .and_then(|ev| ev.get_txt())
                .and_then(|t| t.to_str().map_err(|e| capnp::Error::failed(e.to_string())))
                .unwrap_or("unknown agent error")
                .to_string();
            Err(classify_agent_error(&txt))
        }
    }
}

/// Map the agent's error text onto an [AuthFailureReason].
///
/// ph-cli's `rpc_error_text` (adapter/cli/src/oidc.rs) prefixes the display
/// text with a stable `[class:<token>]` tag naming the failure class, so the
/// class survives the RPC and `connect` can apply its advertised exit codes;
/// the two sides must agree on the tokens matched here. A bare
/// "access_denied" (no tag) is still recognized for the user-refusal case —
/// that spelling is the spec's error-taxonomy contract and keeps
/// third-party/older agents classifiable. Anything else, including an
/// unknown class token, is an agent-side failure.
fn classify_agent_error(txt: &str) -> AuthFailureReason {
    if let Some(rest) = txt.strip_prefix("[class:") {
        if let Some((class, detail)) = rest.split_once(']') {
            let detail = detail.trim_start().to_string();
            match class {
                "user_declined" => return AuthFailureReason::UserDeclined,
                "interaction_timeout" => return AuthFailureReason::InteractionTimeout,
                "idp_unreachable" => return AuthFailureReason::IdpUnreachable(detail),
                // Unknown token: fall through and keep the full text.
                _ => {}
            }
        }
    }
    if txt.contains("access_denied") {
        AuthFailureReason::UserDeclined
    } else {
        AuthFailureReason::AgentError(txt.to_string())
    }
}

// Helper for show_link_summary
fn get_link_summary(asm: &Arc<Assembly>, link_id: LinkId) -> String {
    match asm.peer_table.get(link_id) {
        Some(peer) => format!(
            "{} ({:?})\n{}",
            peer.substrate_addr,
            peer.link_state_machine.get_state(),
            peer.actor_auth,
        ),
        None => format!("Unconfigured"),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::auth::{self, AuthBlob};
    use crate::config::PACKET_BUFFER_SIZE;
    use crate::link_state::LinkType;
    use crate::packet_queue;
    use crate::peer_table;
    use crate::queues::MgmtSubstrateEgress;
    use crate::zdp;
    use base64::prelude::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use tokio::task::LocalSet;
    use zpr_ext::zerocopy::FromBytesExt;
    use zpr_utils::net_defs;

    /// In-process fake AuthAgent whose calls complete only when the test
    /// releases them: each getOidcCredential call appends `(nonce,
    /// Some(release_sender))` to `pending` and then waits for the test to
    /// fire that sender. Leaving the sender in place models a user who
    /// never completes the login; firing it models a (possibly very late)
    /// completion.
    struct GatedAuthAgent {
        id_token: String,
        pending: Rc<RefCell<Vec<(String, Option<tokio::sync::oneshot::Sender<()>>)>>>,
    }

    impl cli::auth_agent::Server for GatedAuthAgent {
        async fn get_oidc_credential(
            self: Rc<Self>,
            params: cli::auth_agent::GetOidcCredentialParams,
            mut results: cli::auth_agent::GetOidcCredentialResults,
        ) -> Result<(), capnp::Error> {
            let nonce = params.get()?.get_nonce()?.to_str()?.to_string();
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending.borrow_mut().push((nonce, Some(tx)));
            // Held until the test releases this call (or the caller cancels
            // the RPC, which drops this task).
            let _ = rx.await;
            let mut rb = results.get();
            rb.set_id_token(&self.id_token[..]);
            rb.init_result().init_success().set_none(());
            Ok(())
        }
    }

    /// A minimal advertised OIDC identity provider for bridge/FSM tests.
    fn test_idp() -> auth::OidcIdpInfo {
        auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: false,
        }
    }

    /// Ask `agent` for an interactive ID token bound to `nonce` on a local
    /// task, the way a Zode's login does
    /// ([crate::auth_agent::request_id_token]).
    fn spawn_request_id_token(
        nonce: &str,
        agent: AuthAgentHandle,
    ) -> tokio::task::JoinHandle<Result<String, AuthFailureReason>> {
        let nonce = nonce.to_string();
        tokio::task::spawn_local(async move {
            crate::auth_agent::request_id_token(
                &agent,
                test_idp(),
                nonce,
                true,
                crate::config::OIDC_USER_INTERACTION_TIMEOUT,
            )
            .await
        })
    }

    /// Sleep in small steps until `cond` holds or `max_ms` elapses.
    async fn wait_for(max_ms: u64, mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..(max_ms / 10) {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    /// The agent (ph-cli's CliAuthAgent) prefixes its error text with a
    /// stable `[class:...]` token (oidc.rs::rpc_error_text). The classifier
    /// must map each token onto the matching `AuthFailureReason` so `connect`
    /// can apply its advertised exit codes, keep the legacy access_denied
    /// spelling working, and fall back to AgentError for untagged text.
    #[test]
    fn test_classify_agent_error_maps_class_tokens() {
        assert_eq!(
            classify_agent_error("[class:user_declined] authorization failed: access_denied"),
            AuthFailureReason::UserDeclined
        );
        assert_eq!(
            classify_agent_error(
                "[class:interaction_timeout] timed out waiting for the authorization callback"
            ),
            AuthFailureReason::InteractionTimeout
        );
        assert_eq!(
            classify_agent_error("[class:idp_unreachable] OIDC discovery failed: HTTP 503"),
            AuthFailureReason::IdpUnreachable("OIDC discovery failed: HTTP 503".to_string())
        );
        assert_eq!(
            classify_agent_error("[class:idp_unreachable] token exchange failed: HTTP 400"),
            AuthFailureReason::IdpUnreachable("token exchange failed: HTTP 400".to_string())
        );
        // Legacy/third-party agents: a bare access_denied still means the
        // user declined, per the spec's error taxonomy.
        assert_eq!(
            classify_agent_error("authorization failed: access_denied"),
            AuthFailureReason::UserDeclined
        );
        // Untagged text stays an agent-side failure (exit 1).
        assert_eq!(
            classify_agent_error("state parameter mismatch in authorization redirect"),
            AuthFailureReason::AgentError(
                "state parameter mismatch in authorization redirect".to_string()
            )
        );
        // An unknown class token is not silently dropped.
        assert_eq!(
            classify_agent_error("[class:something_new] hmm"),
            AuthFailureReason::AgentError("[class:something_new] hmm".to_string())
        );
    }

    /// The bridge must not stay blocked on a getOidcCredential call whose
    /// requester has gone away (link timed out): the abandoned call is
    /// cancelled and the next queued request still reaches the agent.
    #[tokio::test(start_paused = true)]
    async fn test_bridge_abandons_call_when_requester_goes_away() {
        LocalSet::new()
            .run_until(async {
                let pending = Rc::new(RefCell::new(Vec::new()));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(GatedAuthAgent {
                    id_token: "SECOND.JWT.TOKEN".to_string(),
                    pending: pending.clone(),
                });
                let handle = spawn_auth_agent_bridge(client);

                // Request 1: the requester stops waiting (link timeout).
                let (tx1, rx1) = tokio::sync::oneshot::channel();
                handle
                    .send(OidcCredentialRequest {
                        idp: test_idp(),
                        nonce: "nonce-1".to_string(),
                        interactive: true,
                        reply: tx1,
                    })
                    .unwrap();
                assert!(
                    wait_for(2_000, || pending.borrow().len() == 1).await,
                    "agent never saw request 1"
                );
                drop(rx1); // the requester gave up; the bridge must notice

                // Request 2 must still be serviced.
                let (tx2, rx2) = tokio::sync::oneshot::channel();
                handle
                    .send(OidcCredentialRequest {
                        idp: test_idp(),
                        nonce: "nonce-2".to_string(),
                        interactive: true,
                        reply: tx2,
                    })
                    .unwrap();
                assert!(
                    wait_for(5_000, || pending.borrow().len() == 2).await,
                    "request 2 is stuck behind the abandoned request 1"
                );
                let release = pending.borrow_mut()[1].1.take().unwrap();
                let _ = release.send(());

                let outcome = tokio::time::timeout(Duration::from_secs(5), rx2)
                    .await
                    .expect("bridge never answered request 2")
                    .expect("bridge dropped request 2's reply");
                assert_eq!(outcome, Ok("SECOND.JWT.TOKEN".to_string()));
            })
            .await
    }

    /// After an attempt's agent call times out (InteractionTimeout) with
    /// the call still pending, a fresh attempt with the same registered
    /// AuthAgent — as when the user retries a login — must reach the agent
    /// and succeed: it must not queue forever behind the abandoned first
    /// call.
    #[tokio::test(start_paused = true)]
    async fn test_timed_out_agent_call_is_abandoned_and_retry_proceeds() {
        LocalSet::new()
            .run_until(async {
                let pending = Rc::new(RefCell::new(Vec::new()));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(GatedAuthAgent {
                    id_token: "RETRY.JWT.TOKEN".to_string(),
                    pending: pending.clone(),
                });
                let handle = spawn_auth_agent_bridge(client);

                // Attempt 1: the user never completes the login.
                let attempt_1 = spawn_request_id_token("nonce-1", handle.clone());
                assert!(
                    wait_for(2_000, || pending.borrow().len() == 1).await,
                    "agent never saw attempt 1's call"
                );
                assert_eq!(
                    attempt_1.await.unwrap().unwrap_err(),
                    AuthFailureReason::InteractionTimeout
                );

                // Attempt 2: a new nonce, and this time the user logs in.
                let attempt_2 = spawn_request_id_token("nonce-2", handle);
                assert!(
                    wait_for(5_000, || pending.borrow().len() == 2).await,
                    "attempt 2's call is stuck behind the abandoned attempt-1 call"
                );
                let release = pending.borrow_mut()[1].1.take().unwrap();
                let _ = release.send(());

                // The retry proceeded: the second agent call was bound to
                // attempt 2's nonce, and its token is the answer.
                assert_eq!(
                    pending.borrow()[1].0,
                    "nonce-2",
                    "attempt 2's agent call is not bound to attempt 2's nonce"
                );
                assert_eq!(
                    attempt_2.await.unwrap(),
                    Ok("RETRY.JWT.TOKEN".to_string()),
                    "retry must succeed"
                );
            })
            .await
    }

    /// A very late completion of attempt 1's agent call (after it timed out
    /// and a NEW attempt with a new nonce is underway) must be discarded,
    /// not consumed by the new attempt: the old token is bound to the old
    /// nonce.
    #[tokio::test(start_paused = true)]
    async fn test_stale_completion_from_prior_attempt_is_discarded() {
        LocalSet::new()
            .run_until(async {
                let pending = Rc::new(RefCell::new(Vec::new()));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(GatedAuthAgent {
                    id_token: "STALE.JWT.TOKEN".to_string(),
                    pending: pending.clone(),
                });
                let handle = spawn_auth_agent_bridge(client);

                // Attempt 1 (nonce 1): times out.
                let attempt_1 = spawn_request_id_token("nonce-1", handle.clone());
                assert!(
                    wait_for(2_000, || pending.borrow().len() == 1).await,
                    "agent never saw attempt 1's call"
                );
                assert_eq!(
                    attempt_1.await.unwrap().unwrap_err(),
                    AuthFailureReason::InteractionTimeout
                );

                // Attempt 2 (nonce 2) is now waiting for the user.
                let attempt_2 = spawn_request_id_token("nonce-2", handle);
                assert!(
                    wait_for(5_000, || pending.borrow().len() == 2).await,
                    "agent never saw attempt 2's call"
                );

                // Attempt 1's call completes very late. If it was cancelled,
                // this release is a no-op; either way its token must not be
                // consumed by attempt 2.
                if let Some(release) = pending.borrow_mut()[0].1.take() {
                    let _ = release.send(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
                assert!(
                    !attempt_2.is_finished(),
                    "stale attempt-1 completion finished attempt 2"
                );
                attempt_2.abort();
            })
            .await
    }

    /// In-process fake AuthAgent: returns a fixed ID token and records the
    /// nonce it was asked to bind into it.
    struct FakeAuthAgent {
        id_token: String,
        seen_nonce: Rc<RefCell<Option<String>>>,
    }

    impl cli::auth_agent::Server for FakeAuthAgent {
        async fn get_oidc_credential(
            self: Rc<Self>,
            params: cli::auth_agent::GetOidcCredentialParams,
            mut results: cli::auth_agent::GetOidcCredentialResults,
        ) -> Result<(), capnp::Error> {
            let nonce = params.get()?.get_nonce()?.to_str()?.to_string();
            *self.seen_nonce.borrow_mut() = Some(nonce);
            let mut rb = results.get();
            rb.set_id_token(&self.id_token[..]);
            rb.init_result().init_success().set_none(());
            Ok(())
        }
    }

    /// Full callback flow against a fake in-process `AuthAgent`
    /// (zipline#13): a request through the bridge reaches the agent with
    /// the requested nonce, and the agent's ID token is the answer.
    #[tokio::test(start_paused = true)]
    async fn test_agent_token_answers_the_requested_nonce() {
        LocalSet::new()
            .run_until(async {
                // Fake agent, bridged the same way `login` registers a real one.
                let seen_nonce = Rc::new(RefCell::new(None));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(FakeAuthAgent {
                    id_token: "FAKE.JWT.TOKEN".to_string(),
                    seen_nonce: seen_nonce.clone(),
                });
                let agent_handle = spawn_auth_agent_bridge(client);

                let id_token = spawn_request_id_token("login-nonce", agent_handle)
                    .await
                    .unwrap()
                    .expect("an ID token must be returned");
                assert_eq!(id_token, "FAKE.JWT.TOKEN");
                assert_eq!(seen_nonce.borrow().as_deref(), Some("login-nonce"));
            })
            .await
    }

    /// The admin RPC is served over any byte stream (zipline#129): here an
    /// in-memory duplex stands in for the unix socket / named pipe, and a
    /// client on the other end completes an `echo` round trip.
    #[tokio::test]
    async fn test_admin_rpc_round_trips_over_any_byte_stream() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let (client_end, server_end) = tokio::io::duplex(4096);
                serve_connection(
                    asm,
                    byte_stream_network(server_end, capnp_rpc::rpc_twoparty_capnp::Side::Server),
                    true,
                );

                let mut client_rpc = capnp_rpc::RpcSystem::new(
                    byte_stream_network(client_end, capnp_rpc::rpc_twoparty_capnp::Side::Client),
                    None,
                );
                let service: svc::Client =
                    client_rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                tokio::task::spawn_local(client_rpc);

                service
                    .echo_request()
                    .send()
                    .promise
                    .await
                    .expect("echo over a duplex stream must succeed");
            })
            .await
    }

    /// Where capture is unsupported (plan D7), `setCaptureFile` fails with
    /// Unimplemented and says why, before looking at its arguments.
    #[tokio::test]
    async fn test_set_capture_file_unsupported_when_capture_unavailable() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let service: svc::Client = capnp_rpc::new_client(AdminServiceImpl {
                    asm,
                    login_agents: Rc::default(),
                    capture_supported: false,
                });

                let err = match service.set_capture_file_request().send().promise.await {
                    Ok(_) => panic!("setCaptureFile must fail where capture is unsupported"),
                    Err(err) => err,
                };
                assert_eq!(err.kind, capnp::ErrorKind::Unimplemented);
                assert!(
                    err.extra
                        .contains("capture is not available on this platform"),
                    "unexpected error: {err}"
                );
            })
            .await
    }

    /// The FD-passing path end to end (zipline#142): a capture file's
    /// descriptor sent over a `UnixFdStream` VatNetwork arrives in ph as a
    /// usable file — `setCaptureFile` succeeds and ph writes the pcap
    /// header through the received descriptor, which we read back.
    #[cfg(all(unix, feature = "capnp-ancillary"))]
    #[tokio::test]
    async fn test_set_capture_file_fd_arrives_usable_over_unix_fd_stream() {
        use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

        struct TestCaptureFile {
            fd: OwnedFd,
        }
        impl cli::capture_file::Server for TestCaptureFile {
            fn get_fd(&self) -> Option<BorrowedFd<'_>> {
                Some(self.fd.as_fd())
            }
        }

        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));

                // A real socketpair: FD passing needs SCM_RIGHTS, which an
                // in-memory duplex cannot carry.
                let (client_sock, server_sock) = tokio::net::UnixStream::pair().unwrap();
                let fd_network = |sock: tokio::net::UnixStream, side| {
                    let (reader, writer) = sock.into_split();
                    Box::new(capnp_rpc::twoparty::io::VatNetwork::new_with_fds(
                        capnp_futures::io::tokio::UnixFdStream::new(reader),
                        capnp_futures::io::tokio::UnixFdStream::new(writer),
                        1,
                        side,
                        capnp::message::ReaderOptions::new(),
                    ))
                };
                serve_connection(
                    asm,
                    fd_network(server_sock, capnp_rpc::rpc_twoparty_capnp::Side::Server),
                    true,
                );

                let mut client_rpc = capnp_rpc::RpcSystem::new(
                    fd_network(client_sock, capnp_rpc::rpc_twoparty_capnp::Side::Client),
                    None,
                );
                let service: svc::Client =
                    client_rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                tokio::task::spawn_local(client_rpc);

                // The capture file whose fd crosses the socket.
                let tstamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let path = std::env::temp_dir().join(format!("zpr_test_capture_{tstamp}.pcap"));
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&path)
                    .unwrap();

                let mut request = service.set_capture_file_request();
                request
                    .get()
                    .set_capture_file(capnp_rpc::new_client(TestCaptureFile { fd: file.into() }));
                let response = request
                    .send()
                    .promise
                    .await
                    .expect("setCaptureFile over the FD-passing transport must not error");
                match response
                    .get()
                    .unwrap()
                    .get_result()
                    .unwrap()
                    .which()
                    .unwrap()
                {
                    cli::success_or_error::Which::Success(_) => (),
                    cli::success_or_error::Which::Error(e) => panic!(
                        "setCaptureFile must succeed: {}",
                        e.unwrap().get_txt().unwrap().to_string().unwrap()
                    ),
                }

                // ph wrote the pcap global header through the received fd:
                // read the file back and check it.
                let written = std::fs::read(&path).unwrap();
                std::fs::remove_file(&path).unwrap();
                assert!(
                    written.len() >= 24,
                    "pcap header missing: ph did not receive a usable file ({} bytes)",
                    written.len()
                );
                let magic = u32::from_ne_bytes(written[0..4].try_into().unwrap());
                assert_eq!(magic, 0xa1b2_c3d4, "not a pcap global header");
            })
            .await
    }

    /// `setCaptureFile` whose CaptureFile capability yields no descriptor —
    /// the caller is not on the FD-passing transport — answers
    /// Unimplemented rather than opening anything (zipline#142).
    #[cfg(all(unix, feature = "capnp-ancillary"))]
    #[tokio::test]
    async fn test_set_capture_file_without_fd_is_unsupported() {
        use std::os::fd::BorrowedFd;

        struct NoFdCaptureFile;
        impl cli::capture_file::Server for NoFdCaptureFile {
            fn get_fd(&self) -> Option<BorrowedFd<'_>> {
                None
            }
        }

        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let service: svc::Client = capnp_rpc::new_client(AdminServiceImpl {
                    asm,
                    login_agents: Rc::default(),
                    capture_supported: true,
                });

                let mut request = service.set_capture_file_request();
                request
                    .get()
                    .set_capture_file(capnp_rpc::new_client(NoFdCaptureFile));
                let err = match request.send().promise.await {
                    Ok(_) => panic!("setCaptureFile without an fd must fail"),
                    Err(err) => err,
                };
                assert_eq!(err.kind, capnp::ErrorKind::Unimplemented);
                assert!(
                    err.extra.contains("no file descriptor received"),
                    "unexpected error: {err}"
                );
            })
            .await
    }

    /// On a non-ancillary build `setCaptureFile` is Unsupported outright
    /// (zipline#142, plan D4): there is no transport to receive an fd on
    /// and `capture.sock` no longer exists.
    #[cfg(not(all(unix, feature = "capnp-ancillary")))]
    #[tokio::test]
    async fn test_set_capture_file_unsupported_on_non_ancillary_build() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let service: svc::Client = capnp_rpc::new_client(AdminServiceImpl {
                    asm,
                    login_agents: Rc::default(),
                    capture_supported: true,
                });
                let err = match service.set_capture_file_request().send().promise.await {
                    Ok(_) => panic!("setCaptureFile must fail on a non-ancillary build"),
                    Err(err) => err,
                };
                assert_eq!(err.kind, capnp::ErrorKind::Unimplemented);
                assert!(
                    err.extra
                        .contains("capture is not available on this platform"),
                    "unexpected error: {err}"
                );
            })
            .await
    }

    /// Read-only admin RPCs log at DEBUG, not INFO (zipline#188): a poller
    /// such as `zipline log` must not fill the INFO log. State-changing
    /// calls keep their INFO line — `resetCounters` is the positive control
    /// that proves the capture works, so the negative assertion is not
    /// vacuous.
    #[tokio::test]
    async fn test_read_only_rpcs_log_at_debug_state_changing_at_info() {
        use std::sync::Mutex;
        use tracing_subscriber::filter::targets::Targets;
        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .with_filter(Targets::new().with_target(RPC, Level::INFO)),
        );
        let _guard = tracing::subscriber::set_default(subscriber);

        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let service: svc::Client = capnp_rpc::new_client(AdminServiceImpl {
                    asm,
                    login_agents: Rc::default(),
                    capture_supported: false,
                });

                service
                    .show_link_summary_request()
                    .send()
                    .promise
                    .await
                    .expect("showLinkSummary must succeed");
                let mut show_link = service.show_link_request();
                show_link.get().set_id(1);
                show_link
                    .send()
                    .promise
                    .await
                    .expect("showLink must succeed");
                service
                    .perf_sample_request()
                    .send()
                    .promise
                    .await
                    .expect("perfSample must succeed");
                service
                    .reset_counters_request()
                    .send()
                    .promise
                    .await
                    .expect("resetCounters must succeed");
            })
            .await;

        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        for read_only in [
            "Show link summary procedure initiated",
            "Show link procedure initiated",
            "Perf sample procedure initiated",
        ] {
            assert!(
                !output.lines().any(|l| l.contains(read_only)),
                "read-only RPC logged at INFO: {read_only:?}\ncaptured INFO output:\n{output}"
            );
        }
        let control: Vec<&str> = output
            .lines()
            .filter(|l| l.contains("Reset counters procedure initiated"))
            .collect();
        assert_eq!(
            control.len(),
            1,
            "state-changing resetCounters must log exactly one INFO line\ncaptured INFO output:\n{output}"
        );
        assert!(
            control[0].contains(" INFO "),
            "resetCounters line must be at INFO: {:?}",
            control[0]
        );
    }

    /// A `TunCtl` for the `getTunInfo` tests (zipline#202): a fixed
    /// interface name, exactly the addresses it was given on the device,
    /// and optionally an `Unsupported` answer to every `has_address`.
    struct TunInfoTunCtl {
        name: &'static str,
        on_tun: Vec<IpAddr>,
        inspect_unsupported: bool,
    }

    impl crate::tun_ctl::TunCtl for TunInfoTunCtl {
        fn name(&self) -> String {
            self.name.to_string()
        }
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        /// The AAA is just another address to this double.
        fn add_authentication_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            self.add_address(addr, prefix_len)
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
            if self.inspect_unsupported {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TunInfoTunCtl: has_address deliberately unsupported",
                ));
            }
            Ok(self.on_tun.contains(&addr))
        }
    }

    /// Calls `getTunInfo` over an in-process RPC pair on a Zode assembly
    /// whose configured local ZPR addresses are `zpr_addr` and whose TUN is
    /// `tun_ctl`. Returns the interface name and the reported addresses, or
    /// the error text when ph answered with an error.
    async fn get_tun_info(
        zpr_addr: &[&str],
        tun_ctl: TunInfoTunCtl,
    ) -> Result<(String, Vec<IpAddr>), String> {
        let zpr_addr: Vec<IpAddr> = zpr_addr.iter().map(|a| a.parse().unwrap()).collect();
        let mut builder = TestAssemblyBuilder::new();
        let cfg = config::Config {
            zpr_addr,
            ..Default::default()
        };
        builder.config = Some(rcu::RcuBox::new(cfg));
        builder.tun_ctl = Some(Box::new(tun_ctl));
        let asm = Arc::new(create_assembly(builder));

        LocalSet::new()
            .run_until(async move {
                let (client_end, server_end) = tokio::io::duplex(4096);
                serve_connection(
                    asm,
                    byte_stream_network(server_end, capnp_rpc::rpc_twoparty_capnp::Side::Server),
                    true,
                );
                let mut client_rpc = capnp_rpc::RpcSystem::new(
                    byte_stream_network(client_end, capnp_rpc::rpc_twoparty_capnp::Side::Client),
                    None,
                );
                let service: svc::Client =
                    client_rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
                tokio::task::spawn_local(client_rpc);

                let response = service
                    .get_tun_info_request()
                    .send()
                    .promise
                    .await
                    .expect("getTunInfo must be answered");
                let results = response.get().unwrap();
                if let cli::success_or_error::Which::Error(e) =
                    results.get_result().unwrap().which().unwrap()
                {
                    return Err(e.unwrap().get_txt().unwrap().to_string().unwrap());
                }
                let info = results.get_info().unwrap();
                let name = info.get_if_name().unwrap().to_string().unwrap();
                let addrs = info
                    .get_zpr_addrs()
                    .unwrap()
                    .iter()
                    .map(|a| match a.which().unwrap() {
                        cli::ip_addr::Which::V4(b) => {
                            IpAddr::from(<[u8; 4]>::try_from(b.unwrap()).unwrap())
                        }
                        cli::ip_addr::Which::V6(b) => {
                            IpAddr::from(<[u8; 16]>::try_from(b.unwrap()).unwrap())
                        }
                    })
                    .collect();
                Ok((name, addrs))
            })
            .await
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// (a) zipline#202: `getTunInfo` reports the name of the TUN ph opened.
    #[tokio::test]
    async fn get_tun_info_reports_interface_name() {
        let (name, _) = get_tun_info(
            &[],
            TunInfoTunCtl {
                name: "utun7",
                on_tun: vec![],
                inspect_unsupported: false,
            },
        )
        .await
        .expect("getTunInfo must succeed");
        assert_eq!(name, "utun7");
    }

    /// (b) A configured address that is on the TUN is reported.
    #[tokio::test]
    async fn get_tun_info_reports_granted_address_on_tun() {
        let (name, addrs) = get_tun_info(
            &["fd5a:5052::1234"],
            TunInfoTunCtl {
                name: "tun0",
                on_tun: vec![ip("fd5a:5052::1234"), ip("fe80::1")],
                inspect_unsupported: false,
            },
        )
        .await
        .expect("getTunInfo must succeed");
        assert_eq!(name, "tun0");
        assert_eq!(addrs, vec![ip("fd5a:5052::1234")]);
    }

    /// (c) An address ph believes it owns but which is not on the TUN (a
    /// stale or not-yet-applied one) is not reported (plan Q2).
    #[tokio::test]
    async fn get_tun_info_omits_address_absent_from_tun() {
        let (_, addrs) = get_tun_info(
            &["fd5a:5052::1234", "fd5a:5052::99"],
            TunInfoTunCtl {
                name: "tun0",
                on_tun: vec![ip("fd5a:5052::99")],
                inspect_unsupported: false,
            },
        )
        .await
        .expect("getTunInfo must succeed");
        assert_eq!(addrs, vec![ip("fd5a:5052::99")]);
    }

    /// An address the platform cannot inspect (`Unsupported`) is omitted,
    /// not guessed (plan Q2).
    #[tokio::test]
    async fn get_tun_info_omits_uninspectable_address() {
        let (_, addrs) = get_tun_info(
            &["10.0.0.5"],
            TunInfoTunCtl {
                name: "tun0",
                on_tun: vec![ip("10.0.0.5")],
                inspect_unsupported: true,
            },
        )
        .await
        .expect("getTunInfo must succeed");
        assert!(
            addrs.is_empty(),
            "uninspectable address reported: {addrs:?}"
        );
    }

    /// A capnp AuthAgent that answers every request at once with
    /// [crate::zode_login::tests::ID_TOKEN], recording each nonce and
    /// whether the request was interactive.
    struct InstantAuthAgent {
        seen: Rc<RefCell<Vec<(String, bool)>>>,
    }

    impl cli::auth_agent::Server for InstantAuthAgent {
        async fn get_oidc_credential(
            self: Rc<Self>,
            params: cli::auth_agent::GetOidcCredentialParams,
            mut results: cli::auth_agent::GetOidcCredentialResults,
        ) -> Result<(), capnp::Error> {
            let p = params.get()?;
            self.seen
                .borrow_mut()
                .push((p.get_nonce()?.to_str()?.to_string(), p.get_interactive()));
            let mut rb = results.get();
            rb.set_id_token(crate::zode_login::tests::ID_TOKEN);
            rb.init_result().init_success().set_none(());
            Ok(())
        }
    }

    /// Serve the admin RPC for `asm` over an in-memory duplex (standing in
    /// for the unix socket and the named pipe alike) and return a client
    /// plus the client RPC task, which a test aborts to close the
    /// connection.
    fn duplex_admin_client(asm: Arc<Assembly>) -> (svc::Client, tokio::task::JoinHandle<()>) {
        let (client_end, server_end) = tokio::io::duplex(4096);
        serve_connection(
            asm,
            byte_stream_network(server_end, capnp_rpc::rpc_twoparty_capnp::Side::Server),
            true,
        );
        let mut client_rpc = capnp_rpc::RpcSystem::new(
            byte_stream_network(client_end, capnp_rpc::rpc_twoparty_capnp::Side::Client),
            None,
        );
        let service: svc::Client =
            client_rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
        let task = tokio::task::spawn_local(async move {
            let _ = client_rpc.await;
        });
        (service, task)
    }

    /// The error text of a `SuccessOrError`, or None on success.
    fn error_text(result: cli::success_or_error::Reader<'_>) -> Option<String> {
        match result.which().unwrap() {
            cli::success_or_error::Which::Success(_) => None,
            cli::success_or_error::Which::Error(e) => {
                Some(e.unwrap().get_txt().unwrap().to_string().unwrap())
            }
        }
    }

    /// Call `login` with an [InstantAuthAgent]; returns the error text, if
    /// any, and what the agent saw.
    async fn call_login(
        service: &svc::Client,
    ) -> (Option<String>, Rc<RefCell<Vec<(String, bool)>>>) {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let mut request = service.login_request();
        request
            .get()
            .set_auth_agent(capnp_rpc::new_client(InstantAuthAgent {
                seen: seen.clone(),
            }));
        let response = request
            .send()
            .promise
            .await
            .expect("login must be answered");
        (
            error_text(response.get().unwrap().get_result().unwrap()),
            seen,
        )
    }

    /// zl-zipline#233: `login` over a byte stream logs the Zode in, with the
    /// agent called back over the same connection with the visa-service
    /// nonce; `showLogin` then reports it, and `logout` logs out.
    #[tokio::test]
    async fn test_login_logout_and_show_login_over_a_byte_stream() {
        LocalSet::new()
            .run_until(async {
                let (asm, _fake) =
                    crate::zode_login::tests::zode(crate::fake_vs::FakeVsState::default(), true)
                        .await;
                let (service, _client) = duplex_admin_client(asm.clone());

                let (err, seen) = call_login(&service).await;
                assert_eq!(err, None);
                assert_eq!(*seen.borrow(), vec![("vs-nonce-1".to_string(), true)]);
                assert!(asm.zode_login.is_logged_in());

                let response = service.show_login_request().send().promise.await.unwrap();
                let text = response
                    .get()
                    .unwrap()
                    .get_result()
                    .unwrap()
                    .to_string()
                    .unwrap();
                assert!(text.starts_with("State: logged in\n"), "{text}");
                assert!(text.contains("Auth agent: registered"), "{text}");

                let response = service.logout_request().send().promise.await.unwrap();
                assert_eq!(
                    error_text(response.get().unwrap().get_result().unwrap()),
                    None
                );
                assert!(!asm.zode_login.is_logged_in());

                let response = service.logout_request().send().promise.await.unwrap();
                assert_eq!(
                    error_text(response.get().unwrap().get_result().unwrap()).as_deref(),
                    Some("not logged in")
                );
            })
            .await
    }

    /// A failed `login` answers with the AuthFailureReason Debug spelling,
    /// which ph-cli maps onto its exit codes.
    #[tokio::test]
    async fn test_login_failure_text_is_the_reason_spelling() {
        LocalSet::new()
            .run_until(async {
                let (asm, _fake) =
                    crate::zode_login::tests::zode(crate::fake_vs::FakeVsState::default(), false)
                        .await;
                let (service, _client) = duplex_admin_client(asm);
                let (err, _) = call_login(&service).await;
                assert_eq!(err.as_deref(), Some("AuthUnavailable"));
            })
            .await
    }

    /// The agent registered by `login` is unregistered when its admin
    /// connection closes (zipline#45); the login itself is kept (q5).
    #[tokio::test]
    async fn test_login_agent_is_cleared_when_the_connection_closes() {
        LocalSet::new()
            .run_until(async {
                let (asm, _fake) =
                    crate::zode_login::tests::zode(crate::fake_vs::FakeVsState::default(), true)
                        .await;
                let (service, client) = duplex_admin_client(asm.clone());
                let (err, _) = call_login(&service).await;
                assert_eq!(err, None);
                assert!(asm.zode_login.has_agent());

                client.abort();
                drop(service);
                assert!(
                    wait_for(5000, || !asm.zode_login.has_agent()).await,
                    "the agent must be unregistered when its connection closes"
                );
                assert!(
                    asm.zode_login.is_logged_in(),
                    "the login is kept until expiry"
                );
            })
            .await
    }
}
