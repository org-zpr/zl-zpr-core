//! Tool to help debug PH
//! Note: at this moment the program can only handle one-word commands, so
//! when a command is multiple words, this program assumes the spaces are replaced
//! with a '-' on the command line
mod control;
mod main_args;
mod oidc;
mod rusty_helper;

use crate::main_args::{CaptureCommands, CliCommand, CmdlineArgs, Commands, LinkCommands};
use admin_api::v1 as cli;
use clap::Parser;
use cli::cmd_line_inter as svc;
use rustyline::{CompletionType, Config, Editor, error::ReadlineError, history::FileHistory};
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
// The FD-passing capture path (capnp-ancillary) opens the file here and
// hands its fd to ph over the admin RPC; unix only (capture is Unsupported
// on Windows, plan D7 / zipline#130).
#[cfg(all(unix, feature = "capnp-ancillary"))]
use std::fs::OpenOptions;
#[cfg(all(unix, feature = "capnp-ancillary"))]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use thiserror::Error;
use tokio::time::{Duration, sleep};
#[cfg(not(all(unix, feature = "capnp-ancillary")))]
use tokio_util::compat::*;

// The pcap-consuming code is additionally gated off Windows (plan D13):
// filter-string compilation would need the Npcap SDK, so a Windows build
// uses `--no-default-features` and the paths below answer Unsupported.
#[cfg(all(feature = "pcap", not(windows)))]
use {
    cbpf_rs,
    pcap::{Capture, Linktype},
    std::borrow::Borrow,
};

#[allow(unused_imports)]
use ctrlc;
#[allow(unused_imports)]
use std::sync::{Arc, Condvar, Mutex};

#[derive(Error, Debug)]
enum CliError {
    #[error("Protocol error: {0}")]
    ProtocolError(#[from] capnp::Error),
    #[error("OS error: {0}")]
    OsError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Deserialization Error")]
    DeserializationError(#[from] std::array::TryFromSliceError),
    #[error("ReadLineError")]
    ReadLineError(#[from] ReadlineError),

    #[allow(dead_code)]
    #[error("Feature Not Enabled: {0}")]
    FeatureNotEnabled(String),

    #[cfg(all(feature = "pcap", not(windows)))]
    #[error("Pcap error: {0}")]
    CaptureError(#[from] pcap::Error),
}

// thiserror does not propagate From implementations up
impl From<capnp::NotInSchema> for CliError {
    fn from(err: capnp::NotInSchema) -> Self {
        // could also use .into() instead
        CliError::ProtocolError(capnp::Error::from(err))
    }
}

impl From<std::str::Utf8Error> for CliError {
    fn from(err: std::str::Utf8Error) -> Self {
        CliError::ProtocolError(capnp::Error::from(err))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), CliError> {
    let args = CmdlineArgs::parse();
    // zipline#39: default socket search — per-uid path for our euid, then the
    // shared path; explicit -p short-circuits. Commands that never touch
    // the packet handler socket must not fail when no socket exists.
    let socket = match main_args::resolve_sockets(args.socket.clone()) {
        Ok(path) => path,
        Err(msg) => {
            if matches!(
                args.command,
                Some(Commands::Quit) | Some(Commands::OidcLogin { .. })
            ) {
                PathBuf::new()
            } else {
                eprintln!("{msg}");
                return Err(CliError::ParseError(msg));
            }
        }
    };

    if let Some(command) = args.command {
        process_command(command, &socket).await.map(|_| {})
    } else {
        run_cli(socket).await
    }
}

async fn run_cli(socket: PathBuf) -> Result<(), CliError> {
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .completion_show_all_if_ambiguous(true)
        .build();
    let mut rl = Editor::<rusty_helper::RustyHelper, FileHistory>::with_config(config)?;

    rl.set_helper(Some(rusty_helper::RustyHelper));

    // Optionally load history from a file, allows for cross sessioin history
    let history_path = dirs::home_dir().map(|p| p.join(".ph_cli_history"));
    if let Some(ref path) = history_path {
        let _ = rl.load_history(path); // ignore error if file doesn't exist yet
    }

    loop {
        match rl.readline("> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                rl.add_history_entry(line)?;

                match parse_and_exec(line, &socket).await {
                    Ok(quit) => {
                        if quit {
                            break;
                        }
                    }
                    Err(err) => match err {
                        CliError::OsError(err) => match err.kind() {
                            std::io::ErrorKind::NotFound => return Err(CliError::OsError(err)),
                            _ => println!("Failed to parse command \"{}\".  Error: {}", line, err),
                        },
                        _ => println!("Failed to parse command \"{}\".  Error: {}", line, err),
                    },
                }
            }
            Err(ReadlineError::Interrupted) => {
                continue;
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Error: {}", err);
                return Err(CliError::ParseError(err.to_string()));
            }
        }
    }

    // Save history on exit
    if let Some(ref path) = history_path {
        let _ = rl.save_history(path);
    }

    Ok(())
}

async fn parse_and_exec(line: &str, socket: &PathBuf) -> Result<bool, CliError> {
    let args = shlex::split(line).ok_or(Error::other("Invalid quoting"))?;
    let cli = CliCommand::try_parse_from(args).map_err(|e| Error::other(e.to_string()))?;

    process_command(cli.command, &socket).await
}

async fn process_command(command: Commands, socket: &PathBuf) -> Result<bool, CliError> {
    // Must quit immediately otherwise you get an error if the port is no longer open
    if matches!(command, Commands::Quit) {
        return Ok(true);
    }

    // The standalone OIDC login test harness talks to the IdP only; it does
    // not need the packet handler's management socket.
    if let Commands::OidcLogin {
        issuer,
        client_id,
        client_secret,
        scopes,
        nonce,
        no_browser,
    } = command
    {
        let idp = oidc::OidcIdpInfo {
            issuer,
            client_id,
            client_secret,
            scopes,
            allow_offline_access: false,
        };
        return oidc_login_task(idp, nonce, no_browser).await;
    }

    let sock = control::connect(socket).await?;

    #[cfg(not(all(unix, feature = "capnp-ancillary")))]
    let network = {
        let (reader, writer) = tokio::io::split(sock);
        capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Client,
            capnp::message::ReaderOptions::new(),
        )
    };

    // FD-passing transport (zipline#142): `capture set-file` sends the opened
    // capture file's descriptor to ph as SCM_RIGHTS ancillary data. Needs the
    // capnproto-rust fork, so normal builds compile this out — see the
    // workspace root Cargo.toml.
    #[cfg(all(unix, feature = "capnp-ancillary"))]
    let network = {
        let (reader, writer) = sock.into_split();
        capnp_rpc::twoparty::io::VatNetwork::new_with_fds(
            capnp_futures::io::tokio::UnixFdStream::new(reader),
            capnp_futures::io::tokio::UnixFdStream::new(writer),
            1,
            capnp_rpc::rpc_twoparty_capnp::Side::Client,
            capnp::message::ReaderOptions::new(),
        )
    };

    let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);

    let service: cli::cmd_line_inter::Client =
        rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);

    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(rpc_system);

            match command {
                Commands::Echo => echo_task(service).await?,
                Commands::Counters { reset } => {
                    if reset {
                        counters_reset_task(service).await?
                    } else {
                        counters_task(service).await?
                    }
                }
                Commands::Capture(capture) => match capture.command {
                    CaptureCommands::SetFile { file_path } => {
                        set_capture_file_task(service, file_path).await?;
                    }
                    CaptureCommands::CloseFile => close_capture_file_task(service).await?,
                    CaptureCommands::FlushFile => flush_capture_file_task(service).await?,
                    CaptureCommands::SetProgram { program } => {
                        set_capture_program_task(service, program).await?
                    }
                    CaptureCommands::DeleteProgram => delete_capture_program_task(service).await?,
                    CaptureCommands::Sequence {
                        file_path,
                        duration,
                        program,
                    } => capture_sequence_task(service, file_path, duration, program).await?,
                },
                Commands::Watch { interval } => watch_task(service, interval).await?,
                Commands::PerfSample {
                    duration,
                    frequency,
                } => perf_sample_task(service, duration, frequency).await?,
                Commands::Link(link) => match link.command {
                    LinkCommands::Show { id: None } => show_link_summary_task(service).await?,
                    LinkCommands::Show { id: Some(id) } => show_link_task(service, id).await?,
                    LinkCommands::Configure { id } => configure_link_task(service, id).await?,
                    LinkCommands::Start { id } => start_link_task(service, id).await?,
                    LinkCommands::Stop { id } => stop_link_task(service, id).await?,
                    LinkCommands::Reset { id } => reset_link_task(service, id).await?,
                },
                Commands::Logging { logs } => change_logging_task(service, logs).await?,
                Commands::Addr => get_node_addr_task(service).await?,
                Commands::Tun => get_tun_info_task(service).await?,
                Commands::Connect { id, no_browser } => {
                    connect_task(service, id, no_browser).await?
                }
                Commands::AuthAgent { id, no_browser } => {
                    auth_agent_task(service, id, no_browser).await?
                }
                Commands::OidcLogin { .. } => unreachable!("handled before connecting"),
                Commands::Quit => return Ok(true), // Will never reach here
            }

            Ok(false)
        })
        .await
}

/// Run the standalone OIDC login flow (hidden `oidc-login` debug command)
/// and print the resulting id_token to stdout. On failure, exits with the
/// contract exit code for the failure class.
async fn oidc_login_task(
    idp: oidc::OidcIdpInfo,
    nonce: String,
    no_browser: bool,
) -> Result<bool, CliError> {
    match oidc::login(&idp, &nonce, !no_browser, oidc::OIDC_LOGIN_TIMEOUT).await {
        Ok(id_token) => {
            // The one deliberate place the token is emitted: stdout, for the
            // test harness. Progress/log output never carries it.
            println!("{id_token}");
            Ok(false)
        }
        Err(err) => {
            eprintln!("oidc-login failed: {err}");
            std::process::exit(oidc::exit_code_for_oidc_error(&err));
        }
    }
}

/// How long `connect` waits for the link to come up. Slightly above ph's
/// authentication budget (the node's 330 s ACTOR_AUTHENTICATION_TIMEOUT
/// bounds the 300 s user-interaction window), so ph decides the outcome and
/// this deadline only catches a wedged link.
const CONNECT_DEADLINE: Duration = Duration::from_secs(330);

/// How often `connect` polls `showLink` while waiting for the outcome.
const CONNECT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// `connect`: start a link, supplying this process as its AuthAgent
/// (`AuthAgent` in adapter/admin-api/cli.capnp), and hold the RPC
/// connection open so the packet handler's `getOidcCredential` callback can reach us while the link authenticates.
///
/// `startLink` returns as soon as the Start event is accepted, so the
/// outcome is observed by polling `showLink` until the state is `Active`
/// (exit 0) or `Error` (exit per the failure-class contract: 2 declined,
/// 3 timeout, 4 IdP unreachable, 5 VS rejected token, 6 policy denied,
/// 7 device blob rejected, 1 anything else). On a device-only link the
/// agent is supplied but never called and the link simply comes up.
///
/// ph only accepts Start from Inactive; any other state answers
/// `UnexpectedTransition`, but the agent is registered by then (zipline#111).
/// A link tearing down (e.g. before its holddown restart) is retried until
/// Start is accepted. An attempt already in flight authenticates with our
/// agent, so its outcome is polled like our own. An already-Active link is
/// still an error on the first call, but a success on a retry: an attempt
/// ran between two retries and came up with our agent.
async fn connect_task(service: svc::Client, id: u32, no_browser: bool) -> Result<(), CliError> {
    println!("Connecting link {id}…");
    let deadline = tokio::time::Instant::now() + CONNECT_DEADLINE;
    let mut first_attempt = true;
    loop {
        let mut request = service.start_link_request();
        request.get().set_id(id);
        // Register the agent on the first call only. It stays on the link
        // for the link's lifetime, so retries must not spawn another bridge.
        // The agent prints its own progress ("Authentication with <issuer>
        // required…") when — and only when — ph calls back for a credential,
        // since the issuer is not known until then.
        if first_attempt {
            request
                .get()
                .set_auth_agent(capnp_rpc::new_client(interactive_auth_agent(no_browser)));
        }

        let response = request.send().promise.await?;
        let results = response.get()?;
        let cli::success_or_error::Which::Error(e) = results.get_result()?.which()? else {
            break; // Start accepted.
        };
        let msg = e?.get_txt()?.to_string()?;
        match oidc::classify_start_link_error(&msg) {
            oidc::StartLinkError::AlreadyActive if !first_attempt => {
                println!("Link {id} up");
                return Ok(());
            }
            oidc::StartLinkError::InFlight => {
                println!("Link {id} already connecting; waiting for that attempt");
                break;
            }
            oidc::StartLinkError::TearingDown if tokio::time::Instant::now() < deadline => {
                println!(
                    "Link {id} not startable yet ({}), retrying…",
                    msg.trim_end()
                );
            }
            class => {
                // A TearingDown that reaches this arm means the deadline
                // expired while the link stayed in teardown — the wedged
                // link CONNECT_DEADLINE exists to catch — so it reports the
                // documented timeout outcome (exit 3), matching the polling
                // loop below. Everything else is a generic failure (exit 1).
                let code = oidc::exit_code_for_start_link_giveup(&class);
                if code == 3 {
                    eprintln!(
                        "connect failed: timed out waiting for link {id} to come up ({})",
                        msg.trim_end()
                    );
                } else {
                    eprintln!("connect failed: {msg}");
                }
                std::process::exit(code);
            }
        }
        first_attempt = false;
        sleep(CONNECT_POLL_INTERVAL).await;
    }

    // Started. Poll showLink for the outcome; the RpcSystem stays alive on
    // this LocalSet the whole time, serving getOidcCredential callbacks.
    loop {
        if tokio::time::Instant::now() >= deadline {
            eprintln!("connect failed: timed out waiting for link {id} to come up");
            std::process::exit(3);
        }
        sleep(CONNECT_POLL_INTERVAL).await;

        let mut show = service.show_link_request();
        show.get().set_id(id);
        let response = show.send().promise.await?;
        let text = response.get()?.get_result()?.to_string()?;
        match oidc::parse_show_link_state(&text) {
            oidc::LinkOutcome::Up => {
                println!("Link {id} up");
                return Ok(());
            }
            oidc::LinkOutcome::Failed(reason) => {
                if reason.is_empty() {
                    eprintln!("connect failed: link {id} is in the Error state");
                } else {
                    eprintln!("connect failed: {reason}");
                }
                std::process::exit(oidc::exit_code_for_auth_failure(&reason));
            }
            oidc::LinkOutcome::Pending => {}
        }
    }
}

/// Build the interactive [`oidc::CliAuthAgent`] shared by `connect` and
/// `auth-agent`: `--no-browser` prints authorization URLs through the
/// progress path instead of launching a browser.
fn interactive_auth_agent(no_browser: bool) -> oidc::CliAuthAgent {
    oidc::CliAuthAgent::new(!no_browser, None)
}

/// `auth-agent`: register as the authentication agent for a link and serve
/// interactive OIDC requests until SIGINT.
///
/// Registration goes through `startLink` with the agent capability: ph
/// registers the agent before firing the Start event, so on a link that is
/// already started the resulting `UnexpectedTransition` error is benign and
/// tolerated (see [oidc::start_link_error_is_fatal]).
async fn auth_agent_task(service: svc::Client, id: u32, no_browser: bool) -> Result<(), CliError> {
    let mut request = service.start_link_request();
    request.get().set_id(id);
    request
        .get()
        .set_auth_agent(capnp_rpc::new_client(interactive_auth_agent(no_browser)));

    let response = request.send().promise.await?;
    let results = response.get()?;
    match results.get_result()?.which()? {
        cli::success_or_error::Which::Success(_) => {
            println!("Registered as authentication agent for link {id} (link started)");
        }
        cli::success_or_error::Which::Error(e) => {
            let msg = e?.get_txt()?.to_string()?;
            if oidc::start_link_error_is_fatal(&msg) {
                eprintln!("auth-agent registration failed: {msg}");
                std::process::exit(1);
            }
            println!("Registered as authentication agent for already-started link {id}");
        }
    }

    println!("Serving authentication requests until interrupted (Ctrl-C)…");
    tokio::signal::ctrl_c().await?;
    println!("auth-agent: interrupted, exiting");
    Ok(())
}

// TODO combine no arg tasks into one func w/ closure
async fn echo_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.echo_request();

    request.send().promise.await?;
    println!("Echo received");

    Ok(())
}

async fn counters_reset_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.reset_counters_request();

    request.send().promise.await?;
    println!("Counters Reset");

    Ok(())
}

async fn counters_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.counters_request();

    let response = request.send().promise.await?;
    let results = response.get()?.get_counts()?;

    let management = results.get_management()?;
    let fastpaths = results.get_fastpaths()?;
    let uptime_sec = results.get_uptime_sec();
    let uptime_subsec_ms = results.get_uptime_subsec_ms();

    println!("Management counts:");
    let counters = management.get_counters()?;
    for counter in counters.iter() {
        println!("{}: {}", counter.get_name()?.to_str()?, counter.get_val());
    }

    for fastpath in fastpaths.iter() {
        println!("\nFastpath #{} counts:", fastpath.get_id());
        let counters = fastpath.get_counters()?;
        for counter in counters.iter() {
            println!("{}: {}", counter.get_name()?.to_str()?, counter.get_val());
        }
    }

    println!("\nUptime: {uptime_sec}.{uptime_subsec_ms}");

    Ok(())
}

async fn close_capture_file_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.close_capture_file_request();

    request.send().promise.await?;
    println!("Capture file closed and capture program deleted");

    Ok(())
}

async fn flush_capture_file_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.flush_capture_file_request();

    request.send().promise.await?;
    println!("Capture file flushed");

    Ok(())
}

/// Converts capture program into serialized format so that the RPC worker doesn't
/// need to use the pcap library, and can just have knowledge of the serialized
/// format and use exclusively cbpf-rs
// TODO change parameters of set cap prog to take the actual bpf vals instead of string
#[cfg(all(feature = "pcap", not(windows)))]
async fn set_capture_program_task(service: svc::Client, program: String) -> Result<(), CliError> {
    let capture = Capture::dead(Linktype::USER0)?;
    let program = capture.compile(&program, true)?;
    let instructions: &[pcap::BpfInstruction] = program.get_instructions();

    let mut request = service.set_capture_program_request();
    let mut program_request = request
        .get()
        .init_program()
        .init_bpf_prog(instructions.len() as u32);

    for (i, instruction) in instructions.iter().enumerate() {
        let insn: &cbpf_rs::BpfInsn = instruction.borrow();
        let mut insn_builder = program_request.reborrow().get(i as u32);
        insn_builder.set_code(insn.code);
        insn_builder.set_jt(insn.jt);
        insn_builder.set_jf(insn.jf);
        insn_builder.set_k(insn.k);
    }

    let response = request.send().promise.await?;
    let results = response.get()?;
    match results.get_result()?.which()? {
        cli::success_or_error::Which::Success(_) => {
            println!("Capture program set")
        }
        cli::success_or_error::Which::Error(e) => {
            let result = e.unwrap().get_txt()?.to_string()?;
            println!("{result}");
            return Err(CliError::RpcError(result));
        }
    };
    Ok(())
}

/// Filter-string compilation is unavailable without pcap, and on Windows
/// regardless of features (plan D13: no Npcap in this release).
#[cfg(not(all(feature = "pcap", not(windows))))]
async fn set_capture_program_task(_service: svc::Client, _program: String) -> Result<(), CliError> {
    Err(CliError::FeatureNotEnabled(
        "packet capture (pcap)".to_string(),
    ))
}

async fn delete_capture_program_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.delete_capture_program_request();

    request.send().promise.await?;
    println!("Capture program deleted");

    Ok(())
}

async fn capture_sequence_task(
    service: svc::Client,
    file_path: String,
    time: u64,
    program: String,
) -> Result<(), CliError> {
    let sleep_time = Duration::new(time, 0);
    set_capture_file_task(service.clone(), file_path).await?;
    set_capture_program_task(service.clone(), program).await?;

    let handler = Arc::new(CtrlcHandle::new());
    let ctrlc_handler = handler.clone();

    // Will set wait to false in CtrlcHandler if ctrl+c is pressed
    ctrlc::set_handler(move || ctrlc_handler.set_false()).unwrap();

    handler.timed_wait(sleep_time);

    close_capture_file_task(service).await?;

    Ok(())
}

async fn watch_task(service: svc::Client, interval: u64) -> Result<(), CliError> {
    let mut mgmt_values: Vec<u64> = Vec::new();
    let mut fastpaths_values: Vec<Vec<u64>> = Vec::new();

    let sleep_time = Duration::new(interval, 0);
    let mut first_run = true;

    loop {
        let request = service.counters_request();
        let response = request.send().promise.await?;
        let results = response.get()?.get_counts()?;

        let management = results.get_management()?;
        let fastpaths = results.get_fastpaths()?;

        // Set initial counts to 0
        if first_run {
            mgmt_values.resize(management.get_counters()?.len() as usize, 0);
            fastpaths_values.resize(fastpaths.len() as usize, Vec::new());
            for (i, fastpath) in fastpaths.reborrow().iter().enumerate() {
                fastpaths_values[i].resize(fastpath.get_counters()?.len() as usize, 0)
            }
        }

        println!("Increases in management counts:");
        let counters = management.get_counters()?;
        for (i, counter) in counters.iter().enumerate() {
            println!(
                "{}: {}",
                counter.get_name()?.to_str()?,
                counter.get_val() - mgmt_values[i]
            );
            mgmt_values[i] = counter.get_val();
        }

        for (i, fastpath) in fastpaths.iter().enumerate() {
            println!("\nIncreases in Fastpath #{} counts:", fastpath.get_id());
            let counters = fastpath.get_counters()?;
            for (j, counter) in counters.iter().enumerate() {
                println!(
                    "{}: {}",
                    counter.get_name()?.to_str()?,
                    counter.get_val() - fastpaths_values[i][j]
                );
                fastpaths_values[i][j] = counter.get_val();
            }
        }

        first_run = false;
        sleep(sleep_time).await;
    }
}

async fn perf_sample_task(
    service: svc::Client,
    duration: u64,
    frequency: u64,
) -> Result<(), CliError> {
    let mut request = service.perf_sample_request();
    request.get().set_duration_secs(duration);
    request.get().set_frequency_per_sec(frequency);

    let response = request.send().promise.await?;
    let results = response.get()?;
    println!("{}", results.get_result()?.to_str()?);

    Ok(())
}

async fn show_link_summary_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.show_link_summary_request();

    let response = request.send().promise.await?;
    let results = response.get()?;
    let summaries = results.get_summary()?;
    println!("Link summary:");
    for summary in summaries.iter() {
        println!("{}", summary?.to_str()?)
    }

    Ok(())
}

async fn show_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.show_link_request();
    request.get().set_id(id);

    let response = request.send().promise.await?;
    let results = response.get()?;
    println!("{}", results.get_result()?.to_str()?);

    Ok(())
}

async fn configure_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.show_link_request();
    request.get().set_id(id);

    request.send().promise.await?;
    println!("Command currently unsupported");

    Ok(())
}

async fn start_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.start_link_request();
    request.get().set_id(id);

    let response = request.send().promise.await?;
    let results = response.get()?;
    match results.get_result()?.which()? {
        cli::success_or_error::Which::Success(_) => {
            println!("Link {id} started")
        }
        cli::success_or_error::Which::Error(e) => {
            let result = e.unwrap().get_txt()?.to_string()?;
            println!("{result}");
            return Err(CliError::RpcError(result));
        }
    };

    Ok(())
}

async fn stop_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.stop_link_request();
    request.get().set_id(id);

    let response = request.send().promise.await?;
    let results = response.get()?;
    match results.get_result()?.which()? {
        cli::success_or_error::Which::Success(_) => {
            println!("CLink {id} stopped")
        }
        cli::success_or_error::Which::Error(e) => {
            let result = e.unwrap().get_txt()?.to_string()?;
            println!("{result}");
            return Err(CliError::RpcError(result));
        }
    };

    Ok(())
}

async fn reset_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.reset_link_request();
    request.get().set_id(id);

    request.send().promise.await?;
    println!("Link reset");

    Ok(())
}

async fn change_logging_task(
    service: svc::Client,
    logs: Vec<(String, String)>,
) -> Result<(), CliError> {
    // TODO convert logging to take a List instead of a string
    let mut request = service.change_logging_request();
    let mut log_builder = request.get().init_logs(logs.len() as u32);

    for (i, log) in logs.iter().enumerate() {
        let mut tuple_builder = log_builder.reborrow().get(i as u32);
        tuple_builder.set_level(&log.0);
        tuple_builder.set_target(&log.1);
    }

    let response = request.send().promise.await?;
    let results = response.get()?.get_result()?;
    if results.has_applied() {
        println!("Applied: {:?}", results.get_applied()?);
    }
    if results.has_ignored() {
        println!("Ignored: {:?}", results.get_ignored()?);
    }

    Ok(())
}

async fn get_node_addr_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.get_node_info_request();
    let response = request.send().promise.await?;

    let results = response.get()?;
    match results.get_result()?.which()? {
        cli::success_or_error::Which::Success(s) => {
            let sock_addr = s.unwrap().get_sock_addr()?;
            let ip_addr = match sock_addr.get_addr()?.which()? {
                cli::ip_addr::Which::V4(addr) => {
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(addr?)?))
                }
                cli::ip_addr::Which::V6(addr) => {
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(addr?)?))
                }
            };
            let port = sock_addr.get_port();

            println!("IP address: {ip_addr}, Port: {port}");
            Ok(())
        }
        cli::success_or_error::Which::Error(e) => {
            println!("error");
            let result = e.unwrap().get_txt()?.to_string()?;
            println!("{result}");
            Err(CliError::RpcError(result))
        }
    }
}

/// `ph-cli tun` output (zipline#202): line 1 is the interface name, then
/// one ZPR address per line. Pure, so the format is unit-tested.
fn format_tun_info(if_name: &str, addrs: &[IpAddr]) -> String {
    let mut out = String::new();
    out.push_str(if_name);
    out.push('\n');
    for addr in addrs {
        out.push_str(&addr.to_string());
        out.push('\n');
    }
    out
}

async fn get_tun_info_task(service: svc::Client) -> Result<(), CliError> {
    let response = service.get_tun_info_request().send().promise.await?;
    let results = response.get()?;
    if let cli::success_or_error::Which::Error(e) = results.get_result()?.which()? {
        return Err(CliError::RpcError(e?.get_txt()?.to_string()?));
    }
    let info = results.get_info()?;
    let if_name = info.get_if_name()?.to_string()?;
    let mut addrs = Vec::new();
    for addr in info.get_zpr_addrs()?.iter() {
        addrs.push(match addr.which()? {
            cli::ip_addr::Which::V4(a) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(a?)?)),
            cli::ip_addr::Which::V6(a) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(a?)?)),
        });
    }
    print!("{}", format_tun_info(&if_name, &addrs));
    Ok(())
}

// This struct implements the CaptureFile capability for the admin RPC: ph
// calls back `get_fd` and the transport sends the descriptor as SCM_RIGHTS
// ancillary data. Only used with the capnp-ancillary FD-passing transport
// (zipline#142).
#[cfg(all(unix, feature = "capnp-ancillary"))]
struct CaptureFileImpl {
    fd: OwnedFd,
}

#[cfg(all(unix, feature = "capnp-ancillary"))]
impl cli::capture_file::Server for CaptureFileImpl {
    fn get_fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }
}

/// Opens the named capture file and passes its FD to ph as a CaptureFile
/// capability on `setCaptureFile`, so root-running ph never opens a
/// user-chosen path (zipline#142). Needs the capnp-ancillary FD-passing
/// transport.
#[cfg(all(unix, feature = "capnp-ancillary"))]
async fn set_capture_file_task(service: svc::Client, file_path: String) -> Result<(), CliError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;

    let mut request = service.set_capture_file_request();
    request
        .get()
        .set_capture_file(capnp_rpc::new_client(CaptureFileImpl { fd: file.into() }));
    let response = request.send().promise.await?;

    match response.get()?.get_result()?.which()? {
        cli::success_or_error::Which::Success(_) => {
            println!("Capture file opened");
            Ok(())
        }
        cli::success_or_error::Which::Error(e) => {
            let result = e?.get_txt()?.to_string()?;
            println!("{result}");
            Err(CliError::RpcError(result))
        }
    }
}

/// Without the FD-passing transport there is no way to hand ph a capture
/// file: send `setCaptureFile` anyway and print ph's authoritative error
/// (`Unimplemented: capture is not available on this platform`, plan D7).
#[cfg(not(all(unix, feature = "capnp-ancillary")))]
async fn set_capture_file_task(service: svc::Client, _file_path: String) -> Result<(), CliError> {
    let request = service.set_capture_file_request();
    match request.send().promise.await {
        Ok(_) => {
            println!("Capture file set");
            Ok(())
        }
        Err(e) => {
            println!("{}", e.extra);
            Err(CliError::RpcError(e.extra))
        }
    }
}

#[allow(dead_code)]
struct CtrlcHandle {
    wait: Mutex<bool>,
    cv: Condvar,
}

#[allow(dead_code)]
impl CtrlcHandle {
    pub fn new() -> Self {
        Self {
            wait: Mutex::new(true),
            cv: Condvar::new(),
        }
    }

    pub fn set_false(&self) {
        *self.wait.lock().unwrap() = false;
        self.cv.notify_one();
    }

    // Waits for a specified duration, but the timeout can be interrupted if wait becomes
    // false
    pub fn timed_wait(&self, dur: Duration) -> bool {
        let (mut guard, _) = self
            .cv
            .wait_timeout_while(self.wait.lock().unwrap(), dur, |&mut wait| wait)
            .unwrap();
        let wait = *guard;
        *guard = true;
        wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared constructor maps `--no-browser` onto
    /// `CliAuthAgent::open_browser` for both `connect` and `auth-agent`
    /// (zipline#20).
    #[test]
    fn interactive_auth_agent_maps_no_browser_to_open_browser() {
        let agent = interactive_auth_agent(true);
        assert!(
            !agent.open_browser,
            "no_browser: true → open_browser: false"
        );
        assert!(agent.progress.is_none());

        let agent = interactive_auth_agent(false);
        assert!(agent.open_browser, "no_browser: false → open_browser: true");
        assert!(agent.progress.is_none());
    }

    /// `ph-cli tun` output (zipline#202, Q1): line 1 is the interface
    /// name, then one ZPR address per line; no address lines before the
    /// grant.
    #[test]
    fn format_tun_info_prints_name_then_one_address_per_line() {
        let addrs: Vec<IpAddr> = vec![
            "fd5a:5052::1234".parse().unwrap(),
            "fd5a:5052::99".parse().unwrap(),
        ];
        assert_eq!(
            format_tun_info("utun7", &addrs),
            "utun7\nfd5a:5052::1234\nfd5a:5052::99\n"
        );
        assert_eq!(format_tun_info("tun0", &[]), "tun0\n");
    }
}
