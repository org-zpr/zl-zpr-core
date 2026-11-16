use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

use admin_api::{choose_socket_path, control_socket_candidates};

#[derive(Parser, Debug)]
#[command(version = build_info::BUILD_VERSION, about = "This program controls the RPC calls to the ZPR Packet Handler\nRun without a command to enter CLI mode", long_about = None)]
pub struct CmdlineArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to the Packet Handler's management socket. Default: the per-user
    /// socket for your uid when a server answers there, else the shared
    /// socket (zipline#39).
    #[arg(long, short = 'p')]
    pub socket: Option<PathBuf>,
}

/// Resolve the control socket path for this invocation (zipline#39). An
/// explicit `-p` short-circuits. Otherwise the control socket is searched:
/// per-uid path for the caller's euid first, then the shared path; when
/// neither answers the error names both. A candidate is selected by a probe
/// connect, not by pathname existence — a stale socket file left by a dead
/// ph must not shadow a live server at the other path.
pub fn resolve_sockets(explicit_control: Option<PathBuf>) -> Result<PathBuf, String> {
    let user_id = admin_api::current_user_id()
        .map_err(|e| format!("cannot determine the current user id: {e}"))?;
    resolve_sockets_with(explicit_control, &user_id, admin_api::socket_is_live)
}

/// Testable core of [resolve_sockets]: the caller's user id (as
/// [admin_api::current_user_id] spells it) and liveness predicate injected.
pub fn resolve_sockets_with<F>(
    explicit_control: Option<PathBuf>,
    user_id: &str,
    exists: F,
) -> Result<PathBuf, String>
where
    F: Fn(&Path) -> bool,
{
    choose_socket_path(
        explicit_control,
        control_socket_candidates(user_id),
        &exists,
    )
}

#[derive(Parser, Debug)]
#[command(multicall = true)]
pub struct CliCommand {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Echo,
    /// Display or reset counters
    Counters {
        #[arg(long, short = 'r')]
        /// Reset counters
        reset: bool,
    },
    #[command(arg_required_else_help = true)]
    /// Connect to the Packet Handler for periodic counter updates
    Watch {
        #[arg(required = true)]
        /// How frequently to receive updates
        interval: u64,
    },
    #[command(arg_required_else_help = true)]
    /// Start performance sampling (currently not functional)
    PerfSample {
        #[arg(required = true)]
        /// How long the sampling should run
        duration: u64,

        #[arg(required = true)]
        /// How frequently packets should be injected
        frequency: u64,
    },
    /// Set up or tear down packet captures
    Capture(CaptureArgs),
    /// Change link state
    Link(LinkArgs),
    /// Change the log level of a node or adapter
    /// Format: logging [<level>=<target>]*
    /// There must be at least level, target pair
    /// The options for targets are:
    ///     all, capture, datapath, flow_mgmt, link_state,
    ///     mgmt_events, net_os, peer_mgmt, reporting, rpc,
    ///     startup, visa_mgmt, zdp
    /// The options for levels are:
    ///     OFF, ERROR, WARN, INFO, DEBUG, TRACE
    Logging {
        #[arg(required = true, value_delimiter = ' ', num_args = 1.., value_parser = parse_key_val, verbatim_doc_comment)]
        logs: Vec<(String, String)>,
    },
    /// Exit the CLI
    Quit,
    /// Gets the address of an adapter's node
    Addr,
    /// Print the TUN interface ph uses and its ZPR address(es).
    ///
    /// Line 1 is the interface name (e.g. `tun0`, or the kernel-assigned
    /// `utun7` on macOS); each further line is one ZPR address confirmed on
    /// that interface. An adapter prints no address line until its address
    /// is granted. Works against a node as well as an adapter.
    Tun,
    /// Connect (start) a link, authenticate interactively if the packet
    /// handler asks, then exit reporting the outcome.
    ///
    /// On a Zode, run it without a link id: it logs the Zode in (you, on
    /// this machine) and exits. The login lasts until it expires, because
    /// nothing is left to renew it silently; use `auth-agent` for that.
    ///
    /// For scripts and CI: it blocks until the link is up or the attempt
    /// fails and says which through its exit code (2 declined, 3 timeout,
    /// 4 IdP unreachable, 5 visa service rejected the token, 6 policy
    /// denied, 7 device blob rejected).
    ///
    /// The authentication agent it registers dies with this process, so it
    /// cannot serve a later credential request. For an interactive session
    /// use `auth-agent`, which stays resident — and do not run `connect` on
    /// a link that already has one, because the registration overwrites it
    /// and replaces a live agent with one that is about to exit.
    #[command(verbatim_doc_comment)]
    Connect {
        /// Link id to connect (ph adapter); omit it on a Zode to log in
        id: Option<u32>,
        /// Print authentication URLs instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
    /// Start a link and stay resident serving its authentication requests.
    /// This is how a human logs in.
    ///
    /// The browser opens once, and the process then runs until interrupted
    /// (Ctrl-C). It does not report the link's outcome — use
    /// `link show <id>`, which also reports the authentication expiry.
    ///
    /// Keeping this process resident is what makes silent renewal happen:
    /// when a renewal comes due, the packet handler asks this agent for a
    /// fresh credential (zipline#66) and it is served from the refresh
    /// token held in memory, with no browser. The browser paste is
    /// therefore needed once per session ceiling (max_auth_age_seconds),
    /// not once per expiration_seconds.
    ///
    /// On a Zode, run it without a link id: it logs the Zode in and stays
    /// resident to renew the login silently. If the visa service drops the
    /// login (a reconnect or restart), it asks you to log in again.
    ///
    /// Under sudo, pass --no-browser and paste the printed URL into your own
    /// browser: a root process cannot usefully open one.
    #[command(verbatim_doc_comment)]
    AuthAgent {
        /// Link id to serve as authentication agent for (ph adapter); omit
        /// it on a Zode to log in
        id: Option<u32>,
        /// Print authentication URLs instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
    /// Log out the user logged in on this Zode. The machine stays connected.
    Logout,
    /// Show who is logged in on this Zode: the state, the identity
    /// provider, the time left, whether an auth agent is registered, and
    /// the last failure.
    LoginStatus,
    /// Debug: run the OIDC relying-party login flow standalone and print the
    /// resulting id_token to stdout
    #[command(hide = true, arg_required_else_help = true)]
    OidcLogin {
        /// OIDC issuer URL
        #[arg(long)]
        issuer: String,
        /// OAuth client id
        #[arg(long)]
        client_id: String,
        /// OAuth client secret (confidential clients only)
        #[arg(long)]
        client_secret: Option<String>,
        /// Scopes to request (comma-separated)
        #[arg(long, value_delimiter = ',', default_value = "openid")]
        scopes: Vec<String>,
        /// Nonce to bind into the id_token
        #[arg(long)]
        nonce: String,
        /// Print the authorization URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
}

#[derive(Debug, Args)]
#[command(flatten_help = true)]
pub struct CaptureArgs {
    #[command(subcommand)]
    pub command: CaptureCommands,
}

#[derive(Debug, Subcommand)]
pub enum CaptureCommands {
    /// Set a capture file
    SetFile {
        #[arg(required = true)]
        file_path: String,
    },
    /// Close a capture file
    CloseFile,
    /// Set a BPF to filter captured packets
    SetProgram {
        #[arg(required = true, default_value = "link[0] == 1 or link[0] == 0")]
        program: String,
    },
    /// Delete any set BPF
    DeleteProgram,
    /// Flush any outstanding packets to the capture file
    FlushFile,
    #[command(arg_required_else_help = true)]
    /// Create a temporary packet capture
    Sequence {
        file_path: String,
        /// Duration in seconds
        duration: u64,
        #[arg(default_value = "link[0] == 1 or link[0] == 0")]
        program: String,
    },
}

#[derive(Debug, Args)]
#[command(flatten_help = true)]
pub struct LinkArgs {
    #[command(subcommand)]
    pub command: LinkCommands,
}

#[derive(Debug, Subcommand)]
pub enum LinkCommands {
    /// Show a link's status
    Show { id: Option<u32> },
    /// Configure a link
    Configure { id: u32 },
    /// Start a link
    Start { id: u32 },
    /// Stop a link
    Stop { id: u32 },
    /// Reset a link.  It will require a configure before starting again
    Reset { id: u32 },
}

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let key_val: Vec<&str> = s.split("=").collect();
    match key_val.len() {
        2 => {
            return Ok((key_val[0].to_string(), key_val[1].to_uppercase()));
        }
        1 => {
            return Ok(("all".to_string(), key_val[0].to_uppercase()));
        }
        _ => Err(format!("Invalid key-value pair")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use admin_api::control_socket_path;

    /// `auth-agent <id> --no-browser` must parse, setting the flag
    /// (zipline#20).
    #[test]
    fn auth_agent_accepts_no_browser_flag() {
        let parsed = CmdlineArgs::try_parse_from(["ph-cli", "auth-agent", "1", "--no-browser"]);
        match parsed {
            Ok(CmdlineArgs {
                command: Some(Commands::AuthAgent { id, no_browser }),
                ..
            }) => {
                assert_eq!(id, Some(1));
                assert!(no_browser);
            }
            other => panic!("auth-agent should accept --no-browser: {other:?}"),
        }
    }

    /// Without the flag, `auth-agent <id>` still parses with the flag
    /// defaulting off.
    #[test]
    fn auth_agent_parses_without_no_browser_flag() {
        let parsed = CmdlineArgs::try_parse_from(["ph-cli", "auth-agent", "1"]);
        match parsed {
            Ok(CmdlineArgs {
                command: Some(Commands::AuthAgent { id, no_browser }),
                ..
            }) => {
                assert_eq!(id, Some(1));
                assert!(!no_browser, "--no-browser must default off");
            }
            other => panic!("auth-agent without --no-browser should parse: {other:?}"),
        }
    }

    /// `ph-cli tun` parses to `Commands::Tun` (zipline#202).
    #[test]
    fn tun_subcommand_parses() {
        let parsed = CmdlineArgs::try_parse_from(["ph-cli", "tun"]);
        assert!(
            matches!(
                parsed,
                Ok(CmdlineArgs {
                    command: Some(Commands::Tun),
                    ..
                })
            ),
            "`ph-cli tun` should parse to Commands::Tun: {parsed:?}"
        );
    }

    /// An explicit `-p` short-circuits the socket search entirely, even
    /// when the path does not exist (zipline#39).
    #[test]
    fn explicit_sockets_short_circuit() {
        let control = resolve_sockets_with(
            Some(PathBuf::from("/x/control.sock")),
            "1000",
            |_: &Path| false,
        )
        .unwrap();
        assert_eq!(control, PathBuf::from("/x/control.sock"));
    }

    /// Default search prefers the per-uid socket for the caller's euid — the
    /// path a sudo-started ph created for us (zipline#39).
    #[test]
    fn per_uid_socket_preferred() {
        let per_uid = control_socket_path(Some("1000"));
        let control =
            resolve_sockets_with(None, "1000", |p: &Path| p == per_uid.as_path()).unwrap();
        assert_eq!(control, per_uid);
    }

    /// When there is no per-uid socket the shared path is used (systemd-run
    /// ph) (zipline#39).
    #[test]
    fn shared_socket_fallback() {
        let shared = control_socket_path(None);
        let control = resolve_sockets_with(None, "1000", |p: &Path| p == shared.as_path()).unwrap();
        assert_eq!(control, shared);
    }

    /// A systemd/launchd-started ph binds `/var/run/zpr/control.sock`; a
    /// non-root user whose data home is `~/.local/share` must still find it
    /// without `-p` (zipline#77).
    #[cfg(unix)]
    #[test]
    fn fixed_shared_socket_fallback() {
        let fixed = Path::new("/var/run/zpr/control.sock");
        let control = resolve_sockets_with(None, "1000", |p: &Path| p == fixed).unwrap();
        assert_eq!(control, fixed);
    }

    /// With no socket anywhere the error names every path tried (zipline#39).
    #[test]
    fn missing_sockets_error_names_paths() {
        let err = resolve_sockets_with(None, "1000", |_: &Path| false)
            .expect_err("no socket exists, resolution must fail");
        for path in control_socket_candidates("1000") {
            let path = path.to_str().unwrap().to_string();
            assert!(err.contains(&path), "error must name {path}: {err}");
        }
    }

    /// zl-zipline#233: on a Zode, `connect` and `auth-agent` take no link id
    /// and log the Zode in; with an id they start that link as before.
    #[test]
    fn connect_and_auth_agent_take_an_optional_link_id() {
        for (args, want_id, want_resident) in [
            (vec!["ph-cli", "connect"], None, false),
            (vec!["ph-cli", "connect", "--no-browser"], None, false),
            (vec!["ph-cli", "connect", "3"], Some(3), false),
            (vec!["ph-cli", "auth-agent"], None, true),
            (vec!["ph-cli", "auth-agent", "--no-browser"], None, true),
            (vec!["ph-cli", "auth-agent", "3"], Some(3), true),
        ] {
            let parsed = CmdlineArgs::try_parse_from(&args).expect("parses");
            match parsed.command {
                Some(Commands::Connect { id, .. }) if !want_resident => {
                    assert_eq!(id, want_id, "{args:?}")
                }
                Some(Commands::AuthAgent { id, .. }) if want_resident => {
                    assert_eq!(id, want_id, "{args:?}")
                }
                other => panic!("{args:?} parsed to {other:?}"),
            }
        }
    }

    /// zl-zipline#233: `logout` and `login-status` parse.
    #[test]
    fn logout_and_login_status_parse() {
        assert!(matches!(
            CmdlineArgs::try_parse_from(["ph-cli", "logout"])
                .unwrap()
                .command,
            Some(Commands::Logout)
        ));
        assert!(matches!(
            CmdlineArgs::try_parse_from(["ph-cli", "login-status"])
                .unwrap()
                .command,
            Some(Commands::LoginStatus)
        ));
    }
}
