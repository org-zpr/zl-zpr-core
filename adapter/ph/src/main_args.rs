//! ZPR Packet Handler command line arg processing structs.
//!
//! The main entry point is [crate::main_argparse::argparse] which will parse the command line arguments
//! and any config file, returning a PH configuration.

use crate::batch_io;
use crate::logging::{levels, targets};
use clap::{Args, Parser, Subcommand};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::str::FromStr;

/// Errors you may encounter when trying to parse command line or configuration
/// file.
#[cfg(not(feature = "complete"))]
#[derive(thiserror::Error, Debug)]
pub enum ArgsError {
    #[error("missing argument: {0}")]
    Missing(String),

    #[error("{0}")]
    IOError(#[from] std::io::Error),

    #[error("{0}")]
    ParseError(String),

    #[error("{0}")]
    PathError(String),
}

/// ZPR Packet Handler
///
/// Runs a Zode: a ZPR node that carries its own actor. You can specify a configuration
/// file and you can override configuration file settings with command line arguments.
///
/// Eg, start a relay Zode:
///    sudo ./ph zode -c relay_config.toml --relay true
///
/// Eg, start a Zode that dials its relay:
///    sudo ./ph zode -c zode_config.toml --initial-link relay.zpr@10.1.0.8:5000
///
#[derive(Debug, Parser)]
#[command(version = build_info::BUILD_VERSION, verbatim_doc_comment)]
pub struct Control {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug)]
pub struct CommonArgs {
    /// Unix domain socket path for the "control" interface
    #[arg(long, value_name = "DOMAIN_SOCKET_PATH")]
    pub control_path: Option<String>,

    /// Local group whose members may drive the control channel when ph
    /// runs as a service (zipline#154). Windows: an extra ACE on the
    /// control pipe. Linux/macOS: the socket's group when no invoking user
    /// is resolved (systemd/launchd). No default; overrides `control_group`
    /// in the config file's `[global]` section
    #[arg(long, value_name = "GROUP")]
    pub control_group: Option<String>,

    /// Substrate address the Zode's link sockets bind to: the address peers dial.
    /// The default binds every IPv4 interface (0.0.0.0); port 0, the default,
    /// becomes the default link port, 5000
    #[arg(short = 'a', long, value_name = "ADDR:PORT", value_parser = parse_socket_addr_or_scoped_ip_addr)]
    pub self_addr: Option<SocketAddr>,

    /// Certificate of the Certificate Authority
    #[arg(long, value_name = "PATH")]
    pub ca_file: Option<String>,

    /// Certificate including the noise public key, signed by the authority
    #[arg(long, value_name = "PATH")]
    pub certificate_file: Option<String>, // noise public key signed by authority

    /// Path to the noise private key file (PEM format)
    #[arg(long, short = 'k', value_name = "PATH")]
    pub private_key_file: Option<String>, // noise private key

    /// Base64 encoded noise private key (alternative to specifying a PEM encoded private-key-file)
    #[arg(long, env, short = 'K', value_name = "NOISE_KEY")]
    pub noise_private_key: Option<String>, // noise private key (base64 encoded)

    /// TUN device to use, eg "tun1" (leave blank for automatic selection -- the default)
    #[arg(long, short = 'i', value_name = "DEVICE")]
    pub tun_if: Option<String>,

    /// ZPR address (no port) of the Zode, an address of its TUN. Repeatable. The
    /// first is the Zode's own address and must be IPv6; a relay adds
    /// fd5a:5052::1 (vs.zpr) after it, and no other Zode lists it.
    #[arg(long, short = 'z')]
    pub zpr_addr: Option<Vec<IpAddr>>,

    /// Set log level using key value pairs: <target>=<LEVEL>
    /// The options for targets are:
    ///     all, capture, datapath, flow_mgmt, link_state,
    ///     mgmt_events, net_os, peer_mgmt, reporting, rpc,
    ///     startup, visa_mgmt, zdp
    /// The options for levels are:
    ///     OFF, ERROR, WARN, INFO, DEBUG, TRACE
    /// You can include as many key-value pairs as you want. If you do multiple
    /// pairs with the same key, the last last pair will be the one considered.
    /// If you include a pair with the target all, you can still set the level
    /// for individual targets
    /// --logging zdp=TRACE link_state=TRACE all=DEBUG would set all the targets
    /// to the DEBUG level, except zdp and link_state, which would be set to TRACE
    /// When setting the target 'all' you can also omit the target. i.e.
    /// --logging all=DEBUG zdp=TRACE is the same as --logging DEBUG zdp=TRACE
    #[arg(long, short = 'l', value_delimiter = ' ', num_args = 1.., value_parser = parse_key_val, verbatim_doc_comment)]
    pub logging: Vec<(String, String)>,

    /// Which packet I/O engine to use
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(std::iter::once(batch_io::AUTO_ENGINE_NAME).chain(batch_io::engine_names())), default_value_t = batch_io::AUTO_ENGINE_NAME.to_owned())]
    pub io_engine: String,

    /// Current supported implementations: noise (default), null
    #[arg(long, default_value = "noise")]
    pub km_impl: String,

    /// Security Testing: corrupt forwarded ICMP echo packets so that a
    /// correct receiver must reject them.
    #[cfg(feature = "enable-security-testing")]
    #[arg(long)]
    pub security_testing_mangle_forwarded_pings: bool,

    /// Security Testing: fall back to old-style unkeyed A2A MICVs. Zodes
    /// write and verify with the unkeyed hash; a malicious node forges with it.
    #[cfg(feature = "enable-security-testing")]
    #[arg(long)]
    pub security_testing_unkeyed_a2a_micv: bool,

    /// Security Testing: whether a mangling node recomputes the A2A MICV
    /// (true, the default) or reuses the original (false). Reusing it proves the
    /// MICV covers the payload: a mangled ping is then rejected even when unkeyed.
    #[cfg(feature = "enable-security-testing")]
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    pub security_testing_recompute_micvs: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the Zode
    #[command(verbatim_doc_comment)]
    Zode {
        /// Path to the Zode configuration file (any options specified on command line will override configuration file)
        #[arg(long, short = 'c', value_name = "PATH")]
        config_file: Option<PathBuf>,

        /// RSA private key used for authentication with the visa service.
        #[arg(long, value_name = "PATH")]
        auth_private_key: Option<PathBuf>,

        /// Whether this node carries other nodes' traffic, i.e. accepts
        /// forward-only visas. Off by default. Overrides the `forwarding`
        /// key in the `[node]` section of the config file.
        #[arg(long, value_name = "BOOL", action = clap::ArgAction::Set)]
        forwarding: Option<bool>,

        /// This Zode's initial link: the relay it dials at startup, as
        /// CN@IP:PORT (IPv6 in square brackets, e.g.
        /// relay.zpr@[2001:db8::1]:5000). CN is the relay's certificate CN.
        /// At most one. Overrides `[node.initial_link]` in the config file.
        #[arg(long, value_name = "CN@IP:PORT")]
        initial_link: Option<String>,

        /// Whether this Zode is a relay: it never dials, and accepts a link
        /// from any peer in its topology. Off by default. Overrides the
        /// `relay` key in the `[node]` section of the config file. A relay
        /// hosts the visa service: list fd5a:5052::1 in --zpr-addr after
        /// the relay's own address.
        #[arg(long, value_name = "BOOL", action = clap::ArgAction::Set)]
        relay: Option<bool>,

        #[command(flatten)]
        common: CommonArgs,
    },
}

fn parse_socket_addr_or_scoped_ip_addr(
    s: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync + 'static>> {
    // First try to parse as a full socket address (IP + optional scope + port).
    if let Ok(sa) = SocketAddr::from_str(s) {
        return Ok(sa);
    }

    // Failing that, assume we have just IP.

    if s.starts_with("[") && s.ends_with("]") {
        // IPv6

        let s = &s[1..s.len() - 1];

        let addr_str;
        let scope_id;
        match s.split_once('%') {
            Some((a, b)) => {
                addr_str = a;
                scope_id = u32::from_str(b).map_err(Box::new)?;
            }

            None => {
                addr_str = s;
                scope_id = 0;
            }
        }

        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from_str(addr_str).map_err(Box::new)?,
            0,
            0,
            scope_id,
        )))
    } else {
        // IPv4
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str(s).map_err(Box::new)?,
            0,
        )))
    }
}

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let key_val: Vec<&str> = s.split("=").collect();
    match key_val.len() {
        2 => {
            if targets::ALL_TARGETS.contains(&key_val[0])
                && levels::ALL_LEVELS.contains(&key_val[1].to_uppercase().as_str())
            {
                return Ok((key_val[0].to_string(), key_val[1].to_uppercase()));
            } else {
                return Err(format!("Invalid key-value pair"));
            }
        }
        1 => {
            if levels::ALL_LEVELS.contains(&key_val[0].to_uppercase().as_str()) {
                return Ok(("all".to_string(), key_val[0].to_uppercase()));
            } else {
                return Err(format!("Invalid key-value pair"));
            }
        }
        _ => Err(format!("Invalid key-value pair")),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_socket_addr_or_scoped_ip_addr;
    use std::net::SocketAddr;
    use std::str::FromStr;

    const SOCKET_ADDR_OR_SCOPED_IP_ADDR_PARSE_TEST_PAIRS: &[(&'static str, &'static str)] = &[
        // (test string, SocketAddr equivalent)
        ("12.34.56.78", "12.34.56.78:0"),
        ("12.34.56.78:31415", "12.34.56.78:31415"),
        ("[1234:5678::abcd]", "[1234:5678::abcd]:0"),
        ("[1234:5678::abcd]:31415", "[1234:5678::abcd]:31415"),
        ("[1234:5678::abcd%12]", "[1234:5678::abcd%12]:0"),
        ("[1234:5678::abcd%12]:31415", "[1234:5678::abcd%12]:31415"),
    ];

    #[test]
    fn socket_addr_or_scoped_ip_addr_parse_test() {
        for (test, expected) in SOCKET_ADDR_OR_SCOPED_IP_ADDR_PARSE_TEST_PAIRS {
            let exp = SocketAddr::from_str(expected);
            if exp.is_err() {
                panic!("BAD {expected}");
            }
            match parse_socket_addr_or_scoped_ip_addr(test) {
                Ok(res) => assert_eq!(res, SocketAddr::from_str(expected).unwrap()),
                Err(_) => panic!("parse failed on {test}"),
            }
        }
    }
}
