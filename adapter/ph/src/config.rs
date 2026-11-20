//! Static system configuration.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{self, Path, PathBuf};
use zpr::addrs::VISA_SERVICE_ADDR;
use zpr::packet_info::{KM_ID_NOISE, KM_ID_NULL, KmId};

use admin_api::{SocketOwner, control_socket_path};
use base64::prelude::*;
use serde::Deserialize;

use crate::batch_io;
use crate::pki::{NOISE_KEY_LEN, common_name, load_cert, load_noise_private_key};

use crate::main_args::{ArgsError, CommonArgs};

/// Upper bound on number of active links (peers) that the PH can manage.
pub const MAX_ACTIVE_LINKS: usize = 1024;

/// Size of a packet buffer.
pub const PACKET_BUFFER_SIZE: usize = 4096 * 3;

/// Size of a "small" packet buffer, suitable for most outbound management traffic.
/// 4096 (not 2048): an AcquireZprAddress blob carrying an OIDC ID token (JWT)
/// plus a self-signed blob in a JSON array runs to ~3 KB, and the mgmt path
/// has no fragmentation. The egress queues and crypto scratch buffers are
/// sized at PACKET_BUFFER_SIZE (12 KB), so a 4 KB mgmt frame stays deliverable.
pub const SMALL_PACKET_BUFFER_SIZE: usize = 4096;

/// Size of a "tiny" packet buffer, suitable for packets with no bodies (e.g. acks).
/// Note, this is not large enough for `DEFAULT_MESSAGE_HEADROOM`; use
/// with `TINY_MESSAGE_HEADROOM` instead.
pub const TINY_PACKET_BUFFER_SIZE: usize = 256;

/// Size of headroom necessary for most messages.
pub const DEFAULT_MESSAGE_HEADROOM: usize = 256;

/// Size of headroom suitable for "tiny" (bodyless) messages.
pub const TINY_MESSAGE_HEADROOM: usize = 64;

pub const DEFAULT_ZDPR_RECEIVE_WINDOW_SIZE: usize = 32;

pub const DEFAULT_ZDPR_RETRY_TIMER: std::time::Duration = std::time::Duration::from_millis(600);

/// Used for specific messages to limit the number of ZDPR retries before giving up.
/// (Not a global default!)
pub const DEFAULT_ZDPR_RETRY_LIMIT: u8 = 3;

pub const DEFAULT_TERMINATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// How long either end of a Zode link may stay in `Keying` before it closes
/// the link (zl-zipline#250). A real handshake takes one round trip.
///
/// Every per-attempt bound on a Zode link fits inside the owner's link-up
/// window (ZODE_LINKS.md rule 6, `zode_link_record::LINK_UP_WINDOW`): this
/// plus [ZODE_HELLO_TIMEOUT] is shorter, so an attempt has ended on its own
/// by the time the window does (checked at compile time there).
pub const ZODE_KEYING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How long either end of a Zode link may stay in `Helloing` before it
/// closes the link (zl-zipline#250). Covers a few ZDP-R retransmissions
/// ([DEFAULT_ZDPR_RETRY_TIMER]) of the dialer's HelloRequest. See
/// [ZODE_KEYING_TIMEOUT] for how the two fit the link-up window.
pub const ZODE_HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub const DEFAULT_VSS_PORT: u16 = 8183;

/// Visa service minimum visa ID value. Values below this are reserved.
/// More importantly, if code puts visas into the table with IDs below this, they will not be cleared
/// out during normal operation.
pub const MIN_VISA_ID: u64 = 1000;

/// If we loose the Cap'n Proto connection to the VS, or are unable to establish it in the first place,
/// wait this long before retry.
pub const VSCONN_RETRY_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// How long the adapter waits for the AuthAgent to return an OIDC
/// credential: the human has this long to complete the browser login
/// (zipline#13/D2). The node sets no timer of its own on the exchange
/// (#1410); ZDP-R and keep-alives bound it.
pub const OIDC_USER_INTERACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// How long a graceful shutdown waits for the visa service to answer the
/// Zode's `notify_disconnect(NodeShutdown)` before it tears its links down
/// anyway (zl-zipline#284). On a healthy link the RPC takes milliseconds.
/// The bound matters because the command can queue behind a stuck RPC
/// (each one bounded at 10 s inside VSConn), and Windows gives a
/// console-close handler about 5 s in total.
pub const SHUTDOWN_DEREGISTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

const DEFAULT_BUFFER_COUNT: usize = 512; // should be at least 5x batch size; see fastpath_worker.rs for explanation
const DEFAULT_BATCH_SIZE: usize = 64;
const DEFAULT_DATAPATH_QUEUE_SIZE: usize = 256;
const DEFAULT_MGMT_QUEUE_SIZE: usize = 128; // should be at least 2x batch size to avoid oscillating behavior
const DEFAULT_SERVICE_QUEUE_SIZE: usize = 128;

#[cfg(not(any(target_os = "macos", windows)))]
const DEFAULT_WORKER_CONCURRENCY: usize = 4;

/// One fastpath worker on macOS (single-queue utun) and on Windows
/// (single-queue Wintun session, and no SO_REUSEPORT to spread the
/// substrate socket across workers — zipline#131, plan C4).
#[cfg(any(target_os = "macos", windows))]
const DEFAULT_WORKER_CONCURRENCY: usize = 1;

pub const DEFAULT_KEEP_ALIVE_PERIOD: std::time::Duration = std::time::Duration::from_secs(3);
pub const DEFAULT_KEEP_ALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Consecutive keep-alive (echo) misses tolerated on an Active link before
/// the link is declared dead (zipline#113). A single dropped echo on the VS
/// adapter link used to kill the whole run: with a 3 s period and 3 s
/// timeout, 3 misses gives roughly 9-12 s of grace before teardown.
pub const KEEP_ALIVE_MAX_MISSES: u32 = 3;

/// How often, at most, the expiry sweep runs (zl-zipline#274,
/// [crate::visa_mgmt::sweep_expired_visas_if_due]). The sweep enforces
/// nothing: the fast path drops every packet of an expired visa on its own.
/// It frees expired visas and their streams, and withdraws an expired
/// stream from this Zode's own actor so its next packet binds afresh. So
/// this is also about how long such a flow can stay stalled after its
/// visa expired before it binds again. The sweep has no timer of its own
/// (operator, g184 q7): it runs on the first link keep-alive tick (every
/// [DEFAULT_KEEP_ALIVE_PERIOD]) once the interval has passed.
pub const VISA_EXPIRY_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a removed stream's ID stays out of use (zl-zipline#282), and
/// how long past its expiry a visa with a stream entering over a Zode link
/// (transit, or egress from an upstream Zode) is kept (zl-zipline#274,
/// D4).
///
/// Every removal of a stream (revocation, the expiry sweep, the match
/// eject, link loss), on every link, puts its PFT slot into quarantine
/// for this long ([crate::forwarding_tables::PeerForwardingTable::quarantine]):
/// the peer may still send on the old ID, because an adapter processes a
/// withdrawal asynchronously and an upstream Zode's clock may lag, so the
/// ID is not handed to a new stream before the grace has passed. A transit
/// visa's stream thus stays out of use for twice this long after its
/// expiry: the visa is kept for the grace (it forwards nothing from the
/// expiry on), then its slot is quarantined for the grace again.
/// ponytail: a fixed bound on clock skew between Zodes; raise it if Zode
/// clocks are not NTP-synced.
pub const STREAM_ID_REUSE_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum length of payload to include in a Bind Request.
///
/// 256 octects is more than enough to capture the longest common headers
/// (e.g. QUIC, which is over 64) without bumping up against IPv4 min-max
/// length of 576.
pub const BIND_REQUEST_MAX_PAYLOAD_LENGTH: usize = 256;

// Little trait to make creating "missing argument" errors easier.
trait ArgError {
    fn arg_missing(&self) -> ArgsError;
}

// With this you can just do `"some-field-name".arg_missing()`.
impl ArgError for str {
    fn arg_missing(&self) -> ArgsError {
        ArgsError::Missing(self.to_string())
    }
}

/// This config struct is loaded up from the command line args and used by the
/// ph system to configure itself.  Do not create this directly,
/// use [crate::main_argparse::argparse].
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to the unix domain socket for the control interface.
    pub control_path: PathBuf,

    /// Local group granted control-channel access (zipline#154): on
    /// Windows an extra ACE on the control pipe's DACL; on Linux/macOS the
    /// socket's group when no invoking user is resolved. `None` (the
    /// default) keeps each platform's owner-only access. Validated by
    /// [validate_control_group]; only a name, never interpolated into SDDL.
    pub control_group: Option<String>,

    /// Source address for our UDP substrate sockets: the address this Zode's
    /// peers dial.
    pub self_addr: SocketAddr,

    /// Path to a PEM file containing the Certificate Authority certificate.
    /// Optional and if present is used by the link management system to verify passed noise certificates.
    pub ca_file: Option<PathBuf>,

    /// Path to a PEM file containing the signed certificate listing the noise public key.
    pub certificate_file: Option<PathBuf>,

    /// Path to a PEM file containing the noise private key, if specified.
    /// For a node, one of either `private_key_file` or `private_key_data` must be specified.
    pub private_key_file: Option<PathBuf>,

    /// The noise private key data, base64 encoded. User has option to set this through an environment variable.
    /// For a node, one of either `private_key_file` or `private_key_data` must be specified.
    pub private_key_data: Option<String>,

    /// The RSA private key used by a node to authenticate with the visa service.
    /// Required for nodes.
    pub auth_private_key: Option<PathBuf>,

    /// Optionally specify the name of the TUN interface to use. In most cases this
    /// should be left as None so that the kernal can pick a free one.
    pub tun_if: Option<String>,

    /// Enable debug logging for specified targets, or ALL
    pub logging: Vec<(String, String)>,

    /// Required - the ZPR addresses (no port).
    /// On a node, `zpr_addr[0]` is the node's own address. A relay lists
    /// `vs.zpr` (fd5a:5052::1) after it, because it hosts the visa service;
    /// no other node lists `vs.zpr`, and no address appears twice
    /// (zl-zipline#229, see [Config::check_valid]).
    pub zpr_addr: Vec<IpAddr>,

    /// The batch I/O engine to use.
    pub batch_io_engine: String,

    /// Type of key manager implementation
    pub km_impl: KmId,

    /// The user the control socket should belong to, resolved from
    /// `SUDO_UID`/`SUDO_GID`/`PKEXEC_UID` by [Config::apply_socket_owner].
    /// `None` when ph was started with no recoverable invoking user (e.g.
    /// under systemd), in which case the control socket goes to the
    /// configured [Config::control_group], if any (zipline#39, zipline#154).
    pub socket_owner: Option<SocketOwner>,

    /// True while `control_path` is still the derived default — no config
    /// file or command line override. Only a derived path follows the
    /// resolved owner into its per-uid directory, and only a derived path's
    /// parent directory is auto-created; an explicit path keeps today's
    /// "parent must already exist" contract (zipline#39).
    pub(crate) control_path_derived: bool,

    /// Node only — whether this node carries other nodes' traffic, that is,
    /// accepts forward-only visas (zl-zipline#219, Zodes plan §5.7, §5.9).
    /// Off by default: with it off, a forward-only visa from the visa
    /// service is refused and logged. Configured via `forwarding` in the
    /// `[node]` config section or `ph zode --forwarding`.
    pub forwarding: bool,

    /// Node only — the Zode's initial link: the relay it dials at startup
    /// and keeps redialing, its lifeline to the network (ZODE_LINKS.md
    /// "Kinds of link", zl-zipline#250). At most one. Configured via
    /// `[node.initial_link]` or `ph zode --initial-link CN@IP:PORT`.
    pub initial_link: Option<InitialLink>,

    /// Node only — whether this Zode is a relay (ZODE_LINKS.md rule 4). A
    /// relay never dials: it accepts a link from any peer whose CN is in its
    /// topology. Off by default. Configured via `relay` in the `[node]`
    /// section or `ph zode --relay`. A relay has no initial link. A relay
    /// hosts the visa service on its own TUN, so it lists `vs.zpr` in
    /// `zpr_addr` after its own address (zl-zipline#229).
    pub relay: bool,

    /// Security testing for A2A Pubkeys
    #[cfg(feature = "enable-security-testing")]
    pub security_testing_mangle_forwarded_pings: bool,

    /// Security testing: force old-style unkeyed A2A MICVs.
    #[cfg(feature = "enable-security-testing")]
    pub security_testing_unkeyed_a2a_micv: bool,

    /// Security testing: recompute the A2A MICV after mangling (vs. reuse it).
    #[cfg(feature = "enable-security-testing")]
    pub security_testing_recompute_micvs: bool,
}

impl Config {
    /// If private noise key is specified through config or args, return it here.
    pub fn get_noise_private_key_data(&self) -> Result<Option<[u8; NOISE_KEY_LEN]>, ArgsError> {
        if let Some(ref b64data) = self.private_key_data {
            let key_data: [u8; NOISE_KEY_LEN] = match BASE64_STANDARD.decode(b64data) {
                Ok(data) => data
                    .try_into()
                    .map_err(|v| ArgsError::ParseError(format!("malformed noise key: {v:?}")))?,
                Err(e) => {
                    return Err(ArgsError::ParseError(format!(
                        "failed to decode base64 noise key: {e:?}"
                    )));
                }
            };
            return Ok(Some(key_data));
        }
        if let Some(ref pkf) = self.private_key_file {
            let pk = load_noise_private_key(&pkf).map_err(|e| {
                ArgsError::ParseError(format!("failed to load private key from file: {e:?}"))
            })?;
            return Ok(Some(pk));
        }
        Ok(None)
    }

    pub fn noise_private_key_source(&self) -> String {
        if let Some(ref b64data) = self.private_key_data {
            return format!("key://{}", b64data);
        }
        if let Some(ref pkf) = self.private_key_file {
            return format!("file://{}", pkf.display());
        }
        return "".to_string();
    }

    /// Create the [Config] struct from an optional configuration file, the
    /// optional `--auth-private-key` and the "common" command line arguments.
    ///
    /// Command line arguments win over the configuration file
    /// (zl-zipline#278): the file's sections apply first, onto the
    /// defaults, and the command line applies last, so every flag that is
    /// given overrides the file's value. A list flag (`--zpr-addr`,
    /// `--logging`) replaces the file's whole list. The `ph zode` flags
    /// for the `[node]` section are applied by the caller, after this; the
    /// caller drops a `[node]` value that such a flag replaces before it
    /// calls this (see [NodeConfig::drop_node_values_replaced_by_flags]).
    ///
    /// A file value that a given flag replaces must not be validated: an
    /// invalid or stale value in the file must not stop ph when the flag
    /// gives a valid one (zl-zipline#278 review). `control_group` is
    /// stored raw by both sources and validated once below, after the
    /// command line applies.
    pub fn new_for_node(
        config_file: Option<NodeConfig>,
        auth_private_key: Option<PathBuf>,
        common: &CommonArgs,
    ) -> Result<Self, ArgsError> {
        let mut config = Config::default();
        if let Some(config_file) = config_file {
            let base_dir = config_file.config_path.parent().unwrap();
            config.set_from_globals(&config_file.global, base_dir)?;
            config.set_from_authentication(&config_file.authentication, base_dir)?;
            config.set_from_node(&config_file.node)?;
        }
        config.set_from_common(common)?;
        // Validate only the control_group that won, so an invalid name in
        // the file that a valid --control-group overrides is no error.
        if let Some(group) = &config.control_group {
            validate_control_group(group)?;
        }
        if let Some(pkey_file) = auth_private_key {
            config.auth_private_key = Some(path::absolute(pkey_file).or_else(|e| {
                Err(ArgsError::PathError(format!(
                    "path error for auth_private_key: {:?}",
                    e
                )))
            })?);
        }
        Ok(config)
    }

    /// The CN of this Zode's link certificate, read from `certificate_file`
    /// (which [Config::check_valid] requires).
    pub fn get_noise_cn(&self) -> Result<String, ArgsError> {
        match self.certificate_file.as_ref() {
            None => Err("certificate_file".arg_missing()),
            Some(f) => get_noise_cn(&f),
        }
    }

    /// Fold the resolved socket owner into the config (zipline#39): socket
    /// paths that are still the derived default move into the owner's
    /// per-uid directory, so ph and a same-user ph-cli agree on the path.
    /// Explicitly configured paths (config file or command line) always win
    /// and are left untouched.
    pub fn apply_socket_owner(&mut self, owner: Option<SocketOwner>) {
        if let Some(ref owner) = owner {
            // Same owner-id spelling as admin_api::current_user_id, which
            // is what a same-user ph-cli derives its path from.
            let owner_id = owner.uid.to_string();
            if self.control_path_derived {
                self.control_path = control_socket_path(Some(&owner_id));
            }
        }
        self.socket_owner = owner;
    }

    /// Create the per-owner socket directory (mode 0700, chowned to the
    /// owner) for each still-derived socket path, so `check_valid`'s
    /// parent-directory check passes without pre-provisioning (zipline#39).
    /// Explicit paths keep today's contract: their parent must already exist.
    /// Unix only: on Windows the control channel is a named pipe, with no
    /// directory to create (plan D6).
    #[cfg(unix)]
    pub fn prepare_socket_dirs(&self) -> Result<(), ArgsError> {
        use std::os::unix::fs::PermissionsExt;
        for (path, derived) in [(&self.control_path, self.control_path_derived)] {
            // Explicit paths keep the parent-must-exist contract; only the
            // derived per-owner directory is created here. socket_owner
            // presence gates it too: without an owner the derived path is
            // the shared data home, which stays a packaging concern.
            if !derived {
                continue;
            }
            let Some(ref owner) = self.socket_owner else {
                continue;
            };
            let Some(parent) = path.parent() else {
                continue;
            };
            if fs::exists(parent).unwrap_or(false) {
                continue;
            }
            fs::create_dir_all(parent).map_err(|e| {
                ArgsError::PathError(format!(
                    "failed to create socket directory {parent:?}: {e:?}"
                ))
            })?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                ArgsError::PathError(format!(
                    "failed to set mode 0700 on socket directory {parent:?}: {e:?}"
                ))
            })?;
            nix::unistd::chown(
                parent,
                Some(nix::unistd::Uid::from_raw(owner.uid)),
                owner.gid.map(nix::unistd::Gid::from_raw),
            )
            .map_err(|e| {
                ArgsError::PathError(format!(
                    "failed to chown socket directory {parent:?} to uid {}: {e:?}",
                    owner.uid
                ))
            })?;
        }
        Ok(())
    }

    /// Node mode: check `zpr_addr` against the relay rules (zl-zipline#229,
    /// gate g117 q2). A relay hosts the visa service on its own TUN, so it
    /// lists `vs.zpr` ([VISA_SERVICE_ADDR]) after its own address:
    /// `zpr_addr[0]` is the node's own address everywhere (the VS-API
    /// session and its source, the VSS listener, link ownership), so
    /// `vs.zpr` may never be first. No address may be listed twice, and a
    /// node that is not a relay never lists `vs.zpr`. `zpr_addr[0]` is
    /// IPv6, since the VS-API session to `vs.zpr` leaves from it. Each
    /// refusal names the fix. There is no implicit `vs.zpr`: the TUN's addresses are all
    /// in the configuration.
    fn check_node_zpr_addrs(&self) -> Result<(), ArgsError> {
        for (i, addr) in self.zpr_addr.iter().enumerate() {
            if self.zpr_addr[..i].contains(addr) {
                return Err(ArgsError::ParseError(format!(
                    "zpr_addr lists {addr} more than once; list each address once"
                )));
            }
        }
        // The node's own address is the source of its VS-API session to
        // vs.zpr (VSConn binds it, zl-zipline#229). vs.zpr is IPv6, so an
        // IPv4 own address could never connect: refuse it here rather than
        // have the session retry forever.
        if let Some(own) = self.zpr_addr.first() {
            if !own.is_ipv6() {
                return Err(ArgsError::ParseError(format!(
                    "zpr_addr[0] ({own}) is the node's own address and must be an IPv6 \
                     address: the VS-API session to {VISA_SERVICE_ADDR} leaves from it"
                )));
            }
        }
        let vs_listed = self.zpr_addr.contains(&VISA_SERVICE_ADDR);
        if self.relay {
            if self.zpr_addr[0] == VISA_SERVICE_ADDR {
                return Err(ArgsError::ParseError(format!(
                    "a relay hosts the visa service: list {VISA_SERVICE_ADDR} in zpr_addr \
                     after the relay's own address, not first"
                )));
            }
            if !vs_listed {
                return Err(ArgsError::ParseError(format!(
                    "a relay hosts the visa service: add {VISA_SERVICE_ADDR} to zpr_addr \
                     after the relay's own address"
                )));
            }
        } else if vs_listed {
            return Err(ArgsError::ParseError(format!(
                "only a relay hosts the visa service: remove {VISA_SERVICE_ADDR} from \
                 zpr_addr, or set relay"
            )));
        }
        Ok(())
    }

    /// Check that the required bits of a Zode configuration are present, and
    /// that the files it names exist.
    pub fn check_valid(&self) -> Result<(), ArgsError> {
        if self.control_path.as_os_str().is_empty() {
            return Err("control_path".arg_missing());
        }
        // For control path, the parent dir must exist or there will be an error later.
        if let Some(parent) = self.control_path.parent() {
            match check_file_exists("control socket parent directory", parent) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        if let Some(ca_file) = &self.ca_file {
            check_file_exists("certificate authority file", ca_file)?;
        }
        if let Some(ref cf) = self.certificate_file {
            check_file_exists("certificate file", cf)?;
        }
        if let Some(ref pkf) = self.private_key_file {
            if pkf.to_str().unwrap().is_empty() {
                return Err("private_key_file".arg_missing());
            }
            check_file_exists("private key file", &pkf)?;
        } else if let Some(ref pkd) = self.private_key_data {
            if pkd.is_empty() {
                return Err("private_key_data".arg_missing());
            }
        }
        // A Zode is a relay, which never dials (ZODE_LINKS.md rule 4), or
        // dials its relay over its initial link: never both, and never
        // neither, since a Zode with neither could reach no visa service
        // (zl-zipline#234).
        match (self.relay, self.initial_link.is_some()) {
            (true, true) => {
                return Err(ArgsError::ParseError(
                    "a relay has no initial link: set relay or initial_link, not both".to_string(),
                ));
            }
            (false, false) => {
                return Err(ArgsError::ParseError(
                    "a Zode needs relay or initial_link: set relay = true, or the relay \
                     to dial with initial_link"
                        .to_string(),
                ));
            }
            _ => {}
        }
        // The initial link is dialed from the substrate sockets, which are
        // bound to self_addr: an address of the other family could never be
        // dialed.
        if let Some(link) = &self.initial_link {
            if link.addr.is_ipv4() != self.self_addr.is_ipv4() {
                return Err(ArgsError::ParseError(format!(
                    "initial_link addr {} and self_addr {} are of different address \
                     families; set self_addr to an address of the relay's family",
                    link.addr, self.self_addr
                )));
            }
        }
        if self.zpr_addr.is_empty() {
            return Err("zpr_addr".arg_missing());
        }
        self.check_node_zpr_addrs()?;
        if self.certificate_file.is_none() {
            return Err("certificate_file".arg_missing());
        }
        if self.private_key_file.is_none() && self.private_key_data.is_none() {
            return Err("private_key_file or noise_private_key".arg_missing());
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the global
    // section. This runs before set_from_common, so a command line flag
    // overrides each value set here (zl-zipline#278).
    fn set_from_globals(
        &mut self,
        config: &GlobalConfigSection,
        base_dir: &Path,
    ) -> Result<(), ArgsError> {
        if let Some(control_path) = &config.control_path {
            if control_path.is_relative() {
                self.control_path = base_dir.join(control_path);
            } else {
                self.control_path = control_path.clone();
            }
            self.control_path_derived = false;
        }
        if let Some(group) = &config.control_group {
            // Validated in new_for_node once the command line has had its
            // say: an invalid name that a flag overrides is no error.
            self.control_group = Some(group.clone());
        }
        if let Some(self_addr) = &config.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &config.ca_file {
            if ca_file.is_relative() {
                self.ca_file = Some(base_dir.join(ca_file));
            } else {
                self.ca_file = Some(ca_file.clone());
            }
        }
        if let Some(certificate_file) = &config.certificate_file {
            if certificate_file.is_relative() {
                self.certificate_file = Some(base_dir.join(certificate_file));
            } else {
                self.certificate_file = Some(certificate_file.clone());
            }
        }
        if let Some(private_key_file) = &config.private_key_file {
            if private_key_file.is_relative() {
                self.private_key_file = Some(base_dir.join(private_key_file));
            } else {
                self.private_key_file = Some(private_key_file.clone());
            }
        }
        if let Some(tun_if) = &config.tun_if {
            self.tun_if = Some(tun_if.clone());
        }
        if let Some(actor_addr) = &config.zpr_addr {
            self.zpr_addr = actor_addr.clone();
        }
        if let Some(logging) = &config.logging {
            self.logging = logging.clone();
        }
        if let Some(io_engine) = &config.io_engine {
            self.batch_io_engine = io_engine.clone();
        }
        Ok(())
    }

    fn set_from_authentication(
        &mut self,
        config: &Option<AuthenticationConfigSection>,
        base_dir: &Path,
    ) -> Result<(), ArgsError> {
        if let Some(config) = config {
            if let Some(auth_private_key) = &config.auth_private_key {
                let keyfile = if auth_private_key.is_relative() {
                    base_dir.join(auth_private_key)
                } else {
                    auth_private_key.clone()
                };
                self.auth_private_key = Some(keyfile);
            }
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the node section
    // of TOML config.
    fn set_from_node(&mut self, config: &Option<NodeConfigSection>) -> Result<(), ArgsError> {
        if let Some(config) = config {
            if let Some(forwarding) = config.forwarding {
                self.forwarding = forwarding;
            }
            if let Some(link) = &config.initial_link {
                self.initial_link = Some(InitialLink::new(&link.cn, &link.addr)?);
            }
            if let Some(relay) = config.relay {
                self.relay = relay;
            }
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the CommonArgs
    // (from command line). This runs after the config file sections, so
    // every flag that is given wins (zl-zipline#278); a flag that is not
    // given leaves the file's value, or the default, in place. A list flag
    // (`--zpr-addr`, `--logging`) replaces the whole list.
    fn set_from_common(&mut self, common: &CommonArgs) -> Result<(), ArgsError> {
        if let Some(control_path) = &common.control_path {
            let cp = PathBuf::from(control_path);
            self.control_path = path::absolute(cp).or_else(|e| {
                Err(ArgsError::PathError(format!(
                    "path error for control_path: {:?}",
                    e
                )))
            })?;
            self.control_path_derived = false;
        }
        if let Some(group) = &common.control_group {
            // Validated in new_for_node, with the file's value.
            self.control_group = Some(group.clone());
        }
        if let Some(self_addr) = &common.self_addr {
            self.self_addr = *self_addr;
        }
        if let Some(ca_file) = &common.ca_file {
            let cf = PathBuf::from(ca_file);
            self.ca_file = Some(path::absolute(cf).or_else(|e| {
                Err(ArgsError::PathError(format!(
                    "path error for ca_file: {:?}",
                    e
                )))
            })?);
        }
        if let Some(certificate_file) = &common.certificate_file {
            let cf = PathBuf::from(certificate_file);
            self.certificate_file = Some(path::absolute(cf).or_else(|e| {
                Err(ArgsError::PathError(format!(
                    "path error for certificate_file: {:?}",
                    e
                )))
            })?);
        }
        if common.private_key_file.is_some() && common.noise_private_key.is_some() {
            return Err(ArgsError::ParseError(
                "private_key_file and noise_private_key cannot be used together".to_string(),
            ));
        }
        if let Some(private_key_data) = &common.noise_private_key {
            self.private_key_file = None;
            self.private_key_data = Some(private_key_data.clone());
        }
        if let Some(private_key_file) = &common.private_key_file {
            self.private_key_data = None;
            let pkf = PathBuf::from(private_key_file);
            self.private_key_file = Some(path::absolute(pkf).or_else(|e| {
                Err(ArgsError::PathError(format!(
                    "path error for private_key_file: {:?}",
                    e
                )))
            })?);
        }
        if let Some(tun_if) = &common.tun_if {
            self.tun_if = Some(tun_if.clone());
        }
        if let Some(addrs) = &common.zpr_addr {
            self.zpr_addr = addrs.clone();
        }
        // clap gives an empty list when `--logging` is absent: an empty
        // `--logging` is refused by `num_args = 1..`.
        if !common.logging.is_empty() {
            self.logging = common.logging.clone();
        }
        if let Some(io_engine) = &common.io_engine {
            self.batch_io_engine = io_engine.clone();
        }

        self.km_impl = match common.km_impl.as_str() {
            "noise" => KM_ID_NOISE,
            "null" => KM_ID_NULL,
            oth => {
                return Err(ArgsError::ParseError(format!(
                    "Unknown key management implementation: {oth}"
                )));
            }
        };

        #[cfg(feature = "enable-security-testing")]
        {
            self.security_testing_mangle_forwarded_pings =
                common.security_testing_mangle_forwarded_pings;
            self.security_testing_unkeyed_a2a_micv = common.security_testing_unkeyed_a2a_micv;
            self.security_testing_recompute_micvs = common.security_testing_recompute_micvs;
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_path: control_socket_path(None),
            control_group: None,
            self_addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0),
            ca_file: None,
            certificate_file: None,
            private_key_file: None,
            private_key_data: None,
            auth_private_key: None,
            tun_if: None,
            logging: Vec::new(),
            zpr_addr: Vec::new(),
            batch_io_engine: batch_io::AUTO_ENGINE_NAME.to_owned(),
            km_impl: KM_ID_NOISE,
            socket_owner: None,
            control_path_derived: true,
            forwarding: false,
            initial_link: None,
            relay: false,
            #[cfg(feature = "enable-security-testing")]
            security_testing_mangle_forwarded_pings: false,
            #[cfg(feature = "enable-security-testing")]
            security_testing_unkeyed_a2a_micv: false,
            #[cfg(feature = "enable-security-testing")]
            security_testing_recompute_micvs: true,
        }
    }
}

// This describes the Zode configuration file TOML format. Unknown sections,
// `[adapter]` among them, are refused rather than ignored (zl-zipline#234).
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(skip)]
    pub config_path: PathBuf,

    pub global: GlobalConfigSection,
    pub node: Option<NodeConfigSection>,
    pub authentication: Option<AuthenticationConfigSection>,
}

impl NodeConfig {
    /// Drop each `[node]` value that a given `ph zode` flag replaces
    /// (zl-zipline#278 review). [Config::new_for_node] validates the
    /// `[node]` values when it applies them, before the caller applies
    /// these flags. Without this, an invalid `[node.initial_link]` in the
    /// file stops ph although `--initial-link` gives a valid value. With
    /// no flag, the file value stays, and is validated as before.
    pub fn drop_node_values_replaced_by_flags(&mut self, initial_link: bool) {
        if let Some(node) = self.node.as_mut() {
            if initial_link {
                node.initial_link = None;
            }
        }
    }
}

// The `[node]` section of a Zode config file.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NodeConfigSection {
    /// Whether this node accepts forward-only visas, i.e. carries other
    /// nodes' traffic (zl-zipline#219). Default false. A relay sets it.
    pub forwarding: Option<bool>,

    /// The Zode's initial link, `[node.initial_link]` (zl-zipline#250).
    /// TOML refuses a second table of the same name, so there is at most one.
    pub initial_link: Option<InitialLinkSection>,

    /// Whether this Zode is a relay (ZODE_LINKS.md rule 4). Default false.
    /// A relay lists `vs.zpr` in `zpr_addr` after its own address
    /// (zl-zipline#229).
    pub relay: Option<bool>,
}

/// The `[node.initial_link]` table as written in the config file. Both keys
/// are required; [InitialLink::new] validates them.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct InitialLinkSection {
    /// The relay's substrate address, a literal `"IP:port"`.
    pub addr: String,
    /// The CN the relay's link certificate must carry.
    pub cn: String,
}

/// A Zode's initial link (ZODE_LINKS.md "Kinds of link"): the relay it dials
/// at startup. This Zode always owns it, and it is the only link a Zode
/// retries on its own (rule 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialLink {
    /// The relay's substrate address, which this Zode dials.
    pub addr: SocketAddr,
    /// The CN the relay's CA-signed link certificate must carry. The link is
    /// closed after keying if the peer presents any other.
    pub cn: String,
}

impl InitialLink {
    /// Validate an initial link from its CN and its `"IP:port"` address.
    /// An empty CN, a hostname, an unspecified IP and port 0 are errors:
    /// there is no fallback (ZODE_LINKS.md non-goals).
    pub fn new(cn: &str, addr: &str) -> Result<Self, ArgsError> {
        if cn.is_empty() {
            return Err(ArgsError::ParseError(
                "initial_link cn is empty; it must name the relay's certificate CN".to_string(),
            ));
        }
        Ok(InitialLink {
            addr: resolve_dialable_addr("initial_link addr", addr)?,
            cn: cn.to_owned(),
        })
    }

    /// Parse the command line form `CN@IP:PORT` (IPv6 in square brackets,
    /// e.g. `relay.zpr@[2001:db8::1]:5000`). The address follows the last
    /// `@`, since an IP address never contains one.
    pub fn parse_cli(spec: &str) -> Result<Self, ArgsError> {
        let Some((cn, addr)) = spec.rsplit_once('@') else {
            return Err(ArgsError::ParseError(format!(
                "--initial-link {spec:?} is not CN@IP:PORT"
            )));
        };
        InitialLink::new(cn, addr)
    }
}

// The `[global]` section of a Zode config file.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfigSection {
    pub control_path: Option<PathBuf>,
    pub control_group: Option<String>,
    pub self_addr: Option<SocketAddr>,
    pub ca_file: Option<PathBuf>,
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
    pub tun_if: Option<String>,
    pub zpr_addr: Option<Vec<IpAddr>>,
    pub logging: Option<Vec<(String, String)>>,
    pub io_engine: Option<String>,
}

// The `[authentication]` section of a Zode config file.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationConfigSection {
    auth_private_key: Option<PathBuf>,
}

/// Configuration of data path & control plane topology.
pub struct TopologyConfig {
    /// Number of packet buffers to allocate per fastpath worker.
    pub buffer_count: usize,

    pub fastpath_concurrency: usize,

    pub fastpath_batch_size: usize,
    pub capture_batch_size: usize,

    pub capture_queue_size: usize,
    pub mgmt_datapath_queue_size: usize,
    pub mgmt_dispatch_queue_size: usize,
    pub adapter_manager_queue_size: usize,
    pub km_signal_queue_size: usize,
    pub km_message_queue_size: usize,
    pub km_link_queue_size: usize,

    pub vs_queue_size: usize,
    pub vss_queue_size: usize,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            buffer_count: DEFAULT_BUFFER_COUNT,

            fastpath_concurrency: DEFAULT_WORKER_CONCURRENCY,

            fastpath_batch_size: DEFAULT_BATCH_SIZE,
            capture_batch_size: DEFAULT_BATCH_SIZE,

            capture_queue_size: DEFAULT_DATAPATH_QUEUE_SIZE,
            mgmt_datapath_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            mgmt_dispatch_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            adapter_manager_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            km_signal_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            km_message_queue_size: DEFAULT_MGMT_QUEUE_SIZE,
            km_link_queue_size: DEFAULT_MGMT_QUEUE_SIZE,

            vs_queue_size: DEFAULT_SERVICE_QUEUE_SIZE,
            vss_queue_size: DEFAULT_SERVICE_QUEUE_SIZE,
        }
    }
}

/// Characters a `control_group` name must not contain (zipline#154): the
/// Windows local-group-name restriction set, which is also safe for unix
/// group names. Control characters are rejected separately.
const CONTROL_GROUP_FORBIDDEN: &[char] = &[
    '\\', '/', '"', '[', ']', ':', '|', '<', '>', '+', '=', ';', ',', '?', '*', '@',
];

/// Validate a `control_group` name from the config file or command line
/// (zipline#154). The value is only ever a name handed to the platform's
/// group lookup — the SID that goes into the pipe's SDDL is produced by the
/// OS from that lookup, never from this text — but rejecting the Windows
/// restricted set keeps the name unambiguous on every platform (and keeps a
/// `DOMAIN\name` spelling from reaching a lookup that must stay local).
pub fn validate_control_group(name: &str) -> Result<String, ArgsError> {
    if name.is_empty() {
        return Err(ArgsError::ParseError(
            "control_group must not be empty".to_string(),
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| c.is_control() || CONTROL_GROUP_FORBIDDEN.contains(c))
    {
        return Err(ArgsError::ParseError(format!(
            "control_group {name:?} contains the invalid character {bad:?} \
             (not allowed: control characters and \\ / \" [ ] : | < > + = ; , ? * @)"
        )));
    }
    Ok(name.to_string())
}

fn check_file_exists(desc: &str, path: &Path) -> Result<(), ArgsError> {
    match fs::exists(path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ArgsError::PathError(format!(
            "{} not found: {:?}",
            desc, path
        ))),
        Err(e) => Err(ArgsError::PathError(format!(
            "{} path error: {:?}",
            desc, e
        ))),
    }
}

/// Parse a substrate address that someone dials: a literal `IP:port`, IPv6 in
/// square-bracket notation, e.g. `"[2001:db8::1]:5000"`. Unspecified IPs (e.g.
/// `0.0.0.0`) and port 0 are rejected because nobody can dial them. `key`
/// names the setting in error messages.
fn resolve_dialable_addr(key: &str, addr_str: &str) -> Result<SocketAddr, ArgsError> {
    let resolved: SocketAddr = addr_str.parse().map_err(|e| {
        ArgsError::ParseError(format!(
            "{key} {addr_str:?} is not a literal IP:port \
             (IPv6 in square brackets, e.g. \"[2001:db8::1]:5000\"): {e}"
        ))
    })?;
    if resolved.ip().is_unspecified() {
        return Err(ArgsError::ParseError(format!(
            "{key} {addr_str:?} is an unspecified address; it cannot be dialed"
        )));
    }
    if resolved.port() == 0 {
        return Err(ArgsError::ParseError(format!(
            "{key} {addr_str:?} has port 0; it cannot be dialed"
        )));
    }
    Ok(resolved)
}

/// Parse the `certificate_file` (a noise certificate) and return the CN value found within.
///
/// TODO: This has nothing to do with noise.  And nothing to do with km_cert_exchange.  Move to a pki util file.
pub fn get_noise_cn(certificate_file: &Path) -> Result<String, ArgsError> {
    let cert = load_cert(certificate_file)
        .map_err(|e| ArgsError::ParseError(format!("failed to load noise certificate: {e:?}")))?;
    common_name(&cert).ok_or(ArgsError::ParseError(
        "failed to get CN from certificate".to_string(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    /// zl-zipline#264: a Zode never reports its own substrate address, so
    /// `advertised_substrate_addr` is gone. A config that still sets it is
    /// refused as unknown, not ignored.
    #[test]
    fn test_node_config_refuses_advertised_substrate_addr() {
        let err = config_from_node_section("advertised_substrate_addr = \"203.0.113.7:6000\"")
            .unwrap_err();
        assert!(
            err.to_string().contains("advertised_substrate_addr"),
            "the error names the refused key: {err}"
        );
    }

    /// `auth_renewal_lead_seconds` configured the renewal of docked
    /// adapters, which are gone (zl-zipline#234): the key is refused as
    /// unknown, not ignored.
    #[test]
    fn test_node_config_refuses_auth_renewal_lead_seconds() {
        let err = config_from_node_section("auth_renewal_lead_seconds = 60").unwrap_err();
        assert!(
            err.to_string().contains("auth_renewal_lead_seconds"),
            "the error names the refused key: {err}"
        );
    }

    /// `forwarding` in the `[node]` section turns on forward-only visas;
    /// absent, forwarding stays off (zl-zipline#219).
    #[test]
    fn test_node_config_forwarding() {
        assert!(!Config::default().forwarding);

        let parse = |node_section: &str| {
            let toml_str =
                format!("[global]\nself_addr = \"10.0.0.1:5000\"\n\n[node]\n{node_section}\n");
            let file_config: NodeConfig = toml::from_str(&toml_str).unwrap();
            let mut config = Config::default();
            config.set_from_node(&file_config.node).unwrap();
            config.forwarding
        };
        assert!(parse("forwarding = true"));
        assert!(!parse("forwarding = false"));
    }

    /// Apply a `[node]` section body (after `[node]`, so it may open
    /// sub-tables) to a default config, as the config file loader does.
    fn config_from_node_section(node_section: &str) -> Result<Config, ArgsError> {
        let toml_str =
            format!("[global]\nself_addr = \"10.0.0.1:5000\"\n\n[node]\n{node_section}\n");
        let file_config: NodeConfig =
            toml::from_str(&toml_str).map_err(|e| ArgsError::ParseError(format!("toml: {e}")))?;
        let mut config = Config::default();
        config.set_from_node(&file_config.node)?;
        Ok(config)
    }

    /// `[node.initial_link]` names the relay this Zode dials and the CN its
    /// certificate must carry (ZODE_LINKS.md "Kinds of link", zl-zipline#250).
    #[test]
    fn test_node_config_initial_link() {
        assert_eq!(Config::default().initial_link, None);
        let config = config_from_node_section(
            "[node.initial_link]\naddr = \"10.0.0.9:5000\"\ncn = \"relay.zpr\"",
        )
        .unwrap();
        assert_eq!(
            config.initial_link,
            Some(InitialLink {
                addr: "10.0.0.9:5000".parse().unwrap(),
                cn: "relay.zpr".to_owned(),
            })
        );
        let config = config_from_node_section(
            "[node.initial_link]\naddr = \"[fd00::9]:5000\"\ncn = \"relay.zpr\"",
        )
        .unwrap();
        assert_eq!(
            config.initial_link.unwrap().addr,
            "[fd00::9]:5000".parse::<SocketAddr>().unwrap()
        );
    }

    /// An initial link is rejected, with no fallback, when its CN is empty,
    /// its IP is unspecified or its port is 0. Both keys are required.
    #[test]
    fn test_node_config_initial_link_rejects_bad_values() {
        for section in [
            "[node.initial_link]\naddr = \"10.0.0.9:5000\"\ncn = \"\"",
            "[node.initial_link]\naddr = \"0.0.0.0:5000\"\ncn = \"relay.zpr\"",
            "[node.initial_link]\naddr = \"[::]:5000\"\ncn = \"relay.zpr\"",
            "[node.initial_link]\naddr = \"10.0.0.9:0\"\ncn = \"relay.zpr\"",
            "[node.initial_link]\naddr = \"relay.example:5000\"\ncn = \"relay.zpr\"",
            "[node.initial_link]\ncn = \"relay.zpr\"",
            "[node.initial_link]\naddr = \"10.0.0.9:5000\"",
        ] {
            assert!(
                config_from_node_section(section).is_err(),
                "accepted a bad initial link: {section}"
            );
        }
    }

    /// A Zode has at most one initial link: a second `[node.initial_link]`
    /// table does not parse.
    #[test]
    fn test_node_config_second_initial_link_is_rejected() {
        let twice = "[node.initial_link]\naddr = \"10.0.0.9:5000\"\ncn = \"a.zpr\"\n\
                     [node.initial_link]\naddr = \"10.0.0.8:5000\"\ncn = \"b.zpr\"";
        assert!(config_from_node_section(twice).is_err());
    }

    /// `relay` in the `[node]` section marks this Zode as a relay (R4);
    /// absent, it is false.
    #[test]
    fn test_node_config_relay() {
        assert!(!Config::default().relay);
        assert!(config_from_node_section("relay = true").unwrap().relay);
        assert!(!config_from_node_section("relay = false").unwrap().relay);
        assert!(!config_from_node_section("forwarding = true").unwrap().relay);
    }

    /// `InitialLink::parse_cli` reads `CN@IP:PORT`, IPv6 in brackets, and
    /// applies the same checks as the config file.
    #[test]
    fn test_initial_link_parse_cli() {
        assert_eq!(
            InitialLink::parse_cli("relay.zpr@10.0.0.9:5000").unwrap(),
            InitialLink {
                addr: "10.0.0.9:5000".parse().unwrap(),
                cn: "relay.zpr".to_owned(),
            }
        );
        assert_eq!(
            InitialLink::parse_cli("relay.zpr@[fd00::9]:5000")
                .unwrap()
                .addr,
            "[fd00::9]:5000".parse::<SocketAddr>().unwrap()
        );
        for bad in [
            "@10.0.0.9:5000",
            "relay.zpr@0.0.0.0:5000",
            "relay.zpr@10.0.0.9:0",
            "relay.zpr10.0.0.9:5000",
            "relay.zpr@",
        ] {
            assert!(InitialLink::parse_cli(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// An initial link must use the address family of the substrate
    /// address it is dialed from; anything else could never be dialed.
    #[test]
    fn test_check_valid_initial_link_family() {
        let node = |self_addr: &str, link: &str| Config {
            zpr_addr: vec!["fd5a:5052::2".parse().unwrap()],
            certificate_file: Some(std::env::temp_dir()),
            private_key_data: Some("key".to_owned()),
            control_path: std::env::temp_dir().join("ctl.sock"),
            self_addr: self_addr.parse().unwrap(),
            initial_link: Some(InitialLink::parse_cli(link).unwrap()),
            ..Config::default()
        };
        let ok = |s, l| node(s, l).check_valid().is_ok();
        assert!(ok("0.0.0.0:0", "r@10.0.0.9:5000"));
        assert!(ok("10.0.0.1:5000", "r@10.0.0.9:5000"));
        assert!(ok("[::]:5000", "r@[fd00::9]:5000"));
        assert!(!ok("0.0.0.0:0", "r@[fd00::9]:5000"));
        assert!(!ok("[::]:5000", "r@10.0.0.9:5000"));
        assert!(!ok("[fd00::1]:5000", "r@10.0.0.9:5000"));
    }

    /// A Zode is a relay or has an initial link, exactly one of them: a relay
    /// never dials (R4), and a Zode with neither reaches no visa service.
    #[test]
    fn test_check_valid_initial_link_and_relay() {
        let link = InitialLink::parse_cli("relay.zpr@10.0.0.9:5000").unwrap();
        let node = || Config {
            zpr_addr: vec!["fd5a:5052::2".parse().unwrap()],
            certificate_file: Some(std::env::temp_dir()),
            private_key_data: Some("key".to_owned()),
            control_path: std::env::temp_dir().join("ctl.sock"),
            ..Config::default()
        };

        let mut config = node();
        config.initial_link = Some(link.clone());
        assert!(config.check_valid().is_ok());

        // A relay lists vs.zpr after its own address (zl-zipline#229), so
        // only the initial link makes this one invalid.
        config.relay = true;
        config.zpr_addr.push(VISA_SERVICE_ADDR);
        assert!(config.check_valid().is_err());

        let mut config = node();
        config.relay = true;
        config.zpr_addr.push(VISA_SERVICE_ADDR);
        assert!(config.check_valid().is_ok());

        // Neither: a Zode that is no relay and dials nothing could reach no
        // visa service (zl-zipline#234).
        let msg = match node().check_valid() {
            Err(ArgsError::ParseError(msg)) => msg,
            other => panic!("expected a ParseError, got {other:?}"),
        };
        assert!(msg.contains("needs relay or initial_link"), "{msg}");
    }

    /// zl-zipline#229 (gate g117 q2): a relay hosts the visa service, so it
    /// lists `vs.zpr` in `zpr_addr` after its own address. A relay without
    /// it, with it first, or with a duplicate address is refused, and so is
    /// a node that is not a relay but lists it.
    #[test]
    fn test_check_valid_relay_hosts_visa_service() {
        let own: IpAddr = "fd5a:5052::2".parse().unwrap();
        let check = |relay: bool, zpr_addr: Vec<IpAddr>| {
            Config {
                zpr_addr,
                relay,
                // A Zode that is not a relay dials one.
                initial_link: (!relay).then(|| InitialLink::parse_cli("r@10.0.0.9:5000").unwrap()),
                certificate_file: Some(std::env::temp_dir()),
                private_key_data: Some("key".to_owned()),
                control_path: std::env::temp_dir().join("ctl.sock"),
                ..Config::default()
            }
            .check_valid()
        };
        let refusal = |relay: bool, zpr_addr: Vec<IpAddr>| match check(relay, zpr_addr) {
            Err(ArgsError::ParseError(msg)) => msg,
            other => panic!("expected a ParseError, got {other:?}"),
        };

        // The relay: its own address first, then vs.zpr.
        assert!(check(true, vec![own, VISA_SERVICE_ADDR]).is_ok());
        let msg = refusal(true, vec![own]);
        assert!(msg.contains("add fd5a:5052::1 to zpr_addr"), "{msg}");
        let msg = refusal(true, vec![VISA_SERVICE_ADDR, own]);
        assert!(msg.contains("after the relay's own address"), "{msg}");
        let msg = refusal(true, vec![VISA_SERVICE_ADDR]);
        assert!(msg.contains("after the relay's own address"), "{msg}");

        // Duplicates, on a relay and on any other node.
        let msg = refusal(true, vec![own, VISA_SERVICE_ADDR, own]);
        assert!(msg.contains("more than once"), "{msg}");
        let msg = refusal(true, vec![own, VISA_SERVICE_ADDR, VISA_SERVICE_ADDR]);
        assert!(msg.contains("more than once"), "{msg}");
        let msg = refusal(false, vec![own, own]);
        assert!(msg.contains("more than once"), "{msg}");

        // A node that is not a relay never lists vs.zpr.
        assert!(check(false, vec![own]).is_ok());
        let msg = refusal(false, vec![own, VISA_SERVICE_ADDR]);
        assert!(msg.contains("only a relay"), "{msg}");
        let msg = refusal(false, vec![VISA_SERVICE_ADDR]);
        assert!(msg.contains("only a relay"), "{msg}");

        // The node's own address is IPv6: its VS-API session to vs.zpr
        // leaves from it (VSConn binds it), and vs.zpr is IPv6, so an IPv4
        // own address could never connect. A later IPv4 entry is not the
        // session's source and stays allowed.
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let msg = refusal(false, vec![v4]);
        assert!(msg.contains("must be an IPv6 address"), "{msg}");
        let msg = refusal(true, vec![v4, VISA_SERVICE_ADDR]);
        assert!(msg.contains("must be an IPv6 address"), "{msg}");
        assert!(check(false, vec![own, v4]).is_ok());
    }

    /// A substrate address someone dials (the initial link's) must be a
    /// literal, concrete IP:port.
    #[test]
    fn test_resolve_dialable_addr() {
        let resolve_dialable = |addr: &str| resolve_dialable_addr("addr", addr);
        // Plain IP:port passes through.
        assert_eq!(
            resolve_dialable("203.0.113.7:5000").unwrap(),
            "203.0.113.7:5000".parse::<SocketAddr>().unwrap()
        );
        // V6 in square-bracket notation passes through.
        assert_eq!(
            resolve_dialable("[2001:db8::7]:5000").unwrap(),
            "[2001:db8::7]:5000".parse::<SocketAddr>().unwrap()
        );
        // V6 with a scope-free full form.
        assert_eq!(
            resolve_dialable("[2001:db8:0:0:0:0:0:9]:6000").unwrap(),
            "[2001:db8::9]:6000".parse::<SocketAddr>().unwrap()
        );
        // V6 without brackets rejected.
        assert!(resolve_dialable("2001:db8::7:5000").is_err());
        // Hostnames rejected: the claim is always for a specific IP address.
        assert!(resolve_dialable("localhost:5000").is_err());
        assert!(resolve_dialable("node1.example.com:5000").is_err());
        // Unspecified IP rejected.
        assert!(resolve_dialable("0.0.0.0:5000").is_err());
        assert!(resolve_dialable("[::]:5000").is_err());
        // Port 0 rejected (V4 and V6).
        assert!(resolve_dialable("203.0.113.7:0").is_err());
        assert!(resolve_dialable("[2001:db8::7]:0").is_err());
        // Garbage rejected.
        assert!(resolve_dialable("not an address").is_err());
        assert!(resolve_dialable("203.0.113.7").is_err());
    }

    /// With a resolved owner and a derived (default) socket path, the
    /// control path moves into the owner's per-uid directory and matches
    /// what admin-api derives — the ph / ph-cli agreement this issue exists
    /// for (zipline#39).
    #[test]
    fn test_apply_socket_owner_moves_derived_paths() {
        let mut config = Config::default();
        config.apply_socket_owner(Some(SocketOwner {
            uid: 1234,
            gid: Some(1234),
        }));
        assert_eq!(config.control_path, control_socket_path(Some("1234")));
        assert_eq!(
            config.socket_owner,
            Some(SocketOwner {
                uid: 1234,
                gid: Some(1234)
            })
        );
    }

    /// No owner: the derived path stays at today's shared location.
    #[test]
    fn test_apply_socket_owner_none_keeps_shared_paths() {
        let mut config = Config::default();
        config.apply_socket_owner(None);
        assert_eq!(config.control_path, control_socket_path(None));
        assert_eq!(config.socket_owner, None);
    }

    /// Explicitly configured socket paths win over the owner-derived
    /// default — the override contract that keeps multi-adapter and test
    /// setups working (zipline#39).
    #[test]
    fn test_apply_socket_owner_respects_explicit_paths() {
        let section: GlobalConfigSection = toml::from_str(
            r#"
            control_path = "/explicit/control.sock"
            "#,
        )
        .unwrap();
        let mut config = Config::default();
        config
            .set_from_globals(&section, Path::new("/tmp"))
            .unwrap();
        config.apply_socket_owner(Some(SocketOwner {
            uid: 1234,
            gid: Some(1234),
        }));
        assert_eq!(config.control_path, PathBuf::from("/explicit/control.sock"));
        // The owner is still recorded for the post-bind chown.
        assert_eq!(
            config.socket_owner,
            Some(SocketOwner {
                uid: 1234,
                gid: Some(1234)
            })
        );
    }

    /// `prepare_socket_dirs` creates the per-owner directory for derived
    /// paths, so config validation passes even though the parent did not
    /// pre-exist (zipline#39). Uses the current euid so the chown is a no-op
    /// permitted without root.
    #[cfg(unix)]
    #[test]
    fn test_prepare_socket_dirs_creates_derived_parent() {
        let tstamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("zpr_test_sockdir_{tstamp}"));

        let mut config = Config::default();
        // Simulate the derived per-uid layout under a temp data home; keep
        // the derived flag true so prepare_socket_dirs owns the parent.
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        config.socket_owner = Some(SocketOwner {
            uid,
            gid: Some(gid),
        });
        config.control_path = base.join(uid.to_string()).join("control.sock");

        let parent = config.control_path.parent().unwrap().to_path_buf();
        assert!(!parent.exists(), "parent must not pre-exist for this test");

        config.prepare_socket_dirs().unwrap();

        assert!(
            parent.exists(),
            "prepare_socket_dirs must create the parent"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&parent).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700, "per-owner dir must be mode 0700");

        // And the config now passes the parent-directory validation.
        if let Some(parent) = config.control_path.parent() {
            assert!(fs::exists(parent).unwrap());
        }

        fs::remove_dir_all(&base).unwrap();
    }

    /// Explicit socket paths are left alone by `prepare_socket_dirs`: a
    /// missing parent stays missing and still fails validation, exactly as
    /// today (zipline#39).
    #[cfg(unix)]
    #[test]
    fn test_prepare_socket_dirs_leaves_explicit_paths_alone() {
        let tstamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("zpr_test_sockdir_expl_{tstamp}"));

        let section: GlobalConfigSection = toml::from_str(&format!(
            r#"
            control_path = "{base}/nosuchdir/control.sock"
            "#,
            base = base.display()
        ))
        .unwrap();
        let mut config = Config::default();
        config
            .set_from_globals(&section, Path::new("/tmp"))
            .unwrap();
        config.socket_owner = Some(SocketOwner {
            uid: nix::unistd::geteuid().as_raw(),
            gid: None,
        });

        config.prepare_socket_dirs().unwrap();
        assert!(
            !config.control_path.parent().unwrap().exists(),
            "explicit path parents must not be auto-created"
        );
    }
}
