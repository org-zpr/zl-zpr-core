//! Static system configuration.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{self, Path, PathBuf};
use zpr::packet_info::{KM_ID_NOISE, KM_ID_NULL, KmId};

use admin_api::{SocketOwner, control_socket_path};
use base64::prelude::*;
use serde::Deserialize;

use crate::assembly::PhMode;
use crate::auth::RsaBootstrapAuth;
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

pub const LINK_HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
pub const DEFAULT_TERMINATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Node side only: how long a node-to-adapter link may stay in `Keying`
/// before the node gives up on it and tears it down (zipline#173).
///
/// The node is the noise responder, so it has nothing to retry on its own:
/// a peer that vanished mid-handshake (NAT rebinding, crashed adapter,
/// garbage first packet) would otherwise leave a link and peer-table entry
/// behind for the life of the process. A real handshake completes in well
/// under a second; 60 s is four noise `HANDSHAKE_TIMEOUT`s (15 s, in
/// `km_noise.rs`), so a live initiator gets several attempts first. If the
/// adapter docks again after the teardown, the node simply allocates a
/// fresh link for it.
pub const NODE_KEYING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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

/// Actor authorization retry backoff after a retryable failure: starts at
/// the initial delay, doubles per attempt, capped at the max (#1410).
pub const ACTOR_AUTH_RETRY_INITIAL: std::time::Duration = std::time::Duration::from_secs(1);
pub const ACTOR_AUTH_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);

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

/// Default authentication-renewal lead: how far ahead of `auth_expires` the
/// node starts trying to renew an actor's authentication on the keep-alive
/// tick (zipline#45). Configurable per node via `auth_renewal_lead_seconds`
/// in the `[node]` config section; the effective lead is further clamped to
/// half the granted authentication lifetime so short `expiration_seconds`
/// values stay workable (see [crate::link_state::renewal_lead]).
pub const DEFAULT_AUTH_RENEWAL_LEAD: std::time::Duration = std::time::Duration::from_secs(300);

pub const DEFAULT_LINK_RESTART_HOLDDOWN: std::time::Duration = std::time::Duration::from_secs(5);

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
    /// Adapter CN fallback when no signed certificate is configured. Ignored by nodes.
    pub name: String,

    /// Path to the unix domain socket for the control interface.
    pub control_path: PathBuf,

    /// Local group granted control-channel access (zipline#154): on
    /// Windows an extra ACE on the control pipe's DACL; on Linux/macOS the
    /// socket's group when no invoking user is resolved. `None` (the
    /// default) keeps each platform's owner-only access. Validated by
    /// [validate_control_group]; only a name, never interpolated into SDDL.
    pub control_group: Option<String>,

    /// Source address for our UDP substrate socket. For an adapter this should (always?) be `0.0.0.0:0`.
    /// For a node this is the nodes dock listening address.
    pub self_addr: SocketAddr,

    /// Node only, optional - the substrate address this node advertises to the visa
    /// service (the address peers dial). Needed when it differs from the bind address,
    /// e.g. behind NAT. Resolved from the config-file string at parse time.
    pub advertised_substrate_addr: Option<SocketAddr>,

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

    /// Required for adapter - the node dock address on substrate.
    pub node_addr: Option<SocketAddr>,

    /// Required for node, optional for adapter - the ZPR address (no port) of the adapter.
    pub zpr_addr: Vec<IpAddr>,

    /// Ignored for node, optional for adapter - Only set if the adapter is configured for bootstrap authentication.
    pub bootstrap: Option<RsaBootstrapAuth>,

    /// Resolved path to the bootstrap RSA key file; used by finalize() to construct `bootstrap`.
    pub bootstrap_key_path: Option<PathBuf>,

    /// The batch I/O engine to use.
    pub batch_io_engine: String,

    /// Type of key manager implementation
    pub km_impl: KmId,

    /// Adapter only - whether the tether link connects (and reconnects) on
    /// its own. `true` (the default) is today's behaviour: start keying at
    /// startup and restart after the holddown when the link drops. `false`
    /// leaves the link Inactive until a `startLink` RPC (ph-cli connect /
    /// link start) wakes it, and a drop returns it to Inactive with no
    /// automatic restart (zipline#28).
    pub auto_connect: bool,

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

    /// Node only — how far ahead of an actor's `auth_expires` the node
    /// starts attempting silent authentication renewal (zipline#45).
    /// Configured via `auth_renewal_lead_seconds` in the `[node]` config
    /// section; defaults to [DEFAULT_AUTH_RENEWAL_LEAD]. The effective lead
    /// on a link is `min(this, remaining_lifetime / 2)`.
    pub auth_renewal_lead: std::time::Duration,

    /// Node only — whether this node carries other nodes' traffic, that is,
    /// accepts forward-only visas (zl-zipline#219, Zodes plan §5.7, §5.9).
    /// Off by default: with it off, a forward-only visa from the visa
    /// service is refused and logged. Configured via `forwarding` in the
    /// `[node]` config section or `ph node --forwarding`.
    pub forwarding: bool,

    /// Node only — the links this Zode starts at startup, before the visa
    /// service has pushed any topology (zl-zipline#222, Zodes plan §5.5).
    /// An endpoint's initial link is its relay. Each peer's certificate CN
    /// is accepted on a Zode link alongside the topology's. Configured via
    /// `[[node.initial_link]]` in the config file or repeated
    /// `ph node --initial-link CN@IP:PORT`.
    pub initial_links: Vec<InitialLink>,

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

    /// Create the [Config] struct using an optional configuration file plus
    /// any passed "common" command line arguments.
    ///
    /// Note that additional, adapter specific command line arguments may get
    /// folded into the returned object later.
    pub fn new_for_adapter(
        config_file: Option<AdapterConfig>,
        common: &CommonArgs,
    ) -> Result<Self, ArgsError> {
        let mut config = Config::default();
        config.set_from_common(common)?;
        if let Some(config_file) = config_file {
            let base_dir = config_file.config_path.parent().unwrap();
            config.set_from_globals(&config_file.global, base_dir)?;
            config.set_from_adapter(&config_file.adapter, base_dir)?;
            config.set_from_authentication(&config_file.authentication, base_dir)?;
        }
        Ok(config)
    }

    pub fn new_for_node(
        config_file: Option<NodeConfig>,
        auth_private_key: Option<PathBuf>,
        common: &CommonArgs,
    ) -> Result<Self, ArgsError> {
        let mut config = Config::default();
        if let Some(pkey_file) = auth_private_key {
            config.auth_private_key = Some(path::absolute(pkey_file).or_else(|e| {
                Err(ArgsError::PathError(format!(
                    "path error for auth_private_key: {:?}",
                    e
                )))
            })?);
        }
        config.set_from_common(common)?;
        if let Some(config_file) = config_file {
            let base_dir = config_file.config_path.parent().unwrap();
            config.set_from_globals(&config_file.global, base_dir)?;
            config.set_from_authentication(&config_file.authentication, base_dir)?;
            config.set_from_node(&config_file.node)?;
        }
        Ok(config)
    }

    /// If we have a `certificate_file` use that to figure out our CN.
    /// Otherwise we return the `global.name` value. Returns an error if both are absent.
    pub fn get_noise_cn(&self) -> Result<String, ArgsError> {
        match self.certificate_file.as_ref() {
            None => {
                if self.name.is_empty() {
                    Err("certificate_file or name (required for CN derivation)".arg_missing())
                } else {
                    Ok(self.name.clone())
                }
            }
            Some(f) => get_noise_cn(&f),
        }
    }

    /// Construct auth objects from stored key paths, using the resolved CN.
    /// Must be called after all name sources (config file and CLI) have been merged.
    pub fn finalize(&mut self) -> Result<(), ArgsError> {
        if let Some(path) = self.bootstrap_key_path.clone() {
            let cn = self.get_noise_cn()?;
            self.bootstrap = Some(RsaBootstrapAuth::new(&cn, &path)?);
        }
        Ok(())
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

    // Check that the required bits are present based on mode.
    // Also checks that the various files exist.
    pub fn check_valid(&self, mode: PhMode) -> Result<(), ArgsError> {
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
        match mode {
            PhMode::Node => {
                if self.zpr_addr.is_empty() {
                    return Err("zpr_addr".arg_missing());
                }
                if self.certificate_file.is_none() {
                    return Err("certificate_file".arg_missing());
                }
                if self.private_key_file.is_none() && self.private_key_data.is_none() {
                    return Err("private_key_file or noise_private_key".arg_missing());
                }
            }
            PhMode::Adapter => {
                if self.node_addr.is_none() {
                    return Err("node_addr".arg_missing());
                }
                if self.certificate_file.is_none() && self.name.is_empty() {
                    return Err("name (required when certificate_file is absent)".arg_missing());
                }
                if self.private_key_file.is_none()
                    && self.private_key_data.is_none()
                    && self.name.is_empty()
                {
                    return Err(
                        "adapter name must be set to CN when not using explicit link keys"
                            .arg_missing(),
                    );
                }
            }
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the global section.
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
        // The command line wins: set_from_common ran first, so only fill
        // the value in when no flag supplied it.
        if self.control_group.is_none() {
            if let Some(group) = &config.control_group {
                self.control_group = Some(validate_control_group(group)?);
            }
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
            self.zpr_addr.extend(&*actor_addr);
        }
        if let Some(logging) = &config.logging {
            self.logging.extend(logging.into_iter().cloned());
        }
        if let Some(io_engine) = &config.io_engine {
            self.batch_io_engine = io_engine.clone();
        }
        Ok(())
    }

    // Overwrite our internal state with the values present in the adapter section
    // of TOML config.
    fn set_from_adapter(
        &mut self,
        config: &AdapterConfigSection,
        base_dir: &Path,
    ) -> Result<(), ArgsError> {
        if let Some(cn) = &config.name {
            self.name = cn.clone();
        }
        if let Some(node_addr) = &config.node_addr {
            self.node_addr = Some(*node_addr);
        }

        if let Some(bootstrap_key_file) = &config.bootstrap_key {
            if bootstrap_key_file.is_relative() {
                self.bootstrap_key_path = Some(base_dir.join(bootstrap_key_file));
            } else {
                self.bootstrap_key_path = Some(bootstrap_key_file.clone());
            }
        }
        if let Some(auto_connect) = config.auto_connect {
            self.auto_connect = auto_connect;
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
            if let Some(advertised) = &config.advertised_substrate_addr {
                self.advertised_substrate_addr = Some(resolve_advertised_addr(advertised)?);
            }
            if let Some(lead_seconds) = config.auth_renewal_lead_seconds {
                self.auth_renewal_lead = std::time::Duration::from_secs(lead_seconds);
            }
            if let Some(forwarding) = config.forwarding {
                self.forwarding = forwarding;
            }
            if let Some(links) = &config.initial_link {
                self.initial_links = links
                    .iter()
                    .map(|l| InitialLink::new(&l.cn, &l.addr))
                    .collect::<Result<_, _>>()?;
            }
        }
        Ok(())
    }

    /// Set the advertised substrate address from a command-line string,
    /// applying the same resolution/validation as the config-file path.
    pub fn set_advertised_substrate_addr(&mut self, addr_str: &str) -> Result<(), ArgsError> {
        self.advertised_substrate_addr = Some(resolve_advertised_addr(addr_str)?);
        Ok(())
    }

    // Overwrite our internal state with the values present in the CommonArgs (from command line)
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
            self.control_group = Some(validate_control_group(group)?);
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
            self.zpr_addr.extend(addrs);
        }

        self.logging.extend(common.logging.iter().cloned());

        self.batch_io_engine = common.io_engine.clone();

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
            name: String::new(),
            control_path: control_socket_path(None),
            control_group: None,
            self_addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0),
            ca_file: None,
            certificate_file: None,
            private_key_file: None,
            private_key_data: None,
            advertised_substrate_addr: None,
            auth_private_key: None,
            tun_if: None,
            logging: Vec::new(),
            node_addr: None,
            zpr_addr: Vec::new(),
            bootstrap: None,
            bootstrap_key_path: None,
            batch_io_engine: batch_io::AUTO_ENGINE_NAME.to_owned(),
            km_impl: KM_ID_NOISE,
            auto_connect: true,
            socket_owner: None,
            control_path_derived: true,
            auth_renewal_lead: DEFAULT_AUTH_RENEWAL_LEAD,
            forwarding: false,
            initial_links: Vec::new(),
            #[cfg(feature = "enable-security-testing")]
            security_testing_mangle_forwarded_pings: false,
            #[cfg(feature = "enable-security-testing")]
            security_testing_unkeyed_a2a_micv: false,
            #[cfg(feature = "enable-security-testing")]
            security_testing_recompute_micvs: true,
        }
    }
}

// This describes the adapter configuration file TOML format.
#[derive(Deserialize, Debug, Clone)]
pub struct AdapterConfig {
    #[serde(skip)]
    pub config_path: PathBuf,

    pub global: GlobalConfigSection,
    pub adapter: AdapterConfigSection,
    pub authentication: Option<AuthenticationConfigSection>,
}

// This describes the node configuration file TOML format.
#[derive(Deserialize, Debug, Clone)]
pub struct NodeConfig {
    #[serde(skip)]
    pub config_path: PathBuf,

    pub global: GlobalConfigSection,
    pub node: Option<NodeConfigSection>,
    pub authentication: Option<AuthenticationConfigSection>,
}

// Node only bits.
#[derive(Deserialize, Debug, Clone)]
pub struct NodeConfigSection {
    /// The substrate address this node advertises to the visa service, as a
    /// literal `"IP:port"` string (IPv6 in square-bracket notation).
    pub advertised_substrate_addr: Option<String>,

    /// How far ahead of an actor's authentication expiry the node starts
    /// attempting silent renewal, in seconds (zipline#45). Default 300.
    pub auth_renewal_lead_seconds: Option<u64>,

    /// Whether this node accepts forward-only visas, i.e. carries other
    /// nodes' traffic (zl-zipline#219). Default false. A relay sets it.
    pub forwarding: Option<bool>,

    /// Links started at startup, before any topology (zl-zipline#222).
    /// Each is a TOML `[[node.initial_link]]` table with `addr` and `cn`.
    pub initial_link: Option<Vec<InitialLinkSection>>,
}

/// One `[[node.initial_link]]` table in the node config file.
#[derive(Deserialize, Debug, Clone)]
pub struct InitialLinkSection {
    /// The peer's substrate address, a literal `"IP:port"`.
    pub addr: String,
    /// The CN the peer's certificate must carry.
    pub cn: String,
}

/// A link a Zode starts at startup, before the visa service has pushed any
/// topology (zl-zipline#222, Zodes plan §5.5): the substrate address to dial
/// and the certificate CN the peer must present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialLink {
    pub addr: SocketAddr,
    pub cn: String,
}

impl InitialLink {
    /// Build an initial link from a CN and a literal `IP:port`. The CN must
    /// be non-empty and the address must be dialable (not unspecified, not
    /// port 0).
    pub fn new(cn: &str, addr: &str) -> Result<Self, ArgsError> {
        if cn.is_empty() {
            return Err(ArgsError::ParseError(format!(
                "initial link {addr:?} has an empty cn"
            )));
        }
        Ok(InitialLink {
            addr: parse_dialable_addr("initial link addr", addr)?,
            cn: cn.to_string(),
        })
    }

    /// Parse the command-line form `CN@IP:PORT`.
    pub fn parse_cli(s: &str) -> Result<Self, ArgsError> {
        let (cn, addr) = s.split_once('@').ok_or_else(|| {
            ArgsError::ParseError(format!("initial link {s:?} is not of the form CN@IP:PORT"))
        })?;
        InitialLink::new(cn, addr)
    }
}

// Global section is shared by nodes and adapters.
#[derive(Deserialize, Debug, Clone)]
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

// Adapter only bits.
#[derive(Deserialize, Debug, Clone)]
pub struct AdapterConfigSection {
    pub name: Option<String>,
    pub node_addr: Option<SocketAddr>,
    pub bootstrap_key: Option<PathBuf>,
    pub auto_connect: Option<bool>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AuthenticationConfigSection {
    // TODO move this here: pub bootstrap_key: Option<PathBuf>,
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

/// Parse an `advertised_substrate_addr` config string to a concrete [SocketAddr].
/// The value must be a literal `IP:port` — IPv6 in square-bracket notation, e.g.
/// `"[2001:db8::1]:5000"`. Hostnames are deliberately not accepted: substrate
/// claims are always for a specific IP address and adapters dial nodes by IP, so
/// the advertised value must be the concrete address itself. Unspecified IPs
/// (e.g. `0.0.0.0`) and port 0 are rejected: the value is what peers dial.
fn resolve_advertised_addr(addr_str: &str) -> Result<SocketAddr, ArgsError> {
    parse_dialable_addr("advertised_substrate_addr", addr_str)
}

/// Parse `addr_str` as a literal `IP:port` that a peer can dial: not an
/// unspecified address and not port 0. `field` names the setting in errors.
fn parse_dialable_addr(field: &str, addr_str: &str) -> Result<SocketAddr, ArgsError> {
    let resolved: SocketAddr = addr_str.parse().map_err(|e| {
        ArgsError::ParseError(format!(
            "{field} {addr_str:?} is not a literal IP:port \
             (IPv6 in square brackets, e.g. \"[2001:db8::1]:5000\"): {e}"
        ))
    })?;
    if resolved.ip().is_unspecified() {
        return Err(ArgsError::ParseError(format!(
            "{field} {addr_str:?} is an unspecified address; peers cannot dial it"
        )));
    }
    if resolved.port() == 0 {
        return Err(ArgsError::ParseError(format!(
            "{field} {addr_str:?} has port 0; peers cannot dial it"
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
    use std::time::Duration;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_deserialize_adapter_config() {
        let toml_str = r#"
            node_addr = "10.0.0.1:5000"
            bootstrap_key = "rsa_key.pem"
            "#;
        let _config: AdapterConfigSection = toml::from_str(toml_str).unwrap();
    }

    /// `auto_connect = false` under `[adapter]` must deserialize, and an
    /// omitted key must stay `None` so the built-in default applies.
    #[test]
    fn test_deserialize_adapter_config_auto_connect() {
        let toml_str = r#"
            node_addr = "10.0.0.1:5000"
            auto_connect = false
            "#;
        let config: AdapterConfigSection = toml::from_str(toml_str).unwrap();
        assert_eq!(config.auto_connect, Some(false));

        let toml_str = r#"
            node_addr = "10.0.0.1:5000"
            "#;
        let config: AdapterConfigSection = toml::from_str(toml_str).unwrap();
        assert_eq!(config.auto_connect, None);
    }

    /// The default is auto-connect (today's behaviour): a default `Config`
    /// has `auto_connect = true`, and `set_from_adapter` only overrides it
    /// when the config file actually carries the key.
    #[test]
    fn test_set_from_adapter_auto_connect() {
        // Default: on.
        let config = Config::default();
        assert!(config.auto_connect, "auto_connect must default to true");

        // Config file says off.
        let section: AdapterConfigSection = toml::from_str(
            r#"
            auto_connect = false
            "#,
        )
        .unwrap();
        let mut config = Config::default();
        config
            .set_from_adapter(&section, Path::new("/tmp"))
            .unwrap();
        assert!(!config.auto_connect);

        // Config file silent: default preserved.
        let section: AdapterConfigSection = toml::from_str("").unwrap();
        let mut config = Config::default();
        config
            .set_from_adapter(&section, Path::new("/tmp"))
            .unwrap();
        assert!(config.auto_connect);
    }

    #[test]
    fn test_deserialize_node_config_section() {
        let toml_str = r#"
            advertised_substrate_addr = "203.0.113.7:5000"
            "#;
        let config: NodeConfigSection = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.advertised_substrate_addr.as_deref(),
            Some("203.0.113.7:5000")
        );
    }

    #[test]
    fn test_node_config_advertised_substrate_addr() {
        let toml_str = r#"
            [global]
            self_addr = "10.0.0.1:5000"

            [node]
            advertised_substrate_addr = "203.0.113.7:6000"
            "#;
        let file_config: NodeConfig = toml::from_str(toml_str).unwrap();
        let mut config = Config::default();
        config.set_from_node(&file_config.node).unwrap();
        assert_eq!(
            config.advertised_substrate_addr,
            Some("203.0.113.7:6000".parse().unwrap())
        );

        // Without a [node] section the option stays unset.
        let toml_str = r#"
            [global]
            self_addr = "10.0.0.1:5000"
            "#;
        let file_config: NodeConfig = toml::from_str(toml_str).unwrap();
        let mut config = Config::default();
        config.set_from_node(&file_config.node).unwrap();
        assert_eq!(config.advertised_substrate_addr, None);
    }

    /// `auth_renewal_lead_seconds` in the `[node]` section overrides the
    /// renewal lead; absent, the 300s default stands (zipline#45).
    #[test]
    fn test_node_config_auth_renewal_lead_seconds() {
        // Default: 300 s.
        let config = Config::default();
        assert_eq!(config.auth_renewal_lead, DEFAULT_AUTH_RENEWAL_LEAD);
        assert_eq!(config.auth_renewal_lead, Duration::from_secs(300));

        // Config file overrides.
        let toml_str = r#"
            [global]
            self_addr = "10.0.0.1:5000"

            [node]
            auth_renewal_lead_seconds = 60
            "#;
        let file_config: NodeConfig = toml::from_str(toml_str).unwrap();
        let mut config = Config::default();
        config.set_from_node(&file_config.node).unwrap();
        assert_eq!(config.auth_renewal_lead, Duration::from_secs(60));

        // A [node] section without the key preserves the default.
        let toml_str = r#"
            [global]
            self_addr = "10.0.0.1:5000"

            [node]
            advertised_substrate_addr = "203.0.113.7:6000"
            "#;
        let file_config: NodeConfig = toml::from_str(toml_str).unwrap();
        let mut config = Config::default();
        config.set_from_node(&file_config.node).unwrap();
        assert_eq!(config.auth_renewal_lead, DEFAULT_AUTH_RENEWAL_LEAD);
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
        assert!(!parse("auth_renewal_lead_seconds = 60"));
    }

    /// `[[node.initial_link]]` entries become the Zode's initial links
    /// (zl-zipline#222); none configured means none.
    #[test]
    fn test_node_config_initial_links() {
        assert!(Config::default().initial_links.is_empty());

        let toml_str = r#"
            [global]
            self_addr = "10.0.0.1:5000"

            [node]
            [[node.initial_link]]
            addr = "203.0.113.7:5000"
            cn = "relay.zpr"

            [[node.initial_link]]
            addr = "[2001:db8::1]:5001"
            cn = "relay2.zpr"
            "#;
        let file_config: NodeConfig = toml::from_str(toml_str).unwrap();
        let mut config = Config::default();
        config.set_from_node(&file_config.node).unwrap();
        assert_eq!(
            config.initial_links,
            vec![
                InitialLink {
                    addr: "203.0.113.7:5000".parse().unwrap(),
                    cn: "relay.zpr".to_string(),
                },
                InitialLink {
                    addr: "[2001:db8::1]:5001".parse().unwrap(),
                    cn: "relay2.zpr".to_string(),
                },
            ]
        );
    }

    /// An initial link needs a CN and an address a Zode can dial.
    #[test]
    fn test_initial_link_validation() {
        assert!(InitialLink::new("relay.zpr", "203.0.113.7:5000").is_ok());
        assert!(InitialLink::new("", "203.0.113.7:5000").is_err());
        assert!(InitialLink::new("relay.zpr", "0.0.0.0:5000").is_err());
        assert!(InitialLink::new("relay.zpr", "203.0.113.7:0").is_err());
        assert!(InitialLink::new("relay.zpr", "relay.example:5000").is_err());
    }

    /// The command-line form is `CN@IP:PORT`.
    #[test]
    fn test_initial_link_parse_cli() {
        assert_eq!(
            InitialLink::parse_cli("relay.zpr@203.0.113.7:5000").unwrap(),
            InitialLink {
                addr: "203.0.113.7:5000".parse().unwrap(),
                cn: "relay.zpr".to_string(),
            }
        );
        assert!(InitialLink::parse_cli("203.0.113.7:5000").is_err());
        assert!(InitialLink::parse_cli("@203.0.113.7:5000").is_err());
    }

    #[test]
    fn test_resolve_advertised_addr() {
        // Plain IP:port passes through.
        assert_eq!(
            resolve_advertised_addr("203.0.113.7:5000").unwrap(),
            "203.0.113.7:5000".parse::<SocketAddr>().unwrap()
        );
        // V6 in square-bracket notation passes through.
        assert_eq!(
            resolve_advertised_addr("[2001:db8::7]:5000").unwrap(),
            "[2001:db8::7]:5000".parse::<SocketAddr>().unwrap()
        );
        // V6 with a scope-free full form.
        assert_eq!(
            resolve_advertised_addr("[2001:db8:0:0:0:0:0:9]:6000").unwrap(),
            "[2001:db8::9]:6000".parse::<SocketAddr>().unwrap()
        );
        // V6 without brackets rejected.
        assert!(resolve_advertised_addr("2001:db8::7:5000").is_err());
        // Hostnames rejected: the claim is always for a specific IP address.
        assert!(resolve_advertised_addr("localhost:5000").is_err());
        assert!(resolve_advertised_addr("node1.example.com:5000").is_err());
        // Unspecified IP rejected.
        assert!(resolve_advertised_addr("0.0.0.0:5000").is_err());
        assert!(resolve_advertised_addr("[::]:5000").is_err());
        // Port 0 rejected (V4 and V6).
        assert!(resolve_advertised_addr("203.0.113.7:0").is_err());
        assert!(resolve_advertised_addr("[2001:db8::7]:0").is_err());
        // Garbage rejected.
        assert!(resolve_advertised_addr("not an address").is_err());
        assert!(resolve_advertised_addr("203.0.113.7").is_err());
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
