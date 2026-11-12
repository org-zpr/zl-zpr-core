#![cfg_attr(feature = "ci", deny(warnings))]

use itertools::izip;
use km_cert_exchange::KmCertExchange;
use std::default::Default;
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::process;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::*;

mod actor_activation;
mod actor_auth;
mod actor_renewal;
mod adapter_manager_worker;
mod adapter_tables;
mod address_pool;
mod admin_worker;
mod assembly;
mod auth;
mod auth_agent;
mod batch_io;
mod bootstrap_handoff;
mod capture_worker;
mod classifier;
mod compress;
mod config;
mod counters;
mod defs;
mod fastpath;
mod fastpath_io;
mod fastpath_worker;
mod flow_control;
mod forwarding_tables;
mod km;
mod km_cert_exchange;
mod km_multiplexor;
mod km_noise;
mod link_state;
mod logging;
mod main_argparse;
mod main_args;
mod mgmt;
mod mgmt_dispatch_worker;
mod mgmt_processor_worker;
mod packet;
mod packet_queue;
mod packet_steering;
mod pcap_writer;
mod peer_table;
mod pki;
mod prelude;
mod queues;
mod sample_ring;
mod signal_worker;
mod special_peers;
mod sys;
mod tc;
mod test_packet;
mod tlv;
mod tun_ctl;
mod two_way_queue;
mod visa_mgmt;
mod visa_table;
mod vs_worker;
mod vss_worker;
mod zdp;
mod zdp_ll;
mod zdpr;
mod zdpr_worker;
mod zprtun;

#[cfg(test)]
mod km_testdata;

use assembly::{Assembly, PhMode, SelfAddressError};
use capture_worker::CaptureWorker;
use fastpath::FastpathWorkerConfig;
use flow_control::FlowControl;
use km_multiplexor::KmState;
use km_noise::NoiseKeypair;
use logging::targets::STARTUP;
use pki::load_cert;
use queues::*;
use sys::ZprTun;
use tun_ctl::TunCtl;
use zpr_utils::net_defs::SocketAddrExt;

use zpr::addrs::{
    DEFAULT_TETHER_PORT, VISA_SERVICE_ADDR, VISA_SERVICE_PORT, ZPR_INTERNAL_NETWORK,
    ZPRNET_PREFIX_LEN,
};
use zpr::packet_info::{DOCK_LINK_ID, LOCAL_ACTOR_LINK_ID};
use zpr::vsapi_types::AuthServicesList;

fn main() -> ExitCode {
    let system_start_time = std::time::Instant::now();

    //
    // parse configuration from command line
    //

    let (ph_mode, mut config) = match main_argparse::argparse(None) {
        Ok((ph_mode, config)) => (ph_mode, config),
        Err(e) => {
            eprintln!("failed to parse command line arguments: {:?}", e);
            eprintln!("try `ph --help` for help");
            return ExitCode::FAILURE;
        }
    };

    //
    // set up logging
    //
    let (reload_handle, logging_map) = logging::initialize(&mut config.logging);

    info!(target: STARTUP, "starting with PID {}", process::id());

    #[cfg(feature = "enable-security-testing")]
    {
        error!(
            target: STARTUP,
            "\n\
             ################################################################\n\
             ##                                                            ##\n\
             ##   W A R N I N G  SECURITY TESTING BUILD                    ##\n\
             ##                                                            ##\n\
             ##   Built with the `enable-security-testing` feature, which  ##\n\
             ##   compiles in code that DELIBERATELY BREAKS the security   ##\n\
             ##   guarantees of ZPR in order to test them.                 ##\n\
             ##                                                            ##\n\
             ##   NEVER RUN THIS BINARY IN A PRODUCTION ENVIRONMENT!       ##\n\
             ##                                                            ##\n\
             ################################################################"
        );
        error!(
            target: STARTUP,
            "security testing: mangle forwarded pings = {}, unkeyed a2a micv = {}, recompute micvs = {}",
            config.security_testing_mangle_forwarded_pings,
            config.security_testing_unkeyed_a2a_micv,
            config.security_testing_recompute_micvs
        );
    }

    //
    // read key material
    //

    let self_noise_keypair;
    let certx;

    let maybe_private_key = match config.get_noise_private_key_data() {
        Ok(key) => key,
        Err(e) => {
            error!(
                target: STARTUP,
                "failed to load private key from: {:?}: {e:?}",
                config.noise_private_key_source()
            );
            return ExitCode::FAILURE;
        }
    };
    if ph_mode == PhMode::Node {
        // In node mode a private key is required -- since client adapters use the public key to verify the node.
        let Some(private_key) = maybe_private_key else {
            // Note that this is already checked in the config code, so this should be redundant.
            error!(target: STARTUP, "nodes require a noise private key to be specified");
            return ExitCode::FAILURE;
        };
        self_noise_keypair = NoiseKeypair::new(private_key);
    } else {
        self_noise_keypair = match maybe_private_key {
            Some(private_key) => NoiseKeypair::new(private_key),
            None => NoiseKeypair::generate(),
        };
    }

    // Set up key exchange.
    //
    // If we have a signed certificate, use it during keying. Otherwise none is
    // sent: nodes do not verify the certificates of non-special adapters, so an
    // adapter without one simply presents no name (the Noise handshake still
    // authenticates its static key).

    let self_cert = match config.certificate_file.as_ref() {
        None => None,
        Some(cert_path) => match load_cert(cert_path) {
            Ok(cert) => Some(cert),
            Err(e) => {
                error!(target: STARTUP, "failed to load certificate from {:?}: {e:?}", cert_path);
                return ExitCode::FAILURE;
            }
        },
    };
    let opt_ca_cert = if let Some(ref ca_file) = config.ca_file {
        let ca_cert = match load_cert(&ca_file) {
            Ok(cert) => cert,
            Err(e) => {
                error!(target: STARTUP, "failed to load CA certificate from {:?}: {e:?}", ca_file);
                return ExitCode::FAILURE;
            }
        };
        Some(ca_cert)
    } else {
        None
    };
    if opt_ca_cert.is_none() {
        warn!(
            target: STARTUP,
            "no ca_file configured; peer certificates will not be verified"
        );
    }
    certx = KmCertExchange::new(self_cert, opt_ca_cert);

    //
    // instantiate bounded resources (queues and buffers)
    //

    let topology_config = config::TopologyConfig::default();

    let (cap_inq, cap_outq) = queues::capture_queue(topology_config.capture_queue_size);
    let (md_inq_factory, md_outq) =
        two_way_queue::two_way_queue(topology_config.mgmt_dispatch_queue_size);
    let (mhd_inq, mhd_outq) = mpsc::channel(topology_config.mgmt_dispatch_queue_size);
    let (am_inq_factory, am_outq) =
        two_way_queue::two_way_queue(topology_config.adapter_manager_queue_size);
    let (km_sig_inq, km_sig_outq) = mpsc::channel(topology_config.km_signal_queue_size);
    let (km_inq, km_outq) = mpsc::channel(topology_config.km_message_queue_size);

    //
    // startup Tokio
    //

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let _runtime_guard = runtime.enter();

    //
    // create control socket
    //

    // zipline#39: hand the sockets to whoever should drive ph-cli. The
    // access planning is posix-specific (chown/chmod; on Windows access
    // control is the named pipe's DACL, zipline#130), so it lives inside
    // the posix ControlListener::bind — both platforms share one cfg-free
    // signature here (zipline#177).
    let control_listener = match sys::control::ControlListener::bind(
        &config.control_path,
        config.socket_owner.as_ref(),
        config.control_group.as_deref(),
    ) {
        Ok(listener) => listener,
        Err(e) => {
            error!(target: STARTUP, "{e}");
            return ExitCode::FAILURE;
        }
    };

    //
    // open TUN devices and actor requeue sockets
    //

    // The TUN device is never addressed at creation on any platform
    // (zipline#161): it is created bare and addressed later via
    // `add_address` once the node's ZPR address is known. The value
    // computed here only picks the address family of the control socket
    // on macOS (which derives IPv6 when None, zipline#177) and is ignored
    // on Linux and Windows, which is why a placeholder is fine — it is
    // never put on the wire or on the device.
    let tun_addr = if !config.zpr_addr.is_empty() && config.tun_if.is_none() {
        Some(config.zpr_addr[0])
    } else {
        None
    };

    let tun_devs: Vec<_> = match ZprTun::new_mq(
        config.tun_if.clone(),
        topology_config.fastpath_concurrency,
        tun_addr,
    ) {
        Ok(devs) => devs.into_iter().map(Arc::new).collect(),
        Err(err) => {
            panic!("unable to create TUN device: {err}");
        }
    };
    let tun_ctl = Box::new(tun_ctl::TunCtlImpl::new(tun_devs[0].clone()));

    // zipline#101: only one adapter per host can own fd5a:5052::/32. A
    // second adapter would dock, activate, and then silently receive no
    // traffic — its route loses to the first adapter's. Refuse to start
    // when the internal-network route already resolves to another live
    // interface (a route on our own TUN — the pre-provisioned tun_if case —
    // or on a linkdown persistent TUN passes). Read-only route query, so
    // unprivileged instances can still run it.
    if ph_mode == PhMode::Adapter {
        match tun_ctl.route_owner_conflict(IpAddr::V6(ZPR_INTERNAL_NETWORK), ZPRNET_PREFIX_LEN) {
            Ok(None) => {}
            Ok(Some(owner_if)) => {
                error!(
                    target: STARTUP,
                    "refusing to start: {ZPR_INTERNAL_NETWORK}/{ZPRNET_PREFIX_LEN} already \
                     routes to interface {owner_if} — another ZPR adapter or tool already \
                     owns ZPR traffic on this host. Stop it (or remove its route) and try \
                     again; running two adapters on one host is not supported."
                );
                return ExitCode::FAILURE;
            }
            Err(e) => {
                // Could not read the routing table at all: unknown, not a
                // conflict. Do not block startup on a failed probe.
                warn!(
                    target: STARTUP,
                    "could not check whether {ZPR_INTERNAL_NETWORK}/{ZPRNET_PREFIX_LEN} is \
                     already routed to another interface: {e}; continuing"
                );
            }
        }
    }

    // Node must be set ON (adapter will be turned on as part of finishing hello)
    // TODO: There is more subtlety here, see issue ( https://github.com/org-zpr/zpr-core/issues/937 )
    tun_ctl.set_carrier(ph_mode == PhMode::Node).unwrap();

    let mut actor_requeue_inqs = Vec::new();
    let mut actor_requeue_outqs = Vec::new();
    for _i in 0..topology_config.fastpath_concurrency {
        let (inq, outq) = packet_queue::packet_queue(topology_config.mgmt_datapath_queue_size);
        actor_requeue_inqs.push(inq);
        actor_requeue_outqs.push(outq);
    }

    //
    // open substrate sockets and mgmt substrate injection socket
    //

    match ph_mode {
        PhMode::Node => {
            if config.self_addr.port() == 0 {
                config.self_addr.set_port(DEFAULT_TETHER_PORT);
                info!(target: STARTUP, "listening on default tether port {}", config.self_addr.port());
            }
        }

        PhMode::Adapter => {
            let node_addr = config.node_addr.as_mut().unwrap();
            if node_addr.port() == 0 {
                node_addr.set_port(DEFAULT_TETHER_PORT);
                info!(target: STARTUP, "connecting to default tether port {}", node_addr.port());
            }
        }
    }

    // An adapter (it has a remote node address) without a specified self
    // address: ask the OS which local address routes to the node, and use
    // it as our self address so that every substrate socket binds the same
    // concrete address. Done once, with a throwaway probe socket, before
    // any substrate socket exists (zipline#175). The probe binds our
    // configured port, so the route is chosen for the 5-tuple the
    // substrate sockets will actually use; if no port was configured, we
    // adopt the one the OS gave the probe, for the same reason.
    if let Some(node_addr) = config.node_addr {
        if config.self_addr.ip().is_unspecified() {
            let local = sys::substrate::resolve_local_addr(config.self_addr, node_addr)
                .unwrap_or_else(|e| panic!("unable to connect to node_addr ({node_addr}): {e}"));
            config.self_addr.set_scoped_ip(local.scoped_ip());
            info!(target: STARTUP, "assigned substrate address {}", local.scoped_ip());
            if config.self_addr.port() == 0 {
                // ponytail: the port is free between the probe's drop and
                // the first bind below; another process grabbing that exact
                // ephemeral port in that window fails the bind (a startup
                // panic, not misrouting). Hold the probe open across the
                // bind with SO_REUSEPORT if that is ever seen.
                config.self_addr.set_port(local.port());
                info!(target: STARTUP, "assigned substrate UDP port {}", local.port());
            }
        }
    }

    let mut substrate_sockets: Vec<std::net::UdpSocket> = Vec::new();

    for _i in 0..topology_config.fastpath_concurrency {
        // Create, configure and bind one substrate socket; the platform
        // differences (pktinfo and SO_REUSEPORT on unix, the wildcard
        // bind check and SIO_UDP_CONNRESET on Windows) live behind
        // `sys::substrate::open` (zipline#176). Any failure — including
        // the bind, and Windows' wildcard-bind rejection — is a logged
        // error and a clean exit, not a panic (zipline#160): a
        // misconfigured node must fail with the message that names the
        // fix, like the ZPR-address check below.
        //
        // The bind is to our self address. If the port is unspecified,
        // one is selected by the OS. (The IP address may also be
        // unspecified -- a node with a wildcard self_addr -- in which
        // case the socket receives on every local address.)
        let socket = match sys::substrate::open(config.self_addr) {
            Ok(socket) => socket,
            Err(err) => {
                error!(
                    target: STARTUP,
                    "unable to open a substrate socket on self_addr ({}): {err}",
                    config.self_addr
                );
                return ExitCode::FAILURE;
            }
        };

        if config.self_addr.port() == 0 {
            // Update the port of our configured self address to match
            // what the OS chose.  This ensures that all sockets we open share
            // the same port.
            let port = socket.local_addr().unwrap().as_socket().unwrap().port();
            config.self_addr.set_port(port);
            info!(target: STARTUP, "assigned substrate UDP port {port}");
        }

        substrate_sockets.push(socket.into());
    }

    let node_zpr_addr: IpAddr;
    if ph_mode == PhMode::Node {
        info!(
            target: STARTUP,
            "dock listening on {}",
            substrate_sockets[0].local_addr().unwrap()
        );
        node_zpr_addr = config.zpr_addr[0].clone();
    } else {
        node_zpr_addr = Ipv6Addr::UNSPECIFIED.into(); // only node uses this.
    }

    let (mgmt_substrate_inq, mgmt_substrate_outq) =
        packet_queue::packet_queue(topology_config.mgmt_datapath_queue_size);

    //
    // configure packet steering for better load balancing
    //

    if let Err(err) = packet_steering::set_steering(
        &substrate_sockets[0],
        topology_config.fastpath_concurrency,
        packet_steering::SteeringMethod::ZdpStreamId,
    ) {
        // It's OK if this fails; flows will still be pinned to a queue;
        // they'll just be pinned there with all other flows from the same link.
        warn!(target: STARTUP, "Unable to enable ingress packet steering: {err}");
    }

    //
    // instantiate (but don't launch yet) Visa Service connection manager if we're a node
    //

    let mut vsconn;

    if ph_mode == PhMode::Node {
        // config parsing ensures that IF node THEN certificate_file is set.
        let node_name = config
            .get_noise_cn()
            .expect("unable to determine node name: cannot parse CN");
        info!(target: STARTUP, "node CN is \"{node_name}\"");

        // Load the node's RSA private key for VS "static" authentication. The public key is mapped to the
        // node CN value in the policy.
        let auth_key_path = config
            .auth_private_key
            .as_ref()
            .expect("nodes require auth_private_key for visa service authentication");
        let auth_key_pem = fs::read_to_string(auth_key_path)
            .unwrap_or_else(|e| panic!("failed to read auth_private_key {auth_key_path:?}: {e}"));
        let auth_private_key = zpr_utils::rsa_sign::load_rsa_key(auth_key_pem.as_bytes())
            .unwrap_or_else(|e| panic!("failed to parse auth_private_key {auth_key_path:?}: {e}"));

        // Advertised substrate address resolution, in order:
        //   1. advertised_substrate_addr config, if set.
        //   2. self_addr, if its IP is specified (common LAN/single-host case).
        // A wildcard self_addr with no configured advertised address is a startup
        // error: a wildcard binds every local IP (including ones added later), of
        // which the machine may have several, but we can advertise only one —
        // there is no sound way to pick it automatically, so the operator must
        // choose via advertised_substrate_addr.
        let advertised_substrate = config
            .advertised_substrate_addr
            .or_else(|| {
                if config.self_addr.ip().is_unspecified() {
                    None
                } else {
                    Some(config.self_addr)
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "cannot determine an advertised substrate address: self_addr {} \
                     has an unspecified IP; set advertised_substrate_addr in the \
                     [node] config section",
                    config.self_addr
                )
            });
        info!(
            target: STARTUP,
            "advertising substrate address {advertised_substrate} to the visa service"
        );

        vsconn = Some(libnode::vsconn::VSConn::new(
            topology_config.vs_queue_size,
            SocketAddr::new(VISA_SERVICE_ADDR, VISA_SERVICE_PORT),
            node_name,
            auth_private_key,
            advertised_substrate,
        ));
    } else {
        vsconn = None;
    }

    //
    // create system assembly
    //

    let asm = Arc::new(Assembly {
        actor_rejected: std::sync::atomic::AtomicBool::new(false),
        ph_mode,
        topology_config,
        mgmt_substrate_egress: MgmtSubstrateEgress::new(mgmt_substrate_inq),
        actor_output_requeue: ActorOutputRequeue::new(actor_requeue_inqs),
        vsconn: vsconn.as_ref().map(|c| c.handle()),
        visa_table: std::sync::RwLock::new(visa_table::VisaTable::initial_for_node(
            &node_zpr_addr,
            !config.initial_links.is_empty(),
        )),
        topology: Default::default(),
        vs_auth_services: std::sync::RwLock::new(AuthServicesList::default()),
        vs_session_up: std::sync::atomic::AtomicBool::new(false),
        deferred_vs_connect: Mutex::new(None),
        self_reauth_in_flight: std::sync::atomic::AtomicBool::new(false),
        capture_queue: cap_inq,
        capture_worker: CaptureWorker::new(),
        flow_control: FlowControl::new(),
        counters: Default::default(),
        tun_ctl,
        peer_table: peer_table::PeerTable::new(),
        elt: adapter_tables::EndpointLookupTable::new(),
        dlt: adapter_tables::DockLookupTable::new(),
        mgmt_dispatch_factory: MgmtDispatchFactory::new(md_inq_factory),
        mgmt_hairpin_dispatch: MgmtHairpinDispatch::new(mhd_inq),
        adapter_manager_factory: AdapterManagerFactory::new(am_inq_factory),
        km_state: KmState::new(km_inq, km_sig_inq),
        self_noise_keypair: Some(self_noise_keypair),
        a2a_dh_keypair: x25519_dalek::ReusableSecret::random(),
        certx: Some(certx),
        system_start_time,
        address_pool: std::sync::Mutex::new(None),
        configured_zpr_addr_demand: config.zpr_addr.clone(),
        config: rcu::RcuBox::new(config),
        fatal_error: Mutex::new(None),
        fatal_notify: tokio::sync::Notify::new(),
        logging: Mutex::new(logging_map),
        reload_handle,
    });

    //
    // create a Tokio "local set" to schedule all our management workers on
    //

    let local_set = tokio::task::LocalSet::new();

    let _local_set_guard = local_set.enter();

    //
    // instantiate local actor and tether links
    // NOTE: must occur before we start any other workers!
    //

    match ph_mode {
        PhMode::Adapter => {
            // instantiate the "fake" local actor link
            assert_eq!(
                asm.peer_table.insert_internal_peer().get(),
                LOCAL_ACTOR_LINK_ID
            );

            // instantiate tether
            let auto_connect = asm.config.get().auto_connect;
            let dsid = asm
                .start_tether(
                    asm.config.get().node_addr.as_ref().unwrap(),
                    &asm.config.get().self_addr.scoped_ip(),
                    link_state::LinkType::AdapterToNode,
                    auto_connect,
                )
                .unwrap();

            assert_eq!(dsid.get(), DOCK_LINK_ID);
        }

        PhMode::Node => {
            // instantiate the "fake" local actor and dock links

            let (lalid, dlid) = asm.peer_table.insert_internal_peer_pair(|link_id, q| {
                mgmt_processor_worker::launch(
                    mgmt_processor_worker::Config { link_id },
                    asm.clone(),
                    q,
                )
            });
            assert_eq!(lalid.get(), LOCAL_ACTOR_LINK_ID);
            assert_eq!(dlid.get(), DOCK_LINK_ID);

            // For now, we use ZDPR for flow control on internal mgmt links.
            tokio::task::spawn_local(zdpr_worker::launch(asm.clone(), lalid.get()));
            tokio::task::spawn_local(zdpr_worker::launch(asm.clone(), dlid.get()));

            // Nodes use the local actor link as the source of bind requests from the
            // internal adapter, which require that the originator has a valid
            // actor address (which matches the requested source address).
            for addr in &asm.config.get().zpr_addr {
                asm.peer_table
                    .get(LOCAL_ACTOR_LINK_ID)
                    .unwrap()
                    .actor_auth
                    .add_internal_address(addr.into());
            }

            // Those are the only source addresses the node will accept from
            // itself, and the addresses it binds its own services to. Apply
            // them to the TUN device ourselves (zipline#159, N3): on Linux a
            // hand-configured or script-configured device already carries
            // them and nothing is called; on macOS and Windows nobody else
            // addresses a node's TUN at all. On Windows this also installs
            // the /128 visa-service host route, because `netsh add address`
            // ignores the prefix and the address alone makes nothing
            // on-link. Failure means the node cannot reach the visa service
            // and every symptom would appear somewhere other than here, so
            // refuse to start — naming the manual command that matches what
            // actually failed (PR #61 review): an address failure gets the
            // add-address command, a route failure the add-route command,
            // and a route owned by another live interface means a second
            // ZPR instance on this host already carries visa-service
            // traffic, which is a conflict to resolve, not a command to run.
            if let Err(e) = asm.ensure_local_zpr_addrs_on_tun() {
                let ifname = asm
                    .config
                    .get()
                    .tun_if
                    .clone()
                    .unwrap_or_else(|| "<TUN device>".to_string());
                match &e {
                    SelfAddressError::Address { addr, .. } => {
                        error!(
                            target: STARTUP,
                            "{e}; configure it manually with: {}",
                            sys::addr_hint::manual_add_address_hint(
                                addr,
                                ZPRNET_PREFIX_LEN as usize,
                                &ifname
                            )
                        );
                    }
                    SelfAddressError::VsRoute { .. } => {
                        // Only Windows has a manual command for this
                        // (zipline#177): manual_add_route_hint is None on
                        // Linux and macOS, where the message stands alone.
                        match sys::addr_hint::manual_add_route_hint(&VISA_SERVICE_ADDR, &ifname) {
                            Some(hint) => {
                                error!(target: STARTUP, "{e}; configure it manually with: {hint}")
                            }
                            None => error!(target: STARTUP, "{e}"),
                        }
                    }
                    SelfAddressError::VsRouteConflict { .. } => {
                        error!(
                            target: STARTUP,
                            "{e}; stop the other instance, or remove its route, before \
                             starting this node on {ifname}"
                        );
                    }
                }
                return ExitCode::FAILURE;
            }

            // The self-addressing above is best-effort only for addresses
            // the platform cannot inspect -- so confirm the device actually
            // has them; this check stays the hard stop.
            let missing = asm.local_zpr_addrs_missing_from_tun();
            if !missing.is_empty() {
                let ifname = asm
                    .config
                    .get()
                    .tun_if
                    .clone()
                    .unwrap_or_else(|| "<TUN device>".to_string());
                for addr in &missing {
                    error!(
                        target: STARTUP,
                        "node ZPR address {addr} is not configured on {ifname}; \
                         configure it with: {}",
                        sys::addr_hint::manual_add_address_hint(
                            addr,
                            ZPRNET_PREFIX_LEN as usize,
                            &ifname
                        )
                    );
                }
                return ExitCode::FAILURE;
            }

            // Dial the configured initial links (zl-zipline#222): an
            // endpoint's link to its relay, which carries its first
            // visa-service traffic before any topology exists.
            asm.dial_initial_links();
        }
    }

    //
    // start mgmt workers
    //

    let mut js = JoinSet::new();

    // zipline#83: a worker can declare the process dead (e.g. the fabric
    // granted a ZPR address differing from the configured --zpr-addr).
    // Exit non-zero with the message on stderr — a misaddressed adapter
    // must not keep running looking healthy.
    {
        let asm = asm.clone();
        js.spawn_local(async move {
            asm.fatal_notify.notified().await;
            let msg = asm
                .get_fatal_error()
                .unwrap_or_else(|| "unspecified fatal error".to_string());
            error!(target: STARTUP, "fatal: {msg}");
            eprintln!("ph: fatal: {msg}");
            // Give the link teardown a moment to put the Terminate on the
            // wire, then exit hard: this is unrecoverable by design.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            process::exit(1);
        });
    }

    js.spawn_local(signal_worker::launch(asm.clone()));
    js.spawn_local(mgmt_dispatch_worker::launch(asm.clone(), md_outq, mhd_outq));
    js.spawn_local(adapter_manager_worker::launch(asm.clone(), am_outq));
    js.spawn_local(admin_worker::launch(asm.clone(), control_listener));
    js.spawn_local(km_multiplexor::launch_signal_worker(
        asm.clone(),
        km_sig_outq,
    ));
    js.spawn_local(km_multiplexor::launch_message_worker(asm.clone(), km_outq));

    //
    // select batch I/O engine
    //

    let Some(batch_io_engine) = batch_io::select_engine_by_name(&asm.config.get().batch_io_engine)
    else {
        error!(target: STARTUP, "Unknown packet I/O engine {}", asm.config.get().batch_io_engine);
        return ExitCode::FAILURE;
    };

    info!(target: STARTUP, "Using packet I/O engine {}", batch_io_engine.engine_name());

    //
    // start data path workers
    //

    let mut fastpath_threads = Vec::new();

    let mut mgmt_substrate_outq = Some(mgmt_substrate_outq); // only the first fastpath worker gets this

    let fastpath_worker_config = FastpathWorkerConfig {
        batch_io_engine,
        buffer_count: asm.topology_config.buffer_count,
        batch_size: asm.topology_config.fastpath_batch_size,
        #[cfg(feature = "enable-security-testing")]
        mangle_forwarded_pings: asm.config.get().security_testing_mangle_forwarded_pings,
        #[cfg(feature = "enable-security-testing")]
        unkeyed_a2a_micv: asm.config.get().security_testing_unkeyed_a2a_micv,
        #[cfg(feature = "enable-security-testing")]
        recompute_micvs: asm.config.get().security_testing_recompute_micvs,
    };

    for (worker_index, socket, tun_dev, requeue_outq) in izip!(
        0..asm.topology_config.fastpath_concurrency,
        substrate_sockets,
        tun_devs,
        actor_requeue_outqs
    ) {
        let builder = std::thread::Builder::new().name(format!("fastpath {worker_index}"));
        fastpath_threads.push(
            builder
                .spawn(fastpath_worker::launch(
                    fastpath_worker_config,
                    worker_index,
                    asm.clone(),
                    socket,
                    tun_dev,
                    requeue_outq,
                    mgmt_substrate_outq.take(),
                ))
                .unwrap(),
        );
    }

    js.spawn(capture_worker::launch(
        capture_worker::Config {
            batch_size: asm.topology_config.capture_batch_size,
        },
        asm.clone(),
        cap_outq,
    ));

    if ph_mode == PhMode::Node {
        asm.tun_ctl.set_carrier(true).unwrap();
    }

    //
    // TEMP HACK: bring up tether if we're an adapter
    //

    if ph_mode == PhMode::Adapter {
        local_set.block_on(&runtime, async {
            let dsid = DOCK_LINK_ID;
            debug!(target: STARTUP, "waiting on security association establishment on {}", asm.formatted_link_id(dsid));
            while !asm.peer_table.is_security_association_established(dsid) {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            debug!(target: STARTUP, "security association established successfully on {}", asm.formatted_link_id(dsid));
        });
    }

    //
    // start Visa Support Service, Visa Service connection manager, and their workers, if we're a node
    //
    // TODO: More thought needed here about lifecycle. It's possible the connection to the visa service
    // may fail (ie, the visa service may go down momentarily), and in that case we would normally want
    // to restart it, which may also require restarting the vss -- both while the node (ph) remains up.
    //

    if ph_mode == PhMode::Node {
        let (vss_inq, vss_outq) = mpsc::channel(asm.topology_config.vss_queue_size);

        let vss_addr =
            std::net::SocketAddr::new(asm.get_local_dock_addr(), config::DEFAULT_VSS_PORT);

        // Launch VSS server (requires local set). This expects an inbound connection from the VS.
        js.spawn_local(async move {
            if let Err(e) = libnode::vss::launch_vss(&vss_addr, vss_inq).await {
                error!(target: STARTUP, "VSS server terminated: {e:?}");
                // TODO: If the VSS goes down we would normally want to restart it.
            }
        });

        // Launch VSConn run loop (sets up its own local set). The VSConn handles reconnects.
        // Send the "stop" command to cause it to exit cleanly.
        let mut vsconn_instance = vsconn.take().unwrap();
        let vsconn_lifecycle_rx = vsconn_instance.subscribe_lifecycle_events();
        js.spawn_local(async move {
            let res = vsconn_instance
                .run_with_reconnect(config::VSCONN_RETRY_WAIT)
                .await;
            error!(target: STARTUP, "visa service connection manager terminated: {res:?}");
        });

        let vs_handle = asm.vsconn.as_ref().unwrap().clone();

        js.spawn_local(vs_worker::launch(
            asm.clone(),
            node_zpr_addr,
            vss_addr,
            vs_handle,
            vsconn_lifecycle_rx,
        ));

        js.spawn_local(vss_worker::launch(asm.clone(), vss_outq));
    }

    //
    // drive the local set, and handle worker termination
    //

    local_set.block_on(&runtime, async {
        while let Some(res) = js.join_next().await {
            res.unwrap();
        }
    });

    for th in fastpath_threads {
        th.join().unwrap();
    }

    info!(target: STARTUP, "exiting");

    ExitCode::SUCCESS
}
