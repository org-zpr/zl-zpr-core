//! ZPR Packet Handler command line arg processing.
//!
//! The main entry point is [argparse] which will parse the command line arguments
//! and any config file, returning a PH configuration. See [crate::config::Config] for
//! more details on the configuration.

use clap::Parser;
use std::io::Read;
use std::path::{self, Path};

use crate::main_args::{ArgsError, Command, Control};

use crate::config::{Config, NodeConfig};

/// Parse the program arguments, may also parse a configuration file if that has been
/// specified in the arguments.  If all goes well this returns a valid Zode
/// configuration.
///
/// Additional checking is still necessary.  For example, file paths specified
/// may not actually exist.
///
/// # Arguments
///
/// `args` - Optional vector of strings representing the command line arguments.
/// If None we parse from `std::env::args_os()`.
pub fn argparse(args: Option<Vec<&str>>) -> std::result::Result<Config, ArgsError> {
    let control = match args {
        Some(args) => Control::parse_from(args),
        None => Control::parse(),
    };

    // `zode` is the only subcommand (zl-zipline#234).
    let Command::Zode {
        config_file,
        auth_private_key,
        advertised_substrate_addr,
        forwarding,
        initial_link,
        relay,
        common,
    } = control.command;

    let config_file: Option<NodeConfig> = match config_file {
        Some(p) => {
            let mut nc = load_config::<NodeConfig>(&p)?;
            nc.config_path = path::absolute(&p).or_else(|e| {
                Err(ArgsError::PathError(format!(
                    "path error for config file: {:?}",
                    e
                )))
            })?;
            Some(nc)
        }
        None => None,
    };
    let mut config = Config::new_for_node(config_file, auth_private_key, &common)?;
    // Command line overrides the config file.
    if let Some(advertised) = advertised_substrate_addr {
        config.set_advertised_substrate_addr(&advertised)?;
    }
    // An omitted flag preserves the config file value (or the
    // default, false).
    if let Some(forwarding) = forwarding {
        config.forwarding = forwarding;
    }
    if let Some(spec) = initial_link {
        config.initial_link = Some(crate::config::InitialLink::parse_cli(&spec)?);
    }
    if let Some(relay) = relay {
        config.relay = relay;
    }
    // zipline#39: resolve the invoking user (sudo/pkexec), fold it into the
    // config (derived socket paths become per-uid) and create the per-owner
    // socket directories before validation, so check_valid's parent-directory
    // check passes without pre-provisioning.
    config.apply_socket_owner(admin_api::resolve_socket_owner(|key| {
        std::env::var(key).ok()
    }));
    #[cfg(unix)]
    config.prepare_socket_dirs()?;
    config.check_valid()?;
    Ok(config)
}

// Load a Zode config from a TOML file.
fn load_config<T>(path: &Path) -> Result<T, ArgsError>
where
    T: serde::de::DeserializeOwned,
{
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(ArgsError::ParseError(format!(
            "Empty configuration file {:?}",
            path
        )));
    }
    let ac: T = match toml::from_str(&toml_text) {
        Ok(ac) => ac,
        Err(e) => {
            return Err(ArgsError::ParseError(format!(
                "Error parsing configuration file {:?}: {}",
                path, e
            )));
        }
    };
    Ok(ac)
}

// The TOML fixtures below splice temp-file paths into `'$PLACEHOLDER'`
// single-quoted (literal) strings: a Windows path such as `C:\Users\...` in a
// double-quoted TOML string would be parsed as `\U` escapes.
#[cfg(test)]
mod test {

    use super::*;
    use serial_test::{parallel, serial};
    use std::env;
    use std::fs;
    use std::net::{IpAddr, SocketAddr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempFile {
        path: String,
    }

    /// Rewrite `/tmp/...` socket paths onto [`env::temp_dir`] so test
    /// fixtures run on Windows too (config validation requires the parent
    /// directory to exist, and `/tmp` only exists on unix). Forward slashes
    /// keep the result valid inside a TOML basic string on every OS —
    /// Windows APIs accept them.
    fn portable_tmp_paths(contents: &str) -> String {
        let tmp = env::temp_dir();
        let tmp = tmp.to_str().unwrap().trim_end_matches(['/', '\\']);
        contents.replace("/tmp/", &format!("{}/", tmp.replace('\\', "/")))
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TempFile {
        fn new_toml(contents: &str) -> TempFile {
            let tstamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let dir = env::temp_dir();
            let mut buf = [0u8; 4];
            aws_lc_rs::rand::fill(&mut buf).unwrap();
            let num = u32::from_be_bytes(buf);
            let path = dir.join(format!("org_zpr_ph_test_main_{}_{}.toml", num, tstamp));
            // The templates name sockets under /tmp, which exists on every
            // unix but not on Windows — and config validation requires the
            // socket paths' parent directory to exist. Rewrite them onto the
            // OS temp dir so the same templates run everywhere
            // (zipline#131 step 7).
            let contents = portable_tmp_paths(contents);
            fs::write(&path, contents).expect("Unable to write file");
            TempFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn touch() -> TempFile {
            Self::new_toml("")
        }

        fn get_path(&self) -> &Path {
            return Path::new(&self.path);
        }

        #[allow(dead_code)]
        fn get_dir(&self) -> &Path {
            return Path::new(&self.path).parent().unwrap();
        }
    }

    #[test]
    fn test_main_args_load_config_node() {
        let tomltxt = r#"
        [global]
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        logging = [ ["all", "TRACE"] ]

        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let config: NodeConfig = load_config(tmpfile.get_path()).unwrap();

        assert_eq!(
            config.global.control_path,
            Some(PathBuf::from("/var/run/zpr/control.sock"))
        );
        assert_eq!(
            config.global.self_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)),
                12345
            ))
        );
        assert_eq!(config.global.ca_file, Some(PathBuf::from("tests/ca.pem")));
        assert_eq!(
            config.global.certificate_file,
            Some(PathBuf::from("tests/certificate.pem"))
        );
        assert_eq!(
            config.global.private_key_file,
            Some(PathBuf::from("tests/private_key.pem"))
        );
        assert_eq!(config.global.tun_if, Some("tun23".to_string()));
        assert_eq!(
            config.global.logging,
            Some(Vec::from([("all".to_string(), "TRACE".to_string())]))
        );
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_config_minimal() {
        // Not quite minimal since we need to set control path to make CI happy.
        let mut tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"
        zpr_addr = [ "fd5a:5052::2" ]

        [node.initial_link]
        addr = "10.0.0.9:5000"
        cn = "relay.zpr"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "zode", "-c", tmpfile.get_path().to_str().unwrap()];

        let config = argparse(Some(args)).unwrap();

        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, Some(ca_file.get_path().into()));
        assert_eq!(config.certificate_file, Some(cert_file.get_path().into()));
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file.get_path().display())
        );
        assert!(config.tun_if.is_none());
        assert!(config.logging.is_empty());
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_config_no_toml() {
        // The files references on command line need to exist
        let ca_file = TempFile::touch();
        let ca_file_fname = String::from(ca_file.get_path().to_str().unwrap());
        let cert_file = TempFile::touch();
        let cert_file_fname = String::from(cert_file.get_path().to_str().unwrap());
        let pk_file = TempFile::touch();
        let pk_file_fname = String::from(pk_file.get_path().to_str().unwrap());
        let control_sock = portable_tmp_paths("/tmp/control.sock");

        let args = vec![
            "ph",
            "zode",
            "--ca-file",
            &ca_file_fname,
            "--certificate-file",
            &cert_file_fname,
            "--private-key-file",
            &pk_file_fname,
            "--control-path",
            &control_sock,
            "--zpr-addr",
            "fd5a:5052::2",
            "--initial-link",
            "relay.zpr@10.0.0.9:5000",
        ];

        let config = argparse(Some(args)).unwrap();

        assert!(!config.control_path.to_string_lossy().is_empty());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(config.ca_file, Some(PathBuf::from(&ca_file_fname)));
        assert_eq!(
            config.certificate_file,
            Some(PathBuf::from(&cert_file_fname))
        );
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file_fname)
        );
        assert!(config.tun_if.is_none());
        assert!(config.logging.is_empty());
    }

    // CLI --advertised-substrate-addr sets the advertised address with no config file.
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_advertised_addr_cli_only() {
        let ca_file = TempFile::touch();
        let ca_file_fname = String::from(ca_file.get_path().to_str().unwrap());
        let cert_file = TempFile::touch();
        let cert_file_fname = String::from(cert_file.get_path().to_str().unwrap());
        let pk_file = TempFile::touch();
        let pk_file_fname = String::from(pk_file.get_path().to_str().unwrap());
        let control_sock = portable_tmp_paths("/tmp/control.sock");

        let args = vec![
            "ph",
            "zode",
            "--ca-file",
            &ca_file_fname,
            "--certificate-file",
            &cert_file_fname,
            "--private-key-file",
            &pk_file_fname,
            "--control-path",
            &control_sock,
            "--zpr-addr",
            "fd5a:5052::2",
            "--initial-link",
            "relay.zpr@10.0.0.9:5000",
            "--self-addr",
            "0.0.0.0:12345",
            "--advertised-substrate-addr",
            "203.0.113.7:12345",
        ];

        let config = argparse(Some(args)).unwrap();

        // The bind address stays wildcard; only the advertised address is concrete.
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 12345)
        );
        assert_eq!(
            config.advertised_substrate_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
                12345
            ))
        );
    }

    // CLI --advertised-substrate-addr wins over [node] advertised_substrate_addr.
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_advertised_addr_cli_overrides_config() {
        let mut tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"
        self_addr = "0.0.0.0:12345"
        zpr_addr = [ "fd5a:5052::2" ]

        [node]
        advertised_substrate_addr = "203.0.113.7:6000"
        initial_link = { addr = "10.0.0.9:5000", cn = "relay.zpr" }
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "zode",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--advertised-substrate-addr",
            "198.51.100.9:7000",
        ];

        let config = argparse(Some(args)).unwrap();

        assert_eq!(
            config.advertised_substrate_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9)),
                7000
            ))
        );
    }

    // The CLI value goes through the same validation as the config-file value:
    // an unspecified IP is rejected because peers cannot dial it.
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_advertised_addr_cli_rejects_unspecified() {
        let ca_file = TempFile::touch();
        let ca_file_fname = String::from(ca_file.get_path().to_str().unwrap());
        let cert_file = TempFile::touch();
        let cert_file_fname = String::from(cert_file.get_path().to_str().unwrap());
        let pk_file = TempFile::touch();
        let pk_file_fname = String::from(pk_file.get_path().to_str().unwrap());
        let control_sock = portable_tmp_paths("/tmp/control.sock");

        let args = vec![
            "ph",
            "zode",
            "--ca-file",
            &ca_file_fname,
            "--certificate-file",
            &cert_file_fname,
            "--private-key-file",
            &pk_file_fname,
            "--control-path",
            &control_sock,
            "--zpr-addr",
            "fd5a:5052::2",
            "--advertised-substrate-addr",
            "0.0.0.0:12345",
        ];

        match argparse(Some(args)) {
            Err(ArgsError::ParseError(msg)) => {
                assert!(
                    msg.contains("unspecified"),
                    "expected 'unspecified' in error, got: {msg}"
                );
            }
            other => panic!("expected ParseError, got: {:?}", other),
        }
    }

    // CLI --forwarding wins over [node] forwarding in either direction, and an
    // omitted flag keeps the config file value (zl-zipline#219).
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_forwarding_cli_overrides_config() {
        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"
        self_addr = "10.0.0.1:12345"
        zpr_addr = [ "fd5a:5052::2" ]

        [node]
        forwarding = true
        initial_link = { addr = "10.0.0.9:5000", cn = "relay.zpr" }
        "#
        .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
        .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
        .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        let tmpfile = TempFile::new_toml(&tomltxt);
        let config_path = tmpfile.get_path().to_str().unwrap();

        let config = argparse(Some(vec!["ph", "zode", "-c", config_path])).unwrap();
        assert!(config.forwarding, "the config file turns forwarding on");

        let config = argparse(Some(vec![
            "ph",
            "zode",
            "-c",
            config_path,
            "--forwarding",
            "false",
        ]))
        .unwrap();
        assert!(!config.forwarding, "--forwarding false overrides the file");
    }

    /// A `[node]` section line giving a Zode that is no relay its initial link.
    const DIAL: &str = r#"initial_link = { addr = "10.0.0.9:5000", cn = "relay.zpr" }"#;

    /// A minimal node config file whose `[node]` section is `node_section`,
    /// with the referenced key files kept alive by the returned guards.
    fn node_config_file(node_section: &str) -> (TempFile, [TempFile; 3]) {
        node_config_file_at("10.0.0.1:12345", node_section)
    }

    /// [node_config_file] with substrate address `self_addr`.
    fn node_config_file_at(self_addr: &str, node_section: &str) -> (TempFile, [TempFile; 3]) {
        node_config_file_full(self_addr, r#"[ "fd5a:5052::2" ]"#, node_section)
    }

    /// [node_config_file] whose `zpr_addr` is the TOML array `zpr_addr`.
    fn node_config_file_addrs(zpr_addr: &str, node_section: &str) -> (TempFile, [TempFile; 3]) {
        node_config_file_full("10.0.0.1:12345", zpr_addr, node_section)
    }

    /// [node_config_file] with substrate address `self_addr` and `zpr_addr`
    /// the TOML array `zpr_addr`.
    fn node_config_file_full(
        self_addr: &str,
        zpr_addr: &str,
        node_section: &str,
    ) -> (TempFile, [TempFile; 3]) {
        node_config_file_with(self_addr, zpr_addr, "", node_section)
    }

    /// [node_config_file] whose `[global]` section also carries
    /// `global_extra` verbatim.
    fn node_config_file_global(
        global_extra: &str,
        node_section: &str,
    ) -> (TempFile, [TempFile; 3]) {
        node_config_file_with(
            "10.0.0.1:12345",
            r#"[ "fd5a:5052::2" ]"#,
            global_extra,
            node_section,
        )
    }

    /// The general form of [node_config_file]: substrate address
    /// `self_addr`, `zpr_addr` the TOML array `zpr_addr`, and `global_extra`
    /// appended verbatim to the `[global]` section.
    fn node_config_file_with(
        self_addr: &str,
        zpr_addr: &str,
        global_extra: &str,
        node_section: &str,
    ) -> (TempFile, [TempFile; 3]) {
        let files = [TempFile::touch(), TempFile::touch(), TempFile::touch()];
        let tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"
        self_addr = "$SELFADDR"
        zpr_addr = $ZPRADDR
        $GLOBALEXTRA

        [node]
        "#
        .replace("$GLOBALEXTRA", global_extra)
        .replace("$SELFADDR", self_addr)
        .replace("$ZPRADDR", zpr_addr)
        .replace("$CAFILE", files[0].get_path().to_str().unwrap())
        .replace("$CERTFILE", files[1].get_path().to_str().unwrap())
        .replace("$PKFILE", files[2].get_path().to_str().unwrap());
        (
            TempFile::new_toml(&format!("{tomltxt}{node_section}\n")),
            files,
        )
    }

    /// `ph zode --initial-link CN@IP:PORT` sets the initial link, IPv6 in
    /// brackets too, and overrides the config file (zl-zipline#250).
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_initial_link_cli() {
        let (cfg, _keys) = node_config_file_at("[::1]:12345", "");
        let path = cfg.get_path().to_str().unwrap();
        let config = argparse(Some(vec![
            "ph",
            "zode",
            "-c",
            path,
            "--initial-link",
            "relay.zpr@[fd00::9]:5000",
        ]))
        .unwrap();
        let link = config.initial_link.unwrap();
        assert_eq!(link.cn, "relay.zpr");
        assert_eq!(link.addr, "[fd00::9]:5000".parse::<SocketAddr>().unwrap());

        let (cfg, _keys) =
            node_config_file("[node.initial_link]\naddr = \"10.0.0.9:5000\"\ncn = \"file.zpr\"");
        let path = cfg.get_path().to_str().unwrap();
        let config = argparse(Some(vec!["ph", "zode", "-c", path])).unwrap();
        assert_eq!(config.initial_link.as_ref().unwrap().cn, "file.zpr");
        let config = argparse(Some(vec![
            "ph",
            "zode",
            "-c",
            path,
            "--initial-link",
            "cli.zpr@10.0.0.7:6000",
        ]))
        .unwrap();
        let link = config.initial_link.unwrap();
        assert_eq!(link.cn, "cli.zpr");
        assert_eq!(link.addr, "10.0.0.7:6000".parse::<SocketAddr>().unwrap());
    }

    /// A Zode has at most one initial link: `--initial-link` given twice is
    /// an error, and so is a malformed one.
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_initial_link_cli_rejects() {
        let (cfg, _keys) = node_config_file("");
        let path = cfg.get_path().to_str().unwrap();
        let twice = Control::try_parse_from(vec![
            "ph",
            "zode",
            "-c",
            path,
            "--initial-link",
            "a.zpr@10.0.0.9:5000",
            "--initial-link",
            "b.zpr@10.0.0.8:5000",
        ]);
        assert!(twice.is_err(), "a second --initial-link must be refused");
        for bad in ["@10.0.0.9:5000", "a.zpr@0.0.0.0:5000", "a.zpr@10.0.0.9:0"] {
            assert!(
                argparse(Some(vec!["ph", "zode", "-c", path, "--initial-link", bad])).is_err(),
                "accepted --initial-link {bad}"
            );
        }
    }

    /// `ph zode --relay` overrides `relay` in the config file, and a relay
    /// with an initial link is refused (a relay never dials, R4).
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_relay_cli() {
        // A relay lists vs.zpr after its own address (zl-zipline#229).
        let relay_addrs = r#"[ "fd5a:5052::2", "fd5a:5052::1" ]"#;
        let (cfg, _keys) = node_config_file_addrs(relay_addrs, "relay = true");
        let path = cfg.get_path().to_str().unwrap();
        let config = argparse(Some(vec!["ph", "zode", "-c", path])).unwrap();
        assert!(config.relay);

        let (cfg, _keys) = node_config_file("relay = true");
        let path = cfg.get_path().to_str().unwrap();
        let config = argparse(Some(vec![
            "ph",
            "zode",
            "-c",
            path,
            "--relay",
            "false",
            "--initial-link",
            "relay.zpr@10.0.0.9:5000",
        ]))
        .unwrap();
        assert!(!config.relay);

        let (cfg, _keys) = node_config_file(DIAL);
        let path = cfg.get_path().to_str().unwrap();
        let config = argparse(Some(vec!["ph", "zode", "-c", path])).unwrap();
        assert!(!config.relay, "relay defaults to false");

        let (cfg, _keys) = node_config_file_addrs(relay_addrs, "");
        let path = cfg.get_path().to_str().unwrap();
        assert!(argparse(Some(vec!["ph", "zode", "-c", path, "--relay", "true"])).is_ok());
        assert!(
            argparse(Some(vec![
                "ph",
                "zode",
                "-c",
                path,
                "--relay",
                "true",
                "--initial-link",
                "a.zpr@10.0.0.9:5000",
            ]))
            .is_err()
        );
    }

    /// zl-zipline#229 (gate g117 q2): the relay config contract, with
    /// `relay` from the `[node]` section or from `--relay`, and the
    /// addresses from the config file or from `--zpr-addr`. A node applies
    /// `--zpr-addr` before the file's `zpr_addr`, so the command line's
    /// addresses come first.
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_relay_lists_visa_service_addr() {
        let vs = "fd5a:5052::1";
        let parse = |path: &str, extra: &[&str]| {
            let mut args = vec!["ph", "zode", "-c", path];
            args.extend_from_slice(extra);
            argparse(Some(args))
        };
        let parse_file = |zpr_addr: &str, node_section: &str, extra: &[&str]| {
            let (cfg, _keys) = node_config_file_addrs(zpr_addr, node_section);
            parse(cfg.get_path().to_str().unwrap(), extra)
        };

        // `relay = true` in the [node] section, addresses in the file.
        let config = parse_file(r#"["fd5a:5052::2", "fd5a:5052::1"]"#, "relay = true", &[])
            .expect("a relay with vs.zpr after its own address");
        let expected: Vec<IpAddr> = vec!["fd5a:5052::2".parse().unwrap(), vs.parse().unwrap()];
        assert_eq!(config.zpr_addr, expected);
        for refused in [
            r#"["fd5a:5052::2"]"#,
            r#"["fd5a:5052::1", "fd5a:5052::2"]"#,
            r#"["fd5a:5052::2", "fd5a:5052::1", "fd5a:5052::1"]"#,
            r#"["fd5a:5052::2", "fd5a:5052::1", "fd5a:5052::2"]"#,
        ] {
            assert!(
                parse_file(refused, "relay = true", &[]).is_err(),
                "relay with zpr_addr = {refused}"
            );
        }

        // `--relay true` and `--zpr-addr` on the command line; the file
        // lists no addresses.
        let none = "[]";
        assert!(parse_file(none, "", &["--relay", "true", "-z", "fd5a:5052::2"]).is_err());
        assert!(
            parse_file(
                none,
                "",
                &["--relay", "true", "-z", "fd5a:5052::2", "-z", vs]
            )
            .is_ok()
        );
        assert!(
            parse_file(
                none,
                "",
                &["--relay", "true", "-z", vs, "-z", "fd5a:5052::2"]
            )
            .is_err()
        );
        // The command line's addresses come before the file's.
        assert!(parse_file(r#"["fd5a:5052::2"]"#, "relay = true", &["-z", vs]).is_err());

        // A node that is not a relay never lists vs.zpr, nor any duplicate.
        assert!(parse_file(r#"["fd5a:5052::2"]"#, DIAL, &[]).is_ok());
        assert!(parse_file(r#"["fd5a:5052::2", "fd5a:5052::1"]"#, DIAL, &[]).is_err());
        assert!(parse_file(none, DIAL, &["-z", "fd5a:5052::2", "-z", vs]).is_err());
        assert!(parse_file(r#"["fd5a:5052::2"]"#, DIAL, &["-z", "fd5a:5052::2"]).is_err());
    }

    #[test]
    #[serial(env)] // serialize with other tests because we modify process environment
    fn test_main_args_argparse_zode_key_in_env() {
        let mut tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        control_path = "/tmp/control.sock"
        zpr_addr = [ "fd5a:5052::2" ]

        [node.initial_link]
        addr = "10.0.0.9:5000"
        cn = "relay.zpr"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "zode", "-c", tmpfile.get_path().to_str().unwrap()];

        let noise_key = "GExPGh5RE/nKo8WoN8EqknDDNIEjWBL6PZm08Uhvn0w=";
        unsafe {
            // SAFETY: this test is executed serially
            env::set_var("NOISE_PRIVATE_KEY", noise_key);
        }
        let presult = argparse(Some(args));
        unsafe {
            // SAFETY: this test is executed serially
            env::remove_var("NOISE_PRIVATE_KEY");
        }

        let config = presult.unwrap();
        assert_eq!(
            config.noise_private_key_source(),
            format!("key://{}", noise_key)
        )
    }

    /// Parse a minimal valid Zode config whose `[global]` section carries
    /// `global_extra` verbatim, with `extra_args` appended to the command
    /// line (zipline#154 `control_group` tests).
    fn argparse_zode_with(global_extra: &str, extra_args: &[&str]) -> Result<Config, ArgsError> {
        let (tmpfile, _keys) = node_config_file_global(
            global_extra,
            "[node.initial_link]\naddr = \"10.0.0.9:5000\"\ncn = \"relay.zpr\"",
        );
        let mut args = vec!["ph", "zode", "-c", tmpfile.get_path().to_str().unwrap()];
        args.extend_from_slice(extra_args);
        argparse(Some(args))
    }

    /// zipline#154: `control_group` in `[global]` is parsed into the config.
    #[test]
    #[parallel(env)]
    fn test_control_group_from_config_file() {
        let config = argparse_zode_with(r#"control_group = "zipline""#, &[]).unwrap();
        assert_eq!(config.control_group.as_deref(), Some("zipline"));
    }

    /// zipline#154: `--control-group` overrides the config file, the same
    /// precedence as `control_path`.
    #[test]
    #[parallel(env)]
    fn test_control_group_flag_overrides_config_file() {
        let config = argparse_zode_with(
            r#"control_group = "from-file""#,
            &["--control-group", "from-flag"],
        )
        .unwrap();
        assert_eq!(config.control_group.as_deref(), Some("from-flag"));
    }

    /// zipline#154: the flag alone sets it too.
    #[test]
    #[parallel(env)]
    fn test_control_group_from_flag_only() {
        let config = argparse_zode_with("", &["--control-group", "zipline"]).unwrap();
        assert_eq!(config.control_group.as_deref(), Some("zipline"));
    }

    /// zipline#154: no default — absent everywhere means `None`.
    #[test]
    #[parallel(env)]
    fn test_control_group_absent_is_none() {
        let config = argparse_zode_with("", &[]).unwrap();
        assert_eq!(config.control_group, None);
    }

    /// zipline#154: invalid group names are rejected, from the config file
    /// and from the flag alike, with an error naming `control_group`.
    #[test]
    #[parallel(env)]
    fn test_control_group_invalid_names_rejected() {
        for bad in ["", "a\\b", "a,b", "a/b", "a:b", "a*b", "a@b", "a\tb"] {
            let line = format!("control_group = {}", toml::Value::String(bad.to_string()));
            let err = argparse_zode_with(&line, &[]).expect_err(bad);
            assert!(
                err.to_string().contains("control_group"),
                "config {bad:?}: error does not name control_group: {err}"
            );
            let err = argparse_zode_with("", &["--control-group", bad]).expect_err(bad);
            assert!(
                err.to_string().contains("control_group"),
                "flag {bad:?}: error does not name control_group: {err}"
            );
        }
    }

    /// zipline#154: ordinary names (spaces, dots, dashes, underscores) pass.
    #[test]
    #[parallel(env)]
    fn test_control_group_ordinary_names_accepted() {
        for good in [
            "zipline",
            "zpr",
            "zpr-users",
            "zpr_users",
            "ZPR Users",
            "a.b",
        ] {
            let config = argparse_zode_with("", &["--control-group", good]).unwrap();
            assert_eq!(config.control_group.as_deref(), Some(good));
        }
    }

    /// zl-zipline#234: `ph zode` parses the argv zipline passes
    /// (`zipline-cmd` `ph_args`).
    #[test]
    #[parallel(env)]
    fn test_zode_parses_zipline_argv() {
        let files = [
            TempFile::touch(),
            TempFile::touch(),
            TempFile::touch(),
            TempFile::touch(),
        ];
        let path = |i: usize| files[i].get_path().to_str().unwrap().to_owned();
        let (ca, cert, key, auth) = (path(0), path(1), path(2), path(3));
        let control_sock = portable_tmp_paths("/tmp/control.sock");
        let args = vec![
            "ph",
            "zode",
            "--ca-file",
            &ca,
            "--certificate-file",
            &cert,
            "--private-key-file",
            &key,
            "--zpr-addr",
            "fd5a:5052::2",
            "--auth-private-key",
            &auth,
            "--initial-link",
            "relay.zpr@10.0.0.9:5000",
            "--tun-if",
            "tun9",
            "--control-group",
            "zipline",
            "--control-path",
            &control_sock,
        ];
        let config = argparse(Some(args)).expect("zipline's ph zode argv");
        assert_eq!(config.initial_link.unwrap().cn, "relay.zpr");
        assert!(!config.relay);
        assert_eq!(config.tun_if.as_deref(), Some("tun9"));
        assert_eq!(config.control_group.as_deref(), Some("zipline"));
        assert_eq!(config.auth_private_key, Some(PathBuf::from(&auth)));
    }

    /// zl-zipline#234: `zode` is the only subcommand. `node` and `adapter`
    /// are unknown, with no alias, so clap refuses them (exit status 2).
    #[test]
    #[parallel(env)]
    fn test_node_and_adapter_are_unknown_subcommands() {
        for gone in ["node", "adapter"] {
            let err = Control::try_parse_from(["ph", gone]).expect_err(gone);
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "{gone}"
            );
            assert_eq!(err.exit_code(), 2, "{gone}");
        }
    }

    /// zl-zipline#234: a Zode is either a relay or dials an initial link,
    /// never neither: with neither it could reach no visa service.
    #[test]
    #[parallel(env)]
    fn test_zode_needs_relay_or_initial_link() {
        let (cfg, _keys) = node_config_file("");
        let err = argparse(Some(vec![
            "ph",
            "zode",
            "-c",
            cfg.get_path().to_str().unwrap(),
        ]))
        .expect_err("neither relay nor initial_link");
        assert!(err.to_string().contains("relay or initial_link"), "{err}");
    }

    /// zl-zipline#234: there is no adapter, so a config file with an
    /// `[adapter]` section is refused, not ignored.
    #[test]
    #[parallel(env)]
    fn test_zode_config_refuses_adapter_section() {
        let (cfg, _keys) = node_config_file_global(
            "",
            "[node.initial_link]\naddr = \"10.0.0.9:5000\"\ncn = \"relay.zpr\"\n\n[adapter]\nnode_addr = \"10.0.0.9:5000\"",
        );
        let err = argparse(Some(vec![
            "ph",
            "zode",
            "-c",
            cfg.get_path().to_str().unwrap(),
        ]))
        .expect_err("[adapter] section");
        assert!(err.to_string().contains("adapter"), "{err}");
    }

    /// zl-zipline#234: no backwards compatibility, so an unknown key is
    /// refused in every section, not ignored: adapter keys in `[global]` and
    /// `[node]`, and a misspelt key in `[authentication]`.
    #[test]
    #[parallel(env)]
    fn test_zode_config_refuses_unknown_keys() {
        for (global_extra, rest, key) in [
            (r#"name = "adapter1""#, DIAL, "name"),
            ("", "auto_connect = true", "auto_connect"),
            (
                "",
                "[authentication]\nauth_private_ky = \"key.pem\"",
                "auth_private_ky",
            ),
        ] {
            let (cfg, _keys) = node_config_file_global(global_extra, rest);
            let err = argparse(Some(vec![
                "ph",
                "zode",
                "-c",
                cfg.get_path().to_str().unwrap(),
            ]))
            .expect_err(key);
            assert!(err.to_string().contains(key), "{key}: {err}");
        }
    }

    /// The shipped example config parses: it names no refused section or key.
    #[test]
    #[parallel(env)]
    fn test_example_node_config_parses() {
        let config: NodeConfig = toml::from_str(include_str!("../example-node-config.toml"))
            .expect("example-node-config.toml must parse");
        assert!(config.node.unwrap().initial_link.is_some());
    }
}
