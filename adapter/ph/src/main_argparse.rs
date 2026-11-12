//! ZPR Packet Handler command line arg processing.
//!
//! The main entry point is [argparse] which will parse the command line arguments
//! and any config file, returning a PH configuration. See [crate::config::Config] for
//! more details on the configuration.

use clap::Parser;
use std::io::Read;
use std::path::{self, Path};

use crate::assembly::PhMode;
use crate::main_args::{ArgsError, Command, Control};

use crate::config::{AdapterConfig, Config, NodeConfig};

/// Parse the program arguments, may also parse a configuration file if that has been
/// specified in the arguments.  If all goes well this returns a valid configuration
/// and "mode" for the program.
///
/// The configuration returned will have the correct contents for the [PhMode], but
/// additional checking is still necessary.  For example, file paths specified
/// may not actually exist.
///
/// # Arguments
///
/// `args` - Optional vector of strings representing the command line arguments.
/// If None we parse from `std::env::args_os()`.
pub fn argparse(args: Option<Vec<&str>>) -> std::result::Result<(PhMode, Config), ArgsError> {
    let mut config: Config;
    let ph_mode: PhMode;
    let control = match args {
        Some(args) => Control::parse_from(args),
        None => Control::parse(),
    };

    match control.command {
        Command::Adapter {
            name,
            config_file,
            common,
            node_addr,
            bootstrap_key,
            auto_connect,
        } => {
            ph_mode = PhMode::Adapter;
            let config_file: Option<AdapterConfig> = match config_file {
                Some(p) => match load_config::<AdapterConfig>(&p) {
                    Ok(mut ac) => {
                        ac.config_path = path::absolute(&p).or_else(|e| {
                            Err(ArgsError::PathError(format!(
                                "path error for config file: {:?}",
                                e
                            )))
                        })?;
                        Some(ac)
                    }
                    Err(e) => {
                        return Err(e);
                    }
                },
                None => None,
            };

            config = Config::new_for_adapter(config_file, &common)?;

            // fold in the optional, adapter specific command line args:
            if let Some(cn) = name {
                config.name = cn;
            }
            if let Some(node_addr) = node_addr {
                config.node_addr = Some(node_addr);
            }
            if let Some(bootstrap_key) = bootstrap_key {
                config.bootstrap_key_path = Some(path::absolute(bootstrap_key).or_else(|e| {
                    Err(ArgsError::PathError(format!(
                        "path error for bootstrap key: {:?}",
                        e
                    )))
                })?);
            }
            // Command line overrides the config file; an omitted flag
            // preserves the config file value (or the default, true).
            if let Some(auto_connect) = auto_connect {
                config.auto_connect = auto_connect;
            }
        }

        Command::Node {
            config_file,
            auth_private_key,
            advertised_substrate_addr,
            forwarding,
            initial_link,
            relay,
            common,
        } => {
            ph_mode = PhMode::Node;
            let config_file: Option<NodeConfig> = match config_file {
                Some(p) => match load_config::<NodeConfig>(&p) {
                    Ok(mut ac) => {
                        ac.config_path = path::absolute(&p).or_else(|e| {
                            Err(ArgsError::PathError(format!(
                                "path error for config file: {:?}",
                                e
                            )))
                        })?;
                        Some(ac)
                    }
                    Err(e) => {
                        return Err(e);
                    }
                },
                None => None,
            };
            config = Config::new_for_node(config_file, auth_private_key, &common)?;
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
        }
    }
    config.finalize()?;
    // zipline#39: resolve the invoking user (sudo/pkexec), fold it into the
    // config (derived socket paths become per-uid) and create the per-owner
    // socket directories before validation, so check_valid's parent-directory
    // check passes without pre-provisioning.
    config.apply_socket_owner(admin_api::resolve_socket_owner(|key| {
        std::env::var(key).ok()
    }));
    #[cfg(unix)]
    config.prepare_socket_dirs()?;
    if let Err(e) = config.check_valid(ph_mode) {
        return Err(e);
    }
    Ok((ph_mode, config))
}

// Load a config, either adapter or node, from a TOML file.
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
    fn test_main_args_load_config_adapter() {
        let tomltxt = r#"
        [global]
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        zpr_addr = [ "10.0.0.1" ]
        logging = [ ["zdp", "INFO"] ]


        [adapter]
        node_addr = "192.168.0.2:5000"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let config: AdapterConfig = load_config(tmpfile.get_path()).unwrap();

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
            Some(Vec::from([("zdp".to_string(), "INFO".to_string())]))
        );
        assert_eq!(
            config.adapter.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.global.zpr_addr,
            Some(Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(
                10, 0, 0, 1
            ))]))
        );
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
    fn test_main_args_argparse_adapter_config() {
        let mut tomltxt = r#"
        [global]
        control_path = '$CONTROLFILE'
        self_addr = "192.168.0.1:12345"
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        tun_if = "tun23"
        zpr_addr = [ "10.0.0.1" ]
        logging = [ ["link_state", "DEBUG"] ]


        [adapter]
        node_addr = "192.168.0.2:5000"
        "#;

        let ca_file = TempFile::touch();
        let control_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$CONTROLFILE", control_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(config.control_path, control_file.get_path());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 12345)
        );
        assert_eq!(config.ca_file, Some(ca_file.get_path().into()));
        assert_eq!(config.certificate_file, Some(cert_file.get_path().into()));
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file.get_path().display())
        );
        assert_eq!(config.tun_if, Some("tun23".to_string()));
        assert_eq!(
            config.logging,
            Vec::from([("link_state".to_string(), "DEBUG".to_string())])
        );

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_adapter_config_requires_adapter_section() {
        let tomltxt = r#"
        [global]
        control_path = "/var/run/zpr/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = "tests/ca.pem"
        certificate_file = "tests/certificate.pem"
        private_key_file = "tests/private_key.pem"
        tun_if = "tun23"
        "#;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];
        match argparse(Some(args)) {
            Err(ArgsError::ParseError(_)) => {}
            _ => panic!("Expected ParseError"),
        }
    }

    // You can leave the adapter section blank and provide the details on
    // the command line.
    #[test]
    #[parallel(env)]
    fn test_main_args_adapter_config_blank_adapter() {
        let mut tomltxt = r#"
        [global]
        control_path = "/tmp/control.sock"
        self_addr = "192.168.0.1:12345"
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        tun_if = "tun23"

        [adapter]
        "#;

        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();
        let ca_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--node-addr",
            "192.168.0.2:5000",
            "--zpr-addr",
            "10.0.0.1",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
    }

    // Leave out some stuff in the config file, but specify on command line.
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_adapter_config_override_globs() {
        let mut tomltxt = r#"
        [global]
        control_path = '$CONTROLFILE'
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        zpr_addr = [ "10.0.0.1" ]

        [adapter]
        node_addr = "192.168.0.2:5000"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let control_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$CONTROLFILE", control_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--self-addr",
            "192.168.0.1:12345",
            "--tun-if",
            "tun23",
            "-l",
            "peer_mgmt=DEBUG zdp=TRACE",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

        assert_eq!(config.control_path, control_file.get_path());
        assert_eq!(
            config.self_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 1)), 12345)
        );
        assert_eq!(config.ca_file, Some(ca_file.get_path().into()));
        assert_eq!(config.certificate_file, Some(cert_file.get_path().into()));
        assert_eq!(
            config.noise_private_key_source(),
            format!("file://{}", pk_file.get_path().display())
        );
        assert_eq!(config.tun_if, Some("tun23".to_string()));
        assert_eq!(
            config.logging,
            Vec::from([
                ("peer_mgmt".to_string(), "DEBUG".to_string()),
                ("zdp".to_string(), "TRACE".to_string())
            ])
        );

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
    }

    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_adapter_config_minimal() {
        // Not quite minimal since we need to set control path to make CI happy.
        let mut tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"
        zpr_addr = [ "10.0.0.1" ]

        [adapter]
        node_addr = "192.168.0.2:5000"
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

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Adapter);

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

        assert_eq!(
            config.node_addr,
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 2)),
                5000
            ))
        );
        assert_eq!(
            config.zpr_addr,
            Vec::from([IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        );
    }

    /// `--auto-connect` precedence (zipline#28): an explicitly passed value
    /// overrides the config file; an omitted flag preserves the config file's
    /// value; omitted everywhere defaults to `true` (today's behaviour).
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_adapter_auto_connect() {
        let base_toml = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"
        zpr_addr = [ "10.0.0.1" ]

        [adapter]
        node_addr = "192.168.0.2:5000"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let fill = |toml: &str| -> String {
            toml.replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
                .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
                .replace("$CAFILE", ca_file.get_path().to_str().unwrap())
        };

        // No key in the file, no flag: default true.
        let plain = TempFile::new_toml(&fill(base_toml));
        let args = vec!["ph", "adapter", "-c", plain.get_path().to_str().unwrap()];
        let (_, config) = argparse(Some(args)).unwrap();
        assert!(config.auto_connect, "default must be auto-connect");

        // No key in the file, --auto-connect=false: flag wins.
        let args = vec![
            "ph",
            "adapter",
            "-c",
            plain.get_path().to_str().unwrap(),
            "--auto-connect=false",
        ];
        let (_, config) = argparse(Some(args)).unwrap();
        assert!(!config.auto_connect, "--auto-connect=false must override");

        // Key false in the file, no flag: config value preserved.
        let false_toml = fill(&format!("{base_toml}\n        auto_connect = false\n"));
        let cfg_false = TempFile::new_toml(&false_toml);
        let args = vec![
            "ph",
            "adapter",
            "-c",
            cfg_false.get_path().to_str().unwrap(),
        ];
        let (_, config) = argparse(Some(args)).unwrap();
        assert!(
            !config.auto_connect,
            "omitted flag must preserve the config file value"
        );

        // Key false in the file, --auto-connect=true: flag wins over a
        // contradicting config file.
        let args = vec![
            "ph",
            "adapter",
            "-c",
            cfg_false.get_path().to_str().unwrap(),
            "--auto-connect=true",
        ];
        let (_, config) = argparse(Some(args)).unwrap();
        assert!(
            config.auto_connect,
            "--auto-connect=true must override a config file that says false"
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
        zpr_addr = [ "10.0.0.1" ]
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

        let args = vec!["ph", "node", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Node);

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
            "node",
            "--ca-file",
            &ca_file_fname,
            "--certificate-file",
            &cert_file_fname,
            "--private-key-file",
            &pk_file_fname,
            "--control-path",
            &control_sock,
            "--zpr-addr",
            "10.0.0.1",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Node);

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
            "node",
            "--ca-file",
            &ca_file_fname,
            "--certificate-file",
            &cert_file_fname,
            "--private-key-file",
            &pk_file_fname,
            "--control-path",
            &control_sock,
            "--zpr-addr",
            "10.0.0.1",
            "--self-addr",
            "0.0.0.0:12345",
            "--advertised-substrate-addr",
            "203.0.113.7:12345",
        ];

        let (pmode, config) = argparse(Some(args)).unwrap();

        assert_eq!(pmode, PhMode::Node);
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
        zpr_addr = [ "10.0.0.1" ]

        [node]
        advertised_substrate_addr = "203.0.113.7:6000"
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
            "node",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--advertised-substrate-addr",
            "198.51.100.9:7000",
        ];

        let (_, config) = argparse(Some(args)).unwrap();

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
            "node",
            "--ca-file",
            &ca_file_fname,
            "--certificate-file",
            &cert_file_fname,
            "--private-key-file",
            &pk_file_fname,
            "--control-path",
            &control_sock,
            "--zpr-addr",
            "10.0.0.1",
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
        zpr_addr = [ "10.0.0.1" ]

        [node]
        forwarding = true
        "#
        .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
        .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
        .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        let tmpfile = TempFile::new_toml(&tomltxt);
        let config_path = tmpfile.get_path().to_str().unwrap();

        let (_, config) = argparse(Some(vec!["ph", "node", "-c", config_path])).unwrap();
        assert!(config.forwarding, "the config file turns forwarding on");

        let (_, config) = argparse(Some(vec![
            "ph",
            "node",
            "-c",
            config_path,
            "--forwarding",
            "false",
        ]))
        .unwrap();
        assert!(!config.forwarding, "--forwarding false overrides the file");
    }

    /// The node-only settings in an adapter config file are refused, not
    /// silently ignored: a `[node]` section, and `relay` or `initial_link`
    /// in `[adapter]` (zl-zipline#250).
    #[test]
    #[parallel(env)]
    fn test_main_args_adapter_config_refuses_node_settings() {
        for extra in [
            "[adapter]\nnode_addr = \"10.0.0.9:5000\"\nrelay = false\n",
            "[adapter]\nnode_addr = \"10.0.0.9:5000\"\n[adapter.initial_link]\naddr = \"10.0.0.9:5000\"\ncn = \"r\"\n",
            "[adapter]\nnode_addr = \"10.0.0.9:5000\"\n[node]\nrelay = true\n",
        ] {
            let tomltxt = format!(
                "[global]\ncontrol_path = \"/tmp/control.sock\"\nname = \"adapter\"\n{extra}"
            );
            let tmpfile = TempFile::new_toml(&tomltxt);
            let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];
            match argparse(Some(args)) {
                Err(ArgsError::ParseError(msg)) => {
                    assert!(msg.contains("node"), "unexpected error: {msg}")
                }
                other => panic!("accepted node settings in an adapter config: {other:?}"),
            }
        }
    }

    /// A minimal node config file whose `[node]` section is `node_section`,
    /// with the referenced key files kept alive by the returned guards.
    fn node_config_file(node_section: &str) -> (TempFile, [TempFile; 3]) {
        node_config_file_at("10.0.0.1:12345", node_section)
    }

    /// [node_config_file] with substrate address `self_addr`.
    fn node_config_file_at(self_addr: &str, node_section: &str) -> (TempFile, [TempFile; 3]) {
        let files = [TempFile::touch(), TempFile::touch(), TempFile::touch()];
        let tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"
        self_addr = "$SELFADDR"
        zpr_addr = [ "10.0.0.1" ]

        [node]
        "#
        .replace("$SELFADDR", self_addr)
        .replace("$CAFILE", files[0].get_path().to_str().unwrap())
        .replace("$CERTFILE", files[1].get_path().to_str().unwrap())
        .replace("$PKFILE", files[2].get_path().to_str().unwrap());
        (
            TempFile::new_toml(&format!("{tomltxt}{node_section}\n")),
            files,
        )
    }

    /// `ph node --initial-link CN@IP:PORT` sets the initial link, IPv6 in
    /// brackets too, and overrides the config file (zl-zipline#250).
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_initial_link_cli() {
        let (cfg, _keys) = node_config_file_at("[::1]:12345", "");
        let path = cfg.get_path().to_str().unwrap();
        let (_, config) = argparse(Some(vec![
            "ph",
            "node",
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
        let (_, config) = argparse(Some(vec!["ph", "node", "-c", path])).unwrap();
        assert_eq!(config.initial_link.as_ref().unwrap().cn, "file.zpr");
        let (_, config) = argparse(Some(vec![
            "ph",
            "node",
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
            "node",
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
                argparse(Some(vec!["ph", "node", "-c", path, "--initial-link", bad])).is_err(),
                "accepted --initial-link {bad}"
            );
        }
    }

    /// `ph node --relay` overrides `relay` in the config file, and a relay
    /// with an initial link is refused (a relay never dials, R4).
    #[test]
    #[parallel(env)]
    fn test_main_args_argparse_node_relay_cli() {
        let (cfg, _keys) = node_config_file("relay = true");
        let path = cfg.get_path().to_str().unwrap();
        let (_, config) = argparse(Some(vec!["ph", "node", "-c", path])).unwrap();
        assert!(config.relay);
        let (_, config) =
            argparse(Some(vec!["ph", "node", "-c", path, "--relay", "false"])).unwrap();
        assert!(!config.relay);

        let (cfg, _keys) = node_config_file("");
        let path = cfg.get_path().to_str().unwrap();
        let (_, config) = argparse(Some(vec!["ph", "node", "-c", path])).unwrap();
        assert!(!config.relay, "relay defaults to false");
        assert!(
            argparse(Some(vec![
                "ph",
                "node",
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

    #[test]
    #[serial(env)] // serialize with other tests because we modify process environment
    fn test_main_args_argparse_adapter_key_in_env() {
        let mut tomltxt = r#"
        [global]
        ca_file = '$CAFILE'
        certificate_file = '$CERTFILE'
        control_path = "/tmp/control.sock"
        zpr_addr = [ "10.0.0.1" ]

        [adapter]
        node_addr = "192.168.0.2:5000"
        "#;

        let ca_file = TempFile::touch();
        let cert_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$CAFILE", ca_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);

        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

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

        let (pmode, config) = presult.unwrap();
        assert_eq!(pmode, PhMode::Adapter);
        assert_eq!(
            config.noise_private_key_source(),
            format!("key://{}", noise_key)
        )
    }

    // Adapter without ca_file passes config validation.
    #[test]
    #[parallel(env)]
    fn test_adapter_no_ca_file_passes_validation() {
        let mut tomltxt = r#"
        [global]
        certificate_file = '$CERTFILE'
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"

        [adapter]
        node_addr = "192.168.0.2:5000"
        "#;

        let cert_file = TempFile::touch();
        let pk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$CERTFILE", cert_file.get_path().to_str().unwrap())
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();
        assert_eq!(pmode, PhMode::Adapter);
        assert!(config.ca_file.is_none());
    }

    // Adapter without certificate_file but with name passes config validation.
    #[test]
    #[parallel(env)]
    fn test_adapter_no_cert_with_name_passes_validation() {
        let mut tomltxt = r#"
        [global]
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"

        [adapter]
        name = "my-adapter"
        node_addr = "192.168.0.2:5000"
        "#;

        let pk_file = TempFile::touch();

        let tmp = tomltxt.replace("$PKFILE", pk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        let (pmode, config) = argparse(Some(args)).unwrap();
        assert_eq!(pmode, PhMode::Adapter);
        assert!(config.certificate_file.is_none());
        assert_eq!(config.name, "my-adapter");
    }

    // Adapter without certificate_file and without name fails config validation, even with private key.
    #[test]
    #[parallel(env)]
    fn test_adapter_no_cert_no_name_fails_validation() {
        let mut tomltxt = r#"
        [global]
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"

        [adapter]
        node_addr = "192.168.0.2:5000"
        "#;

        let pk_file = TempFile::touch();

        let tmp = tomltxt.replace("$PKFILE", pk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];

        match argparse(Some(args)) {
            Err(ArgsError::Missing(msg)) => {
                assert!(msg.contains("name"), "expected 'name' in error, got: {msg}");
            }
            other => panic!("expected Missing error, got: {:?}", other),
        }
    }

    // CLI --name overrides config [adapter].name.
    #[test]
    #[parallel(env)]
    fn test_adapter_cli_name_overrides_config_name() {
        let mut tomltxt = r#"
        [global]
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"

        [adapter]
        name = "config-name"
        node_addr = "192.168.0.2:5000"
        "#;

        let pk_file = TempFile::touch();

        let tmp = tomltxt.replace("$PKFILE", pk_file.get_path().to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--name",
            "cli-name",
        ];

        let (_, config) = argparse(Some(args)).unwrap();
        assert_eq!(config.name, "cli-name");
    }

    // CLI --name with config-file bootstrap_key and no certificate_file: bootstrap CN equals CLI name.
    #[test]
    #[parallel(env)]
    fn test_adapter_cli_name_bootstrap_cn_ordering() {
        let bootstrap_key_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/rsa-key.pem");

        let mut tomltxt = r#"
        [global]
        private_key_file = '$PKFILE'
        control_path = "/tmp/control.sock"

        [adapter]
        node_addr = "192.168.0.2:5000"
        bootstrap_key = '$BSKEY'
        "#;

        let pk_file = TempFile::touch();

        let tmp = tomltxt
            .replace("$PKFILE", pk_file.get_path().to_str().unwrap())
            .replace("$BSKEY", bootstrap_key_path.to_str().unwrap());
        tomltxt = &tmp;

        let tmpfile = TempFile::new_toml(&tomltxt);
        let args = vec![
            "ph",
            "adapter",
            "-c",
            tmpfile.get_path().to_str().unwrap(),
            "--name",
            "cli-adapter-name",
        ];

        let (_, config) = argparse(Some(args)).unwrap();
        assert_eq!(config.name, "cli-adapter-name");
        let bootstrap = config.bootstrap.as_ref().expect("bootstrap should be set");
        assert_eq!(bootstrap.cn(), "cli-adapter-name");
    }

    /// Parse a minimal valid adapter config whose `[global]` section carries
    /// `global_extra` verbatim, with `extra_args` appended to the command
    /// line (zipline#154 `control_group` tests).
    fn argparse_adapter_with(
        global_extra: &str,
        extra_args: &[&str],
    ) -> Result<(PhMode, Config), ArgsError> {
        let pk_file = TempFile::touch();
        let tomltxt = format!(
            r#"
        [global]
        private_key_file = '{pk}'
        control_path = "/tmp/control.sock"
        {global_extra}

        [adapter]
        name = "my-adapter"
        node_addr = "192.168.0.2:5000"
        "#,
            pk = pk_file.get_path().to_str().unwrap()
        );
        let tmpfile = TempFile::new_toml(&tomltxt);
        let mut args = vec!["ph", "adapter", "-c", tmpfile.get_path().to_str().unwrap()];
        args.extend_from_slice(extra_args);
        argparse(Some(args))
    }

    /// zipline#154: `control_group` in `[global]` is parsed into the config.
    #[test]
    #[parallel(env)]
    fn test_control_group_from_config_file() {
        let (_, config) = argparse_adapter_with(r#"control_group = "zipline""#, &[]).unwrap();
        assert_eq!(config.control_group.as_deref(), Some("zipline"));
    }

    /// zipline#154: `--control-group` overrides the config file, the same
    /// precedence as `control_path`.
    #[test]
    #[parallel(env)]
    fn test_control_group_flag_overrides_config_file() {
        let (_, config) = argparse_adapter_with(
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
        let (_, config) = argparse_adapter_with("", &["--control-group", "zipline"]).unwrap();
        assert_eq!(config.control_group.as_deref(), Some("zipline"));
    }

    /// zipline#154: no default — absent everywhere means `None`.
    #[test]
    #[parallel(env)]
    fn test_control_group_absent_is_none() {
        let (_, config) = argparse_adapter_with("", &[]).unwrap();
        assert_eq!(config.control_group, None);
    }

    /// zipline#154: invalid group names are rejected, from the config file
    /// and from the flag alike, with an error naming `control_group`.
    #[test]
    #[parallel(env)]
    fn test_control_group_invalid_names_rejected() {
        for bad in ["", "a\\b", "a,b", "a/b", "a:b", "a*b", "a@b", "a\tb"] {
            let line = format!("control_group = {}", toml::Value::String(bad.to_string()));
            let err = argparse_adapter_with(&line, &[]).expect_err(bad);
            assert!(
                err.to_string().contains("control_group"),
                "config {bad:?}: error does not name control_group: {err}"
            );
            let err = argparse_adapter_with("", &["--control-group", bad]).expect_err(bad);
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
            let (_, config) = argparse_adapter_with("", &["--control-group", good]).unwrap();
            assert_eq!(config.control_group.as_deref(), Some(good));
        }
    }
}
