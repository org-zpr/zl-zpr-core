//! KeyManager implementation using Noise protocol.
//!
//! Configured to use the "XX" pattern (see Noise paper).  This does not
//! require that initiators know the 25519 public key of the responder.  The
//! idea here is that an adapter wanting to connect to a remote node will
//! validate the certificate which the node sends against a well-known CA
//! certificate and confirm that the certificate's public key matches that
//! exchanged by Noise.
//!
//! The key management messages are all handled by the noise protocol.
//!
//! Transport messages are encoded as follows:
//!
//! ```text
//!
//!    |------- n bytes --------|
//!    [ ZDP payload or message ]
//!
//!
//!    |--- 8 bytes ---||-------- n + 16 bytes ----------|
//!    [     nonce     ][ encrypted buffer               ]
//!
//!    So total extra space needed by encryption is 16 + 8 = 24 bytes.
//! ```
//!
//! Note that the encrypt/decrypt functions expect to operate on entire
//! buffer.  Caller is responsible for dealing with cases when only
//! part of the buffer is to be encrypted or decrypted.
//!
//!
//! Note you can create 32 byte noise keys with the `wg` command line tool on recent versions of linux.
//! For example, to generate a private key: `wg genkey`.  Then you can pass that private key
//! into `wg pubkey` to get the public key.  You can also generate keys using `openssl`, eg
//! `openssl genpkey -algorithm x25519` (but this generates 48 byte keys instead of 32, so
//! you will need to do some editing to get the expected size).

use crate::km::*;
use crate::km_cert_exchange::KmCertExchange;
use crate::logging::targets::KEY_MGMT;
use crate::pki::{self, NOISE_KEY_LEN};
use crate::prelude::*;
use base64::prelude::*;
use bytes::{BufMut, Bytes, BytesMut};
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::fmt::{self, Display, Formatter};
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
static PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

const MSG_BUF_SIZE: usize = 4096;

/// Will transition to error state if we are handshake initator and do not get
/// a handshake response within this time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The plaintext payload a dialing Zode puts in the first Noise XX message of
/// a Zode link (zl-zipline#250). The node it reaches reads it before any link
/// exists, so it can create a Zode link instead of an adapter dock (see
/// `mgmt::dispatch`). Noise mixes the payload into the handshake hash, so a
/// marker changed in transit makes the handshake fail. Adding the marker gains
/// an attacker nothing: a Zode link then demands a CA-signed certificate
/// whose CN passes the acceptance rules.
pub const ZODE_HANDSHAKE_MARKER: &[u8] = b"ZODE1";

/// Whether `noise_msg` is the first message of a Zode handshake. The first
/// Noise XX message is the initiator's ephemeral public key followed by its
/// plaintext payload, which for a Zode is exactly [ZODE_HANDSHAKE_MARKER].
pub fn starts_zode_handshake(noise_msg: &[u8]) -> bool {
    noise_msg.len() == NOISE_KEY_LEN + ZODE_HANDSHAKE_MARKER.len()
        && noise_msg.ends_with(ZODE_HANDSHAKE_MARKER)
}

const NOISE_NONCE_LEN: usize = 8;
pub const NOISE_PADLEN: usize = 16 + NOISE_NONCE_LEN; // 16 byte tag + 8 byte nonce

// The size (in bytes) of the random HMAC key used for messages over which we just compute a hmac.
const HMAC_KEY_LEN: usize = 32;

impl From<snow::Error> for KmError {
    fn from(e: snow::Error) -> KmError {
        KmError::MachineError(e.to_string())
    }
}

pub struct KmNoise {
    settings: KmSettings,
    state: KmSMState,
    /// which message in the handshake sequence is next to send or receive
    msg_nr: u8,
    initiate: bool,
    /// Should we abort if we cannot verify the certificate received from the peer?
    /// (Has no effect if the KmCertificateExchange is not configured for validation.)
    verify_cert: bool,
    /// Zode link (zl-zipline#220): the peer must present a certificate signed
    /// by our CA, whichever end we are. Set only by [KmNoise::new_zode].
    strict: bool,
    local_keypair: NoiseKeypair,
    hs_sent_t: Option<Instant>,
    hs_state: Option<snow::HandshakeState>,
    //t_state: Option<snow::TransportState>,
    /// messages sent to us from peer will use this key (we create this)
    recv_hmac_key: [u8; HMAC_KEY_LEN],
    /// messages sent to peer will use this key (peers creates this)
    send_hmac_key: Option<[u8; HMAC_KEY_LEN]>,
    recv_zpis: ZPIPair,
    send_zpis: Option<ZPIPair>,
    certx: KmCertExchange,
    /// result of key exchange
    peer_cert: Option<PeerCertificate>,
}

/// Should this message number in the Noise handshake sequence carry a ZPI
/// parameter payload.  Which message(s) this is varies by Noise pattern
/// chosen.
fn msg_carries_zpi_payload(msg_nr: u8) -> bool {
    // Our XX pattern has three handshake messages.  We only expect to find
    // a KeyMsg in the payload of the 2nd and 3rd messages: the 1st message
    // is not encrypted.  (Note, msg_nr is 0-based).
    msg_nr == 1 || msg_nr == 2
}

/// Holds a noise keypair.
///
/// Slightly more convenient than a [snow::Keypair] in our context as it implements
/// `Display`, `Debug`, and `Clone`.  Can also easily be converted to/from
/// a [snow::Keypair].  Makes assumption about the crypto algorithm in use.
#[derive(Debug, Clone)]
pub struct NoiseKeypair {
    pub private: [u8; NOISE_KEY_LEN],
    pub public: [u8; NOISE_KEY_LEN],
}

impl NoiseKeypair {
    /// Create keypair from a private key.
    pub fn new(private: [u8; NOISE_KEY_LEN]) -> Self {
        NoiseKeypair {
            private,
            public: derive_public_key(&private),
        }
    }

    /// Create an all zeros keypair (not a valid keypair).
    pub fn new_zeroed() -> Self {
        NoiseKeypair {
            private: [0u8; NOISE_KEY_LEN],
            public: [0u8; NOISE_KEY_LEN],
        }
    }

    /// Generate a new, random keypair.
    pub fn generate() -> Self {
        let pat = PATTERN.parse().unwrap();
        let skp = match snow::Builder::new(pat).generate_keypair() {
            Ok(k) => k,
            Err(e) => {
                panic!("error generating keypair: {:?}", e);
            }
        };
        skp.into()
    }
}

impl From<NoiseKeypair> for snow::Keypair {
    fn from(kp: NoiseKeypair) -> snow::Keypair {
        snow::Keypair {
            private: kp.private.into(),
            public: kp.public.into(),
        }
    }
}

impl From<snow::Keypair> for NoiseKeypair {
    fn from(kp: snow::Keypair) -> NoiseKeypair {
        let mut npk = NoiseKeypair::new_zeroed();
        npk.private.copy_from_slice(&kp.private);
        npk.public.copy_from_slice(&kp.public);
        npk
    }
}

impl Display for NoiseKeypair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NoiseKeypair (private: {}, public: {})",
            BASE64_STANDARD.encode(&self.private),
            BASE64_STANDARD.encode(&self.public)
        )
    }
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
struct KeyMsg {
    pub zpi_full_encr: u8,
    pub zpi_transit_hmac: u8,
    pub hmac_key: [u8; HMAC_KEY_LEN],
}

impl KmNoise {
    /// Create the Noise KeyManager.
    ///
    /// This requires Noise keys.  We also pass certificates through here
    /// so that each side can check for certificate authority signautre.
    ///
    /// The ZPI stuff here is definately first pass. Currently there is no way to change the
    /// ZPI values.  The ZPIs passed in here are sent to the peer for use in messages sent to us.
    ///
    /// - `local_keypair` is optional. If not provided, a new keypair will be generated.
    /// - `zpis` are the ZPI values that the peer should use for messages.
    /// - `certx` is the certificate exchange creator/verifier.
    pub fn new(
        initiate: bool,
        verify_cert: bool,
        local_keypair: Option<NoiseKeypair>,
        zpis: ZPIPair,
        certx: KmCertExchange,
    ) -> Result<Self, KmError> {
        let settings = KmSettings {
            zdp_km_type: KM_ID_NOISE,
            padlen: NOISE_PADLEN,
            alignment: 0,
            tick_interval: Duration::from_millis(500),
        };

        let kp: NoiseKeypair;
        if let Some(kkp) = local_keypair {
            kp = kkp;
        } else {
            kp = NoiseKeypair::generate();
        }
        Ok(KmNoise {
            settings,
            state: KmSMState::Configuring,
            msg_nr: 0,
            initiate,
            verify_cert,
            strict: false,
            local_keypair: kp,
            hs_sent_t: None,
            hs_state: None,
            recv_hmac_key: [0u8; HMAC_KEY_LEN], // we generate this and send to peer
            send_hmac_key: None,                // we get this during handshake
            recv_zpis: zpis,
            send_zpis: None,
            certx,
            peer_cert: None,
        })
    }

    /// Create a noise handshake message with our KeyMsg payload.
    /// Returns a [KmError::HandshakeError] if there is a problem.
    fn create_hs_message(&mut self, hs: &mut snow::HandshakeState) -> Result<Bytes, KmError> {
        let mut payload_buf = BytesMut::with_capacity(MSG_BUF_SIZE);

        if msg_carries_zpi_payload(self.msg_nr) {
            let payload = KeyMsg {
                zpi_full_encr: self.recv_zpis.encr,
                zpi_transit_hmac: self.recv_zpis.hmac,
                hmac_key: self.recv_hmac_key,
            };

            payload_buf.put_slice(payload.as_bytes());
            match self.certx.write_payload(&mut payload_buf) {
                Ok(_) => {}
                Err(e) => {
                    error!(target: KEY_MGMT, "noise: error writing certificate exchange payload: {e:?}");
                    return Err(KmError::CertExchangeError);
                }
            };
        } else if self.msg_nr == 0 && self.strict && self.initiate {
            // A dialing Zode announces a Zode link (zl-zipline#250).
            payload_buf.put_slice(ZODE_HANDSHAKE_MARKER);
        }

        let mut buf = BytesMut::zeroed(MSG_BUF_SIZE);
        match hs.write_message(&payload_buf.freeze(), &mut buf) {
            Ok(len) => {
                self.msg_nr += 1;
                buf.truncate(len);
                Ok(buf.freeze())
            }
            Err(e) => {
                error!(target: KEY_MGMT, "noise: error creating handshake message: {e:?}");
                Err(KmError::HandshakeError)
            }
        }
    }

    /// Create the Noise KeyManager for a Zode-to-Zode link (zl-zipline#220).
    ///
    /// Both ends verify: the handshake aborts unless the peer presents a
    /// certificate signed by our CA whose key is the peer's Noise static key.
    /// A Zode without a CA certificate cannot link at all, so this returns
    /// [KmError::ConfigurationError] when `certx` has no authority certificate.
    pub fn new_zode(
        initiate: bool,
        local_keypair: NoiseKeypair,
        zpis: ZPIPair,
        certx: KmCertExchange,
    ) -> Result<Self, KmError> {
        if !certx.requires_verification() {
            error!(target: KEY_MGMT, "noise: no CA certificate configured; refusing to start a Zode link");
            return Err(KmError::ConfigurationError);
        }
        let mut noise = KmNoise::new(initiate, true, Some(local_keypair), zpis, certx)?;
        noise.strict = true;
        Ok(noise)
    }

    /// Check the certificate the peer presented during the handshake.
    /// Returns the reason for refusing it, if any.
    fn check_peer_cert(&self) -> Result<(), &'static str> {
        let verified = self.peer_cert.as_ref().is_some_and(|c| c.is_verified());
        if self.strict {
            return match &self.peer_cert {
                None => Err("peer presented no certificate, which a Zode link requires"),
                Some(_) if !verified => Err("peer certificate is not signed by our CA"),
                Some(c) if !pki::is_valid_at(c.get_cert(), std::time::SystemTime::now()) => {
                    Err("peer certificate is outside its validity period")
                }
                Some(_) => Ok(()),
            };
        }
        if self.verify_cert && self.certx.requires_verification() && !verified {
            return Err("unable to verify remote certificate");
        }
        Ok(())
    }

    fn parse_km_payload(&mut self, payload: &[u8], peer_public_key: &[u8]) -> KmResult<()> {
        if payload.len() < std::mem::size_of::<KeyMsg>() {
            error!(target: KEY_MGMT, "noise: handshake payload is too short: {}", payload.len());
            return Err(KmError::HandshakeError);
        }

        let Ok((km, _)) = KeyMsg::ref_from_prefix(&payload) else {
            error!(target: KEY_MGMT, "noise: error parsing KeyMsg handshake payload");
            return Err(KmError::HandshakeError);
        };

        self.send_zpis = Some(ZPIPair {
            encr: km.zpi_full_encr,
            hmac: km.zpi_transit_hmac,
        });
        self.send_hmac_key = Some(km.hmac_key);

        // The key exchange payload follows the KeyMsg.
        // The peer may legitimately send no certificate (`None`): the Noise
        // handshake already authenticated its static key.
        let peer_cert = match self
            .certx
            .process_payload(&payload[std::mem::size_of::<KeyMsg>()..], peer_public_key)
        {
            Ok(c) => c,
            Err(e) => {
                error!(
                    target: KEY_MGMT,
                    "noise: error processing certificate exchange payload: {e:?}",
                );
                return Err(KmError::CertExchangeError);
            }
        };
        self.peer_cert = peer_cert;
        Ok(())
    }
}

/// Helper function to derive public key from private key.
#[allow(dead_code)]
pub fn derive_public_key(private_key: &[u8; NOISE_KEY_LEN]) -> [u8; NOISE_KEY_LEN] {
    let point = MontgomeryPoint::mul_base_clamped(*private_key);
    point.to_bytes()
}

struct NoiseCodec {
    snow_state: snow::StatelessTransportState,
    encr_nonce: AtomicU64,
}

impl NoiseCodec {
    fn new(snow_state: snow::StatelessTransportState) -> Self {
        NoiseCodec {
            snow_state,
            encr_nonce: AtomicU64::new(1),
        }
    }
}

impl Codec for NoiseCodec {
    fn max_overhead(self: &Self) -> usize {
        NOISE_PADLEN
    }

    fn encrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError> {
        let nonce = self
            .encr_nonce
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64;
        message[..NOISE_NONCE_LEN].copy_from_slice(&nonce.to_be_bytes());
        match self
            .snow_state
            .write_message(nonce, payload, &mut message[NOISE_NONCE_LEN..])
        {
            Ok(len) => Ok(len + NOISE_NONCE_LEN),
            Err(e) => match e {
                snow::error::Error::Input => Err(EncryptionError::MessageTooLarge),
                _ => panic!("noise encryption failed: {}", e),
            },
        }
    }

    fn decrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, DecryptionError> {
        // nonce is first 8 bytes of the message.
        let plen = payload.len();
        if plen < NOISE_NONCE_LEN {
            error!(target: KEY_MGMT, "noise: message too short");
            return Err(DecryptionError::MessageTooShort);
        }
        let nonce: u64 = u64::from_be_bytes(payload[0..NOISE_NONCE_LEN].try_into().unwrap()); // pretty sure this cannot fail
        match self
            .snow_state
            .read_message(nonce, &payload[NOISE_NONCE_LEN..plen], message)
        {
            Ok(len) => Ok(len),
            Err(e) => match e {
                snow::error::Error::Decrypt => Err(DecryptionError::DecryptFailed),
                _ => Err(DecryptionError::InternalError(format!(
                    "noise failed to decrypt message: {}",
                    e
                ))),
            },
        }
    }
}

struct NullCodec;

impl NullCodec {
    fn new() -> NullCodec {
        NullCodec {}
    }
}

impl Codec for NullCodec {
    fn max_overhead(self: &Self) -> usize {
        0
    }

    fn encrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError> {
        if message.len() < payload.len() {
            return Err(EncryptionError::ParseError);
        }
        message[..payload.len()].copy_from_slice(&payload);

        Ok(payload.len())
    }

    fn decrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, DecryptionError> {
        if message.len() < payload.len() {
            return Err(DecryptionError::ParseError);
        }
        message[..payload.len()].copy_from_slice(&payload);

        Ok(payload.len())
    }
}

impl KeyManagerStateMachine for KmNoise {
    fn get_settings(&self) -> KmSettings {
        self.settings.clone()
    }

    fn get_state(&self) -> KmSMState {
        self.state.clone()
    }

    fn reset(&mut self) -> Result<Option<Bytes>, KmError> {
        self.state = KmSMState::Configuring;
        self.msg_nr = 0;
        let np: snow::params::NoiseParams = match PATTERN.parse() {
            Ok(p) => p,
            Err(e) => {
                error!(target: KEY_MGMT, "noise: error parsing pattern: {e:?}");
                self.state = KmSMState::Error;
                return Err(KmError::ConfigurationError);
            }
        };
        aws_lc_rs::rand::fill(&mut self.recv_hmac_key).expect("OS RNG Failed"); // generate an HMAC key
        self.send_hmac_key = None;
        if self.initiate {
            let mut initiator = match snow::Builder::new(np)
                .local_private_key(self.local_keypair.private.as_ref())
                .unwrap()
                .build_initiator()
            {
                Ok(i) => i,
                Err(e) => {
                    error!(target: KEY_MGMT, "noise: error building initiator: {e:?}");
                    self.state = KmSMState::Error;
                    return Err(KmError::MachineError(format!(
                        "failed to build initiator: {}",
                        e
                    )));
                }
            };
            let hs_msg = match self.create_hs_message(&mut initiator) {
                Ok(m) => m,
                Err(_) => {
                    self.state = KmSMState::Error;
                    return Err(KmError::HandshakeError);
                }
            };
            self.hs_state = Some(initiator);
            self.hs_sent_t = Some(Instant::now());
            Ok(Some(hs_msg))
        } else {
            let responder = match snow::Builder::new(np)
                .local_private_key(self.local_keypair.private.as_ref())
                .unwrap()
                .build_responder()
            {
                Ok(r) => r,
                Err(e) => {
                    error!(target: KEY_MGMT, "noise: error building responder: {e:?}");
                    self.state = KmSMState::Error;
                    return Err(KmError::MachineError(format!(
                        "failed to build responder: {}",
                        e
                    )));
                }
            };
            self.hs_state = Some(responder);
            self.hs_sent_t = None;
            Ok(None)
        }
    }

    // Handle a KM message.
    //
    // Initiator will only get a handshake-reply msg, to which no reply is sent.
    // Responder will only get a handshake-request msg (and return a reply).
    fn handle_message(&mut self, message: &[u8], km_impl: KmId) -> Result<Option<Bytes>, KmError> {
        if self.state != KmSMState::Configuring {
            error!(
                target: KEY_MGMT,
                "noise: handle_message called but not in configuring state: in {:?}",
                self.state
            );
            return Err(KmError::InvalidState);
        }
        assert!(self.hs_state.is_some()); // or a programming error has occurred

        // message received; clear timeout
        self.hs_sent_t = None;

        let mut hs = self.hs_state.take().unwrap();
        let mut payload = BytesMut::zeroed(MSG_BUF_SIZE);
        match hs.read_message(&message[..], &mut payload) {
            Ok(len) => {
                let msg_nr = self.msg_nr;
                self.msg_nr += 1;
                if msg_carries_zpi_payload(msg_nr) {
                    let peer_pubkey = match hs.get_remote_static() {
                        Some(p) => p,
                        None => {
                            error!(target: KEY_MGMT, "noise: no remote public key - cannot do cert exchange");
                            self.state = KmSMState::Error;
                            self.hs_state = Some(hs);
                            return Err(KmError::CertExchangeError);
                        }
                    };
                    match self.parse_km_payload(&payload[..len], peer_pubkey) {
                        Ok(_) => {
                            if let Err(reason) = self.check_peer_cert() {
                                error!(target: KEY_MGMT, "noise: {reason}; aborting handshake");
                                self.state = KmSMState::Error;
                                self.hs_state = Some(hs);
                                return Err(KmError::CertExchangeError);
                            }
                        }

                        // A certificate problem (e.g. its key is not the peer's
                        // static key) stays a CertExchangeError so callers can
                        // tell it from a malformed handshake.
                        Err(e) => {
                            self.state = KmSMState::Error;
                            self.hs_state = Some(hs);
                            return Err(e);
                        }
                    }
                }
            }
            Err(e) => {
                error!(target: KEY_MGMT, "noise: error handling handshake message: {e:?}");
                self.state = KmSMState::Error;
                self.hs_state = Some(hs);
                return Err(KmError::HandshakeError);
            }
        };

        let mut hs_msg: Option<Bytes> = None;

        if !hs.is_handshake_finished() {
            match self.create_hs_message(&mut hs) {
                Ok(m) => {
                    self.hs_sent_t = Some(Instant::now());
                    hs_msg = Some(m);
                }
                Err(_) => {
                    self.hs_state = Some(hs);
                    self.state = KmSMState::Error;
                    return Err(KmError::HandshakeError);
                }
            };
        }

        // Just the act of creating the message above will finish the handshake on the responder.
        // And recieving the response on the intiator will too.
        if hs.is_handshake_finished() {
            let send_zpis = match self.send_zpis {
                Some(z) => z,
                None => {
                    error!(target: KEY_MGMT, "noise: handshake finished by no ZPIs received");
                    self.state = KmSMState::Error;
                    return Err(KmError::HandshakeError);
                }
            };
            let send_key = match self.send_hmac_key {
                Some(h) => h,
                None => {
                    error!(target: KEY_MGMT, "noise: handshake finished by no HMAC key received");
                    self.state = KmSMState::Error;
                    return Err(KmError::HandshakeError);
                }
            };
            let peer_cert = match &self.peer_cert {
                Some(c) => Some(c.clone()),
                None => {
                    warn!(target: KEY_MGMT, "noise: handshake finished but no peer cert received");
                    None
                }
            };
            match hs.into_stateless_transport_mode() {
                Ok(t) => {
                    let codec: Arc<dyn Codec> = match km_impl {
                        KM_ID_NOISE => Arc::new(NoiseCodec::new(t)),
                        KM_ID_NULL => Arc::new(NullCodec::new()),
                        _ => return Err(KmError::HandshakeError),
                    };
                    self.state = KmSMState::Transport(KmTransportSA::new(
                        send_zpis,
                        self.recv_zpis,
                        send_key,
                        self.recv_hmac_key,
                        codec,
                        peer_cert,
                    ));
                }
                Err(e) => {
                    error!(target: KEY_MGMT, "noise: error switching to transport mode: {e:?}");
                    self.state = KmSMState::Error;
                    return Err(KmError::HandshakeError);
                }
            };
        } else {
            self.hs_state = Some(hs);
        }
        return Ok(hs_msg);
    }

    fn tick(&mut self) -> Result<Option<Bytes>, KmError> {
        if self.state == KmSMState::Configuring
            && self.hs_state.is_some()
            && self.hs_sent_t.is_some()
            && Instant::now().duration_since(self.hs_sent_t.unwrap()) > HANDSHAKE_TIMEOUT
        {
            error!(target: KEY_MGMT, "noise: handshake timeout - node-adapter connection failed");
            self.hs_state = None;
            self.hs_sent_t = None;
            self.state = KmSMState::Error;
            return Err(KmError::HandshakeError);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::task::yield_now;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use crate::km;
    use crate::km_testdata::test::*;
    use crate::pki;

    fn test_noise_handshake_common() -> (km::KmTransportSA, km::KmTransportSA) {
        let node_kp = NoiseKeypair::new(
            BASE64_STANDARD
                .decode(NODE_NOISE_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );

        let initiator_exchanger =
            KmCertExchange::new_from_pem(ADAPTER_CERT_DATA, CA_CERT_DATA).unwrap();

        let initiator_keypair = NoiseKeypair::new(
            BASE64_STANDARD
                .decode(ADAPTER_NOISE_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );

        let mut initiator = KmNoise::new(
            true,
            true,
            Some(initiator_keypair),
            ZPIPair::new(1, 2),
            initiator_exchanger,
        )
        .unwrap();
        assert!(initiator.get_state() == KmSMState::Configuring);

        let responder_exchanger =
            KmCertExchange::new_from_pem(NODE_CERT_DATA, CA_CERT_DATA).unwrap();

        let mut responder = KmNoise::new(
            false,
            false,
            Some(node_kp),
            ZPIPair::new(3, 4),
            responder_exchanger,
        )
        .unwrap();
        assert!(responder.get_state() == KmSMState::Configuring);

        let handshake_msg_0 = match initiator.reset() {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake message");
            }
            Err(e) => {
                panic!("error resetting initiator: {:?}", e);
            }
        };
        assert_eq!(
            handshake_msg_0.len(),
            32,
            "unexpected handshake message-0 length",
        );
        assert!(initiator.get_state() == KmSMState::Configuring);

        match responder.reset() {
            Ok(Some(_m)) => panic!("unexpected message from responder.reset!"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("error resetting responder: {:?}", e);
            }
        };

        // -> e
        let handshake_msg_1 = match responder.handle_message(&handshake_msg_0, KM_ID_NOISE) {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake-1 message, got nothing!");
            }
            Err(e) => {
                panic!("responder handle_message failed on handshake-0: {:?}", e);
            }
        };
        assert_eq!(
            handshake_msg_1.len(),
            910,
            "unexpected handshake message-1 length",
        );
        assert!(matches!(responder.get_state(), KmSMState::Configuring));

        // <- e, ee, s, es
        let handshake_msg_2 = match initiator.handle_message(&handshake_msg_1, KM_ID_NOISE) {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake-2 message, got nothing!");
            }
            Err(e) => {
                panic!("initiator.handle_message failed on handshake-1: {:?}", e);
            }
        };
        assert_eq!(
            handshake_msg_2.len(),
            881,
            "unexpected handshake message-2 length",
        );
        assert!(matches!(initiator.get_state(), KmSMState::Transport { .. }));

        // -> s, se
        match responder.handle_message(&handshake_msg_2, KM_ID_NOISE) {
            Ok(Some(_)) => panic!("unexpected additional handshake message from responder"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("responder.handle_message failed on handshake-2: {:?}", e);
            }
        };
        assert!(matches!(responder.get_state(), KmSMState::Transport { .. }));

        let KmSMState::Transport(i_transport) = initiator.get_state() else {
            panic!("unexpected state after handshake");
        };

        let KmSMState::Transport(r_transport) = responder.get_state() else {
            panic!("unexpected state after handshake");
        };

        (i_transport, r_transport)
    }

    #[test]
    fn test_noise_handshake_manually_1() {
        let (i_transport, r_transport) = test_noise_handshake_common();

        // Handshake complete, now we can encrypt/decrypt

        let plaintext = b"hello world";

        let mut out_buf = [0u8; 4096];
        let out_len = match i_transport
            .codec
            .encrypt_transport_stateless(plaintext, &mut out_buf)
        {
            Ok(l) => l,
            Err(e) => {
                panic!("error encrypting message: {:?}", e);
            }
        };

        let expect_ciphertext_len = plaintext.len() + NOISE_PADLEN;

        assert!(
            out_len == expect_ciphertext_len,
            "unexpected encrypted message length, got {}",
            out_len
        );

        let mut in_buf = [0u8; 4096];
        let in_len = match r_transport
            .codec
            .decrypt_transport_stateless(&out_buf[..out_len], &mut in_buf)
        {
            Ok(l) => l,
            Err(e) => {
                panic!("error decrypting message: {:?}", e);
            }
        };

        assert!(
            in_len == plaintext.len(),
            "unexpected decrypted message length, got {}",
            in_len
        );
        assert!(
            in_buf[..in_len] == plaintext[..],
            "unexpected decrypted message content"
        );

        assert!(r_transport.peer_cert.is_some());
        assert!(i_transport.peer_cert.is_some());

        {
            let actual_i_cert = match pki::from_pem(ADAPTER_CERT_DATA.as_bytes()) {
                Ok(cert) => cert,
                Err(e) => {
                    panic!("error constructing cert from PEM data: {}", e);
                }
            };

            // Responder has initiator's cert
            assert_eq!(
                r_transport.peer_cert.unwrap(),
                PeerCertificate::Verified(actual_i_cert)
            );
        }

        {
            let actual_r_cert = match pki::from_pem(NODE_CERT_DATA.as_bytes()) {
                Ok(cert) => cert,
                Err(e) => {
                    panic!("error constructing cert from PEM data: {}", e);
                }
            };

            // Initiator has responder's cert
            assert_eq!(
                i_transport.peer_cert.unwrap(),
                PeerCertificate::Verified(actual_r_cert)
            );
        }
    }

    // An adapter with no certificate (self-generated key) can complete the
    // handshake against a node that does not require the adapter's cert.
    // The node ends up with peer_cert == None; the adapter still requires and
    // verifies the node's cert.
    #[test]
    fn test_noise_handshake_certless_initiator() {
        let node_kp = NoiseKeypair::new(
            BASE64_STANDARD
                .decode(NODE_NOISE_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );

        // Initiator (adapter): no local cert, but has the CA and verifies the node.
        let ca_cert = pki::from_pem(CA_CERT_DATA.as_bytes()).unwrap();
        let initiator_exchanger = KmCertExchange::new(None, Some(ca_cert));

        let mut initiator = KmNoise::new(
            true,
            true,
            None, // self-generated static key
            ZPIPair::new(1, 2),
            initiator_exchanger,
        )
        .unwrap();

        // Responder (node): has a cert, does not verify the adapter's.
        let responder_exchanger =
            KmCertExchange::new_from_pem(NODE_CERT_DATA, CA_CERT_DATA).unwrap();
        let mut responder = KmNoise::new(
            false,
            false,
            Some(node_kp),
            ZPIPair::new(3, 4),
            responder_exchanger,
        )
        .unwrap();

        let handshake_msg_0 = initiator.reset().unwrap().unwrap();
        assert!(responder.reset().unwrap().is_none());

        let handshake_msg_1 = responder
            .handle_message(&handshake_msg_0, KM_ID_NOISE)
            .unwrap()
            .unwrap();
        let handshake_msg_2 = initiator
            .handle_message(&handshake_msg_1, KM_ID_NOISE)
            .unwrap()
            .unwrap();
        assert!(
            responder
                .handle_message(&handshake_msg_2, KM_ID_NOISE)
                .unwrap()
                .is_none()
        );

        let KmSMState::Transport(i_transport) = initiator.get_state() else {
            panic!("initiator not in transport state after handshake");
        };
        let KmSMState::Transport(r_transport) = responder.get_state() else {
            panic!("responder not in transport state after handshake");
        };

        // Node saw no cert from the adapter; adapter verified the node's cert.
        assert!(r_transport.peer_cert.is_none());
        let actual_r_cert = pki::from_pem(NODE_CERT_DATA.as_bytes()).unwrap();
        assert_eq!(
            i_transport.peer_cert.unwrap(),
            PeerCertificate::Verified(actual_r_cert)
        );
    }

    // An initiator that requires verification must abort when the responder
    // presents no certificate at all.
    #[test]
    fn test_noise_handshake_aborts_when_required_cert_missing() {
        // Initiator requires verification (has a CA cert, verify_cert=true).
        let ca_cert = pki::from_pem(CA_CERT_DATA.as_bytes()).unwrap();
        let initiator_exchanger = KmCertExchange::new(None, Some(ca_cert));
        let mut initiator =
            KmNoise::new(true, true, None, ZPIPair::new(1, 2), initiator_exchanger).unwrap();

        // Responder has no certificate.
        let responder_exchanger = KmCertExchange::new(None, None);
        let mut responder =
            KmNoise::new(false, false, None, ZPIPair::new(3, 4), responder_exchanger).unwrap();

        let handshake_msg_0 = initiator.reset().unwrap().unwrap();
        assert!(responder.reset().unwrap().is_none());

        let handshake_msg_1 = responder
            .handle_message(&handshake_msg_0, KM_ID_NOISE)
            .unwrap()
            .unwrap();
        match initiator.handle_message(&handshake_msg_1, KM_ID_NOISE) {
            Err(KmError::CertExchangeError) => {} // expected
            other => panic!("expected CertExchangeError, got {other:?}"),
        }
        assert_eq!(initiator.get_state(), KmSMState::Error);
    }

    // Just make sure that our b64 keys work with the code.
    #[test]
    fn test_noise_handshake_manually_static_node_key() {
        let (initiator_sa, responder_sa) = test_noise_handshake_common();

        // At this point each side should know the others hmac key, and the ZPIs should have been exchanged.

        assert!(initiator_sa.recv_hmac_key != [0u8; HMAC_KEY_LEN]);
        assert!(responder_sa.recv_hmac_key != [0u8; HMAC_KEY_LEN]);

        assert!(initiator_sa.recv_hmac_key == responder_sa.send_hmac_key);
        assert!(responder_sa.recv_hmac_key == initiator_sa.send_hmac_key);

        assert!(initiator_sa.send_zpis.encr == 3);
        assert!(initiator_sa.send_zpis.hmac == 4);

        assert!(responder_sa.send_zpis.encr == 1);
        assert!(responder_sa.send_zpis.hmac == 2);
    }

    #[tokio::test]
    async fn test_noise_handshake_via_km() {
        let node_kp = NoiseKeypair::new(
            BASE64_STANDARD
                .decode(NODE_NOISE_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let adapter_kp = NoiseKeypair::new(
            BASE64_STANDARD
                .decode(ADAPTER_NOISE_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );

        let initiator_exchanger =
            KmCertExchange::new_from_pem(ADAPTER_CERT_DATA, CA_CERT_DATA).unwrap();
        let responder_exchanger =
            KmCertExchange::new_from_pem(NODE_CERT_DATA, CA_CERT_DATA).unwrap();

        let initiator = KmNoise::new(
            true,
            true,
            Some(adapter_kp),
            ZPIPair::new(1, 2),
            initiator_exchanger,
        )
        .unwrap();

        let responder = KmNoise::new(
            false,
            false,
            Some(node_kp),
            ZPIPair::new(3, 4),
            responder_exchanger,
        )
        .unwrap();

        let adapter = km::KeyManager::new(1, Box::new(initiator));
        let node = km::KeyManager::new(1, Box::new(responder));

        let ctok = CancellationToken::new();

        let (n_km_tx, mut n_km_rx) = mpsc::channel(16);
        let (n_sig_tx, mut n_sig_rx) = mpsc::channel(16);
        let n_ctok = ctok.clone();

        let (n_km_payload_tx, n_km_payload_rx) = mpsc::channel(16);
        let (a_km_payload_tx, a_km_payload_rx) = mpsc::channel(16);

        let mut sp_node = node.clone();
        tokio::spawn(async move {
            let _ = sp_node
                .start(n_ctok, n_km_tx, n_sig_tx, n_km_payload_rx, KM_ID_NOISE)
                .await; // Start the node
        });

        let (a_km_tx, mut a_km_rx) = mpsc::channel(16);
        let (a_sig_tx, mut a_sig_rx) = mpsc::channel(16);
        let a_ctok = ctok.clone();

        let mut sp_adapter = adapter.clone();
        tokio::spawn(async move {
            let _ = sp_adapter
                .start(a_ctok, a_km_tx, a_sig_tx, a_km_payload_rx, KM_ID_NOISE)
                .await; // Start the adapter
        });

        yield_now().await;

        // Both adapter and node should reset.
        match timeout(Duration::from_secs(2), n_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(sig) => {
                    match sig.msg {
                        km::KmSignal::Reset => {} // ok!
                        _ => {
                            panic!("unexpected signal from node: {:?}", sig.msg);
                        }
                    }
                }
                None => {
                    panic!("timed out or failed waiting for node state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for node state transition");
            }
        }

        match timeout(Duration::from_secs(2), a_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(sig) => {
                    match sig.msg {
                        km::KmSignal::Reset => {} // ok!
                        _ => {
                            panic!("unexpected signal from adapter: {:?}", sig.msg);
                        }
                    }
                }
                None => {
                    panic!("timed out or failed waiting for adapter state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for adapter state transition");
            }
        }

        // Adapter, as the initiator will send a KM handshake message.
        match timeout(Duration::from_secs(2), a_km_rx.recv()).await {
            Ok(resp) => match resp {
                Some(linkmsg) => {
                    // Node will process message and then should generate a handshake reply on its output channel.
                    n_km_payload_tx.send(linkmsg.msg).await.unwrap();
                }
                None => {
                    panic!("timed out or failed waiting for initial handshake message");
                }
            },
            Err(_) => {
                panic!("timed out waiting for initial handshake message");
            }
        }

        // now I expect a message on the node output channel.
        match timeout(Duration::from_secs(2), n_km_rx.recv()).await {
            Ok(resp) => match resp {
                Some(linkmsg) => {
                    a_km_payload_tx.send(linkmsg.msg).await.unwrap();
                }
                None => {
                    panic!("timed out or failed waiting for handshake message response from node");
                }
            },
            Err(_) => {
                panic!("timed out waiting for handshake message from node");
            }
        }

        // and finally, the adapter responds to the node
        match timeout(Duration::from_secs(2), a_km_rx.recv()).await {
            Ok(resp) => match resp {
                Some(linkmsg) => {
                    n_km_payload_tx.send(linkmsg.msg).await.unwrap();
                }
                None => {
                    panic!(
                        "timed out or failed waiting for handshake message response from adapter"
                    );
                }
            },
            Err(_) => {
                panic!("timed out waiting for handshake message from adapter");
            }
        }

        // And node should have transitioned which will generate two signals: SaIdChange, and SaEstablished
        match timeout(Duration::from_secs(2), n_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(linkmsg) => match linkmsg.msg {
                    km::KmSignal::SaIdChange { old, new } => {
                        assert!(new > 0, "new SA_ID is still zero!");
                        assert!(old == 0, "old SA_ID is not zero!");
                    }
                    _ => {
                        panic!("unexpected signal from node: {:?}", linkmsg.msg);
                    }
                },
                None => {
                    panic!("timed out or failed waiting for node state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for node state transition");
            }
        }
        match timeout(Duration::from_secs(2), n_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(linkmsg) => match linkmsg.msg {
                    km::KmSignal::SaEstablished(ts) => {
                        assert!(ts.sa_id > 0, "SA_ID is still zero!");
                    }
                    _ => {
                        panic!("unexpected signal from node: {:?}", linkmsg.msg);
                    }
                },
                None => {
                    panic!("timed out or failed waiting for SaIdEstablished signal");
                }
            },
            Err(_) => {
                panic!("timed out waiting for node state transition (SaIdEstablished)");
            }
        }

        // We sent the nodes response to the adapter above, so it should also have transitioned now.
        match timeout(Duration::from_secs(2), a_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(linkmsg) => match linkmsg.msg {
                    km::KmSignal::SaIdChange { old, new } => {
                        assert!(new > 0, "new adapter SA_ID is still zero!");
                        assert!(old == 0, "old adapter SA_ID is not zero!");
                    }
                    _ => {
                        panic!("unexpected signal from adapter: {:?}", linkmsg.msg);
                    }
                },
                None => {
                    panic!("timed out or failed waiting for adapter state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for adapter state transition");
            }
        }
        match timeout(Duration::from_secs(2), a_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(linkmsg) => match linkmsg.msg {
                    km::KmSignal::SaEstablished(ts) => {
                        assert!(ts.sa_id > 0, "adapter SA_ID is still zero!");
                    }
                    _ => {
                        panic!("unexpected signal from adapter: {:?}", linkmsg.msg);
                    }
                },
                None => {
                    panic!("timed out or failed waiting for SaIdEstablished signal from adapter");
                }
            },
            Err(_) => {
                panic!("timed out waiting for adapter state transition (SaIdEstablished)");
            }
        }

        let adapter_sa = adapter.get_transport_state().unwrap();
        let node_sa = node.get_transport_state().unwrap();

        // Both should hve same SA-ID (well, that is not required but is consequnce of our setup)
        assert!(
            adapter_sa.sa_id == node_sa.sa_id,
            "SA-ID mismatch: adapter={}, node={}",
            adapter_sa.sa_id,
            node_sa.sa_id
        );

        // ZPIs should be exchanged.
        assert!(
            ZPIPair::new(3, 4) == adapter_sa.send_zpis,
            "adapter send ZPIs mismatch: {:?}",
            adapter_sa.send_zpis
        );
        assert!(ZPIPair::new(1, 2) == adapter_sa.recv_zpis);
        assert!(
            ZPIPair::new(1, 2) == node_sa.send_zpis,
            "node send ZPIs mismatch: {:?}",
            node_sa.send_zpis
        );
        assert!(ZPIPair::new(3, 4) == node_sa.recv_zpis);

        // HMAC keys created
        assert!(adapter_sa.recv_hmac_key != [0u8; HMAC_KEY_LEN]);
        assert!(adapter_sa.send_hmac_key != [0u8; HMAC_KEY_LEN]);
        assert!(node_sa.recv_hmac_key != [0u8; HMAC_KEY_LEN]);
        assert!(node_sa.send_hmac_key != [0u8; HMAC_KEY_LEN]);

        ctok.cancel()
    }

    #[test]
    fn test_null_encrypt() {
        let null_codec = NullCodec::new();

        let payload = [2u8; 32];
        let mut message = [0u8; 32];

        let len = null_codec.encrypt_transport_stateless(&payload, &mut message);

        assert_eq!(len.unwrap(), 32);
        assert_eq!(message, payload);
    }

    #[test]
    fn test_null_decrypt() {
        let null_codec = NullCodec::new();

        let payload = [2u8; 32];
        let mut message = [0u8; 32];

        let len = null_codec.decrypt_transport_stateless(&payload, &mut message);

        assert_eq!(len.unwrap(), 32);
        assert_eq!(message, payload);
    }

    // ---- Zode links (zl-zipline#220): both ends verify the peer certificate. ----
    //
    // The checked-in km_testdata certificates have expired, and Zode links
    // refuse expired certificates, so these tests issue certificates from a
    // throwaway CA (pki::TestCa).

    use x509_cert::time::{Time, Validity};

    /// A validity window from `start` to `end`, each an offset from now
    /// (negative = in the past).
    fn validity(start_secs: i64, end_secs: i64) -> Validity {
        let at = |offset: i64| {
            let now = std::time::SystemTime::now();
            let t = if offset < 0 {
                now - Duration::from_secs(offset.unsigned_abs())
            } else {
                now + Duration::from_secs(offset as u64)
            };
            Time::try_from(t).unwrap()
        };
        Validity::new(at(start_secs), at(end_secs))
    }

    /// A day-long window around now.
    fn valid_now() -> Validity {
        validity(-3600, 86400)
    }

    /// A Zode's certificate exchange: a certificate for `kp` named `cn`,
    /// issued by `issuer` over `window`, trusting `trusted` as its CA.
    fn zode_certx(
        issuer: &pki::TestCa,
        trusted: &pki::TestCa,
        cn: &str,
        kp: &NoiseKeypair,
        window: Validity,
    ) -> KmCertExchange {
        KmCertExchange::new(
            Some(issuer.issue(cn, kp, window)),
            Some(trusted.cert.clone()),
        )
    }

    /// A Zode link end with a certificate from `issuer`, trusting `trusted`.
    fn zode_end(
        initiate: bool,
        issuer: &pki::TestCa,
        trusted: &pki::TestCa,
        cn: &str,
        window: Validity,
    ) -> KmNoise {
        let kp = NoiseKeypair::generate();
        let certx = zode_certx(issuer, trusted, cn, &kp, window);
        let zpis = if initiate {
            ZPIPair::new(1, 2)
        } else {
            ZPIPair::new(3, 4)
        };
        KmNoise::new_zode(initiate, kp, zpis, certx).unwrap()
    }

    /// Which end of a Zode handshake refused, if any.
    #[derive(Debug, PartialEq)]
    enum ZodeHandshakeOutcome {
        Completed,
        /// The initiator refused message 1 (the responder's certificate).
        InitiatorRefused,
        /// The responder refused message 2 (the initiator's certificate).
        ResponderRefused,
    }

    /// Drive the three Noise XX messages between `initiator` and `responder`
    /// and report which end, if any, aborted with `CertExchangeError`.
    fn run_zode_handshake(
        initiator: &mut KmNoise,
        responder: &mut KmNoise,
    ) -> ZodeHandshakeOutcome {
        let msg0 = initiator.reset().unwrap().unwrap();
        assert!(responder.reset().unwrap().is_none());
        let msg1 = responder
            .handle_message(&msg0, KM_ID_NOISE)
            .unwrap()
            .unwrap();
        let msg2 = match initiator.handle_message(&msg1, KM_ID_NOISE) {
            Ok(m) => m.unwrap(),
            Err(KmError::CertExchangeError) => {
                assert_eq!(initiator.get_state(), KmSMState::Error);
                return ZodeHandshakeOutcome::InitiatorRefused;
            }
            Err(e) => panic!("initiator failed with unexpected error {e:?}"),
        };
        match responder.handle_message(&msg2, KM_ID_NOISE) {
            Ok(None) => ZodeHandshakeOutcome::Completed,
            Ok(Some(_)) => panic!("responder sent an unexpected 4th message"),
            Err(KmError::CertExchangeError) => {
                assert_eq!(responder.get_state(), KmSMState::Error);
                ZodeHandshakeOutcome::ResponderRefused
            }
            Err(e) => panic!("responder failed with unexpected error {e:?}"),
        }
    }

    /// Two Zodes with certificates from the network CA link, and each holds
    /// the other's verified certificate.
    #[test]
    fn test_zode_handshake_both_ends_verified() {
        let ca = pki::TestCa::new("zode-ca");
        let mut initiator = zode_end(true, &ca, &ca, "a.zpr", valid_now());
        let mut responder = zode_end(false, &ca, &ca, "b.zpr", valid_now());
        assert_eq!(
            run_zode_handshake(&mut initiator, &mut responder),
            ZodeHandshakeOutcome::Completed
        );
        let (KmSMState::Transport(i), KmSMState::Transport(r)) =
            (initiator.get_state(), responder.get_state())
        else {
            panic!("both ends should be in transport state");
        };
        assert_eq!(
            i.peer_cert.and_then(|c| c.common_name()).as_deref(),
            Some("b.zpr")
        );
        assert!(r.peer_cert.is_some_and(|c| c.is_verified()));
    }

    /// A dialing Zode marks the first message of its handshake, so the
    /// node it reaches can tell a Zode link from an adapter dock before
    /// keying (zl-zipline#250).
    #[test]
    fn test_zode_initiator_marks_first_message() {
        let ca = pki::TestCa::new("zode-ca");
        let mut initiator = zode_end(true, &ca, &ca, "a.zpr", valid_now());
        let msg0 = initiator.reset().unwrap().unwrap();
        assert!(starts_zode_handshake(&msg0));
    }

    /// An adapter's first handshake message carries no marker, and empty
    /// or short input is never a Zode handshake.
    #[test]
    fn test_unmarked_first_messages_are_not_zode_handshakes() {
        let ca = pki::TestCa::new("zode-ca");
        let mut adapter = KmNoise::new(
            true,
            true,
            None,
            ZPIPair::new(1, 2),
            KmCertExchange::new(None, Some(ca.cert.clone())),
        )
        .unwrap();
        let msg0 = adapter.reset().unwrap().unwrap();
        assert!(!starts_zode_handshake(&msg0));
        assert!(!starts_zode_handshake(&[]));
        assert!(!starts_zode_handshake(ZODE_HANDSHAKE_MARKER));
        assert!(!starts_zode_handshake(&msg0[..NOISE_KEY_LEN]));
    }

    /// The marker is part of the handshake hash: a responder that reads a
    /// first message whose marker was changed in transit cannot complete
    /// the handshake with the initiator.
    #[test]
    fn test_changed_marker_breaks_the_handshake() {
        let ca = pki::TestCa::new("zode-ca");
        let mut initiator = zode_end(true, &ca, &ca, "a.zpr", valid_now());
        let mut responder = zode_end(false, &ca, &ca, "b.zpr", valid_now());
        let mut msg0 = initiator.reset().unwrap().unwrap().to_vec();
        *msg0.last_mut().unwrap() ^= 0x01;
        assert!(responder.reset().unwrap().is_none());
        let msg1 = responder
            .handle_message(&msg0, KM_ID_NOISE)
            .unwrap()
            .unwrap();
        assert!(initiator.handle_message(&msg1, KM_ID_NOISE).is_err());
    }

    /// The responder refuses an initiator that presents no certificate.
    #[test]
    fn test_zode_responder_refuses_certless_initiator() {
        let ca = pki::TestCa::new("zode-ca");
        // A peer with the CA but no certificate of its own (sends an empty payload).
        let mut initiator = KmNoise::new(
            true,
            true,
            None,
            ZPIPair::new(1, 2),
            KmCertExchange::new(None, Some(ca.cert.clone())),
        )
        .unwrap();
        let mut responder = zode_end(false, &ca, &ca, "b.zpr", valid_now());
        assert_eq!(
            run_zode_handshake(&mut initiator, &mut responder),
            ZodeHandshakeOutcome::ResponderRefused
        );
    }

    /// The responder refuses a certificate that our CA did not sign.
    #[test]
    fn test_zode_responder_refuses_other_ca() {
        let ca = pki::TestCa::new("zode-ca");
        let other = pki::TestCa::new("other-ca");
        // Signed by another CA, but trusting ours: our responder refuses it.
        let mut initiator = zode_end(true, &other, &ca, "intruder.zpr", valid_now());
        let mut responder = zode_end(false, &ca, &ca, "b.zpr", valid_now());
        assert_eq!(
            run_zode_handshake(&mut initiator, &mut responder),
            ZodeHandshakeOutcome::ResponderRefused
        );
    }

    /// The initiator refuses a responder certificate that our CA did not sign.
    #[test]
    fn test_zode_initiator_refuses_other_ca() {
        let ca = pki::TestCa::new("zode-ca");
        let other = pki::TestCa::new("other-ca");
        let mut initiator = zode_end(true, &ca, &ca, "a.zpr", valid_now());
        let mut responder = zode_end(false, &other, &ca, "intruder.zpr", valid_now());
        assert_eq!(
            run_zode_handshake(&mut initiator, &mut responder),
            ZodeHandshakeOutcome::InitiatorRefused
        );
    }

    /// A certificate whose key is not the peer's Noise static key is refused.
    #[test]
    fn test_zode_responder_refuses_key_mismatch() {
        let ca = pki::TestCa::new("zode-ca");
        // A valid certificate for one key, presented with a different static key.
        let certx = zode_certx(&ca, &ca, "a.zpr", &NoiseKeypair::generate(), valid_now());
        let mut initiator =
            KmNoise::new_zode(true, NoiseKeypair::generate(), ZPIPair::new(1, 2), certx).unwrap();
        let mut responder = zode_end(false, &ca, &ca, "b.zpr", valid_now());
        assert_eq!(
            run_zode_handshake(&mut initiator, &mut responder),
            ZodeHandshakeOutcome::ResponderRefused
        );
    }

    /// A CA-signed certificate outside its validity window is refused,
    /// whether it has expired or is not valid yet (core#102 review).
    #[test]
    fn test_zode_refuses_certificate_outside_validity() {
        let ca = pki::TestCa::new("zode-ca");
        for (label, window) in [
            ("expired", validity(-86400, -60)),
            ("not yet valid", validity(3600, 86400)),
        ] {
            let mut initiator = zode_end(true, &ca, &ca, "a.zpr", window);
            let mut responder = zode_end(false, &ca, &ca, "b.zpr", valid_now());
            assert_eq!(
                run_zode_handshake(&mut initiator, &mut responder),
                ZodeHandshakeOutcome::ResponderRefused,
                "{label} initiator certificate"
            );
        }
        let mut initiator = zode_end(true, &ca, &ca, "a.zpr", valid_now());
        let mut responder = zode_end(false, &ca, &ca, "b.zpr", validity(-86400, -60));
        assert_eq!(
            run_zode_handshake(&mut initiator, &mut responder),
            ZodeHandshakeOutcome::InitiatorRefused,
            "expired responder certificate"
        );
    }

    /// A Zode without a CA certificate cannot start a Zode link at all.
    #[test]
    fn test_zode_link_requires_local_ca() {
        let ca = pki::TestCa::new("zode-ca");
        let kp = NoiseKeypair::generate();
        let own_cert = ca.issue("b.zpr", &kp, valid_now());
        match KmNoise::new_zode(
            false,
            kp,
            ZPIPair::new(3, 4),
            KmCertExchange::new(Some(own_cert), None),
        ) {
            Err(KmError::ConfigurationError) => {}
            Ok(_) => panic!("a Zode link without a CA must be refused"),
            Err(e) => panic!("expected ConfigurationError, got {e:?}"),
        }
    }
}
