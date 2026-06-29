use std::sync::Arc;

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme, SupportedCipherSuite};

use shin::asn1::{Reader, Tag};
use shin::cert::Cert;
use shin::client::{Client, Config as ClientConfig, OwnedTrustAnchor, Verifier};
use shin::hash::Digest;
use shin::record::{CipherSuite, ContentType, Opener, PlaintextRecord, Sealer};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

const HOSTNAME: &str = "host.local";

fn extract_ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut r = Reader::new(pkcs8);
    let inner = r.expect(Tag::SEQUENCE).ok()?;
    let mut ir = Reader::new(inner);
    let _version = ir.expect(Tag::INTEGER).ok()?;
    let _alg = ir.expect(Tag::SEQUENCE).ok()?;
    let outer_oct = ir.expect(Tag::OCTET_STRING).ok()?;
    let mut or = Reader::new(outer_oct);
    let inner_oct = or.expect(Tag::OCTET_STRING).ok()?;
    if inner_oct.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_oct);
    Some(seed)
}

struct TestCert {
    cert_der: Vec<u8>,
    pkcs8_der: Vec<u8>,
    signing: SigningKey,
    now_ms: u64,
}

fn gen_ed25519_cert() -> TestCert {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let pkcs8 = key.serialize_der();
    let seed = extract_ed25519_seed(&pkcs8).expect("seed");
    let signing = SigningKey::from_seed(&seed).unwrap();

    let mut params = CertificateParams::new(vec![HOSTNAME.into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOSTNAME);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).unwrap();
    let cert_der = cert.der().to_vec();

    let parsed = Cert::parse(&cert_der).unwrap();
    let nb = shin::time::UnixTime::from_time_value(&parsed.validity.not_before).unwrap();
    let na = shin::time::UnixTime::from_time_value(&parsed.validity.not_after).unwrap();
    let now_ms = ((nb.0 + na.0) / 2) * 1000;

    TestCert {
        cert_der,
        pkcs8_der: pkcs8,
        signing,
        now_ms,
    }
}

fn anchor_for(cert_der: &[u8]) -> OwnedTrustAnchor {
    let view = Cert::parse(cert_der).unwrap();
    OwnedTrustAnchor {
        subject_der: view.subject_der.to_vec(),
        spki_der: view.spki.raw_der.to_vec(),
    }
}

fn rustls_suite(suite: CipherSuite) -> SupportedCipherSuite {
    use rustls::crypto::ring::cipher_suite;
    match suite {
        CipherSuite::Aes128GcmSha256 => cipher_suite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::ChaCha20Poly1305Sha256 => cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::Aes256GcmSha384 => cipher_suite::TLS13_AES_256_GCM_SHA384,
    }
}

fn ring_provider(suite: CipherSuite) -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls_suite(suite)];
    Arc::new(provider)
}

#[derive(Debug)]
struct PinnedServerVerifier {
    cert: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if end_entity.as_ref() == self.cert.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General("unexpected server certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn find_send(events: &[Event], epoch: Epoch) -> Vec<u8> {
    events
        .iter()
        .find_map(|e| match e {
            Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
            _ => None,
        })
        .expect("expected a Send for epoch")
}

fn extract_keys(events: &[Event], epoch: Epoch) -> (Digest, Digest) {
    events
        .iter()
        .find_map(|e| match e {
            Event::KeysReady {
                epoch: ep,
                read_secret,
                write_secret,
            } if *ep == epoch => Some((*read_secret, *write_secret)),
            _ => None,
        })
        .expect("expected KeysReady for epoch")
}

fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done))
}

fn plaintext_record(content_type: ContentType, body: &[u8]) -> Vec<u8> {
    PlaintextRecord::encode(content_type, body).unwrap()
}

fn split_records(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= buf.len() {
        let len = u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize;
        let total = 5 + len;
        if i + total > buf.len() {
            break;
        }
        out.push(buf[i..i + total].to_vec());
        i += total;
    }
    out
}

trait RustlsConn {
    fn rx_tls(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize>;
    fn process(&mut self) -> Result<rustls::IoState, RustlsError>;
    fn tx_tls(&mut self, wr: &mut dyn std::io::Write) -> std::io::Result<usize>;
    fn pending_write(&self) -> bool;
    fn app_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn app_write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
}

macro_rules! impl_rustls_conn {
    ($t:ty) => {
        impl RustlsConn for $t {
            fn rx_tls(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
                self.read_tls(rd)
            }
            fn process(&mut self) -> Result<rustls::IoState, RustlsError> {
                self.process_new_packets()
            }
            fn tx_tls(&mut self, wr: &mut dyn std::io::Write) -> std::io::Result<usize> {
                self.write_tls(wr)
            }
            fn pending_write(&self) -> bool {
                self.wants_write()
            }
            fn app_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                use std::io::Read;
                self.reader().read(buf)
            }
            fn app_write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
                use std::io::Write;
                self.writer().write_all(buf)
            }
        }
    };
}

impl_rustls_conn!(rustls::ServerConnection);
impl_rustls_conn!(rustls::ClientConnection);

fn feed_rustls(conn: &mut dyn RustlsConn, mut data: &[u8]) {
    while !data.is_empty() {
        let n = conn.rx_tls(&mut data).unwrap();
        if n == 0 {
            break;
        }
    }
    conn.process().unwrap();
}

fn drain_rustls(conn: &mut dyn RustlsConn) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.pending_write() {
        conn.tx_tls(&mut out).unwrap();
    }
    out
}

fn rustls_server(suite: CipherSuite, cert: &TestCert) -> rustls::ServerConnection {
    let provider = ring_provider(suite);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.pkcs8_der.clone()));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.cert_der.clone())], key)
        .unwrap();
    config.send_tls13_tickets = 0;
    rustls::ServerConnection::new(Arc::new(config)).unwrap()
}

fn rustls_client(suite: CipherSuite, cert: &TestCert) -> rustls::ClientConnection {
    let provider = ring_provider(suite);
    let verifier = PinnedServerVerifier {
        cert: cert.cert_der.clone(),
        provider: provider.clone(),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let name = ServerName::try_from(HOSTNAME).unwrap();
    rustls::ClientConnection::new(Arc::new(config), name).unwrap()
}

fn shin_client(suite: CipherSuite, cert: &TestCert) -> Client<impl Fn() -> u64> {
    let anchor = anchor_for(&cert.cert_der);
    let now_ms = cert.now_ms;
    let mut client = Client::new(
        ClientConfig {
            verifier: Verifier::X509 {
                anchors: vec![anchor],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now_ms,
    );
    client.set_cipher_suites(&[suite]);
    client
}

fn shin_server(cert: &TestCert) -> Server<impl Fn() -> u64> {
    let now_ms = cert.now_ms;
    Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert.cert_der.clone()],
                signing_key: cert.signing.clone(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        move || now_ms,
    )
}

fn drive_shin_client_vs_rustls_server(suite: CipherSuite) {
    let cert = gen_ed25519_cert();
    let mut server = rustls_server(suite, &cert);
    let mut client = shin_client(suite, &cert);

    // ClientHello -> rustls server.
    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext);
    feed_rustls(&mut server, &plaintext_record(ContentType::Handshake, &ch));

    // Server's first flight: ServerHello (plaintext) [+ CCS] + encrypted EE/Cert/CV/Finished.
    let server_flight = drain_rustls(&mut server);

    let mut hs_opener: Option<Opener> = None;
    let mut hs_sealer: Option<Sealer> = None;
    let mut encrypted_handshake = Vec::new();

    for rec in split_records(&server_flight) {
        match rec[0] {
            x if x == ContentType::Handshake as u8 => {
                let body = &rec[5..];
                let c2 = client.read(Epoch::Plaintext, body).unwrap();
                let (hs_r, hs_w) = extract_keys(&c2, Epoch::Handshake);
                hs_opener = Some(Opener::with_suite(hs_r.as_slice(), suite));
                hs_sealer = Some(Sealer::with_suite(hs_w.as_slice(), suite));
            }
            x if x == ContentType::ChangeCipherSpec as u8 => {}
            x if x == ContentType::ApplicationData as u8 => {
                let opener = hs_opener
                    .as_mut()
                    .expect("handshake keys before ciphertext");
                let mut wire = rec.clone();
                let (inner_type, range, _) = opener.open(&mut wire).unwrap().unwrap();
                assert_eq!(inner_type, ContentType::Handshake);
                encrypted_handshake.extend_from_slice(&wire[range]);
            }
            other => panic!("unexpected record type {other}"),
        }
    }

    let c3 = client.read(Epoch::Handshake, &encrypted_handshake).unwrap();
    assert!(has_done(&c3), "shin client completed handshake");
    let (app_read, app_write) = extract_keys(&c3, Epoch::Application);
    let cf = find_send(&c3, Epoch::Handshake);

    // Client Finished -> rustls server.
    let cf_record = hs_sealer
        .as_mut()
        .unwrap()
        .seal(ContentType::Handshake, &cf)
        .unwrap();
    feed_rustls(&mut server, &cf_record);

    assert!(client.is_done());
    assert!(
        !server.is_handshaking(),
        "rustls server completed handshake"
    );
    assert_eq!(client.negotiated_cipher_suite(), Some(suite));

    let mut app_sealer = Sealer::with_suite(app_write.as_slice(), suite);
    let mut app_opener = Opener::with_suite(app_read.as_slice(), suite);

    // shin client -> rustls server application data.
    let payload_c2s = b"hello from shin client";
    let app_record = app_sealer
        .seal(ContentType::ApplicationData, payload_c2s)
        .unwrap();
    feed_rustls(&mut server, &app_record);
    let mut buf = [0u8; 256];
    let n = server.app_read(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload_c2s);

    // rustls server -> shin client application data.
    let payload_s2c = b"hello from rustls server";
    server.app_write_all(payload_s2c).unwrap();
    let s_app = drain_rustls(&mut server);
    let mut got = Vec::new();
    for rec in split_records(&s_app) {
        if rec[0] == ContentType::ApplicationData as u8 {
            let mut wire = rec.clone();
            let (inner_type, range, _) = app_opener.open(&mut wire).unwrap().unwrap();
            if inner_type == ContentType::ApplicationData {
                got.extend_from_slice(&wire[range]);
            }
        }
    }
    assert_eq!(got, payload_s2c);
}

fn drive_shin_server_vs_rustls_client(suite: CipherSuite) {
    let cert = gen_ed25519_cert();
    let mut client = rustls_client(suite, &cert);
    let mut server = shin_server(&cert);

    // ClientHello from rustls.
    let ch_flight = drain_rustls(&mut client);
    let mut ch_body = None;
    for rec in split_records(&ch_flight) {
        match rec[0] {
            x if x == ContentType::Handshake as u8 => ch_body = Some(rec[5..].to_vec()),
            x if x == ContentType::ChangeCipherSpec as u8 => {}
            other => panic!("unexpected pre-handshake record type {other}"),
        }
    }
    let ch_body = ch_body.expect("ClientHello");

    let s1 = server.read(Epoch::Plaintext, &ch_body).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext);
    let s_hs = find_send(&s1, Epoch::Handshake);
    let (hs_r, hs_w) = extract_keys(&s1, Epoch::Handshake);
    let (ap_r, ap_w) = extract_keys(&s1, Epoch::Application);

    let mut hs_sealer = Sealer::with_suite(hs_w.as_slice(), suite);
    let mut hs_opener = Opener::with_suite(hs_r.as_slice(), suite);

    // ServerHello (plaintext) + encrypted EE/Cert/CV/Finished -> rustls client.
    let mut to_client = plaintext_record(ContentType::Handshake, &sh);
    to_client.extend_from_slice(&hs_sealer.seal(ContentType::Handshake, &s_hs).unwrap());
    feed_rustls(&mut client, &to_client);

    // rustls client's response: [CCS] + encrypted Finished.
    let client_flight = drain_rustls(&mut client);
    let mut client_finished = Vec::new();
    for rec in split_records(&client_flight) {
        match rec[0] {
            x if x == ContentType::ChangeCipherSpec as u8 => {}
            x if x == ContentType::ApplicationData as u8 => {
                let mut wire = rec.clone();
                let (inner_type, range, _) = hs_opener.open(&mut wire).unwrap().unwrap();
                assert_eq!(inner_type, ContentType::Handshake);
                client_finished.extend_from_slice(&wire[range]);
            }
            other => panic!("unexpected record type {other}"),
        }
    }

    let s2 = server.read(Epoch::Handshake, &client_finished).unwrap();
    assert!(has_done(&s2), "shin server completed handshake");
    assert!(server.is_done());
    assert!(
        !client.is_handshaking(),
        "rustls client completed handshake"
    );
    assert_eq!(server.negotiated_cipher_suite(), Some(suite));

    let mut app_sealer = Sealer::with_suite(ap_w.as_slice(), suite);
    let mut app_opener = Opener::with_suite(ap_r.as_slice(), suite);

    // shin server -> rustls client application data.
    let payload_s2c = b"hello from shin server";
    let app_record = app_sealer
        .seal(ContentType::ApplicationData, payload_s2c)
        .unwrap();
    feed_rustls(&mut client, &app_record);
    let mut buf = [0u8; 256];
    let n = client.app_read(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload_s2c);

    // rustls client -> shin server application data.
    let payload_c2s = b"hello from rustls client";
    client.app_write_all(payload_c2s).unwrap();
    let c_app = drain_rustls(&mut client);
    let mut got = Vec::new();
    for rec in split_records(&c_app) {
        if rec[0] == ContentType::ApplicationData as u8 {
            let mut wire = rec.clone();
            let (inner_type, range, _) = app_opener.open(&mut wire).unwrap().unwrap();
            if inner_type == ContentType::ApplicationData {
                got.extend_from_slice(&wire[range]);
            }
        }
    }
    assert_eq!(got, payload_c2s);
}

#[test]
fn shin_client_handshakes_with_rustls_server() {
    drive_shin_client_vs_rustls_server(CipherSuite::Aes128GcmSha256);
}

#[test]
fn shin_client_handshakes_with_rustls_server_chacha20() {
    drive_shin_client_vs_rustls_server(CipherSuite::ChaCha20Poly1305Sha256);
}

#[test]
fn shin_client_handshakes_with_rustls_server_aes256() {
    drive_shin_client_vs_rustls_server(CipherSuite::Aes256GcmSha384);
}

#[test]
fn shin_server_handshakes_with_rustls_client() {
    drive_shin_server_vs_rustls_client(CipherSuite::Aes128GcmSha256);
}

#[test]
fn shin_server_handshakes_with_rustls_client_chacha20() {
    drive_shin_server_vs_rustls_client(CipherSuite::ChaCha20Poly1305Sha256);
}

#[test]
fn shin_server_handshakes_with_rustls_client_aes256() {
    drive_shin_server_vs_rustls_client(CipherSuite::Aes256GcmSha384);
}
