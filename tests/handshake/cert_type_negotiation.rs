//! RFC 7250 cert_type extension negotiation + RFC 9001 QUIC
//! transport_parameters extension gating on the shin server side.
//!
//! Spec rules under test:
//! - The server MUST NOT echo `server_certificate_type` /
//!   `client_certificate_type` extensions in EncryptedExtensions
//!   unless the client offered them (RFC 7250 §4.1).
//! - If the client did offer `server_certificate_type` and the
//!   server's cert format is not in the offered list, the handshake
//!   must fail (RFC 7250 §4.2 — equivalent to "no overlap").
//! - The server MUST NOT include `quic_transport_parameters` in EE
//!   unless the client offered it (RFC 9001 §8.2 — that extension is
//!   QUIC-only; absence means TCP-TLS).
//!
//! Verification strategy: drive a real shin client + shin server pair,
//! capture the server's `Event::Send { epoch: Handshake, data }` —
//! shin emits the EE+Cert+CV+SF concatenation in plaintext (the
//! record-layer AEAD is layered on top by dope-tls or similar
//! wrappers), so the test can decode the handshake messages directly
//! and inspect the EE extensions list. No reliance on whether the
//! shin client tolerates unsolicited extensions.

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};

use shin::client::Client;
use shin::client::config::{Config, OwnedTrustAnchor, Verifier};
use shin::connection::{Epoch, Error};
use shin::crypto::sig::SigningKey;
use shin::identity::CertificateType;
use shin::identity::asn1::{self, Tag};
use shin::server::config::CertSource;
use shin::transport::Mode;
use shin::wire::codec;
use shin::wire::extension::{Extension, Type};
use shin::wire::handshake::frame::Frame;

use crate::common::CollectEvents;
use crate::common::Event;
use crate::common::{Server, ServerConfig, cert_validity_midpoint, find_send};

const HOSTNAME: &str = "host.local";
type TestClock = fn() -> u64;
type RpkPair = (Server<TestClock>, Client<TestClock>);

fn ed25519_self_signed() -> (Vec<u8>, SigningKey) {
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
    (cert.der().to_vec(), signing)
}

fn extract_ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut r = asn1::Reader::new(pkcs8);
    let inner = r.read_tagged(Tag::SEQUENCE).ok()?;
    let mut ir = asn1::Reader::new(inner);
    let _version = ir.read_uint().ok()?;
    let _alg = ir.read_tagged(Tag::SEQUENCE).ok()?;
    let outer_oct = ir.read_tagged(Tag::OCTET_STRING).ok()?;
    let mut or = asn1::Reader::new(outer_oct);
    let inner_oct = or.read_tagged(Tag::OCTET_STRING).ok()?;
    if inner_oct.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_oct);
    Some(seed)
}

/// Pull the EE extensions out of the server's plaintext handshake
/// flight. shin emits the concatenation EE+Cert+CV+SF as a single
/// `Event::Send { Handshake }` payload — record-layer encryption is
/// layered on top elsewhere, so the bytes here are directly decodable.
fn server_ee_extensions(server_events: &[Event]) -> Vec<(u16, Vec<u8>)> {
    let blob = find_send(server_events, Epoch::Handshake)
        .expect("server should emit a Handshake-epoch Send");
    let mut r = codec::Reader::new(&blob);
    while !r.is_empty() {
        let hs = crate::decode_owned(&mut r).expect("decode handshake");
        if let Frame::EncryptedExtensions(ee) = hs {
            return ee
                .extensions
                .iter()
                .map(|e| (e.ty.0, e.data.clone()))
                .collect();
        }
    }
    panic!("EncryptedExtensions message not found in server handshake flight");
}

fn has_ext(ee: &[(u16, Vec<u8>)], ty: Type) -> bool {
    ee.iter().any(|(t, _)| *t == ty.0)
}

fn ext_data(ee: &[(u16, Vec<u8>)], ty: Type) -> Option<&[u8]> {
    ee.iter()
        .find(|(t, _)| *t == ty.0)
        .map(|(_, d)| d.as_slice())
}

fn x509_anchor(cert_der: &[u8]) -> OwnedTrustAnchor {
    OwnedTrustAnchor::from_cert_der(cert_der).unwrap()
}

fn rpk_pair(seed: u8) -> RpkPair {
    let server_key = SigningKey::from_seed(&[seed; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();
    let server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        (|| 0) as TestClock,
    );
    let client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        (|| 0) as TestClock,
    )
    .unwrap();
    (server, client)
}

fn tamper_client_hello(encoded: &[u8], mutate: impl FnOnce(&mut Vec<Extension>)) -> Vec<u8> {
    let mut reader = codec::Reader::new(encoded);
    let Frame::ClientHello(mut hello) = crate::decode_owned(&mut reader).unwrap() else {
        panic!("expected ClientHello");
    };
    mutate(&mut hello.extensions);
    let mut tampered = Vec::new();
    Frame::ClientHello(hello).encode(&mut tampered).unwrap();
    tampered
}

// -------------------------------------------------------------------
// X.509 server + X.509 client (the lsd ingress / curl-style scenario).
// Client does NOT send cert_type extensions because shin client gates
// them on `Verifier::RawPublicKey`. Server MUST NOT echo them.
// transport_params empty on both sides → MUST NOT emit
// quic_transport_parameters either.
// -------------------------------------------------------------------
#[test]
fn x509_server_omits_cert_type_and_quic_tp_when_client_did_not_offer() {
    let (cert_der, signing) = ed25519_self_signed();
    let now = cert_validity_midpoint(&cert_der);

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert_der.clone()],
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: Verifier::X509 {
                anchors: vec![x509_anchor(&cert_der)],
                hostname: HOSTNAME.as_bytes().to_vec(),
                certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        move || now * 1000,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();

    let ee = server_ee_extensions(&s1);
    assert!(
        !has_ext(&ee, Type::SERVER_CERTIFICATE_TYPE),
        "server MUST NOT send server_certificate_type when client did not offer it: ee={ee:?}",
    );
    assert!(
        !has_ext(&ee, Type::CLIENT_CERTIFICATE_TYPE),
        "server MUST NOT send client_certificate_type when client did not offer it: ee={ee:?}",
    );
    assert!(
        !has_ext(&ee, Type::QUIC_TRANSPORT_PARAMETERS),
        "server MUST NOT send quic_transport_parameters in TCP-TLS mode: ee={ee:?}",
    );

    // Sanity: the handshake actually finishes. Validates that
    // suppressing those extensions didn't break the flow.
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    assert!(c3.iter().any(|e| matches!(e, Event::Done)));
}

// -------------------------------------------------------------------
// A QUIC server cannot be downgraded to TLS by a ClientHello that omits the
// mandatory QUIC transport-parameters extension.
// -------------------------------------------------------------------
#[test]
fn quic_server_rejects_tls_client_without_transport_parameters() {
    let (cert_der, signing) = ed25519_self_signed();
    let now = cert_validity_midpoint(&cert_der);

    let mut server = Server::new_with_transport(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert_der.clone()],
                signing_key: signing,
            },
            transport_params: b"server-tp-payload".to_vec(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        Mode::Quic,
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: Verifier::X509 {
                anchors: vec![x509_anchor(&cert_der)],
                hostname: HOSTNAME.as_bytes().to_vec(),
                certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
            },
            transport_params: Vec::new(), // ← TCP-TLS: client doesn't offer
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        move || now * 1000,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    assert_eq!(
        server.read(Epoch::Plaintext, &ch).unwrap_err(),
        shin::connection::Error::IllegalParameter,
    );
}

// -------------------------------------------------------------------
// Client offers QUIC transport_params (= QUIC mode). Server emits its
// configured tp blob in EE, byte-for-byte.
// -------------------------------------------------------------------
#[test]
fn quic_transport_params_round_trip_when_client_offers() {
    let server_key = SigningKey::from_seed(&[0x11u8; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();

    let mut server = Server::new_with_transport(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: b"\xde\xad\xbe\xef-server".to_vec(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        Mode::Quic,
        || 0,
    );
    let mut client = Client::new_with_transport(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: b"\xca\xfe\xba\xbe-client".to_vec(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        Mode::Quic,
        || 0,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let mut encoded = codec::Reader::new(&ch);
    let Frame::ClientHello(client_hello) = crate::decode_owned(&mut encoded).unwrap() else {
        panic!("expected ClientHello");
    };
    assert!(client_hello.legacy_session_id.is_empty());
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();

    let ee = server_ee_extensions(&s1);
    let tp = ext_data(&ee, Type::QUIC_TRANSPORT_PARAMETERS)
        .expect("quic_transport_parameters must be present when client offered");
    assert_eq!(tp, b"\xde\xad\xbe\xef-server");
}

#[test]
fn explicit_quic_emits_empty_transport_parameters_and_empty_session_id() {
    let server_key = SigningKey::from_seed(&[0x12u8; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();
    let mut server = Server::new_with_transport(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        Mode::Quic,
        || 0,
    );
    let mut client = Client::new_with_transport(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        Mode::Quic,
        || 0,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let mut encoded = codec::Reader::new(&ch);
    let Frame::ClientHello(client_hello) = crate::decode_owned(&mut encoded).unwrap() else {
        panic!("expected ClientHello");
    };
    assert!(client_hello.legacy_session_id.is_empty());
    assert_eq!(
        client_hello
            .extensions
            .iter()
            .find(|extension| extension.ty == Type::QUIC_TRANSPORT_PARAMETERS)
            .map(|extension| extension.data.as_slice()),
        Some(&[][..]),
    );

    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let mut encoded = codec::Reader::new(&sh);
    let Frame::ServerHello(server_hello) = crate::decode_owned(&mut encoded).unwrap() else {
        panic!("expected ServerHello");
    };
    assert!(server_hello.legacy_session_id_echo.is_empty());
    let ee = server_ee_extensions(&s1);
    assert_eq!(
        ext_data(&ee, Type::QUIC_TRANSPORT_PARAMETERS),
        Some(&[][..])
    );
}

// -------------------------------------------------------------------
// RPK on both sides — the "negotiate cert_type=RPK" case. Server
// echoes cert_type extensions in EE as a confirmation.
// -------------------------------------------------------------------
#[test]
fn rpk_handshake_echoes_cert_type_extensions() {
    let (mut server, mut client) = rpk_pair(0x22);

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();

    let ee = server_ee_extensions(&s1);
    assert!(
        has_ext(&ee, Type::SERVER_CERTIFICATE_TYPE),
        "RPK negotiation requires server to confirm server_certificate_type: ee={ee:?}",
    );
    assert!(
        has_ext(&ee, Type::CLIENT_CERTIFICATE_TYPE),
        "RPK negotiation requires server to confirm client_certificate_type: ee={ee:?}",
    );
    let s_ct = ext_data(&ee, Type::SERVER_CERTIFICATE_TYPE).unwrap();
    assert_eq!(
        s_ct,
        &[CertificateType::RawPublicKey.wire_id()],
        "server should pick CERT_TYPE_RAW_PUBLIC_KEY (=2)"
    );

    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    assert!(c3.iter().any(|e| matches!(e, Event::Done)));
}

#[test]
fn server_rejects_empty_certificate_type_offer() {
    let (mut server, mut client) = rpk_pair(0x23);
    let started = client.start().unwrap();
    let encoded = find_send(&started, Epoch::Plaintext).unwrap();
    let malformed = tamper_client_hello(&encoded, |extensions| {
        extensions
            .iter_mut()
            .find(|extension| extension.ty == Type::SERVER_CERTIFICATE_TYPE)
            .unwrap()
            .data = vec![0];
    });

    assert_eq!(
        server.read(Epoch::Plaintext, &malformed).unwrap_err(),
        Error::Decode,
    );
}

#[test]
fn server_ignores_unknown_offers_and_selects_known_certificate_type() {
    let (mut server, mut client) = rpk_pair(0x24);
    let started = client.start().unwrap();
    let encoded = find_send(&started, Epoch::Plaintext).unwrap();
    let offered = [2, u8::MAX, CertificateType::RawPublicKey.wire_id()];
    let tampered = tamper_client_hello(&encoded, |extensions| {
        for extension in extensions.iter_mut().filter(|extension| {
            matches!(
                extension.ty,
                Type::SERVER_CERTIFICATE_TYPE | Type::CLIENT_CERTIFICATE_TYPE
            )
        }) {
            extension.data = offered.to_vec();
        }
    });

    let flight = server.read(Epoch::Plaintext, &tampered).unwrap();
    let encrypted_extensions = server_ee_extensions(&flight);
    let selected = [CertificateType::RawPublicKey.wire_id()];
    assert_eq!(
        ext_data(&encrypted_extensions, Type::SERVER_CERTIFICATE_TYPE),
        Some(selected.as_slice()),
    );
    assert_eq!(
        ext_data(&encrypted_extensions, Type::CLIENT_CERTIFICATE_TYPE),
        Some(selected.as_slice()),
    );
}

// -------------------------------------------------------------------
// Mismatch: client demands RPK only (offers cert_type=[RPK]), server
// is configured with X.509. RFC 7250 §4.2 says no overlap → fatal
// alert, handshake aborts.
// -------------------------------------------------------------------
#[test]
fn x509_server_rejects_rpk_only_client_offer() {
    let (cert_der, signing) = ed25519_self_signed();

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert_der.clone()],
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    // RPK verifier on the client → CH carries cert_type=[RPK] only.
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [0xAA; 32], // wrong, but we won't get that far
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let result = server.read(Epoch::Plaintext, &ch);
    assert!(
        result.is_err(),
        "server must abort when its cert format isn't in the client-offered list",
    );
}

// -------------------------------------------------------------------
// ALPN intersection: server lists [h2, http/1.1], client offers
// [http/1.1] → server picks http/1.1 and EE has the ALPN extension.
// -------------------------------------------------------------------
#[test]
fn alpn_intersection_emits_extension() {
    let server_key = SigningKey::from_seed(&[0x33u8; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let ee = server_ee_extensions(&s1);

    let alpn = ext_data(&ee, Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        .expect("ALPN extension must be present after intersection");
    // Wire format: u16 list-len, then per-proto u8 len + bytes.
    assert_eq!(
        alpn,
        &[
            0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
        ],
    );
}

// -------------------------------------------------------------------
// ALPN no-overlap: client offers [http/1.1] but server only allows
// [h2] → server omits the ALPN extension entirely (rather than
// faking one). Some peers treat ALPN absence as "no ALPN agreed".
// -------------------------------------------------------------------
#[test]
fn alpn_no_overlap_aborts() {
    let server_key = SigningKey::from_seed(&[0x44u8; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec()],
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    assert_eq!(
        server.read(Epoch::Plaintext, &ch).unwrap_err(),
        shin::connection::Error::NoApplicationProtocol,
    );
}

// -------------------------------------------------------------------
// Server has ALPN configured but client doesn't offer ALPN at all.
// Server must omit the ALPN extension; nothing was agreed.
// -------------------------------------------------------------------
#[test]
fn alpn_client_silent_omits_extension() {
    let server_key = SigningKey::from_seed(&[0x55u8; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(), // silent
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let ee = server_ee_extensions(&s1);

    assert!(
        !has_ext(&ee, Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        "ALPN absent in CH must produce no ALPN in EE: ee={ee:?}",
    );
}
