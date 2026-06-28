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

use shin::asn1::{Reader as Asn1Reader, Tag};
use shin::cert::Cert;
use shin::client::{Client, Config as ClientConfig, OwnedTrustAnchor, Verifier};
use shin::codec::Reader as CodecReader;
use shin::extension::ExtensionType;
use shin::handshake::Handshake;
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

mod common;
use common::find_send;

const HOSTNAME: &str = "host.local";

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
    let mut r = Asn1Reader::new(pkcs8);
    let inner = r.expect(Tag::SEQUENCE).ok()?;
    let mut ir = Asn1Reader::new(inner);
    let _version = ir.expect(Tag::INTEGER).ok()?;
    let _alg = ir.expect(Tag::SEQUENCE).ok()?;
    let outer_oct = ir.expect(Tag::OCTET_STRING).ok()?;
    let mut or = Asn1Reader::new(outer_oct);
    let inner_oct = or.expect(Tag::OCTET_STRING).ok()?;
    if inner_oct.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_oct);
    Some(seed)
}

fn cert_validity_midpoint(cert_der: &[u8]) -> u64 {
    let cert = Cert::parse(cert_der).unwrap();
    let nb = shin::time::UnixTime::from_time_value(&cert.validity.not_before).unwrap();
    let na = shin::time::UnixTime::from_time_value(&cert.validity.not_after).unwrap();
    (nb.0 + na.0) / 2
}

/// Pull the EE extensions out of the server's plaintext handshake
/// flight. shin emits the concatenation EE+Cert+CV+SF as a single
/// `Event::Send { Handshake }` payload — record-layer encryption is
/// layered on top elsewhere, so the bytes here are directly decodable.
fn server_ee_extensions(server_events: &[Event]) -> Vec<(u16, Vec<u8>)> {
    let blob = find_send(server_events, Epoch::Handshake)
        .expect("server should emit a Handshake-epoch Send");
    let mut r = CodecReader::new(&blob);
    while !r.is_empty() {
        let hs = Handshake::decode(&mut r).expect("decode handshake");
        if let Handshake::EncryptedExtensions(ee) = hs {
            return ee
                .extensions
                .iter()
                .map(|e| (e.ty.0, e.data.clone()))
                .collect();
        }
    }
    panic!("EncryptedExtensions message not found in server handshake flight");
}

fn has_ext(ee: &[(u16, Vec<u8>)], ty: ExtensionType) -> bool {
    ee.iter().any(|(t, _)| *t == ty.0)
}

fn ext_data(ee: &[(u16, Vec<u8>)], ty: ExtensionType) -> Option<&[u8]> {
    ee.iter()
        .find(|(t, _)| *t == ty.0)
        .map(|(_, d)| d.as_slice())
}

fn x509_anchor(cert_der: &[u8]) -> OwnedTrustAnchor {
    let cv = Cert::parse(cert_der).unwrap();
    OwnedTrustAnchor {
        subject_der: cv.subject_der.to_vec(),
        spki_der: cv.spki.raw_der.to_vec(),
    }
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
        ClientConfig {
            verifier: Verifier::X509 {
                anchors: vec![x509_anchor(&cert_der)],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now * 1000,
    );

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();

    let ee = server_ee_extensions(&s1);
    assert!(
        !has_ext(&ee, ExtensionType::SERVER_CERTIFICATE_TYPE),
        "server MUST NOT send server_certificate_type when client did not offer it: ee={ee:?}",
    );
    assert!(
        !has_ext(&ee, ExtensionType::CLIENT_CERTIFICATE_TYPE),
        "server MUST NOT send client_certificate_type when client did not offer it: ee={ee:?}",
    );
    assert!(
        !has_ext(&ee, ExtensionType::QUIC_TRANSPORT_PARAMETERS),
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
// X.509 server with non-empty server transport_params, but client
// didn't offer the QUIC extension → server MUST NOT emit it (RFC 9001
// §8.2). Configuring transport_params on a TCP-TLS server should be a
// silent no-op rather than producing an unsolicited extension.
// -------------------------------------------------------------------
#[test]
fn x509_server_with_transport_params_does_not_leak_to_tcp_tls_client() {
    let (cert_der, signing) = ed25519_self_signed();
    let now = cert_validity_midpoint(&cert_der);

    let mut server = Server::new(
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
        || 0,
    );
    let mut client = Client::new(
        ClientConfig {
            verifier: Verifier::X509 {
                anchors: vec![x509_anchor(&cert_der)],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(), // ← TCP-TLS: client doesn't offer
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now * 1000,
    );

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();

    let ee = server_ee_extensions(&s1);
    assert!(
        !has_ext(&ee, ExtensionType::QUIC_TRANSPORT_PARAMETERS),
        "non-empty server tp must NOT leak when client is TCP-TLS: ee={ee:?}",
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

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: b"\xde\xad\xbe\xef-server".to_vec(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: b"\xca\xfe\xba\xbe-client".to_vec(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    );

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();

    let ee = server_ee_extensions(&s1);
    let tp = ext_data(&ee, ExtensionType::QUIC_TRANSPORT_PARAMETERS)
        .expect("quic_transport_parameters must be present when client offered");
    assert_eq!(tp, b"\xde\xad\xbe\xef-server");
}

// -------------------------------------------------------------------
// RPK on both sides — the "negotiate cert_type=RPK" case. Server
// echoes cert_type extensions in EE as a confirmation.
// -------------------------------------------------------------------
#[test]
fn rpk_handshake_echoes_cert_type_extensions() {
    let server_key = SigningKey::from_seed(&[0x22u8; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    );

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();

    let ee = server_ee_extensions(&s1);
    assert!(
        has_ext(&ee, ExtensionType::SERVER_CERTIFICATE_TYPE),
        "RPK negotiation requires server to confirm server_certificate_type: ee={ee:?}",
    );
    assert!(
        has_ext(&ee, ExtensionType::CLIENT_CERTIFICATE_TYPE),
        "RPK negotiation requires server to confirm client_certificate_type: ee={ee:?}",
    );
    let s_ct = ext_data(&ee, ExtensionType::SERVER_CERTIFICATE_TYPE).unwrap();
    assert_eq!(
        s_ct,
        &[2u8],
        "server should pick CERT_TYPE_RAW_PUBLIC_KEY (=2)"
    );

    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    assert!(c3.iter().any(|e| matches!(e, Event::Done)));
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
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [0xAA; 32], // wrong, but we won't get that far
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    );

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
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    );

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let ee = server_ee_extensions(&s1);

    let alpn = ext_data(&ee, ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
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
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    );

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    assert_eq!(
        server.read(Epoch::Plaintext, &ch).unwrap_err(),
        shin::Error::NoApplicationProtocol,
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
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(), // silent
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    );

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let ee = server_ee_extensions(&s1);

    assert!(
        !has_ext(&ee, ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        "ALPN absent in CH must produce no ALPN in EE: ee={ee:?}",
    );
}
