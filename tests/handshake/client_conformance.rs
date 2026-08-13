//! Negative/conformance tests for the client state machine: HelloRetryRequest,
//! unsolicited ServerHello extensions, CertificateVerify scheme strictness, and
//! KeyUpdate flooding bounds.

use shin::client::Client;
use shin::client::config::{Config, OwnedTrustAnchor, Verifier};
use shin::connection::{self, Epoch, Error};
use shin::crypto::sig::{SignatureScheme, SigningKey};
use shin::server::config::{CertSource, ClientAuth, ClientCertVerifier, ClientIdentity};
use shin::transport::Mode;
use shin::wire::codec::Reader;
use shin::wire::extension::{Extension, Type};
use shin::wire::handshake::Frame;
use shin::wire::handshake::messages::{EncryptedExtensions, KeyUpdate, ServerHello};
use shin::wire::handshake::{KeyUpdateRequest, RANDOM_LEN, TLS_1_2};

use crate::common::CollectEvents;
use crate::common::{Server, ServerConfig, send};

const HRR_RANDOM: [u8; RANDOM_LEN] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_1_3: u16 = 0x0304;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
type TestClient = Client<fn() -> u64>;

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x55u8; 32]).unwrap()
}

fn rpk_client() -> TestClient {
    Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        (|| 0) as fn() -> u64,
    )
    .unwrap()
}

fn x509_client() -> TestClient {
    let root = &webpki_roots::TLS_SERVER_ROOTS[0];
    Client::new(
        Config {
            verifier: Verifier::X509 {
                anchors: vec![OwnedTrustAnchor::from_der_fields(
                    root.subject.as_ref(),
                    root.subject_public_key_info.as_ref(),
                    root.name_constraints.as_ref().map(|value| value.as_ref()),
                )],
                hostname: b"example.com".to_vec(),
                certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        (|| 0) as fn() -> u64,
    )
    .unwrap()
}

fn quic_rpk_client() -> TestClient {
    Client::new_with_transport(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: b"client params".to_vec(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        Mode::Quic,
        (|| 0) as fn() -> u64,
    )
    .unwrap()
}

fn rpk_server() -> Server<fn() -> u64> {
    Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    )
}

struct RejectClientIdentity;

impl ClientCertVerifier for RejectClientIdentity {
    fn verify(&self, _identity: &ClientIdentity<'_>) -> bool {
        false
    }
}

fn client_auth_flight() -> (TestClient, Vec<u8>) {
    let mut server = Server::with_client_auth(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        (|| 0) as fn() -> u64,
        ClientAuth::Requested,
        RejectClientIdentity,
    );
    let mut client = rpk_client();
    let client_start = client.start().unwrap();
    let server_start = server
        .read(Epoch::Plaintext, &send(&client_start, Epoch::Plaintext))
        .unwrap();
    client
        .read(Epoch::Plaintext, &send(&server_start, Epoch::Plaintext))
        .unwrap();
    (client, send(&server_start, Epoch::Handshake))
}

/// Drives a full RPK handshake so the returned client is in the post-handshake
/// (Done) state, where KeyUpdate is the only legal message.
fn completed_rpk_client() -> TestClient {
    let mut server = rpk_server();
    let mut client = rpk_client();
    let c1 = client.start().unwrap();
    let s1 = server
        .read(Epoch::Plaintext, &send(&c1, Epoch::Plaintext))
        .unwrap();
    client
        .read(Epoch::Plaintext, &send(&s1, Epoch::Plaintext))
        .unwrap();
    client
        .read(Epoch::Handshake, &send(&s1, Epoch::Handshake))
        .unwrap();
    assert!(client.is_done());
    client
}

fn supported_versions_ext() -> Extension {
    Extension::new(Type::SUPPORTED_VERSIONS, TLS_1_3.to_be_bytes().to_vec())
}

fn key_share_ext() -> Extension {
    let mut data = Vec::new();
    data.extend_from_slice(&GROUP_X25519.to_be_bytes());
    data.extend_from_slice(&(32u16).to_be_bytes());
    data.extend_from_slice(&[0x07u8; 32]);
    Extension::new(Type::KEY_SHARE, data)
}

fn server_hello(
    random: [u8; RANDOM_LEN],
    session_id_echo: Vec<u8>,
    extensions: Vec<Extension>,
) -> Vec<u8> {
    let sh = ServerHello {
        legacy_version: TLS_1_2,
        random,
        legacy_session_id_echo: session_id_echo,
        cipher_suite: SUITE_AES_128_GCM_SHA256,
        legacy_compression_method: 0,
        extensions,
    };
    let mut out = Vec::new();
    Frame::ServerHello(sh).encode(&mut out).unwrap();
    out
}

fn encrypted_extensions(extensions: Vec<Extension>) -> Vec<u8> {
    let mut out = Vec::new();
    Frame::EncryptedExtensions(EncryptedExtensions { extensions })
        .encode(&mut out)
        .unwrap();
    out
}

fn after_server_hello(mut client: TestClient) -> TestClient {
    let sid = ch_session_id(&send(&client.start().unwrap(), Epoch::Plaintext));
    let hello = server_hello(
        [0x42; RANDOM_LEN],
        sid,
        vec![supported_versions_ext(), key_share_ext()],
    );
    client.read(Epoch::Plaintext, &hello).unwrap();
    client
}

fn ch_session_id(ch_bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(ch_bytes);
    let Frame::ClientHello(ch) = crate::decode_owned(&mut r).unwrap() else {
        panic!("expected ClientHello");
    };
    ch.legacy_session_id
}

fn hrr_key_share_ext() -> Extension {
    Extension::new(Type::KEY_SHARE, GROUP_SECP256R1.to_be_bytes().to_vec())
}

fn cookie_ext(inner: &[u8]) -> Extension {
    let mut data = Vec::new();
    data.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    data.extend_from_slice(inner);
    Extension::new(Type::COOKIE, data)
}

#[test]
fn client_answers_hello_retry_request_echoing_cookie() {
    let mut c = rpk_client();
    let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
    let cookie = cookie_ext(b"server-supplied-cookie");
    let sh = server_hello(
        HRR_RANDOM,
        sid,
        vec![
            supported_versions_ext(),
            hrr_key_share_ext(),
            cookie.clone(),
        ],
    );
    let evs = c
        .read(Epoch::Plaintext, &sh)
        .expect("HRR is answered, not aborted");
    let retry = send(&evs, Epoch::Plaintext);
    use shin::wire::handshake;
    use shin::wire::handshake::Frame;
    let mut r = Reader::new(&retry);
    let Frame::ClientHello(ch2) = crate::decode_owned(&mut r).unwrap() else {
        panic!("retry must be a ClientHello");
    };
    let _ = handshake::Type::ClientHello;
    let echoed = ch2
        .extensions
        .iter()
        .find(|e| e.ty == Type::COOKIE)
        .expect("retry must echo the cookie");
    assert_eq!(echoed.data, cookie.data);
}

#[test]
fn client_rejects_empty_hrr_cookie_during_decode() {
    let mut c = rpk_client();
    let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
    let hrr = server_hello(
        HRR_RANDOM,
        sid,
        vec![
            supported_versions_ext(),
            hrr_key_share_ext(),
            cookie_ext(&[]),
        ],
    );
    assert_eq!(c.read(Epoch::Plaintext, &hrr).unwrap_err(), Error::Decode,);
}

#[test]
fn client_rejects_second_hello_retry_request() {
    let mut c = rpk_client();
    let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
    let sh = server_hello(
        HRR_RANDOM,
        sid.clone(),
        vec![supported_versions_ext(), hrr_key_share_ext()],
    );
    c.read(Epoch::Plaintext, &sh).expect("first HRR answered");
    let sh2 = server_hello(
        HRR_RANDOM,
        sid,
        vec![supported_versions_ext(), hrr_key_share_ext()],
    );
    assert_eq!(
        c.read(Epoch::Plaintext, &sh2).unwrap_err(),
        Error::UnexpectedMessage,
    );
}

#[test]
fn client_rejects_hrr_with_invalid_server_hello_prefix() {
    for mutation in 0..3 {
        let mut c = rpk_client();
        let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
        let encoded = server_hello(
            HRR_RANDOM,
            sid,
            vec![supported_versions_ext(), hrr_key_share_ext()],
        );
        let mut reader = Reader::new(&encoded);
        let Frame::ServerHello(mut hrr) = crate::decode_owned(&mut reader).unwrap() else {
            panic!("expected HRR");
        };
        match mutation {
            0 => hrr.legacy_version = 0x0301,
            1 => hrr.legacy_compression_method = 1,
            2 => hrr.legacy_session_id_echo[0] ^= 1,
            _ => unreachable!(),
        }
        let mut malformed = Vec::new();
        Frame::ServerHello(hrr).encode(&mut malformed).unwrap();
        assert_eq!(
            c.read(Epoch::Plaintext, &malformed).unwrap_err(),
            Error::IllegalParameter,
        );
    }
}

#[test]
fn client_rejects_hrr_request_for_group_already_in_client_hello() {
    let mut c = rpk_client();
    let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
    let hrr = server_hello(
        HRR_RANDOM,
        sid,
        vec![
            supported_versions_ext(),
            Extension::new(Type::KEY_SHARE, GROUP_X25519.to_be_bytes().to_vec()),
        ],
    );
    assert_eq!(
        c.read(Epoch::Plaintext, &hrr).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn client_rejects_unsolicited_server_hello_extension() {
    let mut c = rpk_client();
    let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
    // ALPN belongs in EncryptedExtensions, never ServerHello.
    let sh = server_hello(
        [0x42u8; RANDOM_LEN],
        sid,
        vec![
            supported_versions_ext(),
            key_share_ext(),
            Extension::new(
                Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                vec![0x00, 0x03, 0x02, b'h', b'2'],
            ),
        ],
    );
    assert_eq!(
        c.read(Epoch::Plaintext, &sh).unwrap_err(),
        Error::UnsolicitedExtension
    );
}

#[test]
fn client_accepts_normal_server_hello_with_only_allowed_extensions() {
    let mut c = rpk_client();
    let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
    let sh = server_hello(
        [0x42u8; RANDOM_LEN],
        sid,
        vec![supported_versions_ext(), key_share_ext()],
    );
    assert!(c.read(Epoch::Plaintext, &sh).is_ok());
}

#[test]
fn client_rejects_empty_server_key_exchange_during_decode() {
    let mut c = rpk_client();
    let sid = ch_session_id(&send(&c.start().unwrap(), Epoch::Plaintext));
    let mut empty_share = Vec::new();
    empty_share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    empty_share.extend_from_slice(&0u16.to_be_bytes());
    let sh = server_hello(
        [0x42u8; RANDOM_LEN],
        sid,
        vec![
            supported_versions_ext(),
            Extension::new(Type::KEY_SHARE, empty_share),
        ],
    );
    assert_eq!(c.read(Epoch::Plaintext, &sh).unwrap_err(), Error::Decode,);
}

#[test]
fn client_rejects_certificate_verify_with_unoffered_scheme() {
    let mut server = rpk_server();
    let mut client = rpk_client();

    let c1 = client.start().unwrap();
    let ch = send(&c1, Epoch::Plaintext);
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext);
    let s_hs = send(&s1, Epoch::Handshake);

    client.read(Epoch::Plaintext, &sh).unwrap();

    // Swap CertificateVerify to ECDSA-P256 (0x0403), which an RPK client never offers.
    let mut tampered = Vec::new();
    let mut r = Reader::new(&s_hs);
    while !r.is_empty() {
        match crate::decode_owned(&mut r).unwrap() {
            Frame::CertificateVerify(mut cv) => {
                cv.algorithm = SignatureScheme::ECDSA_SECP256R1_SHA256;
                Frame::CertificateVerify(cv).encode(&mut tampered).unwrap();
            }
            other => other.encode(&mut tampered).unwrap(),
        }
    }

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        Error::SigSchemeNotOffered
    );
}

#[test]
fn client_rejects_main_handshake_certificate_request_context() {
    let (mut client, flight) = client_auth_flight();
    let mut tampered = Vec::new();
    let mut reader = Reader::new(&flight);
    while !reader.is_empty() {
        match crate::decode_owned(&mut reader).unwrap() {
            Frame::CertificateRequest(mut request) => {
                request.certificate_request_context = b"post-handshake-only".to_vec();
                Frame::CertificateRequest(request)
                    .encode(&mut tampered)
                    .unwrap();
            }
            other => other.encode(&mut tampered).unwrap(),
        }
    }

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn client_rejects_repeated_main_handshake_certificate_request() {
    let (mut client, flight) = client_auth_flight();
    let mut tampered = Vec::new();
    let mut reader = Reader::new(&flight);
    while !reader.is_empty() {
        match crate::decode_owned(&mut reader).unwrap() {
            Frame::CertificateRequest(request) => {
                Frame::CertificateRequest(request.clone())
                    .encode(&mut tampered)
                    .unwrap();
                Frame::CertificateRequest(request)
                    .encode(&mut tampered)
                    .unwrap();
            }
            other => other.encode(&mut tampered).unwrap(),
        }
    }

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        Error::UnexpectedMessage,
    );
}

fn tamper_ee<F: FnMut(&mut Vec<Extension>)>(flight: &[u8], mut f: F) -> Vec<u8> {
    let mut out = Vec::new();
    let mut r = Reader::new(flight);
    while !r.is_empty() {
        match crate::decode_owned(&mut r).unwrap() {
            Frame::EncryptedExtensions(mut ee) => {
                f(&mut ee.extensions);
                Frame::EncryptedExtensions(ee).encode(&mut out).unwrap();
            }
            other => other.encode(&mut out).unwrap(),
        }
    }
    out
}

fn rpk_server_flight() -> (TestClient, Vec<u8>) {
    let mut server = rpk_server();
    let mut client = rpk_client();
    let client_start = client.start().unwrap();
    let server_start = server
        .read(Epoch::Plaintext, &send(&client_start, Epoch::Plaintext))
        .unwrap();
    client
        .read(Epoch::Plaintext, &send(&server_start, Epoch::Plaintext))
        .unwrap();
    (client, send(&server_start, Epoch::Handshake))
}

#[derive(Default)]
struct PeerExtensionCounter(usize);

impl connection::EventSink for PeerExtensionCounter {
    type Error = std::convert::Infallible;

    fn event(
        &mut self,
        event: connection::Event<'_>,
        _context: connection::EventContext,
    ) -> Result<(), Self::Error> {
        if matches!(event, connection::Event::PeerExtension { .. }) {
            self.0 += 1;
        }
        Ok(())
    }
}

#[test]
fn client_validates_server_name_acknowledgement_body() {
    let mut valid = after_server_hello(x509_client());
    assert!(
        valid
            .read(
                Epoch::Handshake,
                &encrypted_extensions(vec![Extension::new(Type::SERVER_NAME, vec![])]),
            )
            .is_ok()
    );

    let mut malformed = after_server_hello(x509_client());
    assert_eq!(
        malformed
            .read(
                Epoch::Handshake,
                &encrypted_extensions(vec![Extension::new(Type::SERVER_NAME, vec![0])]),
            )
            .unwrap_err(),
        Error::Decode,
    );
}

#[test]
fn client_rejects_server_name_acknowledgement_when_sni_was_not_offered() {
    let mut client = after_server_hello(rpk_client());
    assert_eq!(
        client
            .read(
                Epoch::Handshake,
                &encrypted_extensions(vec![Extension::new(Type::SERVER_NAME, vec![])]),
            )
            .unwrap_err(),
        Error::UnsolicitedExtension,
    );
}

#[test]
fn client_validates_server_supported_groups_body() {
    let mut valid = after_server_hello(x509_client());
    assert!(
        valid
            .read(
                Epoch::Handshake,
                &encrypted_extensions(vec![Extension::new(
                    Type::SUPPORTED_GROUPS,
                    vec![0, 2, 0, 29],
                )]),
            )
            .is_ok()
    );

    for invalid in [
        vec![],
        vec![0, 0],
        vec![0, 1, 0],
        vec![0, 2, 0],
        vec![0, 2, 0, 29, 0],
    ] {
        let mut client = after_server_hello(x509_client());
        assert_eq!(
            client
                .read(
                    Epoch::Handshake,
                    &encrypted_extensions(vec![Extension::new(Type::SUPPORTED_GROUPS, invalid)]),
                )
                .unwrap_err(),
            Error::Decode,
        );
    }
}

#[test]
fn client_emits_no_peer_extension_before_all_encrypted_extensions_validate() {
    let mut client = after_server_hello(quic_rpk_client());
    let flight = encrypted_extensions(vec![
        Extension::new(Type::QUIC_TRANSPORT_PARAMETERS, b"server params".to_vec()),
        Extension::new(Type::SUPPORTED_GROUPS, vec![0, 0]),
        Extension::new(Type::SERVER_CERTIFICATE_TYPE, vec![2]),
        Extension::new(Type::CLIENT_CERTIFICATE_TYPE, vec![2]),
    ]);
    let mut events = PeerExtensionCounter::default();
    let error = client
        .read_into(Epoch::Handshake, &flight, &mut events)
        .unwrap_err();
    assert!(matches!(
        error,
        connection::DriveError::Protocol(Error::Decode)
    ));
    assert_eq!(events.0, 0);
}

#[test]
fn client_rejects_unsolicited_encrypted_extension() {
    let mut server = rpk_server();
    let mut client = rpk_client();
    let c1 = client.start().unwrap();
    let s1 = server
        .read(Epoch::Plaintext, &send(&c1, Epoch::Plaintext))
        .unwrap();
    client
        .read(Epoch::Plaintext, &send(&s1, Epoch::Plaintext))
        .unwrap();

    let tampered = tamper_ee(&send(&s1, Epoch::Handshake), |exts| {
        exts.push(Extension::new(
            Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            vec![0x00, 0x03, 0x02, b'h', b'2'],
        ));
    });

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        Error::UnsolicitedExtension
    );
}

#[test]
fn client_rejects_duplicate_encrypted_extension() {
    let mut server = rpk_server();
    let mut client = rpk_client();
    let c1 = client.start().unwrap();
    let s1 = server
        .read(Epoch::Plaintext, &send(&c1, Epoch::Plaintext))
        .unwrap();
    client
        .read(Epoch::Plaintext, &send(&s1, Epoch::Plaintext))
        .unwrap();

    let tampered = tamper_ee(&send(&s1, Epoch::Handshake), |exts| {
        if let Some(first) = exts.first().cloned() {
            exts.push(first);
        }
    });

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        Error::Decode
    );
}

#[test]
fn client_rejects_invalid_certificate_type_confirmation() {
    for invalid in [vec![], vec![0], vec![2, 2], vec![u8::MAX]] {
        let (mut client, flight) = rpk_server_flight();
        let tampered = tamper_ee(&flight, |extensions| {
            extensions
                .iter_mut()
                .find(|extension| extension.ty == Type::SERVER_CERTIFICATE_TYPE)
                .unwrap()
                .data = invalid.clone();
        });

        assert_eq!(
            client.read(Epoch::Handshake, &tampered).unwrap_err(),
            Error::IllegalParameter,
        );
    }
}

#[test]
fn client_requires_certificate_type_confirmations() {
    for missing in [Type::SERVER_CERTIFICATE_TYPE, Type::CLIENT_CERTIFICATE_TYPE] {
        let (mut client, flight) = rpk_server_flight();
        let tampered = tamper_ee(&flight, |extensions| {
            extensions.retain(|extension| extension.ty != missing);
        });

        assert_eq!(
            client.read(Epoch::Handshake, &tampered).unwrap_err(),
            Error::MissingExtension,
        );
    }
}

#[test]
fn client_bounds_key_update_flood() {
    let key_updates = |n: usize| {
        let mut blob = Vec::new();
        for _ in 0..n {
            Frame::KeyUpdate(KeyUpdate {
                request: KeyUpdateRequest::NotRequested,
            })
            .encode(&mut blob)
            .unwrap();
        }
        blob
    };
    let mut c = completed_rpk_client();
    // 8 is the cap; a 9th in the same record is rejected.
    assert!(c.read(Epoch::Application, &key_updates(8)).is_ok());
    assert_eq!(
        c.read(Epoch::Application, &key_updates(9)).unwrap_err(),
        Error::UnexpectedMessage
    );
}

#[test]
fn client_bounds_key_update_flood_across_records() {
    let one_key_update = || {
        let mut blob = Vec::new();
        Frame::KeyUpdate(KeyUpdate {
            request: KeyUpdateRequest::NotRequested,
        })
        .encode(&mut blob)
        .unwrap();
        blob
    };
    let mut c = completed_rpk_client();
    // One KeyUpdate per record, no intervening application data: bounded.
    for _ in 0..8 {
        c.read(Epoch::Application, &one_key_update()).unwrap();
    }
    assert_eq!(
        c.read(Epoch::Application, &one_key_update()).unwrap_err(),
        Error::UnexpectedMessage
    );
}

#[test]
fn client_accepts_key_updates_interleaved_with_app_data() {
    let one_key_update = || {
        let mut blob = Vec::new();
        Frame::KeyUpdate(KeyUpdate {
            request: KeyUpdateRequest::NotRequested,
        })
        .encode(&mut blob)
        .unwrap();
        blob
    };
    let mut c = completed_rpk_client();
    // Application-data progress between KeyUpdates resets the flood counter, so a
    // legitimate peer can key-update for the life of the connection.
    for _ in 0..1000 {
        c.read(Epoch::Application, &one_key_update()).unwrap();
        c.key_updates().note_application_data();
    }
}
