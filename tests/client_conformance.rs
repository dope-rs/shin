//! Negative/conformance tests for the client state machine: HelloRetryRequest,
//! unsolicited ServerHello extensions, CertificateVerify scheme strictness, and
//! KeyUpdate flooding bounds.

use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::codec::Reader;
use shin::extension::{Extension, ExtensionType};
use shin::handshake::{Handshake, KeyUpdate, RANDOM_LEN, ServerHello, TLS_1_2};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Error, Event};

const HRR_RANDOM: [u8; RANDOM_LEN] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_1_3: u16 = 0x0304;
const GROUP_X25519: u16 = 0x001d;

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x55u8; 32]).unwrap()
}

fn rpk_client() -> Client<fn() -> u64> {
    Client::new(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    )
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

fn send(events: &[Event], epoch: Epoch) -> Vec<u8> {
    events
        .iter()
        .find_map(|e| match e {
            Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
            _ => None,
        })
        .expect("expected a Send event")
}

/// Drives a full RPK handshake so the returned client is in the post-handshake
/// (Done) state, where KeyUpdate is the only legal message.
fn completed_rpk_client() -> Client<fn() -> u64> {
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
    Extension::new(
        ExtensionType::SUPPORTED_VERSIONS,
        TLS_1_3.to_be_bytes().to_vec(),
    )
}

fn key_share_ext() -> Extension {
    let mut data = Vec::new();
    data.extend_from_slice(&GROUP_X25519.to_be_bytes());
    data.extend_from_slice(&(32u16).to_be_bytes());
    data.extend_from_slice(&[0x07u8; 32]);
    Extension::new(ExtensionType::KEY_SHARE, data)
}

fn server_hello(random: [u8; RANDOM_LEN], extensions: Vec<Extension>) -> Vec<u8> {
    let sh = ServerHello {
        legacy_version: TLS_1_2,
        random,
        legacy_session_id_echo: Vec::new(),
        cipher_suite: SUITE_AES_128_GCM_SHA256,
        legacy_compression_method: 0,
        extensions,
    };
    let mut out = Vec::new();
    Handshake::ServerHello(sh).encode(&mut out);
    out
}

fn hrr_key_share_ext() -> Extension {
    Extension::new(
        ExtensionType::KEY_SHARE,
        GROUP_X25519.to_be_bytes().to_vec(),
    )
}

fn cookie_ext(inner: &[u8]) -> Extension {
    let mut data = Vec::new();
    data.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    data.extend_from_slice(inner);
    Extension::new(ExtensionType::COOKIE, data)
}

#[test]
fn client_answers_hello_retry_request_echoing_cookie() {
    let mut c = rpk_client();
    c.start().unwrap();
    let cookie = cookie_ext(b"server-supplied-cookie");
    let sh = server_hello(
        HRR_RANDOM,
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
    use shin::handshake::{Handshake, HandshakeType};
    let mut r = Reader::new(&retry);
    let Handshake::ClientHello(ch2) = Handshake::decode(&mut r).unwrap() else {
        panic!("retry must be a ClientHello");
    };
    let _ = HandshakeType::ClientHello;
    let echoed = ch2
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::COOKIE)
        .expect("retry must echo the cookie");
    assert_eq!(echoed.data, cookie.data);
}

#[test]
fn client_rejects_second_hello_retry_request() {
    let mut c = rpk_client();
    c.start().unwrap();
    let sh = server_hello(
        HRR_RANDOM,
        vec![supported_versions_ext(), hrr_key_share_ext()],
    );
    c.read(Epoch::Plaintext, &sh).expect("first HRR answered");
    let sh2 = server_hello(
        HRR_RANDOM,
        vec![supported_versions_ext(), hrr_key_share_ext()],
    );
    assert_eq!(
        c.read(Epoch::Plaintext, &sh2).unwrap_err(),
        Error::UnexpectedMessage,
    );
}

#[test]
fn client_rejects_unsolicited_server_hello_extension() {
    let mut c = rpk_client();
    c.start().unwrap();
    // ALPN belongs in EncryptedExtensions, never ServerHello.
    let sh = server_hello(
        [0x42u8; RANDOM_LEN],
        vec![
            supported_versions_ext(),
            key_share_ext(),
            Extension::new(
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
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
    c.start().unwrap();
    let sh = server_hello(
        [0x42u8; RANDOM_LEN],
        vec![supported_versions_ext(), key_share_ext()],
    );
    assert!(c.read(Epoch::Plaintext, &sh).is_ok());
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
        match Handshake::decode(&mut r).unwrap() {
            Handshake::CertificateVerify(mut cv) => {
                cv.algorithm = 0x0403;
                Handshake::CertificateVerify(cv).encode(&mut tampered);
            }
            other => other.encode(&mut tampered),
        }
    }

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        Error::SigSchemeNotOffered
    );
}

fn tamper_ee<F: FnMut(&mut Vec<Extension>)>(flight: &[u8], mut f: F) -> Vec<u8> {
    let mut out = Vec::new();
    let mut r = Reader::new(flight);
    while !r.is_empty() {
        match Handshake::decode(&mut r).unwrap() {
            Handshake::EncryptedExtensions(mut ee) => {
                f(&mut ee.extensions);
                Handshake::EncryptedExtensions(ee).encode(&mut out);
            }
            other => other.encode(&mut out),
        }
    }
    out
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
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
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
fn client_bounds_key_update_flood() {
    let key_updates = |n: usize| {
        let mut blob = Vec::new();
        for _ in 0..n {
            Handshake::KeyUpdate(KeyUpdate { request_update: 0 }).encode(&mut blob);
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
