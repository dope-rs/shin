use shin::client::Client;
use shin::client::config::{Config, Verifier};
use shin::connection::{Epoch, Error};
use shin::crypto::sig::SigningKey;
use shin::server::config::CertSource;
use shin::wire::codec::Reader;
use shin::wire::extension::{Extension, Type};
use shin::wire::handshake::HELLO_RETRY_REQUEST_RANDOM;
use shin::wire::handshake::frame::Frame;

use crate::common::CollectEvents;
use crate::common::Event;
use crate::common::{Server, ServerConfig, send};

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x71u8; 32]).unwrap()
}

fn server() -> Server<fn() -> u64> {
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

fn client() -> Client<fn() -> u64> {
    Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        (|| 0) as fn() -> u64,
    )
    .unwrap()
}

fn strip_key_share(ch_bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(ch_bytes);
    let Frame::ClientHello(mut ch) = Frame::decode(&mut r).unwrap() else {
        panic!("not a ClientHello");
    };
    ch.extensions.retain(|e| e.ty != Type::KEY_SHARE);
    let mut out = Vec::new();
    Frame::ClientHello(ch).encode(&mut out).unwrap();
    out
}

fn mutate_client_hello(
    encoded: &[u8],
    mutate: impl FnOnce(&mut shin::wire::handshake::messages::ClientHello),
) -> Vec<u8> {
    let mut reader = Reader::new(encoded);
    let Frame::ClientHello(mut hello) = Frame::decode(&mut reader).unwrap() else {
        panic!("not a ClientHello");
    };
    mutate(&mut hello);
    let mut out = Vec::new();
    Frame::ClientHello(hello).encode(&mut out).unwrap();
    out
}

fn server_hello_random(blob: &[u8]) -> [u8; 32] {
    let mut r = Reader::new(blob);
    let Frame::ServerHello(sh) = Frame::decode(&mut r).unwrap() else {
        panic!("not a ServerHello");
    };
    sh.random
}

#[test]
fn server_sends_hrr_when_key_share_absent() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let ch_no_ks = strip_key_share(&ch);

    let evs = s.read(Epoch::Plaintext, &ch_no_ks).unwrap();
    let hrr = send(&evs, Epoch::Plaintext);
    assert_eq!(
        server_hello_random(&hrr),
        HELLO_RETRY_REQUEST_RANDOM,
        "server must answer a key_share-less ClientHello with HRR",
    );
}

#[test]
fn server_recovers_after_hrr_when_retry_has_key_share() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);

    // First flight: no key_share -> HRR.
    let _ = s.read(Epoch::Plaintext, &strip_key_share(&ch)).unwrap();
    // Retry: a full ClientHello with a key_share -> real ServerHello.
    let evs = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&evs, Epoch::Plaintext);
    assert_ne!(
        server_hello_random(&sh),
        HELLO_RETRY_REQUEST_RANDOM,
        "retry with a key_share must yield a real ServerHello, not a second HRR",
    );
    // The server has produced handshake-epoch traffic, i.e. it progressed.
    assert!(
        evs.iter().any(|e| matches!(
            e,
            Event::Send {
                epoch: Epoch::Handshake,
                ..
            }
        )),
        "server should emit the encrypted handshake flight",
    );
}

#[test]
fn server_aborts_if_retry_still_lacks_key_share() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let ch_no_ks = strip_key_share(&ch);

    let _ = s.read(Epoch::Plaintext, &ch_no_ks).unwrap();
    // A second key_share-less ClientHello must be fatal (only one HRR allowed).
    assert!(s.read(Epoch::Plaintext, &ch_no_ks).is_err());
}

#[test]
fn server_rejects_client_hello_invariant_changes_after_hrr() {
    for mutation in 0..5 {
        let mut s = server();
        let mut c = client();
        let ch = send(&c.start().unwrap(), Epoch::Plaintext);
        s.read(Epoch::Plaintext, &strip_key_share(&ch)).unwrap();

        let ch2 = mutate_client_hello(&ch, |hello| match mutation {
            0 => hello.random[0] ^= 1,
            1 => hello.legacy_session_id[0] ^= 1,
            2 => hello.cipher_suites.reverse(),
            3 => hello.legacy_compression_methods.push(0),
            4 => hello.extensions.push(Extension::new(Type(0xffa5), vec![1])),
            _ => unreachable!(),
        });
        assert_eq!(
            s.read(Epoch::Plaintext, &ch2).unwrap_err(),
            Error::IllegalParameter,
            "CH2 invariant mutation {mutation} must be rejected",
        );
    }
}

#[test]
fn server_allows_only_hrr_permitted_extension_changes() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    s.read(Epoch::Plaintext, &strip_key_share(&ch)).unwrap();

    let ch2 = mutate_client_hello(&ch, |hello| {
        hello
            .extensions
            .push(Extension::new(Type::COOKIE, vec![0, 2, 7, 9]));
        hello.extensions.push(Extension::new(Type(21), vec![0; 31]));
    });
    assert!(s.read(Epoch::Plaintext, &ch2).is_ok());
}

#[test]
fn server_rejects_early_data_retained_after_hrr() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    s.read(Epoch::Plaintext, &strip_key_share(&ch)).unwrap();

    let ch2 = mutate_client_hello(&ch, |hello| {
        hello
            .extensions
            .push(Extension::new(Type::EARLY_DATA, Vec::new()));
    });
    assert_eq!(
        s.read(Epoch::Plaintext, &ch2).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn server_requires_exactly_the_requested_retry_key_share() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    s.read(Epoch::Plaintext, &strip_key_share(&ch)).unwrap();

    let ch2 = mutate_client_hello(&ch, |hello| {
        let share = hello
            .extensions
            .iter_mut()
            .find(|extension| extension.ty == Type::KEY_SHARE)
            .unwrap();
        // Server requested X25519; answer with secp256r1 instead.
        share.data[2..4].copy_from_slice(&0x0017u16.to_be_bytes());
    });
    assert_eq!(
        s.read(Epoch::Plaintext, &ch2).unwrap_err(),
        Error::IllegalParameter,
    );
}
