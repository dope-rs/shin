use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::codec::Reader;
use shin::extension::ExtensionType;
use shin::handshake::{HELLO_RETRY_REQUEST_RANDOM, Handshake};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

mod common;
use common::send;

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

fn strip_key_share(ch_bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(ch_bytes);
    let Handshake::ClientHello(mut ch) = Handshake::decode(&mut r).unwrap() else {
        panic!("not a ClientHello");
    };
    ch.extensions.retain(|e| e.ty != ExtensionType::KEY_SHARE);
    let mut out = Vec::new();
    Handshake::ClientHello(ch).encode(&mut out);
    out
}

fn server_hello_random(blob: &[u8]) -> [u8; 32] {
    let mut r = Reader::new(blob);
    let Handshake::ServerHello(sh) = Handshake::decode(&mut r).unwrap() else {
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
