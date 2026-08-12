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
            enable_early_data: false,
        },
        (|| 0) as fn() -> u64,
    )
    .unwrap()
}

fn remove_key_share(ch_bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(ch_bytes);
    let Frame::ClientHello(mut ch) = crate::decode_owned(&mut r).unwrap() else {
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
    let Frame::ClientHello(mut hello) = crate::decode_owned(&mut reader).unwrap() else {
        panic!("not a ClientHello");
    };
    mutate(&mut hello);
    let mut out = Vec::new();
    Frame::ClientHello(hello).encode(&mut out).unwrap();
    out
}

fn empty_key_share(ch_bytes: &[u8]) -> Vec<u8> {
    mutate_client_hello(ch_bytes, |hello| set_key_shares(hello, &[]))
}

fn set_supported_groups(hello: &mut shin::wire::handshake::messages::ClientHello, groups: &[u16]) {
    let extension = hello
        .extensions
        .iter_mut()
        .find(|extension| extension.ty == Type::SUPPORTED_GROUPS)
        .unwrap();
    extension.data.clear();
    extension
        .data
        .extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for group in groups {
        extension.data.extend_from_slice(&group.to_be_bytes());
    }
}

fn set_extension_data(
    hello: &mut shin::wire::handshake::messages::ClientHello,
    ty: Type,
    data: &[u8],
) {
    let extension = hello
        .extensions
        .iter_mut()
        .find(|extension| extension.ty == ty)
        .unwrap();
    extension.data.clear();
    extension.data.extend_from_slice(data);
}

fn set_key_shares(
    hello: &mut shin::wire::handshake::messages::ClientHello,
    entries: &[(u16, &[u8])],
) {
    let extension = hello
        .extensions
        .iter_mut()
        .find(|extension| extension.ty == Type::KEY_SHARE)
        .unwrap();
    let encoded_len = entries
        .iter()
        .map(|(_, key_exchange)| 4 + key_exchange.len())
        .sum::<usize>();
    extension.data.clear();
    extension
        .data
        .extend_from_slice(&(encoded_len as u16).to_be_bytes());
    for (group, key_exchange) in entries {
        extension.data.extend_from_slice(&group.to_be_bytes());
        extension
            .data
            .extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
        extension.data.extend_from_slice(key_exchange);
    }
}

fn first_key_exchange(hello: &shin::wire::handshake::messages::ClientHello) -> Vec<u8> {
    hello
        .extensions
        .iter()
        .find(|extension| extension.ty == Type::KEY_SHARE)
        .unwrap()
        .data[6..]
        .to_vec()
}

fn server_hello_random(blob: &[u8]) -> [u8; 32] {
    let mut r = Reader::new(blob);
    let Frame::ServerHello(sh) = crate::decode_owned(&mut r).unwrap() else {
        panic!("not a ServerHello");
    };
    sh.random
}

#[test]
fn server_rejects_missing_key_share() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    assert_eq!(
        s.read(Epoch::Plaintext, &remove_key_share(&ch))
            .unwrap_err(),
        Error::MissingExtension,
    );
}

#[test]
fn server_rejects_empty_required_offer_vectors_during_decode() {
    for (ty, empty_vector) in [
        (Type::SUPPORTED_VERSIONS, &[0][..]),
        (Type::SUPPORTED_GROUPS, &[0, 0][..]),
        (Type::SIGNATURE_ALGORITHMS, &[0, 0][..]),
    ] {
        let mut s = server();
        let mut c = client();
        let ch = send(&c.start().unwrap(), Epoch::Plaintext);
        let malformed = mutate_client_hello(&ch, |hello| {
            set_extension_data(hello, ty, empty_vector);
        });
        assert_eq!(
            s.read(Epoch::Plaintext, &malformed).unwrap_err(),
            Error::Decode,
        );
    }
}

#[test]
fn server_sends_hrr_when_key_share_vector_is_empty() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);

    let evs = s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();
    let hrr = send(&evs, Epoch::Plaintext);
    assert_eq!(
        server_hello_random(&hrr),
        HELLO_RETRY_REQUEST_RANDOM,
        "server must answer an empty key_share vector with HRR",
    );
}

#[test]
fn server_recovers_after_hrr_when_retry_has_key_share() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);

    // First flight: empty key_share vector -> HRR.
    let _ = s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();
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
    let _ = s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();
    assert_eq!(
        s.read(Epoch::Plaintext, &remove_key_share(&ch))
            .unwrap_err(),
        Error::MissingExtension,
    );
}

#[test]
fn server_rejects_empty_key_share_vector_on_retry() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let empty = empty_key_share(&ch);
    let _ = s.read(Epoch::Plaintext, &empty).unwrap();
    assert_eq!(
        s.read(Epoch::Plaintext, &empty).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn server_rejects_client_hello_invariant_changes_after_hrr() {
    for mutation in 0..5 {
        let mut s = server();
        let mut c = client();
        let ch = send(&c.start().unwrap(), Epoch::Plaintext);
        s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();

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
    s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();

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
    s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();

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
    s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();

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

#[test]
fn server_rejects_key_share_not_in_supported_groups() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let mismatched = mutate_client_hello(&ch, |hello| {
        set_supported_groups(hello, &[0x0017]);
    });

    assert_eq!(
        s.read(Epoch::Plaintext, &mismatched).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn server_rejects_duplicate_local_key_share() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let duplicate = mutate_client_hello(&ch, |hello| {
        let key_exchange = first_key_exchange(hello);
        set_key_shares(
            hello,
            &[(0x001d, key_exchange.as_slice()), (0x001d, &key_exchange)],
        );
    });

    assert_eq!(
        s.read(Epoch::Plaintext, &duplicate).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn server_rejects_key_shares_out_of_supported_group_order() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let reordered = mutate_client_hello(&ch, |hello| {
        let key_exchange = first_key_exchange(hello);
        set_supported_groups(hello, &[0x001d, 0x0017]);
        set_key_shares(hello, &[(0x0017, &[1]), (0x001d, key_exchange.as_slice())]);
    });

    assert_eq!(
        s.read(Epoch::Plaintext, &reordered).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn server_rejects_empty_key_exchange_during_decode() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let empty = mutate_client_hello(&ch, |hello| {
        set_key_shares(hello, &[(0x001d, &[])]);
    });

    assert_eq!(s.read(Epoch::Plaintext, &empty).unwrap_err(), Error::Decode,);
}

#[test]
fn server_keeps_unknown_matching_key_share_forward_compatible() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    let unknown = mutate_client_hello(&ch, |hello| {
        set_supported_groups(hello, &[0xaaaa, 0x001d]);
        set_key_shares(hello, &[(0xaaaa, &[1])]);
    });

    let events = s.read(Epoch::Plaintext, &unknown).unwrap();
    assert_eq!(
        server_hello_random(&send(&events, Epoch::Plaintext)),
        HELLO_RETRY_REQUEST_RANDOM,
    );
}

#[test]
fn server_rejects_extra_retry_key_share() {
    let mut s = server();
    let mut c = client();
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);
    s.read(Epoch::Plaintext, &empty_key_share(&ch)).unwrap();

    let ch2 = mutate_client_hello(&ch, |hello| {
        let key_exchange = first_key_exchange(hello);
        set_key_shares(hello, &[(0x001d, key_exchange.as_slice()), (0x0017, &[1])]);
    });
    assert_eq!(
        s.read(Epoch::Plaintext, &ch2).unwrap_err(),
        Error::IllegalParameter,
    );
}
