//! RFC 8446 §4.2.11.2 interop: a PSK binder offered through a HelloRetryRequest
//! must be computed over `Transcript-Hash(ClientHello1) ‖ HelloRetryRequest ‖
//! Truncate(ClientHello2)`. These tests act as an RFC-compliant peer (computing
//! the binder over the post-HRR transcript with the public primitives) and check
//! that both the real server and the real client agree on that transcript.

use std::cell::Cell;
use std::rc::Rc;

use shin::client::Client;
use shin::client::config::{Config, Restore, Verifier};
use shin::connection::{Epoch, Error};
use shin::crypto::hash::{Algorithm, Transcript};
use shin::crypto::sig::SigningKey;
use shin::server::config::CertSource;
use shin::wire::codec::Reader;
use shin::wire::extension::{Extension, Type};
use shin::wire::handshake;
use shin::wire::handshake::Frame;
use shin::wire::handshake::messages::{ClientHello, ServerHello};
use shin::wire::handshake::{HELLO_RETRY_REQUEST_RANDOM, RANDOM_LEN, TLS_1_2};
use shin::wire::psk::{Identity, OfferedPsks, ResumptionBinder};

use crate::common::CollectEvents;
use crate::common::Event;
use crate::common::{FixedClock, Server, ServerConfig, send};

const TICKET_SECRET: [u8; 32] = [0x33u8; 32];
const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_1_3: u16 = 0x0304;
const GROUP_SECP256R1: u16 = 0x0017;
const BINDERS_FIELD_LEN: usize = 2 + 1 + 32;

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x55u8; 32]).unwrap()
}

fn fresh_server() -> Server<FixedClock> {
    Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET).unwrap()),
            accept_early_data: false,
        },
        FixedClock(1_000_000),
    )
}

fn fresh_client(restore: Option<Restore<'_>>) -> Client<fn() -> u64> {
    let template = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
    .try_into_template()
    .unwrap();
    let prepared = match restore {
        Some(restore) => template.restore(restore).unwrap(),
        None => template.without_resumption(),
    };
    let workspace = prepared.workspace_layout(None).allocate();
    prepared
        .try_into_client_with_workspace(None, (|| 0) as fn() -> u64, workspace)
        .unwrap()
}

fn empty_key_share(ch_bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(ch_bytes);
    let Frame::ClientHello(mut ch) = crate::decode_owned(&mut r).unwrap() else {
        panic!("not a ClientHello");
    };
    let key_share = ch
        .extensions
        .iter_mut()
        .find(|extension| extension.ty == Type::KEY_SHARE)
        .expect("ClientHello has key_share");
    key_share.data.clear();
    key_share.data.extend_from_slice(&0u16.to_be_bytes());
    let mut out = Vec::new();
    Frame::ClientHello(ch).encode(&mut out).unwrap();
    out
}

fn mutate_client_hello(encoded: &[u8], mutate: impl FnOnce(&mut ClientHello)) -> Vec<u8> {
    let mut reader = Reader::new(encoded);
    let Frame::ClientHello(mut hello) = crate::decode_owned(&mut reader).unwrap() else {
        panic!("not a ClientHello");
    };
    mutate(&mut hello);
    let mut out = Vec::new();
    Frame::ClientHello(hello).encode(&mut out).unwrap();
    out
}

fn server_hello_random(blob: &[u8]) -> [u8; RANDOM_LEN] {
    let mut r = Reader::new(blob);
    let Frame::ServerHello(sh) = crate::decode_owned(&mut r).unwrap() else {
        panic!("not a ServerHello");
    };
    sh.random
}

fn handshake_types(blob: &[u8]) -> Vec<handshake::Type> {
    let mut r = Reader::new(blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(crate::decode_owned(&mut r).unwrap().msg_type());
    }
    types
}

fn psk_binder(ch_bytes: &[u8]) -> Vec<u8> {
    ch_bytes[ch_bytes.len() - 32..].to_vec()
}

fn obfuscated_ticket_age(ch_bytes: &[u8]) -> u32 {
    let mut reader = Reader::new(ch_bytes);
    let Frame::ClientHello(ch) = crate::decode_owned(&mut reader).unwrap() else {
        panic!("expected ClientHello");
    };
    let psk = ch
        .extensions
        .iter()
        .find(|extension| extension.ty == Type::PRE_SHARED_KEY)
        .expect("resuming ClientHello has pre_shared_key");
    OfferedPsks::decode(&psk.data)
        .unwrap()
        .identities()
        .next()
        .unwrap()
        .obfuscated_ticket_age
}

fn craft_hrr(session_id_echo: Vec<u8>) -> Vec<u8> {
    let sh = ServerHello {
        legacy_version: TLS_1_2,
        random: HELLO_RETRY_REQUEST_RANDOM,
        legacy_session_id_echo: session_id_echo,
        cipher_suite: SUITE_AES_128_GCM_SHA256,
        legacy_compression_method: 0,
        extensions: vec![
            Extension::new(Type::SUPPORTED_VERSIONS, TLS_1_3.to_be_bytes().to_vec()),
            Extension::new(Type::KEY_SHARE, GROUP_SECP256R1.to_be_bytes().to_vec()),
        ],
    };
    let mut out = Vec::new();
    Frame::ServerHello(sh).encode(&mut out).unwrap();
    out
}

/// The binder an RFC-compliant peer computes for `ch2` after a HRR, over
/// `message_hash(ch1) ‖ hrr ‖ Truncate(ch2)`.
fn post_hrr_binder(psk: &[u8; 32], ch1: &[u8], hrr: &[u8], ch2: &[u8]) -> Vec<u8> {
    let mut t =
        Transcript::restart_with_message_hash(Algorithm::Sha256, &Algorithm::Sha256.hash(ch1))
            .unwrap();
    t.update(hrr);
    t.update(&ch2[..ch2.len() - BINDERS_FIELD_LEN]);
    let partial = t.hash(Algorithm::Sha256).unwrap();
    ResumptionBinder::compute(psk, partial.as_slice())
        .unwrap()
        .as_slice()
        .to_vec()
}

fn obtain_resumption() -> (Restore<'static>, [u8; 32]) {
    let mut server = fresh_server();
    let mut client = fresh_client(None);

    let c1 = client.start().unwrap();
    let ch = send(&c1, Epoch::Plaintext);
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext);
    let s_hs = send(&s1, Epoch::Handshake);
    let _ = client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = send(&c3, Epoch::Handshake);
    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    let nst = send(&s2, Epoch::Application);

    let mut all = c3;
    all.extend(client.read(Epoch::Application, &nst).unwrap());

    for e in &all {
        if let Event::NewSessionTicket {
            psk,
            ticket_lifetime,
            ticket_age_add,
            ticket,
            ..
        } = e
        {
            return (
                Restore::try_new(*psk, ticket.clone(), *ticket_age_add, 0, *ticket_lifetime)
                    .unwrap(),
                *psk,
            );
        }
    }
    panic!("no ticket emitted");
}

/// Server side: with a binder computed over the post-HRR transcript, the server
/// must accept the PSK on the retried ClientHello and resume (no Certificate).
#[test]
fn server_accepts_psk_binder_computed_across_hrr() {
    let (restore, psk) = obtain_resumption();

    let mut client = fresh_client(Some(restore));
    let ch1f = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch1s = empty_key_share(&ch1f);

    let mut server = fresh_server();
    let hrr = send(
        &server.read(Epoch::Plaintext, &ch1s).unwrap(),
        Epoch::Plaintext,
    );
    assert_eq!(
        server_hello_random(&hrr),
        HELLO_RETRY_REQUEST_RANDOM,
        "an empty key_share vector must draw an HRR",
    );

    // A compliant peer's retry: the original (key_share-bearing) ClientHello with
    // a binder recomputed over message_hash(CH1) ‖ HRR ‖ Truncate(CH2).
    let mut ch2 = ch1f.clone();
    let n = ch2.len();
    let binder = post_hrr_binder(&psk, &ch1s, &hrr, &ch2);
    ch2[n - 32..].copy_from_slice(&binder);

    let s2 = server.read(Epoch::Plaintext, &ch2).unwrap();
    assert_ne!(
        server_hello_random(&send(&s2, Epoch::Plaintext)),
        HELLO_RETRY_REQUEST_RANDOM,
        "retry with a valid PSK binder must yield a real ServerHello",
    );
    let types = handshake_types(&send(&s2, Epoch::Handshake));
    assert!(
        !types.contains(&handshake::Type::Certificate)
            && !types.contains(&handshake::Type::CertificateVerify),
        "binder validated across HRR -> PSK resumption, no cert flight; saw {:?}",
        types,
    );
    assert!(
        types.contains(&handshake::Type::EncryptedExtensions)
            && types.contains(&handshake::Type::Finished),
        "resumption still emits EE + Finished; saw {:?}",
        types,
    );
}

/// Negative control proving the fix is load-bearing: a binder computed the buggy
/// way (a fresh transcript over only Truncate(CH2), ignoring CH1+HRR) belongs to
/// a recognized ticket and therefore aborts instead of silently downgrading.
#[test]
fn server_rejects_psk_binder_ignoring_hrr_prefix() {
    let (restore, psk) = obtain_resumption();

    let mut client = fresh_client(Some(restore));
    let ch1f = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch1s = empty_key_share(&ch1f);

    let mut server = fresh_server();
    let hrr = send(
        &server.read(Epoch::Plaintext, &ch1s).unwrap(),
        Epoch::Plaintext,
    );
    assert_eq!(server_hello_random(&hrr), HELLO_RETRY_REQUEST_RANDOM);

    let mut ch2 = ch1f.clone();
    let n = ch2.len();
    let mut fresh = Transcript::new();
    fresh.update(&ch2[..n - BINDERS_FIELD_LEN]);
    let wrong =
        ResumptionBinder::compute(&psk, fresh.hash(Algorithm::Sha256).unwrap().as_slice()).unwrap();
    ch2[n - 32..].copy_from_slice(wrong.as_slice());

    assert_eq!(
        server.read(Epoch::Plaintext, &ch2).unwrap_err(),
        Error::BadPskBinder,
    );
}

#[test]
fn server_rejects_psk_identity_change_after_hrr() {
    let (restore, _) = obtain_resumption();
    let mut client = fresh_client(Some(restore));
    let ch1 = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch1_empty_share = empty_key_share(&ch1);

    let mut server = fresh_server();
    server.read(Epoch::Plaintext, &ch1_empty_share).unwrap();

    let mut reader = Reader::new(&ch1);
    let Frame::ClientHello(mut ch2) = crate::decode_owned(&mut reader).unwrap() else {
        panic!("expected ClientHello");
    };
    let psk = ch2
        .extensions
        .iter_mut()
        .find(|extension| extension.ty == Type::PRE_SHARED_KEY)
        .expect("resuming ClientHello has pre_shared_key");
    // identities vector length (2) + first identity length (2), then ticket.
    psk.data[4] ^= 1;
    let mut encoded_ch2 = Vec::new();
    Frame::ClientHello(ch2).encode(&mut encoded_ch2).unwrap();

    assert_eq!(
        server.read(Epoch::Plaintext, &encoded_ch2).unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn server_rejects_pre_shared_key_that_is_not_last() {
    let (restore, _) = obtain_resumption();
    let mut client = fresh_client(Some(restore));
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let malformed = mutate_client_hello(&ch, |hello| {
        hello.extensions.push(Extension::new(Type(0xffa5), vec![1]));
    });

    assert_eq!(
        fresh_server()
            .read(Epoch::Plaintext, &malformed)
            .unwrap_err(),
        Error::IllegalParameter,
    );
}

#[test]
fn server_rejects_psk_without_key_exchange_modes() {
    let (restore, _) = obtain_resumption();
    let mut client = fresh_client(Some(restore));
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let malformed = mutate_client_hello(&ch, |hello| {
        hello
            .extensions
            .retain(|extension| extension.ty != Type::PSK_KEY_EXCHANGE_MODES);
    });

    assert_eq!(
        fresh_server()
            .read(Epoch::Plaintext, &malformed)
            .unwrap_err(),
        Error::MissingExtension,
    );
}

#[test]
fn server_aborts_on_bad_binder_for_recognized_ticket() {
    let (restore, _) = obtain_resumption();
    let mut client = fresh_client(Some(restore));
    let mut ch = send(&client.start().unwrap(), Epoch::Plaintext);
    *ch.last_mut().expect("ClientHello binder") ^= 1;

    assert_eq!(
        fresh_server().read(Epoch::Plaintext, &ch).unwrap_err(),
        Error::BadPskBinder,
    );
}

#[test]
fn server_softly_ignores_unknown_ticket() {
    let (restore, _) = obtain_resumption();
    let mut client = fresh_client(Some(restore));
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let unknown = mutate_client_hello(&ch, |hello| {
        let extension = hello
            .extensions
            .iter_mut()
            .find(|extension| extension.ty == Type::PRE_SHARED_KEY)
            .unwrap();
        let mut offer = OfferedPsks::decode(&extension.data).unwrap().into_owned();
        offer.identities[0].identity[0] ^= 1;
        offer.binders[0][0] ^= 1;
        extension.data = offer.encode().unwrap();
    });

    let types = handshake_types(&send(
        &fresh_server().read(Epoch::Plaintext, &unknown).unwrap(),
        Epoch::Handshake,
    ));
    assert!(types.contains(&handshake::Type::Certificate));
}

#[test]
fn server_hashes_no_binders_from_a_multi_psk_offer() {
    let (restore, psk) = obtain_resumption();
    let mut client = fresh_client(Some(restore));
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let placeholders = mutate_client_hello(&ch, |hello| {
        let extension = hello
            .extensions
            .iter_mut()
            .find(|extension| extension.ty == Type::PRE_SHARED_KEY)
            .unwrap();
        let mut offer = OfferedPsks::decode(&extension.data).unwrap().into_owned();
        offer.identities.push(Identity {
            identity: b"second-ticket".to_vec(),
            obfuscated_ticket_age: 0,
        });
        offer.binders[0].fill(0);
        offer.binders.push(vec![0; 32]);
        extension.data = offer.encode().unwrap();
    });
    const TWO_BINDERS_WIRE_LEN: usize = 2 + 2 * (1 + 32);
    let mut transcript = Transcript::new();
    transcript.update(&placeholders[..placeholders.len() - TWO_BINDERS_WIRE_LEN]);
    let binder =
        ResumptionBinder::compute(&psk, transcript.hash(Algorithm::Sha256).unwrap().as_slice())
            .unwrap();
    let valid = mutate_client_hello(&placeholders, |hello| {
        let extension = hello
            .extensions
            .iter_mut()
            .find(|extension| extension.ty == Type::PRE_SHARED_KEY)
            .unwrap();
        let mut offer = OfferedPsks::decode(&extension.data).unwrap().into_owned();
        offer.binders[0].copy_from_slice(binder.as_slice());
        extension.data = offer.encode().unwrap();
    });

    let types = handshake_types(&send(
        &fresh_server().read(Epoch::Plaintext, &valid).unwrap(),
        Epoch::Handshake,
    ));
    assert!(!types.contains(&handshake::Type::Certificate));
}

/// Client side: the real client, after answering a HRR, must offer the PSK again
/// with a binder over message_hash(CH1) ‖ HRR ‖ Truncate(CH2) — i.e. the binder
/// it emits matches an independent compliant recomputation.
#[test]
fn client_offers_psk_binder_computed_across_hrr() {
    let (restore, psk) = obtain_resumption();

    let mut client = fresh_client(Some(restore));
    let ch1 = send(&client.start().unwrap(), Epoch::Plaintext);
    assert_eq!(
        psk_binder(&ch1).len(),
        32,
        "first flight already carries a PSK binder",
    );

    let mut reader = Reader::new(&ch1);
    let Frame::ClientHello(parsed_ch1) = crate::decode_owned(&mut reader).unwrap() else {
        panic!("expected ClientHello");
    };
    let hrr = craft_hrr(parsed_ch1.legacy_session_id);
    let c2 = client.read(Epoch::Plaintext, &hrr).unwrap();
    let ch2 = send(&c2, Epoch::Plaintext);

    let mut r = Reader::new(&ch2);
    let Frame::ClientHello(parsed) = crate::decode_owned(&mut r).unwrap() else {
        panic!("retry must be a ClientHello");
    };
    assert!(
        parsed
            .extensions
            .iter()
            .any(|e| e.ty == Type::PRE_SHARED_KEY),
        "client must re-offer the PSK after HRR",
    );
    assert!(
        parsed.extensions.iter().any(|e| e.ty == Type::KEY_SHARE),
        "retry must carry a key_share",
    );

    let expected = post_hrr_binder(&psk, &ch1, &hrr, &ch2);
    assert_eq!(
        psk_binder(&ch2),
        expected,
        "client's post-HRR binder must cover message_hash(CH1) ‖ HRR ‖ Truncate(CH2)",
    );
}

#[test]
fn client_recomputes_ticket_age_after_hrr() {
    let clock = Rc::new(Cell::new(1_000));
    let restore = Restore::try_new([0x77; 32], vec![0xAA; 32], 91, 0, 7_200).unwrap();
    let prepared = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
    .try_into_template()
    .unwrap()
    .restore(restore)
    .unwrap();
    let workspace = prepared.workspace_layout(None).allocate();
    let mut client = prepared
        .try_into_client_with_workspace(
            None,
            {
                let clock = Rc::clone(&clock);
                move || clock.get()
            },
            workspace,
        )
        .unwrap();

    let ch1 = send(&client.start().unwrap(), Epoch::Plaintext);
    assert_eq!(obfuscated_ticket_age(&ch1), 1_091);
    let mut reader = Reader::new(&ch1);
    let Frame::ClientHello(parsed_ch1) = crate::decode_owned(&mut reader).unwrap() else {
        panic!("expected ClientHello");
    };

    clock.set(2_500);
    let hrr = craft_hrr(parsed_ch1.legacy_session_id);
    let ch2 = send(
        &client.read(Epoch::Plaintext, &hrr).unwrap(),
        Epoch::Plaintext,
    );

    assert_eq!(obfuscated_ticket_age(&ch2), 2_591);
}
