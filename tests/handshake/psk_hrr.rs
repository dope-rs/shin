//! RFC 8446 §4.2.11.2 interop: a PSK binder offered through a HelloRetryRequest
//! must be computed over `Transcript-Hash(ClientHello1) ‖ HelloRetryRequest ‖
//! Truncate(ClientHello2)`. These tests act as an RFC-compliant peer (computing
//! the binder over the post-HRR transcript with the public primitives) and check
//! that both the real server and the real client agree on that transcript.

use shin::client::Client;
use shin::client::config::{Config, Resumption, Verifier};
use shin::connection::{Epoch, Error};
use shin::crypto::hash::{Algorithm, Transcript};
use shin::crypto::sig::SigningKey;
use shin::server::config::CertSource;
use shin::wire::codec::Reader;
use shin::wire::extension::{Extension, Type};
use shin::wire::handshake;
use shin::wire::handshake::frame::Frame;
use shin::wire::handshake::messages::ServerHello;
use shin::wire::handshake::{HELLO_RETRY_REQUEST_RANDOM, RANDOM_LEN, TLS_1_2};
use shin::wire::psk::ResumptionBinder;

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
            ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET)),
            accept_early_data: false,
        },
        FixedClock(1_000_000),
    )
}

fn fresh_client(resumption: Option<Resumption>) -> Client<fn() -> u64> {
    Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption,
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

fn server_hello_random(blob: &[u8]) -> [u8; RANDOM_LEN] {
    let mut r = Reader::new(blob);
    let Frame::ServerHello(sh) = Frame::decode(&mut r).unwrap() else {
        panic!("not a ServerHello");
    };
    sh.random
}

fn handshake_types(blob: &[u8]) -> Vec<handshake::Type> {
    let mut r = Reader::new(blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(Frame::decode(&mut r).unwrap().msg_type());
    }
    types
}

fn psk_binder(ch_bytes: &[u8]) -> Vec<u8> {
    ch_bytes[ch_bytes.len() - 32..].to_vec()
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

fn obtain_resumption() -> Resumption {
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

    let mut psk: Option<[u8; 32]> = None;
    for e in &all {
        if let Event::ResumptionSecret { psk: p } = e {
            psk = Some(*p);
        }
        if let Event::NewSessionTicket {
            ticket_age_add,
            ticket,
            ..
        } = e
        {
            return Resumption::new(
                psk.expect("ResumptionSecret precedes NewSessionTicket"),
                ticket.clone(),
                *ticket_age_add,
                0,
            );
        }
    }
    panic!("no ticket emitted");
}

/// Server side: with a binder computed over the post-HRR transcript, the server
/// must accept the PSK on the retried ClientHello and resume (no Certificate).
#[test]
fn server_accepts_psk_binder_computed_across_hrr() {
    let resumption = obtain_resumption();
    let psk = *resumption.psk.as_array();

    let mut client = fresh_client(Some(resumption));
    let ch1f = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch1s = strip_key_share(&ch1f);

    let mut server = fresh_server();
    let hrr = send(
        &server.read(Epoch::Plaintext, &ch1s).unwrap(),
        Epoch::Plaintext,
    );
    assert_eq!(
        server_hello_random(&hrr),
        HELLO_RETRY_REQUEST_RANDOM,
        "key_share-less PSK ClientHello must draw an HRR",
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
/// way (a fresh transcript over only Truncate(CH2), ignoring CH1+HRR) must be
/// rejected, so the server falls back to a full handshake with a Certificate.
#[test]
fn server_rejects_psk_binder_ignoring_hrr_prefix() {
    let resumption = obtain_resumption();
    let psk = *resumption.psk.as_array();

    let mut client = fresh_client(Some(resumption));
    let ch1f = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch1s = strip_key_share(&ch1f);

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

    let types = handshake_types(&send(
        &server.read(Epoch::Plaintext, &ch2).unwrap(),
        Epoch::Handshake,
    ));
    assert!(
        types.contains(&handshake::Type::Certificate),
        "a binder that ignores the HRR transcript must be rejected (full handshake); saw {:?}",
        types,
    );
}

#[test]
fn server_rejects_psk_identity_change_after_hrr() {
    let resumption = obtain_resumption();
    let mut client = fresh_client(Some(resumption));
    let ch1 = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch1_without_share = strip_key_share(&ch1);

    let mut server = fresh_server();
    server.read(Epoch::Plaintext, &ch1_without_share).unwrap();

    let mut reader = Reader::new(&ch1);
    let Frame::ClientHello(mut ch2) = Frame::decode(&mut reader).unwrap() else {
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

/// Client side: the real client, after answering a HRR, must offer the PSK again
/// with a binder over message_hash(CH1) ‖ HRR ‖ Truncate(CH2) — i.e. the binder
/// it emits matches an independent compliant recomputation.
#[test]
fn client_offers_psk_binder_computed_across_hrr() {
    let resumption = obtain_resumption();
    let psk = *resumption.psk.as_array();

    let mut client = fresh_client(Some(resumption));
    let ch1 = send(&client.start().unwrap(), Epoch::Plaintext);
    assert_eq!(
        psk_binder(&ch1).len(),
        32,
        "first flight already carries a PSK binder",
    );

    let mut reader = Reader::new(&ch1);
    let Frame::ClientHello(parsed_ch1) = Frame::decode(&mut reader).unwrap() else {
        panic!("expected ClientHello");
    };
    let hrr = craft_hrr(parsed_ch1.legacy_session_id);
    let c2 = client.read(Epoch::Plaintext, &hrr).unwrap();
    let ch2 = send(&c2, Epoch::Plaintext);

    let mut r = Reader::new(&ch2);
    let Frame::ClientHello(parsed) = Frame::decode(&mut r).unwrap() else {
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
