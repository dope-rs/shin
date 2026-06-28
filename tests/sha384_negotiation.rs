use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::codec::Reader;
use shin::extension::ExtensionType;
use shin::handshake::{HELLO_RETRY_REQUEST_RANDOM, Handshake};
use shin::record::CipherSuite;
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Error, Event};

mod common;
use common::{FixedClock, send};

const TICKET_SECRET: [u8; 32] = [0x33u8; 32];

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x77u8; 32]).unwrap()
}

fn server() -> Server<FixedClock> {
    Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: Some(shin::ticket::TicketKeys::single(TICKET_SECRET)),
            accept_early_data: false,
        },
        FixedClock(1_000_000),
    )
}

fn client(suites: &[CipherSuite]) -> Client<fn() -> u64> {
    let mut c = Client::new(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        (|| 0) as fn() -> u64,
    );
    c.set_cipher_suites(suites);
    c
}

fn drive(client: &mut Client<fn() -> u64>, server: &mut Server<FixedClock>) -> Vec<Event> {
    let mut client_events = Vec::new();
    let mut server_events = Vec::new();

    let c1 = client.start().unwrap();
    let ch = send(&c1, Epoch::Plaintext);
    client_events.extend(c1);

    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext);
    let s_hs = send(&s1, Epoch::Handshake);
    server_events.extend(s1);

    client_events.extend(client.read(Epoch::Plaintext, &sh).unwrap());
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = send(&c3, Epoch::Handshake);
    client_events.extend(c3);

    server_events.extend(server.read(Epoch::Handshake, &cf).unwrap());

    if let Some(bytes) = server_events.iter().find_map(|e| match e {
        Event::Send { epoch, data } if *epoch == Epoch::Application => Some(data.clone()),
        _ => None,
    }) {
        client_events.extend(client.read(Epoch::Application, &bytes).unwrap());
    }
    client_events.extend(server_events);
    client_events
}

#[test]
fn sha384_session_emits_no_ticket() {
    let mut s = server();
    let mut c = client(&[CipherSuite::Aes256GcmSha384]);
    let events = drive(&mut c, &mut s);

    assert!(c.is_done() && s.is_done());
    assert_eq!(
        c.negotiated_cipher_suite(),
        Some(CipherSuite::Aes256GcmSha384)
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::NewSessionTicket { .. })),
        "SHA-384 sessions are not resumable; the server must issue no ticket",
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::ResumptionSecret { .. })),
    );
}

#[test]
fn sha256_session_still_emits_a_ticket() {
    let mut s = server();
    let mut c = client(&[CipherSuite::Aes128GcmSha256]);
    let events = drive(&mut c, &mut s);

    assert!(c.is_done() && s.is_done());
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::NewSessionTicket { .. })),
        "SHA-256 sessions remain resumable",
    );
}

#[test]
fn client_rejects_server_hello_with_unoffered_suite() {
    let mut s = server();
    let mut producer = client(&[CipherSuite::Aes256GcmSha384]);
    let ch = send(&producer.start().unwrap(), Epoch::Plaintext);
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh_aes256 = send(&s1, Epoch::Plaintext);

    let mut victim = client(&[CipherSuite::Aes128GcmSha256]);
    let _ = victim.start().unwrap();
    assert_eq!(
        victim.read(Epoch::Plaintext, &sh_aes256),
        Err(Error::IllegalParameter),
        "a ServerHello selecting an unoffered suite must be rejected",
    );
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
fn server_hrr_then_recovers_under_sha384() {
    let mut s = server();
    let mut c = client(&[CipherSuite::Aes256GcmSha384]);
    let ch = send(&c.start().unwrap(), Epoch::Plaintext);

    let hrr_events = s.read(Epoch::Plaintext, &strip_key_share(&ch)).unwrap();
    let hrr = send(&hrr_events, Epoch::Plaintext);
    assert_eq!(
        server_hello_random(&hrr),
        HELLO_RETRY_REQUEST_RANDOM,
        "key_share-less ClientHello must draw an HRR even under SHA-384",
    );

    let retry = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&retry, Epoch::Plaintext);
    assert_ne!(
        server_hello_random(&sh),
        HELLO_RETRY_REQUEST_RANDOM,
        "the retry with a key_share must yield a real ServerHello",
    );
    assert!(
        retry.iter().any(|e| matches!(
            e,
            Event::Send {
                epoch: Epoch::Handshake,
                ..
            }
        )),
        "server should emit its encrypted handshake flight after the SHA-384 HRR",
    );
}
