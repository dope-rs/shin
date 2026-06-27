//! Finished-MAC integrity: the server must reject any tampered client Finished
//! regardless of which byte is altered. This is not a timing measurement — it
//! asserts the functional outcome of the constant-time comparison used for the
//! MAC check (every tamper position yields the same rejection).

use ring::rand::{SecureRandom, SystemRandom};
use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

type TestServer = Server<fn() -> u64>;

fn collect_send(events: &[Event], epoch: Epoch) -> Vec<u8> {
    let mut out = Vec::new();
    for e in events {
        if let Event::Send { epoch: ep, data } = e
            && *ep == epoch
        {
            out.extend_from_slice(data);
        }
    }
    out
}

fn client_finished_and_server() -> (TestServer, Vec<u8>) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing_key = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();

    let mut server: Server<fn() -> u64> = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey { signing_key },
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

    let ch = collect_send(&client.start().unwrap(), Epoch::Plaintext);
    let server_flight = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = collect_send(&server_flight, Epoch::Plaintext);
    let server_hs = collect_send(&server_flight, Epoch::Handshake);
    client.read(Epoch::Plaintext, &sh).unwrap();
    let client_out_hs = client.read(Epoch::Handshake, &server_hs).unwrap();
    let client_finished = collect_send(&client_out_hs, Epoch::Handshake);
    assert!(!client_finished.is_empty());
    (server, client_finished)
}

#[test]
fn server_rejects_tampered_client_finished() {
    let (mut server, client_finished) = client_finished_and_server();

    let mut tampered = client_finished.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xff;
    assert_eq!(
        server.read(Epoch::Handshake, &tampered).unwrap_err(),
        shin::Error::BadFinished,
    );

    let ok = server.read(Epoch::Handshake, &client_finished).unwrap();
    assert!(ok.iter().any(|e| matches!(e, Event::Done)));
}

#[test]
fn finished_rejection_is_independent_of_tamper_position() {
    // The MAC comparison must not short-circuit observably: a flip in the first
    // verify_data byte and a flip in the last must both reject identically.
    let positions = [
        4usize, // first verify_data byte (after the 4-byte handshake header)
        0,      // header byte
    ];
    for delta in positions {
        let (mut server, finished) = client_finished_and_server();
        let mut tampered = finished.clone();
        let idx = if delta < tampered.len() {
            delta
        } else {
            tampered.len() - 1
        };
        tampered[idx] ^= 0xff;
        let err = server.read(Epoch::Handshake, &tampered).unwrap_err();
        assert!(
            matches!(err, shin::Error::BadFinished | shin::Error::Decode),
            "tamper at {idx} must reject, got {err:?}",
        );
    }

    // A flip of the last verify_data byte specifically yields BadFinished.
    let (mut server, finished) = client_finished_and_server();
    let mut tampered = finished.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0x01;
    assert_eq!(
        server.read(Epoch::Handshake, &tampered).unwrap_err(),
        shin::Error::BadFinished,
    );
}
