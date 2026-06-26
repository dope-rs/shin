use ring::rand::{SecureRandom, SystemRandom};
use shin::client::{Client, Config as ClientConfig};
use shin::server::{Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Error, Event};

const SERVER_TP: &[u8] = b"server-transport-params";
const CLIENT_TP: &[u8] = b"client-transport-params";

fn sample_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    SigningKey::from_seed(&seed).unwrap()
}

fn extract_send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done))
}

fn make_pair() -> (Client, Server) {
    let server_key = sample_signing_key();
    let server_pubkey = *server_key.pubkey().unwrap();
    let server = Server::new(ServerConfig {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: server_key,
        },
        transport_params: SERVER_TP.to_vec(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let client = Client::new(ClientConfig {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: CLIENT_TP.to_vec(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });
    (client, server)
}

fn handshake_with_chunking(chunk: usize) {
    let (mut client, mut server) = make_pair();

    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let server_flight = extract_send(&s1, Epoch::Handshake).unwrap();

    client.read(Epoch::Plaintext, &sh).unwrap();

    let mut cf = None;
    let mut done = false;
    for piece in server_flight.chunks(chunk.max(1)) {
        let evs = client.read(Epoch::Handshake, piece).unwrap();
        if let Some(b) = extract_send(&evs, Epoch::Handshake) {
            cf = Some(b);
        }
        if has_done(&evs) {
            done = true;
        }
    }
    assert!(
        done,
        "client must finish even when flight is fragmented (chunk={chunk})"
    );
    let cf = cf.expect("client Finished");

    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    assert!(has_done(&s2));
    assert!(client.is_done());
    assert!(server.is_done());
}

#[test]
fn reassembles_server_flight_byte_by_byte() {
    handshake_with_chunking(1);
}

#[test]
fn reassembles_server_flight_various_chunk_sizes() {
    for chunk in [2usize, 3, 5, 7, 13, 64, 100, 4096] {
        handshake_with_chunking(chunk);
    }
}

#[test]
fn incomplete_message_buffers_without_error_or_done() {
    let (mut client, mut server) = make_pair();
    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let server_flight = extract_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();

    let head = &server_flight[..server_flight.len() - 1];
    let evs = client.read(Epoch::Handshake, head).unwrap();
    assert!(!has_done(&evs));
    assert!(!client.is_done());

    let tail = &server_flight[server_flight.len() - 1..];
    let evs = client.read(Epoch::Handshake, tail).unwrap();
    assert!(has_done(&evs), "final byte must complete the handshake");
    assert!(client.is_done());
}

#[test]
fn partial_message_must_not_span_epoch_change() {
    let (mut client, mut server) = make_pair();
    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let server_flight = extract_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();

    let head = &server_flight[..4];
    client.read(Epoch::Handshake, head).unwrap();

    let tail = &server_flight[4..];
    assert_eq!(
        client.read(Epoch::Application, tail).unwrap_err(),
        Error::Decode
    );
}
