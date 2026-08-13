use shin::client::Client;
use shin::client::config::{Config, Verifier};
use shin::connection::{Clock, Epoch, Error};
use shin::crypto::sig::SigningKey;
use shin::server::{Shard, config::CertSource, config::Connection, config::EarlyDataGuard};
use shin::wire::codec::Reader;
use shin::wire::extension::Type;
use shin::wire::handshake::Frame;
use shin::wire::handshake::messages::ClientHello;

use crate::common::CollectEvents;
use crate::common::CollectServerEvents;
use crate::common::Event;
use crate::common::{Server, ServerConfig};

fn drive_client_hello_alpn(alpn: Vec<Vec<u8>>) -> ClientHello {
    let mut c = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [0x42u8; 32],
            },
            transport_params: Vec::new(),
            alpn_protocols: alpn,
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
    let evs = c.start().unwrap();
    let ch_bytes = evs
        .into_iter()
        .find_map(|e| match e {
            Event::Send {
                epoch: Epoch::Plaintext,
                data,
            } => Some(data),
            _ => None,
        })
        .unwrap();
    let mut r = Reader::new(&ch_bytes);
    match crate::decode_owned(&mut r).unwrap() {
        Frame::ClientHello(ch) => ch,
        _ => panic!(),
    }
}

#[test]
fn empty_alpn_omits_extension() {
    let ch = drive_client_hello_alpn(Vec::new());
    assert!(
        !ch.extensions
            .iter()
            .any(|e| e.ty == Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
    );
}

#[test]
fn single_protocol_emits_extension() {
    let ch = drive_client_hello_alpn(vec![b"http/1.1".to_vec()]);
    let ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        .unwrap();
    assert_eq!(
        &ext.data,
        &[
            0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
        ]
    );
}

#[test]
fn multiple_protocols_emit_in_order() {
    let ch = drive_client_hello_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        .unwrap();
    assert_eq!(
        &ext.data,
        &[
            0x00, 0x0C, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
        ],
    );
}

#[test]
fn server_rejects_empty_alpn_protocol_list_during_decode() {
    let signing = SigningKey::from_seed(&[0x42u8; 32]).unwrap();
    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec()],
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut hello = drive_client_hello_alpn(vec![b"h2".to_vec()]);
    let alpn = hello
        .extensions
        .iter_mut()
        .find(|extension| extension.ty == Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        .unwrap();
    alpn.data.clear();
    alpn.data.extend_from_slice(&0u16.to_be_bytes());
    let mut encoded = Vec::new();
    Frame::ClientHello(hello).encode(&mut encoded).unwrap();

    assert_eq!(
        server.read(Epoch::Plaintext, &encoded).unwrap_err(),
        Error::Decode,
    );
}

#[test]
fn server_picks_first_overlap_and_client_observes() {
    let signing = SigningKey::from_seed(&[0x42u8; 32]).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"http/1.1".to_vec(), b"h2".to_vec()],
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();

    drive_handshake(&mut client, &mut server);

    assert_eq!(server.selected_alpn(), Some(&b"h2"[..]));
    assert_eq!(client.selected_alpn(), Some(&b"h2"[..]));
}

#[test]
fn selected_protocol_is_available_from_the_bound_connection() {
    let signing = SigningKey::from_seed(&[0x42u8; 32]).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();
    let mut shard = Shard::new(shin::server::config::Config {
        source: CertSource::RawPublicKey {
            signing_key: signing,
        },
        alpn_protocols: vec![b"h2".to_vec()],
        ticket_keys: None,
    })
    .unwrap();
    let server = shin::server::Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
    )
    .unwrap();
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec()],
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
    let mut server = shard.bind(server).into_result().unwrap();

    let client_hello = take_send(client.start().unwrap(), Epoch::Plaintext);
    server.read(Epoch::Plaintext, &client_hello).unwrap();

    assert_eq!(server.selected_alpn(), Some(&b"h2"[..]));
}

#[test]
fn no_overlap_aborts_with_no_application_protocol() {
    let signing = SigningKey::from_seed(&[0x42u8; 32]).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec()],
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();

    // RFC 7301 §3.2: empty intersection MUST abort, not complete ALPN-less.
    let evs = client.start().unwrap();
    let ch = take_send(evs, Epoch::Plaintext);
    let err = server.read(Epoch::Plaintext, &ch).unwrap_err();
    assert_eq!(err, shin::connection::Error::NoApplicationProtocol);
    assert_eq!(
        err.alert().description,
        shin::wire::alert::Description::NoApplicationProtocol,
    );
}

fn drive_handshake<CC: Clock, SC: Clock, G: EarlyDataGuard>(
    client: &mut Client<CC>,
    server: &mut Server<SC, G>,
) {
    let evs = client.start().unwrap();
    let ch = take_send(evs, Epoch::Plaintext);
    let evs = server.read(Epoch::Plaintext, &ch).unwrap();
    let mut to_client_plaintext = Vec::new();
    let mut to_client_handshake = Vec::new();
    for e in evs {
        if let Event::Send {
            epoch: Epoch::Plaintext,
            data,
        } = e
        {
            to_client_plaintext.extend(data);
        } else if let Event::Send {
            epoch: Epoch::Handshake,
            data,
        } = e
        {
            to_client_handshake.extend(data);
        }
    }
    if !to_client_plaintext.is_empty() {
        client.read(Epoch::Plaintext, &to_client_plaintext).unwrap();
    }
    if !to_client_handshake.is_empty() {
        client.read(Epoch::Handshake, &to_client_handshake).unwrap();
    }
}

fn take_send(evs: Vec<Event>, epoch: Epoch) -> Vec<u8> {
    let mut out = Vec::new();
    for e in evs {
        if let Event::Send { epoch: ep, data } = e
            && ep == epoch
        {
            out.extend(data);
        }
    }
    out
}
