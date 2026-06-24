use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::codec::Reader;
use shin::extension::ExtensionType;
use shin::handshake::{ClientHello, Handshake};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

fn drive_client_hello_alpn(alpn: Vec<Vec<u8>>) -> ClientHello {
    let mut c = Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0x42u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: alpn,
        resumption: None,
        enable_early_data: false,
    });
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
    match Handshake::decode(&mut r).unwrap() {
        Handshake::ClientHello(ch) => ch,
        _ => panic!(),
    }
}

#[test]
fn empty_alpn_omits_extension() {
    let ch = drive_client_hello_alpn(Vec::new());
    assert!(
        !ch.extensions
            .iter()
            .any(|e| e.ty == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
    );
}

#[test]
fn single_protocol_emits_extension() {
    let ch = drive_client_hello_alpn(vec![b"http/1.1".to_vec()]);
    let ext = ch
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
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
        .find(|e| e.ty == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        .unwrap();
    assert_eq!(
        &ext.data,
        &[
            0x00, 0x0C, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
        ],
    );
}

#[test]
fn server_picks_first_overlap_and_client_observes() {
    let signing = SigningKey::from_seed(&[0x42u8; 32]).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = Server::new(ServerConfig {
        source: CertSource::RawPublicKey {
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"http/1.1".to_vec()],
        resumption: None,
        enable_early_data: false,
    });

    drive_handshake(&mut client, &mut server);

    assert_eq!(server.selected_alpn(), Some(&b"http/1.1"[..]));
    assert_eq!(client.selected_alpn(), Some(&b"http/1.1"[..]));
}

#[test]
fn no_overlap_leaves_alpn_unset() {
    let signing = SigningKey::from_seed(&[0x42u8; 32]).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = Server::new(ServerConfig {
        source: CertSource::RawPublicKey {
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"h2".to_vec()],
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"http/1.1".to_vec()],
        resumption: None,
        enable_early_data: false,
    });

    drive_handshake(&mut client, &mut server);

    assert_eq!(server.selected_alpn(), None);
    assert_eq!(client.selected_alpn(), None);
}

fn drive_handshake(client: &mut Client, server: &mut Server) {
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
