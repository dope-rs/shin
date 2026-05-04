use ring::rand::{SecureRandom, SystemRandom};
use shin::client::{Client, Config as ClientConfig};
use shin::server::{Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

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

fn extract_keys(events: &[Event], epoch: Epoch) -> Option<([u8; 32], [u8; 32])> {
    events.iter().find_map(|e| match e {
        Event::KeysReady {
            epoch: ep,
            read_secret,
            write_secret,
        } if *ep == epoch => Some((*read_secret, *write_secret)),
        _ => None,
    })
}

fn extract_peer_ext(events: &[Event], ty: u16) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::PeerExtension { ty: t, data } if *t == ty => Some(data.clone()),
        _ => None,
    })
}

fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done))
}

const QUIC_TRANSPORT_PARAMETERS: u16 = 57;

#[test]
fn handshake_completes_in_process() {
    let server_key = sample_signing_key();
    let server_pubkey = *server_key.pubkey();

    let mut server = Server::new(ServerConfig {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: server_key,
        },
        transport_params: SERVER_TP.to_vec(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });

    let mut client = Client::new(ClientConfig {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: CLIENT_TP.to_vec(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let c1 = client.start().unwrap();
    let ch_bytes = extract_send(&c1, Epoch::Plaintext).expect("ClientHello");

    let s1 = server.read(Epoch::Plaintext, &ch_bytes).unwrap();
    let sh_bytes = extract_send(&s1, Epoch::Plaintext).expect("ServerHello");
    let server_hs_blob = extract_send(&s1, Epoch::Handshake).expect("server EE+Cert+CV+SF");
    let (server_read_hs, server_write_hs) =
        extract_keys(&s1, Epoch::Handshake).expect("server handshake keys");
    let (server_read_ap, server_write_ap) =
        extract_keys(&s1, Epoch::Application).expect("server application keys");
    let server_saw_client_tp = extract_peer_ext(&s1, QUIC_TRANSPORT_PARAMETERS)
        .expect("server captured client transport_params");
    assert_eq!(server_saw_client_tp, CLIENT_TP);

    let c2 = client.read(Epoch::Plaintext, &sh_bytes).unwrap();
    let (client_read_hs, client_write_hs) =
        extract_keys(&c2, Epoch::Handshake).expect("client handshake keys");

    assert_eq!(client_read_hs, server_write_hs);
    assert_eq!(client_write_hs, server_read_hs);

    let c3 = client.read(Epoch::Handshake, &server_hs_blob).unwrap();
    let (client_read_ap, client_write_ap) =
        extract_keys(&c3, Epoch::Application).expect("client application keys");
    let cf_bytes = extract_send(&c3, Epoch::Handshake).expect("client Finished");
    let client_saw_server_tp = extract_peer_ext(&c3, QUIC_TRANSPORT_PARAMETERS)
        .expect("client captured server transport_params");
    assert_eq!(client_saw_server_tp, SERVER_TP);
    assert!(has_done(&c3), "client must emit Done after server Finished");

    assert_eq!(client_read_ap, server_write_ap);
    assert_eq!(client_write_ap, server_read_ap);

    let s2 = server.read(Epoch::Handshake, &cf_bytes).unwrap();
    assert!(has_done(&s2), "server must emit Done after client Finished");

    assert!(client.is_done());
    assert!(server.is_done());
}

#[test]
fn client_rejects_wrong_server_pubkey() {
    let server_key = sample_signing_key();
    let mut server = Server::new(ServerConfig {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: server_key,
        },
        transport_params: SERVER_TP.to_vec(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });

    let bogus_pubkey = [0xAAu8; 32];
    let mut client = Client::new(ClientConfig {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: bogus_pubkey,
        },
        transport_params: CLIENT_TP.to_vec(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let c1 = client.start().unwrap();
    let ch_bytes = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch_bytes).unwrap();
    let sh_bytes = extract_send(&s1, Epoch::Plaintext).unwrap();
    let server_hs_blob = extract_send(&s1, Epoch::Handshake).unwrap();

    client.read(Epoch::Plaintext, &sh_bytes).unwrap();
    let result = client.read(Epoch::Handshake, &server_hs_blob);
    assert!(
        result.is_err(),
        "client must reject Cert with unknown pubkey"
    );
}

#[test]
fn server_rejects_tampered_client_finished() {
    let server_key = sample_signing_key();
    let server_pubkey = *server_key.pubkey();

    let mut server = Server::new(ServerConfig {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: server_key,
        },
        transport_params: SERVER_TP.to_vec(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = Client::new(ClientConfig {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: CLIENT_TP.to_vec(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let c1 = client.start().unwrap();
    let ch_bytes = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch_bytes).unwrap();
    let sh_bytes = extract_send(&s1, Epoch::Plaintext).unwrap();
    let server_hs_blob = extract_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh_bytes).unwrap();
    let c3 = client.read(Epoch::Handshake, &server_hs_blob).unwrap();
    let mut cf_bytes = extract_send(&c3, Epoch::Handshake).unwrap();
    let last = cf_bytes.len() - 1;
    cf_bytes[last] ^= 0x01;

    assert!(server.read(Epoch::Handshake, &cf_bytes).is_err());
}

#[test]
fn keys_diverge_across_independent_handshakes() {
    let server_key = sample_signing_key();
    let server_pubkey = *server_key.pubkey();

    let do_handshake = || -> ([u8; 32], [u8; 32]) {
        let mut server = Server::new(ServerConfig {
            source: shin::server::CertSource::RawPublicKey {
                signing_key: server_key.clone(),
            },
            transport_params: SERVER_TP.to_vec(),
            alpn_protocols: Vec::new(),
            ticket_secret: None,
            accept_early_data: false,
        });
        let mut client = Client::new(ClientConfig {
            verifier: shin::client::Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: CLIENT_TP.to_vec(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        });

        let c1 = client.start().unwrap();
        let ch_bytes = extract_send(&c1, Epoch::Plaintext).unwrap();
        let s1 = server.read(Epoch::Plaintext, &ch_bytes).unwrap();
        let sh_bytes = extract_send(&s1, Epoch::Plaintext).unwrap();
        let hs_blob = extract_send(&s1, Epoch::Handshake).unwrap();
        client.read(Epoch::Plaintext, &sh_bytes).unwrap();
        let c3 = client.read(Epoch::Handshake, &hs_blob).unwrap();
        let cf = extract_send(&c3, Epoch::Handshake).unwrap();
        server.read(Epoch::Handshake, &cf).unwrap();

        extract_keys(&c3, Epoch::Application).unwrap()
    };

    let (a_read, a_write) = do_handshake();
    let (b_read, b_write) = do_handshake();
    assert_ne!(a_read, b_read);
    assert_ne!(a_write, b_write);
}
