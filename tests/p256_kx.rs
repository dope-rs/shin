use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::kx::KexGroup;
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

type TestClient = Client<fn() -> u64>;
type TestServer = Server<fn() -> u64>;

fn clock() -> u64 {
    1_000_000
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x2au8; 32]).unwrap()
}

fn server() -> TestServer {
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
        clock,
    )
}

fn client() -> TestClient {
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
        clock,
    )
}

fn send(events: &[Event], epoch: Epoch) -> Vec<u8> {
    events
        .iter()
        .find_map(|e| match e {
            Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
            _ => None,
        })
        .expect("expected a Send")
}

fn drive_to_completion(client: &mut TestClient, server: &mut TestServer) {
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext);
    let s_hs = send(&s1, Epoch::Handshake);
    client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = send(&c3, Epoch::Handshake);
    server.read(Epoch::Handshake, &cf).unwrap();
}

#[test]
fn handshake_completes_over_p256() {
    let mut server = server();
    let mut client = client();
    client.set_kex_group(KexGroup::Secp256r1);

    drive_to_completion(&mut client, &mut server);
    assert!(client.is_done(), "client completes over P-256");
    assert!(server.is_done(), "server completes over P-256");

    // App secrets must match across the P-256 exchange.
    let mut c_exp = [0u8; 32];
    let mut s_exp = [0u8; 32];
    client
        .export_keying_material("EXPORTER-x", b"", &mut c_exp)
        .unwrap();
    server
        .export_keying_material("EXPORTER-x", b"", &mut s_exp)
        .unwrap();
    assert_eq!(c_exp, s_exp);
}

#[test]
fn default_is_still_x25519() {
    let mut server = server();
    let mut client = client();
    drive_to_completion(&mut client, &mut server);
    assert!(client.is_done() && server.is_done());
}
