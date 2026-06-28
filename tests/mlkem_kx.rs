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
    SigningKey::from_seed(&[0x3cu8; 32]).unwrap()
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
fn handshake_completes_over_x25519_mlkem768() {
    let mut server = server();
    let mut client = client();
    client.set_kex_group(KexGroup::X25519Mlkem768);

    drive_to_completion(&mut client, &mut server);
    assert!(client.is_done(), "client completes over X25519MLKEM768");
    assert!(server.is_done(), "server completes over X25519MLKEM768");

    // A matching 64-byte hybrid secret yields matching exported keying material.
    let mut c_exp = [0u8; 48];
    let mut s_exp = [0u8; 48];
    client
        .export_keying_material("EXPORTER-pq", b"ctx", &mut c_exp)
        .unwrap();
    server
        .export_keying_material("EXPORTER-pq", b"ctx", &mut s_exp)
        .unwrap();
    assert_eq!(c_exp, s_exp);
    assert_ne!(c_exp, [0u8; 48]);
}

#[test]
fn pq_client_hello_carries_hybrid_key_share() {
    // The ClientHello key_share for the hybrid group is mlkem_ek(1184) ‖
    // x25519(32) = 1216 bytes, far larger than a classical share.
    use shin::codec::Reader;
    use shin::extension::ExtensionType;
    use shin::handshake::Handshake;

    let mut client = client();
    client.set_kex_group(KexGroup::X25519Mlkem768);
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);

    let mut r = Reader::new(&ch);
    let Handshake::ClientHello(chm) = Handshake::decode(&mut r).unwrap() else {
        panic!("not a ClientHello");
    };
    let ks = chm
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::KEY_SHARE)
        .expect("key_share present");
    // list(2) + group(2) + len(2) + share(1216)
    assert!(
        ks.data.len() >= 1216 + 6,
        "hybrid share present: {}",
        ks.data.len()
    );
}
