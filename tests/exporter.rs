use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

type TestClient = Client<fn() -> u64>;
type TestServer = Server<fn() -> u64>;

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x9bu8; 32]).unwrap()
}

fn clock() -> u64 {
    1_000_000
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

fn complete_handshake(client: &mut TestClient, server: &mut TestServer) {
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext);
    let s_hs = send(&s1, Epoch::Handshake);
    client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = send(&c3, Epoch::Handshake);
    server.read(Epoch::Handshake, &cf).unwrap();
    assert!(client.is_done() && server.is_done());
}

#[test]
fn exporter_agrees_between_peers() {
    let mut server = server();
    let mut client = client();
    complete_handshake(&mut client, &mut server);

    let mut c_out = [0u8; 32];
    let mut s_out = [0u8; 32];
    client
        .export_keying_material("EXPORTER-test", b"context", &mut c_out)
        .unwrap();
    server
        .export_keying_material("EXPORTER-test", b"context", &mut s_out)
        .unwrap();
    assert_eq!(c_out, s_out, "both peers derive the same exported secret");
    assert_ne!(c_out, [0u8; 32]);
}

#[test]
fn exporter_varies_by_label_and_context() {
    let mut server = server();
    let mut client = client();
    complete_handshake(&mut client, &mut server);

    let mut base = [0u8; 32];
    let mut diff_ctx = [0u8; 32];
    let mut diff_label = [0u8; 32];
    let mut diff_len = [0u8; 48];
    client
        .export_keying_material("EXPORTER-test", b"context", &mut base)
        .unwrap();
    client
        .export_keying_material("EXPORTER-test", b"other", &mut diff_ctx)
        .unwrap();
    client
        .export_keying_material("EXPORTER-diff", b"context", &mut diff_label)
        .unwrap();
    client
        .export_keying_material("EXPORTER-test", b"context", &mut diff_len)
        .unwrap();

    assert_ne!(base, diff_ctx, "context is mixed in");
    assert_ne!(base, diff_label, "label is mixed in");
    // RFC 8446 §7.1: HKDF-Expand-Label binds the length, so a different length re-streams.
    assert_ne!(&diff_len[..32], &base[..]);
}

#[test]
fn exporter_unavailable_before_handshake() {
    let client = client();
    let mut out = [0u8; 16];
    assert_eq!(
        client
            .export_keying_material("EXPORTER-test", b"", &mut out)
            .unwrap_err(),
        shin::Error::NotReady,
        "exporter must not be available before the handshake completes",
    );
}
