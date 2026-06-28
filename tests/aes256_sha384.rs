use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::record::{CipherSuite, ContentType, Opener, Sealer};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

type TestClient = Client<fn() -> u64>;
type TestServer = Server<fn() -> u64>;

fn clock() -> u64 {
    1_000_000
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x3du8; 32]).unwrap()
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

fn app_secrets(events: &[Event]) -> Option<(shin::hash::Digest, shin::hash::Digest)> {
    events.iter().find_map(|e| match e {
        Event::KeysReady {
            epoch: Epoch::Application,
            read_secret,
            write_secret,
        } => Some((*read_secret, *write_secret)),
        _ => None,
    })
}

#[test]
fn handshake_completes_over_aes256_sha384() {
    let mut server = server();
    let mut client = client();
    client.set_cipher_suites(&[CipherSuite::Aes256GcmSha384]);

    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext);
    let s_hs = send(&s1, Epoch::Handshake);
    let c2 = client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = send(&c3, Epoch::Handshake);
    server.read(Epoch::Handshake, &cf).unwrap();

    assert!(client.is_done() && server.is_done());
    assert_eq!(
        client.negotiated_cipher_suite(),
        Some(CipherSuite::Aes256GcmSha384)
    );
    assert_eq!(
        server.negotiated_cipher_suite(),
        Some(CipherSuite::Aes256GcmSha384)
    );

    // 48-byte (SHA-384) application secrets, agreeing across the two sides.
    let (c_read, c_write) = app_secrets(&c3).expect("client app keys");
    let (s_read, s_write) = app_secrets(&s1).expect("server app keys");
    assert_eq!(c_read.len(), 48);
    assert_eq!(c_read, s_write);
    assert_eq!(c_write, s_read);

    // Records protect/parse end to end under AES-256-GCM with these secrets.
    let mut sealer = Sealer::with_suite(c_write.as_slice(), CipherSuite::Aes256GcmSha384);
    let mut opener = Opener::with_suite(s_read.as_slice(), CipherSuite::Aes256GcmSha384);
    let mut wire = sealer
        .seal(ContentType::ApplicationData, b"hello over aes-256")
        .unwrap();
    let (ty, range, _) = opener.open(&mut wire).unwrap().unwrap();
    assert_eq!(ty, ContentType::ApplicationData);
    assert_eq!(&wire[range], b"hello over aes-256");

    // Exporter agreement across the SHA-384 schedule.
    let mut ce = [0u8; 32];
    let mut se = [0u8; 32];
    client
        .export_keying_material("EXPORTER-x", b"ctx", &mut ce)
        .unwrap();
    server
        .export_keying_material("EXPORTER-x", b"ctx", &mut se)
        .unwrap();
    assert_eq!(ce, se);

    let _ = c2;
}
