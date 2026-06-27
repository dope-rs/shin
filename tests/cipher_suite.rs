use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::codec::Reader;
use shin::handshake::Handshake;
use shin::record::CipherSuite;
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

type TestClient = Client<fn() -> u64>;
type TestServer = Server<fn() -> u64>;

fn clock() -> u64 {
    1_000_000
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x6cu8; 32]).unwrap()
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

fn ch_with_suites(ch_bytes: &[u8], suites: Vec<u16>) -> Vec<u8> {
    let mut r = Reader::new(ch_bytes);
    let Handshake::ClientHello(mut ch) = Handshake::decode(&mut r).unwrap() else {
        panic!("not a ClientHello");
    };
    ch.cipher_suites = suites;
    let mut out = Vec::new();
    Handshake::ClientHello(ch).encode(&mut out);
    out
}

fn server_hello_suite(blob: &[u8]) -> u16 {
    let mut r = Reader::new(blob);
    let Handshake::ServerHello(sh) = Handshake::decode(&mut r).unwrap() else {
        panic!("not a ServerHello");
    };
    sh.cipher_suite
}

#[test]
fn both_suites_offered_negotiates_aes() {
    let mut server = server();
    let mut client = client();
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext);
    let s_hs = send(&s1, Epoch::Handshake);
    client.read(Epoch::Plaintext, &sh).unwrap();
    client.read(Epoch::Handshake, &s_hs).unwrap();

    // AES is server-preferred, so a client offering both keeps AES.
    assert_eq!(
        server.negotiated_cipher_suite(),
        Some(CipherSuite::Aes128GcmSha256)
    );
    assert_eq!(
        client.negotiated_cipher_suite(),
        Some(CipherSuite::Aes128GcmSha256)
    );
}

#[test]
fn server_selects_chacha_when_only_chacha_offered() {
    let mut server = server();
    let mut client = client();
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch = ch_with_suites(&ch, vec![0x1303]);

    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    assert_eq!(
        server.negotiated_cipher_suite(),
        Some(CipherSuite::ChaCha20Poly1305Sha256)
    );
    assert_eq!(server_hello_suite(&send(&s1, Epoch::Plaintext)), 0x1303);
}

#[test]
fn server_rejects_when_no_supported_suite_offered() {
    let mut server = server();
    let mut client = client();
    let ch = send(&client.start().unwrap(), Epoch::Plaintext);
    let ch = ch_with_suites(&ch, vec![0x9999]);
    assert_eq!(
        server.read(Epoch::Plaintext, &ch).unwrap_err(),
        shin::Error::UnsupportedCipherSuite,
    );
}
