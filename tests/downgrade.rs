use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::extension::{Extension, ExtensionType};
use shin::handshake::{Handshake, RANDOM_LEN, ServerHello, TLS_1_2};
use shin::{Epoch, Error, Event};

fn client() -> Client {
    Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
}

fn session_id_echo(events: &[Event]) -> Vec<u8> {
    // Irrelevant to the downgrade check; zeros suffice.
    let _ = events;
    vec![0u8; 32]
}

fn server_hello_bytes(random_tail: [u8; 8], echo: Vec<u8>) -> Vec<u8> {
    let mut random = [0u8; RANDOM_LEN];
    random[RANDOM_LEN - 8..].copy_from_slice(&random_tail);
    let sh = ServerHello {
        legacy_version: TLS_1_2,
        random,
        legacy_session_id_echo: echo,
        cipher_suite: 0x1301,
        legacy_compression_method: 0,
        extensions: vec![
            Extension::new(ExtensionType::SUPPORTED_VERSIONS, {
                let mut v = Vec::new();
                v.extend_from_slice(&0x0304u16.to_be_bytes());
                v
            }),
            Extension::new(ExtensionType::KEY_SHARE, {
                let mut v = Vec::new();
                v.extend_from_slice(&0x001du16.to_be_bytes());
                v.extend_from_slice(&32u16.to_be_bytes());
                v.extend_from_slice(&[0u8; 32]);
                v
            }),
        ],
    };
    let mut bytes = Vec::new();
    Handshake::ServerHello(sh).encode(&mut bytes);
    bytes
}

#[test]
fn downgrade_sentinel_tls12_rejected() {
    let mut c = client();
    let start = c.start().unwrap();
    let echo = session_id_echo(&start);
    let sh = server_hello_bytes([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01], echo);
    assert_eq!(
        c.read(Epoch::Plaintext, &sh).unwrap_err(),
        Error::DowngradeDetected
    );
}

#[test]
fn downgrade_sentinel_tls11_rejected() {
    let mut c = client();
    let start = c.start().unwrap();
    let echo = session_id_echo(&start);
    let sh = server_hello_bytes([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00], echo);
    assert_eq!(
        c.read(Epoch::Plaintext, &sh).unwrap_err(),
        Error::DowngradeDetected
    );
}

#[test]
fn non_sentinel_random_passes_downgrade_check() {
    // A non-sentinel tail must fail later (dummy key share), not as DowngradeDetected.
    let mut c = client();
    let start = c.start().unwrap();
    let echo = session_id_echo(&start);
    let sh = server_hello_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], echo);
    let err = c.read(Epoch::Plaintext, &sh).unwrap_err();
    assert_ne!(err, Error::DowngradeDetected);
}
