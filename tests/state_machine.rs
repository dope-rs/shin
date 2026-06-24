use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::codec::{DecodeError, Reader};
use shin::handshake::Handshake;
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

#[test]
fn key_update_rejects_invalid_request_value() {
    // KeyUpdate (type 24) with body length 1 and request_update = 2.
    let bytes = [24u8, 0x00, 0x00, 0x01, 0x02];
    let mut r = Reader::new(&bytes);
    assert_eq!(
        Handshake::decode(&mut r).unwrap_err(),
        DecodeError::InvalidEnum
    );
}

#[test]
fn key_update_accepts_zero_and_one() {
    for v in [0u8, 1u8] {
        let bytes = [24u8, 0x00, 0x00, 0x01, v];
        let mut r = Reader::new(&bytes);
        Handshake::decode(&mut r).expect("valid KeyUpdate");
    }
}

#[test]
fn client_rejects_finished_before_server_hello() {
    let mut c = client();
    c.start().unwrap();
    // Finished (type 20) at handshake epoch while still in ExpectServerHello.
    let bytes = [20u8, 0x00, 0x00, 0x00];
    assert_eq!(
        c.read(Epoch::Handshake, &bytes).unwrap_err(),
        Error::UnexpectedMessage
    );
}

#[test]
fn client_rejects_server_hello_at_wrong_epoch() {
    let mut c = client();
    let start = c.start().unwrap();
    assert!(matches!(start.first(), Some(Event::Send { .. })));
    // A ServerHello at the handshake (not plaintext) epoch must be rejected.
    let sh = [2u8, 0x00, 0x00, 0x02, 0x03, 0x03];
    let err = c.read(Epoch::Handshake, &sh).unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage | Error::Decode));
}
