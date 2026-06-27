use shin::record::{CipherSuite, ContentType, Opener, RecordError, Sealer};

const SECRET: [u8; 32] = [0x42u8; 32];

#[test]
fn chacha20_round_trips() {
    let suite = CipherSuite::ChaCha20Poly1305Sha256;
    let mut sealer = Sealer::with_suite(&SECRET, suite);
    let mut wire = sealer
        .seal(ContentType::ApplicationData, b"hello chacha")
        .unwrap();
    let mut opener = Opener::with_suite(&SECRET, suite);
    let (inner_type, range, _) = opener.open(&mut wire).unwrap().unwrap();
    assert_eq!(inner_type, ContentType::ApplicationData);
    assert_eq!(&wire[range], b"hello chacha");
}

#[test]
fn chacha_record_does_not_open_under_aes() {
    let mut chacha = Sealer::with_suite(&SECRET, CipherSuite::ChaCha20Poly1305Sha256);
    let mut aes = Sealer::with_suite(&SECRET, CipherSuite::Aes128GcmSha256);
    let cw = chacha.seal(ContentType::ApplicationData, b"data").unwrap();
    let aw = aes.seal(ContentType::ApplicationData, b"data").unwrap();
    assert_ne!(cw, aw);

    let mut wire = chacha.seal(ContentType::ApplicationData, b"data").unwrap();
    let mut wrong = Opener::with_suite(&SECRET, CipherSuite::Aes128GcmSha256);
    assert_eq!(wrong.open(&mut wire), Err(RecordError::OpenFailed));
}
