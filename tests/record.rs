use shin::record::{
    AEAD_TAG_LEN, ContentType, HEADER_LEN, Opener, PROTOCOL_VERSION, PlaintextRecord, RecordError,
    Sealer,
};

const TEST_SECRET: [u8; 32] = [
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
];

#[test]
fn plaintext_round_trip() {
    let body = b"client-hello-bytes";
    let mut buf = Vec::new();
    PlaintextRecord::encode(ContentType::Handshake, body, &mut buf).unwrap();
    assert_eq!(buf[0], ContentType::Handshake as u8);
    assert_eq!(&buf[1..3], &PROTOCOL_VERSION.to_be_bytes());
    assert_eq!(&buf[3..5], &(body.len() as u16).to_be_bytes());
    assert_eq!(&buf[5..], body);

    let parsed = PlaintextRecord::parse(&buf).unwrap().unwrap();
    assert_eq!(parsed.0.content_type, ContentType::Handshake);
    assert_eq!(parsed.0.body, body);
    assert_eq!(parsed.1, buf.len());
}

#[test]
fn parse_plaintext_partial_returns_none() {
    let body = b"abc";
    let mut buf = Vec::new();
    PlaintextRecord::encode(ContentType::Handshake, body, &mut buf).unwrap();
    assert!(PlaintextRecord::parse(&buf[..3]).unwrap().is_none());
    assert!(
        PlaintextRecord::parse(&buf[..buf.len() - 1])
            .unwrap()
            .is_none()
    );
}

#[test]
fn parse_plaintext_rejects_unknown_content_type() {
    let buf = vec![99u8, 0x03, 0x03, 0x00, 0x00];
    assert_eq!(
        PlaintextRecord::parse(&buf).unwrap_err(),
        RecordError::BadContentType
    );
}

#[test]
fn ciphertext_round_trip_handshake_inner() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut opener = Opener::from_secret(&TEST_SECRET);

    let body = b"encrypted-extensions-payload";
    let mut wire = sealer.seal(ContentType::Handshake, body).unwrap();
    assert_eq!(wire[0], ContentType::ApplicationData as u8);
    assert_eq!(wire.len(), HEADER_LEN + body.len() + 1 + AEAD_TAG_LEN);

    let (inner_type, range, consumed) = opener.open(&mut wire).unwrap().unwrap();
    assert_eq!(inner_type, ContentType::Handshake);
    assert_eq!(consumed, wire.len());
    assert_eq!(&wire[range], body);
}

#[test]
fn ciphertext_round_trip_app_data_inner() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut opener = Opener::from_secret(&TEST_SECRET);

    let body = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    let mut wire = sealer.seal(ContentType::ApplicationData, body).unwrap();
    let (inner_type, range, _) = opener.open(&mut wire).unwrap().unwrap();
    assert_eq!(inner_type, ContentType::ApplicationData);
    assert_eq!(&wire[range], body);
}

#[test]
fn sequence_number_increments_per_record() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut opener = Opener::from_secret(&TEST_SECRET);

    for i in 0..5u8 {
        let body = vec![i; 32];
        let mut wire = sealer.seal(ContentType::ApplicationData, &body).unwrap();
        let (_, range, _) = opener.open(&mut wire).unwrap().unwrap();
        assert_eq!(&wire[range], &body);
    }
    assert_eq!(sealer.seq(), 5);
    assert_eq!(opener.seq(), 5);
}

#[test]
fn ciphertext_open_rejects_tampered_tag() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut opener = Opener::from_secret(&TEST_SECRET);
    let mut wire = sealer.seal(ContentType::ApplicationData, b"body").unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    assert_eq!(opener.open(&mut wire).unwrap_err(), RecordError::OpenFailed);
}

#[test]
fn ciphertext_open_rejects_wrong_seq_order() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut opener = Opener::from_secret(&TEST_SECRET);
    let _wire1 = sealer.seal(ContentType::ApplicationData, b"first").unwrap();
    let mut wire2 = sealer
        .seal(ContentType::ApplicationData, b"second")
        .unwrap();
    assert_eq!(
        opener.open(&mut wire2).unwrap_err(),
        RecordError::OpenFailed
    );
}

#[test]
fn open_returns_none_when_input_short() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut opener = Opener::from_secret(&TEST_SECRET);
    let wire = sealer.seal(ContentType::ApplicationData, b"hi").unwrap();

    let mut head = wire[..HEADER_LEN - 1].to_vec();
    assert!(opener.open(&mut head).unwrap().is_none());

    let mut full_header = wire[..HEADER_LEN + 5].to_vec();
    assert!(opener.open(&mut full_header).unwrap().is_none());
}

#[test]
fn open_rejects_plaintext_outer_type() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut opener = Opener::from_secret(&TEST_SECRET);
    let mut wire = sealer.seal(ContentType::Handshake, b"x").unwrap();
    wire[0] = ContentType::Handshake as u8;
    assert_eq!(
        opener.open(&mut wire).unwrap_err(),
        RecordError::NotCipherTextOuter
    );
}

#[test]
fn auth_failure_poisons_opener_so_later_valid_records_are_refused() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut tampered = sealer.seal(ContentType::ApplicationData, b"body").unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let mut opener = Opener::from_secret(&TEST_SECRET);
    assert_eq!(
        opener.open(&mut tampered).unwrap_err(),
        RecordError::OpenFailed
    );
    assert_eq!(opener.seq(), 0, "a forgery must not advance the sequence");

    let mut fresh = Sealer::from_secret(&TEST_SECRET);
    let mut good = fresh.seal(ContentType::ApplicationData, b"body").unwrap();
    assert_eq!(opener.open(&mut good).unwrap_err(), RecordError::Poisoned);
}
