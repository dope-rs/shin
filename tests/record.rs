use shin::aead::AeadKey;
use shin::hash::HashAlg;
use shin::record::{
    AEAD_TAG_LEN, ContentType, HEADER_LEN, MAX_PLAINTEXT_BODY, Opener, PROTOCOL_VERSION,
    PlaintextRecord, RecordError, Sealer,
};
use shin::schedule::TrafficKeys;

const TEST_SECRET: [u8; 32] = [
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
];

fn craft_wire(seq: u64, inner_plaintext: &[u8]) -> Vec<u8> {
    let keys = TrafficKeys::<16>::derive(HashAlg::Sha256, &TEST_SECRET);
    let aead = AeadKey::aes_128_gcm(&keys.key, keys.iv);
    let outer_body_len = inner_plaintext.len() + AEAD_TAG_LEN;
    let mut wire = Vec::with_capacity(HEADER_LEN);
    wire.push(ContentType::ApplicationData as u8);
    wire.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    wire.extend_from_slice(&(outer_body_len as u16).to_be_bytes());
    let ct = aead.seal(seq, &wire, inner_plaintext);
    wire.extend_from_slice(&ct);
    wire
}

#[test]
fn plaintext_round_trip() {
    let body = b"client-hello-bytes";
    let mut buf = Vec::new();
    PlaintextRecord::encode_into(ContentType::Handshake, body, &mut buf).unwrap();
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
    PlaintextRecord::encode_into(ContentType::Handshake, body, &mut buf).unwrap();
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
fn seal_into_staged_equals_seal_and_round_trips() {
    let body = b"hello tls record body";

    let mut allocating = Sealer::from_secret(&TEST_SECRET);
    let one = allocating.seal(ContentType::ApplicationData, body).unwrap();

    let mut staged = vec![0xAA, 0xBB];
    let mut into = Sealer::from_secret(&TEST_SECRET);
    into.seal_into(ContentType::ApplicationData, body, &mut staged)
        .unwrap();
    assert_eq!(&staged[2..], one.as_slice());

    let mut wire = staged[2..].to_vec();
    let mut opener = Opener::from_secret(&TEST_SECRET);
    let (inner_type, range, _) = opener.open(&mut wire).unwrap().unwrap();
    assert_eq!(inner_type, ContentType::ApplicationData);
    assert_eq!(&wire[range], body);
}

#[test]
fn seal_into_slice_matches_allocating_seal_byte_for_byte() {
    let body = b"hello tls record body";

    let mut allocating = Sealer::from_secret(&TEST_SECRET);
    let one = allocating.seal(ContentType::ApplicationData, body).unwrap();

    let mut wire = [0u8; HEADER_LEN + 64];
    let mut into = Sealer::from_secret(&TEST_SECRET);
    let n = into
        .seal_into_slice(ContentType::ApplicationData, body, &mut wire)
        .unwrap();
    assert_eq!(&wire[..n], one.as_slice());
}

#[test]
fn seal_into_slice_accepts_exact_fit_buffer() {
    let body = b"x";
    let total = HEADER_LEN + body.len() + 1 + AEAD_TAG_LEN;
    let mut exact = vec![0u8; total];
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let n = sealer
        .seal_into_slice(ContentType::ApplicationData, body, &mut exact)
        .unwrap();
    assert_eq!(n, total);
}

#[test]
fn seal_into_slice_rejects_undersized_buffer() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let mut tiny = [0u8; HEADER_LEN];
    assert_eq!(
        sealer.seal_into_slice(ContentType::ApplicationData, b"x", &mut tiny),
        Err(RecordError::BufferTooSmall)
    );
    assert_eq!(
        sealer.seq(),
        0,
        "a rejected seal must not spend the sequence"
    );
}

#[test]
fn encode_into_slice_matches_allocating_encode_byte_for_byte() {
    let body = b"client-hello-bytes";
    let one = PlaintextRecord::encode(ContentType::Handshake, body).unwrap();

    let mut wire = [0u8; HEADER_LEN + 64];
    let n = PlaintextRecord::encode_into_slice(ContentType::Handshake, body, &mut wire).unwrap();
    assert_eq!(&wire[..n], one.as_slice());
}

#[test]
fn encode_into_slice_rejects_undersized_buffer() {
    let mut tiny = [0u8; HEADER_LEN];
    assert_eq!(
        PlaintextRecord::encode_into_slice(ContentType::Handshake, b"x", &mut tiny),
        Err(RecordError::BufferTooSmall)
    );
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

#[test]
fn seal_refuses_oversize_body() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET);
    let big = vec![0u8; MAX_PLAINTEXT_BODY + 1];
    assert_eq!(
        sealer.seal(ContentType::ApplicationData, &big),
        Err(RecordError::BodyTooLarge)
    );
}

#[test]
fn encode_rejects_oversize_body() {
    let big = vec![0u8; MAX_PLAINTEXT_BODY + 1];
    let mut out = Vec::new();
    assert_eq!(
        PlaintextRecord::encode_into(ContentType::Handshake, &big, &mut out),
        Err(RecordError::BodyTooLarge)
    );
    assert!(out.is_empty());
}

#[test]
fn open_rejects_record_overflow() {
    let mut inner = vec![0u8; MAX_PLAINTEXT_BODY + 1];
    inner.push(ContentType::ApplicationData as u8);
    let mut wire = craft_wire(0, &inner);
    let mut opener = Opener::from_secret(&TEST_SECRET);
    assert_eq!(opener.open(&mut wire), Err(RecordError::RecordOverflow));
}

#[test]
fn open_accepts_max_plaintext() {
    let mut inner = vec![0u8; MAX_PLAINTEXT_BODY];
    inner.push(ContentType::ApplicationData as u8);
    let mut wire = craft_wire(0, &inner);
    let mut opener = Opener::from_secret(&TEST_SECRET);
    let (inner_type, range, _) = opener.open(&mut wire).unwrap().unwrap();
    assert_eq!(inner_type, ContentType::ApplicationData);
    assert_eq!(range.len(), MAX_PLAINTEXT_BODY);
}

#[test]
fn open_accepts_short_content_with_large_padding() {
    let mut inner = vec![b'h', b'i', ContentType::ApplicationData as u8];
    inner.resize(MAX_PLAINTEXT_BODY + 200, 0);
    let mut wire = craft_wire(0, &inner);
    let mut opener = Opener::from_secret(&TEST_SECRET);
    let (inner_type, range, _) = opener.open(&mut wire).unwrap().unwrap();
    assert_eq!(inner_type, ContentType::ApplicationData);
    assert_eq!(&wire[range], b"hi");
}
