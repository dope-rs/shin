use shin::asn1::{DerError, Reader, Tag, Tlv};

#[test]
fn short_form_length_decodes() {
    let mut r = Reader::new(&[0x30, 0x03, 0x02, 0x01, 0x42]);
    let seq = r.expect(Tag::SEQUENCE).unwrap();
    let mut inner = Reader::new(seq);
    let int_bytes = inner.expect(Tag::INTEGER).unwrap();
    assert_eq!(int_bytes, &[0x42]);
    inner.finish().unwrap();
    r.finish().unwrap();
}

#[test]
fn long_form_length_two_bytes() {
    let mut bytes = vec![0x04, 0x81, 0xc8];
    bytes.extend(std::iter::repeat_n(0xaa, 200));
    let mut r = Reader::new(&bytes);
    let s = r.expect(Tag::OCTET_STRING).unwrap();
    assert_eq!(s.len(), 200);
    r.finish().unwrap();
}

#[test]
fn long_form_minimal_check_rejects_redundant_short() {
    let bytes = [0x04, 0x81, 0x7f];
    assert_eq!(Reader::new(&bytes).next().unwrap_err(), DerError::BadLength);
}

#[test]
fn indefinite_length_rejected() {
    let bytes = [0x04, 0x80];
    assert_eq!(Reader::new(&bytes).next().unwrap_err(), DerError::BadLength);
}

#[test]
fn integer_with_leading_zero_is_unsigned_disambiguator() {
    let bytes = [0x02, 0x02, 0x00, 0x80];
    let mut r = Reader::new(&bytes);
    let int = r.expect(Tag::INTEGER).unwrap();
    let v = Tlv::integer_be(int).unwrap();
    assert_eq!(v, &[0x80]);
}

#[test]
fn integer_redundant_leading_zero_rejected() {
    let bytes = [0x02, 0x02, 0x00, 0x42];
    let mut r = Reader::new(&bytes);
    let int = r.expect(Tag::INTEGER).unwrap();
    assert_eq!(Tlv::integer_be(int).unwrap_err(), DerError::BadInteger);
}

#[test]
fn integer_u64_round_trip() {
    let bytes = [0x02, 0x05, 0x01, 0x23, 0x45, 0x67, 0x89];
    let mut r = Reader::new(&bytes);
    let int = r.expect(Tag::INTEGER).unwrap();
    assert_eq!(Tlv::integer_u64(int).unwrap(), 0x01_2345_6789);
}

#[test]
fn integer_u64_overflow_rejected() {
    let bytes = [
        0x02, 0x09, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let mut r = Reader::new(&bytes);
    let int = r.expect(Tag::INTEGER).unwrap();
    assert_eq!(Tlv::integer_u64(int).unwrap_err(), DerError::BadInteger);
}

#[test]
fn bit_string_zero_unused_bits() {
    let bytes = [0x03, 0x04, 0x00, 0xde, 0xad, 0xbe];
    let mut r = Reader::new(&bytes);
    let bs = r.expect(Tag::BIT_STRING).unwrap();
    assert_eq!(Tlv::bit_string(bs).unwrap(), &[0xde, 0xad, 0xbe]);
}

#[test]
fn bit_string_nonzero_unused_bits_rejected() {
    let bytes = [0x03, 0x02, 0x04, 0xff];
    let mut r = Reader::new(&bytes);
    let bs = r.expect(Tag::BIT_STRING).unwrap();
    assert_eq!(Tlv::bit_string(bs).unwrap_err(), DerError::BadBitString);
}

#[test]
fn oid_decode_rsa_encryption() {
    let bytes = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let mut r = Reader::new(&bytes);
    let oid = r.expect(Tag::OID).unwrap();
    assert_eq!(Tlv::oid(oid).unwrap(), vec![1, 2, 840, 113549, 1, 1, 1]);
    assert!(Tlv::oid_eq(
        oid,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
    ));
}

#[test]
fn boolean_strict() {
    let yes = [0x01, 0x01, 0xff];
    let no = [0x01, 0x01, 0x00];
    let bad = [0x01, 0x01, 0x01];
    let mut r = Reader::new(&yes);
    assert!(Tlv::boolean(r.expect(Tag::BOOLEAN).unwrap()).unwrap());
    let mut r = Reader::new(&no);
    assert!(!Tlv::boolean(r.expect(Tag::BOOLEAN).unwrap()).unwrap());
    let mut r = Reader::new(&bad);
    assert_eq!(
        Tlv::boolean(r.expect(Tag::BOOLEAN).unwrap()).unwrap_err(),
        DerError::BadBool
    );
}

#[test]
fn read_optional_skips_when_tag_mismatches() {
    let bytes = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, b'a', b'b'];
    let mut r = Reader::new(&bytes);
    let seq = r.expect(Tag::SEQUENCE).unwrap();
    let mut inner = Reader::new(seq);
    assert!(inner.read_optional(Tag::BIT_STRING).unwrap().is_none());
    let int = inner.expect(Tag::INTEGER).unwrap();
    assert_eq!(int, &[0x01]);
    let s = inner.expect(Tag::OCTET_STRING).unwrap();
    assert_eq!(s, b"ab");
    inner.finish().unwrap();
    r.finish().unwrap();
}

#[test]
fn trailing_garbage_rejected_by_finish() {
    let bytes = [0x02, 0x01, 0x01, 0xff];
    let mut r = Reader::new(&bytes);
    let _ = r.expect(Tag::INTEGER).unwrap();
    assert_eq!(r.finish().unwrap_err(), DerError::Trailing);
}

#[test]
fn underflow_when_length_exceeds_buffer() {
    let bytes = [0x04, 0x05, 0x01, 0x02];
    assert_eq!(Reader::new(&bytes).next().unwrap_err(), DerError::Underflow);
}

#[test]
fn long_form_leading_zero_length_rejected() {
    let mut bytes = vec![0x04, 0x82, 0x00, 0xff];
    bytes.extend(std::iter::repeat_n(0xaa, 0xff));
    assert_eq!(Reader::new(&bytes).next().unwrap_err(), DerError::BadLength);
}

#[test]
fn oid_non_minimal_subidentifier_rejected() {
    let oid = [0x06, 0x03, 0x2a, 0x80, 0x01];
    let (tlv, _) = Tlv::parse_one(&oid).unwrap();
    assert_eq!(Tlv::oid(tlv.contents).unwrap_err(), DerError::BadOid);
}

#[test]
fn oid_subidentifier_overflow_rejected() {
    let oid = [0x06, 0x07, 0x2a, 0x90, 0x80, 0x80, 0x80, 0x80, 0x00];
    let (tlv, _) = Tlv::parse_one(&oid).unwrap();
    assert_eq!(Tlv::oid(tlv.contents).unwrap_err(), DerError::BadOid);
}

#[test]
fn truncated_oid_continuation_rejected() {
    let oid = [0x06, 0x02, 0x2a, 0x80];
    let (tlv, _) = Tlv::parse_one(&oid).unwrap();
    assert_eq!(Tlv::oid(tlv.contents).unwrap_err(), DerError::BadOid);
}
