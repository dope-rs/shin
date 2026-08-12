use shin::identity::asn1::{BitString, DerError, Oid, Reader, Tag, Uint};

#[test]
fn validated_primitives_are_single_slice_views() {
    use core::mem::size_of;

    let slice = size_of::<&[u8]>();
    assert_eq!(size_of::<Oid<'static>>(), slice);
    assert_eq!(size_of::<Uint<'static>>(), slice);
    assert_eq!(size_of::<BitString<'static>>(), slice);
}

#[test]
fn short_form_length_decodes() {
    let mut r = Reader::new(&[0x30, 0x03, 0x02, 0x01, 0x42]);
    let seq = r.read_tagged(Tag::SEQUENCE).unwrap();
    let mut inner = Reader::new(seq);
    let integer = inner.read_uint().unwrap();
    assert_eq!(integer.as_bytes(), &[0x42]);
    inner.finish().unwrap();
    r.finish().unwrap();
}

#[test]
fn long_form_length_two_bytes() {
    let mut bytes = vec![0x04, 0x81, 0xc8];
    bytes.extend(std::iter::repeat_n(0xaa, 200));
    let mut r = Reader::new(&bytes);
    let s = r.read_tagged(Tag::OCTET_STRING).unwrap();
    assert_eq!(s.len(), 200);
    r.finish().unwrap();
}

#[test]
fn long_form_minimal_check_rejects_redundant_short() {
    let bytes = [0x04, 0x81, 0x7f];
    assert_eq!(
        Reader::new(&bytes).read_tlv().unwrap_err(),
        DerError::BadLength
    );
}

#[test]
fn indefinite_length_rejected() {
    let bytes = [0x04, 0x80];
    assert_eq!(
        Reader::new(&bytes).read_tlv().unwrap_err(),
        DerError::BadLength
    );
}

#[test]
fn integer_with_leading_zero_is_unsigned_disambiguator() {
    let bytes = [0x02, 0x02, 0x00, 0x80];
    let mut r = Reader::new(&bytes);
    let integer = r.read_uint().unwrap();
    assert_eq!(integer.magnitude(), &[0x80]);
}

#[test]
fn integer_redundant_leading_zero_rejected() {
    let bytes = [0x02, 0x02, 0x00, 0x42];
    let mut r = Reader::new(&bytes);
    assert_eq!(r.read_uint().unwrap_err(), DerError::BadInteger);
}

#[test]
fn unsigned_integer_rejects_empty_and_negative_encodings() {
    assert_eq!(
        Reader::new(&[0x02, 0x00]).read_uint().unwrap_err(),
        DerError::BadInteger
    );
    assert_eq!(
        Reader::new(&[0x02, 0x01, 0x80]).read_uint().unwrap_err(),
        DerError::BadInteger
    );
}

#[test]
fn integer_u64_round_trip() {
    let bytes = [0x02, 0x05, 0x01, 0x23, 0x45, 0x67, 0x89];
    let mut r = Reader::new(&bytes);
    assert_eq!(r.read_uint().unwrap().to_u64().unwrap(), 0x01_2345_6789);
}

#[test]
fn integer_u64_overflow_rejected() {
    let bytes = [
        0x02, 0x09, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let mut r = Reader::new(&bytes);
    assert_eq!(
        r.read_uint().unwrap().to_u64().unwrap_err(),
        DerError::BadInteger
    );
}

#[test]
fn bit_string_zero_unused_bits() {
    let bytes = [0x03, 0x04, 0x00, 0xde, 0xad, 0xbe];
    let mut r = Reader::new(&bytes);
    assert_eq!(
        r.read_bit_string().unwrap().octets().unwrap(),
        &[0xde, 0xad, 0xbe]
    );
}

#[test]
fn bit_string_nonzero_unused_bits_rejected() {
    let bytes = [0x03, 0x02, 0x04, 0xff];
    let mut r = Reader::new(&bytes);
    assert_eq!(r.read_bit_string().unwrap_err(), DerError::BadBitString);
}

#[test]
fn bit_string_rejects_missing_unused_bit_count() {
    assert_eq!(
        Reader::new(&[0x03, 0x00]).read_bit_string().unwrap_err(),
        DerError::BadBitString
    );
}

#[test]
fn oid_decode_rsa_encryption() {
    let bytes = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let mut r = Reader::new(&bytes);
    let oid = r.read_oid().unwrap();
    assert!(oid.is(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,]));
}

#[test]
fn boolean_strict() {
    let yes = [0x01, 0x01, 0xff];
    let no = [0x01, 0x01, 0x00];
    let bad = [0x01, 0x01, 0x01];
    let mut r = Reader::new(&yes);
    assert!(r.read_bool().unwrap());
    let mut r = Reader::new(&no);
    assert!(!r.read_bool().unwrap());
    let mut r = Reader::new(&bad);
    assert_eq!(r.read_bool().unwrap_err(), DerError::BadBool);
}

#[test]
fn read_optional_skips_when_tag_mismatches() {
    let bytes = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, b'a', b'b'];
    let mut r = Reader::new(&bytes);
    let seq = r.read_tagged(Tag::SEQUENCE).unwrap();
    let mut inner = Reader::new(seq);
    assert!(inner.read_optional(Tag::BIT_STRING).unwrap().is_none());
    assert_eq!(inner.read_uint().unwrap().to_u64().unwrap(), 1);
    let s = inner.read_tagged(Tag::OCTET_STRING).unwrap();
    assert_eq!(s, b"ab");
    inner.finish().unwrap();
    r.finish().unwrap();
}

#[test]
fn trailing_garbage_rejected_by_finish() {
    let bytes = [0x02, 0x01, 0x01, 0xff];
    let mut r = Reader::new(&bytes);
    let _ = r.read_uint().unwrap();
    assert_eq!(r.finish().unwrap_err(), DerError::Trailing);
}

#[test]
fn underflow_when_length_exceeds_buffer() {
    let bytes = [0x04, 0x05, 0x01, 0x02];
    assert_eq!(
        Reader::new(&bytes).read_tlv().unwrap_err(),
        DerError::Underflow
    );
}

#[test]
fn long_form_leading_zero_length_rejected() {
    let mut bytes = vec![0x04, 0x82, 0x00, 0xff];
    bytes.extend(std::iter::repeat_n(0xaa, 0xff));
    assert_eq!(
        Reader::new(&bytes).read_tlv().unwrap_err(),
        DerError::BadLength
    );
}

#[test]
fn oid_non_minimal_subidentifier_rejected() {
    let oid = [0x06, 0x03, 0x2a, 0x80, 0x01];
    assert_eq!(Reader::new(&oid).read_oid().unwrap_err(), DerError::BadOid);
}

#[test]
fn oid_empty_contents_rejected() {
    assert_eq!(
        Reader::new(&[0x06, 0x00]).read_oid().unwrap_err(),
        DerError::BadOid
    );
}

#[test]
fn oid_large_subidentifier_is_valid_without_numeric_materialization() {
    let oid = [0x06, 0x07, 0x2a, 0x90, 0x80, 0x80, 0x80, 0x80, 0x00];
    assert_eq!(Reader::new(&oid).read_oid().unwrap().as_bytes(), &oid[2..]);
}

#[test]
fn truncated_oid_continuation_rejected() {
    let oid = [0x06, 0x02, 0x2a, 0x80];
    assert_eq!(Reader::new(&oid).read_oid().unwrap_err(), DerError::BadOid);
}

#[test]
fn oid_multibyte_first_subidentifier_is_valid() {
    let oid = [0x06, 0x03, 0x88, 0x37, 0x03];
    assert_eq!(
        Reader::new(&oid).read_oid().unwrap().as_bytes(),
        &[0x88, 0x37, 0x03]
    );
}

#[test]
fn bit_string_preserves_valid_unused_bit_count() {
    let value = [0x03, 0x02, 0x04, 0xf0];
    let bits = Reader::new(&value).read_bit_string().unwrap();
    assert_eq!(bits.as_bytes(), &[0xf0]);
    assert_eq!(bits.unused_bits(), 4);
}

#[test]
fn unsupported_identifier_forms_are_rejected_without_misparsing_length() {
    assert_eq!(
        Reader::new(&[0x00, 0x00]).read_tlv().unwrap_err(),
        DerError::BadTag
    );
    assert_eq!(
        Reader::new(&[0x1f, 0x01, 0x00]).read_tlv().unwrap_err(),
        DerError::BadTag
    );
}
