use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SerialNumber};
use shin::identity::asn1::{DerError, Tag};
use shin::identity::cert::Cert;
use shin::identity::cert::algorithm::{PublicKey, Signature};

fn gen_self_signed(name: &str) -> Vec<u8> {
    let cert = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    cert.cert.der().to_vec()
}

fn cert_with_serial(serial: &[u8]) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["serial.local".into()]).unwrap();
    params.serial_number = Some(SerialNumber::from_slice(serial));
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn parses_rcgen_self_signed_cert() {
    let der = gen_self_signed("example.local");
    let cert = Cert::parse(&der).expect("parse cert");
    assert_eq!(cert.tbs.version, 3);
    assert!(!cert.tbs.serial.is_zero());
    assert_ne!(cert.tbs.signature_alg, Signature::Unsupported);
    assert!(!cert.signature.bytes.is_empty());
    assert!(cert.tbs.validity.not_before <= cert.tbs.validity.not_after);
    assert!(!cert.tbs.spki.subject_public_key.is_empty());
    assert!(cert.tbs.extensions_der.is_some());
}

#[test]
fn tbs_der_slice_round_trips_when_re_parsed() {
    let der = gen_self_signed("rt.local");
    let cert = Cert::parse(&der).expect("parse cert");
    let (tlv, rest) = shin::identity::asn1::Tlv::parse_one(cert.tbs_der).unwrap();
    assert_eq!(tlv.tag, Tag::SEQUENCE);
    assert!(rest.is_empty(), "tbs_der is exactly one TLV");
}

#[test]
fn spki_algorithm_is_typed_during_parsing() {
    let der = gen_self_signed("kx.local");
    let cert = Cert::parse(&der).expect("parse cert");
    assert!(
        !matches!(cert.tbs.spki.algorithm, PublicKey::Unsupported),
        "unexpected SPKI algorithm: {:?}",
        cert.tbs.spki.algorithm,
    );
}

#[test]
fn parse_rejects_trailing_garbage() {
    let mut der = gen_self_signed("trail.local");
    der.push(0x00);
    let err = Cert::parse(&der).unwrap_err();
    assert!(
        matches!(
            err,
            shin::identity::cert::Error::Der(shin::identity::asn1::DerError::Trailing)
        ),
        "got {err:?}"
    );
}

#[test]
fn parse_rejects_truncated_cert() {
    let der = gen_self_signed("truncate.local");
    let err = Cert::parse(&der[..der.len() - 5]).unwrap_err();
    assert!(matches!(
        err,
        shin::identity::cert::Error::Der(shin::identity::asn1::DerError::Underflow)
    ));
}

const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

fn find_last(hay: &[u8], needle: &[u8]) -> Option<usize> {
    (0..=hay.len().saturating_sub(needle.len()))
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

#[test]
fn rejects_signature_algorithm_substitution() {
    // Parse must reject when the inner TBS `signature` and the outer
    // `signatureAlgorithm` AlgorithmIdentifiers disagree (RFC 5280 4.1.1.2).
    let der = gen_self_signed("sigalg.local");
    let cert = Cert::parse(&der).expect("baseline parses");
    assert_eq!(cert.tbs.signature_alg, Signature::EcdsaSha256);

    // Flip the last byte of the outer signatureAlgorithm OID (last occurrence).
    let mut tampered = der.clone();
    let pos = find_last(&tampered, OID_ECDSA_SHA256).expect("sig oid present");
    let last = pos + OID_ECDSA_SHA256.len() - 1;
    tampered[last] = 0x03; // turns ...0403_02 into ...0403_03 (ECDSA-SHA384)
    assert_eq!(
        Cert::parse(&tampered).unwrap_err(),
        shin::identity::cert::Error::BadAlgorithm
    );
}

#[test]
fn rejects_explicit_default_version() {
    // An explicit version field encoding v1 (INTEGER 0) violates the DER
    // DEFAULT-omission rule and must be rejected.
    let der = gen_self_signed("ver.local");
    let cert = Cert::parse(&der).expect("baseline parses");
    assert_eq!(cert.tbs.version, 3);

    // v3 cert begins TBS with [0]{ INTEGER 2 } = a0 03 02 01 02.
    let v3 = [0xa0u8, 0x03, 0x02, 0x01, 0x02];
    let pos = find_last(&der, &v3).expect("v3 version prefix present");
    // Locate the first occurrence (inside TBS) instead.
    let pos = (0..=der.len() - v3.len())
        .find(|&i| der[i..i + v3.len()] == v3)
        .unwrap_or(pos);
    let mut tampered = der.clone();
    tampered[pos + 4] = 0x00; // INTEGER value 2 -> 0 (explicit v1)
    assert_eq!(
        Cert::parse(&tampered).unwrap_err(),
        shin::identity::cert::Error::BadVersion
    );
}

#[test]
fn rejects_zero_and_overlong_serial_numbers() {
    assert_eq!(
        Cert::parse(&cert_with_serial(&[0])).unwrap_err(),
        shin::identity::cert::Error::BadSerial
    );
    assert_eq!(
        Cert::parse(&cert_with_serial(&[1; 21])).unwrap_err(),
        shin::identity::cert::Error::BadSerial
    );
}

#[test]
fn rejects_noncanonical_serial_number() {
    let der = gen_self_signed("serial-der.local");
    let cert = Cert::parse(&der).unwrap();
    let offset = cert.tbs.serial.as_bytes().as_ptr() as usize - der.as_ptr() as usize;
    let mut tampered = der.clone();
    tampered[offset] = 0;
    tampered[offset + 1] &= 0x7f;
    assert_eq!(
        Cert::parse(&tampered).unwrap_err(),
        shin::identity::cert::Error::Der(DerError::BadInteger)
    );
}

#[test]
fn rejects_malformed_name_and_algorithm_oids() {
    let der = gen_self_signed("oid.local");
    for oid in [&[0x55, 0x04, 0x03][..], OID_ECDSA_SHA256] {
        let position = der
            .windows(oid.len())
            .position(|candidate| candidate == oid)
            .unwrap();
        let mut tampered = der.clone();
        tampered[position] = 0x80;
        assert_eq!(
            Cert::parse(&tampered).unwrap_err(),
            shin::identity::cert::Error::Der(DerError::BadOid)
        );
    }
}
