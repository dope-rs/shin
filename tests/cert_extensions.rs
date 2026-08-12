use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

use shin::identity::cert::Cert;
use shin::identity::cert::ext::scope::{GeneralName, GeneralNames, NameConstraints};
use shin::identity::cert::ext::{
    BasicConstraints, ExtendedKeyUsages, ExtensionIter, KeyUsage, OID_BASIC_CONSTRAINTS,
    OID_EKU_CLIENT_AUTH, OID_EKU_SERVER_AUTH, OID_EXTENDED_KEY_USAGE, OID_KEY_USAGE,
    OID_SUBJECT_ALT_NAME,
};

fn make_cert(setup: impl FnOnce(&mut CertificateParams)) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["host.local".into()]).unwrap();
    setup(&mut params);
    params.self_signed(&key).unwrap().der().to_vec()
}

fn extension(oid: u8) -> Vec<u8> {
    vec![0x30, 0x05, 0x06, 0x01, oid, 0x04, 0x00]
}

#[test]
fn iter_walks_all_entries() {
    let der = make_cert(|p| {
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(2));
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    });
    let cert = Cert::parse(&der).unwrap();
    let exts: Vec<_> = ExtensionIter::new(cert.tbs.extensions_der.unwrap())
        .map(|e| e.unwrap())
        .collect();
    assert!(!exts.is_empty());
    assert!(exts.iter().any(|e| e.oid.is(OID_BASIC_CONSTRAINTS)));
    assert!(exts.iter().any(|e| e.oid.is(OID_KEY_USAGE)));
}

#[test]
fn basic_constraints_ca_with_path_len() {
    let der = make_cert(|p| {
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(3));
    });
    let cert = Cert::parse(&der).unwrap();
    let (critical, val) =
        ExtensionIter::find(cert.tbs.extensions_der.unwrap(), OID_BASIC_CONSTRAINTS)
            .unwrap()
            .expect("BC present");
    assert!(critical, "BC should be critical for CA");
    let bc = BasicConstraints::parse(val).unwrap();
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(3));
}

#[test]
fn basic_constraints_default_when_absent() {
    let value = [0x30u8, 0x00];
    let bc = BasicConstraints::parse(&value).unwrap();
    assert_eq!(bc, BasicConstraints::default());
}

#[test]
fn basic_constraints_path_len_without_ca_rejected() {
    // SEQUENCE { INTEGER 3 } : pathLenConstraint with cA absent/FALSE is malformed.
    let value = [0x30u8, 0x03, 0x02, 0x01, 0x03];
    assert!(BasicConstraints::parse(&value).is_err());
}

#[test]
fn basic_constraints_ca_false_boolean_rejected() {
    // SEQUENCE { BOOLEAN FALSE } : DEFAULT FALSE must be omitted in DER.
    let value = [0x30u8, 0x03, 0x01, 0x01, 0x00];
    assert!(BasicConstraints::parse(&value).is_err());
}

#[test]
fn basic_constraints_ca_true_with_path_len_ok() {
    // SEQUENCE { BOOLEAN TRUE, INTEGER 2 }
    let value = [0x30u8, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02];
    let bc = BasicConstraints::parse(&value).unwrap();
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(2));
}

#[test]
fn key_usage_rejects_nonzero_unused_bits() {
    // BIT STRING, 1 unused bit, content byte 0x81: bit in the unused region is set.
    let value = [0x03u8, 0x02, 0x01, 0x81];
    assert!(KeyUsage::parse(&value).is_err());
}

#[test]
fn key_usage_rejects_trailing_zero_byte() {
    // BIT STRING, 0 unused, content {0x80, 0x00}: trailing all-zero byte is non-canonical.
    let value = [0x03u8, 0x03, 0x00, 0x80, 0x00];
    assert!(KeyUsage::parse(&value).is_err());
}

#[test]
fn key_usage_rejects_overlong_content() {
    // KeyUsage has at most 9 bits; a 3-byte content payload is invalid.
    let value = [0x03u8, 0x04, 0x00, 0x80, 0x00, 0x01];
    assert!(KeyUsage::parse(&value).is_err());
}

#[test]
fn key_usage_rejects_empty_nonminimal_and_unknown_bits() {
    assert!(KeyUsage::parse(&[0x03, 0x01, 0x00]).is_err());
    assert!(KeyUsage::parse(&[0x03, 0x02, 0x00, 0x80]).is_err());
    assert!(KeyUsage::parse(&[0x03, 0x03, 0x06, 0x00, 0x40]).is_err());
}

#[test]
fn key_usage_decipher_only_bit_honored() {
    // BIT STRING, 7 unused, content {0x00, 0x80}: only bit 8 (decipherOnly) set.
    let value = [0x03u8, 0x03, 0x07, 0x00, 0x80];
    let ku = KeyUsage::parse(&value).unwrap();
    assert_eq!(ku.raw_bits(), KeyUsage::DECIPHER_ONLY);
}

#[test]
fn key_usage_bits_decode() {
    let der = make_cert(|p| {
        p.is_ca = rcgen::IsCa::NoCa;
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
    });
    let cert = Cert::parse(&der).unwrap();
    let (_, val) = ExtensionIter::find(cert.tbs.extensions_der.unwrap(), OID_KEY_USAGE)
        .unwrap()
        .expect("KU present");
    let ku = KeyUsage::parse(val).unwrap();
    assert!(ku.has(KeyUsage::DIGITAL_SIGNATURE));
    assert!(ku.has(KeyUsage::KEY_ENCIPHERMENT));
    assert!(!ku.has(KeyUsage::KEY_CERT_SIGN));
}

#[test]
fn key_usage_cert_sign_alone() {
    let der = make_cert(|p| {
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    });
    let cert = Cert::parse(&der).unwrap();
    let (_, val) = ExtensionIter::find(cert.tbs.extensions_der.unwrap(), OID_KEY_USAGE)
        .unwrap()
        .unwrap();
    let ku = KeyUsage::parse(val).unwrap();
    assert!(ku.has(KeyUsage::KEY_CERT_SIGN));
    assert!(!ku.has(KeyUsage::DIGITAL_SIGNATURE));
}

#[test]
fn extended_key_usage_lists_purposes() {
    let der = make_cert(|p| {
        p.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
    });
    let cert = Cert::parse(&der).unwrap();
    let (_, val) = ExtensionIter::find(cert.tbs.extensions_der.unwrap(), OID_EXTENDED_KEY_USAGE)
        .unwrap()
        .expect("EKU present");
    let oids = ExtendedKeyUsages::parse(val).unwrap();
    assert!(oids.iter().any(|oid| oid.unwrap().is(OID_EKU_SERVER_AUTH)));
    assert!(oids.iter().any(|oid| oid.unwrap().is(OID_EKU_CLIENT_AUTH)));
}

#[test]
fn extended_key_usage_rejects_empty_sequence() {
    assert!(ExtendedKeyUsages::parse(&[0x30, 0x00]).is_err());
    assert!(ExtendedKeyUsages::parse(&[0x30, 0x02, 0x06, 0x00]).is_err());
}

#[test]
fn extension_rejects_malformed_oid_and_explicit_default_critical() {
    let malformed_oid = [0x30, 0x05, 0x06, 0x00, 0x04, 0x01, 0x00];
    assert!(ExtensionIter::new(&malformed_oid).next().unwrap().is_err());

    let explicit_false = [0x30, 0x08, 0x06, 0x01, 0x2a, 0x01, 0x01, 0x00, 0x04, 0x00];
    assert!(ExtensionIter::new(&explicit_false).next().unwrap().is_err());
}

#[test]
fn extension_iterator_bounds_and_exactly_rejects_duplicates() {
    let mut distinct = Vec::new();
    for oid in 0..63 {
        distinct.extend_from_slice(&extension(oid));
    }
    // OIDs 0 and 64 share this implementation's filter bit. Exact replay
    // must distinguish them rather than turning a filter collision into an error.
    distinct.extend_from_slice(&extension(64));
    assert_eq!(
        ExtensionIter::new(&distinct)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        64
    );

    distinct.extend_from_slice(&extension(63));
    assert_eq!(
        ExtensionIter::new(&distinct).last().unwrap().unwrap_err(),
        shin::identity::cert::Error::TooManyEntries
    );

    let mut duplicate = extension(42);
    duplicate.extend_from_slice(&extension(42));
    assert_eq!(
        ExtensionIter::new(&duplicate).last().unwrap().unwrap_err(),
        shin::identity::cert::Error::DuplicateExtension
    );
}

#[test]
fn subject_alt_name_dns_entries() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params =
        CertificateParams::new(vec!["primary.example".into(), "alt.example".into()]).unwrap();
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let cert = Cert::parse(&der).unwrap();
    let (_, val) = ExtensionIter::find(cert.tbs.extensions_der.unwrap(), OID_SUBJECT_ALT_NAME)
        .unwrap()
        .expect("SAN present");
    let names = GeneralNames::parse(val).unwrap();
    let dns: Vec<&[u8]> = names
        .iter()
        .filter_map(|name| match name.unwrap() {
            GeneralName::DnsName(dns) => Some(dns),
            _ => None,
        })
        .collect();
    assert!(dns.contains(&&b"primary.example"[..]));
    assert!(dns.contains(&&b"alt.example"[..]));
}

#[test]
fn name_constraints_reject_distance_fields_in_general_subtree() {
    // permittedSubtrees { dNSName "example.com", minimum 1 }
    let mut value = vec![
        0x30, 0x14, 0xa0, 0x12, 0x30, 0x10, 0x82, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        b'.', b'c', b'o', b'm', 0x80, 0x01, 0x01,
    ];
    assert!(NameConstraints::parse(&value).is_err());

    // maximum is also unsupported by the RFC 5280 profile and cannot be ignored.
    value[19] = 0x81;
    assert!(NameConstraints::parse(&value).is_err());
}

#[test]
fn name_constraints_reject_empty_sequences_and_subtree_sets() {
    assert!(NameConstraints::parse(&[0x30, 0x00]).is_err());
    assert!(NameConstraints::parse(&[0x30, 0x02, 0xa0, 0x00]).is_err());
}

#[test]
fn name_constraints_reject_invalid_ip_networks() {
    // An IPv4 constraint is address || mask and therefore exactly eight octets.
    let short = [0x30, 0x0a, 0xa0, 0x08, 0x30, 0x06, 0x87, 0x04, 10, 0, 0, 0];
    assert!(NameConstraints::parse(&short).is_err());

    // CIDR masks are contiguous; FF:00:FF:00 cannot describe a subtree.
    let non_contiguous = [
        0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a, 0x87, 0x08, 10, 0, 0, 0, 0xff, 0x00, 0xff, 0x00,
    ];
    assert!(NameConstraints::parse(&non_contiguous).is_err());
}

#[test]
fn subject_alt_name_rejects_empty_or_malformed_general_names() {
    assert!(GeneralNames::parse(&[0x30, 0x00]).is_err());
    assert!(GeneralNames::parse(&[0x30, 0x07, 0x87, 0x05, 127, 0, 0, 1, 0]).is_err());
    assert!(GeneralNames::parse(&[0x30, 0x03, 0x04, 0x01, 0x00]).is_err());
}
