use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

use shin::cert::{
    BasicConstraints, Cert, ExtensionIter, GeneralName, KeyUsage, OID_EKU_CLIENT_AUTH,
    OID_EKU_SERVER_AUTH, OID_EXT_BASIC_CONSTRAINTS, OID_EXT_EXTENDED_KEY_USAGE, OID_EXT_KEY_USAGE,
    OID_EXT_SAN,
};

fn make_cert(setup: impl FnOnce(&mut CertificateParams)) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["host.local".into()]).unwrap();
    setup(&mut params);
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn iter_walks_all_entries() {
    let der = make_cert(|p| {
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(2));
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    });
    let cert = Cert::parse(&der).unwrap();
    let exts: Vec<_> = ExtensionIter::new(cert.extensions_der.unwrap())
        .map(|e| e.unwrap())
        .collect();
    assert!(!exts.is_empty());
    assert!(exts.iter().any(|e| e.oid == OID_EXT_BASIC_CONSTRAINTS));
    assert!(exts.iter().any(|e| e.oid == OID_EXT_KEY_USAGE));
}

#[test]
fn basic_constraints_ca_with_path_len() {
    let der = make_cert(|p| {
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(3));
    });
    let cert = Cert::parse(&der).unwrap();
    let (critical, val) =
        ExtensionIter::find(cert.extensions_der.unwrap(), OID_EXT_BASIC_CONSTRAINTS)
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
    let (_, val) = ExtensionIter::find(cert.extensions_der.unwrap(), OID_EXT_KEY_USAGE)
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
    let (_, val) = ExtensionIter::find(cert.extensions_der.unwrap(), OID_EXT_KEY_USAGE)
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
    let (_, val) = ExtensionIter::find(cert.extensions_der.unwrap(), OID_EXT_EXTENDED_KEY_USAGE)
        .unwrap()
        .expect("EKU present");
    let oids = KeyUsage::parse_extended(val).unwrap();
    assert!(oids.contains(&OID_EKU_SERVER_AUTH));
    assert!(oids.contains(&OID_EKU_CLIENT_AUTH));
}

#[test]
fn subject_alt_name_dns_entries() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params =
        CertificateParams::new(vec!["primary.example".into(), "alt.example".into()]).unwrap();
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let cert = Cert::parse(&der).unwrap();
    let (_, val) = ExtensionIter::find(cert.extensions_der.unwrap(), OID_EXT_SAN)
        .unwrap()
        .expect("SAN present");
    let names = GeneralName::parse_alt_names(val).unwrap();
    let dns: Vec<&[u8]> = names
        .iter()
        .filter_map(|n| match n {
            GeneralName::DnsName(d) => Some(*d),
            _ => None,
        })
        .collect();
    assert!(dns.contains(&&b"primary.example"[..]));
    assert!(dns.contains(&&b"alt.example"[..]));
}
