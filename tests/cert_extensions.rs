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
