use rcgen::{
    CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    SignatureAlgorithm,
};

use shin::cert::{Cert, VerifyError};

fn self_signed(alg: &'static SignatureAlgorithm, name: &str) -> Vec<u8> {
    let key = KeyPair::generate_for(alg).unwrap();
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

#[test]
fn verify_self_signed_ecdsa_p256() {
    let der = self_signed(&PKCS_ECDSA_P256_SHA256, "ec256.local");
    let cert = Cert::parse(&der).unwrap();
    cert.verify_signature(&cert.spki)
        .expect("self-sig verifies");
}

#[test]
fn verify_self_signed_ecdsa_p384() {
    let der = self_signed(&PKCS_ECDSA_P384_SHA384, "ec384.local");
    let cert = Cert::parse(&der).unwrap();
    cert.verify_signature(&cert.spki)
        .expect("self-sig verifies");
}

#[test]
fn verify_self_signed_ed25519() {
    let der = self_signed(&PKCS_ED25519, "ed25519.local");
    let cert = Cert::parse(&der).unwrap();
    cert.verify_signature(&cert.spki)
        .expect("self-sig verifies");
}

#[test]
fn tampered_signature_rejected() {
    let der = self_signed(&PKCS_ECDSA_P256_SHA256, "tamper.local");
    let cert = Cert::parse(&der).unwrap();
    let mut hacked = der.clone();
    let last = hacked.len() - 1;
    hacked[last] ^= 0x01;
    let cert2 = Cert::parse(&hacked).unwrap();
    assert_eq!(
        cert2.verify_signature(&cert2.spki).unwrap_err(),
        VerifyError::Failed
    );
}

#[test]
fn issuer_with_wrong_key_family_rejected() {
    let ec_der = self_signed(&PKCS_ECDSA_P256_SHA256, "ec.local");
    let ed_der = self_signed(&PKCS_ED25519, "ed.local");
    let ec = Cert::parse(&ec_der).unwrap();
    let ed = Cert::parse(&ed_der).unwrap();
    assert_eq!(
        ec.verify_signature(&ed.spki).unwrap_err(),
        VerifyError::AlgorithmMismatch
    );
}
