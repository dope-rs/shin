use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rustls_pki_types::PrivatePkcs8KeyDer;

use shin::crypto::sig::SigningKey;
use shin::identity::cert::{Cert, SubjectPublicKeyInfo, VerifyError};

const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const SHA1_OID: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const UNKNOWN_HASH_OID: &[u8] = &[0x2a, 0x03];
const RSASSA_PSS_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const MGF1_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const RSA_SHA256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const EC_PUBLIC_KEY_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const ECDSA_SHA256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];

fn rsa_cert() -> Vec<u8> {
    rsa_cert_and_key().0
}

fn rsa_cert_and_key() -> (Vec<u8>, SigningKey) {
    let mut rng = rsa::rand_core::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pkcs8 = priv_key.to_pkcs8_der().unwrap();
    let signing_key = SigningKey::from_rsa_pkcs8(pkcs8.as_bytes()).unwrap();
    let pki = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
    let key = KeyPair::from_pkcs8_der_and_sign_algo(&pki, &PKCS_RSA_SHA256).unwrap();
    let params = CertificateParams::new(vec!["pss.local".into()]).unwrap();
    (
        params.self_signed(&key).unwrap().der().to_vec(),
        signing_key,
    )
}

fn der_len(b: &[u8], i: usize) -> (usize, usize) {
    let first = b[i];
    if first & 0x80 == 0 {
        (first as usize, i + 1)
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0;
        for k in 0..n {
            len = (len << 8) | b[i + 1 + k] as usize;
        }
        (len, i + 1 + n)
    }
}

fn elem_end(b: &[u8], tag_at: usize) -> usize {
    let (len, value_at) = der_len(b, tag_at + 1);
    value_at + len
}

fn enc_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else if n < 0x10000 {
        vec![0x82, (n >> 8) as u8, n as u8]
    } else {
        vec![0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    }
}

fn seq(content: &[u8]) -> Vec<u8> {
    let mut o = vec![0x30];
    o.extend(enc_len(content.len()));
    o.extend_from_slice(content);
    o
}

fn oid_tlv(oid: &[u8]) -> Vec<u8> {
    let mut o = vec![0x06, oid.len() as u8];
    o.extend_from_slice(oid);
    o
}

fn integer(value: u8) -> Vec<u8> {
    vec![0x02, 0x01, value]
}

fn explicit(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 | tag];
    out.extend(enc_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn algorithm(oid: &[u8], parameters: Option<&[u8]>) -> Vec<u8> {
    let mut content = oid_tlv(oid);
    if let Some(parameters) = parameters {
        content.extend_from_slice(parameters);
    }
    seq(&content)
}

fn pss_sig_alg(params: &[u8]) -> Vec<u8> {
    algorithm(RSASSA_PSS_OID, Some(params))
}

fn pss_params(hash_oid: &[u8], mask_hash_oid: &[u8], salt_length: u8) -> Vec<u8> {
    let hash = algorithm(hash_oid, None);
    let mask_hash = algorithm(mask_hash_oid, Some(&[0x05, 0x00]));
    let mask = algorithm(MGF1_OID, Some(&mask_hash));
    let mut fields = explicit(0, &hash);
    fields.extend(explicit(1, &mask));
    if salt_length != 20 {
        fields.extend(explicit(2, &integer(salt_length)));
    }
    seq(&fields)
}

fn params_with_hash(hash_oid: &[u8]) -> Vec<u8> {
    let hash = algorithm(hash_oid, None);
    seq(&explicit(0, &hash))
}

// TBSCertificate content is [version[0], serialNumber, signature, ...]; replace
// the third element (signature AlgorithmIdentifier).
fn patch_tbs_sig_alg(tbs: &[u8], new_sig_alg: &[u8]) -> Vec<u8> {
    let (_, cs) = der_len(tbs, 1);
    let version_end = elem_end(tbs, cs);
    let serial_end = elem_end(tbs, version_end);
    let sig_alg_end = elem_end(tbs, serial_end);
    let mut content = Vec::new();
    content.extend_from_slice(&tbs[cs..serial_end]);
    content.extend_from_slice(new_sig_alg);
    content.extend_from_slice(&tbs[sig_alg_end..]);
    seq(&content)
}

// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
// Rewrite both signature-algorithm fields to RSASSA-PSS with the given params so
// Cert::parse (which requires the two to match) accepts it.
fn patch_signature_algorithm(cert: &[u8], new_sig_alg: &[u8]) -> Vec<u8> {
    let (_, cs) = der_len(cert, 1);
    let tbs_end = elem_end(cert, cs);
    let sig_alg_end = elem_end(cert, tbs_end);
    let sig_value_end = elem_end(cert, sig_alg_end);
    let new_tbs = patch_tbs_sig_alg(&cert[cs..tbs_end], new_sig_alg);
    let mut content = Vec::new();
    content.extend_from_slice(&new_tbs);
    content.extend_from_slice(new_sig_alg);
    content.extend_from_slice(&cert[sig_alg_end..sig_value_end]);
    seq(&content)
}

fn patch_to_pss(cert: &[u8], params: &[u8]) -> Vec<u8> {
    patch_signature_algorithm(cert, &pss_sig_alg(params))
}

fn spki(algorithm: Vec<u8>, public_key: &[u8]) -> Vec<u8> {
    let mut bit_string = vec![0x03];
    bit_string.extend(enc_len(public_key.len() + 1));
    bit_string.push(0);
    bit_string.extend_from_slice(public_key);
    let mut contents = algorithm;
    contents.extend(bit_string);
    seq(&contents)
}

fn pss_spki(public_key: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    spki(algorithm(RSASSA_PSS_OID, params), public_key)
}

#[test]
fn pss_sha256_profile_verifies_a_real_signature() {
    let (cert_der, signing_key) = rsa_cert_and_key();
    let mut cert_der = patch_to_pss(&cert_der, &pss_params(SHA256_OID, SHA256_OID, 32));
    let (signature_offset, signature_len, signature) = {
        let cert = Cert::parse(&cert_der).expect("patched PSS cert parses");
        let signature = signing_key.sign(cert.tbs_der).unwrap();
        (
            cert.signature.bytes.as_ptr() as usize - cert_der.as_ptr() as usize,
            cert.signature.bytes.len(),
            signature,
        )
    };
    assert_eq!(signature.len(), signature_len);
    cert_der[signature_offset..signature_offset + signature_len].copy_from_slice(&signature);
    let cert = Cert::parse(&cert_der).unwrap();
    cert.verify_signature(&cert.tbs.spki).unwrap();
}

#[test]
fn pss_mgf_hash_must_match_the_signature_profile() {
    let params = pss_params(SHA256_OID, SHA384_OID, 32);
    let cert_der = patch_to_pss(&rsa_cert(), &params);
    let cert = Cert::parse(&cert_der).expect("well-formed PSS parameters parse");
    assert_eq!(
        cert.verify_signature(&cert.tbs.spki).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}

#[test]
fn pss_salt_length_must_match_the_available_verifier() {
    let params = pss_params(SHA256_OID, SHA256_OID, 20);
    let cert_der = patch_to_pss(&rsa_cert(), &params);
    let cert = Cert::parse(&cert_der).expect("well-formed PSS parameters parse");
    assert_eq!(
        cert.verify_signature(&cert.tbs.spki).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}

#[test]
fn pss_rejects_unsupported_trailer_field() {
    let mut fields = pss_params(SHA256_OID, SHA256_OID, 32);
    let (_, contents_at) = der_len(&fields, 1);
    let mut contents = fields.split_off(contents_at);
    contents.extend(explicit(3, &integer(2)));
    let params = seq(&contents);
    let cert_der = patch_to_pss(&rsa_cert(), &params);
    assert_eq!(
        Cert::parse(&cert_der).unwrap_err(),
        shin::identity::cert::Error::BadAlgorithm
    );
}

#[test]
fn pss_rejects_trailing_parameter_fields() {
    let mut fields = pss_params(SHA256_OID, SHA256_OID, 32);
    let (_, contents_at) = der_len(&fields, 1);
    let mut contents = fields.split_off(contents_at);
    contents.extend_from_slice(&[0x05, 0x00]);
    let params = seq(&contents);
    let cert_der = patch_to_pss(&rsa_cert(), &params);
    assert!(Cert::parse(&cert_der).is_err());
}

#[test]
fn pss_spki_constraints_reject_a_different_hash() {
    let signature_params = pss_params(SHA256_OID, SHA256_OID, 32);
    let cert_der = patch_to_pss(&rsa_cert(), &signature_params);
    let cert = Cert::parse(&cert_der).unwrap();
    let key_params = pss_params(SHA384_OID, SHA384_OID, 48);
    let spki_der = pss_spki(cert.tbs.spki.subject_public_key, Some(&key_params));
    let issuer = SubjectPublicKeyInfo::parse_standalone(&spki_der).unwrap();
    assert_eq!(
        cert.verify_signature(&issuer).unwrap_err(),
        VerifyError::AlgorithmMismatch
    );
}

#[test]
fn pss_spki_constraints_are_a_minimum_salt_length() {
    let signature_params = pss_params(SHA256_OID, SHA256_OID, 32);
    let cert_der = patch_to_pss(&rsa_cert(), &signature_params);
    let cert = Cert::parse(&cert_der).unwrap();

    let permitted = pss_params(SHA256_OID, SHA256_OID, 20);
    let permitted_der = pss_spki(cert.tbs.spki.subject_public_key, Some(&permitted));
    let permitted = SubjectPublicKeyInfo::parse_standalone(&permitted_der).unwrap();
    assert_eq!(
        cert.verify_signature(&permitted).unwrap_err(),
        VerifyError::Failed,
        "matching restrictions reach cryptographic verification"
    );

    let forbidden = pss_params(SHA256_OID, SHA256_OID, 48);
    let forbidden_der = pss_spki(cert.tbs.spki.subject_public_key, Some(&forbidden));
    let forbidden = SubjectPublicKeyInfo::parse_standalone(&forbidden_der).unwrap();
    assert_eq!(
        cert.verify_signature(&forbidden).unwrap_err(),
        VerifyError::AlgorithmMismatch
    );
}

#[test]
fn pss_unknown_hash_is_rejected() {
    let cert_der = patch_to_pss(&rsa_cert(), &params_with_hash(UNKNOWN_HASH_OID));
    let cert = Cert::parse(&cert_der).unwrap();
    assert_eq!(
        cert.verify_signature(&cert.tbs.spki).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}

#[test]
fn pss_rejects_explicit_default_fields() {
    let sha1 = algorithm(SHA1_OID, Some(&[0x05, 0x00]));
    let mgf1_sha1 = algorithm(MGF1_OID, Some(&sha1));
    let cert = rsa_cert();
    for field in [
        explicit(0, &sha1),
        explicit(1, &mgf1_sha1),
        explicit(2, &integer(20)),
        explicit(3, &integer(1)),
    ] {
        let cert_der = patch_to_pss(&cert, &seq(&field));
        assert_eq!(
            Cert::parse(&cert_der).unwrap_err(),
            shin::identity::cert::Error::BadAlgorithm
        );
    }
}

#[test]
fn pss_default_sha1_params_are_rejected() {
    let cert_der = patch_to_pss(&rsa_cert(), &[0x30, 0x00]);
    let cert = Cert::parse(&cert_der).unwrap();
    assert_eq!(
        cert.verify_signature(&cert.tbs.spki).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}

#[test]
fn known_signature_algorithms_reject_illegal_parameters() {
    let cert = rsa_cert();
    for algorithm in [
        algorithm(ECDSA_SHA256_OID, Some(&[0x05, 0x00])),
        algorithm(ED25519_OID, Some(&[0x05, 0x00])),
        algorithm(RSA_SHA256_OID, Some(&[0x04, 0x00])),
    ] {
        let patched = patch_signature_algorithm(&cert, &algorithm);
        assert_eq!(
            Cert::parse(&patched).unwrap_err(),
            shin::identity::cert::Error::BadAlgorithm
        );
    }
}

#[test]
fn known_public_key_algorithms_reject_illegal_parameters() {
    let public_key = [0x30, 0x00];
    for algorithm in [
        algorithm(RSA_ENCRYPTION_OID, None),
        algorithm(EC_PUBLIC_KEY_OID, None),
        algorithm(ED25519_OID, Some(&[0x05, 0x00])),
    ] {
        let encoded = spki(algorithm, &public_key);
        assert_eq!(
            SubjectPublicKeyInfo::parse_standalone(&encoded).unwrap_err(),
            shin::identity::cert::Error::BadAlgorithm
        );
    }
}
