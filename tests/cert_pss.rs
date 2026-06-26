use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rustls_pki_types::PrivatePkcs8KeyDer;

use shin::cert::{Cert, VerifyError};

const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA1_OID: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const RSASSA_PSS_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];

fn rsa_cert() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pkcs8 = priv_key.to_pkcs8_der().unwrap();
    let pki = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
    let key = KeyPair::from_pkcs8_der_and_sign_algo(&pki, &PKCS_RSA_SHA256).unwrap();
    let params = CertificateParams::new(vec!["pss.local".into()]).unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
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

fn pss_sig_alg(params: &[u8]) -> Vec<u8> {
    let mut c = oid_tlv(RSASSA_PSS_OID);
    c.extend_from_slice(params);
    seq(&c)
}

// RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm AlgorithmIdentifier }
fn params_with_hash(hash_oid: &[u8]) -> Vec<u8> {
    let alg = seq(&oid_tlv(hash_oid));
    let mut hash_field = vec![0xA0];
    hash_field.extend(enc_len(alg.len()));
    hash_field.extend_from_slice(&alg);
    seq(&hash_field)
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
fn patch_to_pss(cert: &[u8], params: &[u8]) -> Vec<u8> {
    let new_sig_alg = pss_sig_alg(params);
    let (_, cs) = der_len(cert, 1);
    let tbs_end = elem_end(cert, cs);
    let sig_alg_end = elem_end(cert, tbs_end);
    let sig_value_end = elem_end(cert, sig_alg_end);
    let new_tbs = patch_tbs_sig_alg(&cert[cs..tbs_end], &new_sig_alg);
    let mut content = Vec::new();
    content.extend_from_slice(&new_tbs);
    content.extend_from_slice(&new_sig_alg);
    content.extend_from_slice(&cert[sig_alg_end..sig_value_end]);
    seq(&content)
}

#[test]
fn pss_sha256_params_are_accepted_and_reach_verification() {
    let cert_der = patch_to_pss(&rsa_cert(), &params_with_hash(SHA256_OID));
    let cert = Cert::parse(&cert_der).expect("patched PSS cert parses");
    assert_eq!(
        cert.verify_signature(&cert.spki).unwrap_err(),
        VerifyError::Failed
    );
}

#[test]
fn pss_unknown_hash_is_rejected() {
    let cert_der = patch_to_pss(&rsa_cert(), &params_with_hash(SHA1_OID));
    let cert = Cert::parse(&cert_der).unwrap();
    assert_eq!(
        cert.verify_signature(&cert.spki).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}

#[test]
fn pss_default_sha1_params_are_rejected() {
    let cert_der = patch_to_pss(&rsa_cert(), &[0x30, 0x00]);
    let cert = Cert::parse(&cert_der).unwrap();
    assert_eq!(
        cert.verify_signature(&cert.spki).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}
