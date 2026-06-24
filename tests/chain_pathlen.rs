use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

use shin::cert::Cert;
use shin::chain::{Chain, ChainError, TrustAnchor};
use shin::time::UnixTime;

struct Ca {
    params: CertificateParams,
    key: KeyPair,
    der: Vec<u8>,
}

fn ca_params(cn: &str, path_len: Option<u8>) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.is_ca = match path_len {
        Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params
}

fn root(cn: &str, path_len: Option<u8>) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = ca_params(cn, path_len);
    let der = params.clone().self_signed(&key).unwrap().der().to_vec();
    Ca { params, key, der }
}

fn issuer_of(ca: &Ca) -> Issuer<'_, &KeyPair> {
    Issuer::from_params(&ca.params, &ca.key)
}

fn intermediate(cn: &str, path_len: Option<u8>, parent: &Ca) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = ca_params(cn, path_len);
    let der = params
        .clone()
        .signed_by(&key, &issuer_of(parent))
        .unwrap()
        .der()
        .to_vec();
    Ca { params, key, der }
}

fn leaf(dns: &str, parent: &Ca) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![dns.to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .signed_by(&key, &issuer_of(parent))
        .unwrap()
        .der()
        .to_vec()
}

fn mid_time(cert: &Cert<'_>) -> UnixTime {
    let nb = UnixTime::from_time_value(&cert.validity.not_before).unwrap();
    let na = UnixTime::from_time_value(&cert.validity.not_after).unwrap();
    UnixTime((nb.0 + na.0) / 2)
}

#[test]
fn chain_too_long_is_rejected() {
    let r = root("root", None);
    let leaf_der = leaf("host.local", &r);
    let leaf_cert = Cert::parse(&leaf_der).unwrap();
    let anchor_cert = Cert::parse(&r.der).unwrap();
    let chain: Vec<Cert<'_>> = (0..shin::chain::MAX_CHAIN_LEN + 1)
        .map(|_| leaf_cert.clone())
        .collect();
    let anchors = [TrustAnchor::from_cert(&anchor_cert)];
    let now = mid_time(&leaf_cert);
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::ChainTooLong
    );
}

#[test]
fn valid_two_level_chain_accepts() {
    let r = root("root", Some(1));
    let im = intermediate("im", Some(0), &r);
    let leaf_der = leaf("host.local", &im);

    let leaf_cert = Cert::parse(&leaf_der).unwrap();
    let im_cert = Cert::parse(&im.der).unwrap();
    let root_cert = Cert::parse(&r.der).unwrap();
    let now = mid_time(&leaf_cert);

    let chain = [leaf_cert.clone(), im_cert];
    let anchors = [TrustAnchor::from_cert(&root_cert)];
    Chain::validate(&chain, &anchors, now, b"host.local").expect("valid 2-level chain");
}

#[test]
fn path_len_zero_intermediate_rejects_extra_intermediate() {
    // root -> im0(pathLen 0) -> im1 -> leaf: im0 must not certify another intermediate.
    let r = root("root", Some(2));
    let im0 = intermediate("im0", Some(0), &r);
    let im1 = intermediate("im1", None, &im0);
    let leaf_der = leaf("host.local", &im1);

    let leaf_cert = Cert::parse(&leaf_der).unwrap();
    let im1_cert = Cert::parse(&im1.der).unwrap();
    let im0_cert = Cert::parse(&im0.der).unwrap();
    let root_cert = Cert::parse(&r.der).unwrap();
    let now = mid_time(&leaf_cert);

    let chain = [leaf_cert.clone(), im1_cert, im0_cert];
    let anchors = [TrustAnchor::from_cert(&root_cert)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::PathLenExceeded
    );
}
