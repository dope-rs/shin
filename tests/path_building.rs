use rcgen::{
    BasicConstraints as RcgenBasicConstraints, CertificateParams, CustomExtension,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

use shin::cert::Cert;
use shin::chain::{Chain, ChainError, TrustAnchor};
use shin::time::UnixTime;

type Ca = (CertificateParams, KeyPair, Vec<u8>);

fn ca(cn: &str) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(RcgenBasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let der = params.clone().self_signed(&key).unwrap().der().to_vec();
    (params, key, der)
}

fn intermediate(cn: &str, parent: &Ca, eku: Vec<ExtendedKeyUsagePurpose>) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(RcgenBasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.extended_key_usages = eku;
    let issuer = Issuer::from_params(&parent.0, &parent.1);
    let der = params
        .clone()
        .signed_by(&key, &issuer)
        .unwrap()
        .der()
        .to_vec();
    (params, key, der)
}

fn leaf_signed_by(dns: &str, parent: &Ca) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![dns.to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let issuer = Issuer::from_params(&parent.0, &parent.1);
    params.signed_by(&key, &issuer).unwrap().der().to_vec()
}

fn now_for(leaf: &Cert<'_>) -> UnixTime {
    let nb = UnixTime::from_time_value(&leaf.validity.not_before).unwrap();
    let na = UnixTime::from_time_value(&leaf.validity.not_after).unwrap();
    UnixTime((nb.0 + na.0) / 2)
}

#[test]
fn accepts_reordered_intermediates() {
    let root = ca("root");
    let im1 = intermediate("im1", &root, vec![]);
    let im2 = intermediate("im2", &im1, vec![]);
    let leaf_der = leaf_signed_by("host.local", &im2);

    let leaf = Cert::parse(&leaf_der).unwrap();
    let c_im1 = Cert::parse(&im1.2).unwrap();
    let c_im2 = Cert::parse(&im2.2).unwrap();
    let c_root = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf);
    let anchors = [TrustAnchor::from_cert(&c_root)];

    // Intermediates presented out of order (im1 before im2).
    let shuffled = [leaf.clone(), c_im1.clone(), c_im2.clone()];
    Chain::validate(&shuffled, &anchors, now, b"host.local").expect("reordered chain validates");
}

#[test]
fn tolerates_extra_unrelated_cert() {
    let root = ca("root");
    let im = intermediate("im", &root, vec![]);
    let leaf_der = leaf_signed_by("host.local", &im);
    let unrelated = ca("unrelated");

    let leaf = Cert::parse(&leaf_der).unwrap();
    let c_im = Cert::parse(&im.2).unwrap();
    let c_root = Cert::parse(&root.2).unwrap();
    let c_extra = Cert::parse(&unrelated.2).unwrap();
    let now = now_for(&leaf);
    let anchors = [TrustAnchor::from_cert(&c_root)];

    let chain = [leaf.clone(), c_extra, c_im];
    Chain::validate(&chain, &anchors, now, b"host.local").expect("extra cert tolerated");
}

#[test]
fn tries_alternate_cross_signed_anchors() {
    let root_a = ca("root");
    let root_b = ca("root");
    // root_b shares root_a's subject DN but has a different key. Only root_a
    // actually signed the intermediate; the validator must try both.
    let im = intermediate("im", &root_a, vec![]);
    let leaf_der = leaf_signed_by("host.local", &im);

    let leaf = Cert::parse(&leaf_der).unwrap();
    let c_im = Cert::parse(&im.2).unwrap();
    let c_root_a = Cert::parse(&root_a.2).unwrap();
    let c_root_b = Cert::parse(&root_b.2).unwrap();
    let now = now_for(&leaf);

    let chain = [leaf.clone(), c_im];
    // root_b listed first, root_a second; the wrong-key anchor must be skipped.
    let anchors = [
        TrustAnchor::from_cert(&c_root_b),
        TrustAnchor::from_cert(&c_root_a),
    ];
    Chain::validate(&chain, &anchors, now, b"host.local").expect("alternate anchor tried");
}

#[test]
fn rejects_intermediate_without_server_auth_eku() {
    let root = ca("root");
    let im = intermediate("im", &root, vec![ExtendedKeyUsagePurpose::ClientAuth]);
    let leaf_der = leaf_signed_by("host.local", &im);

    let leaf = Cert::parse(&leaf_der).unwrap();
    let c_im = Cert::parse(&im.2).unwrap();
    let c_root = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf);
    let anchors = [TrustAnchor::from_cert(&c_root)];

    let chain = [leaf.clone(), c_im];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::NoServerAuth,
    );
}

#[test]
fn accepts_intermediate_with_server_auth_eku() {
    let root = ca("root");
    let im = intermediate("im", &root, vec![ExtendedKeyUsagePurpose::ServerAuth]);
    let leaf_der = leaf_signed_by("host.local", &im);

    let leaf = Cert::parse(&leaf_der).unwrap();
    let c_im = Cert::parse(&im.2).unwrap();
    let c_root = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf);
    let anchors = [TrustAnchor::from_cert(&c_root)];

    let chain = [leaf.clone(), c_im];
    Chain::validate(&chain, &anchors, now, b"host.local").expect("serverAuth EKU CA is fine");
}

#[test]
fn rejects_duplicate_extension() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["host.local".to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "host.local");
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let oid = &[1, 3, 6, 1, 4, 1, 99999, 7];
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(oid, vec![0x05, 0x00]));
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(oid, vec![0x05, 0x00]));
    let der = params.self_signed(&key).unwrap().der().to_vec();

    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::DuplicateExtension,
    );
}
