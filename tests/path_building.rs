use rcgen::{
    CertificateParams, CustomExtension, DnValue, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, date_time_ymd,
};

use shin::identity::UnixTime;
use shin::identity::cert::Cert;
use shin::identity::chain::{Chain, Error, TrustAnchor};

type Ca = (CertificateParams, KeyPair, Vec<u8>);

fn ca(cn: &str) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
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
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
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
    let nb = leaf.tbs.validity.not_before;
    let na = leaf.tbs.validity.not_after;
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
    let shuffled = [leaf, c_im1, c_im2];
    Chain::new(shuffled)
        .validate(&anchors, now, b"host.local")
        .expect("reordered chain validates");
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

    let chain = [leaf, c_extra, c_im];
    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("extra cert tolerated");
}

#[test]
fn ignores_expired_unrelated_candidate() {
    let root = ca("root");
    let im = intermediate("im", &root, vec![]);
    let leaf_der = leaf_signed_by("host.local", &im);
    let unrelated = ca("expired-unrelated");
    let mut expired_params = unrelated.0.clone();
    expired_params.not_before = date_time_ymd(1999, 1, 1);
    expired_params.not_after = date_time_ymd(2000, 1, 1);
    let expired_der = expired_params
        .self_signed(&unrelated.1)
        .unwrap()
        .der()
        .to_vec();

    let leaf = Cert::parse(&leaf_der).unwrap();
    let expired = Cert::parse(&expired_der).unwrap();
    let issuer = Cert::parse(&im.2).unwrap();
    let anchor = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf);
    let chain = [leaf, expired, issuer];
    let anchors = [TrustAnchor::from_cert(&anchor)];

    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("an unused candidate's validity cannot poison the selected path");
}

#[test]
fn skips_invalid_matching_candidate_for_valid_alternative() {
    let root = ca("root");
    let valid_issuer = intermediate("issuer", &root, vec![]);
    let invalid_issuer = intermediate("issuer", &root, vec![]);
    let leaf_der = leaf_signed_by("host.local", &valid_issuer);

    let mut invalid_params = invalid_issuer.0.clone();
    let mut extension =
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 8], vec![0x05, 0x00]);
    extension.set_criticality(true);
    invalid_params.custom_extensions.push(extension);
    let invalid_der = invalid_params
        .signed_by(&invalid_issuer.1, &Issuer::from_params(&root.0, &root.1))
        .unwrap()
        .der()
        .to_vec();

    let leaf = Cert::parse(&leaf_der).unwrap();
    let invalid = Cert::parse(&invalid_der).unwrap();
    let valid = Cert::parse(&valid_issuer.2).unwrap();
    let anchor = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf);
    let chain = [leaf, invalid, valid];
    let anchors = [TrustAnchor::from_cert(&anchor)];

    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("a rejected issuer candidate cannot poison an alternate path");
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

    let chain = [leaf, c_im];
    // root_b listed first, root_a second; the wrong-key anchor must be skipped.
    let anchors = [
        TrustAnchor::from_cert(&c_root_b),
        TrustAnchor::from_cert(&c_root_a),
    ];
    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("alternate anchor tried");
}

#[test]
fn unique_same_name_issuer_with_wrong_key_is_rejected() {
    let root = ca("root");
    let actual_issuer = intermediate("issuer", &root, vec![]);
    let wrong_issuer = intermediate("issuer", &root, vec![]);
    let leaf_der = leaf_signed_by("host.local", &actual_issuer);

    let leaf = Cert::parse(&leaf_der).unwrap();
    let wrong_issuer = Cert::parse(&wrong_issuer.2).unwrap();
    let root = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf);
    let chain = [leaf, wrong_issuer];
    let anchors = [TrustAnchor::from_cert(&root)];

    assert!(matches!(
        Chain::new(chain)
            .validate(&anchors, now, b"host.local")
            .unwrap_err(),
        Error::Verify(_)
    ));
}

#[test]
fn ambiguous_same_name_issuers_choose_the_signature_valid_path() {
    let root = ca("root");
    let actual_issuer = intermediate("issuer", &root, vec![]);
    let wrong_issuer = intermediate("issuer", &root, vec![]);
    let leaf_der = leaf_signed_by("host.local", &actual_issuer);

    let leaf = Cert::parse(&leaf_der).unwrap();
    let actual_issuer = Cert::parse(&actual_issuer.2).unwrap();
    let wrong_issuer = Cert::parse(&wrong_issuer.2).unwrap();
    let root = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf);
    let chain = [leaf, wrong_issuer, actual_issuer];
    let anchors = [TrustAnchor::from_cert(&root)];

    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("same-name candidates are disambiguated by signature");
}

#[test]
fn cross_signed_intermediates_backtrack_to_the_trusted_path() {
    let root_a = ca("root-a");
    let root_b = ca("root-b");

    let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    intermediate_params.distinguished_name = rcgen::DistinguishedName::new();
    intermediate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cross-signed-issuer");
    intermediate_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let cross_a = intermediate_params
        .clone()
        .signed_by(
            &intermediate_key,
            &Issuer::from_params(&root_a.0, &root_a.1),
        )
        .unwrap()
        .der()
        .to_vec();
    let cross_b = intermediate_params
        .clone()
        .signed_by(
            &intermediate_key,
            &Issuer::from_params(&root_b.0, &root_b.1),
        )
        .unwrap()
        .der()
        .to_vec();
    let intermediate = (intermediate_params, intermediate_key, cross_a);
    let leaf_der = leaf_signed_by("host.local", &intermediate);

    let leaf = Cert::parse(&leaf_der).unwrap();
    let untrusted_cross_sign = Cert::parse(&cross_b).unwrap();
    let trusted_cross_sign = Cert::parse(&intermediate.2).unwrap();
    let root_a = Cert::parse(&root_a.2).unwrap();
    let now = now_for(&leaf);
    let chain = [leaf, untrusted_cross_sign, trusted_cross_sign];
    let anchors = [TrustAnchor::from_cert(&root_a)];

    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("the alternate cross-sign reaches the configured root");
}

#[test]
fn equivalent_distinguished_names_link_an_anchor() {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params.distinguished_name = rcgen::DistinguishedName::new();
    issuer_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        DnValue::Utf8String("  Straße   ROOT ".into()),
    );
    issuer_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let mut anchor_params = issuer_params.clone();
    anchor_params.distinguished_name = rcgen::DistinguishedName::new();
    anchor_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        DnValue::PrintableString("STRASSE ROOT".try_into().unwrap()),
    );
    let anchor_der = anchor_params.self_signed(&root_key).unwrap().der().to_vec();
    let issuer = Issuer::from_params(&issuer_params, &root_key);

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::new(vec!["host.local".into()]).unwrap();
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_der = leaf_params
        .signed_by(&leaf_key, &issuer)
        .unwrap()
        .der()
        .to_vec();

    let leaf = Cert::parse(&leaf_der).unwrap();
    let anchor = Cert::parse(&anchor_der).unwrap();
    assert_ne!(
        leaf.tbs.names.issuer.as_der(),
        anchor.tbs.names.subject.as_der()
    );
    let now = now_for(&leaf);
    let chain = [leaf];
    let anchors = [TrustAnchor::from_cert(&anchor)];

    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("equivalent X.520 names link despite different DER");
}

#[test]
fn unsupported_matching_rules_do_not_widen_name_equality() {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params.distinguished_name = rcgen::DistinguishedName::new();
    issuer_params.distinguished_name.push(
        rcgen::DnType::CustomDnType(vec![1, 2, 3, 4]),
        DnValue::PrintableString("EXACT".try_into().unwrap()),
    );
    issuer_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let mut anchor_params = issuer_params.clone();
    anchor_params.distinguished_name = rcgen::DistinguishedName::new();
    anchor_params.distinguished_name.push(
        rcgen::DnType::CustomDnType(vec![1, 2, 3, 4]),
        DnValue::PrintableString("exact".try_into().unwrap()),
    );
    let anchor_der = anchor_params.self_signed(&root_key).unwrap().der().to_vec();

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::new(vec!["host.local".into()]).unwrap();
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_der = leaf_params
        .signed_by(&leaf_key, &Issuer::from_params(&issuer_params, &root_key))
        .unwrap()
        .der()
        .to_vec();

    let leaf = Cert::parse(&leaf_der).unwrap();
    let anchor = Cert::parse(&anchor_der).unwrap();
    let now = now_for(&leaf);
    let chain = [leaf];
    let anchors = [TrustAnchor::from_cert(&anchor)];

    assert_eq!(
        Chain::new(chain)
            .validate(&anchors, now, b"host.local")
            .unwrap_err(),
        Error::NoTrustAnchor,
    );
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

    let chain = [leaf, c_im];
    assert_eq!(
        Chain::new(chain)
            .validate(&anchors, now, b"host.local")
            .unwrap_err(),
        Error::NoServerAuth,
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

    let chain = [leaf, c_im];
    Chain::new(chain)
        .validate(&anchors, now, b"host.local")
        .expect("serverAuth EKU CA is fine");
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
    let chain = [cert];
    let anchors = [TrustAnchor::from_cert(&cert)];
    assert_eq!(
        Chain::new(chain)
            .validate(&anchors, now, b"host.local")
            .unwrap_err(),
        Error::DuplicateExtension,
    );
}
