use rcgen::{
    BasicConstraints as RcgenBasicConstraints, CertificateParams, CustomExtension,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

use shin::cert::Cert;
use shin::chain::{Chain, ChainError, TrustAnchor};
use shin::time::UnixTime;

fn self_signed_leaf(dns: &[&str]) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params =
        CertificateParams::new(dns.iter().map(|s| (*s).into()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        dns.first().copied().unwrap_or("leaf"),
    );
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.self_signed(&key).unwrap().der().to_vec()
}

fn self_signed_ip_leaf(ip: &str) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ip-leaf");
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = vec![rcgen::SanType::IpAddress(ip.parse().unwrap())];
    params.self_signed(&key).unwrap().der().to_vec()
}

fn now_for(leaf: &Cert<'_>) -> UnixTime {
    let nb = UnixTime::from_time_value(&leaf.validity.not_before).unwrap();
    let na = UnixTime::from_time_value(&leaf.validity.not_after).unwrap();
    UnixTime((nb.0 + na.0) / 2)
}

#[test]
fn validates_self_signed_leaf_with_ipv6_san() {
    let der = self_signed_ip_leaf("2001:db8::1");
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    Chain::validate(&chain, &anchors, now, b"2001:db8::1").expect("ipv6 SAN matches");
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"2001:db8::2").unwrap_err(),
        ChainError::HostnameMismatch,
    );
}

#[test]
fn ipv6_san_matches_compressed_reference_forms() {
    let der = self_signed_ip_leaf("2001:db8::1");
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    for form in [
        &b"2001:db8::1"[..],
        &b"2001:0db8:0000:0000:0000:0000:0000:0001"[..],
        &b"2001:db8:0:0:0:0:0:1"[..],
    ] {
        Chain::validate(&chain, &anchors, now, form)
            .unwrap_or_else(|_| panic!("form {:?} should match", core::str::from_utf8(form)));
    }
}

#[test]
fn ipv6_san_rejects_dns_reference_and_vice_versa() {
    let ip_der = self_signed_ip_leaf("2001:db8::1");
    let ip_cert = Cert::parse(&ip_der).unwrap();
    let ip_now = now_for(&ip_cert);
    let ip_chain = [ip_cert.clone()];
    let ip_anchors = [TrustAnchor::from_cert(&ip_cert)];
    assert_eq!(
        Chain::validate(&ip_chain, &ip_anchors, ip_now, b"example.com").unwrap_err(),
        ChainError::HostnameMismatch
    );

    let dns_der = self_signed_leaf(&["host.local"]);
    let dns_cert = Cert::parse(&dns_der).unwrap();
    let dns_now = now_for(&dns_cert);
    let dns_chain = [dns_cert.clone()];
    let dns_anchors = [TrustAnchor::from_cert(&dns_cert)];
    assert_eq!(
        Chain::validate(&dns_chain, &dns_anchors, dns_now, b"2001:db8::1").unwrap_err(),
        ChainError::HostnameMismatch
    );
}

#[test]
fn ipv4_mapped_and_distinct_ipv6_do_not_collide() {
    let der = self_signed_ip_leaf("2001:db8::1");
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    // A different address whose textual prefix overlaps must not match.
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"2001:db8::1:0").unwrap_err(),
        ChainError::HostnameMismatch
    );
    // Garbage that is neither a valid IP nor a DNS label must not match.
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"2001:db8::zz").unwrap_err(),
        ChainError::HostnameMismatch
    );
}

#[test]
fn validates_self_signed_leaf_with_dns_san() {
    let der = self_signed_leaf(&["host.local"]);
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    Chain::validate(&chain, &anchors, now, b"host.local").expect("valid");
}

#[test]
fn rejects_unknown_anchor() {
    let leaf_der = self_signed_leaf(&["host.local"]);
    let other_der = self_signed_leaf(&["other.local"]);
    let leaf = Cert::parse(&leaf_der).unwrap();
    let other = Cert::parse(&other_der).unwrap();
    let now = now_for(&leaf);
    let chain = [leaf];
    let anchors = [TrustAnchor::from_cert(&other)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::NoTrustAnchor
    );
}

#[test]
fn rejects_hostname_mismatch() {
    let der = self_signed_leaf(&["host.local"]);
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"other.local").unwrap_err(),
        ChainError::HostnameMismatch
    );
}

#[test]
fn rejects_expired_cert() {
    let der = self_signed_leaf(&["host.local"]);
    let cert = Cert::parse(&der).unwrap();
    let na = UnixTime::from_time_value(&cert.validity.not_after).unwrap();
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    let beyond = UnixTime(na.0 + 60);
    assert_eq!(
        Chain::validate(&chain, &anchors, beyond, b"host.local").unwrap_err(),
        ChainError::Expired
    );
}

#[test]
fn validity_boundaries_are_inclusive() {
    // RFC 5280 §4.1.2.5: notBefore and notAfter are both inclusive.
    let der = self_signed_leaf(&["host.local"]);
    let cert = Cert::parse(&der).unwrap();
    let nb = UnixTime::from_time_value(&cert.validity.not_before).unwrap();
    let na = UnixTime::from_time_value(&cert.validity.not_after).unwrap();
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    Chain::validate(&chain, &anchors, nb, b"host.local").expect("notBefore is inclusive");
    Chain::validate(&chain, &anchors, na, b"host.local").expect("notAfter is inclusive");
    assert_eq!(
        Chain::validate(&chain, &anchors, UnixTime(nb.0 - 1), b"host.local").unwrap_err(),
        ChainError::NotYetValid
    );
    assert_eq!(
        Chain::validate(&chain, &anchors, UnixTime(na.0 + 1), b"host.local").unwrap_err(),
        ChainError::Expired
    );
}

#[test]
fn rejects_not_yet_valid() {
    let der = self_signed_leaf(&["host.local"]);
    let cert = Cert::parse(&der).unwrap();
    let nb = UnixTime::from_time_value(&cert.validity.not_before).unwrap();
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    let earlier = UnixTime(nb.0.saturating_sub(60));
    assert_eq!(
        Chain::validate(&chain, &anchors, earlier, b"host.local").unwrap_err(),
        ChainError::NotYetValid
    );
}

#[test]
fn rejects_ca_marked_cert_as_leaf() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["ca.local".into()]).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"ca.local").unwrap_err(),
        ChainError::NotEndEntity
    );
}

#[test]
fn rejects_missing_server_auth_eku() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["host.local".into()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::NoServerAuth
    );
}

fn leaf_with_custom_ext(critical: bool) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["host.local".into()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut ext =
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![0x05, 0x00]);
    ext.set_criticality(critical);
    params.custom_extensions = vec![ext];
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn rejects_unknown_critical_extension() {
    let der = leaf_with_custom_ext(true);
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::UnhandledCriticalExtension
    );
}

#[test]
fn accepts_unknown_noncritical_extension() {
    let der = leaf_with_custom_ext(false);
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    Chain::validate(&chain, &anchors, now, b"host.local").expect("non-critical unknown ext is ok");
}

fn ca(cn: &str) -> (CertificateParams, KeyPair, Vec<u8>) {
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

fn leaf_signed_by(dns: &str, parent: &(CertificateParams, KeyPair, Vec<u8>)) -> Vec<u8> {
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

#[test]
fn rejects_issuer_subject_dn_mismatch() {
    // Leaf is issued by `real_im`, but the chain presents a different CA
    // (`wrong_im`, distinct subject DN) in the issuer slot. The anchor is a
    // separate root whose subject does not match the leaf's issuer, so the
    // walk reaches chain[1] and the DN linkage check must fire there.
    let root = ca("root");
    let real_im = ca("real-im");
    let wrong_im = ca("wrong-im");
    let leaf_der = leaf_signed_by("host.local", &real_im);

    let leaf_cert = Cert::parse(&leaf_der).unwrap();
    let wrong_cert = Cert::parse(&wrong_im.2).unwrap();
    let root_cert = Cert::parse(&root.2).unwrap();
    let now = now_for(&leaf_cert);

    let chain = [leaf_cert.clone(), wrong_cert];
    let anchors = [TrustAnchor::from_cert(&root_cert)];
    assert_eq!(
        Chain::validate(&chain, &anchors, now, b"host.local").unwrap_err(),
        ChainError::IssuerSubjectMismatch
    );
}

#[test]
fn wildcard_san_matches_subdomain() {
    let der = self_signed_leaf(&["*.example.local"]);
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    Chain::validate(&chain, &anchors, now, b"foo.example.local").expect("valid");
}
