use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};

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

#[test]
fn wildcard_san_matches_subdomain() {
    let der = self_signed_leaf(&["*.example.local"]);
    let cert = Cert::parse(&der).unwrap();
    let now = now_for(&cert);
    let chain = [cert.clone()];
    let anchors = [TrustAnchor::from_cert(&cert)];
    Chain::validate(&chain, &anchors, now, b"foo.example.local").expect("valid");
}
