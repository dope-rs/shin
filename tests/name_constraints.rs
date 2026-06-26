use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256,
};

use shin::cert::Cert;
use shin::chain::{Chain, ChainError, TrustAnchor};
use shin::time::UnixTime;

struct Ca {
    params: CertificateParams,
    key: KeyPair,
    der: Vec<u8>,
}

fn ca_params(cn: &str, nc: Option<NameConstraints>) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.name_constraints = nc;
    params
}

fn root(cn: &str) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = ca_params(cn, None);
    let der = params.clone().self_signed(&key).unwrap().der().to_vec();
    Ca { params, key, der }
}

fn issuer_of(ca: &Ca) -> Issuer<'_, &KeyPair> {
    Issuer::from_params(&ca.params, &ca.key)
}

fn intermediate(cn: &str, nc: NameConstraints, parent: &Ca) -> Ca {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = ca_params(cn, Some(nc));
    let der = params
        .clone()
        .signed_by(&key, &issuer_of(parent))
        .unwrap()
        .der()
        .to_vec();
    Ca { params, key, der }
}

fn leaf(san: &str, parent: &Ca) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, san);
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

fn run(im_nc: NameConstraints, san: &str, host: &[u8]) -> Result<(), ChainError> {
    let r = root("root");
    let im = intermediate("im", im_nc, &r);
    let leaf_der = leaf(san, &im);

    let leaf_cert = Cert::parse(&leaf_der).unwrap();
    let im_cert = Cert::parse(&im.der).unwrap();
    let root_cert = Cert::parse(&r.der).unwrap();
    let now = mid_time(&leaf_cert);

    let chain = [leaf_cert.clone(), im_cert];
    let anchors = [TrustAnchor::from_cert(&root_cert)];
    Chain::validate(&chain, &anchors, now, host)
}

fn permit(subtrees: Vec<GeneralSubtree>) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: subtrees,
        excluded_subtrees: Vec::new(),
    }
}

fn exclude(subtrees: Vec<GeneralSubtree>) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: Vec::new(),
        excluded_subtrees: subtrees,
    }
}

#[test]
fn permitted_dns_subtree_accepts_subdomain_and_proves_critical_nc_handled() {
    let nc = permit(vec![GeneralSubtree::DnsName("corp.example".into())]);
    run(nc, "host.corp.example", b"host.corp.example").expect("name within permitted subtree");
}

#[test]
fn permitted_dns_subtree_rejects_outside_name() {
    let nc = permit(vec![GeneralSubtree::DnsName("corp.example".into())]);
    assert_eq!(
        run(nc, "evil.com", b"evil.com").unwrap_err(),
        ChainError::NameConstraintViolation
    );
}

#[test]
fn excluded_dns_subtree_rejects_match() {
    let nc = exclude(vec![GeneralSubtree::DnsName("bad.example".into())]);
    assert_eq!(
        run(nc, "x.bad.example", b"x.bad.example").unwrap_err(),
        ChainError::NameConstraintViolation
    );
}

#[test]
fn excluded_dns_subtree_allows_nonmatch() {
    let nc = exclude(vec![GeneralSubtree::DnsName("bad.example".into())]);
    run(nc, "good.example", b"good.example").expect("name outside excluded subtree");
}

#[test]
fn permitted_ip_subtree_accepts_in_range() {
    let nc = permit(vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
        [10, 0, 0, 0],
        [255, 0, 0, 0],
    ))]);
    run(nc, "10.1.2.3", b"10.1.2.3").expect("ip within permitted subnet");
}

#[test]
fn permitted_ip_subtree_rejects_out_of_range() {
    let nc = permit(vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
        [10, 0, 0, 0],
        [255, 0, 0, 0],
    ))]);
    assert_eq!(
        run(nc, "192.168.1.1", b"192.168.1.1").unwrap_err(),
        ChainError::NameConstraintViolation
    );
}
