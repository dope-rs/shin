use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, NameConstraints, PKCS_ED25519,
};

use shin::client::Client;
use shin::client::config;
use shin::client::config::{Error, OwnedTrustAnchor, Verifier};
use shin::connection::Epoch;
use shin::crypto::sig::SigningKey;
use shin::identity::asn1::{Reader, Tag};
use shin::identity::cert::Cert;
use shin::server::config::CertSource;

use crate::common::{CollectEvents, Server, ServerConfig, find_send, has_done};

const HOSTNAME: &str = "host.local";

fn ed25519_self_signed() -> (Vec<u8>, SigningKey) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let pkcs8 = key.serialize_der();
    let seed = extract_ed25519_seed(&pkcs8).expect("seed");
    let signing = SigningKey::from_seed(&seed).unwrap();

    let mut params = CertificateParams::new(vec![HOSTNAME.into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOSTNAME);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).unwrap();
    (cert.der().to_vec(), signing)
}

fn extract_ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut r = Reader::new(pkcs8);
    let inner = r.read_tagged(Tag::SEQUENCE).ok()?;
    let mut ir = Reader::new(inner);
    let _version = ir.read_tagged(Tag::INTEGER).ok()?;
    let _alg = ir.read_tagged(Tag::SEQUENCE).ok()?;
    let outer_oct = ir.read_tagged(Tag::OCTET_STRING).ok()?;
    let mut or = Reader::new(outer_oct);
    let inner_oct = or.read_tagged(Tag::OCTET_STRING).ok()?;
    if inner_oct.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_oct);
    Some(seed)
}

fn now_inside(cert_der: &[u8]) -> u64 {
    let cert = Cert::parse(cert_der).unwrap();
    let nb = shin::identity::UnixTime::from_time_value(&cert.tbs.validity.not_before).unwrap();
    let na = shin::identity::UnixTime::from_time_value(&cert.tbs.validity.not_after).unwrap();
    (nb.0 + na.0) / 2
}

#[test]
fn handshake_with_x509_chain() {
    let (cert_der, signing) = ed25519_self_signed();

    let anchor = OwnedTrustAnchor::from_cert_der(&cert_der).unwrap();
    let now = now_inside(&cert_der);

    let server = Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert_der.clone()],
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let client = Client::new(
        config::Config {
            verifier: Verifier::X509 {
                anchors: vec![anchor],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now * 1000,
    )
    .unwrap();

    let (mut client, mut server) = (client, server);

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).expect("CH");
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).expect("SH");
    let s_hs = find_send(&s1, Epoch::Handshake).expect("server EE+Cert+CV+SF");
    let _c2 = client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    assert!(has_done(&c3), "client confirmed via X.509 chain");
    let cf = find_send(&c3, Epoch::Handshake).expect("CF");
    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    assert!(has_done(&s2));
}

#[test]
fn handshake_enforces_certificate_derived_anchor_name_constraints() {
    let root_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.distinguished_name = rcgen::DistinguishedName::new();
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "constrained root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    root_params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("allowed.local".into())],
        excluded_subtrees: Vec::new(),
    });
    let root_der = root_params
        .clone()
        .self_signed(&root_key)
        .unwrap()
        .der()
        .to_vec();

    let intermediate_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    intermediate_params.distinguished_name = rcgen::DistinguishedName::new();
    intermediate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let intermediate_der = intermediate_params
        .clone()
        .signed_by(
            &intermediate_key,
            &Issuer::from_params(&root_params, &root_key),
        )
        .unwrap()
        .der()
        .to_vec();

    let leaf_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let leaf_seed = extract_ed25519_seed(&leaf_key.serialize_der()).unwrap();
    let signing = SigningKey::from_seed(&leaf_seed).unwrap();
    let mut leaf_params = CertificateParams::new(vec![HOSTNAME.into()]).unwrap();
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_der = leaf_params
        .signed_by(
            &leaf_key,
            &Issuer::from_params(&intermediate_params, &intermediate_key),
        )
        .unwrap()
        .der()
        .to_vec();
    let now = now_inside(&leaf_der);

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![leaf_der, intermediate_der],
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        config::Config {
            verifier: Verifier::X509 {
                anchors: vec![OwnedTrustAnchor::from_cert_der(&root_der).unwrap()],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now * 1000,
    )
    .unwrap();

    let ch = find_send(&client.start().unwrap(), Epoch::Plaintext).unwrap();
    let server_flight = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&server_flight, Epoch::Plaintext).unwrap();
    let server_hs = find_send(&server_flight, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    assert_eq!(
        client.read(Epoch::Handshake, &server_hs).unwrap_err(),
        shin::connection::Error::BadCertificateChain(
            shin::identity::chain::Error::NameConstraintViolation,
        ),
    );
}

#[test]
fn rejects_wrong_hostname() {
    let (cert_der, signing) = ed25519_self_signed();
    let anchor = OwnedTrustAnchor::from_cert_der(&cert_der).unwrap();
    let now = now_inside(&cert_der);

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert_der.clone()],
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        config::Config {
            verifier: Verifier::X509 {
                anchors: vec![anchor],
                hostname: b"other.local".to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now * 1000,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    let result = client.read(Epoch::Handshake, &s_hs);
    assert!(
        result.is_err(),
        "client must reject hostname mismatch in cert"
    );
}

#[test]
fn rejects_unknown_anchor() {
    let (cert_der, signing) = ed25519_self_signed();
    let (other_der, _) = ed25519_self_signed();
    let bogus_anchor = OwnedTrustAnchor::from_cert_der(&other_der).unwrap();
    let now = now_inside(&cert_der);

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert_der.clone()],
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        config::Config {
            verifier: Verifier::X509 {
                anchors: vec![bogus_anchor],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now * 1000,
    )
    .unwrap();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    let result = client.read(Epoch::Handshake, &s_hs);
    assert!(result.is_err(), "client must reject unknown anchor");
}

fn not_after(cert_der: &[u8]) -> u64 {
    let cert = Cert::parse(cert_der).unwrap();
    shin::identity::UnixTime::from_time_value(&cert.tbs.validity.not_after)
        .unwrap()
        .0
}

#[test]
fn stale_clock_rejects_expired_certificate() {
    let (cert_der, signing) = ed25519_self_signed();
    let anchor = OwnedTrustAnchor::from_cert_der(&cert_der).unwrap();
    let expired_at = not_after(&cert_der) + 86_400;

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::X509 {
                chain_der: vec![cert_der.clone()],
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        config::Config {
            verifier: Verifier::X509 {
                anchors: vec![anchor],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || expired_at * 1000,
    )
    .unwrap();
    // Clock injected per-handshake reads a time past expiry.

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    assert_eq!(
        client.read(Epoch::Handshake, &s_hs).unwrap_err(),
        shin::connection::Error::BadCertificateChain(shin::identity::chain::Error::Expired),
    );
}

#[test]
fn config_validate_rejects_empty_anchors_and_hostname() {
    let empty_anchors = config::Config {
        verifier: Verifier::X509 {
            anchors: Vec::new(),
            hostname: HOSTNAME.as_bytes().to_vec(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    };
    assert_eq!(
        empty_anchors.validate().unwrap_err(),
        Error::MissingTrustAnchors
    );

    let (cert_der, _) = ed25519_self_signed();
    let anchor = OwnedTrustAnchor::from_cert_der(&cert_der).unwrap();
    let empty_host = config::Config {
        verifier: Verifier::X509 {
            anchors: vec![anchor],
            hostname: Vec::new(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    };
    assert_eq!(empty_host.validate().unwrap_err(), Error::MissingServerName);
}

#[test]
fn config_validate_rejects_oversized_alpn_and_transport_params() {
    let base = || config::Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    };

    let mut over_protocol = base();
    over_protocol.alpn_protocols = vec![vec![b'x'; 256]];
    assert_eq!(
        over_protocol.validate().unwrap_err(),
        Error::AlpnProtocolTooLong {
            index: 0,
            len: 256,
            maximum: 255,
        }
    );

    let mut empty_protocol = base();
    empty_protocol.alpn_protocols = vec![Vec::new()];
    assert_eq!(
        empty_protocol.validate().unwrap_err(),
        Error::EmptyAlpnProtocol { index: 0 }
    );

    let mut over_tp = base();
    over_tp.transport_params = vec![0u8; 65536];
    assert_eq!(
        over_tp.validate().unwrap_err(),
        Error::TransportParametersTooLong {
            len: 65_536,
            maximum: 65_535,
        }
    );

    base().validate().unwrap();
}

#[test]
fn server_config_validate_rejects_inconsistent_identity() {
    let (certificate, _) = ed25519_self_signed();
    let (_, unrelated_key) = ed25519_self_signed();
    let mismatched = ServerConfig {
        source: CertSource::X509 {
            chain_der: vec![certificate],
            signing_key: unrelated_key,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_keys: None,
        accept_early_data: false,
    };
    assert_eq!(
        mismatched.validate(),
        Err(shin::connection::Error::BadConfig)
    );

    let empty_chain = ServerConfig {
        source: CertSource::X509 {
            chain_der: Vec::new(),
            signing_key: ed25519_self_signed().1,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_keys: None,
        accept_early_data: false,
    };
    assert_eq!(
        empty_chain.validate(),
        Err(shin::connection::Error::BadConfig)
    );
}
