use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};

use shin::asn1::{Reader, Tag};
use shin::cert::Cert;
use shin::client::{Client, Config as ClientConfig, OwnedTrustAnchor, Verifier};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

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
    let inner = r.expect(Tag::SEQUENCE).ok()?;
    let mut ir = Reader::new(inner);
    let _version = ir.expect(Tag::INTEGER).ok()?;
    let _alg = ir.expect(Tag::SEQUENCE).ok()?;
    let outer_oct = ir.expect(Tag::OCTET_STRING).ok()?;
    let mut or = Reader::new(outer_oct);
    let inner_oct = or.expect(Tag::OCTET_STRING).ok()?;
    if inner_oct.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_oct);
    Some(seed)
}

fn now_inside(cert_der: &[u8]) -> u64 {
    let cert = Cert::parse(cert_der).unwrap();
    let nb = shin::time::UnixTime::from_time_value(&cert.validity.not_before).unwrap();
    let na = shin::time::UnixTime::from_time_value(&cert.validity.not_after).unwrap();
    (nb.0 + na.0) / 2
}

fn extract_send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done))
}

#[test]
fn handshake_with_x509_chain() {
    let (cert_der, signing) = ed25519_self_signed();

    let cert_view = Cert::parse(&cert_der).unwrap();
    let anchor = OwnedTrustAnchor {
        subject_der: cert_view.subject_der.to_vec(),
        spki_der: cert_view.spki.raw_der.to_vec(),
    };
    let now = now_inside(&cert_der);

    let server = Server::new(ServerConfig {
        source: CertSource::X509 {
            chain_der: vec![cert_der.clone()],
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let client = Client::new(ClientConfig {
        verifier: Verifier::X509 {
            anchors: vec![anchor],
            hostname: HOSTNAME.as_bytes().to_vec(),
            now_seconds: now,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let (mut client, mut server) = (client, server);

    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).expect("CH");
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).expect("SH");
    let s_hs = extract_send(&s1, Epoch::Handshake).expect("server EE+Cert+CV+SF");
    let _c2 = client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    assert!(has_done(&c3), "client confirmed via X.509 chain");
    let cf = extract_send(&c3, Epoch::Handshake).expect("CF");
    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    assert!(has_done(&s2));
}

#[test]
fn rejects_wrong_hostname() {
    let (cert_der, signing) = ed25519_self_signed();
    let cert_view = Cert::parse(&cert_der).unwrap();
    let anchor = OwnedTrustAnchor {
        subject_der: cert_view.subject_der.to_vec(),
        spki_der: cert_view.spki.raw_der.to_vec(),
    };
    let now = now_inside(&cert_der);

    let mut server = Server::new(ServerConfig {
        source: CertSource::X509 {
            chain_der: vec![cert_der.clone()],
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = Client::new(ClientConfig {
        verifier: Verifier::X509 {
            anchors: vec![anchor],
            hostname: b"other.local".to_vec(),
            now_seconds: now,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = extract_send(&s1, Epoch::Handshake).unwrap();
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
    let other_view = Cert::parse(&other_der).unwrap();
    let bogus_anchor = OwnedTrustAnchor {
        subject_der: other_view.subject_der.to_vec(),
        spki_der: other_view.spki.raw_der.to_vec(),
    };
    let now = now_inside(&cert_der);

    let mut server = Server::new(ServerConfig {
        source: CertSource::X509 {
            chain_der: vec![cert_der.clone()],
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = Client::new(ClientConfig {
        verifier: Verifier::X509 {
            anchors: vec![bogus_anchor],
            hostname: HOSTNAME.as_bytes().to_vec(),
            now_seconds: now,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = extract_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    let result = client.read(Epoch::Handshake, &s_hs);
    assert!(result.is_err(), "client must reject unknown anchor");
}
