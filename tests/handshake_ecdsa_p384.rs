use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};

use shin::cert::Cert;
use shin::client::{Client, Config as ClientConfig, OwnedTrustAnchor, Verifier};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

const HOSTNAME: &str = "p384.local";

fn ecdsa_p384_self_signed() -> (Vec<u8>, SigningKey) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let pkcs8 = key.serialize_der();
    let signing = SigningKey::from_ecdsa_p384_pkcs8(&pkcs8).unwrap();

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
fn handshake_with_ecdsa_p384_x509_chain() {
    let (cert_der, signing) = ecdsa_p384_self_signed();

    let cert_view = Cert::parse(&cert_der).unwrap();
    let anchor = OwnedTrustAnchor {
        subject_der: cert_view.subject_der.to_vec(),
        spki_der: cert_view.spki.raw_der.to_vec(),
    };
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
        ClientConfig {
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
    );

    let (mut client, mut server) = (client, server);

    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).expect("CH");
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).expect("SH");
    let s_hs = extract_send(&s1, Epoch::Handshake).expect("server EE+Cert+CV+SF");
    let _c2 = client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    assert!(has_done(&c3), "client confirmed via ECDSA-P384 chain");
    let cf = extract_send(&c3, Epoch::Handshake).expect("CF");
    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    assert!(has_done(&s2));
}
