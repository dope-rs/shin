//! TLS 1.3 mutual authentication (client certificates): the server sends a
//! CertificateRequest, the client presents a Certificate + CertificateVerify,
//! and the server verifies possession then pins the public key
//! (`authorized_keys` model). RFC 8446 §4.3.2, §4.4.2, §4.4.3.

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};

use shin::cert::Cert;
use shin::client::{Client, ClientCertSource, Config as ClientConfig, OwnedTrustAnchor, Verifier};
use shin::server::{
    CertSource, ClientAuth, ClientCertVerifier, ClientIdentity, Config as ServerConfig, Server,
};
use shin::sig::SigningKey;
use shin::spki::SubjectPublicKey;
use shin::{Epoch, Error};

mod common;
use common::{find_send, has_done};

const SERVER_NAME: &str = "server.local";
const CLIENT_NAME: &str = "client.local";

fn ecdsa_p256_self_signed(name: &str) -> (Vec<u8>, SigningKey) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let signing = SigningKey::from_ecdsa_p256_pkcs8(&key.serialize_der()).unwrap();
    (self_signed_der(&key, name), signing)
}

fn self_signed_der(key: &KeyPair, name: &str) -> Vec<u8> {
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.self_signed(key).unwrap().der().to_vec()
}

fn now_inside(cert_der: &[u8]) -> u64 {
    let cert = Cert::parse(cert_der).unwrap();
    let nb = shin::time::UnixTime::from_time_value(&cert.validity.not_before).unwrap();
    let na = shin::time::UnixTime::from_time_value(&cert.validity.not_after).unwrap();
    (nb.0 + na.0) / 2
}

fn anchor(cert_der: &[u8]) -> OwnedTrustAnchor {
    let cv = Cert::parse(cert_der).unwrap();
    OwnedTrustAnchor {
        subject_der: cv.subject_der.to_vec(),
        spki_der: cv.spki.raw_der.to_vec(),
    }
}

fn x509_spki(cert_der: &[u8]) -> Vec<u8> {
    Cert::parse(cert_der).unwrap().spki.raw_der.to_vec()
}

/// Pins one exact SubjectPublicKeyInfo DER — the authorized_keys check.
struct Pinned(Vec<u8>);
impl ClientCertVerifier for Pinned {
    fn verify(&self, id: &ClientIdentity<'_>) -> bool {
        id.spki_der == self.0.as_slice()
    }
}

/// Drive a full handshake to completion. Returns the server's view: the error
/// is whatever the server raises while reading the client's auth flight +
/// Finished (where client-auth rejections land), or Ok on success.
fn drive<V: ClientCertVerifier>(
    server_cert: CertSource,
    client_verifier: Verifier,
    client_cert: Option<ClientCertSource>,
    server_auth: ServerAuth<V>,
    clock: u64,
) -> Result<(), Error> {
    let (mode, verifier) = match server_auth {
        ServerAuth::Required(v) => (ClientAuth::Required, v),
        ServerAuth::Requested(v) => (ClientAuth::Requested, v),
    };
    let mut server = Server::with_client_auth(
        ServerConfig {
            source: server_cert,
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        move || clock,
        mode,
        verifier,
    );
    let mut client = Client::new(
        ClientConfig {
            verifier: client_verifier,
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || clock,
    );
    if let Some(cc) = client_cert {
        client.set_client_cert(cc);
    }

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch)?;
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cflight = find_send(&c3, Epoch::Handshake).unwrap();
    let s2 = server.read(Epoch::Handshake, &cflight)?;
    assert!(has_done(&c3), "client reached Done");
    assert!(has_done(&s2), "server reached Done");
    Ok(())
}

enum ServerAuth<V> {
    Required(V),
    Requested(V),
}

#[test]
fn x509_p256_mutual_auth_succeeds() {
    let (server_der, server_key) = ecdsa_p256_self_signed(SERVER_NAME);
    let (client_der, client_key) = ecdsa_p256_self_signed(CLIENT_NAME);
    let now = now_inside(&server_der);

    drive(
        CertSource::X509 {
            chain_der: vec![server_der.clone()],
            signing_key: server_key,
        },
        Verifier::X509 {
            anchors: vec![anchor(&server_der)],
            hostname: SERVER_NAME.as_bytes().to_vec(),
        },
        Some(ClientCertSource::X509 {
            chain_der: vec![client_der.clone()],
            signing_key: client_key,
        }),
        ServerAuth::Required(Pinned(x509_spki(&client_der))),
        now * 1000,
    )
    .expect("mutual auth with pinned P-256 client cert");
}

#[test]
fn rpk_ed25519_mutual_auth_succeeds() {
    let server_key = SigningKey::from_seed(&[0x11u8; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();
    let client_key = SigningKey::from_seed(&[0x22u8; 32]).unwrap();
    let client_pubkey = *client_key.pubkey().unwrap();
    let client_spki = SubjectPublicKey::Ed25519(client_pubkey).encode().unwrap();

    drive(
        CertSource::RawPublicKey {
            signing_key: server_key,
        },
        Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        Some(ClientCertSource::RawPublicKey {
            signing_key: client_key,
        }),
        ServerAuth::Required(Pinned(client_spki)),
        0,
    )
    .expect("mutual auth with pinned Ed25519 raw public key");
}

#[test]
fn requested_anonymous_client_succeeds() {
    let (server_der, server_key) = ecdsa_p256_self_signed(SERVER_NAME);
    let now = now_inside(&server_der);

    drive(
        CertSource::X509 {
            chain_der: vec![server_der.clone()],
            signing_key: server_key,
        },
        Verifier::X509 {
            anchors: vec![anchor(&server_der)],
            hostname: SERVER_NAME.as_bytes().to_vec(),
        },
        None,                                            // client presents no certificate
        ServerAuth::Requested(Pinned(vec![0xde, 0xad])), // never consulted
        now * 1000,
    )
    .expect("Requested mode tolerates an anonymous client");
}

#[test]
fn required_empty_client_cert_rejected() {
    let (server_der, server_key) = ecdsa_p256_self_signed(SERVER_NAME);
    let now = now_inside(&server_der);

    let err = drive(
        CertSource::X509 {
            chain_der: vec![server_der.clone()],
            signing_key: server_key,
        },
        Verifier::X509 {
            anchors: vec![anchor(&server_der)],
            hostname: SERVER_NAME.as_bytes().to_vec(),
        },
        None, // client has no identity → empty Certificate
        ServerAuth::Required(Pinned(vec![0x00])),
        now * 1000,
    )
    .unwrap_err();
    assert_eq!(err, Error::ClientCertRequired);
}

#[test]
fn unauthorized_client_key_rejected() {
    let (server_der, server_key) = ecdsa_p256_self_signed(SERVER_NAME);
    let (client_der, client_key) = ecdsa_p256_self_signed(CLIENT_NAME);
    let (other_der, _) = ecdsa_p256_self_signed("other.local");
    let now = now_inside(&server_der);

    let err = drive(
        CertSource::X509 {
            chain_der: vec![server_der.clone()],
            signing_key: server_key,
        },
        Verifier::X509 {
            anchors: vec![anchor(&server_der)],
            hostname: SERVER_NAME.as_bytes().to_vec(),
        },
        Some(ClientCertSource::X509 {
            chain_der: vec![client_der.clone()],
            signing_key: client_key,
        }),
        // Valid, possession-proven cert — but we pin a DIFFERENT key.
        ServerAuth::Required(Pinned(x509_spki(&other_der))),
        now * 1000,
    )
    .unwrap_err();
    assert_eq!(err, Error::AccessDenied);
}

#[test]
fn tampered_client_cert_verify_rejected() {
    // Client presents cert C (public key K1) but signs CertificateVerify with a
    // DIFFERENT key K2 — possession of K1 is therefore NOT proven.
    let (server_der, server_key) = ecdsa_p256_self_signed(SERVER_NAME);
    let (client_der, _k1) = ecdsa_p256_self_signed(CLIENT_NAME);
    let (_decoy, k2) = ecdsa_p256_self_signed(CLIENT_NAME);
    let now = now_inside(&server_der);

    let err = drive(
        CertSource::X509 {
            chain_der: vec![server_der.clone()],
            signing_key: server_key,
        },
        Verifier::X509 {
            anchors: vec![anchor(&server_der)],
            hostname: SERVER_NAME.as_bytes().to_vec(),
        },
        Some(ClientCertSource::X509 {
            chain_der: vec![client_der.clone()],
            signing_key: k2, // mismatched private key
        }),
        ServerAuth::Required(Pinned(x509_spki(&client_der))),
        now * 1000,
    )
    .unwrap_err();
    assert_eq!(err, Error::BadCertificateVerify);
}
