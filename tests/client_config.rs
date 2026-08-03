use std::convert::Infallible;
use std::mem::size_of;

use shin::client::Client;
use shin::client::config::{
    ClientCertSource, ClientCertTemplate, Config, ConfigTemplate, MAX_TRUST_ANCHORS,
    OwnedTrustAnchor, Verifier,
};
use shin::connection::{Error, Event, EventContext, EventSink};
use shin::crypto::sig::SigningKey;
use shin::identity::spki::SubjectPublicKey;
use shin::wire::record::CipherSuite;

fn x509_config(anchor_count: usize) -> Config {
    let anchor = OwnedTrustAnchor {
        subject_der: vec![0x30, 0x00],
        spki_der: SubjectPublicKey::Ed25519([0; 32]).encode().unwrap(),
    };
    Config {
        verifier: Verifier::X509 {
            anchors: vec![anchor; anchor_count],
            hostname: b"example.com".to_vec(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    }
}

#[test]
fn x509_trust_anchor_limit_is_inclusive() {
    assert!(x509_config(MAX_TRUST_ANCHORS).try_into_template().is_ok());
    assert!(matches!(
        x509_config(MAX_TRUST_ANCHORS + 1).try_into_template(),
        Err(Error::BadConfig)
    ));
}

#[test]
fn validated_templates_are_one_word_shared_handles() {
    assert_eq!(size_of::<ConfigTemplate>(), size_of::<usize>());
    assert_eq!(size_of::<ClientCertTemplate>(), size_of::<usize>());

    let (config, _) = x509_config(MAX_TRUST_ANCHORS).try_into_template().unwrap();
    let identity = ClientCertSource::RawPublicKey {
        signing_key: SigningKey::from_seed(&[0x31; 32]).unwrap(),
    }
    .try_into_template()
    .unwrap();

    let config_clone = config.clone();
    let identity_clone = identity.clone();
    drop((config, config_clone, identity, identity_clone));
}

#[test]
fn invalid_identity_cannot_become_a_template() {
    let identity = ClientCertSource::X509 {
        chain_der: Vec::new(),
        signing_key: SigningKey::from_seed(&[0x44; 32]).unwrap(),
    };
    assert!(matches!(
        identity.try_into_template(),
        Err(Error::BadConfig)
    ));
}

struct IgnoreEvents;

impl EventSink for IgnoreEvents {
    type Error = Infallible;

    fn event(&mut self, _: Event<'_>, _: EventContext) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn invalid_config_never_becomes_a_runtime_client() {
    assert!(matches!(
        Client::new(x509_config(MAX_TRUST_ANCHORS + 1), || 0),
        Err(Error::BadConfig)
    ));
}

#[test]
fn deterministic_oversized_client_hello_is_rejected_during_validation() {
    let mut config = x509_config(1);
    config.alpn_protocols = vec![vec![b'a'; u8::MAX as usize]; 200];
    assert!(matches!(config.validate(), Err(Error::BadConfig)));
}

#[test]
fn configuration_cannot_replace_a_started_handshake_state() {
    let mut client = Client::new(x509_config(1), || 0).unwrap();
    client.start_into(&mut IgnoreEvents).unwrap();

    let error = client
        .set_client_cert(ClientCertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[0x52; 32]).unwrap(),
        })
        .unwrap_err();
    assert_eq!(error, Error::UnexpectedMessage);
}

#[test]
fn empty_cipher_policy_is_rejected_without_mutating_the_client() {
    let mut client = Client::new(x509_config(1), || 0).unwrap();
    assert_eq!(client.set_cipher_suites(&[]), Err(Error::BadConfig));
    assert_eq!(
        client.set_cipher_suites(&[CipherSuite::Aes128GcmSha256]),
        Ok(())
    );
}
