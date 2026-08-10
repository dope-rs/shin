use std::convert::Infallible;
use std::mem::size_of;

use shin::client::Client;
use shin::client::config::{
    Config, Error, Identity, IdentityTemplate, MAX_TRUST_ANCHORS, OwnedTrustAnchor, Template,
    Verifier,
};
use shin::connection::{Event, EventContext, EventSink};
use shin::crypto::sig::SigningKey;
use shin::identity::spki::SubjectPublicKey;
use shin::transport::Mode;
use shin::wire::record::CipherSuite;

fn x509_config(anchor_count: usize) -> Config {
    let anchor = OwnedTrustAnchor::unconstrained(
        vec![0x30, 0x00],
        SubjectPublicKey::Ed25519([0; 32]).encode().unwrap(),
    );
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
    assert_eq!(x509_config(MAX_TRUST_ANCHORS).validate(), Ok(()));
    assert!(matches!(
        x509_config(MAX_TRUST_ANCHORS + 1).validate(),
        Err(Error::TooManyTrustAnchors {
            count,
            maximum: MAX_TRUST_ANCHORS,
        }) if count == MAX_TRUST_ANCHORS + 1
    ));
}

#[test]
fn malformed_anchor_name_constraints_are_rejected_during_validation() {
    let mut config = x509_config(1);
    let Verifier::X509 { anchors, .. } = &mut config.verifier else {
        unreachable!();
    };
    anchors[0].name_constraints_der = Some(vec![0x05, 0x00]);

    assert_eq!(
        config.validate(),
        Err(Error::MalformedTrustAnchor { index: 0 })
    );
}

#[test]
fn validated_templates_are_one_word_shared_handles() {
    assert_eq!(size_of::<Template>(), size_of::<usize>());
    assert_eq!(size_of::<IdentityTemplate>(), size_of::<usize>());

    let (config, _) = x509_config(MAX_TRUST_ANCHORS).try_into_template().unwrap();
    let identity = Identity::RawPublicKey {
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
    let identity = Identity::X509 {
        chain_der: Vec::new(),
        signing_key: SigningKey::from_seed(&[0x44; 32]).unwrap(),
    };
    assert!(matches!(
        identity.try_into_template(),
        Err(Error::InvalidIdentity)
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
        Err(Error::TooManyTrustAnchors { .. })
    ));
}

#[test]
fn quic_transport_parameters_require_explicit_mode() {
    let mut implicit = x509_config(1);
    implicit.transport_params = vec![1, 2, 3];
    assert_eq!(
        implicit.validate(),
        Err(Error::TransportParametersInTls { len: 3 })
    );

    let mut explicit = x509_config(1);
    explicit.transport_params = vec![1, 2, 3];
    assert_eq!(explicit.validate_with_transport(Mode::Quic), Ok(()));
}

#[test]
fn deterministic_oversized_client_hello_is_rejected_during_validation() {
    let mut config = x509_config(1);
    config.alpn_protocols = vec![vec![b'a'; u8::MAX as usize]; 200];
    assert!(matches!(
        config.validate(),
        Err(Error::ClientHelloTooLarge { .. })
    ));
}

#[test]
fn validated_template_rejects_an_incompatible_resumption_ticket() {
    let mut config = x509_config(1);
    config.alpn_protocols = vec![vec![b'a'; u8::MAX as usize]; 50];
    let (template, _) = config.try_into_template().expect("static template fits");
    let resumption = shin::client::config::Resumption::new([7; 32], vec![9; 4096], 0, 0);

    assert!(matches!(
        template.with_resumption(Some(resumption)),
        Err(Error::ClientHelloTooLarge { .. })
    ));
}

#[test]
fn invalid_server_name_is_rejected_before_client_construction() {
    let mut config = x509_config(1);
    config.verifier = Verifier::X509 {
        anchors: match config.verifier {
            Verifier::X509 { anchors, .. } => anchors,
            Verifier::RawPublicKey { .. } => unreachable!(),
        },
        hostname: b"bad\0host.example".to_vec(),
    };
    assert_eq!(config.validate(), Err(Error::InvalidServerName));
}

#[test]
fn configuration_cannot_replace_a_started_handshake_state() {
    let mut client = Client::new(x509_config(1), || 0).unwrap();
    client.start_into(&mut IgnoreEvents).unwrap();

    let error = client
        .set_identity(Identity::RawPublicKey {
            signing_key: SigningKey::from_seed(&[0x52; 32]).unwrap(),
        })
        .unwrap_err();
    assert_eq!(error, shin::connection::Error::UnexpectedMessage);
}

#[test]
fn empty_cipher_policy_is_rejected_without_mutating_the_client() {
    let mut client = Client::new(x509_config(1), || 0).unwrap();
    assert_eq!(
        client.set_cipher_suites(&[]),
        Err(shin::connection::Error::BadConfig)
    );
    assert_eq!(
        client.set_cipher_suites(&[CipherSuite::Aes128GcmSha256]),
        Ok(())
    );
}
