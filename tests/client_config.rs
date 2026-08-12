use std::mem::size_of;

use shin::client::Client;
use shin::client::config::{
    Config, Error, Identity, IdentityTemplate, MAX_TRUST_ANCHORS, NegotiatedAlpn, OwnedTrustAnchor,
    Restore, Template, TrustStore, Verifier,
};
use shin::crypto::sig::SigningKey;
use shin::transport::Mode;
use shin::wire::record::CipherSuite;

mod support;

use support::AllocationProbe;

fn x509_config(anchor_count: usize) -> Config {
    x509_config_with_hostname(anchor_count, b"example.com".to_vec())
}

fn x509_config_with_hostname(anchor_count: usize, hostname: Vec<u8>) -> Config {
    let root = &webpki_roots::TLS_SERVER_ROOTS[0];
    let anchor = OwnedTrustAnchor::from_der_fields(
        root.subject.as_ref(),
        root.subject_public_key_info.as_ref(),
        root.name_constraints.as_ref().map(|value| value.as_ref()),
    );
    Config {
        verifier: Verifier::X509 {
            anchors: vec![anchor; anchor_count],
            hostname,
            certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
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
    assert_eq!(size_of::<TrustStore>(), size_of::<usize>());

    let config = x509_config(MAX_TRUST_ANCHORS).try_into_template().unwrap();
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
fn complete_webpki_root_set_builds_a_prepared_store() {
    let anchors: Vec<_> = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|anchor| {
            OwnedTrustAnchor::from_der_fields(
                anchor.subject.as_ref(),
                anchor.subject_public_key_info.as_ref(),
                anchor.name_constraints.as_ref().map(|value| value.as_ref()),
            )
        })
        .collect();
    let mut roots = None;
    let profile = AllocationProbe::measured_with_bytes(|| {
        roots = Some(TrustStore::new(anchors).expect("complete WebPKI roots must prepare"));
    });
    let roots = roots.unwrap();
    assert!(roots.len() > 64);
    assert!(roots.len() <= MAX_TRUST_ANCHORS);
    assert!(
        profile.1 <= 64 * 1024,
        "prepared root index allocated {profile:?}"
    );

    let config = Config {
        verifier: Verifier::X509Store {
            roots,
            hostname: b"example.com".to_vec(),
            certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    };
    assert_eq!(config.validate(), Ok(()));
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
    let template = config.try_into_template().expect("static template fits");
    let restore = Restore::try_new([7; 32], vec![9; 4096], 0, 0, 7_200).unwrap();

    assert!(matches!(
        template.restore(restore),
        Err(Error::ClientHelloTooLarge { .. })
    ));
}

#[test]
fn external_restore_binds_through_the_endpoint_template() {
    let template = x509_config(1).try_into_template().unwrap();
    let restore = Restore::try_new([7; 32], vec![9], 0, 0, 7_200).unwrap();
    let prepared = template.restore(restore).unwrap();
    let workspace = prepared.workspace_layout(None).allocate();
    let _client = prepared
        .try_into_client_with_workspace(None, (|| 0) as fn() -> u64, workspace)
        .unwrap();
}

#[test]
fn restored_ticket_lifetime_is_nonzero_and_bounded() {
    for lifetime in [0, 604_801] {
        assert!(matches!(
            Restore::try_new([7; 32], vec![9], 0, 0, lifetime),
            Err(Error::InvalidResumptionLifetime),
        ));
    }
    assert!(Restore::try_new([7; 32], vec![9], 0, 0, 604_800).is_ok());
}

#[test]
fn early_data_entitlement_rejects_invalid_profile_combinations() {
    let restore = || Restore::try_new([7; 32], vec![9], 0, 0, 7_200).unwrap();
    for invalid in [
        restore().try_with_early_data(
            0,
            CipherSuite::Aes128GcmSha256,
            Mode::Tls,
            NegotiatedAlpn::Absent,
        ),
        restore().try_with_early_data(
            u32::MAX,
            CipherSuite::Aes128GcmSha256,
            Mode::Tls,
            NegotiatedAlpn::Absent,
        ),
        restore().try_with_early_data(
            16_384,
            CipherSuite::Aes128GcmSha256,
            Mode::Quic,
            NegotiatedAlpn::Absent,
        ),
        restore().try_with_early_data(
            16_384,
            CipherSuite::Aes256GcmSha384,
            Mode::Tls,
            NegotiatedAlpn::Absent,
        ),
    ] {
        assert!(matches!(invalid, Err(Error::InvalidEarlyDataEntitlement)));
    }
}

#[test]
fn invalid_server_name_is_rejected_before_client_construction() {
    let config = x509_config_with_hostname(1, b"bad\0host.example".to_vec());
    assert_eq!(config.validate(), Err(Error::InvalidServerName));
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
