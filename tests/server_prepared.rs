use core::convert::Infallible;

use rcgen::{
    CertificateParams, CustomExtension, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519,
};

use shin::client;
use shin::connection::{Epoch, Event, EventContext, EventSink};
use shin::crypto::sig::SigningKey;
use shin::identity::asn1::{Reader, Tag};
use shin::server::config::{CertSource, Config, Connection};
use shin::server::{OwnedConnection, ReplayDomain, Server, Shard};
use shin::transport::Mode;

mod support;

use support::AllocationProbe;

fn raw_config() -> Config {
    Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    }
}

fn stream_server() -> Server<fn() -> u64> {
    fn now() -> u64 {
        0
    }

    Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        now as fn() -> u64,
    )
    .unwrap()
}

struct Ignore;

impl EventSink for Ignore {
    type Error = Infallible;

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct CaptureSend(Vec<u8>);

impl EventSink for CaptureSend {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        if let Event::Send {
            epoch: Epoch::Plaintext,
            data,
        } = event
        {
            self.0.extend_from_slice(data);
        }
        Ok(())
    }
}

#[derive(Default)]
struct CountSend {
    bytes: usize,
    done: bool,
}

impl EventSink for CountSend {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        if let Event::Send { data, .. } = event {
            self.bytes += data.len();
        } else if matches!(event, Event::Done) {
            self.done = true;
        }
        Ok(())
    }
}

struct CaptureServerFlight {
    plaintext: Vec<u8>,
    handshake: Vec<u8>,
}

struct CaptureClientFlight {
    handshake: Vec<u8>,
    done: bool,
}

impl CaptureClientFlight {
    fn reserved() -> Self {
        Self {
            handshake: Vec::with_capacity(64 * 1024),
            done: false,
        }
    }
}

impl EventSink for CaptureClientFlight {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send {
                epoch: Epoch::Handshake,
                data,
            } => self.handshake.extend_from_slice(data),
            Event::Done => self.done = true,
            _ => {}
        }
        Ok(())
    }
}

impl CaptureServerFlight {
    fn reserved() -> Self {
        Self {
            plaintext: Vec::with_capacity(16 * 1024),
            handshake: Vec::with_capacity(64 * 1024),
        }
    }
}

impl EventSink for CaptureServerFlight {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        if let Event::Send { epoch, data } = event {
            match epoch {
                Epoch::Plaintext => self.plaintext.extend_from_slice(data),
                Epoch::Handshake => self.handshake.extend_from_slice(data),
                Epoch::Application | Epoch::EarlyData => {}
            }
        }
        Ok(())
    }
}

fn invalid_x509_config() -> Config {
    Config {
        source: CertSource::X509 {
            chain_der: Vec::new(),
            signing_key: SigningKey::from_seed(&[8; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    }
}

fn large_x509_config(extension_len: usize) -> Config {
    large_x509_identity(extension_len).0
}

fn large_x509_identity(extension_len: usize) -> (Config, Vec<u8>) {
    let (certificate, signing_key) =
        large_x509_credentials(extension_len, ExtendedKeyUsagePurpose::ServerAuth);
    (
        Config {
            source: CertSource::X509 {
                chain_der: vec![certificate.clone()],
                signing_key,
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        certificate,
    )
}

fn large_x509_credentials(
    extension_len: usize,
    usage: ExtendedKeyUsagePurpose,
) -> (Vec<u8>, SigningKey) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let seed = extract_ed25519_seed(&key.serialize_der()).unwrap();
    let mut params = CertificateParams::new(vec!["large.shin.local".into()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![usage];
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55_555, 1],
            vec![0xA5; extension_len],
        ));
    let certificate = params.self_signed(&key).unwrap().der().to_vec();
    (certificate, SigningKey::from_seed(&seed).unwrap())
}

fn extract_ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut outer = Reader::new(pkcs8);
    let sequence = outer.read_tagged(Tag::SEQUENCE).ok()?;
    let mut sequence = Reader::new(sequence);
    sequence.read_uint().ok()?;
    sequence.read_tagged(Tag::SEQUENCE).ok()?;
    let private_key = sequence.read_tagged(Tag::OCTET_STRING).ok()?;
    let mut private_key = Reader::new(private_key);
    private_key
        .read_tagged(Tag::OCTET_STRING)
        .ok()?
        .try_into()
        .ok()
}

#[test]
fn shard_constructor_rejects_invalid_identity_immediately() {
    assert_eq!(
        Shard::new(invalid_x509_config()).err(),
        Some(shin::connection::Error::BadConfig),
    );
}

#[test]
fn server_constructor_rejects_bad_config_immediately() {
    assert!(matches!(
        Server::<_>::new(
            Connection {
                transport_params: vec![1],
            },
            || 0,
        ),
        Err(shin::connection::Error::BadConfig)
    ));
}

#[test]
fn valid_server_and_shard_bind_without_deferred_errors() {
    let mut shard = Shard::new(raw_config()).unwrap();
    let server = Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
    )
    .unwrap();
    assert!(shard.bind(server).into_result().is_ok());
}

#[test]
fn rejected_owned_binding_returns_server_and_exact_shard() {
    let shard = Shard::new(large_x509_config(200_000)).unwrap();
    let required = shard.tls_profile().capacities();
    let server = stream_server();
    let actual = server.into_workspace().capacities();
    let server = stream_server();

    let Err(rejection) = OwnedConnection::new(server, shard).into_result() else {
        panic!("undersized owned server was admitted");
    };
    let (error, (server, shard)) = rejection.into_parts();

    assert_eq!(error, shin::connection::Error::BadConfig);
    assert_eq!(server.into_workspace().capacities(), actual);
    assert_eq!(shard.tls_profile().capacities(), required);
}

#[test]
fn prepared_owned_connection_has_no_admission_failure_surface() {
    let shard = Shard::new(large_x509_config(200_000)).unwrap();
    let required = shard.tls_profile().capacities();
    let connection = OwnedConnection::prepare(
        shard,
        Connection {
            transport_params: Vec::new(),
        },
        Mode::Tls,
        (|| 0) as fn() -> u64,
    )
    .unwrap();

    assert_eq!(connection.into_workspace().capacities(), required);
}

#[test]
fn prepared_borrowed_connection_has_no_admission_failure_surface() {
    let mut shard = Shard::new(large_x509_config(200_000)).unwrap();
    let required = shard.tls_profile().capacities();
    let connection = shin::server::Connection::prepare(
        &mut shard,
        Connection {
            transport_params: Vec::new(),
        },
        Mode::Tls,
        (|| 0) as fn() -> u64,
    )
    .unwrap();

    assert_eq!(connection.into_workspace().capacities(), required);
}

#[test]
fn tls_profiles_are_bound_to_exact_shard_identity() {
    let first = Shard::new(raw_config()).unwrap();
    let second = Shard::new(raw_config()).unwrap();

    assert!(first.tls_profile() == first.tls_profile());
    assert!(first.tls_profile() != second.tls_profile());
}

#[test]
fn multiplexed_connections_admit_many_connections_to_one_exact_shard() {
    let shard = Shard::new(raw_config()).unwrap();
    let mut first = shard
        .bind_multiplexed(stream_server())
        .into_result()
        .unwrap();
    let second = shard
        .bind_multiplexed(stream_server())
        .into_result()
        .unwrap();

    shard.replace_ticket_keys(None);
    assert_eq!(first.selected_alpn(), None);
    assert_eq!(second.selected_alpn(), None);
    assert!(first.read_into(Epoch::Plaintext, &[], &mut Ignore).is_ok());
}

#[test]
fn multiplexed_connection_retains_its_exact_authority() {
    let admitting = Shard::new(raw_config()).unwrap();
    let mut connection = admitting
        .bind_multiplexed(stream_server())
        .into_result()
        .unwrap();
    drop(admitting);

    assert!(
        connection
            .read_into(Epoch::Plaintext, &[], &mut Ignore)
            .is_ok()
    );
}

#[test]
fn exact_flight_preflight_preserves_large_tls_identity_but_rejects_quic_sum() {
    let shard = Shard::new(large_x509_config(200_000)).unwrap();
    let layout = shard.tls_workspace_layout();
    assert!(layout.capacities().1 > shin::wire::record::MAX_PLAINTEXT_BODY);
    assert!(
        shard
            .new_multiplexed(
                Connection {
                    transport_params: Vec::new(),
                },
                Mode::Tls,
                || 0,
            )
            .is_ok()
    );

    let default = Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
    )
    .unwrap();
    let Err(rejection) = shard.bind_multiplexed(default).into_result() else {
        panic!("undersized server was admitted");
    };
    assert_eq!(rejection.error(), &shin::connection::Error::BadConfig);

    assert!(matches!(
        shard.new_multiplexed(
            Connection {
                transport_params: vec![0; 65_000],
            },
            Mode::Quic,
            || 0,
        ),
        Err(shin::connection::Error::BadConfig)
    ));
}

#[test]
fn quic_workspace_limit_is_the_exact_extension_vector_bound() {
    let shard = Shard::new(raw_config()).unwrap();
    let at_limit = Connection {
        transport_params: vec![0; 65_521],
    };
    let over_limit = Connection {
        transport_params: vec![0; 65_522],
    };

    assert!(shard.workspace_layout(&at_limit, Mode::Quic).is_ok());
    assert!(matches!(
        shard.workspace_layout(&over_limit, Mode::Quic),
        Err(shin::connection::Error::BadConfig)
    ));
}

#[test]
fn exact_large_server_flight_allocates_only_before_admission() {
    use shin::client::config::{OwnedTrustAnchor, Verifier};
    use shin::crypto::hash;

    const OPTIONAL_CERTIFICATE_TYPE_EXTENSIONS_LEN: usize = 2 * (4 + 1);

    let (config, certificate) = large_x509_identity(32_000);
    let shard = Shard::new(config).unwrap();
    let outbound_flight_capacity = shard.tls_workspace_layout().capacities().1;
    let certificate_view = shin::identity::cert::Cert::parse(&certificate).unwrap();
    let now_ms = shin::identity::UnixTime(
        (certificate_view.tbs.validity.not_before.0 + certificate_view.tbs.validity.not_after.0)
            / 2,
    )
    .as_secs()
    .unwrap()
        * 1_000;
    let mut server = shard
        .new_multiplexed(
            Connection {
                transport_params: Vec::new(),
            },
            Mode::Tls,
            || 0,
        )
        .unwrap();
    let mut client = client::Client::new(
        client::config::Config {
            verifier: Verifier::X509 {
                anchors: vec![OwnedTrustAnchor::from_cert_der(&certificate).unwrap()],
                hostname: b"large.shin.local".to_vec(),
                certificate_limit: shin::client::config::CertificateLimit::new::<{ 64 * 1024 }>(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        move || now_ms,
    )
    .unwrap();
    let mut hello = CaptureSend(Vec::new());
    client.start_into(&mut hello).unwrap();

    let mut sent = CaptureServerFlight::reserved();
    let server_allocations = AllocationProbe::measured(|| {
        server
            .read_into(Epoch::Plaintext, &hello.0, &mut sent)
            .unwrap();
    });

    assert_eq!(server_allocations, 0);
    assert!(sent.handshake.len() > shin::wire::record::MAX_PLAINTEXT_BODY);
    assert_eq!(
        outbound_flight_capacity,
        sent.handshake.len() + hash::MAX_LEN - hash::SHA256_LEN
            + OPTIONAL_CERTIFICATE_TYPE_EXTENSIONS_LEN
    );

    let mut client_events = CountSend::default();
    client
        .read_into(Epoch::Plaintext, &sent.plaintext, &mut client_events)
        .unwrap();
    let client_allocations = AllocationProbe::measured(|| {
        for chunk in sent.handshake.chunks(4096) {
            client
                .read_into(Epoch::Handshake, chunk, &mut client_events)
                .unwrap();
        }
    });

    assert_eq!(client_allocations, 0);
    assert!(client_events.done);
}

#[test]
fn exact_large_client_identity_allocates_only_before_admission() {
    use shin::client::config::{Identity, Verifier};
    use shin::identity::cert::Cert;
    use shin::server::config::{ClientAuth, ClientCertVerifier, ClientIdentity};

    struct PinnedLargeIdentity(Vec<u8>);

    impl ClientCertVerifier for PinnedLargeIdentity {
        const MAX_CERTIFICATE_MESSAGE_SIZE: usize = 64 * 1024;

        fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
            identity.spki_der == self.0
        }
    }

    let server_key = SigningKey::from_seed(&[7; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();
    let (client_certificate, client_key) =
        large_x509_credentials(32_000, ExtendedKeyUsagePurpose::ClientAuth);
    let client_spki = Cert::parse(&client_certificate)
        .unwrap()
        .tbs
        .spki
        .raw_der
        .to_vec();
    let shard = Shard::with_client_auth(
        Config {
            source: CertSource::RawPublicKey {
                signing_key: server_key,
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        PinnedLargeIdentity(client_spki),
    )
    .unwrap();
    let server_profile = shard.tls_profile();
    assert_eq!(
        server_profile.capacities(),
        (64 * 1024, shin::wire::record::MAX_PLAINTEXT_BODY, 64 * 1024)
    );
    let mut server_pool = None;
    let allocation_profile = AllocationProbe::measured_with_bytes(|| {
        server_pool = Some(
            server_profile
                .into_pool::<fn() -> u64>(o3::collections::slab::Capacity::try_from(1).unwrap()),
        );
    });
    assert_eq!(allocation_profile.0, 4);
    assert!(allocation_profile.1 >= 144 * 1024);
    let server_pool = server_pool.unwrap();
    let mut server = server_pool.connect((|| 0) as fn() -> u64).unwrap();

    let identity = Identity::X509 {
        chain_der: vec![client_certificate],
        signing_key: client_key,
    }
    .try_into_template()
    .unwrap();
    let prepared = client::config::Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
    .try_into_prepared()
    .unwrap();
    let anonymous_layout = prepared.workspace_layout(None);
    let identity_layout = prepared.workspace_layout(Some(&identity));
    let rejection = match prepared
        .template()
        .without_resumption()
        .try_into_client_with_workspace(Some(identity.clone()), || 0, anonymous_layout.allocate())
    {
        Ok(_) => panic!("undersized anonymous workspace admitted a large client identity"),
        Err(rejection) => rejection,
    };
    assert_eq!(rejection.mismatch().required(), identity_layout);
    assert_eq!(rejection.mismatch().actual(), anonymous_layout);
    let (_, recovered_workspace) = rejection.into_parts();
    assert_eq!(
        recovered_workspace.capacities(),
        anonymous_layout.capacities()
    );

    let client_layout = prepared.workspace_layout(Some(&identity));
    let client_capacities = client_layout.capacities();
    assert!(client_capacities.1 > shin::wire::record::MAX_PLAINTEXT_BODY);
    let mut client_workspace = None;
    let client_profile = AllocationProbe::measured_with_bytes(|| {
        client_workspace = Some(client_layout.allocate());
    });
    assert_eq!(
        client_profile,
        (2, client_capacities.0 + client_capacities.1)
    );
    let mut client = prepared
        .try_into_client_with_workspace(Some(identity), || 0, client_workspace.unwrap())
        .unwrap();

    let mut hello = CaptureSend(Vec::new());
    client.start_into(&mut hello).unwrap();
    let mut server_flight = CaptureServerFlight::reserved();
    server
        .read_into(Epoch::Plaintext, &hello.0, &mut server_flight)
        .unwrap();

    let mut client_flight = CaptureClientFlight::reserved();
    let client_allocations = AllocationProbe::measured(|| {
        client
            .read_into(
                Epoch::Plaintext,
                &server_flight.plaintext,
                &mut client_flight,
            )
            .unwrap();
        client
            .read_into(
                Epoch::Handshake,
                &server_flight.handshake,
                &mut client_flight,
            )
            .unwrap();
    });

    assert_eq!(client_allocations, 0);
    assert!(client_flight.done);
    assert!(client_flight.handshake.len() > shin::wire::record::MAX_PLAINTEXT_BODY);

    let mut server_events = CountSend::default();
    let server_allocations = AllocationProbe::measured(|| {
        for chunk in client_flight.handshake.chunks(4096) {
            server
                .read_into(Epoch::Handshake, chunk, &mut server_events)
                .unwrap();
        }
    });

    assert_eq!(server_allocations, 0);
    assert!(server_events.done);
}

#[test]
fn shard_rejects_a_policy_whose_minimum_tls_flight_cannot_fit() {
    assert!(matches!(
        Shard::new(large_x509_config(261_700)),
        Err(shin::connection::Error::BadConfig)
    ));
}

#[test]
fn replay_domain_is_an_explicit_cloneable_namespace_token() {
    let domain = ReplayDomain::new([0xA5; 16]);
    assert_eq!(domain, domain.clone());

    // Creating ordinary shards still needs no caller-provided namespace.
    Shard::new(raw_config()).unwrap();
}
