use std::convert::Infallible;
use std::hint::black_box;

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
use shin::client::config::{Config, Identity, OwnedTrustAnchor, Resumption, Verifier};
use shin::client::{Client, Hybrid};
use shin::connection::{Epoch, Error, Event, EventContext, EventSink};
use shin::crypto::kx::HybridWorkspace;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::Keys;
use shin::identity::asn1::{Reader, Tag};
use shin::identity::cert::Cert;
use shin::identity::spki::SubjectPublicKey;
use shin::server::{
    Server, Shard, config, config::CertSource, config::ClientAuth, config::ClientCertVerifier,
    config::ClientIdentity, config::Connection, config::EarlyDataGuard,
};
use shin::transport::Mode;
use shin::wire::codec;
use shin::wire::extension::Type;
use shin::wire::handshake::Frame;
use shin::wire::handshake::storage::Scratch;
use shin::wire::handshake::views::MessageRef;
use shin::wire::record::{CipherSuite, MAX_PLAINTEXT_BODY};

mod support;

use support::AllocationProbe;

struct PinnedSpki(Vec<u8>);

#[test]
fn public_borrowed_handshake_view_is_allocation_free() {
    use shin::wire::extension::Extension;
    use shin::wire::handshake::messages::ClientHello;
    use shin::wire::handshake::{RANDOM_LEN, TLS_1_2};

    let frame = Frame::ClientHello(ClientHello {
        legacy_version: TLS_1_2,
        random: [0xA5; RANDOM_LEN],
        legacy_session_id: vec![1, 2, 3],
        cipher_suites: vec![0x1301, 0x1303],
        legacy_compression_methods: vec![0],
        extensions: vec![Extension::new(Type::SUPPORTED_VERSIONS, vec![2, 3, 4])],
    });
    let mut encoded = Vec::new();
    frame.encode(&mut encoded).unwrap();

    let allocations = AllocationProbe::measured(|| {
        let MessageRef::ClientHello(hello) = MessageRef::decode(&encoded).unwrap() else {
            panic!("expected ClientHello");
        };
        assert_eq!(hello.cipher_suites.len(), 2);
        assert!(hello.cipher_suites.contains(0x1303));
        assert!(hello.extensions.find(Type::SUPPORTED_VERSIONS).is_some());
        black_box(hello);
    });
    assert_eq!(allocations, 0);
}

impl ClientCertVerifier for PinnedSpki {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        identity.spki_der == self.0
    }
}

struct AcceptEarlyData;

impl EarlyDataGuard for AcceptEarlyData {
    fn register(&self, _token: &[u8]) -> bool {
        true
    }
}

#[derive(Default)]
struct Wire {
    plaintext: Vec<u8>,
    handshake: Vec<u8>,
    application: Vec<u8>,
    peer_extension: Vec<u8>,
    ticket_suite: Option<CipherSuite>,
    resumption: Option<Resumption>,
    retain_tickets: bool,
    zero_rtt_max: Option<u32>,
    zero_rtt_alpn_h3: bool,
}

impl Wire {
    fn reserved() -> Self {
        Self {
            plaintext: Vec::with_capacity(16 * 1024),
            handshake: Vec::with_capacity(16 * 1024),
            application: Vec::with_capacity(16 * 1024),
            peer_extension: Vec::with_capacity(16 * 1024),
            ticket_suite: None,
            resumption: None,
            retain_tickets: true,
            zero_rtt_max: None,
            zero_rtt_alpn_h3: false,
        }
    }

    fn clear(&mut self) {
        self.plaintext.clear();
        self.handshake.clear();
        self.application.clear();
        self.peer_extension.clear();
        self.ticket_suite = None;
        self.resumption = None;
        self.zero_rtt_max = None;
        self.zero_rtt_alpn_h3 = false;
    }
}

impl EventSink for Wire {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => match epoch {
                Epoch::Plaintext => self.plaintext.extend_from_slice(data),
                Epoch::Handshake => self.handshake.extend_from_slice(data),
                Epoch::Application => self.application.extend_from_slice(data),
                Epoch::EarlyData => {}
            },
            Event::PeerExtension { data, .. } => {
                self.peer_extension.clear();
                self.peer_extension.extend_from_slice(data);
            }
            Event::NewSessionTicket(ticket) => {
                self.ticket_suite = context.cipher_suite();
                if self.retain_tickets {
                    self.resumption = Some(ticket.try_retain().unwrap());
                }
            }
            Event::ZeroRttKeysReady {
                max_early_data,
                alpn,
                ..
            } => {
                self.zero_rtt_max = Some(max_early_data);
                self.zero_rtt_alpn_h3 = alpn == Some(b"h3".as_slice());
            }
            _ => {}
        }
        Ok(())
    }
}

fn workspace() -> Scratch {
    Scratch::new(16 * 1024, 16 * 1024, 16 * 1024)
}

fn assert_zero_allocations(counts: [usize; 5]) {
    assert_eq!(counts, [0; 5]);
}

fn ticket_processing_allocations(retain: bool) -> usize {
    let signing_key = SigningKey::from_seed(&[0x31; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut shard = Shard::new(config::Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: Some(Keys::single([0x32; 32]).unwrap()),
    })
    .unwrap();
    let server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    )
    .unwrap();
    let mut server = shard.bind(server).into_result().unwrap();
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    client.start_into(&mut client_wire).unwrap();
    server
        .read_into(Epoch::Plaintext, &client_wire.plaintext, &mut server_wire)
        .unwrap();
    client_wire.clear();
    client
        .read_into(Epoch::Plaintext, &server_wire.plaintext, &mut client_wire)
        .unwrap();
    client
        .read_into(Epoch::Handshake, &server_wire.handshake, &mut client_wire)
        .unwrap();
    server_wire.clear();
    server
        .read_into(Epoch::Handshake, &client_wire.handshake, &mut server_wire)
        .unwrap();
    client_wire.clear();
    client_wire.retain_tickets = retain;

    AllocationProbe::measured(|| {
        client
            .read_into(
                Epoch::Application,
                &server_wire.application,
                &mut client_wire,
            )
            .unwrap()
    })
}

#[test]
fn session_ticket_retention_is_the_only_ticket_allocation() {
    assert_eq!(ticket_processing_allocations(false), 0);
    assert_eq!(ticket_processing_allocations(true), 1);
}

#[test]
fn role_defaults_reserve_only_reachable_workspace_regions() {
    assert_eq!(
        Scratch::for_server().capacities(),
        (MAX_PLAINTEXT_BODY, MAX_PLAINTEXT_BODY, MAX_PLAINTEXT_BODY)
    );
}

fn x509_identity() -> (Vec<u8>, SigningKey, u64) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let pkcs8 = key.serialize_der();
    let mut reader = Reader::new(&pkcs8);
    let sequence = reader.read_tagged(Tag::SEQUENCE).unwrap();
    let mut sequence = Reader::new(sequence);
    sequence.read_uint().unwrap();
    sequence.read_tagged(Tag::SEQUENCE).unwrap();
    let outer = sequence.read_tagged(Tag::OCTET_STRING).unwrap();
    let mut outer = Reader::new(outer);
    let seed = outer.read_tagged(Tag::OCTET_STRING).unwrap();
    let signing_key = SigningKey::from_seed(seed.try_into().unwrap()).unwrap();

    let mut params = CertificateParams::new(vec!["host.local".into()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).unwrap();
    let cert_der = cert.der().to_vec();
    let parsed = Cert::parse(&cert_der).unwrap();
    let validity = parsed.tbs.validity;
    let now = shin::identity::UnixTime((validity.not_before.0 + validity.not_after.0) / 2)
        .as_secs()
        .unwrap();
    (cert_der, signing_key, now)
}

#[test]
fn caller_owned_hybrid_rpk_handshake_has_no_allocations() {
    let signing_key = SigningKey::from_seed(&[7; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let client_signing_key = SigningKey::from_seed(&[6; 32]).unwrap();
    let client_spki = SubjectPublicKey::Ed25519(*client_signing_key.pubkey().unwrap())
        .encode()
        .unwrap();
    let mut shard = Shard::with_client_auth(
        config::Config {
            source: CertSource::RawPublicKey { signing_key },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        PinnedSpki(client_spki),
    )
    .unwrap();
    let server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    )
    .unwrap();
    let mut server = shard.bind(server).into_result().unwrap();
    let mut hybrid_workspace = HybridWorkspace::new();
    let client = Client::mutual(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        Identity::RawPublicKey {
            signing_key: client_signing_key,
        },
        || 0,
    )
    .unwrap();
    let mut client = Hybrid::from_client(client, &mut hybrid_workspace).unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = AllocationProbe::measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = AllocationProbe::measured(|| {
        server
            .read_into(Epoch::Plaintext, &client_hello, &mut server_wire)
            .unwrap()
    });
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = AllocationProbe::measured(|| {
        client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = AllocationProbe::measured(|| {
        for fragment in server_flight.chunks(1) {
            client
                .read_into(Epoch::Handshake, fragment, &mut client_wire)
                .unwrap();
        }
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = AllocationProbe::measured(|| {
        for fragment in client_flight.chunks(1) {
            server
                .read_into(Epoch::Handshake, fragment, &mut server_wire)
                .unwrap();
        }
    });

    assert_zero_allocations([
        client_start,
        server_read,
        client_server_hello,
        client_server_flight,
        server_finish,
    ]);
}

#[test]
fn x509_handshake_has_no_allocations_after_construction() {
    let (cert_der, signing_key, now) = x509_identity();
    let (client_cert_der, client_signing_key, _) = x509_identity();
    let client_spki = Cert::parse(&client_cert_der)
        .unwrap()
        .tbs
        .spki
        .raw_der
        .to_vec();
    let anchor = OwnedTrustAnchor::from_cert_der(&cert_der).unwrap();
    let mut shard = Shard::with_client_auth(
        config::Config {
            source: CertSource::X509 {
                chain_der: vec![cert_der],
                signing_key,
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        PinnedSpki(client_spki),
    )
    .unwrap();
    let server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    )
    .unwrap();
    let mut server = shard.bind(server).into_result().unwrap();
    let mut client = Client::mutual(
        Config {
            verifier: Verifier::X509 {
                anchors: vec![anchor],
                hostname: b"host.local".to_vec(),
                certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        Identity::X509 {
            chain_der: vec![client_cert_der],
            signing_key: client_signing_key,
        },
        move || now * 1000,
    )
    .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = AllocationProbe::measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = AllocationProbe::measured(|| {
        server
            .read_into(Epoch::Plaintext, &client_hello, &mut server_wire)
            .unwrap()
    });
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = AllocationProbe::measured(|| {
        client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = AllocationProbe::measured(|| {
        for fragment in server_flight.chunks(1) {
            client
                .read_into(Epoch::Handshake, fragment, &mut client_wire)
                .unwrap();
        }
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = AllocationProbe::measured(|| {
        for fragment in client_flight.chunks(1) {
            server
                .read_into(Epoch::Handshake, fragment, &mut server_wire)
                .unwrap();
        }
    });
    assert_zero_allocations([
        client_start,
        server_read,
        client_server_hello,
        client_server_flight,
        server_finish,
    ]);
}

#[test]
fn fragmented_alpn_transport_params_and_resumption_have_no_allocations() {
    let signing_key = SigningKey::from_seed(&[8; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut shard = Shard::with_early_data_guard(
        config::Config {
            source: CertSource::RawPublicKey { signing_key },
            alpn_protocols: vec![b"h3".to_vec()],
            ticket_keys: Some(Keys::single([9; 32]).unwrap()),
        },
        AcceptEarlyData,
    )
    .unwrap();
    let server = Server::with_transport_workspace(
        Connection {
            transport_params: b"server tp".to_vec(),
        },
        Mode::Quic,
        || 0,
        workspace(),
    )
    .unwrap();
    let mut server = shard.bind(server).into_result().unwrap();
    let mut client = Client::new_with_transport(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: b"client tp".to_vec(),
            alpn_protocols: vec![b"h3".to_vec()],
            enable_early_data: false,
        },
        Mode::Quic,
        || 0,
    )
    .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = AllocationProbe::measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = AllocationProbe::measured(|| {
        for fragment in client_hello.chunks(1) {
            server
                .read_into(Epoch::Plaintext, fragment, &mut server_wire)
                .unwrap();
        }
    });
    assert_eq!(server_wire.peer_extension, b"client tp");
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = AllocationProbe::measured(|| {
        for fragment in server_hello.chunks(1) {
            client
                .read_into(Epoch::Plaintext, fragment, &mut client_wire)
                .unwrap();
        }
    });
    let client_server_flight = AllocationProbe::measured(|| {
        for fragment in server_flight.chunks(1) {
            client
                .read_into(Epoch::Handshake, fragment, &mut client_wire)
                .unwrap();
        }
    });
    assert_eq!(client_wire.peer_extension, b"server tp");
    assert_eq!(client.selected_alpn(), Some(b"h3".as_slice()));
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = AllocationProbe::measured(|| {
        for fragment in client_flight.chunks(1) {
            server
                .read_into(Epoch::Handshake, fragment, &mut server_wire)
                .unwrap();
        }
    });
    assert_zero_allocations([
        client_start,
        server_read,
        client_server_hello,
        client_server_flight,
        server_finish,
    ]);

    let ticket_record = server_wire.application.clone();
    client_wire.clear();
    assert_eq!(
        AllocationProbe::measured(|| {
            client
                .read_into(Epoch::Application, &ticket_record, &mut client_wire)
                .unwrap()
        }),
        1,
        "retaining an opaque peer ticket performs exactly one allocation",
    );
    assert_eq!(client_wire.ticket_suite, Some(CipherSuite::Aes128GcmSha256),);
    let resumption = client_wire.resumption.take().unwrap();
    drop(server);

    let resumed_server = Server::with_transport_workspace(
        Connection {
            transport_params: b"server tp".to_vec(),
        },
        Mode::Quic,
        || 0,
        workspace(),
    )
    .unwrap();
    let mut resumed_server = shard.bind(resumed_server).into_result().unwrap();
    let mut resumed_client = Client::resume(resumption, true, || 0).unwrap();
    client_wire.clear();
    server_wire.clear();
    let client_start =
        AllocationProbe::measured(|| resumed_client.start_into(&mut client_wire).unwrap());
    assert_eq!(client_wire.zero_rtt_max, Some(u32::MAX));
    assert!(client_wire.zero_rtt_alpn_h3);
    let client_hello = client_wire.plaintext.clone();
    let server_read = AllocationProbe::measured(|| {
        resumed_server
            .read_into(Epoch::Plaintext, &client_hello, &mut server_wire)
            .unwrap()
    });
    assert_eq!(server_wire.zero_rtt_max, Some(u32::MAX));
    assert!(server_wire.zero_rtt_alpn_h3);
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = AllocationProbe::measured(|| {
        resumed_client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = AllocationProbe::measured(|| {
        resumed_client
            .read_into(Epoch::Handshake, &server_flight, &mut client_wire)
            .unwrap()
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = AllocationProbe::measured(|| {
        resumed_server
            .read_into(Epoch::Handshake, &client_flight, &mut server_wire)
            .unwrap()
    });
    assert_zero_allocations([
        client_start,
        server_read,
        client_server_hello,
        client_server_flight,
        server_finish,
    ]);
}

#[test]
fn server_admission_rejects_undersized_storage_without_allocating() {
    let signing_key = SigningKey::from_seed(&[10; 32]).unwrap();
    let mut shard = Shard::new(config::Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let workspace = Scratch::new(0, 16 * 1024, 0);
    let capacities = workspace.capacities();
    let server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace,
    )
    .unwrap();
    let mut rejected = false;
    let mut recovered = None;
    let allocations = AllocationProbe::measured(|| {
        let Err(rejection) = shard.bind(server).into_result() else {
            panic!("undersized server was admitted");
        };
        rejected = rejection.error() == &Error::BadConfig;
        recovered = Some(rejection.into_parts().1);
    });
    assert_eq!(allocations, 0);
    assert!(rejected);
    assert_eq!(recovered.unwrap().into_workspace().capacities(), capacities);

    let server_signing_key = SigningKey::from_seed(&[12; 32]).unwrap();
    let mut shard = Shard::with_client_auth(
        config::Config {
            source: CertSource::RawPublicKey {
                signing_key: server_signing_key,
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        PinnedSpki(Vec::new()),
    )
    .unwrap();
    let workspace = Scratch::new(16 * 1024, 16 * 1024, 0);
    let capacities = workspace.capacities();
    let server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace,
    )
    .unwrap();
    let mut rejected = false;
    let mut recovered = None;
    let allocations = AllocationProbe::measured(|| {
        let Err(rejection) = shard.bind(server).into_result() else {
            panic!("undersized server was admitted");
        };
        rejected = rejection.error() == &Error::BadConfig;
        recovered = Some(rejection.into_parts().1);
    });
    assert_eq!(allocations, 0);
    assert!(rejected);
    assert_eq!(recovered.unwrap().into_workspace().capacities(), capacities);
}

#[test]
fn hello_retry_request_has_no_allocations() {
    let signing_key = SigningKey::from_seed(&[11; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut shard = Shard::new(config::Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    )
    .unwrap();
    let mut server = shard.bind(server).into_result().unwrap();
    let mut client = Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
    client
        .set_kex_group(shin::crypto::kx::KexGroup::Secp256r1)
        .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();
    client.start_into(&mut client_wire).unwrap();

    let mut reader = codec::Reader::new(&client_wire.plaintext);
    let Frame::ClientHello(mut hello) = MessageRef::decode_from(&mut reader).unwrap().into_owned()
    else {
        panic!("client did not emit ClientHello");
    };
    let key_share = hello
        .extensions
        .iter_mut()
        .find(|extension| extension.ty == Type::KEY_SHARE)
        .unwrap();
    key_share.data.clear();
    key_share.data.extend_from_slice(&0u16.to_be_bytes());
    let mut empty_key_share = Vec::new();
    Frame::ClientHello(hello)
        .encode(&mut empty_key_share)
        .unwrap();

    assert_eq!(
        AllocationProbe::measured(|| {
            server
                .read_into(Epoch::Plaintext, &empty_key_share, &mut server_wire)
                .unwrap()
        }),
        0
    );
    let retry = server_wire.plaintext.clone();
    client_wire.clear();
    assert_eq!(
        AllocationProbe::measured(|| {
            client
                .read_into(Epoch::Plaintext, &retry, &mut client_wire)
                .unwrap()
        }),
        0
    );
}
