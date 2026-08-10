use std::convert::Infallible;

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
use shin::client::config::{Config, Identity, OwnedTrustAnchor, Resumption, Verifier};
use shin::client::{Client, Hybrid};
use shin::connection::{DriveError, Epoch, Error, Event, EventContext, EventSink, WorkspaceRegion};
use shin::crypto::kx::HybridWorkspace;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::Keys;
use shin::identity::asn1::{Reader, Tag};
use shin::identity::cert::Cert;
use shin::identity::spki::SubjectPublicKey;
use shin::server::{
    Server, Shard, config, config::CertSource, config::ClientAuth, config::ClientCertVerifier,
    config::ClientIdentity, config::Connection,
};
use shin::transport::Mode;
use shin::wire::codec;
use shin::wire::extension::Type;
use shin::wire::handshake::MAX_SIZE;
use shin::wire::handshake::frame::Frame;
use shin::wire::handshake::workspace::Scratch;

mod raw;

struct PinnedSpki(Vec<u8>);

impl ClientCertVerifier for PinnedSpki {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        identity.spki_der == self.0
    }
}

#[derive(Default)]
struct Wire {
    plaintext: Vec<u8>,
    handshake: Vec<u8>,
    application: Vec<u8>,
    peer_extension: Vec<u8>,
    ticket_nonce: Vec<u8>,
    ticket: Vec<u8>,
    ticket_age_add: u32,
    resumption_psk: Option<[u8; 32]>,
}

impl Wire {
    fn reserved() -> Self {
        Self {
            plaintext: Vec::with_capacity(16 * 1024),
            handshake: Vec::with_capacity(16 * 1024),
            application: Vec::with_capacity(16 * 1024),
            peer_extension: Vec::with_capacity(16 * 1024),
            ticket_nonce: Vec::with_capacity(255),
            ticket: Vec::with_capacity(512),
            ticket_age_add: 0,
            resumption_psk: None,
        }
    }

    fn clear(&mut self) {
        self.plaintext.clear();
        self.handshake.clear();
        self.application.clear();
        self.peer_extension.clear();
        self.ticket_nonce.clear();
        self.ticket.clear();
        self.ticket_age_add = 0;
        self.resumption_psk = None;
    }
}

impl EventSink for Wire {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
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
            Event::NewSessionTicket {
                ticket_age_add,
                ticket_nonce,
                ticket,
                ..
            } => {
                self.ticket_age_add = ticket_age_add;
                self.ticket_nonce.clear();
                self.ticket_nonce.extend_from_slice(ticket_nonce);
                self.ticket.clear();
                self.ticket.extend_from_slice(ticket);
            }
            Event::ResumptionSecret { psk } => self.resumption_psk = Some(*psk.as_array()),
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

#[test]
fn role_defaults_reserve_only_reachable_workspace_regions() {
    assert_eq!(Scratch::for_client().capacities(), (MAX_SIZE, MAX_SIZE, 0));
    assert_eq!(
        Scratch::for_server().capacities(),
        (MAX_SIZE, MAX_SIZE, MAX_SIZE)
    );
}

fn x509_identity() -> (Vec<u8>, SigningKey, u64) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let pkcs8 = key.serialize_der();
    let mut reader = Reader::new(&pkcs8);
    let sequence = reader.read_tagged(Tag::SEQUENCE).unwrap();
    let mut sequence = Reader::new(sequence);
    sequence.read_tagged(Tag::INTEGER).unwrap();
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
    let not_before =
        shin::identity::UnixTime::from_time_value(&parsed.tbs.validity.not_before).unwrap();
    let not_after =
        shin::identity::UnixTime::from_time_value(&parsed.tbs.validity.not_after).unwrap();
    (cert_der, signing_key, (not_before.0 + not_after.0) / 2)
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
    );
    let mut server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    );
    let mut hybrid_workspace = HybridWorkspace::new();
    let client = Client::with_transport_workspace(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        Mode::Tls,
        || 0,
        workspace(),
    )
    .unwrap();
    let mut client = Hybrid::from_client(client, &mut hybrid_workspace).unwrap();
    client
        .set_identity(Identity::RawPublicKey {
            signing_key: client_signing_key,
        })
        .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = raw::measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = raw::measured(|| {
        server
            .read_into(
                Epoch::Plaintext,
                &client_hello,
                &mut shard,
                &mut server_wire,
            )
            .unwrap()
    });
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = raw::measured(|| {
        client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = raw::measured(|| {
        client
            .read_into(Epoch::Handshake, &server_flight, &mut client_wire)
            .unwrap()
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = raw::measured(|| {
        server
            .read_into(
                Epoch::Handshake,
                &client_flight,
                &mut shard,
                &mut server_wire,
            )
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
    );
    let mut server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    );
    let mut client = Client::with_transport_workspace(
        Config {
            verifier: Verifier::X509 {
                anchors: vec![anchor],
                hostname: b"host.local".to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        Mode::Tls,
        move || now * 1000,
        workspace(),
    )
    .unwrap();
    client
        .set_identity(Identity::X509 {
            chain_der: vec![client_cert_der],
            signing_key: client_signing_key,
        })
        .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = raw::measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = raw::measured(|| {
        server
            .read_into(
                Epoch::Plaintext,
                &client_hello,
                &mut shard,
                &mut server_wire,
            )
            .unwrap()
    });
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = raw::measured(|| {
        client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = raw::measured(|| {
        client
            .read_into(Epoch::Handshake, &server_flight, &mut client_wire)
            .unwrap()
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = raw::measured(|| {
        server
            .read_into(
                Epoch::Handshake,
                &client_flight,
                &mut shard,
                &mut server_wire,
            )
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
fn fragmented_alpn_transport_params_and_resumption_have_no_allocations() {
    let signing_key = SigningKey::from_seed(&[8; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut shard = Shard::new(config::Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: vec![b"h3".to_vec()],
        ticket_keys: Some(Keys::single([9; 32])),
    });
    let mut server = Server::with_transport_workspace(
        Connection {
            transport_params: b"server tp".to_vec(),
        },
        Mode::Quic,
        || 0,
        workspace(),
    );
    let mut client = Client::with_transport_workspace(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: b"client tp".to_vec(),
            alpn_protocols: vec![b"h3".to_vec()],
            resumption: None,
            enable_early_data: false,
        },
        Mode::Quic,
        || 0,
        workspace(),
    )
    .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = raw::measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = raw::measured(|| {
        for fragment in client_hello.chunks(1) {
            server
                .read_into(Epoch::Plaintext, fragment, &mut shard, &mut server_wire)
                .unwrap();
        }
    });
    assert_eq!(server_wire.peer_extension, b"client tp");
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = raw::measured(|| {
        for fragment in server_hello.chunks(1) {
            client
                .read_into(Epoch::Plaintext, fragment, &mut client_wire)
                .unwrap();
        }
    });
    let client_server_flight = raw::measured(|| {
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
    let server_finish = raw::measured(|| {
        for fragment in client_flight.chunks(1) {
            server
                .read_into(Epoch::Handshake, fragment, &mut shard, &mut server_wire)
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
        raw::measured(|| {
            client
                .read_into(Epoch::Application, &ticket_record, &mut client_wire)
                .unwrap()
        }),
        0
    );
    let resumption = Resumption::new(
        client_wire.resumption_psk.unwrap(),
        client_wire.ticket.clone(),
        client_wire.ticket_age_add,
        0,
    );

    let mut resumed_server = Server::with_transport_workspace(
        Connection {
            transport_params: b"server tp".to_vec(),
        },
        Mode::Quic,
        || 0,
        workspace(),
    );
    let mut resumed_client = Client::with_transport_workspace(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: b"client tp".to_vec(),
            alpn_protocols: vec![b"h3".to_vec()],
            resumption: Some(resumption),
            enable_early_data: true,
        },
        Mode::Quic,
        || 0,
        workspace(),
    )
    .unwrap();
    client_wire.clear();
    server_wire.clear();
    let client_start = raw::measured(|| resumed_client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = raw::measured(|| {
        resumed_server
            .read_into(
                Epoch::Plaintext,
                &client_hello,
                &mut shard,
                &mut server_wire,
            )
            .unwrap()
    });
    let server_hello = server_wire.plaintext.clone();
    let server_flight = server_wire.handshake.clone();
    client_wire.clear();
    let client_server_hello = raw::measured(|| {
        resumed_client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = raw::measured(|| {
        resumed_client
            .read_into(Epoch::Handshake, &server_flight, &mut client_wire)
            .unwrap()
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = raw::measured(|| {
        resumed_server
            .read_into(
                Epoch::Handshake,
                &client_flight,
                &mut shard,
                &mut server_wire,
            )
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
fn workspace_exhaustion_is_typed_and_never_reallocates() {
    let signing_key = SigningKey::from_seed(&[10; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut client = Client::with_transport_workspace(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        Mode::Tls,
        || 0,
        Scratch::new(0, 0, 0),
    )
    .unwrap();
    let mut wire = Wire::reserved();
    let mut result = None;
    let allocations = raw::measured(|| result = Some(client.start_into(&mut wire)));
    assert_eq!(allocations, 0);
    assert_eq!(
        result.unwrap(),
        Err(DriveError::Protocol(Error::WorkspaceExhausted(
            WorkspaceRegion::OutboundFlight
        )))
    );

    let mut shard = Shard::new(config::Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
    let mut server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        Scratch::new(0, 16 * 1024, 0),
    );
    let mut result = None;
    let allocations = raw::measured(|| {
        result = Some(server.read_into(Epoch::Plaintext, &[1], &mut shard, &mut wire))
    });
    assert_eq!(allocations, 0);
    assert_eq!(
        result.unwrap(),
        Err(DriveError::Protocol(Error::WorkspaceExhausted(
            WorkspaceRegion::FragmentedMessage
        )))
    );

    let server_signing_key = SigningKey::from_seed(&[12; 32]).unwrap();
    let server_pubkey = *server_signing_key.pubkey().unwrap();
    let client_signing_key = SigningKey::from_seed(&[13; 32]).unwrap();
    let client_spki = SubjectPublicKey::Ed25519(*client_signing_key.pubkey().unwrap())
        .encode()
        .unwrap();
    let mut shard = Shard::with_client_auth(
        config::Config {
            source: CertSource::RawPublicKey {
                signing_key: server_signing_key,
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        PinnedSpki(client_spki),
    );
    let mut server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        Scratch::new(16 * 1024, 16 * 1024, 0),
    );
    let mut client = Client::with_transport_workspace(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        Mode::Tls,
        || 0,
        workspace(),
    )
    .unwrap();
    client
        .set_identity(Identity::RawPublicKey {
            signing_key: client_signing_key,
        })
        .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();
    client.start_into(&mut client_wire).unwrap();
    server
        .read_into(
            Epoch::Plaintext,
            &client_wire.plaintext,
            &mut shard,
            &mut server_wire,
        )
        .unwrap();
    client_wire.clear();
    client
        .read_into(Epoch::Plaintext, &server_wire.plaintext, &mut client_wire)
        .unwrap();
    client
        .read_into(Epoch::Handshake, &server_wire.handshake, &mut client_wire)
        .unwrap();
    let client_flight = client_wire.handshake.clone();
    let mut result = None;
    let allocations = raw::measured(|| {
        result = Some(server.read_into(
            Epoch::Handshake,
            &client_flight,
            &mut shard,
            &mut server_wire,
        ));
    });
    assert_eq!(allocations, 0);
    assert_eq!(
        result.unwrap(),
        Err(DriveError::Protocol(Error::WorkspaceExhausted(
            WorkspaceRegion::PeerIdentity
        )))
    );
}

#[test]
fn hello_retry_request_has_no_allocations() {
    let signing_key = SigningKey::from_seed(&[11; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut shard = Shard::new(config::Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
    let mut server = Server::with_workspace(
        Connection {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    );
    let mut client = Client::with_transport_workspace(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        Mode::Tls,
        || 0,
        workspace(),
    )
    .unwrap();
    client
        .set_kex_group(shin::crypto::kx::KexGroup::Secp256r1)
        .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();
    client.start_into(&mut client_wire).unwrap();

    let mut reader = codec::Reader::new(&client_wire.plaintext);
    let Frame::ClientHello(mut hello) = Frame::decode(&mut reader).unwrap() else {
        panic!("client did not emit ClientHello");
    };
    hello
        .extensions
        .retain(|extension| extension.ty != Type::KEY_SHARE);
    let mut without_key_share = Vec::new();
    Frame::ClientHello(hello)
        .encode(&mut without_key_share)
        .unwrap();

    assert_eq!(
        raw::measured(|| {
            server
                .read_into(
                    Epoch::Plaintext,
                    &without_key_share,
                    &mut shard,
                    &mut server_wire,
                )
                .unwrap()
        }),
        0
    );
    let retry = server_wire.plaintext.clone();
    client_wire.clear();
    assert_eq!(
        raw::measured(|| {
            client
                .read_into(Epoch::Plaintext, &retry, &mut client_wire)
                .unwrap()
        }),
        0
    );
}
