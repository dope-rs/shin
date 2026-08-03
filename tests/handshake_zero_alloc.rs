use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::convert::Infallible;

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
use shin::client::Client;
use shin::client::config::{
    ClientCertSource, Config as ClientConfig, OwnedTrustAnchor, Resumption, Verifier,
};
use shin::connection::{DriveError, Epoch, Error, Event, EventContext, EventSink, WorkspaceRegion};
use shin::crypto::kx::KexGroup;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::TicketKeys;
use shin::identity::asn1::{Reader, Tag};
use shin::identity::cert::Cert;
use shin::identity::spki::SubjectPublicKey;
use shin::server::{
    Server, Shard, config::CertSource, config::ClientAuth, config::ClientCertVerifier,
    config::ClientIdentity, config::Config as ServerConfig, config::ConnectionConfig,
};
use shin::wire::codec::Reader as CodecReader;
use shin::wire::extension::ExtensionType;
use shin::wire::handshake::MAX_HANDSHAKE_SIZE;
use shin::wire::handshake::frame::Frame;
use shin::wire::handshake::workspace::HandshakeWorkspace;

struct CountingAllocator;

struct PinnedSpki(Vec<u8>);

impl ClientCertVerifier for PinnedSpki {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        identity.spki_der == self.0
    }
}

thread_local! {
    static COUNT_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation() {
    let _ = COUNT_ALLOCATIONS.try_with(|active| {
        if active.get() {
            let _ = ALLOCATIONS.try_with(|count| {
                count.set(count.get() + 1);
            });
        }
    });
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, new_size) }
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
            Event::ResumptionSecret { psk } => self.resumption_psk = Some(psk),
            _ => {}
        }
        Ok(())
    }
}

fn measured(run: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|count| count.set(0));
    COUNT_ALLOCATIONS.with(|active| active.set(true));
    run();
    COUNT_ALLOCATIONS.with(|active| active.set(false));
    ALLOCATIONS.with(Cell::get)
}

fn workspace() -> HandshakeWorkspace {
    HandshakeWorkspace::new(16 * 1024, 16 * 1024, 16 * 1024)
}

fn assert_zero_allocations(counts: [usize; 5]) {
    assert_eq!(counts, [0; 5]);
}

#[test]
fn role_defaults_reserve_only_reachable_workspace_regions() {
    assert_eq!(
        HandshakeWorkspace::for_client().capacities(),
        (MAX_HANDSHAKE_SIZE, MAX_HANDSHAKE_SIZE, 0)
    );
    assert_eq!(
        HandshakeWorkspace::for_server().capacities(),
        (MAX_HANDSHAKE_SIZE, MAX_HANDSHAKE_SIZE, MAX_HANDSHAKE_SIZE)
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
        shin::identity::time::UnixTime::from_time_value(&parsed.validity.not_before).unwrap();
    let not_after =
        shin::identity::time::UnixTime::from_time_value(&parsed.validity.not_after).unwrap();
    (cert_der, signing_key, (not_before.0 + not_after.0) / 2)
}

#[test]
fn rpk_handshake_has_no_allocations_after_construction() {
    let signing_key = SigningKey::from_seed(&[7; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let client_signing_key = SigningKey::from_seed(&[6; 32]).unwrap();
    let client_spki = SubjectPublicKey::Ed25519(*client_signing_key.pubkey().unwrap())
        .encode()
        .unwrap();
    let mut shard = Shard::with_client_auth(
        ServerConfig {
            source: CertSource::RawPublicKey { signing_key },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        PinnedSpki(client_spki),
    );
    let mut server = Server::with_workspace(
        ConnectionConfig {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    );
    let mut client = Client::with_workspace(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
        workspace(),
    )
    .unwrap();
    client
        .set_client_cert(ClientCertSource::RawPublicKey {
            signing_key: client_signing_key,
        })
        .unwrap();
    client.set_kex_group(KexGroup::X25519Mlkem768).unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = measured(|| {
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
    let client_server_hello = measured(|| {
        client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = measured(|| {
        client
            .read_into(Epoch::Handshake, &server_flight, &mut client_wire)
            .unwrap()
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = measured(|| {
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
    let client_spki = Cert::parse(&client_cert_der).unwrap().spki.raw_der.to_vec();
    let cert = Cert::parse(&cert_der).unwrap();
    let anchor = OwnedTrustAnchor {
        subject_der: cert.subject_der.to_vec(),
        spki_der: cert.spki.raw_der.to_vec(),
    };
    let mut shard = Shard::with_client_auth(
        ServerConfig {
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
        ConnectionConfig {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    );
    let mut client = Client::with_workspace(
        ClientConfig {
            verifier: Verifier::X509 {
                anchors: vec![anchor],
                hostname: b"host.local".to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        move || now * 1000,
        workspace(),
    )
    .unwrap();
    client
        .set_client_cert(ClientCertSource::X509 {
            chain_der: vec![client_cert_der],
            signing_key: client_signing_key,
        })
        .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = measured(|| {
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
    let client_server_hello = measured(|| {
        client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = measured(|| {
        client
            .read_into(Epoch::Handshake, &server_flight, &mut client_wire)
            .unwrap()
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = measured(|| {
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
    let mut shard = Shard::new(ServerConfig {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: vec![b"h3".to_vec()],
        ticket_keys: Some(TicketKeys::single([9; 32])),
    });
    let mut server = Server::with_workspace(
        ConnectionConfig {
            transport_params: b"server tp".to_vec(),
        },
        || 0,
        workspace(),
    );
    let mut client = Client::with_workspace(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: b"client tp".to_vec(),
            alpn_protocols: vec![b"h3".to_vec()],
            resumption: None,
            enable_early_data: false,
        },
        || 0,
        workspace(),
    )
    .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();

    let client_start = measured(|| client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = measured(|| {
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
    let client_server_hello = measured(|| {
        for fragment in server_hello.chunks(1) {
            client
                .read_into(Epoch::Plaintext, fragment, &mut client_wire)
                .unwrap();
        }
    });
    let client_server_flight = measured(|| {
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
    let server_finish = measured(|| {
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
        measured(|| {
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

    let mut resumed_server = Server::with_workspace(
        ConnectionConfig {
            transport_params: b"server tp".to_vec(),
        },
        || 0,
        workspace(),
    );
    let mut resumed_client = Client::with_workspace(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: b"client tp".to_vec(),
            alpn_protocols: vec![b"h3".to_vec()],
            resumption: Some(resumption),
            enable_early_data: true,
        },
        || 0,
        workspace(),
    )
    .unwrap();
    client_wire.clear();
    server_wire.clear();
    let client_start = measured(|| resumed_client.start_into(&mut client_wire).unwrap());
    let client_hello = client_wire.plaintext.clone();
    let server_read = measured(|| {
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
    let client_server_hello = measured(|| {
        resumed_client
            .read_into(Epoch::Plaintext, &server_hello, &mut client_wire)
            .unwrap()
    });
    let client_server_flight = measured(|| {
        resumed_client
            .read_into(Epoch::Handshake, &server_flight, &mut client_wire)
            .unwrap()
    });
    let client_flight = client_wire.handshake.clone();
    server_wire.clear();
    let server_finish = measured(|| {
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
    let mut client = Client::with_workspace(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
        HandshakeWorkspace::new(0, 0, 0),
    )
    .unwrap();
    let mut wire = Wire::reserved();
    let mut result = None;
    let allocations = measured(|| result = Some(client.start_into(&mut wire)));
    assert_eq!(allocations, 0);
    assert_eq!(
        result.unwrap(),
        Err(DriveError::Protocol(Error::WorkspaceExhausted(
            WorkspaceRegion::OutboundFlight
        )))
    );

    let mut shard = Shard::new(ServerConfig {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
    let mut server = Server::with_workspace(
        ConnectionConfig {
            transport_params: Vec::new(),
        },
        || 0,
        HandshakeWorkspace::new(0, 16 * 1024, 0),
    );
    let mut result = None;
    let allocations =
        measured(|| result = Some(server.read_into(Epoch::Plaintext, &[1], &mut shard, &mut wire)));
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
        ServerConfig {
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
        ConnectionConfig {
            transport_params: Vec::new(),
        },
        || 0,
        HandshakeWorkspace::new(16 * 1024, 16 * 1024, 0),
    );
    let mut client = Client::with_workspace(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
        workspace(),
    )
    .unwrap();
    client
        .set_client_cert(ClientCertSource::RawPublicKey {
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
    let allocations = measured(|| {
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
    let mut shard = Shard::new(ServerConfig {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
    let mut server = Server::with_workspace(
        ConnectionConfig {
            transport_params: Vec::new(),
        },
        || 0,
        workspace(),
    );
    let mut client = Client::with_workspace(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
        workspace(),
    )
    .unwrap();
    let mut client_wire = Wire::reserved();
    let mut server_wire = Wire::reserved();
    client.start_into(&mut client_wire).unwrap();

    let mut reader = CodecReader::new(&client_wire.plaintext);
    let Frame::ClientHello(mut hello) = Frame::decode(&mut reader).unwrap() else {
        panic!("client did not emit ClientHello");
    };
    hello
        .extensions
        .retain(|extension| extension.ty != ExtensionType::KEY_SHARE);
    let mut without_key_share = Vec::new();
    Frame::ClientHello(hello)
        .encode(&mut without_key_share)
        .unwrap();

    assert_eq!(
        measured(|| {
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
        measured(|| {
            client
                .read_into(Epoch::Plaintext, &retry, &mut client_wire)
                .unwrap()
        }),
        0
    );
}
