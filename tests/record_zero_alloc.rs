use std::convert::Infallible;

use o3::buffer;
use shin::client::Client;
use shin::client::config::Config;
use shin::connection::{DriveError, Epoch, Event, EventContext, EventSink};
use shin::crypto::sig;
use shin::server;
use shin::wire::handshake::KeyUpdateRequest;
use shin::wire::record::{CipherSuite, ContentType, Opener, Sealer};

mod support;

use support::AllocationProbe;

const TEST_SECRET: [u8; 32] = [
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
];

#[derive(Default)]
struct HandshakeEvents {
    sends: Vec<(Epoch, Vec<u8>)>,
    done: bool,
}

impl HandshakeEvents {
    fn send(&self, epoch: Epoch) -> Vec<u8> {
        self.sends
            .iter()
            .find_map(|(event_epoch, data)| (*event_epoch == epoch).then(|| data.clone()))
            .expect("expected handshake send")
    }
}

impl EventSink for HandshakeEvents {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => self.sends.push((epoch, data.to_vec())),
            Event::Done => self.done = true,
            _ => {}
        }
        Ok(())
    }
}

fn collect_handshake_events(
    run: impl FnOnce(&mut HandshakeEvents) -> Result<(), DriveError<Infallible>>,
) -> HandshakeEvents {
    let mut events = HandshakeEvents::default();
    run(&mut events).expect("handshake drive failed");
    events
}

struct KeyUpdateSink {
    sends: usize,
    updates: usize,
    suite: Option<CipherSuite>,
    expected_request: u8,
}

impl EventSink for KeyUpdateSink {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => {
                assert_eq!(epoch, Epoch::Application);
                assert_eq!(data, [24, 0, 0, 1, self.expected_request]);
                self.sends += 1;
                self.suite = context.cipher_suite();
            }
            Event::KeyUpdate { secret, .. } => {
                // Record protection consumes the synchronous secret borrow;
                // the secret itself never escapes the callback.
                let _ = Sealer::with_suite(
                    secret.as_slice(),
                    context.cipher_suite().expect("negotiated suite"),
                )
                .unwrap();
                self.updates += 1;
                self.suite = context.cipher_suite();
            }
            event => panic!("unexpected event: {event:?}"),
        }
        Ok(())
    }
}

#[test]
fn caller_owned_record_and_event_hot_paths_allocate_nothing() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET).unwrap();
    let mut warmup = sealer
        .seal(ContentType::ApplicationData, b"warm up crypto state")
        .unwrap();
    let mut measured = sealer
        .seal(ContentType::ApplicationData, b"caller-owned output")
        .unwrap();
    let mut opener = Opener::from_secret(&TEST_SECRET).unwrap();
    let mut parts_sealer = Sealer::from_secret(&TEST_SECRET).unwrap();
    let pool = buffer::Pool::try_new(1, 128).unwrap();
    let mut sealed_output = pool.try_acquire_buffer().unwrap();
    let parts = [&b"caller-"[..], &b"owned "[..], &b"input"[..]];

    opener.open(&mut warmup).unwrap().unwrap();

    AllocationProbe::reset();
    let (content_type, range, _) = opener.open(&mut measured).unwrap().unwrap();
    let allocations = AllocationProbe::count();

    assert_eq!(content_type, ContentType::ApplicationData);
    assert_eq!(&measured[range], b"caller-owned output");
    assert_eq!(allocations, 0, "opening a caller-owned record allocated");

    AllocationProbe::reset();
    {
        let mut writer = sealed_output.spare_writer();
        parts_sealer
            .seal_parts_to(
                ContentType::ApplicationData,
                b"caller-owned input".len(),
                parts,
                &mut writer,
            )
            .unwrap();
    }
    let allocations = AllocationProbe::count();

    assert!(!sealed_output.is_empty());
    assert_eq!(
        allocations, 0,
        "sealing into caller-owned storage allocated"
    );

    let server_key = sig::SigningKey::from_seed(&[0x51; 32]).unwrap();
    let server_pubkey = *server_key.pubkey().unwrap();
    let mut shard = server::Shard::new(server::config::Config {
        source: server::config::CertSource::RawPublicKey {
            signing_key: server_key,
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let server = server::Server::new(
        server::config::Connection {
            transport_params: Vec::new(),
        },
        || 0,
    )
    .unwrap();
    let mut server = shard.bind(server).unwrap();
    let mut client = Client::new(
        Config {
            verifier: shin::client::config::Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
    let client_start = collect_handshake_events(|events| client.start_into(events));
    let client_hello = client_start.send(Epoch::Plaintext);
    let server_start = collect_handshake_events(|events| {
        server.read_into(Epoch::Plaintext, &client_hello, events)
    });
    let server_hello = server_start.send(Epoch::Plaintext);
    let server_flight = server_start.send(Epoch::Handshake);
    collect_handshake_events(|events| client.read_into(Epoch::Plaintext, &server_hello, events));
    let client_finish = collect_handshake_events(|events| {
        client.read_into(Epoch::Handshake, &server_flight, events)
    });
    let client_flight = client_finish.send(Epoch::Handshake);
    let server_finish = collect_handshake_events(|events| {
        server.read_into(Epoch::Handshake, &client_flight, events)
    });
    assert!(server_finish.done);

    let key_update = [24, 0, 0, 1, 0];
    let mut sink = KeyUpdateSink {
        sends: 0,
        updates: 0,
        suite: None,
        expected_request: 0,
    };
    AllocationProbe::reset();
    client
        .key_updates()
        .send_into(KeyUpdateRequest::NotRequested, &mut sink)
        .unwrap();
    let allocations = AllocationProbe::count();

    assert_eq!(sink.sends, 1);
    assert_eq!(sink.updates, 1);
    assert_eq!(sink.suite, Some(CipherSuite::Aes128GcmSha256));
    assert_eq!(allocations, 0);

    sink.expected_request = 1;
    AllocationProbe::reset();
    client
        .key_updates()
        .send_into(KeyUpdateRequest::Requested, &mut sink)
        .unwrap();
    let allocations = AllocationProbe::count();

    assert_eq!(sink.sends, 2);
    assert_eq!(sink.updates, 2);
    assert_eq!(allocations, 0);

    AllocationProbe::reset();
    client
        .read_into(Epoch::Application, &key_update, &mut sink)
        .unwrap();
    let allocations = AllocationProbe::count();

    assert_eq!(sink.updates, 3);
    assert_eq!(sink.suite, Some(CipherSuite::Aes128GcmSha256));
    assert_eq!(allocations, 0);

    client
        .read_into(Epoch::Application, &key_update[..2], &mut sink)
        .unwrap();
    client
        .read_into(Epoch::Application, &key_update[2..], &mut sink)
        .unwrap();
    AllocationProbe::reset();
    client
        .read_into(Epoch::Application, &key_update[..3], &mut sink)
        .unwrap();
    client
        .read_into(Epoch::Application, &key_update[3..], &mut sink)
        .unwrap();
    let allocations = AllocationProbe::count();

    assert_eq!(sink.updates, 5);
    assert_eq!(allocations, 0);
}
