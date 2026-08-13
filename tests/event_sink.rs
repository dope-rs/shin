use core::convert::Infallible;

use shin::client::Client;
use shin::client::config::{Config, NegotiatedAlpn, Restore, Verifier};
use shin::connection::{DriveError, Epoch, Error, Event, EventContext, EventSink, OutboundFlight};
use shin::crypto::sig::SigningKey;
use shin::server;
use shin::server::config;
use shin::server::config::CertSource;
use shin::transport::Mode;
use shin::wire::handshake::storage::Scratch;
use shin::wire::record::{CipherSuite, MAX_PLAINTEXT_BODY};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rejected;

struct RejectFirst {
    seen: usize,
}

impl EventSink for RejectFirst {
    type Error = Rejected;

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        self.seen += 1;
        Err(Rejected)
    }
}

struct RejectNth {
    seen: usize,
    reject_at: usize,
}

impl EventSink for RejectNth {
    type Error = Rejected;

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        self.seen += 1;
        if self.seen == self.reject_at {
            Err(Rejected)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct CountEvents(usize);

impl EventSink for CountEvents {
    type Error = Infallible;

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        self.0 += 1;
        Ok(())
    }
}

struct Ignore;

impl EventSink for Ignore {
    type Error = Infallible;

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct DirectSend {
    bytes: Vec<u8>,
    borrowed_sends: usize,
}

impl DirectSend {
    fn new() -> Self {
        let mut bytes = Vec::with_capacity(MAX_PLAINTEXT_BODY);
        bytes.push(0xa5);
        Self {
            bytes,
            borrowed_sends: 0,
        }
    }
}

impl EventSink for DirectSend {
    type Error = Infallible;

    fn begin_send(
        &mut self,
        _epoch: Epoch,
        maximum: usize,
        _context: EventContext,
    ) -> Result<Option<OutboundFlight<'_>>, Self::Error> {
        Ok(Some(
            OutboundFlight::try_append(&mut self.bytes, maximum).unwrap(),
        ))
    }

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        if matches!(event, Event::Send { .. }) {
            self.borrowed_sends += 1;
        }
        Ok(())
    }
}

struct ShortDirectSend(Vec<u8>);

impl EventSink for ShortDirectSend {
    type Error = Infallible;

    fn begin_send(
        &mut self,
        _epoch: Epoch,
        _maximum: usize,
        _context: EventContext,
    ) -> Result<Option<OutboundFlight<'_>>, Self::Error> {
        Ok(Some(OutboundFlight::try_append(&mut self.0, 1).unwrap()))
    }

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Default)]
struct FirstPlaintextSend(Vec<u8>);

impl EventSink for FirstPlaintextSend {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
        if let Event::Send {
            epoch: Epoch::Plaintext,
            data,
        } = event
            && self.0.is_empty()
        {
            self.0.extend_from_slice(data);
        }
        Ok(())
    }
}

#[derive(Default)]
struct ZeroRttSuite(Option<Option<CipherSuite>>);

impl EventSink for ZeroRttSuite {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        if matches!(event, Event::ZeroRttKeysReady { .. }) {
            self.0 = Some(context.cipher_suite());
        }
        Ok(())
    }
}

fn early_client(suite: CipherSuite) -> Client<fn() -> u64> {
    let restore = Restore::try_new([7; 32], vec![9], 0, 0, 7_200)
        .unwrap()
        .try_with_early_data(16_384, suite, Mode::Tls, NegotiatedAlpn::Absent)
        .unwrap();
    let prepared = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: [0u8; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: true,
    }
    .try_into_template()
    .unwrap()
    .restore(restore)
    .unwrap();
    let workspace = prepared.workspace_layout(None).allocate();
    prepared
        .try_into_client_with_workspace(None, (|| 0) as fn() -> u64, workspace)
        .unwrap()
}

#[test]
fn zero_rtt_context_uses_ticket_authorized_suite() {
    let mut client = early_client(CipherSuite::ChaCha20Poly1305Sha256);
    let mut sink = ZeroRttSuite::default();

    client.start_into(&mut sink).unwrap();

    assert_eq!(sink.0, Some(Some(CipherSuite::ChaCha20Poly1305Sha256)),);
}

#[test]
fn zero_rtt_keys_are_not_emitted_without_their_authorized_suite() {
    let mut client = early_client(CipherSuite::ChaCha20Poly1305Sha256);
    client
        .set_cipher_suites(&[CipherSuite::Aes128GcmSha256])
        .unwrap();
    let mut sink = ZeroRttSuite::default();

    client.start_into(&mut sink).unwrap();

    assert_eq!(sink.0, None);
}

fn client() -> Client<fn() -> u64> {
    Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [0u8; 32],
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            enable_early_data: false,
        },
        (|| 0) as fn() -> u64,
    )
    .unwrap()
}

#[test]
fn direct_send_encodes_into_the_consumers_owner_without_a_borrowed_event() {
    let mut fallback_client = client();
    let mut fallback = FirstPlaintextSend::default();
    fallback_client.start_into(&mut fallback).unwrap();

    let mut direct_client = client();
    let mut direct = DirectSend::new();
    let allocation = direct.bytes.as_ptr();
    direct_client.start_into(&mut direct).unwrap();

    assert_eq!(direct.bytes.as_ptr(), allocation);
    assert_eq!(direct.bytes[0], 0xa5);
    assert_eq!(direct.bytes.len(), fallback.0.len() + 1);
    assert!(matches!(
        shin::wire::handshake::views::MessageRef::decode(&direct.bytes[1..]).unwrap(),
        shin::wire::handshake::views::MessageRef::ClientHello(_)
    ));
    assert_eq!(direct.borrowed_sends, 0);
}

#[test]
fn failed_direct_send_rolls_back_without_touching_retained_bytes() {
    let mut client = client();
    let mut direct = ShortDirectSend(vec![0xa5]);

    assert!(matches!(
        client.start_into(&mut direct),
        Err(DriveError::Protocol(_))
    ));
    assert_eq!(direct.0, [0xa5]);
}

#[test]
fn sink_error_is_typed_and_stops_on_the_rejected_event() {
    let mut client = client();
    let mut sink = RejectFirst { seen: 0 };

    let result = client.start_into(&mut sink);

    assert_eq!(result, Err(DriveError::Sink(Rejected)));
    assert_eq!(sink.seen, 1);

    let mut ignore = Ignore;
    assert_eq!(
        client.start_into(&mut ignore),
        Err(DriveError::Protocol(Error::ConnectionFailed))
    );
}

#[test]
fn protocol_error_remains_distinct_from_infallible_sink() {
    let mut client = client();
    let mut sink = Ignore;

    let result = client.read_into(Epoch::Plaintext, &[0xff, 0, 0, 0], &mut sink);

    assert!(matches!(result, Err(DriveError::Protocol(_))));
    assert_eq!(
        client.read_into(Epoch::Plaintext, &[], &mut sink),
        Err(DriveError::Protocol(Error::ConnectionFailed))
    );
}

#[test]
fn fragmented_client_error_preserves_reassembly_reservation() {
    let mut client = client();
    let mut sink = Ignore;
    client.start_into(&mut sink).unwrap();

    let malformed_server_hello = [2, 0, 0, 1, 0];
    client
        .read_into(Epoch::Plaintext, &malformed_server_hello[..2], &mut sink)
        .unwrap();
    assert!(
        client
            .read_into(Epoch::Plaintext, &malformed_server_hello[2..], &mut sink,)
            .is_err()
    );

    assert_eq!(
        client.into_workspace().capacities(),
        (MAX_PLAINTEXT_BODY, MAX_PLAINTEXT_BODY),
    );
}

fn shard<const DOMAIN: u8>(
    seed: u8,
) -> server::Shard<config::NoGuard, config::NoClientAuth, DOMAIN> {
    server::PreparedShard::new(server::config::Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[seed; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap()
    .bind_domain::<DOMAIN>()
}

#[test]
fn valid_policy_is_bound_before_the_first_read() {
    let server = server::Server::<_, 7>::new(
        config::Connection {
            transport_params: Vec::new(),
        },
        (|| 0) as fn() -> u64,
    )
    .unwrap();
    let mut first = shard::<7>(7);
    let mut connection = first.bind(server).into_result().unwrap();
    connection
        .read_into(Epoch::Plaintext, &[], &mut Ignore)
        .unwrap();
}

#[test]
fn fragmented_server_error_preserves_reassembly_reservation() {
    let workspace = Scratch::for_server();
    let capacities = workspace.capacities();
    let server = server::Server::with_workspace(
        config::Connection {
            transport_params: Vec::new(),
        },
        (|| 0) as fn() -> u64,
        workspace,
    )
    .unwrap();
    let mut shard = shard::<0>(7);
    let mut connection = shard.bind(server).into_result().unwrap();
    let mut sink = Ignore;

    let malformed_client_hello = [1, 0, 0, 1, 0];
    connection
        .read_into(Epoch::Plaintext, &malformed_client_hello[..2], &mut sink)
        .unwrap();
    assert!(
        connection
            .read_into(Epoch::Plaintext, &malformed_client_hello[2..], &mut sink,)
            .is_err()
    );

    assert_eq!(connection.into_workspace().capacities(), capacities);
}

#[test]
fn every_server_flight_sink_failure_is_terminal() {
    let mut client = client();
    let mut client_events = FirstPlaintextSend::default();
    client.start_into(&mut client_events).unwrap();

    let connection = || config::Connection {
        transport_params: Vec::new(),
    };
    let baseline = server::Server::new(connection(), (|| 0) as fn() -> u64).unwrap();
    let mut baseline_shard = shard::<0>(9);
    let mut baseline = baseline_shard.bind(baseline).into_result().unwrap();
    let mut count = CountEvents::default();
    baseline
        .read_into(Epoch::Plaintext, &client_events.0, &mut count)
        .unwrap();
    assert!(
        count.0 > 1,
        "server flight must exercise multiple callbacks"
    );

    for reject_at in 1..=count.0 {
        let server = server::Server::new(connection(), (|| 0) as fn() -> u64).unwrap();
        let mut shard = shard::<0>(9);
        let mut server = shard.bind(server).into_result().unwrap();
        let mut reject = RejectNth { seen: 0, reject_at };
        assert_eq!(
            server.read_into(Epoch::Plaintext, &client_events.0, &mut reject),
            Err(DriveError::Sink(Rejected)),
            "callback {reject_at} must propagate its sink error",
        );
        assert_eq!(reject.seen, reject_at);

        let mut ignore = Ignore;
        assert_eq!(
            server.read_into(Epoch::Plaintext, &[], &mut ignore),
            Err(DriveError::Protocol(Error::ConnectionFailed)),
            "callback {reject_at} must leave the server terminal",
        );
    }
}
