use core::convert::Infallible;

use shin::client::Client;
use shin::client::config::{Config, NegotiatedAlpn, Restore, Verifier};
use shin::connection::{DriveError, Epoch, Error, Event, EventContext, EventSink};
use shin::crypto::sig::SigningKey;
use shin::server;
use shin::server::config;
use shin::server::config::CertSource;
use shin::transport::Mode;
use shin::wire::record::CipherSuite;

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

fn shard(seed: u8) -> server::Shard {
    server::Shard::new(server::config::Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[seed; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap()
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
    let mut first = shard(7).into_domain::<7>();
    let mut connection = first.bind(server).unwrap();
    connection
        .read_into(Epoch::Plaintext, &[], &mut Ignore)
        .unwrap();
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
    let mut baseline_shard = shard(9);
    let mut baseline = baseline_shard.bind(baseline).unwrap();
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
        let mut shard = shard(9);
        let mut server = shard.bind(server).unwrap();
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
