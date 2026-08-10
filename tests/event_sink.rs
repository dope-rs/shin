use core::convert::Infallible;

use shin::client::Client;
use shin::client::config::{Config, Verifier};
use shin::connection::{DriveError, Epoch, Error, Event, EventContext, EventSink};
use shin::crypto::sig::SigningKey;
use shin::server;
use shin::server::ReplayDomain;
use shin::server::config;
use shin::server::config::{CertSource, EarlyDataGuard};

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

fn client() -> Client<fn() -> u64> {
    Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [0u8; 32],
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
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
}

struct AlwaysFresh;

impl EarlyDataGuard for AlwaysFresh {
    fn register(&mut self, _token: &[u8]) -> bool {
        true
    }
}

fn shard_in_replay_domain(seed: u8, domain: ReplayDomain) -> server::Shard<AlwaysFresh> {
    server::Shard::with_early_data_guard_in_replay_domain(
        server::config::Config {
            source: CertSource::RawPublicKey {
                signing_key: SigningKey::from_seed(&[seed; 32]).unwrap(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        domain,
        AlwaysFresh,
    )
}

#[test]
fn server_is_permanently_bound_to_its_first_shard() {
    let mut server = server::Server::new(
        config::Connection {
            transport_params: Vec::new(),
        },
        (|| 0) as fn() -> u64,
    );
    let mut first = shard(7);
    let mut replacement = shard(8);
    let mut sink = Ignore;

    server
        .read_into(Epoch::Plaintext, &[], &mut first, &mut sink)
        .unwrap();
    assert_eq!(
        server.read_into(Epoch::Plaintext, &[], &mut replacement, &mut sink),
        Err(DriveError::Protocol(Error::ConnectionFailed))
    );
    assert_eq!(
        server.read_into(Epoch::Plaintext, &[], &mut first, &mut sink),
        Err(DriveError::Protocol(Error::ConnectionFailed))
    );
}

#[test]
fn shared_replay_domain_does_not_weaken_live_shard_binding() {
    let domain = ReplayDomain::new([0x44; 16]);
    let mut first = shard_in_replay_domain(7, domain.clone());
    let mut replacement = shard_in_replay_domain(8, domain);
    let mut server = server::Server::new(
        config::Connection {
            transport_params: Vec::new(),
        },
        (|| 0) as fn() -> u64,
    );
    let mut sink = Ignore;

    server
        .read_into(Epoch::Plaintext, &[], &mut first, &mut sink)
        .unwrap();
    assert_eq!(
        server.read_into(Epoch::Plaintext, &[], &mut replacement, &mut sink),
        Err(DriveError::Protocol(Error::ConnectionFailed)),
    );
}

#[test]
fn every_server_flight_sink_failure_is_terminal() {
    let mut client = client();
    let mut client_events = FirstPlaintextSend::default();
    client.start_into(&mut client_events).unwrap();

    let connection = || config::Connection {
        transport_params: Vec::new(),
    };
    let mut baseline = server::Server::new(connection(), (|| 0) as fn() -> u64);
    let mut baseline_shard = shard(9);
    let mut count = CountEvents::default();
    baseline
        .read_into(
            Epoch::Plaintext,
            &client_events.0,
            &mut baseline_shard,
            &mut count,
        )
        .unwrap();
    assert!(
        count.0 > 1,
        "server flight must exercise multiple callbacks"
    );

    for reject_at in 1..=count.0 {
        let mut server = server::Server::new(connection(), (|| 0) as fn() -> u64);
        let mut shard = shard(9);
        let mut reject = RejectNth { seen: 0, reject_at };
        assert_eq!(
            server.read_into(Epoch::Plaintext, &client_events.0, &mut shard, &mut reject,),
            Err(DriveError::Sink(Rejected)),
            "callback {reject_at} must propagate its sink error",
        );
        assert_eq!(reject.seen, reject_at);

        let mut ignore = Ignore;
        assert_eq!(
            server.read_into(Epoch::Plaintext, &[], &mut shard, &mut ignore),
            Err(DriveError::Protocol(Error::ConnectionFailed)),
            "callback {reject_at} must leave the server terminal",
        );
    }
}
