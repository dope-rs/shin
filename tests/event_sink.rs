use core::convert::Infallible;

use shin::client::Client;
use shin::client::config::{Config, Verifier};
use shin::connection::{DriveError, Epoch, Event, EventContext, EventSink};

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

struct Ignore;

impl EventSink for Ignore {
    type Error = Infallible;

    fn event(&mut self, _event: Event<'_>, _context: EventContext) -> Result<(), Self::Error> {
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
}

#[test]
fn protocol_error_remains_distinct_from_infallible_sink() {
    let mut client = client();
    let mut sink = Ignore;

    let result = client.read_into(Epoch::Plaintext, &[0xff, 0, 0, 0], &mut sink);

    assert!(matches!(result, Err(DriveError::Protocol(_))));
}
