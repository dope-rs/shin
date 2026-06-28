use std::cell::RefCell;
use std::rc::Rc;

use shin::client::{Client, Config as ClientConfig, Resumption, Verifier};
use shin::hash::Digest;
use shin::server::{CertSource, Config as ServerConfig, EarlyDataGuard, Server};
use shin::sig::SigningKey;
use shin::{Clock, Epoch, Event};

const TICKET_SECRET: [u8; 32] = [0x55u8; 32];
const NOW_MS: u64 = 1_700_000_000_000;

#[derive(Clone)]
struct TestGuard {
    now: u64,
    seen: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl TestGuard {
    fn new(now: u64) -> Self {
        Self {
            now,
            seen: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl Clock for TestGuard {
    fn now_ms(&self) -> u64 {
        self.now
    }
}

impl EarlyDataGuard for TestGuard {
    fn register(&mut self, token: &[u8]) -> bool {
        let mut seen = self.seen.borrow_mut();
        if seen.iter().any(|t| t.as_slice() == token) {
            return false;
        }
        seen.push(token.to_vec());
        true
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x99u8; 32]).unwrap()
}

fn send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

fn app_keys(events: &[Event]) -> Option<(Digest, Digest)> {
    events.iter().find_map(|e| match e {
        Event::KeysReady {
            epoch: Epoch::Application,
            read_secret,
            write_secret,
        } => Some((*read_secret, *write_secret)),
        _ => None,
    })
}

fn has(events: &[Event], want: &Event) -> bool {
    events.iter().any(|e| e == want)
}

fn server(accept: bool) -> Server<TestGuard, TestGuard> {
    Server::with_early_data_guard(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: Some(shin::ticket::TicketKeys::single(TICKET_SECRET)),
            accept_early_data: accept,
        },
        TestGuard::new(NOW_MS),
        TestGuard::new(NOW_MS),
    )
}

fn client(resumption: Option<Resumption>, enable_early_data: bool) -> Client<fn() -> u64> {
    Client::new(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption,
            enable_early_data,
        },
        || 0,
    )
}

fn issue_ticket() -> Resumption {
    let mut s = server(false);
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    let ch = send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = send(&s1, Epoch::Handshake).unwrap();
    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = send(&c3, Epoch::Handshake).unwrap();
    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    let nst = send(&s2, Epoch::Application).unwrap();
    let extra = c.read(Epoch::Application, &nst).unwrap();

    let mut psk = None;
    let mut tkt = None;
    for e in extra {
        match e {
            Event::ResumptionSecret { psk: p } => psk = Some(p),
            Event::NewSessionTicket {
                ticket_age_add,
                ticket,
                ..
            } => tkt = Some((ticket_age_add, ticket)),
            _ => {}
        }
    }
    let (age_add, ticket) = tkt.unwrap();
    Resumption {
        psk: psk.unwrap(),
        ticket,
        ticket_age_add: age_add,
        age_millis: 0,
    }
}

#[test]
fn full_zero_rtt_handshake_completes_via_end_of_early_data() {
    let mut c = client(Some(issue_ticket()), true);
    let mut s = server(true);

    let c1 = c.start().unwrap();
    let ch = send(&c1, Epoch::Plaintext).unwrap();
    let client_cets = c1.iter().find_map(|e| match e {
        Event::ZeroRttKeysReady { secret } => Some(*secret),
        _ => None,
    });
    assert!(client_cets.is_some(), "client must emit 0-RTT keys");

    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = send(&s1, Epoch::Handshake).unwrap();
    let (s_app_read, s_app_write) = app_keys(&s1).unwrap();

    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();

    assert!(has(&c3, &Event::EarlyDataAccepted));
    let eod = send(&c3, Epoch::EarlyData).expect("client sends EndOfEarlyData under early epoch");
    let cf = send(&c3, Epoch::Handshake).expect("client Finished under handshake epoch");
    assert!(has(&c3, &Event::Done));
    let (c_app_read, c_app_write) = app_keys(&c3).unwrap();

    assert_eq!(c_app_read, s_app_write);
    assert_eq!(c_app_write, s_app_read);

    s.read(Epoch::EarlyData, &eod).unwrap();
    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    assert!(
        has(&s2, &Event::Done),
        "server completes after client Finished"
    );
    assert!(c.is_done());
    assert!(s.is_done());
}

#[test]
fn server_rejecting_early_data_yields_rejected_and_no_eod() {
    let mut c = client(Some(issue_ticket()), true);
    let mut s = server(false);

    let c1 = c.start().unwrap();
    let ch = send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = send(&s1, Epoch::Handshake).unwrap();

    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();

    assert!(has(&c3, &Event::EarlyDataRejected));
    assert!(
        send(&c3, Epoch::EarlyData).is_none(),
        "no EndOfEarlyData when rejected"
    );
    let cf = send(&c3, Epoch::Handshake).unwrap();
    assert!(has(&c3, &Event::Done));

    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    assert!(has(&s2, &Event::Done));
    assert!(s.is_done());
}

#[test]
fn server_rejects_finished_before_end_of_early_data() {
    let mut c = client(Some(issue_ticket()), true);
    let mut s = server(true);

    let c1 = c.start().unwrap();
    let ch = send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = send(&s1, Epoch::Handshake).unwrap();
    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = send(&c3, Epoch::Handshake).unwrap();

    assert_eq!(
        s.read(Epoch::Handshake, &cf).unwrap_err(),
        shin::Error::UnexpectedMessage
    );
}
