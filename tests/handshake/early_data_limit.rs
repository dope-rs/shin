use shin::client::Client;
use shin::client::config::{Config, Restore, Verifier};
use shin::connection::{Clock, Epoch, Error};
use shin::crypto::sig::SigningKey;
use shin::server::{config::CertSource, config::EarlyDataGuard};

use crate::common::CollectEvents;
use crate::common::Event;
use crate::common::{Server, ServerConfig, find_send};

const TICKET_SECRET: [u8; 32] = [0x55u8; 32];
const NOW_MS: u64 = 1_700_000_000_000;
const MAX_EARLY_DATA_SIZE: u32 = 16384;

struct TestGuard {
    now: u64,
    seen: Vec<Vec<u8>>,
}

impl TestGuard {
    fn new(now: u64) -> Self {
        Self {
            now,
            seen: Vec::new(),
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
        if self.seen.iter().any(|t| t.as_slice() == token) {
            return false;
        }
        self.seen.push(token.to_vec());
        true
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x99u8; 32]).unwrap()
}

fn server(accept: bool) -> Server<TestGuard, TestGuard> {
    Server::with_early_data_guard(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET).unwrap()),
            accept_early_data: accept,
        },
        TestGuard::new(NOW_MS),
        TestGuard::new(NOW_MS),
    )
}

fn client(restore: Option<Restore<'_>>, enable_early_data: bool) -> Client<fn() -> u64> {
    let template = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data,
    }
    .try_into_template()
    .unwrap();
    let prepared = match restore {
        Some(restore) => template.restore(restore).unwrap(),
        None => template.without_resumption(),
    };
    let workspace = prepared.workspace_layout(None).allocate();
    prepared
        .try_into_client_with_workspace(None, (|| 0) as fn() -> u64, workspace)
        .unwrap()
}

fn issue_ticket() -> Restore<'static> {
    let mut s = server(true);
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = find_send(&c3, Epoch::Handshake).unwrap();
    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    let nst = find_send(&s2, Epoch::Application).unwrap();
    let extra = c.read(Epoch::Application, &nst).unwrap();

    extra
        .into_iter()
        .find_map(Event::into_restore)
        .expect("server issued a restorable ticket")
}

fn early_accepted_server() -> Server<TestGuard, TestGuard> {
    let mut c = client(Some(issue_ticket()), true);
    let mut s = server(true);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        s1.iter()
            .any(|e| matches!(e, Event::ZeroRttKeysReady { .. })),
        "server must accept 0-RTT for this fixture"
    );
    s
}

#[test]
fn limit_is_exposed_only_while_window_open() {
    let mut c = client(Some(issue_ticket()), true);
    let mut s = server(true);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let eod = find_send(&c3, Epoch::Handshake).unwrap();

    assert_eq!(s.max_early_data_size(), Some(MAX_EARLY_DATA_SIZE));
    s.read(Epoch::Handshake, &eod).unwrap();
    assert_eq!(
        s.max_early_data_size(),
        None,
        "window closes after EndOfEarlyData"
    );
    assert_eq!(s.note_early_data(1), Err(Error::EarlyDataLimitExceeded));
}

#[test]
fn early_data_within_limit_succeeds_then_overflow_is_fatal() {
    let mut s = early_accepted_server();
    assert!(s.note_early_data(8192).is_ok());
    assert!(s.note_early_data(8192).is_ok());
    assert_eq!(
        s.note_early_data(1),
        Err(Error::EarlyDataLimitExceeded),
        "one byte past the limit must be fatal"
    );
    assert_eq!(s.max_early_data_size(), None, "window closes on overflow");
}

#[test]
fn single_oversized_chunk_is_fatal() {
    let mut s = early_accepted_server();
    assert_eq!(
        s.note_early_data((MAX_EARLY_DATA_SIZE as usize) + 1),
        Err(Error::EarlyDataLimitExceeded)
    );
}

#[test]
fn note_early_data_rejected_when_not_accepted() {
    let mut s = server(true);
    assert_eq!(s.max_early_data_size(), None);
    assert_eq!(s.note_early_data(1), Err(Error::EarlyDataLimitExceeded));
}

#[test]
fn overflow_error_maps_to_unexpected_message_alert() {
    use shin::wire::alert::Description;
    assert_eq!(
        Error::EarlyDataLimitExceeded.alert().description,
        Description::UnexpectedMessage
    );
}
