use std::cell::RefCell;
use std::rc::Rc;

use shin::client::{Client, Config as ClientConfig, Resumption, Verifier};
use shin::extension::ExtensionType;
use shin::server::{CertSource, Config as ServerConfig, EarlyDataGuard, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

const TICKET_SECRET: [u8; 32] = [0x55u8; 32];

// Fixed clock so the measured ticket age is ~0 in happy-path tests.
const NOW_MS: u64 = 1_700_000_000_000;

// Fixed-clock guard; clones share one strike list so two servers can model a replay.
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

impl EarlyDataGuard for TestGuard {
    fn now_ms(&self) -> u64 {
        self.now
    }
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

fn extract_send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

fn cets(events: &[Event]) -> Option<[u8; 32]> {
    events.iter().find_map(|e| match e {
        Event::ZeroRttKeysReady { secret } => Some(*secret),
        _ => None,
    })
}

fn server(accept: bool) -> Server {
    Server::new(ServerConfig {
        source: CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: accept,
    })
}

fn client(resumption: Option<Resumption>, enable_early_data: bool) -> Client {
    Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption,
        enable_early_data,
    })
}

fn first_handshake_ticket() -> Resumption {
    let mut s = server(false);
    // Issue with a guard so the ticket carries a real issued-at timestamp.
    s.set_early_data_guard(Box::new(TestGuard::new(NOW_MS)));
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = extract_send(&s1, Epoch::Handshake).unwrap();
    let _ = c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = extract_send(&c3, Epoch::Handshake).unwrap();
    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    let nst = extract_send(&s2, Epoch::Application).unwrap();
    let extra = c.read(Epoch::Application, &nst).unwrap();

    let mut psk: Option<[u8; 32]> = None;
    let mut tkt: Option<(u32, Vec<u8>)> = None;
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
fn no_early_data_offer_emits_no_cets() {
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), false);
    let evs = c.start().unwrap();
    assert!(cets(&evs).is_none());
}

#[test]
fn client_offers_early_data_emits_cets_and_ext() {
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), true);
    let evs = c.start().unwrap();

    let ch_bytes = extract_send(&evs, Epoch::Plaintext).unwrap();
    use shin::codec::Reader;
    use shin::handshake::Handshake;
    let mut r = Reader::new(&ch_bytes);
    let m = Handshake::decode(&mut r).unwrap();
    let Handshake::ClientHello(ch) = m else {
        panic!()
    };
    assert!(
        ch.extensions
            .iter()
            .any(|e| e.ty == ExtensionType::EARLY_DATA),
        "early_data ext must be in CH",
    );

    let secret = cets(&evs).expect("CETS emitted");
    assert!(!secret.iter().all(|&b| b == 0));
}

#[test]
fn server_accepts_early_data_emits_matching_cets_and_ee_ext() {
    let resumption = first_handshake_ticket();

    let mut c = client(Some(resumption), true);
    let mut s = server(true);
    s.set_early_data_guard(Box::new(TestGuard::new(NOW_MS)));

    let c1 = c.start().unwrap();
    let ch_bytes = extract_send(&c1, Epoch::Plaintext).unwrap();
    let client_cets = cets(&c1).expect("client CETS");

    let s1 = s.read(Epoch::Plaintext, &ch_bytes).unwrap();
    let server_cets = cets(&s1).expect("server CETS");

    assert_eq!(client_cets, server_cets, "CETS must match across sides");

    let s_hs_blob = extract_send(&s1, Epoch::Handshake).unwrap();
    use shin::codec::Reader;
    use shin::handshake::Handshake;
    let mut r = Reader::new(&s_hs_blob);
    let m = Handshake::decode(&mut r).unwrap();
    let Handshake::EncryptedExtensions(ee) = m else {
        panic!(
            "first message in hs blob must be EE; got {:?}",
            m.msg_type()
        )
    };
    assert!(
        ee.extensions
            .iter()
            .any(|e| e.ty == ExtensionType::EARLY_DATA),
        "EE must echo early_data",
    );
}

#[test]
fn server_with_accept_off_skips_cets_even_with_offer() {
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), true);
    let mut s = server(false);

    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        cets(&s1).is_none(),
        "server didn't enable accept_early_data"
    );
}

#[test]
fn server_without_guard_refuses_early_data() {
    // accept_early_data = true but no guard: must still refuse.
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), true);
    let mut s = server(true); // deliberately no set_early_data_guard
    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&s1).is_none(), "no guard => early data refused");
}

#[test]
fn replayed_early_data_is_rejected() {
    // Same ClientHello to two servers sharing a strike list: the 2nd is a replay.
    let resumption = first_handshake_ticket();
    let guard = TestGuard::new(NOW_MS);

    let mut c = client(Some(resumption), true);
    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();

    let mut s1 = server(true);
    s1.set_early_data_guard(Box::new(guard.clone()));
    let out1 = s1.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&out1).is_some(), "first use accepts early data");

    let mut s2 = server(true);
    s2.set_early_data_guard(Box::new(guard.clone()));
    let out2 = s2.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        cets(&out2).is_none(),
        "replayed binder => early data refused"
    );
}

#[test]
fn stale_ticket_outside_freshness_window_rejected() {
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), true);
    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();

    // Server clock far ahead of issued-at; client claims age ~0 -> exceeds skew.
    let mut s = server(true);
    s.set_early_data_guard(Box::new(TestGuard::new(NOW_MS + 60_000)));
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&s1).is_none(), "stale ticket => early data refused");
}
