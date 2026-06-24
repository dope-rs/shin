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
    server_alpn(accept, Vec::new())
}

fn server_alpn(accept: bool, alpn_protocols: Vec<Vec<u8>>) -> Server {
    Server::new(ServerConfig {
        source: CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        transport_params: Vec::new(),
        alpn_protocols,
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: accept,
    })
}

fn client(resumption: Option<Resumption>, enable_early_data: bool) -> Client {
    client_alpn(resumption, enable_early_data, Vec::new())
}

fn client_alpn(
    resumption: Option<Resumption>,
    enable_early_data: bool,
    alpn_protocols: Vec<Vec<u8>>,
) -> Client {
    Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols,
        resumption,
        enable_early_data,
    })
}

fn first_handshake_ticket() -> Resumption {
    first_handshake_ticket_cfg(Vec::new(), NOW_MS)
}

fn first_handshake_ticket_cfg(alpn_protocols: Vec<Vec<u8>>, now_ms: u64) -> Resumption {
    let mut s = server_alpn(false, alpn_protocols.clone());
    // Issue with a guard so the ticket carries a real issued-at timestamp.
    s.set_early_data_guard(Box::new(TestGuard::new(now_ms)));
    let mut c = client_alpn(None, false, alpn_protocols);
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

#[test]
fn early_data_accepted_when_resumed_alpn_matches() {
    // Sanity: identical ALPN on the issuing and resuming sessions still accepts 0-RTT.
    let resumption = first_handshake_ticket_cfg(alloc_vec(b"h2"), NOW_MS);
    let mut c = client_alpn(Some(resumption), true, alloc_vec(b"h2"));
    let mut s = server_alpn(true, alloc_vec(b"h2"));
    s.set_early_data_guard(Box::new(TestGuard::new(NOW_MS)));

    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&s1).is_some(), "matching ALPN => early data accepted");
}

#[test]
fn early_data_rejected_when_resumed_alpn_mismatches() {
    // Original session negotiated "h2"; resumption negotiates "http/1.1".
    let resumption = first_handshake_ticket_cfg(alloc_vec(b"h2"), NOW_MS);
    let mut c = client_alpn(Some(resumption), true, alloc_vec(b"http/1.1"));
    let mut s = server_alpn(true, alloc_vec(b"http/1.1"));
    s.set_early_data_guard(Box::new(TestGuard::new(NOW_MS)));

    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        cets(&s1).is_none(),
        "mismatched ALPN must reject 0-RTT (RFC 8446 4.2.10)"
    );
    // Handshake still proceeds (1-RTT): ServerHello + handshake messages emitted.
    assert!(
        extract_send(&s1, Epoch::Plaintext).is_some(),
        "server still completes 1-RTT handshake"
    );
    assert!(
        extract_send(&s1, Epoch::Handshake).is_some(),
        "server emits handshake messages for 1-RTT fallback"
    );
}

#[test]
fn expired_ticket_does_not_resume_via_psk() {
    // Ticket issued at NOW_MS; resume far beyond TICKET_LIFETIME so PSK is rejected.
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), false);

    // 8 days after issuance (> 7200s lifetime).
    let mut s = server(false);
    s.set_early_data_guard(Box::new(TestGuard::new(NOW_MS + 8 * 86_400_000)));

    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();

    // PSK rejected => full handshake => Certificate is sent in the handshake blob.
    let s_hs_blob = extract_send(&s1, Epoch::Handshake).unwrap();
    use shin::codec::Reader;
    use shin::handshake::{Handshake, HandshakeType};
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(Handshake::decode(&mut r).unwrap().msg_type());
    }
    assert!(
        types.contains(&HandshakeType::Certificate),
        "expired ticket must force full handshake (Certificate present); saw {:?}",
        types,
    );
}

#[test]
fn fresh_ticket_still_resumes_via_psk() {
    // Control: ticket within lifetime resumes (no Certificate in handshake blob).
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), false);

    let mut s = server(false);
    s.set_early_data_guard(Box::new(TestGuard::new(NOW_MS + 1000)));

    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();

    let s_hs_blob = extract_send(&s1, Epoch::Handshake).unwrap();
    use shin::codec::Reader;
    use shin::handshake::{Handshake, HandshakeType};
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(Handshake::decode(&mut r).unwrap().msg_type());
    }
    assert!(
        !types.contains(&HandshakeType::Certificate),
        "fresh ticket must resume via PSK (no Certificate); saw {:?}",
        types,
    );
}

fn alloc_vec(s: &[u8]) -> Vec<Vec<u8>> {
    vec![s.to_vec()]
}

fn fresh_client_hello() -> Vec<u8> {
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    extract_send(&c1, Epoch::Plaintext).unwrap()
}

fn reencode_ch<F: FnOnce(&mut shin::handshake::ClientHello)>(
    ch_bytes: &[u8],
    mutate: F,
) -> Vec<u8> {
    use shin::codec::Reader;
    use shin::handshake::Handshake;
    let mut r = Reader::new(ch_bytes);
    let Handshake::ClientHello(mut ch) = Handshake::decode(&mut r).unwrap() else {
        panic!()
    };
    mutate(&mut ch);
    let mut out = Vec::new();
    Handshake::ClientHello(ch).encode(&mut out);
    out
}

#[test]
fn server_rejects_nonnull_compression_method() {
    let ch = reencode_ch(&fresh_client_hello(), |ch| {
        ch.legacy_compression_methods = vec![0, 1];
    });
    let mut s = server(false);
    let err = s.read(Epoch::Plaintext, &ch).unwrap_err();
    assert_eq!(err, shin::Error::Decode);
}

#[test]
fn server_accepts_null_compression_method() {
    let ch = fresh_client_hello();
    let mut s = server(false);
    let out = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(extract_send(&out, Epoch::Plaintext).is_some());
}

#[test]
fn server_rejects_oversized_session_id() {
    let ch = reencode_ch(&fresh_client_hello(), |ch| {
        ch.legacy_session_id = vec![0u8; 33];
    });
    let mut s = server(false);
    let err = s.read(Epoch::Plaintext, &ch).unwrap_err();
    assert_eq!(err, shin::Error::Decode);
}

#[test]
fn server_accepts_max_session_id() {
    let ch = reencode_ch(&fresh_client_hello(), |ch| {
        ch.legacy_session_id = vec![7u8; 32];
    });
    let mut s = server(false);
    let out = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(extract_send(&out, Epoch::Plaintext).is_some());
}

// Drive a server to Done, returning it ready for application-epoch messages.
fn established_server() -> Server {
    let mut s = server(false);
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = extract_send(&s1, Epoch::Handshake).unwrap();
    let _ = c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = extract_send(&c3, Epoch::Handshake).unwrap();
    let _ = s.read(Epoch::Handshake, &cf).unwrap();
    assert!(s.is_done());
    s
}

#[test]
fn server_caps_key_updates_per_record() {
    use shin::handshake::{Handshake, KeyUpdate};
    let mut s = established_server();
    // Many KeyUpdate(request_update=1) in one record => bounded reply amplification.
    let mut record = Vec::new();
    for _ in 0..64 {
        Handshake::KeyUpdate(KeyUpdate { request_update: 1 }).encode(&mut record);
    }
    let err = s.read(Epoch::Application, &record).unwrap_err();
    assert_eq!(err, shin::Error::UnexpectedMessage);
}

#[test]
fn server_allows_bounded_key_updates() {
    use shin::handshake::{Handshake, KeyUpdate};
    let mut s = established_server();
    let mut record = Vec::new();
    for _ in 0..8 {
        Handshake::KeyUpdate(KeyUpdate { request_update: 0 }).encode(&mut record);
    }
    s.read(Epoch::Application, &record).unwrap();
}

#[test]
fn nst_advertises_early_data_when_accept_enabled() {
    use shin::codec::Reader;
    use shin::extension::ExtensionType;
    use shin::handshake::Handshake;

    let mut s = server(true);
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
    let nst_bytes = extract_send(&s2, Epoch::Application).unwrap();

    let mut r = Reader::new(&nst_bytes);
    let Handshake::NewSessionTicket(nst) = Handshake::decode(&mut r).unwrap() else {
        panic!("expected NewSessionTicket")
    };
    let ext = nst
        .extensions
        .iter()
        .find(|e| e.ty == ExtensionType::EARLY_DATA)
        .expect("NST must advertise early_data when 0-RTT accepted");
    assert_eq!(
        ext.data.len(),
        4,
        "early_data body is uint32 max_early_data_size"
    );
}

#[test]
fn nst_omits_early_data_when_accept_disabled() {
    use shin::codec::Reader;
    use shin::extension::ExtensionType;
    use shin::handshake::Handshake;

    let mut s = server(false);
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
    let nst_bytes = extract_send(&s2, Epoch::Application).unwrap();

    let mut r = Reader::new(&nst_bytes);
    let Handshake::NewSessionTicket(nst) = Handshake::decode(&mut r).unwrap() else {
        panic!("expected NewSessionTicket")
    };
    assert!(
        nst.extensions
            .iter()
            .all(|e| e.ty != ExtensionType::EARLY_DATA),
        "NST must not advertise early_data when accept disabled",
    );
}
