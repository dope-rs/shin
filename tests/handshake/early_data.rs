use std::sync::{Arc, Mutex};

use shin::client::Client;
use shin::client::config::{Config, Resumption, Verifier};
use shin::connection::{Clock, Epoch};
use shin::crypto::hash::Digest;
use shin::crypto::sig::SigningKey;
use shin::server::{
    self, ReplayDomain, Shard, config, config::CertSource, config::Connection,
    config::EarlyDataGuard, config::NoGuard,
};
use shin::wire::extension::Type;

use crate::common::Event;
use crate::common::{CollectEvents, CollectServerEvents};
use crate::common::{Server, ServerConfig, find_send, replay_domain};

const TICKET_SECRET: [u8; 32] = [0x55u8; 32];

// Fixed clock so the measured ticket age is ~0 in happy-path tests.
const NOW_MS: u64 = 1_700_000_000_000;

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

#[derive(Clone, Default)]
struct SharedGuard {
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl EarlyDataGuard for SharedGuard {
    fn register(&mut self, token: &[u8]) -> bool {
        let mut seen = self.seen.lock().unwrap();
        if seen.iter().any(|entry| entry.as_slice() == token) {
            return false;
        }
        seen.push(token.to_vec());
        true
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x99u8; 32]).unwrap()
}

fn cets(events: &[Event]) -> Option<Digest> {
    events.iter().find_map(|e| match e {
        Event::ZeroRttKeysReady { secret } => Some(*secret),
        _ => None,
    })
}

fn server_config(accept: bool, alpn_protocols: Vec<Vec<u8>>) -> ServerConfig {
    ServerConfig {
        source: CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        transport_params: Vec::new(),
        alpn_protocols,
        ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET)),
        accept_early_data: accept,
    }
}

fn server(accept: bool, now_ms: u64) -> Server<TestGuard, TestGuard> {
    server_alpn(accept, Vec::new(), now_ms)
}

fn server_alpn(
    accept: bool,
    alpn_protocols: Vec<Vec<u8>>,
    now_ms: u64,
) -> Server<TestGuard, TestGuard> {
    Server::with_early_data_guard(
        server_config(accept, alpn_protocols),
        TestGuard::new(now_ms),
        TestGuard::new(now_ms),
    )
}

fn server_no_guard(accept: bool, now_ms: u64) -> Server<TestGuard, NoGuard> {
    Server::new(server_config(accept, Vec::new()), TestGuard::new(now_ms))
}

fn client(resumption: Option<Resumption>, enable_early_data: bool) -> Client<fn() -> u64> {
    client_alpn(resumption, enable_early_data, Vec::new())
}

fn client_alpn(
    resumption: Option<Resumption>,
    enable_early_data: bool,
    alpn_protocols: Vec<Vec<u8>>,
) -> Client<fn() -> u64> {
    Client::new(
        Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: *signing_key().pubkey().unwrap(),
            },
            transport_params: Vec::new(),
            alpn_protocols,
            resumption,
            enable_early_data,
        },
        (|| 0) as fn() -> u64,
    )
    .unwrap()
}

fn first_handshake_ticket() -> Resumption {
    first_handshake_ticket_cfg(Vec::new(), NOW_MS)
}

fn first_handshake_ticket_cfg(alpn_protocols: Vec<Vec<u8>>, now_ms: u64) -> Resumption {
    first_handshake_ticket_with_policy(alpn_protocols, now_ms, true)
}

fn first_handshake_ticket_with_policy(
    alpn_protocols: Vec<Vec<u8>>,
    now_ms: u64,
    allow_early_data: bool,
) -> Resumption {
    let mut s = server_alpn(allow_early_data, alpn_protocols.clone(), now_ms);
    let mut c = client_alpn(None, false, alpn_protocols);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    let _ = c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = find_send(&c3, Epoch::Handshake).unwrap();
    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    let nst = find_send(&s2, Epoch::Application).unwrap();
    let extra = c.read(Epoch::Application, &nst).unwrap();

    let mut psk: Option<[u8; 32]> = None;
    let mut tkt: Option<(u32, Vec<u8>, Option<u32>)> = None;
    for e in extra {
        match e {
            Event::ResumptionSecret { psk: p } => psk = Some(p),
            Event::NewSessionTicket {
                ticket_age_add,
                ticket,
                max_early_data,
                ..
            } => tkt = Some((ticket_age_add, ticket, max_early_data)),
            _ => {}
        }
    }
    let (age_add, ticket, max_early_data) = tkt.unwrap();
    let psk = psk.unwrap();
    match max_early_data {
        Some(maximum) => Resumption::new_with_early_data(
            psk,
            ticket,
            age_add,
            0,
            maximum,
            shin::transport::Mode::Tls,
        ),
        None => Resumption::new(psk, ticket, age_add, 0),
    }
}

fn shard_config() -> config::Config {
    config::Config {
        source: CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET)),
    }
}

fn ticket_from_shard<G: EarlyDataGuard>(shard: &mut Shard<G>) -> Resumption {
    let mut server = server::Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        TestGuard::new(NOW_MS),
    );
    let mut client = client(None, false);
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let server_start = server.read(Epoch::Plaintext, &client_hello, shard).unwrap();
    let server_hello = find_send(&server_start, Epoch::Plaintext).unwrap();
    let server_handshake = find_send(&server_start, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &server_hello).unwrap();
    let client_finished = client.read(Epoch::Handshake, &server_handshake).unwrap();
    let client_finished = find_send(&client_finished, Epoch::Handshake).unwrap();
    let server_finished = server
        .read(Epoch::Handshake, &client_finished, shard)
        .unwrap();
    let new_session_ticket = find_send(&server_finished, Epoch::Application).unwrap();
    let ticket_events = client
        .read(Epoch::Application, &new_session_ticket)
        .unwrap();

    let mut psk = None;
    let mut ticket = None;
    for event in ticket_events {
        match event {
            Event::ResumptionSecret { psk: secret } => psk = Some(secret),
            Event::NewSessionTicket {
                ticket_age_add,
                ticket: bytes,
                max_early_data,
                ..
            } => ticket = Some((ticket_age_add, bytes, max_early_data)),
            _ => {}
        }
    }
    let (ticket_age_add, ticket, max_early_data) = ticket.unwrap();
    Resumption::new_with_early_data(
        psk.unwrap(),
        ticket,
        ticket_age_add,
        0,
        max_early_data.unwrap(),
        shin::transport::Mode::Tls,
    )
}

fn copy_resumption(resumption: &Resumption) -> Resumption {
    Resumption::new_with_early_data(
        *resumption.psk.as_array(),
        resumption.ticket.clone(),
        resumption.ticket_age_add,
        resumption.age_millis,
        resumption.max_early_data().unwrap(),
        resumption.early_data_transport_mode().unwrap(),
    )
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

    let ch_bytes = find_send(&evs, Epoch::Plaintext).unwrap();
    use shin::wire::codec::Reader;
    use shin::wire::handshake::frame::Frame;
    let mut r = Reader::new(&ch_bytes);
    let m = Frame::decode(&mut r).unwrap();
    let Frame::ClientHello(ch) = m else { panic!() };
    assert!(
        ch.extensions.iter().any(|e| e.ty == Type::EARLY_DATA),
        "early_data ext must be in CH",
    );

    let secret = cets(&evs).expect("CETS emitted");
    assert!(!secret.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn ticket_issued_without_early_data_authority_cannot_gain_it_later() {
    let resumption = first_handshake_ticket_with_policy(Vec::new(), NOW_MS, false);
    let mut c = client(Some(resumption), true);
    let mut s = server(true, NOW_MS);

    let c1 = c.start().unwrap();
    assert!(
        cets(&c1).is_none(),
        "client must not invent 0-RTT authority"
    );
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        cets(&s1).is_none(),
        "current server policy cannot upgrade the authenticated ticket"
    );

    let handshake = find_send(&s1, Epoch::Handshake).unwrap();
    let mut reader = shin::wire::codec::Reader::new(&handshake);
    let mut saw_certificate = false;
    while !reader.is_empty() {
        let frame = shin::wire::handshake::frame::Frame::decode(&mut reader).unwrap();
        saw_certificate |= frame.msg_type() == shin::wire::handshake::Type::Certificate;
    }
    assert!(
        !saw_certificate,
        "1-RTT PSK resumption must remain available"
    );
}

#[test]
fn server_accepts_early_data_emits_matching_cets_and_ee_ext() {
    let resumption = first_handshake_ticket();

    let mut c = client(Some(resumption), true);
    let mut s = server(true, NOW_MS);

    let c1 = c.start().unwrap();
    let ch_bytes = find_send(&c1, Epoch::Plaintext).unwrap();
    let client_cets = cets(&c1).expect("client CETS");

    let s1 = s.read(Epoch::Plaintext, &ch_bytes).unwrap();
    let server_cets = cets(&s1).expect("server CETS");

    assert_eq!(client_cets, server_cets, "CETS must match across sides");

    let s_hs_blob = find_send(&s1, Epoch::Handshake).unwrap();
    use shin::wire::codec::Reader;
    use shin::wire::handshake::frame::Frame;
    let mut r = Reader::new(&s_hs_blob);
    let m = Frame::decode(&mut r).unwrap();
    let Frame::EncryptedExtensions(ee) = m else {
        panic!(
            "first message in hs blob must be EE; got {:?}",
            m.msg_type()
        )
    };
    assert!(
        ee.extensions.iter().any(|e| e.ty == Type::EARLY_DATA),
        "EE must echo early_data",
    );
}

#[test]
fn server_with_accept_off_skips_cets_even_with_offer() {
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), true);
    let mut s = server(false, NOW_MS);

    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
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
    let mut s = server_no_guard(true, NOW_MS);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&s1).is_none(), "no guard => early data refused");
}

#[test]
fn replayed_early_data_is_rejected() {
    let resumption = first_handshake_ticket();

    let mut c = client(Some(resumption), true);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();

    let mut shard = Shard::with_early_data_guard_in_replay_domain(
        config::Config {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET)),
        },
        replay_domain(),
        TestGuard::new(NOW_MS),
    );
    let connection_config = || Connection {
        transport_params: Vec::new(),
    };

    let mut s1 = server::Server::new(connection_config(), TestGuard::new(NOW_MS));
    let out1 = s1.read(Epoch::Plaintext, &ch, &mut shard).unwrap();
    assert!(cets(&out1).is_some(), "first use accepts early data");

    let mut s2 = server::Server::new(connection_config(), TestGuard::new(NOW_MS));
    let out2 = s2.read(Epoch::Plaintext, &ch, &mut shard).unwrap();
    assert!(
        cets(&out2).is_none(),
        "replayed binder => early data refused"
    );
}

#[test]
fn different_default_random_domains_reject_zero_rtt_but_keep_psk_resumption() {
    let guard = SharedGuard::default();
    let mut issuing_shard =
        Shard::try_with_early_data_guard(shard_config(), guard.clone()).unwrap();
    let ticket = ticket_from_shard(&mut issuing_shard);
    let mut accepting_shard = Shard::try_with_early_data_guard(shard_config(), guard).unwrap();

    let mut client = client(Some(ticket), true);
    let client_start = client.start().unwrap();
    assert!(
        cets(&client_start).is_some(),
        "client offers its entitlement"
    );
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let mut server = server::Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        TestGuard::new(NOW_MS),
    );
    let server_start = server
        .read(Epoch::Plaintext, &client_hello, &mut accepting_shard)
        .unwrap();
    assert!(
        cets(&server_start).is_none(),
        "an independently random replay domain cannot authorize 0-RTT",
    );

    let handshake = find_send(&server_start, Epoch::Handshake).unwrap();
    let mut reader = shin::wire::codec::Reader::new(&handshake);
    let mut saw_certificate = false;
    while !reader.is_empty() {
        saw_certificate |= shin::wire::handshake::frame::Frame::decode(&mut reader)
            .unwrap()
            .msg_type()
            == shin::wire::handshake::Type::Certificate;
    }
    assert!(!saw_certificate, "1-RTT PSK resumption remains valid");
}

#[test]
fn explicit_shared_domain_and_atomic_guard_accept_once_across_shards() {
    let domain = ReplayDomain::new([0x6D; 16]);
    let guard = SharedGuard::default();
    let mut issuing_shard = Shard::try_with_early_data_guard_in_replay_domain(
        shard_config(),
        domain.clone(),
        guard.clone(),
    )
    .unwrap();
    let ticket = ticket_from_shard(&mut issuing_shard);
    let mut accepting_shard = Shard::try_with_early_data_guard_in_replay_domain(
        shard_config(),
        domain.clone(),
        guard.clone(),
    )
    .unwrap();
    let mut replay_shard =
        Shard::try_with_early_data_guard_in_replay_domain(shard_config(), domain, guard).unwrap();

    let mut client = client(Some(copy_resumption(&ticket)), true);
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let connection = || Connection {
        transport_params: Vec::new(),
    };
    let mut first_server = server::Server::new(connection(), TestGuard::new(NOW_MS));
    let first = first_server
        .read(Epoch::Plaintext, &client_hello, &mut accepting_shard)
        .unwrap();
    assert!(
        cets(&first).is_some(),
        "another shard in the same deployment replay domain accepts 0-RTT",
    );

    let mut replay_server = server::Server::new(connection(), TestGuard::new(NOW_MS));
    let replay = replay_server
        .read(Epoch::Plaintext, &client_hello, &mut replay_shard)
        .unwrap();
    assert!(
        cets(&replay).is_none(),
        "the shared atomic replay store rejects the replayed ClientHello",
    );
}

#[test]
fn ticket_key_rotation_preserves_shard_replay_domain() {
    let guard = SharedGuard::default();
    let mut shard = Shard::try_with_early_data_guard(shard_config(), guard).unwrap();
    let ticket = ticket_from_shard(&mut shard);
    shard.replace_ticket_keys(Some(shin::crypto::ticket::Keys::with_previous(
        [0x77; 32],
        Some(TICKET_SECRET),
    )));

    let mut client = client(Some(ticket), true);
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let mut server = server::Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        TestGuard::new(NOW_MS),
    );
    let server_start = server
        .read(Epoch::Plaintext, &client_hello, &mut shard)
        .unwrap();
    assert!(
        cets(&server_start).is_some(),
        "key rotation within one Shard must preserve its replay domain",
    );
}

#[test]
fn stale_ticket_outside_freshness_window_rejected() {
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), true);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();

    // Server clock far ahead of issued-at; client claims age ~0 -> exceeds skew.
    let mut s = server(true, NOW_MS + 60_000);
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&s1).is_none(), "stale ticket => early data refused");
}

#[test]
fn early_data_rejected_when_claimed_ticket_age_is_implausible() {
    // RFC 8446 §8.2: claimed ticket age must be within skew of the measured age.
    let mut resumption = first_handshake_ticket();
    resumption.age_millis = 3_600_000;
    let mut c = client(Some(resumption), true);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();

    let mut s = server(true, NOW_MS);
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        cets(&s1).is_none(),
        "implausible claimed ticket age must reject 0-RTT"
    );
    // 1-RTT resumption still proceeds: the binder itself is valid.
    assert!(find_send(&s1, Epoch::Plaintext).is_some());
}

#[test]
fn early_data_accepted_when_resumed_alpn_matches() {
    // Sanity: identical ALPN on the issuing and resuming sessions still accepts 0-RTT.
    let resumption = first_handshake_ticket_cfg(alloc_vec(b"h2"), NOW_MS);
    let mut c = client_alpn(Some(resumption), true, alloc_vec(b"h2"));
    let mut s = server_alpn(true, alloc_vec(b"h2"), NOW_MS);

    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&s1).is_some(), "matching ALPN => early data accepted");
}

#[test]
fn early_data_rejected_when_resumed_alpn_mismatches() {
    // Original session negotiated "h2"; resumption negotiates "http/1.1".
    let resumption = first_handshake_ticket_cfg(alloc_vec(b"h2"), NOW_MS);
    let mut c = client_alpn(Some(resumption), true, alloc_vec(b"http/1.1"));
    let mut s = server_alpn(true, alloc_vec(b"http/1.1"), NOW_MS);

    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        cets(&s1).is_none(),
        "mismatched ALPN must reject 0-RTT (RFC 8446 4.2.10)"
    );
    // Handshake still proceeds (1-RTT): ServerHello + handshake messages emitted.
    assert!(
        find_send(&s1, Epoch::Plaintext).is_some(),
        "server still completes 1-RTT handshake"
    );
    assert!(
        find_send(&s1, Epoch::Handshake).is_some(),
        "server emits handshake messages for 1-RTT fallback"
    );
}

#[test]
fn expired_ticket_does_not_resume_via_psk() {
    // Ticket issued at NOW_MS; resume far beyond TICKET_LIFETIME so PSK is rejected.
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), false);

    // 8 days after issuance (> 7200s lifetime).
    let mut s = server(false, NOW_MS + 8 * 86_400_000);

    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();

    // PSK rejected => full handshake => Certificate is sent in the handshake blob.
    let s_hs_blob = find_send(&s1, Epoch::Handshake).unwrap();
    use shin::wire::codec::Reader;
    use shin::wire::handshake;
    use shin::wire::handshake::frame::Frame;
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(Frame::decode(&mut r).unwrap().msg_type());
    }
    assert!(
        types.contains(&handshake::Type::Certificate),
        "expired ticket must force full handshake (Certificate present); saw {:?}",
        types,
    );
}

#[test]
fn fresh_ticket_still_resumes_via_psk() {
    // Control: ticket within lifetime resumes (no Certificate in handshake blob).
    let resumption = first_handshake_ticket();
    let mut c = client(Some(resumption), false);

    let mut s = server(false, NOW_MS + 1000);

    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();

    let s_hs_blob = find_send(&s1, Epoch::Handshake).unwrap();
    use shin::wire::codec::Reader;
    use shin::wire::handshake;
    use shin::wire::handshake::frame::Frame;
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(Frame::decode(&mut r).unwrap().msg_type());
    }
    assert!(
        !types.contains(&handshake::Type::Certificate),
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
    find_send(&c1, Epoch::Plaintext).unwrap()
}

fn reencode_ch<F: FnOnce(&mut shin::wire::handshake::messages::ClientHello)>(
    ch_bytes: &[u8],
    mutate: F,
) -> Vec<u8> {
    use shin::wire::codec::Reader;
    use shin::wire::handshake::frame::Frame;
    let mut r = Reader::new(ch_bytes);
    let Frame::ClientHello(mut ch) = Frame::decode(&mut r).unwrap() else {
        panic!()
    };
    mutate(&mut ch);
    let mut out = Vec::new();
    Frame::ClientHello(ch).encode(&mut out).unwrap();
    out
}

#[test]
fn server_rejects_nonnull_compression_method() {
    let ch = reencode_ch(&fresh_client_hello(), |ch| {
        ch.legacy_compression_methods = vec![0, 1];
    });
    let mut s = server(false, NOW_MS);
    let err = s.read(Epoch::Plaintext, &ch).unwrap_err();
    assert_eq!(err, shin::connection::Error::IllegalParameter);
}

#[test]
fn server_accepts_null_compression_method() {
    let ch = fresh_client_hello();
    let mut s = server(false, NOW_MS);
    let out = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(find_send(&out, Epoch::Plaintext).is_some());
}

#[test]
fn server_rejects_oversized_session_id() {
    let ch = reencode_ch(&fresh_client_hello(), |ch| {
        ch.legacy_session_id = vec![0u8; 33];
    });
    let mut s = server(false, NOW_MS);
    let err = s.read(Epoch::Plaintext, &ch).unwrap_err();
    assert_eq!(err, shin::connection::Error::Decode);
}

#[test]
fn server_accepts_max_session_id() {
    let ch = reencode_ch(&fresh_client_hello(), |ch| {
        ch.legacy_session_id = vec![7u8; 32];
    });
    let mut s = server(false, NOW_MS);
    let out = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(find_send(&out, Epoch::Plaintext).is_some());
}

// Drive a server to Done, returning it ready for application-epoch messages.
fn established_server() -> Server<TestGuard, TestGuard> {
    let mut s = server(false, NOW_MS);
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    let _ = c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = find_send(&c3, Epoch::Handshake).unwrap();
    let _ = s.read(Epoch::Handshake, &cf).unwrap();
    assert!(s.is_done());
    s
}

#[test]
fn server_caps_key_updates_per_record() {
    use shin::wire::handshake::frame::Frame;
    use shin::wire::handshake::messages::KeyUpdate;
    let mut s = established_server();
    // Many KeyUpdate(request_update=1) in one record => bounded reply amplification.
    let mut record = Vec::new();
    for _ in 0..64 {
        Frame::KeyUpdate(KeyUpdate { request_update: 1 })
            .encode(&mut record)
            .unwrap();
    }
    let err = s.read(Epoch::Application, &record).unwrap_err();
    assert_eq!(err, shin::connection::Error::UnexpectedMessage);
}

#[test]
fn server_allows_bounded_key_updates() {
    use shin::wire::handshake::frame::Frame;
    use shin::wire::handshake::messages::KeyUpdate;
    let mut s = established_server();
    let mut record = Vec::new();
    for _ in 0..8 {
        Frame::KeyUpdate(KeyUpdate { request_update: 0 })
            .encode(&mut record)
            .unwrap();
    }
    s.read(Epoch::Application, &record).unwrap();
}

#[test]
fn nst_advertises_early_data_when_accept_enabled() {
    use shin::wire::codec::Reader;
    use shin::wire::extension::Type;
    use shin::wire::handshake::frame::Frame;

    let mut s = server(true, NOW_MS);
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    let _ = c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = find_send(&c3, Epoch::Handshake).unwrap();
    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    let nst_bytes = find_send(&s2, Epoch::Application).unwrap();

    let mut r = Reader::new(&nst_bytes);
    let Frame::NewSessionTicket(nst) = Frame::decode(&mut r).unwrap() else {
        panic!("expected NewSessionTicket")
    };
    let ext = nst
        .extensions
        .iter()
        .find(|e| e.ty == Type::EARLY_DATA)
        .expect("NST must advertise early_data when 0-RTT accepted");
    assert_eq!(
        ext.data.len(),
        4,
        "early_data body is uint32 max_early_data_size"
    );
}

#[test]
fn nst_does_not_advertise_early_data_without_replay_guard() {
    use shin::wire::codec::Reader;
    use shin::wire::handshake::frame::Frame;

    let mut s = server_no_guard(true, NOW_MS);
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
    let nst_bytes = find_send(&s2, Epoch::Application).unwrap();

    let mut r = Reader::new(&nst_bytes);
    let Frame::NewSessionTicket(nst) = Frame::decode(&mut r).unwrap() else {
        panic!("expected NewSessionTicket")
    };
    assert!(
        nst.extensions
            .iter()
            .all(|extension| extension.ty != Type::EARLY_DATA),
        "0-RTT cannot be advertised when replay protection is unavailable",
    );
}

#[test]
fn nst_omits_early_data_when_accept_disabled() {
    use shin::wire::codec::Reader;
    use shin::wire::extension::Type;
    use shin::wire::handshake::frame::Frame;

    let mut s = server(false, NOW_MS);
    let mut c = client(None, false);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    let _ = c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = find_send(&c3, Epoch::Handshake).unwrap();
    let s2 = s.read(Epoch::Handshake, &cf).unwrap();
    let nst_bytes = find_send(&s2, Epoch::Application).unwrap();

    let mut r = Reader::new(&nst_bytes);
    let Frame::NewSessionTicket(nst) = Frame::decode(&mut r).unwrap() else {
        panic!("expected NewSessionTicket")
    };
    assert!(
        nst.extensions.iter().all(|e| e.ty != Type::EARLY_DATA),
        "NST must not advertise early_data when accept disabled",
    );
}
