use std::sync::{Arc, Mutex};

use shin::client::Client;
use shin::client::config::{Config, NegotiatedAlpn, Restore, Verifier};
use shin::connection::{Clock, Epoch};
use shin::crypto::hash::Digest;
use shin::crypto::sig::SigningKey;
use shin::server::{
    self, ReplayDomain, Shard, config, config::CertSource, config::Connection,
    config::EarlyDataGuard, config::NoGuard,
};
use shin::wire::extension::Type;
use shin::wire::record::CipherSuite;

use crate::common::Event;
use crate::common::{CollectEvents, CollectServerEvents};
use crate::common::{Server, ServerConfig, find_send, replay_domain};

const TICKET_SECRET: [u8; 32] = [0x55u8; 32];

// Fixed clock so the measured ticket age is ~0 in happy-path tests.
const NOW_MS: u64 = 1_700_000_000_000;
type TestClient = Client<fn() -> u64>;

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
        Event::ZeroRttKeysReady { secret, .. } => Some(*secret),
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
        ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET).unwrap()),
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

fn client(restore: Option<Restore<'_>>, enable_early_data: bool) -> Client<fn() -> u64> {
    client_alpn(restore, enable_early_data, Vec::new())
}

fn client_alpn(
    restore: Option<Restore<'_>>,
    enable_early_data: bool,
    alpn_protocols: Vec<Vec<u8>>,
) -> Client<fn() -> u64> {
    let template = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols,
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

fn first_handshake_ticket() -> Restore<'static> {
    first_handshake_ticket_cfg(Vec::new(), NOW_MS)
}

fn first_handshake_ticket_cfg(alpn_protocols: Vec<Vec<u8>>, now_ms: u64) -> Restore<'static> {
    first_handshake_ticket_with_policy(alpn_protocols, now_ms, true)
}

fn first_handshake_ticket_with_policy(
    alpn_protocols: Vec<Vec<u8>>,
    now_ms: u64,
    allow_early_data: bool,
) -> Restore<'static> {
    first_handshake_ticket_for_suite(
        alpn_protocols,
        now_ms,
        allow_early_data,
        CipherSuite::Aes128GcmSha256,
    )
}

fn first_handshake_ticket_for_suite(
    alpn_protocols: Vec<Vec<u8>>,
    now_ms: u64,
    allow_early_data: bool,
    suite: CipherSuite,
) -> Restore<'static> {
    first_handshake_ticket_for_suite_at(alpn_protocols, now_ms, allow_early_data, suite, 0)
}

fn first_handshake_ticket_for_suite_at(
    alpn_protocols: Vec<Vec<u8>>,
    now_ms: u64,
    allow_early_data: bool,
    suite: CipherSuite,
    received_at_ms: u64,
) -> Restore<'static> {
    let mut s = server_alpn(allow_early_data, alpn_protocols.clone(), now_ms);
    let mut c = client_alpn(None, false, alpn_protocols);
    c.set_cipher_suites(&[suite]).unwrap();
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

    let Event::NewSessionTicket {
        psk,
        ticket,
        ticket_age_add,
        ticket_lifetime,
        max_early_data,
        suite,
        transport_mode,
        alpn,
    } = extra
        .into_iter()
        .find(|event| matches!(event, Event::NewSessionTicket { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    let restore =
        Restore::try_new(psk, ticket, ticket_age_add, received_at_ms, ticket_lifetime).unwrap();
    match max_early_data {
        Some(maximum) => restore
            .try_with_early_data(
                maximum,
                suite,
                transport_mode,
                alpn.map_or(NegotiatedAlpn::Absent, |protocol| {
                    NegotiatedAlpn::Protocol(protocol.into())
                }),
            )
            .unwrap(),
        None => restore,
    }
}

fn shard_config() -> config::Config {
    config::Config {
        source: CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET).unwrap()),
    }
}

fn ticket_from_shard<G: EarlyDataGuard>(shard: &mut Shard<G>) -> Restore<'static> {
    let server = server::Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        TestGuard::new(NOW_MS),
    )
    .unwrap();
    let mut server = shard.bind(server).unwrap();
    let mut client = client(None, false);
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let server_start = server.read(Epoch::Plaintext, &client_hello).unwrap();
    let server_hello = find_send(&server_start, Epoch::Plaintext).unwrap();
    let server_handshake = find_send(&server_start, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &server_hello).unwrap();
    let client_finished = client.read(Epoch::Handshake, &server_handshake).unwrap();
    let client_finished = find_send(&client_finished, Epoch::Handshake).unwrap();
    let server_finished = server.read(Epoch::Handshake, &client_finished).unwrap();
    let new_session_ticket = find_send(&server_finished, Epoch::Application).unwrap();
    let ticket_events = client
        .read(Epoch::Application, &new_session_ticket)
        .unwrap();

    ticket_events
        .into_iter()
        .find_map(Event::into_restore)
        .expect("shard issued a restorable ticket")
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
    let m = crate::decode_owned(&mut r).unwrap();
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
        let frame = crate::decode_owned(&mut reader).unwrap();
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
    let m = crate::decode_owned(&mut r).unwrap();
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
            ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET).unwrap()),
        },
        replay_domain(),
        TestGuard::new(NOW_MS),
    )
    .unwrap();
    let connection_config = || Connection {
        transport_params: Vec::new(),
    };

    let s1 = server::Server::new(connection_config(), TestGuard::new(NOW_MS)).unwrap();
    let mut s1 = shard.bind(s1).unwrap();
    let out1 = s1.read(Epoch::Plaintext, &ch).unwrap();
    assert!(cets(&out1).is_some(), "first use accepts early data");
    drop(s1);

    let s2 = server::Server::new(connection_config(), TestGuard::new(NOW_MS)).unwrap();
    let mut s2 = shard.bind(s2).unwrap();
    let out2 = s2.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        cets(&out2).is_none(),
        "replayed binder => early data refused"
    );
}

#[test]
fn different_default_random_domains_reject_zero_rtt_but_keep_psk_resumption() {
    let guard = SharedGuard::default();
    let mut issuing_shard = Shard::with_early_data_guard(shard_config(), guard.clone()).unwrap();
    let ticket = ticket_from_shard(&mut issuing_shard);
    let mut accepting_shard = Shard::with_early_data_guard(shard_config(), guard).unwrap();

    let mut client = client(Some(ticket), true);
    let client_start = client.start().unwrap();
    assert!(
        cets(&client_start).is_some(),
        "client offers its entitlement"
    );
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let server = server::Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        TestGuard::new(NOW_MS),
    )
    .unwrap();
    let mut server = accepting_shard.bind(server).unwrap();
    let server_start = server.read(Epoch::Plaintext, &client_hello).unwrap();
    assert!(
        cets(&server_start).is_none(),
        "an independently random replay domain cannot authorize 0-RTT",
    );

    let handshake = find_send(&server_start, Epoch::Handshake).unwrap();
    let mut reader = shin::wire::codec::Reader::new(&handshake);
    let mut saw_certificate = false;
    while !reader.is_empty() {
        saw_certificate |= crate::decode_owned(&mut reader).unwrap().msg_type()
            == shin::wire::handshake::Type::Certificate;
    }
    assert!(!saw_certificate, "1-RTT PSK resumption remains valid");
}

#[test]
fn explicit_shared_domain_and_shared_guard_accept_once_across_shards() {
    let domain = ReplayDomain::new([0x6D; 16]);
    let guard = SharedGuard::default();
    let mut issuing_shard = Shard::with_early_data_guard_in_replay_domain(
        shard_config(),
        domain.clone(),
        guard.clone(),
    )
    .unwrap();
    let ticket = ticket_from_shard(&mut issuing_shard);
    let mut accepting_shard = Shard::with_early_data_guard_in_replay_domain(
        shard_config(),
        domain.clone(),
        guard.clone(),
    )
    .unwrap();
    let mut replay_shard =
        Shard::with_early_data_guard_in_replay_domain(shard_config(), domain, guard).unwrap();

    let mut client = client(Some(ticket), true);
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let connection = || Connection {
        transport_params: Vec::new(),
    };
    let first_server = server::Server::new(connection(), TestGuard::new(NOW_MS)).unwrap();
    let mut first_server = accepting_shard.bind(first_server).unwrap();
    let first = first_server.read(Epoch::Plaintext, &client_hello).unwrap();
    assert!(
        cets(&first).is_some(),
        "another shard in the same deployment replay domain accepts 0-RTT",
    );

    let replay_server = server::Server::new(connection(), TestGuard::new(NOW_MS)).unwrap();
    let mut replay_server = replay_shard.bind(replay_server).unwrap();
    let replay = replay_server.read(Epoch::Plaintext, &client_hello).unwrap();
    assert!(
        cets(&replay).is_none(),
        "the shared replay store rejects the replayed ClientHello",
    );
}

#[test]
fn ticket_key_rotation_preserves_shard_replay_domain() {
    let guard = SharedGuard::default();
    let mut shard = Shard::with_early_data_guard(shard_config(), guard).unwrap();
    let ticket = ticket_from_shard(&mut shard);
    shard.replace_ticket_keys(Some(
        shin::crypto::ticket::Keys::with_previous([0x77; 32], Some(TICKET_SECRET)).unwrap(),
    ));

    let mut client = client(Some(ticket), true);
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let server = server::Server::new(
        Connection {
            transport_params: Vec::new(),
        },
        TestGuard::new(NOW_MS),
    )
    .unwrap();
    let mut server = shard.bind(server).unwrap();
    let server_start = server.read(Epoch::Plaintext, &client_hello).unwrap();
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
    let resumption = first_handshake_ticket_for_suite_at(
        Vec::new(),
        NOW_MS,
        true,
        CipherSuite::Aes128GcmSha256,
        NOW_MS - 3_600_000,
    );
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
    let restored_profile = c1.iter().find_map(|event| match event {
        Event::ZeroRttKeysReady {
            max_early_data,
            alpn,
            ..
        } => Some((*max_early_data, alpn.as_deref())),
        _ => None,
    });
    assert_eq!(restored_profile, Some((16_384, Some(b"h2".as_slice()))));
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
    assert!(
        cets(&c1).is_none(),
        "an ALPN that cannot bind to the endpoint must drop only 0-RTT authority"
    );
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
fn early_data_rejected_when_resumed_cipher_suite_differs() {
    use shin::wire::codec::Reader;
    use shin::wire::handshake::frame::Frame;

    let resumption = first_handshake_ticket_for_suite(
        Vec::new(),
        NOW_MS,
        true,
        CipherSuite::ChaCha20Poly1305Sha256,
    );
    let mut client = client(Some(resumption), true);
    let mut server = server(true, NOW_MS);

    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let server_start = server.read(Epoch::Plaintext, &client_hello).unwrap();
    assert!(
        cets(&server_start).is_none(),
        "0-RTT requires the ticket's exact cipher suite",
    );
    let server_hello = find_send(&server_start, Epoch::Plaintext).unwrap();
    let Frame::ServerHello(server_hello) =
        crate::decode_owned(&mut Reader::new(&server_hello)).unwrap()
    else {
        panic!("expected ServerHello");
    };
    assert!(
        server_hello
            .extensions
            .iter()
            .any(|extension| extension.ty == Type::PRE_SHARED_KEY),
        "a different SHA-256 suite still permits 1-RTT resumption",
    );
}

fn rewrite_early_data_acceptance(flight: &[u8], early_data_first: bool, body: &[u8]) -> Vec<u8> {
    use shin::wire::codec::Reader;
    use shin::wire::extension::Extension;
    use shin::wire::handshake::frame::Frame;

    let mut encoded = Vec::new();
    let mut reader = Reader::new(flight);
    while !reader.is_empty() {
        match crate::decode_owned(&mut reader).unwrap() {
            Frame::EncryptedExtensions(mut extensions) => {
                extensions
                    .extensions
                    .retain(|extension| extension.ty != Type::EARLY_DATA);
                let early_data = Extension::new(Type::EARLY_DATA, body.to_vec());
                if early_data_first {
                    extensions.extensions.insert(0, early_data);
                } else {
                    extensions.extensions.push(early_data);
                }
                Frame::EncryptedExtensions(extensions)
                    .encode(&mut encoded)
                    .unwrap();
            }
            frame => frame.encode(&mut encoded).unwrap(),
        }
    }
    encoded
}

#[test]
fn client_rejects_nonempty_early_data_acceptance() {
    let resumption = first_handshake_ticket();
    let mut client = client(Some(resumption), true);
    let mut server = server(true, NOW_MS);

    let client_start = client.start().unwrap();
    let server_start = server
        .read(
            Epoch::Plaintext,
            &find_send(&client_start, Epoch::Plaintext).unwrap(),
        )
        .unwrap();
    client
        .read(
            Epoch::Plaintext,
            &find_send(&server_start, Epoch::Plaintext).unwrap(),
        )
        .unwrap();
    let malformed = rewrite_early_data_acceptance(
        &find_send(&server_start, Epoch::Handshake).unwrap(),
        false,
        &[0],
    );

    assert_eq!(
        client.read(Epoch::Handshake, &malformed).unwrap_err(),
        shin::connection::Error::Decode,
    );
}

#[test]
fn client_rejects_early_acceptance_under_a_different_suite() {
    let restore = first_handshake_ticket_for_suite(
        Vec::new(),
        NOW_MS,
        true,
        CipherSuite::ChaCha20Poly1305Sha256,
    );
    let mut client = client(Some(restore), true);
    let mut server = server(true, NOW_MS);

    let client_start = client.start().unwrap();
    assert!(cets(&client_start).is_some());
    let server_start = server
        .read(
            Epoch::Plaintext,
            &find_send(&client_start, Epoch::Plaintext).unwrap(),
        )
        .unwrap();
    assert!(cets(&server_start).is_none());
    client
        .read(
            Epoch::Plaintext,
            &find_send(&server_start, Epoch::Plaintext).unwrap(),
        )
        .unwrap();
    let tampered = rewrite_early_data_acceptance(
        &find_send(&server_start, Epoch::Handshake).unwrap(),
        false,
        &[],
    );

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        shin::connection::Error::IllegalParameter,
    );
}

#[test]
fn client_rejects_early_acceptance_under_a_different_alpn_in_any_order() {
    let restore = first_handshake_ticket_cfg(alloc_vec(b"h2"), NOW_MS);
    let mut client = client_alpn(
        Some(restore),
        true,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    );
    let mut server = server_alpn(true, vec![b"http/1.1".to_vec(), b"h2".to_vec()], NOW_MS);

    let client_start = client.start().unwrap();
    assert!(cets(&client_start).is_some());
    let server_start = server
        .read(
            Epoch::Plaintext,
            &find_send(&client_start, Epoch::Plaintext).unwrap(),
        )
        .unwrap();
    assert!(cets(&server_start).is_none());
    client
        .read(
            Epoch::Plaintext,
            &find_send(&server_start, Epoch::Plaintext).unwrap(),
        )
        .unwrap();
    let tampered = rewrite_early_data_acceptance(
        &find_send(&server_start, Epoch::Handshake).unwrap(),
        true,
        &[],
    );

    assert_eq!(
        client.read(Epoch::Handshake, &tampered).unwrap_err(),
        shin::connection::Error::IllegalParameter,
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
    use shin::wire::handshake::frame::MessageRef;
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(MessageRef::decode_from(&mut r).unwrap().msg_type());
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
    use shin::wire::handshake::frame::MessageRef;
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(MessageRef::decode_from(&mut r).unwrap().msg_type());
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
    let Frame::ClientHello(mut ch) = crate::decode_owned(&mut r).unwrap() else {
        panic!()
    };
    mutate(&mut ch);
    let mut out = Vec::new();
    Frame::ClientHello(ch).encode(&mut out).unwrap();
    out
}

#[test]
fn server_rejects_nonempty_client_hello_early_data() {
    use shin::wire::extension::Extension;

    let malformed = reencode_ch(&fresh_client_hello(), |hello| {
        hello
            .extensions
            .push(Extension::new(Type::EARLY_DATA, vec![0]));
    });
    let mut server = server(false, NOW_MS);

    assert_eq!(
        server.read(Epoch::Plaintext, &malformed).unwrap_err(),
        shin::connection::Error::Decode,
    );
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
        Frame::KeyUpdate(KeyUpdate {
            request: shin::wire::handshake::KeyUpdateRequest::Requested,
        })
        .encode(&mut record)
        .unwrap();
    }
    let err = s.read(Epoch::Application, &record).unwrap_err();
    assert_eq!(err, shin::connection::Error::UnexpectedMessage);
}

#[test]
fn requested_key_updates_coalesce_until_the_response_is_drained() {
    use std::convert::Infallible;

    use shin::connection::{EventContext, EventSink, KeyDirection};
    use shin::wire::handshake::KeyUpdateRequest;
    use shin::wire::handshake::frame::Frame;
    use shin::wire::handshake::messages::KeyUpdate;

    #[derive(Default)]
    struct ResponseEvents {
        sends: usize,
        write_updates: usize,
    }

    impl EventSink for ResponseEvents {
        type Error = Infallible;

        fn event(
            &mut self,
            event: shin::connection::Event<'_>,
            _context: EventContext,
        ) -> Result<(), Self::Error> {
            match event {
                shin::connection::Event::Send {
                    epoch: Epoch::Application,
                    ..
                } => self.sends += 1,
                shin::connection::Event::KeyUpdate {
                    direction: KeyDirection::Write,
                    ..
                } => self.write_updates += 1,
                _ => {}
            }
            Ok(())
        }
    }

    let mut server = established_server();
    let mut record = Vec::new();
    for _ in 0..2 {
        Frame::KeyUpdate(KeyUpdate {
            request: KeyUpdateRequest::Requested,
        })
        .encode(&mut record)
        .unwrap();
    }
    let received = server.read(Epoch::Application, &record).unwrap();
    assert_eq!(
        received
            .iter()
            .filter(|event| matches!(
                event,
                Event::KeyUpdate {
                    direction: KeyDirection::Read,
                    ..
                }
            ))
            .count(),
        2
    );
    assert!(!received.iter().any(|event| matches!(
        event,
        Event::Send {
            epoch: Epoch::Application,
            ..
        }
    )));
    assert!(server.key_updates().response_pending());
    server.key_updates().note_application_data();
    assert!(server.key_updates().response_pending());

    let mut response = ResponseEvents::default();
    server
        .key_updates()
        .send_into(KeyUpdateRequest::Requested, &mut response)
        .unwrap();
    assert_eq!((response.sends, response.write_updates), (1, 1));
    assert!(server.key_updates().response_pending());

    server
        .key_updates()
        .send_pending_into(&mut response)
        .unwrap();
    assert_eq!((response.sends, response.write_updates), (2, 2));
    assert!(!server.key_updates().response_pending());

    server
        .key_updates()
        .send_pending_into(&mut response)
        .unwrap();
    assert_eq!((response.sends, response.write_updates), (2, 2));
}

#[test]
fn server_allows_bounded_key_updates() {
    use shin::wire::handshake::frame::Frame;
    use shin::wire::handshake::messages::KeyUpdate;
    let mut s = established_server();
    let mut record = Vec::new();
    for _ in 0..8 {
        Frame::KeyUpdate(KeyUpdate {
            request: shin::wire::handshake::KeyUpdateRequest::NotRequested,
        })
        .encode(&mut record)
        .unwrap();
    }
    s.read(Epoch::Application, &record).unwrap();
}

fn client_waiting_for_ticket() -> (TestClient, Vec<u8>) {
    let mut server = server(false, NOW_MS);
    let mut client = client(None, false);
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let server_start = server.read(Epoch::Plaintext, &client_hello).unwrap();
    let server_hello = find_send(&server_start, Epoch::Plaintext).unwrap();
    let server_handshake = find_send(&server_start, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &server_hello).unwrap();
    let client_finished = client.read(Epoch::Handshake, &server_handshake).unwrap();
    let client_finished = find_send(&client_finished, Epoch::Handshake).unwrap();
    let server_finished = server.read(Epoch::Handshake, &client_finished).unwrap();
    let ticket = find_send(&server_finished, Epoch::Application).unwrap();
    (client, ticket)
}

fn rewrite_ticket(
    encoded: &[u8],
    edit: impl FnOnce(&mut shin::wire::handshake::messages::NewSessionTicket),
) -> Vec<u8> {
    use shin::wire::codec::Reader;
    use shin::wire::handshake::frame::Frame;

    let Frame::NewSessionTicket(mut ticket) =
        crate::decode_owned(&mut Reader::new(encoded)).unwrap()
    else {
        panic!("expected NewSessionTicket");
    };
    edit(&mut ticket);
    let mut encoded = Vec::new();
    Frame::NewSessionTicket(ticket)
        .encode(&mut encoded)
        .unwrap();
    encoded
}

#[derive(Default)]
struct CountTicketEvents(usize);

impl shin::connection::EventSink for CountTicketEvents {
    type Error = core::convert::Infallible;

    fn event(
        &mut self,
        event: shin::connection::Event<'_>,
        _context: shin::connection::EventContext,
    ) -> Result<(), Self::Error> {
        self.0 += usize::from(matches!(
            event,
            shin::connection::Event::NewSessionTicket(_)
        ));
        Ok(())
    }
}

#[test]
fn malformed_ticket_is_rejected_before_event_emission() {
    use shin::connection::{DriveError, Error};
    use shin::wire::extension::{Extension, Type};

    let (mut client, ticket) = client_waiting_for_ticket();
    let ticket = rewrite_ticket(&ticket, |ticket| {
        ticket
            .extensions
            .push(Extension::new(Type::EARLY_DATA, vec![0]));
    });
    let mut events = CountTicketEvents::default();

    assert_eq!(
        client.read_into(Epoch::Application, &ticket, &mut events),
        Err(DriveError::Protocol(Error::Decode)),
    );
    assert_eq!(events.0, 0);
}

#[test]
fn empty_ticket_is_rejected_before_event_emission() {
    use shin::connection::{DriveError, Error};

    let (mut client, ticket) = client_waiting_for_ticket();
    let ticket = rewrite_ticket(&ticket, |ticket| ticket.ticket.clear());
    let mut events = CountTicketEvents::default();

    assert_eq!(
        client.read_into(Epoch::Application, &ticket, &mut events),
        Err(DriveError::Protocol(Error::Decode)),
    );
    assert_eq!(events.0, 0);
}

#[test]
fn zero_lifetime_ticket_is_discarded_without_an_event() {
    let (mut client, ticket) = client_waiting_for_ticket();
    let ticket = rewrite_ticket(&ticket, |ticket| ticket.ticket_lifetime = 0);
    let mut events = CountTicketEvents::default();

    client
        .read_into(Epoch::Application, &ticket, &mut events)
        .unwrap();
    assert_eq!(events.0, 0);
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
    let Frame::NewSessionTicket(nst) = crate::decode_owned(&mut r).unwrap() else {
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
    let Frame::NewSessionTicket(nst) = crate::decode_owned(&mut r).unwrap() else {
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
    let Frame::NewSessionTicket(nst) = crate::decode_owned(&mut r).unwrap() else {
        panic!("expected NewSessionTicket")
    };
    assert!(
        nst.extensions.iter().all(|e| e.ty != Type::EARLY_DATA),
        "NST must not advertise early_data when accept disabled",
    );
}
