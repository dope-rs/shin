use ring::rand::SystemRandom;
use shin::client::Client;
use shin::client::config::{Config, Restore, Verifier};
use shin::connection::Epoch;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::{Keys, Rotator};
use shin::server::config::CertSource;

use crate::common::CollectEvents;
use crate::common::Event;
use crate::common::{FixedClock, Server, ServerConfig, find_send};

const TICKET_SECRET: [u8; 32] = [0x33u8; 32];

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x55u8; 32]).unwrap()
}

fn server_with(keys: Option<Keys>, now_ms: u64) -> Server<FixedClock> {
    Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: keys,
            accept_early_data: false,
        },
        FixedClock(now_ms),
    )
}

fn fresh_client(restore: Option<Restore<'_>>) -> Client<fn() -> u64> {
    let template = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
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

fn full_handshake(client: &mut Client<fn() -> u64>, server: &mut Server<FixedClock>) -> Vec<Event> {
    let mut client_events = Vec::new();
    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    client_events.extend(c1);

    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();

    client_events.extend(client.read(Epoch::Plaintext, &sh).unwrap());
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = find_send(&c3, Epoch::Handshake).unwrap();
    client_events.extend(c3);

    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    if let Some(nst) = find_send(&s2, Epoch::Application) {
        client_events.extend(client.read(Epoch::Application, &nst).unwrap());
    }
    client_events
}

fn ticket_from(events: &[Event]) -> Option<Restore<'static>> {
    for e in events {
        if let Event::NewSessionTicket {
            psk,
            ticket_lifetime,
            ticket_age_add,
            ticket,
            ..
        } = e
        {
            return Restore::try_new(*psk, ticket.clone(), *ticket_age_add, 0, *ticket_lifetime)
                .ok();
        }
    }
    None
}

fn server_resumed(server: &mut Server<FixedClock>, restore: Restore<'_>) -> bool {
    use shin::wire::codec::Reader;
    use shin::wire::handshake::Type;
    use shin::wire::handshake::views::MessageRef;

    let mut client = fresh_client(Some(restore));
    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();

    let mut r = Reader::new(&s_hs);
    let mut saw_cert = false;
    while !r.is_empty() {
        let m = MessageRef::decode_from(&mut r).unwrap();
        if m.msg_type() == Type::Certificate {
            saw_cert = true;
        }
    }
    // Resumption skips Certificate; a full handshake sends it.
    !saw_cert
}

#[test]
fn expired_ticket_is_rejected_even_without_early_data_guard() {
    const ISSUE_MS: u64 = 1_000_000;
    let mut issuing = server_with(Some(Keys::single(TICKET_SECRET).unwrap()), ISSUE_MS);
    let mut client = fresh_client(None);
    let events = full_handshake(&mut client, &mut issuing);
    let stale_resumption = ticket_from(&events).expect("ticket issued");

    let mut issuing = server_with(Some(Keys::single(TICKET_SECRET).unwrap()), ISSUE_MS);
    let mut client = fresh_client(None);
    let events = full_handshake(&mut client, &mut issuing);
    let fresh_resumption = ticket_from(&events).expect("second ticket issued");

    // Past lifetime (7200s) plus skew -> must not resume.
    let mut stale = server_with(
        Some(Keys::single(TICKET_SECRET).unwrap()),
        ISSUE_MS + 7_300_000,
    );
    assert!(
        !server_resumed(&mut stale, stale_resumption),
        "expired ticket must force a full handshake",
    );

    // Well inside lifetime -> resumes.
    let mut fresh = server_with(
        Some(Keys::single(TICKET_SECRET).unwrap()),
        ISSUE_MS + 60_000,
    );
    assert!(
        server_resumed(&mut fresh, fresh_resumption),
        "fresh ticket must resume",
    );
}

#[test]
fn ticket_issued_under_previous_key_still_accepted_after_rotation() {
    const ISSUE_MS: u64 = 5_000_000;
    let rng = SystemRandom::new();
    // Rotate after a single issuance so the next call rolls the key.
    let mut rotator = Rotator::new(&rng, ISSUE_MS, u64::MAX, 1).unwrap();

    let keys_v1 = rotator.issuing_keys(&rng, ISSUE_MS).unwrap();
    let mut issuing = server_with(Some(keys_v1), ISSUE_MS);
    let events = full_handshake(&mut fresh_client(None), &mut issuing);
    let resumption = ticket_from(&events).expect("ticket issued");

    // Trigger rotation: current becomes previous, a brand-new current appears.
    let keys_v2 = rotator.issuing_keys(&rng, ISSUE_MS + 1000).unwrap();
    let mut rotated = server_with(Some(keys_v2), ISSUE_MS + 1000);
    assert!(
        server_resumed(&mut rotated, resumption),
        "ticket from previous key must still resume across one rotation",
    );
}

#[test]
fn ticket_two_rotations_old_renders_undecryptable() {
    const ISSUE_MS: u64 = 9_000_000;
    let rng = SystemRandom::new();
    let mut rotator = Rotator::new(&rng, ISSUE_MS, u64::MAX, 1).unwrap();

    let keys_v1 = rotator.issuing_keys(&rng, ISSUE_MS).unwrap();
    let mut issuing = server_with(Some(keys_v1), ISSUE_MS);
    let events = full_handshake(&mut fresh_client(None), &mut issuing);
    let resumption = ticket_from(&events).expect("ticket issued");

    rotator.issuing_keys(&rng, ISSUE_MS + 1).unwrap(); // v1 -> previous
    let keys_v3 = rotator.issuing_keys(&rng, ISSUE_MS + 2).unwrap(); // v1 dropped
    let mut rotated = server_with(Some(keys_v3), ISSUE_MS + 2);
    assert!(
        !server_resumed(&mut rotated, resumption),
        "ticket two rotations old must no longer decrypt",
    );
}
