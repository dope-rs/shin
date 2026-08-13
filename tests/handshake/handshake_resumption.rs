use shin::client::Client;
use shin::client::config::{Config, Restore, Verifier};
use shin::connection::Epoch;
use shin::crypto::sig::SigningKey;
use shin::server::config::CertSource;

use crate::common::CollectEvents;
use crate::common::Event;
use crate::common::{FixedClock, Server, ServerConfig, find_send};

const TICKET_SECRET: [u8; 32] = [0x33u8; 32];

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x55u8; 32]).unwrap()
}

fn fresh_server() -> Server<FixedClock> {
    Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET).unwrap()),
            accept_early_data: false,
        },
        FixedClock(1_000_000),
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

fn drive(
    client: &mut Client<fn() -> u64>,
    server: &mut Server<FixedClock>,
) -> (Vec<Event>, Vec<Event>) {
    let mut all_client = Vec::new();
    let mut all_server = Vec::new();

    let c1 = client.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    all_client.extend(c1);

    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    all_server.extend(s1);

    let c2 = client.read(Epoch::Plaintext, &sh).unwrap();
    all_client.extend(c2);
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = find_send(&c3, Epoch::Handshake).unwrap();
    all_client.extend(c3);

    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    all_server.extend(s2);

    let nst = find_send(&all_server, Epoch::Application);
    if let Some(bytes) = nst {
        let extra = client.read(Epoch::Application, &bytes).unwrap();
        all_client.extend(extra);
    }
    (all_client, all_server)
}

fn first_session_ticket(events: &[Event]) -> Option<(Restore<'static>, [u8; 32])> {
    for e in events {
        if let Event::NewSessionTicket {
            psk,
            ticket_lifetime,
            ticket_age_add,
            ticket,
            ..
        } = e
        {
            return Some((
                Restore::try_new(*psk, ticket.clone(), *ticket_age_add, 0, *ticket_lifetime)
                    .unwrap(),
                *psk,
            ));
        }
    }
    None
}

#[test]
fn resumed_handshake_skips_certificate_and_certificate_verify() {
    let mut server1 = fresh_server();
    let mut client1 = fresh_client(None);
    let (c_events, _) = drive(&mut client1, &mut server1);
    let (resumption, _psk) = first_session_ticket(&c_events).expect("ticket emitted");

    let mut server2 = fresh_server();
    let mut client2 = fresh_client(Some(resumption));

    let c1 = client2.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server2.read(Epoch::Plaintext, &ch).unwrap();
    let s_hs_blob = find_send(&s1, Epoch::Handshake).unwrap();

    use shin::wire::codec::Reader;
    use shin::wire::handshake::Type;
    use shin::wire::handshake::views::MessageRef;
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        let snap = r.remaining();
        let m = MessageRef::decode_from(&mut r).unwrap();
        let _ = snap;
        types.push(m.msg_type());
    }
    assert!(
        !types.contains(&Type::Certificate),
        "PSK resumption must skip Certificate; saw {:?}",
        types,
    );
    assert!(
        !types.contains(&Type::CertificateVerify),
        "PSK resumption must skip CertificateVerify",
    );
    assert!(
        types.contains(&Type::EncryptedExtensions),
        "EE still required",
    );
    assert!(
        types.contains(&Type::Finished),
        "ServerFinished still required",
    );
}

#[test]
fn resumed_handshake_completes_end_to_end() {
    let mut server1 = fresh_server();
    let mut client1 = fresh_client(None);
    let (c_events, _) = drive(&mut client1, &mut server1);
    let (resumption, _) = first_session_ticket(&c_events).expect("ticket emitted");

    let mut server2 = fresh_server();
    let mut client2 = fresh_client(Some(resumption));
    let (c2_events, s2_events) = drive(&mut client2, &mut server2);
    assert!(
        c2_events.iter().any(|e| matches!(e, Event::Done)),
        "client done on resumption",
    );
    assert!(
        s2_events.iter().any(|e| matches!(e, Event::Done)),
        "server done on resumption",
    );
}
