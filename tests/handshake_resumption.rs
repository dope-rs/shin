use shin::client::{Client, Config as ClientConfig, Resumption, Verifier};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

const TICKET_SECRET: [u8; 32] = [0x33u8; 32];

fn extract_send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x55u8; 32]).unwrap()
}

fn fresh_server() -> Server {
    Server::new(ServerConfig {
        source: CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: false,
    })
}

fn fresh_client(resumption: Option<Resumption>) -> Client {
    Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption,
        enable_early_data: false,
    })
}

fn drive(client: &mut Client, server: &mut Server) -> (Vec<Event>, Vec<Event>) {
    let mut all_client = Vec::new();
    let mut all_server = Vec::new();

    let c1 = client.start().unwrap();
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    all_client.extend(c1);

    let s1 = server.read(Epoch::Plaintext, &ch).unwrap();
    let sh = extract_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = extract_send(&s1, Epoch::Handshake).unwrap();
    all_server.extend(s1);

    let c2 = client.read(Epoch::Plaintext, &sh).unwrap();
    all_client.extend(c2);
    let c3 = client.read(Epoch::Handshake, &s_hs).unwrap();
    let cf = extract_send(&c3, Epoch::Handshake).unwrap();
    all_client.extend(c3);

    let s2 = server.read(Epoch::Handshake, &cf).unwrap();
    all_server.extend(s2);

    let nst = extract_send(&all_server, Epoch::Application);
    if let Some(bytes) = nst {
        let extra = client.read(Epoch::Application, &bytes).unwrap();
        all_client.extend(extra);
    }
    (all_client, all_server)
}

fn first_session_ticket(events: &[Event]) -> Option<(Resumption, [u8; 32])> {
    let mut psk: Option<[u8; 32]> = None;
    for e in events {
        if let Event::ResumptionSecret { psk: p } = e {
            psk = Some(*p);
        }
        if let Event::NewSessionTicket {
            ticket_age_add,
            ticket,
            ..
        } = e
        {
            return Some((
                Resumption {
                    psk: psk.expect("ResumptionSecret precedes NewSessionTicket"),
                    ticket: ticket.clone(),
                    ticket_age_add: *ticket_age_add,
                    age_millis: 0,
                },
                psk.unwrap(),
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
    let ch = extract_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = server2.read(Epoch::Plaintext, &ch).unwrap();
    let s_hs_blob = extract_send(&s1, Epoch::Handshake).unwrap();

    use shin::codec::Reader;
    use shin::handshake::{Handshake, HandshakeType};
    let mut r = Reader::new(&s_hs_blob);
    let mut types = Vec::new();
    while !r.is_empty() {
        let snap = r.remaining();
        let m = Handshake::decode(&mut r).unwrap();
        let _ = snap;
        types.push(m.msg_type());
    }
    assert!(
        !types.contains(&HandshakeType::Certificate),
        "PSK resumption must skip Certificate; saw {:?}",
        types,
    );
    assert!(
        !types.contains(&HandshakeType::CertificateVerify),
        "PSK resumption must skip CertificateVerify",
    );
    assert!(
        types.contains(&HandshakeType::EncryptedExtensions),
        "EE still required",
    );
    assert!(
        types.contains(&HandshakeType::Finished),
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
