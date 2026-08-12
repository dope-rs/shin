use shin::client::Client;
use shin::client::config::{Config, Restore, Verifier};
use shin::connection::{Clock, Epoch};
use shin::crypto::hash::Digest;
use shin::crypto::sig::SigningKey;
use shin::server::{config::CertSource, config::EarlyDataGuard};
use shin::transport::Mode;
use shin::wire::handshake::KeyUpdateRequest;

use crate::common::CollectEvents;
use crate::common::Event;
use crate::common::{Server, ServerConfig, find_send};

const TICKET_SECRET: [u8; 32] = [0x55u8; 32];
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

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&[0x99u8; 32]).unwrap()
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

fn sends(events: &[Event], epoch: Epoch) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Send { epoch: sent, data } if *sent == epoch => Some(data.clone()),
            _ => None,
        })
        .collect()
}

fn server(accept: bool) -> Server<TestGuard, TestGuard> {
    server_with_transport(accept, Mode::Tls)
}

fn server_with_transport(accept: bool, transport_mode: Mode) -> Server<TestGuard, TestGuard> {
    server_with_transport_params(accept, transport_mode, Vec::new())
}

fn server_with_transport_params(
    accept: bool,
    transport_mode: Mode,
    transport_params: Vec<u8>,
) -> Server<TestGuard, TestGuard> {
    Server::with_early_data_guard_and_transport(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing_key(),
            },
            transport_params,
            alpn_protocols: Vec::new(),
            ticket_keys: Some(shin::crypto::ticket::Keys::single(TICKET_SECRET).unwrap()),
            accept_early_data: accept,
        },
        transport_mode,
        TestGuard::new(NOW_MS),
        TestGuard::new(NOW_MS),
    )
}

fn client(restore: Option<Restore<'_>>, enable_early_data: bool) -> Client<fn() -> u64> {
    client_with_transport(restore, enable_early_data, Mode::Tls)
}

fn client_with_transport(
    restore: Option<Restore<'_>>,
    enable_early_data: bool,
    transport_mode: Mode,
) -> Client<fn() -> u64> {
    let template = Config {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: *signing_key().pubkey().unwrap(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data,
    }
    .try_into_template_with_transport(transport_mode)
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
    issue_ticket_with_transport(Mode::Tls, true).0
}

fn issue_ticket_with_transport(
    transport_mode: Mode,
    advertise_early_data: bool,
) -> (Restore<'static>, Option<u32>) {
    let mut s = server_with_transport(advertise_early_data, transport_mode);
    let mut c = client_with_transport(None, false, transport_mode);
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

    let ticket = extra
        .into_iter()
        .find(|event| matches!(event, Event::NewSessionTicket { .. }))
        .unwrap();
    let maximum = match &ticket {
        Event::NewSessionTicket { max_early_data, .. } => *max_early_data,
        _ => None,
    };
    (ticket.into_restore().unwrap(), maximum)
}

#[test]
fn full_zero_rtt_handshake_completes_via_end_of_early_data() {
    let mut c = client(Some(issue_ticket()), true);
    let mut s = server(true);

    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let client_cets = c1.iter().find_map(|e| match e {
        Event::ZeroRttKeysReady { secret, .. } => Some(*secret),
        _ => None,
    });
    assert!(client_cets.is_some(), "client must emit 0-RTT keys");

    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    let (s_app_read, s_app_write) = app_keys(&s1).unwrap();

    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();

    assert!(
        has(&c3, &Event::EarlyDataAccepted),
        "expected QUIC early-data acceptance, events={c3:?}"
    );
    let handshake_sends = sends(&c3, Epoch::Handshake);
    assert_eq!(handshake_sends.len(), 2);
    let eod = &handshake_sends[0];
    let cf = &handshake_sends[1];
    assert!(has(&c3, &Event::Done));
    let (c_app_read, c_app_write) = app_keys(&c3).unwrap();

    assert_eq!(c_app_read, s_app_write);
    assert_eq!(c_app_write, s_app_read);

    s.read(Epoch::Handshake, eod).unwrap();
    let s2 = s.read(Epoch::Handshake, cf).unwrap();
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
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();

    assert!(has(&c3, &Event::EarlyDataRejected));
    let handshake_sends = sends(&c3, Epoch::Handshake);
    assert_eq!(handshake_sends.len(), 1, "no EndOfEarlyData when rejected");
    let cf = &handshake_sends[0];
    assert!(has(&c3, &Event::Done));

    let s2 = s.read(Epoch::Handshake, cf).unwrap();
    assert!(has(&s2, &Event::Done));
    assert!(s.is_done());
}

#[test]
fn server_rejects_finished_before_end_of_early_data() {
    let mut c = client(Some(issue_ticket()), true);
    let mut s = server(true);

    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    let handshake_sends = sends(&c3, Epoch::Handshake);
    assert_eq!(handshake_sends.len(), 2);
    let cf = &handshake_sends[1];

    assert_eq!(
        s.read(Epoch::Handshake, cf).unwrap_err(),
        shin::connection::Error::UnexpectedMessage
    );
}

#[test]
fn quic_zero_rtt_uses_sentinel_and_omits_end_of_early_data() {
    let (ticket, maximum) = issue_ticket_with_transport(Mode::Quic, true);
    assert_eq!(maximum, Some(u32::MAX));

    let mut c = client_with_transport(Some(ticket), true, Mode::Quic);
    let mut s = server_with_transport(true, Mode::Quic);
    let c1 = c.start().unwrap();
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        s1.iter()
            .any(|event| matches!(event, Event::ZeroRttKeysReady { .. })),
        "server did not accept QUIC 0-RTT, events={s1:?}"
    );
    let sh = find_send(&s1, Epoch::Plaintext).unwrap();
    let s_hs = find_send(&s1, Epoch::Handshake).unwrap();
    let mut encoded = shin::wire::codec::Reader::new(&s_hs);
    let mut server_advertised_early_data = false;
    while !encoded.is_empty() {
        if let shin::wire::handshake::frame::Frame::EncryptedExtensions(extensions) =
            crate::decode_owned(&mut encoded).unwrap()
        {
            server_advertised_early_data = extensions
                .extensions
                .iter()
                .any(|extension| extension.ty == shin::wire::extension::Type::EARLY_DATA);
        }
    }
    assert!(server_advertised_early_data);

    c.read(Epoch::Plaintext, &sh).unwrap();
    let c3 = c.read(Epoch::Handshake, &s_hs).unwrap();
    assert!(
        has(&c3, &Event::EarlyDataAccepted),
        "expected QUIC early-data acceptance, events={c3:?}"
    );
    assert_eq!(s.max_early_data_size(), Some(u32::MAX));

    let handshake_sends = sends(&c3, Epoch::Handshake);
    assert_eq!(
        handshake_sends.len(),
        1,
        "QUIC sends Finished directly without EndOfEarlyData"
    );
    assert_eq!(
        handshake_sends[0].first().copied(),
        Some(shin::wire::handshake::Type::Finished as u8),
    );
    let s2 = s.read(Epoch::Handshake, &handshake_sends[0]).unwrap();
    assert!(has(&s2, &Event::Done));
    assert_eq!(s.max_early_data_size(), None);

    struct Ignore;
    impl shin::connection::EventSink for Ignore {
        type Error = core::convert::Infallible;

        fn event(
            &mut self,
            _event: shin::connection::Event<'_>,
            _context: shin::connection::EventContext,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    assert!(matches!(
        c.key_updates()
            .send_into(KeyUpdateRequest::NotRequested, &mut Ignore),
        Err(shin::connection::DriveError::Protocol(
            shin::connection::Error::UnexpectedMessage
        ))
    ));
    assert!(matches!(
        s.key_updates()
            .send_into(KeyUpdateRequest::NotRequested, &mut Ignore),
        Err(shin::connection::DriveError::Protocol(
            shin::connection::Error::UnexpectedMessage
        ))
    ));

    let key_update = [shin::wire::handshake::Type::KeyUpdate as u8, 0, 0, 1, 0];
    assert_eq!(
        c.read(Epoch::Application, &key_update).unwrap_err(),
        shin::connection::Error::UnexpectedMessage,
    );
    assert_eq!(
        s.read(Epoch::Application, &key_update).unwrap_err(),
        shin::connection::Error::UnexpectedMessage,
    );
}

#[test]
fn changed_server_transport_params_reject_zero_rtt_but_keep_psk_resumption() {
    let (ticket, maximum) = issue_ticket_with_transport(Mode::Quic, true);
    assert_eq!(maximum, Some(u32::MAX));

    let mut c = client_with_transport(Some(ticket), true, Mode::Quic);
    let mut s = server_with_transport_params(
        true,
        Mode::Quic,
        b"changed server transport parameters".to_vec(),
    );
    let c1 = c.start().unwrap();
    assert!(
        c1.iter()
            .any(|event| matches!(event, Event::ZeroRttKeysReady { .. })),
        "the client may offer using its stored entitlement"
    );
    let ch = find_send(&c1, Epoch::Plaintext).unwrap();
    let s1 = s.read(Epoch::Plaintext, &ch).unwrap();
    assert!(
        !s1.iter()
            .any(|event| matches!(event, Event::ZeroRttKeysReady { .. })),
        "the authenticated server TP context must reject 0-RTT"
    );

    let handshake = find_send(&s1, Epoch::Handshake).unwrap();
    let mut reader = shin::wire::codec::Reader::new(&handshake);
    let mut saw_certificate = false;
    while !reader.is_empty() {
        let frame = crate::decode_owned(&mut reader).unwrap();
        saw_certificate |= frame.msg_type() == shin::wire::handshake::Type::Certificate;
    }
    assert!(!saw_certificate, "PSK 1-RTT resumption should remain valid");
}

#[test]
fn client_does_not_offer_quic_entitlement_in_tls_mode() {
    let (ticket, _) = issue_ticket_with_transport(Mode::Quic, true);
    let mut client = client_with_transport(Some(ticket), true, Mode::Tls);
    let events = client.start().unwrap();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::ZeroRttKeysReady { .. }))
    );
    let hello = find_send(&events, Epoch::Plaintext).unwrap();
    let mut reader = shin::wire::codec::Reader::new(&hello);
    let shin::wire::handshake::frame::Frame::ClientHello(hello) =
        crate::decode_owned(&mut reader).unwrap()
    else {
        panic!("expected ClientHello")
    };
    assert!(
        hello
            .extensions
            .iter()
            .all(|extension| extension.ty != shin::wire::extension::Type::EARLY_DATA)
    );
}
