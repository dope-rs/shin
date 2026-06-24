use ring::rand::{SecureRandom, SystemRandom};
use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::{Epoch, Event};

fn collect_send(events: &[Event], epoch: Epoch) -> Vec<u8> {
    let mut out = Vec::new();
    for e in events {
        if let Event::Send { epoch: ep, data } = e
            && *ep == epoch
        {
            out.extend_from_slice(data);
        }
    }
    out
}

#[test]
fn server_rejects_tampered_client_finished() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing_key = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing_key.pubkey();

    let mut server = Server::new(ServerConfig {
        source: CertSource::RawPublicKey { signing_key },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = Client::new(ClientConfig {
        verifier: Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    });

    let ch = collect_send(&client.start().unwrap(), Epoch::Plaintext);
    let server_flight = server.read(Epoch::Plaintext, &ch).unwrap();

    let sh = collect_send(&server_flight, Epoch::Plaintext);
    let server_hs = collect_send(&server_flight, Epoch::Handshake);

    let client_out_pt = client.read(Epoch::Plaintext, &sh).unwrap();
    assert!(collect_send(&client_out_pt, Epoch::Handshake).is_empty());
    let client_out_hs = client.read(Epoch::Handshake, &server_hs).unwrap();
    let client_finished = collect_send(&client_out_hs, Epoch::Handshake);
    assert!(!client_finished.is_empty());

    let mut tampered = client_finished.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xff;
    let err = server.read(Epoch::Handshake, &tampered).unwrap_err();
    assert_eq!(err, shin::Error::BadFinished);

    // Untampered path still succeeds.
    let ok = server.read(Epoch::Handshake, &client_finished).unwrap();
    assert!(ok.iter().any(|e| matches!(e, Event::Done)));
}
