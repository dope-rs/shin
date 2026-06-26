#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::client::{Client, Config as ClientConfig, Verifier};
use shin::server::{CertSource, Config as ServerConfig, Server};
use shin::sig::SigningKey;
use shin::Epoch;

fn epoch(b: u8) -> Epoch {
    match b & 0b11 {
        0 => Epoch::Plaintext,
        1 => Epoch::EarlyData,
        2 => Epoch::Handshake,
        _ => Epoch::Application,
    }
}

// Drive both endpoints' `read` with an attacker-chosen sequence of
// (epoch, bytes) records. The state machines must never panic, regardless of
// framing, ordering, or content.
fuzz_target!(|data: &[u8]| {
    let signing = match SigningKey::from_seed(&[0x5au8; 32]) {
        Ok(k) => k,
        Err(_) => return,
    };
    let pubkey = match signing.pubkey() {
        Some(p) => *p,
        None => return,
    };

    let mut server = Server::new(
        ServerConfig {
            source: CertSource::RawPublicKey {
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        ClientConfig {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    );
    let _ = client.start();

    let mut r = data;
    while r.len() >= 2 {
        let hdr = r[0];
        let len = r[1] as usize;
        r = &r[2..];
        let take = len.min(r.len());
        let (chunk, rest) = r.split_at(take);
        r = rest;
        let ep = epoch(hdr);
        if hdr & 0b100 == 0 {
            let _ = server.read(ep, chunk);
        } else {
            let _ = client.read(ep, chunk);
        }
    }
});
