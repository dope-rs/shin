#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::client::Client;
use shin::client::config::{Config as ClientConfig, Verifier};
use shin::server::{config::CertSource, config::Config as ShardConfig, config::ConnectionConfig, Server, Shard};
use shin::crypto::sig::SigningKey;
use shin::connection::{Epoch, Event, EventContext, EventSink};

struct IgnoreEvents;

impl EventSink for IgnoreEvents {
    type Error = core::convert::Infallible;

    fn event(
        &mut self,
        _event: Event<'_>,
        _context: EventContext,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

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
        ConnectionConfig {
            transport_params: Vec::new(),
        },
        || 0,
    );
    let mut shard = Shard::new(ShardConfig {
        source: CertSource::RawPublicKey {
            signing_key: signing,
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
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
    let mut events = IgnoreEvents;
    let _ = client.start_into(&mut events);

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
            let _ = server.read_into(ep, chunk, &mut shard, &mut events);
        } else {
            let _ = client.read_into(ep, chunk, &mut events);
        }
    }
});
