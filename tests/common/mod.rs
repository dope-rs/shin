#![allow(dead_code)]

use ring::rand::{SecureRandom, SystemRandom};

use shin::sig::SigningKey;
use shin::{Clock, Epoch, Event};

pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

pub fn find_send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

pub fn send(events: &[Event], epoch: Epoch) -> Vec<u8> {
    find_send(events, epoch).expect("expected a Send")
}

pub fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done))
}

pub fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    SigningKey::from_seed(&seed).unwrap()
}
