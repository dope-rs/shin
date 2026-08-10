use crate::crypto::ticket;
use crate::memory::threadbound;
use core::mem;
use ring::rand;

/// Scheduled ticket-key rotation retaining one accepting generation.
pub struct Rotator {
    current: ticket::Secret,
    previous: Option<ticket::Secret>,
    schedule: Schedule,
    _thread: threadbound::ThreadBound,
}

struct Schedule {
    current_since_ms: u64,
    issued_under_current: u64,
    rotate_after_ms: u64,
    rotate_after_count: u64,
}

impl Rotator {
    pub fn new(
        rng: &impl rand::SecureRandom,
        now_ms: u64,
        rotate_after_ms: u64,
        rotate_after_count: u64,
    ) -> Result<Self, ticket::Error> {
        let mut current = [0u8; 32];
        rng.fill(&mut current).map_err(|_| ticket::Error::BadKey)?;
        Ok(Self {
            current: ticket::Secret::new(current),
            previous: None,
            schedule: Schedule {
                current_since_ms: now_ms,
                issued_under_current: 0,
                rotate_after_ms,
                rotate_after_count,
            },
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    /// Keys for sealing now, rotating first when the schedule is due.
    pub fn issuing_keys(
        &mut self,
        rng: &impl rand::SecureRandom,
        now_ms: u64,
    ) -> Result<ticket::Keys, ticket::Error> {
        if self.schedule.due(now_ms) {
            self.rotate(rng, now_ms)?;
        }
        self.schedule.issued_under_current = self.schedule.issued_under_current.saturating_add(1);
        Ok(self.accepting_keys())
    }

    /// Current and previous keys for opening without rotating.
    pub fn accepting_keys(&self) -> ticket::Keys {
        ticket::Keys {
            current: self.current.clone(),
            previous: self.previous.clone(),
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    fn rotate(&mut self, rng: &impl rand::SecureRandom, now_ms: u64) -> Result<(), ticket::Error> {
        let mut next = [0u8; 32];
        rng.fill(&mut next).map_err(|_| ticket::Error::BadKey)?;
        self.previous = Some(mem::replace(&mut self.current, ticket::Secret::new(next)));
        self.schedule.current_since_ms = now_ms;
        self.schedule.issued_under_current = 0;
        Ok(())
    }
}

impl Schedule {
    fn due(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.current_since_ms) >= self.rotate_after_ms
            || self.issued_under_current >= self.rotate_after_count
    }
}
