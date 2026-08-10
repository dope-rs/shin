use crate::crypto::ticket;
use crate::memory::threadbound;
use ring::rand;

/// Two-generation key set that opens one previous rotation window.
pub struct Keys {
    pub(super) current: ticket::Secret,
    pub(super) previous: Option<ticket::Secret>,
    pub(super) _thread: threadbound::ThreadBound,
}

impl Keys {
    pub fn single(secret: [u8; 32]) -> Self {
        Self {
            current: ticket::Secret::new(secret),
            previous: None,
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub fn with_previous(current: [u8; 32], previous: Option<[u8; 32]>) -> Self {
        Self {
            current: ticket::Secret::new(current),
            previous: previous.map(ticket::Secret::new),
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub fn encrypt(
        &self,
        psk: &[u8; ticket::PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        suite: u16,
        alpn: &[u8],
        rng: &impl rand::SecureRandom,
    ) -> Result<ticket::Encrypted, ticket::Error> {
        self.current
            .encrypt(psk, age_add, issued_at_ms, suite, alpn, rng)
    }

    pub fn encrypt_claims(
        &self,
        claims: ticket::Claims<'_>,
        rng: &impl rand::SecureRandom,
    ) -> Result<ticket::Encrypted, ticket::Error> {
        self.current.encrypt_claims(claims, rng)
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<ticket::Decrypted, ticket::Error> {
        match self.current.decrypt(encrypted) {
            Ok(value) => Ok(value),
            Err(error) => match &self.previous {
                Some(previous) => previous.decrypt(encrypted),
                None => Err(error),
            },
        }
    }
}
