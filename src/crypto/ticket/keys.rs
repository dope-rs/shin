use crate::crypto::material;
use crate::crypto::ticket;
use crate::crypto::ticket::secret;
use crate::memory::threadbound;
use crate::wire::record;
use ring::rand;

/// Two-generation key set that opens one previous rotation window.
pub struct Keys {
    pub(super) current: ticket::Secret,
    pub(super) previous: Option<ticket::Secret>,
    pub(super) _thread: threadbound::ThreadBound,
}

impl Keys {
    pub fn single(secret: [u8; 32]) -> Result<Self, ticket::Error> {
        Ok(Self {
            current: ticket::Secret::new(secret)?,
            previous: None,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn with_previous(
        current: [u8; 32],
        previous: Option<[u8; 32]>,
    ) -> Result<Self, ticket::Error> {
        Ok(Self {
            current: ticket::Secret::new(current)?,
            previous: previous.map(ticket::Secret::new).transpose()?,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn encrypt(
        &self,
        psk: &[u8; ticket::PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        suite: record::CipherSuite,
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
        self.decrypt_with(encrypted, &|opened| opened.to_owned())?
    }

    pub(crate) fn decrypt_resumption(
        &self,
        encrypted: &[u8],
        selected_alpn: &[u8],
    ) -> Result<ticket::OpenedResumption, ticket::Error> {
        self.decrypt_with(encrypted, &|opened| ticket::OpenedResumption {
            psk: material::ResumptionPsk::new(*opened.psk),
            age_add: opened.age_add,
            issued_at_ms: opened.issued_at_ms,
            suite: opened.suite,
            context: opened.context,
            alpn_matches: opened.alpn == selected_alpn,
        })
    }

    fn decrypt_with<R>(
        &self,
        encrypted: &[u8],
        consume: &impl for<'a> Fn(secret::Opened<'a>) -> R,
    ) -> Result<R, ticket::Error> {
        match self.current.decrypt_with(encrypted, consume) {
            Ok(value) => Ok(value),
            Err(error) => match &self.previous {
                Some(previous) => previous.decrypt_with(encrypted, consume),
                None => Err(error),
            },
        }
    }
}
