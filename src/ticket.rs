use alloc::vec::Vec;

use ring::aead::{self, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;

use crate::hash::HashAlg;
use crate::kdf::Hkdf;

const TICKET_NONCE_LEN: usize = 12;
const TICKET_TAG_LEN: usize = 16;
const PSK_LEN: usize = 32;
const AGE_ADD_LEN: usize = 4;
const ISSUED_AT_LEN: usize = 8;
const SUITE_LEN: usize = 2;
const ALPN_LEN_LEN: usize = 1;
const MAX_ALPN_LEN: usize = 255;
const FIXED_PLAINTEXT_LEN: usize = PSK_LEN + AGE_ADD_LEN + ISSUED_AT_LEN + SUITE_LEN + ALPN_LEN_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    BadFormat,
    BadAuth,
    BadKey,
}

#[derive(Clone)]
pub struct TicketSecret([u8; 32]);

impl TicketSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self(secret)
    }

    fn aead_key(&self) -> Result<LessSafeKey, TicketError> {
        let mut key_bytes = [0u8; 16];
        Hkdf::expand_label(HashAlg::Sha256, &self.0, "ticket", &[], &mut key_bytes);
        let unbound =
            UnboundKey::new(&aead::AES_128_GCM, &key_bytes).map_err(|_| TicketError::BadKey)?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn encrypt(
        &self,
        psk: &[u8; PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        suite: u16,
        alpn: &[u8],
        rng: &impl SecureRandom,
    ) -> Result<Vec<u8>, TicketError> {
        if alpn.len() > MAX_ALPN_LEN {
            return Err(TicketError::BadFormat);
        }
        let key = self.aead_key()?;
        let mut nonce_bytes = [0u8; TICKET_NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| TicketError::BadKey)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = Vec::with_capacity(FIXED_PLAINTEXT_LEN + alpn.len() + TICKET_TAG_LEN);
        buf.extend_from_slice(psk);
        buf.extend_from_slice(&age_add.to_be_bytes());
        buf.extend_from_slice(&issued_at_ms.to_be_bytes());
        buf.extend_from_slice(&suite.to_be_bytes());
        buf.push(alpn.len() as u8);
        buf.extend_from_slice(alpn);
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut buf)
            .map_err(|_| TicketError::BadAuth)?;

        let mut out = Vec::with_capacity(TICKET_NONCE_LEN + buf.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        Ok(out)
    }

    pub fn decrypt(&self, ticket: &[u8]) -> Result<DecryptedTicket, TicketError> {
        if ticket.len() < TICKET_NONCE_LEN + FIXED_PLAINTEXT_LEN + TICKET_TAG_LEN {
            return Err(TicketError::BadFormat);
        }
        let key = self.aead_key()?;
        let mut nonce_bytes = [0u8; TICKET_NONCE_LEN];
        nonce_bytes.copy_from_slice(&ticket[..TICKET_NONCE_LEN]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = ticket[TICKET_NONCE_LEN..].to_vec();
        let plain = key
            .open_in_place(nonce, aead::Aad::empty(), &mut buf)
            .map_err(|_| TicketError::BadAuth)?;
        if plain.len() < FIXED_PLAINTEXT_LEN {
            return Err(TicketError::BadFormat);
        }
        let mut psk = [0u8; PSK_LEN];
        psk.copy_from_slice(&plain[..PSK_LEN]);
        let mut age_bytes = [0u8; AGE_ADD_LEN];
        age_bytes.copy_from_slice(&plain[PSK_LEN..PSK_LEN + AGE_ADD_LEN]);
        let mut issued_bytes = [0u8; ISSUED_AT_LEN];
        let issued_at_off = PSK_LEN + AGE_ADD_LEN;
        issued_bytes.copy_from_slice(&plain[issued_at_off..issued_at_off + ISSUED_AT_LEN]);
        let suite_off = issued_at_off + ISSUED_AT_LEN;
        let suite = u16::from_be_bytes([plain[suite_off], plain[suite_off + 1]]);
        let alpn_len = plain[FIXED_PLAINTEXT_LEN - ALPN_LEN_LEN] as usize;
        if plain.len() != FIXED_PLAINTEXT_LEN + alpn_len {
            return Err(TicketError::BadFormat);
        }
        let alpn = plain[FIXED_PLAINTEXT_LEN..].to_vec();
        Ok(DecryptedTicket {
            psk,
            age_add: u32::from_be_bytes(age_bytes),
            issued_at_ms: u64::from_be_bytes(issued_bytes),
            suite,
            alpn,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedTicket {
    pub psk: [u8; PSK_LEN],
    pub age_add: u32,
    pub issued_at_ms: u64,
    pub suite: u16,
    pub alpn: Vec<u8>,
}

/// Two-generation key set: seal under `current`, still open `previous` for one
/// rotation window. Produced by [`TicketRotator`].
#[derive(Clone)]
pub struct TicketKeys {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

impl TicketKeys {
    pub fn single(secret: [u8; 32]) -> Self {
        Self {
            current: secret,
            previous: None,
        }
    }

    pub fn with_previous(current: [u8; 32], previous: Option<[u8; 32]>) -> Self {
        Self { current, previous }
    }

    pub fn encrypt(
        &self,
        psk: &[u8; PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        suite: u16,
        alpn: &[u8],
        rng: &impl SecureRandom,
    ) -> Result<Vec<u8>, TicketError> {
        TicketSecret::new(self.current).encrypt(psk, age_add, issued_at_ms, suite, alpn, rng)
    }

    pub fn decrypt(&self, ticket: &[u8]) -> Result<DecryptedTicket, TicketError> {
        match TicketSecret::new(self.current).decrypt(ticket) {
            Ok(v) => Ok(v),
            Err(e) => match self.previous {
                Some(prev) => TicketSecret::new(prev).decrypt(ticket),
                None => Err(e),
            },
        }
    }
}

/// Rolls the ticket key once it is older than `rotate_after_ms` or has sealed
/// `rotate_after_count` tickets, keeping the displaced key as `previous` for one
/// generation. [`issuing_keys`](Self::issuing_keys) seals,
/// [`accepting_keys`](Self::accepting_keys) opens.
pub struct TicketRotator {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    current_since_ms: u64,
    issued_under_current: u64,
    rotate_after_ms: u64,
    rotate_after_count: u64,
}

impl TicketRotator {
    pub fn new(
        rng: &impl SecureRandom,
        now_ms: u64,
        rotate_after_ms: u64,
        rotate_after_count: u64,
    ) -> Result<Self, TicketError> {
        let mut current = [0u8; 32];
        rng.fill(&mut current).map_err(|_| TicketError::BadKey)?;
        Ok(Self {
            current,
            previous: None,
            current_since_ms: now_ms,
            issued_under_current: 0,
            rotate_after_ms,
            rotate_after_count,
        })
    }

    fn due(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.current_since_ms) >= self.rotate_after_ms
            || self.issued_under_current >= self.rotate_after_count
    }

    fn rotate(&mut self, rng: &impl SecureRandom, now_ms: u64) -> Result<(), TicketError> {
        let mut next = [0u8; 32];
        rng.fill(&mut next).map_err(|_| TicketError::BadKey)?;
        self.previous = Some(self.current);
        self.current = next;
        self.current_since_ms = now_ms;
        self.issued_under_current = 0;
        Ok(())
    }

    /// Keys for sealing a ticket now, rotating first if the schedule is due.
    pub fn issuing_keys(
        &mut self,
        rng: &impl SecureRandom,
        now_ms: u64,
    ) -> Result<TicketKeys, TicketError> {
        if self.due(now_ms) {
            self.rotate(rng, now_ms)?;
        }
        self.issued_under_current = self.issued_under_current.saturating_add(1);
        Ok(self.accepting_keys())
    }

    /// Current + previous keys for opening an inbound ticket. Never rotates.
    pub fn accepting_keys(&self) -> TicketKeys {
        TicketKeys {
            current: self.current,
            previous: self.previous,
        }
    }
}
