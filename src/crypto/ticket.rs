use arrayvec::ArrayVec;
use core::fmt;
use core::ops::Deref;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;

use crate::crypto::hash::HashAlg;
use crate::crypto::kdf::Hkdf;
use crate::memory::bound::ThreadBound;
use zeroize::Zeroize;

const TICKET_NONCE_LEN: usize = 12;
const TICKET_TAG_LEN: usize = 16;
const PSK_LEN: usize = 32;
const AGE_ADD_LEN: usize = 4;
const ISSUED_AT_LEN: usize = 8;
const SUITE_LEN: usize = 2;
const ALPN_LEN_LEN: usize = 1;
const MAX_ALPN_LEN: usize = 255;
const FIXED_PLAINTEXT_LEN: usize = PSK_LEN + AGE_ADD_LEN + ISSUED_AT_LEN + SUITE_LEN + ALPN_LEN_LEN;
const MAX_PLAINTEXT_LEN: usize = FIXED_PLAINTEXT_LEN + MAX_ALPN_LEN;
const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + TICKET_TAG_LEN;
pub const MAX_TICKET_LEN: usize = TICKET_NONCE_LEN + MAX_CIPHERTEXT_LEN;

/// An authenticated, opaque session ticket with a protocol-bounded size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedTicket {
    bytes: ArrayVec<u8, MAX_TICKET_LEN>,
}

impl EncryptedTicket {
    fn new() -> Self {
        Self {
            bytes: ArrayVec::new(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for EncryptedTicket {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for EncryptedTicket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    BadFormat,
    BadAuth,
    BadKey,
}

/// ```compile_fail
/// use shin::crypto::ticket::TicketSecret;
/// fn assert_send<T: Send>() {}
/// assert_send::<TicketSecret>();
/// ```
pub struct TicketSecret {
    secret: [u8; 32],
    _thread: ThreadBound,
}

impl TicketSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            _thread: ThreadBound::NEW,
        }
    }

    fn aead_key(&self) -> Result<LessSafeKey, TicketError> {
        let mut key_bytes = [0u8; 16];
        Hkdf::new(HashAlg::Sha256)
            .expand_label(&self.secret, "ticket", &[], &mut key_bytes)
            .map_err(|_| TicketError::BadKey)?;
        let unbound = UnboundKey::new(&aead::AES_128_GCM, &key_bytes);
        key_bytes.zeroize();
        let unbound = unbound.map_err(|_| TicketError::BadKey)?;
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
    ) -> Result<EncryptedTicket, TicketError> {
        if alpn.len() > MAX_ALPN_LEN {
            return Err(TicketError::BadFormat);
        }
        let key = self.aead_key()?;
        let mut nonce_bytes = [0u8; TICKET_NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| TicketError::BadKey)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = ArrayVec::<u8, MAX_PLAINTEXT_LEN>::new();
        buf.try_extend_from_slice(psk)
            .map_err(|_| TicketError::BadFormat)?;
        buf.try_extend_from_slice(&age_add.to_be_bytes())
            .map_err(|_| TicketError::BadFormat)?;
        buf.try_extend_from_slice(&issued_at_ms.to_be_bytes())
            .map_err(|_| TicketError::BadFormat)?;
        buf.try_extend_from_slice(&suite.to_be_bytes())
            .map_err(|_| TicketError::BadFormat)?;
        buf.try_push(alpn.len() as u8)
            .map_err(|_| TicketError::BadFormat)?;
        buf.try_extend_from_slice(alpn)
            .map_err(|_| TicketError::BadFormat)?;
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), buf.as_mut_slice())
            .map_err(|_| TicketError::BadAuth)?;

        let mut out = EncryptedTicket::new();
        out.bytes
            .try_extend_from_slice(&nonce_bytes)
            .map_err(|_| TicketError::BadFormat)?;
        out.bytes
            .try_extend_from_slice(&buf)
            .map_err(|_| TicketError::BadFormat)?;
        out.bytes
            .try_extend_from_slice(tag.as_ref())
            .map_err(|_| TicketError::BadFormat)?;
        Ok(out)
    }

    pub fn decrypt(&self, ticket: &[u8]) -> Result<DecryptedTicket, TicketError> {
        if ticket.len() < TICKET_NONCE_LEN + FIXED_PLAINTEXT_LEN + TICKET_TAG_LEN {
            return Err(TicketError::BadFormat);
        }
        if ticket.len() > MAX_TICKET_LEN {
            return Err(TicketError::BadFormat);
        }
        let key = self.aead_key()?;
        let mut nonce_bytes = [0u8; TICKET_NONCE_LEN];
        nonce_bytes.copy_from_slice(&ticket[..TICKET_NONCE_LEN]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = ArrayVec::<u8, MAX_CIPHERTEXT_LEN>::new();
        buf.try_extend_from_slice(&ticket[TICKET_NONCE_LEN..])
            .map_err(|_| TicketError::BadFormat)?;
        let plain = key
            .open_in_place(nonce, Aad::empty(), buf.as_mut_slice())
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
        let alpn = ArrayVec::try_from(&plain[FIXED_PLAINTEXT_LEN..])
            .map_err(|_| TicketError::BadFormat)?;
        buf.as_mut_slice().zeroize();
        Ok(DecryptedTicket {
            psk,
            age_add: u32::from_be_bytes(age_bytes),
            issued_at_ms: u64::from_be_bytes(issued_bytes),
            suite,
            alpn,
            _thread: ThreadBound::NEW,
        })
    }
}

impl Drop for TicketSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(PartialEq, Eq)]
pub struct DecryptedTicket {
    pub psk: [u8; PSK_LEN],
    pub age_add: u32,
    pub issued_at_ms: u64,
    pub suite: u16,
    pub alpn: ArrayVec<u8, MAX_ALPN_LEN>,
    _thread: ThreadBound,
}

impl Drop for DecryptedTicket {
    fn drop(&mut self) {
        self.psk.zeroize();
    }
}

impl fmt::Debug for DecryptedTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedTicket")
            .field("psk", &"[redacted]")
            .field("age_add", &self.age_add)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("suite", &self.suite)
            .field("alpn", &self.alpn)
            .finish()
    }
}

/// Two-generation key set: seal under `current`, still open `previous` for one
/// rotation window. Produced by [`TicketRotator`].
pub struct TicketKeys {
    current: TicketSecret,
    previous: Option<TicketSecret>,
    _thread: ThreadBound,
}

impl TicketKeys {
    pub fn single(secret: [u8; 32]) -> Self {
        Self {
            current: TicketSecret::new(secret),
            previous: None,
            _thread: ThreadBound::NEW,
        }
    }

    pub fn with_previous(current: [u8; 32], previous: Option<[u8; 32]>) -> Self {
        Self {
            current: TicketSecret::new(current),
            previous: previous.map(TicketSecret::new),
            _thread: ThreadBound::NEW,
        }
    }

    pub fn encrypt(
        &self,
        psk: &[u8; PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        suite: u16,
        alpn: &[u8],
        rng: &impl SecureRandom,
    ) -> Result<EncryptedTicket, TicketError> {
        self.current
            .encrypt(psk, age_add, issued_at_ms, suite, alpn, rng)
    }

    pub fn decrypt(&self, ticket: &[u8]) -> Result<DecryptedTicket, TicketError> {
        match self.current.decrypt(ticket) {
            Ok(v) => Ok(v),
            Err(e) => match &self.previous {
                Some(previous) => previous.decrypt(ticket),
                None => Err(e),
            },
        }
    }
}

/// Rolls a ticket key by age or seal count and retains one previous generation;
/// [`issuing_keys`](Self::issuing_keys) seals and [`accepting_keys`](Self::accepting_keys) opens.
pub struct TicketRotator {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    current_since_ms: u64,
    issued_under_current: u64,
    rotate_after_ms: u64,
    rotate_after_count: u64,
    _thread: ThreadBound,
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
            _thread: ThreadBound::NEW,
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
            current: TicketSecret::new(self.current),
            previous: self.previous.map(TicketSecret::new),
            _thread: ThreadBound::NEW,
        }
    }
}

impl Drop for TicketRotator {
    fn drop(&mut self) {
        self.current.zeroize();
        self.previous.zeroize();
    }
}
