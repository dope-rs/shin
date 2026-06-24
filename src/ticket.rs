use alloc::vec::Vec;

use ring::aead::{self, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;

use crate::kdf::Hkdf;

const TICKET_NONCE_LEN: usize = 12;
const TICKET_TAG_LEN: usize = 16;
const PSK_LEN: usize = 32;
const AGE_ADD_LEN: usize = 4;
const ISSUED_AT_LEN: usize = 8;
const ALPN_LEN_LEN: usize = 1;
const MAX_ALPN_LEN: usize = 255;
const FIXED_PLAINTEXT_LEN: usize = PSK_LEN + AGE_ADD_LEN + ISSUED_AT_LEN + ALPN_LEN_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    BadFormat,
    BadAuth,
    BadKey,
}

pub struct TicketSecret([u8; 32]);

impl TicketSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self(secret)
    }

    fn aead_key(&self) -> Result<LessSafeKey, TicketError> {
        let mut key_bytes = [0u8; 16];
        Hkdf::expand_label(&self.0, "ticket", &[], &mut key_bytes);
        let unbound =
            UnboundKey::new(&aead::AES_128_GCM, &key_bytes).map_err(|_| TicketError::BadKey)?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn encrypt(
        &self,
        psk: &[u8; PSK_LEN],
        age_add: u32,
        issued_at_ms: u64,
        alpn: &[u8],
        rng: &dyn SecureRandom,
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
        buf.push(alpn.len() as u8);
        buf.extend_from_slice(alpn);
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut buf)
            .map_err(|_| TicketError::BadAuth)?;

        let mut out = Vec::with_capacity(TICKET_NONCE_LEN + buf.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        Ok(out)
    }

    pub fn decrypt(
        &self,
        ticket: &[u8],
    ) -> Result<([u8; PSK_LEN], u32, u64, Vec<u8>), TicketError> {
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
        issued_bytes
            .copy_from_slice(&plain[PSK_LEN + AGE_ADD_LEN..PSK_LEN + AGE_ADD_LEN + ISSUED_AT_LEN]);
        let alpn_len = plain[FIXED_PLAINTEXT_LEN - ALPN_LEN_LEN] as usize;
        if plain.len() != FIXED_PLAINTEXT_LEN + alpn_len {
            return Err(TicketError::BadFormat);
        }
        let alpn = plain[FIXED_PLAINTEXT_LEN..].to_vec();
        Ok((
            psk,
            u32::from_be_bytes(age_bytes),
            u64::from_be_bytes(issued_bytes),
            alpn,
        ))
    }
}
