use crate::memory::threadbound;
use alloc::vec;

use ring::aead;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidKey,
    SealFailed,
    OpenFailed,
}

pub struct Key {
    inner: aead::LessSafeKey,
    iv: [u8; 12],
    _thread: threadbound::ThreadBound,
}

impl Key {
    pub fn aes_128_gcm(key: &[u8; 16], iv: [u8; 12]) -> Result<Self, Error> {
        let unbound =
            aead::UnboundKey::new(&aead::AES_128_GCM, key).map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            inner: aead::LessSafeKey::new(unbound),
            iv,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn aes_256_gcm(key: &[u8; 32], iv: [u8; 12]) -> Result<Self, Error> {
        let unbound =
            aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            inner: aead::LessSafeKey::new(unbound),
            iv,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn chacha20_poly1305(key: &[u8; 32], iv: [u8; 12]) -> Result<Self, Error> {
        let unbound =
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            inner: aead::LessSafeKey::new(unbound),
            iv,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    fn nonce_for(&self, seq: u64) -> aead::Nonce {
        aead::Nonce::assume_unique_for_key(self.nonce(seq))
    }

    pub fn seal(&self, seq: u64, aad: &[u8], plaintext: &[u8]) -> Result<vec::Vec<u8>, Error> {
        let mut buf = plaintext.to_vec();
        self.inner
            .seal_in_place_append_tag(self.nonce_for(seq), aead::Aad::from(aad), &mut buf)
            .map_err(|_| Error::SealFailed)?;
        Ok(buf)
    }

    pub fn seal_detached(
        &self,
        seq: u64,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        let tag = self
            .inner
            .seal_in_place_separate_tag(self.nonce_for(seq), aead::Aad::from(aad), in_out)
            .map_err(|_| Error::SealFailed)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    pub fn open<'a>(&self, seq: u64, aad: &[u8], in_out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.inner
            .open_in_place(self.nonce_for(seq), aead::Aad::from(aad), in_out)
            .map(|p| &*p)
            .map_err(|_| Error::OpenFailed)
    }
}
