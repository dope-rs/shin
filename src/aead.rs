use alloc::vec::Vec;

use ring::aead;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    OpenFailed,
}

pub struct AeadKey {
    inner: aead::LessSafeKey,
    iv: [u8; 12],
}

impl AeadKey {
    pub fn aes_128_gcm(key: &[u8; 16], iv: [u8; 12]) -> Self {
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key)
            .expect("AES-128-GCM accepts a 16-byte key by construction");
        Self {
            inner: aead::LessSafeKey::new(unbound),
            iv,
        }
    }

    pub fn chacha20_poly1305(key: &[u8; 32], iv: [u8; 12]) -> Self {
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .expect("ChaCha20-Poly1305 accepts a 32-byte key by construction");
        Self {
            inner: aead::LessSafeKey::new(unbound),
            iv,
        }
    }

    pub fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    pub fn seal(&self, seq: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(seq));
        let mut buf = plaintext.to_vec();
        self.inner
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut buf)
            .expect("AES-128-GCM seal cannot fail with a 12-byte nonce");
        buf
    }

    pub fn open<'a>(
        &self,
        seq: u64,
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], AeadError> {
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(seq));
        self.inner
            .open_in_place(nonce, aead::Aad::from(aad), in_out)
            .map(|p| &*p)
            .map_err(|_| AeadError::OpenFailed)
    }
}
