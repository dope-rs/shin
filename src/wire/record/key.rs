use core::ops;

use crate::crypto::aead;

pub(super) struct Key(aead::Key);

impl Key {
    pub(super) fn derive(
        secret: &[u8],
        suite: super::CipherSuite,
    ) -> Result<Self, super::KeyError> {
        use crate::crypto::schedule::TrafficKeys;
        let alg = suite.hash_alg();
        let key = match suite {
            super::CipherSuite::Aes128GcmSha256 => {
                let keys = TrafficKeys::<16>::derive(alg, secret)?;
                aead::Key::aes_128_gcm(&keys.key, keys.iv)?
            }
            super::CipherSuite::ChaCha20Poly1305Sha256 => {
                let keys = TrafficKeys::<32>::derive(alg, secret)?;
                aead::Key::chacha20_poly1305(&keys.key, keys.iv)?
            }
            super::CipherSuite::Aes256GcmSha384 => {
                let keys = TrafficKeys::<32>::derive(alg, secret)?;
                aead::Key::aes_256_gcm(&keys.key, keys.iv)?
            }
        };
        Ok(Self(key))
    }
}

impl ops::Deref for Key {
    type Target = aead::Key;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
