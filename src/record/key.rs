use core::ops::Deref;

use crate::aead::AeadKey;
use crate::schedule::TrafficKeys;

use super::{CipherSuite, RecordKeyError};

pub(super) struct Key(AeadKey);

impl Key {
    pub(super) fn derive(secret: &[u8], suite: CipherSuite) -> Result<Self, RecordKeyError> {
        let alg = suite.hash_alg();
        let key = match suite {
            CipherSuite::Aes128GcmSha256 => {
                let keys = TrafficKeys::<16>::derive(alg, secret)?;
                AeadKey::aes_128_gcm(&keys.key, keys.iv)?
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let keys = TrafficKeys::<32>::derive(alg, secret)?;
                AeadKey::chacha20_poly1305(&keys.key, keys.iv)?
            }
            CipherSuite::Aes256GcmSha384 => {
                let keys = TrafficKeys::<32>::derive(alg, secret)?;
                AeadKey::aes_256_gcm(&keys.key, keys.iv)?
            }
        };
        Ok(Self(key))
    }
}

impl Deref for Key {
    type Target = AeadKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
