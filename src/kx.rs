use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SecureRandom;

pub const PUBKEY_LEN: usize = 32;
pub const SHARED_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KxError {
    Generate,
    InvalidPubkey,
}

pub struct EphemeralKey {
    inner: EphemeralPrivateKey,
    pubkey: [u8; PUBKEY_LEN],
}

impl EphemeralKey {
    pub fn generate<R: SecureRandom>(rng: &R) -> Result<Self, KxError> {
        let inner = EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| KxError::Generate)?;
        let pub_obj = inner.compute_public_key().map_err(|_| KxError::Generate)?;
        let mut pubkey = [0u8; PUBKEY_LEN];
        pubkey.copy_from_slice(pub_obj.as_ref());
        Ok(Self { inner, pubkey })
    }

    pub fn pubkey(&self) -> &[u8; PUBKEY_LEN] {
        &self.pubkey
    }

    pub fn agree(self, peer_pubkey: &[u8]) -> Result<[u8; SHARED_LEN], KxError> {
        if peer_pubkey.len() != PUBKEY_LEN {
            return Err(KxError::InvalidPubkey);
        }
        let peer = UnparsedPublicKey::new(&X25519, peer_pubkey);
        agreement::agree_ephemeral(self.inner, &peer, |secret| {
            let mut out = [0u8; SHARED_LEN];
            out.copy_from_slice(secret);
            out
        })
        .map_err(|_| KxError::InvalidPubkey)
    }
}
