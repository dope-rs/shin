use alloc::vec::Vec;

use ring::agreement::{self, Algorithm, ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SecureRandom;

pub const SHARED_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KxError {
    Generate,
    InvalidPubkey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexGroup {
    X25519,
    Secp256r1,
}

impl KexGroup {
    pub const SUPPORTED: [KexGroup; 2] = [KexGroup::X25519, KexGroup::Secp256r1];

    fn algorithm(self) -> &'static Algorithm {
        match self {
            Self::X25519 => &X25519,
            Self::Secp256r1 => &ECDH_P256,
        }
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x001d => Some(Self::X25519),
            0x0017 => Some(Self::Secp256r1),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::X25519 => 0x001d,
            Self::Secp256r1 => 0x0017,
        }
    }
}

pub struct EphemeralKey {
    inner: EphemeralPrivateKey,
    group: KexGroup,
    pubkey: Vec<u8>,
}

impl EphemeralKey {
    pub fn generate<R: SecureRandom>(group: KexGroup, rng: &R) -> Result<Self, KxError> {
        let inner =
            EphemeralPrivateKey::generate(group.algorithm(), rng).map_err(|_| KxError::Generate)?;
        let pub_obj = inner.compute_public_key().map_err(|_| KxError::Generate)?;
        Ok(Self {
            inner,
            group,
            pubkey: pub_obj.as_ref().to_vec(),
        })
    }

    pub fn group(&self) -> KexGroup {
        self.group
    }

    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    pub fn agree(self, peer_pubkey: &[u8]) -> Result<[u8; SHARED_LEN], KxError> {
        let peer = UnparsedPublicKey::new(self.group.algorithm(), peer_pubkey);
        agreement::agree_ephemeral(self.inner, &peer, |secret| {
            // Both supported groups produce a 32-byte shared secret.
            let mut out = [0u8; SHARED_LEN];
            out.copy_from_slice(secret);
            out
        })
        .map_err(|_| KxError::InvalidPubkey)
    }
}
