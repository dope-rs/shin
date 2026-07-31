use arrayvec::ArrayVec;
use core::fmt;

use ml_kem::kem::Decapsulate;
use ml_kem::{
    B32, Ciphertext, EncapsulationKey, KeyExport, MlKem768, Seed, TryKeyInit,
    ml_kem_768::DecapsulationKey,
};
use ring::agreement::{self, Algorithm, ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SecureRandom;

use zeroize::Zeroize;

use crate::memory::bound::ThreadBound;

/// Largest (EC)DHE / hybrid shared secret: ML-KEM-768 (32) ‖ X25519 (32).
pub const MAX_SHARED_LEN: usize = 64;

const X25519_LEN: usize = 32;
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
pub(crate) const MAX_CLIENT_SHARE_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;
const MAX_SERVER_SHARE_LEN: usize = MLKEM768_CT_LEN + X25519_LEN;

/// (EC)DHE / hybrid shared secret of up to [`MAX_SHARED_LEN`] bytes, kept inline
/// (no heap) and zeroized on drop.
pub struct SharedSecret {
    bytes: [u8; MAX_SHARED_LEN],
    len: usize,
    _thread: ThreadBound,
}

impl SharedSecret {
    fn from_slice(s: &[u8]) -> Self {
        Self::from_parts(s, &[])
    }

    fn from_parts(a: &[u8], b: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_SHARED_LEN];
        bytes[..a.len()].copy_from_slice(a);
        bytes[a.len()..a.len() + b.len()].copy_from_slice(b);
        Self {
            bytes,
            len: a.len() + b.len(),
            _thread: ThreadBound::NEW,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret([redacted; {}])", self.len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KxError {
    Generate,
    InvalidPubkey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexGroup {
    X25519,
    Secp256r1,
    X25519Mlkem768,
}

impl KexGroup {
    /// Preference order keeps X25519MLKEM768 last, selecting it only when the
    /// client commits a hybrid key share.
    pub const SUPPORTED: [KexGroup; 3] = [
        KexGroup::X25519,
        KexGroup::Secp256r1,
        KexGroup::X25519Mlkem768,
    ];

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x001d => Some(Self::X25519),
            0x0017 => Some(Self::Secp256r1),
            0x11ec => Some(Self::X25519Mlkem768),
            _ => None,
        }
    }

    pub fn wire_id(self) -> u16 {
        match self {
            Self::X25519 => 0x001d,
            Self::Secp256r1 => 0x0017,
            Self::X25519Mlkem768 => 0x11ec,
        }
    }

    fn ecdh_algorithm(self) -> &'static Algorithm {
        match self {
            Self::Secp256r1 => &ECDH_P256,
            Self::X25519 | Self::X25519Mlkem768 => &X25519,
        }
    }
}

/// Inline ML-KEM state preserves the allocation-free handshake contract.
#[allow(clippy::large_enum_variant)]
enum Secret {
    Ecdhe(EphemeralPrivateKey),
    /// Hybrid initiator state: the classical ephemeral plus the ML-KEM
    /// decapsulation key used to recover the PQ half from the server's ciphertext.
    Hybrid {
        x25519: EphemeralPrivateKey,
        mlkem_dk: DecapsulationKey,
    },
}

/// Initiator (client) key-exchange state: holds the private key(s) and exposes
/// the public `client_share` to put in the key_share extension.
pub struct EphemeralKey {
    secret: Secret,
    group: KexGroup,
    client_share: ArrayVec<u8, MAX_CLIENT_SHARE_LEN>,
    _thread: ThreadBound,
}

impl EphemeralKey {
    pub fn generate<R: SecureRandom>(group: KexGroup, rng: &R) -> Result<Self, KxError> {
        match group {
            KexGroup::X25519 | KexGroup::Secp256r1 => {
                let inner = EphemeralPrivateKey::generate(group.ecdh_algorithm(), rng)
                    .map_err(|_| KxError::Generate)?;
                let public = inner.compute_public_key().map_err(|_| KxError::Generate)?;
                let mut client_share = ArrayVec::new();
                client_share
                    .try_extend_from_slice(public.as_ref())
                    .map_err(|_| KxError::Generate)?;
                Ok(Self {
                    secret: Secret::Ecdhe(inner),
                    group,
                    client_share,
                    _thread: ThreadBound::NEW,
                })
            }
            KexGroup::X25519Mlkem768 => {
                let mut seed = [0u8; 64];
                rng.fill(&mut seed).map_err(|_| KxError::Generate)?;
                let mlkem_dk = DecapsulationKey::from_seed(Seed::from(seed));
                let x25519 =
                    EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| KxError::Generate)?;
                let x25519_pk = x25519.compute_public_key().map_err(|_| KxError::Generate)?;
                let mut client_share = ArrayVec::new();
                client_share
                    .try_extend_from_slice(mlkem_dk.encapsulation_key().to_bytes().as_slice())
                    .map_err(|_| KxError::Generate)?;
                client_share
                    .try_extend_from_slice(x25519_pk.as_ref())
                    .map_err(|_| KxError::Generate)?;
                Ok(Self {
                    secret: Secret::Hybrid { x25519, mlkem_dk },
                    group,
                    client_share,
                    _thread: ThreadBound::NEW,
                })
            }
        }
    }

    pub fn group(&self) -> KexGroup {
        self.group
    }

    pub fn client_share(&self) -> &[u8] {
        &self.client_share
    }

    pub(crate) fn copied_client_share(&self) -> ArrayVec<u8, MAX_CLIENT_SHARE_LEN> {
        self.client_share.clone()
    }

    /// Consume the initiator state and combine it with the server's share to
    /// produce the shared secret (32 bytes classical, 64 bytes hybrid).
    pub fn agree(self, server_share: &[u8]) -> Result<SharedSecret, KxError> {
        match self.secret {
            Secret::Ecdhe(inner) => {
                let peer = UnparsedPublicKey::new(self.group.ecdh_algorithm(), server_share);
                agreement::agree_ephemeral(inner, &peer, SharedSecret::from_slice)
                    .map_err(|_| KxError::InvalidPubkey)
            }
            Secret::Hybrid { x25519, mlkem_dk } => {
                if server_share.len() != MLKEM768_CT_LEN + X25519_LEN {
                    return Err(KxError::InvalidPubkey);
                }
                let (ct_bytes, x25519_server_pk) = server_share.split_at(MLKEM768_CT_LEN);
                let ct = Ciphertext::<MlKem768>::try_from(ct_bytes)
                    .map_err(|_| KxError::InvalidPubkey)?;
                let mlkem_ss = mlkem_dk.decapsulate(&ct);
                let peer = UnparsedPublicKey::new(&X25519, x25519_server_pk);
                let shared = agreement::agree_ephemeral(x25519, &peer, |x25519_ss| {
                    SharedSecret::from_parts(mlkem_ss.as_slice(), x25519_ss)
                })
                .map_err(|_| KxError::InvalidPubkey)?;
                Ok(shared)
            }
        }
    }
}

impl KexGroup {
    pub fn respond<R: SecureRandom>(
        self,
        client_share: &[u8],
        rng: &R,
    ) -> Result<(ArrayVec<u8, MAX_SERVER_SHARE_LEN>, SharedSecret), KxError> {
        match self {
            KexGroup::X25519 | KexGroup::Secp256r1 => {
                let eph = EphemeralPrivateKey::generate(self.ecdh_algorithm(), rng)
                    .map_err(|_| KxError::Generate)?;
                let public = eph.compute_public_key().map_err(|_| KxError::Generate)?;
                let mut server_share = ArrayVec::new();
                server_share
                    .try_extend_from_slice(public.as_ref())
                    .map_err(|_| KxError::Generate)?;
                let peer = UnparsedPublicKey::new(self.ecdh_algorithm(), client_share);
                let shared = agreement::agree_ephemeral(eph, &peer, SharedSecret::from_slice)
                    .map_err(|_| KxError::InvalidPubkey)?;
                Ok((server_share, shared))
            }
            KexGroup::X25519Mlkem768 => {
                if client_share.len() != MLKEM768_EK_LEN + X25519_LEN {
                    return Err(KxError::InvalidPubkey);
                }
                let (ek_bytes, x25519_client_pk) = client_share.split_at(MLKEM768_EK_LEN);
                let ek = EncapsulationKey::<MlKem768>::new_from_slice(ek_bytes)
                    .map_err(|_| KxError::InvalidPubkey)?;
                let mut randomness = [0u8; 32];
                rng.fill(&mut randomness).map_err(|_| KxError::Generate)?;
                let (ct, mlkem_ss) = ek.encapsulate_deterministic(&B32::from(randomness));

                let x25519 =
                    EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| KxError::Generate)?;
                let x25519_server_pk =
                    x25519.compute_public_key().map_err(|_| KxError::Generate)?;
                let peer = UnparsedPublicKey::new(&X25519, x25519_client_pk);
                let shared = agreement::agree_ephemeral(x25519, &peer, |x25519_ss| {
                    SharedSecret::from_parts(mlkem_ss.as_slice(), x25519_ss)
                })
                .map_err(|_| KxError::InvalidPubkey)?;

                let mut server_share = ArrayVec::new();
                server_share
                    .try_extend_from_slice(ct.as_slice())
                    .map_err(|_| KxError::Generate)?;
                server_share
                    .try_extend_from_slice(x25519_server_pk.as_ref())
                    .map_err(|_| KxError::Generate)?;
                Ok((server_share, shared))
            }
        }
    }
}
