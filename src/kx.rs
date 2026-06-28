use alloc::vec::Vec;
use core::convert::Infallible;

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{
    Ciphertext as MlKemCiphertext, EncapsulationKey, KeyExport, MlKem768, TryKeyInit,
    kem::Kem as _, ml_kem_768::DecapsulationKey,
};
use rand_core::{TryCryptoRng, TryRng};
use ring::agreement::{self, Algorithm, ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SecureRandom;

/// Largest (EC)DHE / hybrid shared secret: ML-KEM-768 (32) ‖ X25519 (32).
pub const MAX_SHARED_LEN: usize = 64;

const X25519_LEN: usize = 32;
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;

/// (EC)DHE / hybrid shared secret of up to [`MAX_SHARED_LEN`] bytes, kept inline
/// (no heap) and zeroized on drop.
pub struct SharedSecret {
    bytes: [u8; MAX_SHARED_LEN],
    len: usize,
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
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        crate::schedule::zeroize(&mut self.bytes);
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    /// Advertised in preference order. X25519MLKEM768 is offered but kept last so
    /// that peers offering classical groups keep the smaller, established
    /// exchange; the post-quantum group is selected only when a client commits a
    /// key share for it.
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

    pub fn to_u16(self) -> u16 {
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

/// rand_core 0.10 adapter over a fixed buffer of bytes drawn from ring up front,
/// so ML-KEM (which wants an infallible `CryptoRng`) is fed system randomness
/// while ring's fallible `fill` is handled at the call boundary.
struct BufRng {
    buf: Vec<u8>,
    pos: usize,
}

impl BufRng {
    fn draw(rng: &dyn SecureRandom, n: usize) -> Result<Self, KxError> {
        let mut buf = alloc::vec![0u8; n];
        rng.fill(&mut buf).map_err(|_| KxError::Generate)?;
        Ok(Self { buf, pos: 0 })
    }
}

impl TryCryptoRng for BufRng {}

impl TryRng for BufRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        assert!(self.pos + dst.len() <= self.buf.len(), "BufRng exhausted");
        dst.copy_from_slice(&self.buf[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
        Ok(())
    }
}

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
    client_share: Vec<u8>,
}

impl EphemeralKey {
    pub fn generate<R: SecureRandom>(group: KexGroup, rng: &R) -> Result<Self, KxError> {
        match group {
            KexGroup::X25519 | KexGroup::Secp256r1 => {
                let inner = EphemeralPrivateKey::generate(group.ecdh_algorithm(), rng)
                    .map_err(|_| KxError::Generate)?;
                let client_share = inner
                    .compute_public_key()
                    .map_err(|_| KxError::Generate)?
                    .as_ref()
                    .to_vec();
                Ok(Self {
                    secret: Secret::Ecdhe(inner),
                    group,
                    client_share,
                })
            }
            KexGroup::X25519Mlkem768 => {
                let mut kem_rng = BufRng::draw(rng, 64)?;
                let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair_from_rng(&mut kem_rng);
                let x25519 =
                    EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| KxError::Generate)?;
                let x25519_pk = x25519.compute_public_key().map_err(|_| KxError::Generate)?;
                let mut client_share = Vec::with_capacity(MLKEM768_EK_LEN + X25519_LEN);
                client_share.extend_from_slice(mlkem_ek.to_bytes().as_slice());
                client_share.extend_from_slice(x25519_pk.as_ref());
                Ok(Self {
                    secret: Secret::Hybrid { x25519, mlkem_dk },
                    group,
                    client_share,
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
                let ct = MlKemCiphertext::<MlKem768>::try_from(ct_bytes)
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

/// Responder (server) side: given the client's share, produce the
/// `server_share` to echo and the matching shared secret in one step. KEM is
/// asymmetric — the responder encapsulates rather than generating its own
/// keypair — so this is a free function, not a mirror of [`EphemeralKey`].
pub fn responder<R: SecureRandom>(
    group: KexGroup,
    client_share: &[u8],
    rng: &R,
) -> Result<(Vec<u8>, SharedSecret), KxError> {
    match group {
        KexGroup::X25519 | KexGroup::Secp256r1 => {
            let eph = EphemeralPrivateKey::generate(group.ecdh_algorithm(), rng)
                .map_err(|_| KxError::Generate)?;
            let server_share = eph
                .compute_public_key()
                .map_err(|_| KxError::Generate)?
                .as_ref()
                .to_vec();
            let peer = UnparsedPublicKey::new(group.ecdh_algorithm(), client_share);
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
            let mut kem_rng = BufRng::draw(rng, 32)?;
            let (ct, mlkem_ss) = ek.encapsulate_with_rng(&mut kem_rng);

            let x25519 =
                EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| KxError::Generate)?;
            let x25519_server_pk = x25519.compute_public_key().map_err(|_| KxError::Generate)?;
            let peer = UnparsedPublicKey::new(&X25519, x25519_client_pk);
            let shared = agreement::agree_ephemeral(x25519, &peer, |x25519_ss| {
                SharedSecret::from_parts(mlkem_ss.as_slice(), x25519_ss)
            })
            .map_err(|_| KxError::InvalidPubkey)?;

            let mut server_share = Vec::with_capacity(MLKEM768_CT_LEN + X25519_LEN);
            server_share.extend_from_slice(ct.as_slice());
            server_share.extend_from_slice(x25519_server_pk.as_ref());
            Ok((server_share, shared))
        }
    }
}
