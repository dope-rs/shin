use crate::memory::threadbound;
use alloc::boxed;
use ml_kem::KeyExport as _;
use ml_kem::TryKeyInit as _;
use ml_kem::kem::Decapsulate as _;
use ml_kem::ml_kem_768;
use ring::rand;
use zeroize::Zeroize as _;

use core::fmt;

use ring::agreement;

/// Largest (EC)DHE / hybrid shared secret: ML-KEM-768 (32) ‖ X25519 (32).
pub const MAX_SHARED_LEN: usize = 64;

const X25519_LEN: usize = 32;
const P256_LEN: usize = 65;
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
pub(crate) const MAX_CLIENT_SHARE_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;
const MAX_SERVER_SHARE_LEN: usize = MLKEM768_CT_LEN + X25519_LEN;

/// (EC)DHE / hybrid shared secret of up to [`MAX_SHARED_LEN`] bytes, kept inline
/// (no heap) and zeroized on drop.
pub struct SharedSecret {
    bytes: [u8; MAX_SHARED_LEN],
    len: usize,
    _thread: threadbound::ThreadBound,
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
            _thread: threadbound::ThreadBound::NEW,
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
pub enum Error {
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

    fn ecdh_algorithm(self) -> &'static agreement::Algorithm {
        use ring::agreement::ECDH_P256;
        match self {
            Self::Secp256r1 => &ECDH_P256,
            Self::X25519 | Self::X25519Mlkem768 => &agreement::X25519,
        }
    }
}

struct ClassicalMaterial {
    ecdhe: agreement::EphemeralPrivateKey,
    client_share: arrayvec::ArrayVec<u8, P256_LEN>,
}

struct HybridMaterial {
    private: HybridPrivate,
    client_share: arrayvec::ArrayVec<u8, MAX_CLIENT_SHARE_LEN>,
}

struct HybridPrivate {
    x25519: agreement::EphemeralPrivateKey,
    mlkem_dk: ml_kem_768::DecapsulationKey,
}

/// Keep the common classical state inline. The explicitly selected hybrid
/// group pays one allocation for its much larger, short-lived material.
enum Material {
    Classical(ClassicalMaterial),
    /// `Some` is the standalone compatibility owner; `None` is the sealed
    /// token whose private state lives in `HybridWorkspace`.
    Hybrid(Option<boxed::Box<HybridMaterial>>),
}

/// Initiator (client) key-exchange state: holds the private key(s) and exposes
/// the public `client_share` to put in the key_share extension.
pub struct EphemeralKey {
    material: Material,
    group: KexGroup,
    _thread: threadbound::ThreadBound,
}

/// Caller-owned storage for the large hybrid private state. Both the slot and
/// in-place construction are crate-private so a token cannot be paired with an
/// unrelated slot by an embedder.
pub(crate) struct EphemeralKeySlot {
    hybrid: Option<HybridPrivate>,
    _thread: threadbound::ThreadBound,
}

/// Opt-in caller-owned storage for allocation-free hybrid client key exchange.
///
/// The large ML-KEM private state is charged only to callers that construct
/// this workspace. Bind it to a client with
/// [`crate::client::Hybrid`]; ordinary [`crate::client::Client`] and
/// classical handshakes retain their compact layout.
///
/// ```compile_fail
/// use shin::crypto::kx::HybridWorkspace;
/// fn assert_send<T: Send>() {}
/// assert_send::<HybridWorkspace>();
/// ```
pub struct HybridWorkspace {
    slot: EphemeralKeySlot,
}

impl HybridWorkspace {
    pub const fn new() -> Self {
        Self {
            slot: EphemeralKeySlot::new(),
        }
    }

    pub(crate) fn slot_mut(&mut self) -> &mut EphemeralKeySlot {
        &mut self.slot
    }

    pub(crate) fn clear(&mut self) {
        self.slot.clear();
    }
}

impl Default for HybridWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HybridWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridWorkspace")
            .field("occupied", &self.slot.hybrid.is_some())
            .field("private_state", &"[redacted]")
            .finish()
    }
}

impl Drop for HybridWorkspace {
    fn drop(&mut self) {
        self.clear();
    }
}

impl EphemeralKeySlot {
    pub(crate) const fn new() -> Self {
        Self {
            hybrid: None,
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.hybrid = None;
    }
}

impl EphemeralKey {
    pub fn generate<R: rand::SecureRandom>(group: KexGroup, rng: &R) -> Result<Self, Error> {
        match group {
            KexGroup::X25519 | KexGroup::Secp256r1 => {
                let material = generate_classical(group, rng)?;
                Ok(Self {
                    material: Material::Classical(material),
                    group,
                    _thread: threadbound::ThreadBound::NEW,
                })
            }
            KexGroup::X25519Mlkem768 => {
                let (private, client_share) = generate_hybrid(rng)?;
                Ok(Self {
                    material: Material::Hybrid(Some(boxed::Box::new(HybridMaterial {
                        private,
                        client_share,
                    }))),
                    group,
                    _thread: threadbound::ThreadBound::NEW,
                })
            }
        }
    }

    pub fn group(&self) -> KexGroup {
        self.group
    }

    pub fn client_share(&self) -> &[u8] {
        match &self.material {
            Material::Classical(material) => &material.client_share,
            Material::Hybrid(Some(material)) => &material.client_share,
            Material::Hybrid(None) => &[],
        }
    }

    /// Consume the initiator state and combine it with the server's share to
    /// produce the shared secret (32 bytes classical, 64 bytes hybrid).
    pub fn agree(self, server_share: &[u8]) -> Result<SharedSecret, Error> {
        match self.material {
            Material::Classical(material) => {
                let peer =
                    agreement::UnparsedPublicKey::new(self.group.ecdh_algorithm(), server_share);
                agreement::agree_ephemeral(material.ecdhe, &peer, SharedSecret::from_slice)
                    .map_err(|_| Error::InvalidPubkey)
            }
            Material::Hybrid(Some(material)) => agree_hybrid(material.private, server_share),
            Material::Hybrid(None) => Err(Error::Generate),
        }
    }

    pub(crate) fn generate_in<R: rand::SecureRandom>(
        group: KexGroup,
        rng: &R,
        slot: &mut EphemeralKeySlot,
    ) -> Result<(Self, arrayvec::ArrayVec<u8, MAX_CLIENT_SHARE_LEN>), Error> {
        slot.clear();
        match group {
            KexGroup::X25519 | KexGroup::Secp256r1 => {
                let material = generate_classical(group, rng)?;
                let client_share = material.client_share.iter().copied().collect();
                Ok((
                    Self {
                        material: Material::Classical(material),
                        group,
                        _thread: threadbound::ThreadBound::NEW,
                    },
                    client_share,
                ))
            }
            KexGroup::X25519Mlkem768 => {
                let (private, client_share) = generate_hybrid(rng)?;
                slot.hybrid = Some(private);
                Ok((
                    Self {
                        material: Material::Hybrid(None),
                        group,
                        _thread: threadbound::ThreadBound::NEW,
                    },
                    client_share,
                ))
            }
        }
    }

    pub(crate) fn agree_in(
        self,
        slot: &mut EphemeralKeySlot,
        server_share: &[u8],
    ) -> Result<SharedSecret, Error> {
        match self.material {
            Material::Classical(material) => {
                slot.clear();
                agree_classical(self.group, material, server_share)
            }
            Material::Hybrid(None) => {
                let private = slot.hybrid.take().ok_or(Error::Generate)?;
                agree_hybrid(private, server_share)
            }
            Material::Hybrid(Some(material)) => {
                slot.clear();
                agree_hybrid(material.private, server_share)
            }
        }
    }
}

fn generate_classical<R: rand::SecureRandom>(
    group: KexGroup,
    rng: &R,
) -> Result<ClassicalMaterial, Error> {
    let ecdhe = agreement::EphemeralPrivateKey::generate(group.ecdh_algorithm(), rng)
        .map_err(|_| Error::Generate)?;
    let public = ecdhe.compute_public_key().map_err(|_| Error::Generate)?;
    let mut client_share = arrayvec::ArrayVec::new();
    client_share
        .try_extend_from_slice(public.as_ref())
        .map_err(|_| Error::Generate)?;
    Ok(ClassicalMaterial {
        ecdhe,
        client_share,
    })
}

fn generate_hybrid<R: rand::SecureRandom>(
    rng: &R,
) -> Result<(HybridPrivate, arrayvec::ArrayVec<u8, MAX_CLIENT_SHARE_LEN>), Error> {
    use ml_kem::Seed;
    let mut seed = [0u8; 64];
    rng.fill(&mut seed).map_err(|_| Error::Generate)?;
    let mlkem_dk = ml_kem_768::DecapsulationKey::from_seed(Seed::from(seed));
    seed.zeroize();
    let x25519 = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)
        .map_err(|_| Error::Generate)?;
    let x25519_pk = x25519.compute_public_key().map_err(|_| Error::Generate)?;
    let mut client_share = arrayvec::ArrayVec::new();
    client_share
        .try_extend_from_slice(mlkem_dk.encapsulation_key().to_bytes().as_slice())
        .map_err(|_| Error::Generate)?;
    client_share
        .try_extend_from_slice(x25519_pk.as_ref())
        .map_err(|_| Error::Generate)?;
    Ok((HybridPrivate { x25519, mlkem_dk }, client_share))
}

fn agree_classical(
    group: KexGroup,
    material: ClassicalMaterial,
    server_share: &[u8],
) -> Result<SharedSecret, Error> {
    let peer = agreement::UnparsedPublicKey::new(group.ecdh_algorithm(), server_share);
    agreement::agree_ephemeral(material.ecdhe, &peer, SharedSecret::from_slice)
        .map_err(|_| Error::InvalidPubkey)
}

fn agree_hybrid(material: HybridPrivate, server_share: &[u8]) -> Result<SharedSecret, Error> {
    use ml_kem::Ciphertext;
    if server_share.len() != MLKEM768_CT_LEN + X25519_LEN {
        return Err(Error::InvalidPubkey);
    }
    let (ct_bytes, x25519_server_pk) = server_share.split_at(MLKEM768_CT_LEN);
    let ct =
        Ciphertext::<ml_kem::MlKem768>::try_from(ct_bytes).map_err(|_| Error::InvalidPubkey)?;
    let mlkem_ss = material.mlkem_dk.decapsulate(&ct);
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, x25519_server_pk);
    agreement::agree_ephemeral(material.x25519, &peer, |x25519_ss| {
        SharedSecret::from_parts(mlkem_ss.as_slice(), x25519_ss)
    })
    .map_err(|_| Error::InvalidPubkey)
}

impl KexGroup {
    pub fn respond<R: rand::SecureRandom>(
        self,
        client_share: &[u8],
        rng: &R,
    ) -> Result<(arrayvec::ArrayVec<u8, MAX_SERVER_SHARE_LEN>, SharedSecret), Error> {
        match self {
            KexGroup::X25519 | KexGroup::Secp256r1 => {
                let eph = agreement::EphemeralPrivateKey::generate(self.ecdh_algorithm(), rng)
                    .map_err(|_| Error::Generate)?;
                let public = eph.compute_public_key().map_err(|_| Error::Generate)?;
                let mut server_share = arrayvec::ArrayVec::new();
                server_share
                    .try_extend_from_slice(public.as_ref())
                    .map_err(|_| Error::Generate)?;
                let peer = agreement::UnparsedPublicKey::new(self.ecdh_algorithm(), client_share);
                let shared = agreement::agree_ephemeral(eph, &peer, SharedSecret::from_slice)
                    .map_err(|_| Error::InvalidPubkey)?;
                Ok((server_share, shared))
            }
            KexGroup::X25519Mlkem768 => {
                use ml_kem::B32;
                use ml_kem::EncapsulationKey;
                if client_share.len() != MLKEM768_EK_LEN + X25519_LEN {
                    return Err(Error::InvalidPubkey);
                }
                let (ek_bytes, x25519_client_pk) = client_share.split_at(MLKEM768_EK_LEN);
                let ek = EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(ek_bytes)
                    .map_err(|_| Error::InvalidPubkey)?;
                let mut randomness = [0u8; 32];
                rng.fill(&mut randomness).map_err(|_| Error::Generate)?;
                let (ct, mlkem_ss) = ek.encapsulate_deterministic(&B32::from(randomness));

                let x25519 = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)
                    .map_err(|_| Error::Generate)?;
                let x25519_server_pk = x25519.compute_public_key().map_err(|_| Error::Generate)?;
                let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, x25519_client_pk);
                let shared = agreement::agree_ephemeral(x25519, &peer, |x25519_ss| {
                    SharedSecret::from_parts(mlkem_ss.as_slice(), x25519_ss)
                })
                .map_err(|_| Error::InvalidPubkey)?;

                let mut server_share = arrayvec::ArrayVec::new();
                server_share
                    .try_extend_from_slice(ct.as_slice())
                    .map_err(|_| Error::Generate)?;
                server_share
                    .try_extend_from_slice(x25519_server_pk.as_ref())
                    .map_err(|_| Error::Generate)?;
                Ok((server_share, shared))
            }
        }
    }
}
