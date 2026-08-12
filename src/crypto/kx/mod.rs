use crate::memory::threadbound;
use alloc::boxed;
use ml_kem::KeyExport as _;
use ml_kem::kem::Decapsulate as _;
use ml_kem::ml_kem_768;
use o3::collections::fixed::array;
use ring::rand;
use zeroize::Zeroize as _;

use core::fmt;

use ring::agreement;

mod initiator;
mod owned;
mod proof;
mod responder;
mod workspace;

#[doc(hidden)]
pub use initiator::Initiator;
#[doc(hidden)]
pub use owned::Owned;
pub(crate) use proof::Proof;
#[doc(hidden)]
pub use workspace::Workspace;

type Respond<R> = for<'output> fn(
    responder::Responder,
    &[u8],
    &R,
    &'output mut [u8],
) -> Result<ServerResponse<'output>, Error>;

/// Largest (EC)DHE / hybrid shared secret: ML-KEM-768 (32) ‖ X25519 (32).
pub const MAX_SHARED_LEN: usize = 64;

const X25519_LEN: usize = 32;
const P256_LEN: usize = 65;
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
pub(crate) const MAX_CLIENT_SHARE_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;

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

/// A server KX result borrowing the caller-owned output containing its share.
#[derive(Debug)]
pub struct ServerResponse<'output> {
    share: &'output [u8],
    secret: SharedSecret,
}

impl<'output> ServerResponse<'output> {
    pub fn share(&self) -> &'output [u8] {
        self.share
    }

    pub fn shared_secret(&self) -> &SharedSecret {
        &self.secret
    }

    pub fn into_secret(self) -> SharedSecret {
        self.secret
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Generate,
    InvalidPubkey,
    InvalidOutput,
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

    pub const fn server_share_len(self) -> usize {
        match self {
            Self::X25519 => X25519_LEN,
            Self::Secp256r1 => P256_LEN,
            Self::X25519Mlkem768 => MLKEM768_CT_LEN + X25519_LEN,
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
    client_share: array::CopyInline<u8, P256_LEN>,
}

struct HybridMaterial {
    private: HybridPrivate,
    client_share: array::CopyInline<u8, MAX_CLIENT_SHARE_LEN>,
}

struct HybridPrivate {
    x25519: agreement::EphemeralPrivateKey,
    mlkem_dk: ml_kem_768::DecapsulationKey,
}

/// Keep the common classical state inline. The explicitly selected hybrid
/// group pays one allocation for its much larger, short-lived material.
enum OwnedMaterial {
    X25519(ClassicalMaterial),
    Secp256r1(ClassicalMaterial),
    Hybrid(boxed::Box<HybridMaterial>),
}

/// Initiator (client) key-exchange state: holds the private key(s) and exposes
/// the public `client_share` to put in the key_share extension.
pub struct EphemeralKey {
    material: OwnedMaterial,
    _thread: threadbound::ThreadBound,
}

/// The inline hybrid variant preserves the workspace's zero-allocation contract.
#[allow(clippy::large_enum_variant)]
enum WorkspaceMaterial {
    Empty,
    X25519(ClassicalMaterial),
    Secp256r1(ClassicalMaterial),
    Hybrid(HybridPrivate),
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
    material: WorkspaceMaterial,
    _thread: threadbound::ThreadBound,
}

impl HybridWorkspace {
    pub const fn new() -> Self {
        Self {
            material: WorkspaceMaterial::Empty,
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.material = WorkspaceMaterial::Empty;
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
            .field(
                "occupied",
                &!matches!(self.material, WorkspaceMaterial::Empty),
            )
            .field("private_state", &"[redacted]")
            .finish()
    }
}

impl Drop for HybridWorkspace {
    fn drop(&mut self) {
        self.clear();
    }
}

impl EphemeralKey {
    pub fn generate<R: rand::SecureRandom>(group: KexGroup, rng: &R) -> Result<Self, Error> {
        let material = match group {
            KexGroup::X25519 => OwnedMaterial::X25519(generate_classical(group, rng)?),
            KexGroup::Secp256r1 => OwnedMaterial::Secp256r1(generate_classical(group, rng)?),
            KexGroup::X25519Mlkem768 => {
                let (private, client_share) = generate_hybrid(rng)?;
                OwnedMaterial::Hybrid(boxed::Box::new(HybridMaterial {
                    private,
                    client_share,
                }))
            }
        };
        Ok(Self {
            material,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn group(&self) -> KexGroup {
        match self.material {
            OwnedMaterial::X25519(_) => KexGroup::X25519,
            OwnedMaterial::Secp256r1(_) => KexGroup::Secp256r1,
            OwnedMaterial::Hybrid(_) => KexGroup::X25519Mlkem768,
        }
    }

    pub fn client_share(&self) -> &[u8] {
        match &self.material {
            OwnedMaterial::X25519(material) | OwnedMaterial::Secp256r1(material) => {
                &material.client_share
            }
            OwnedMaterial::Hybrid(material) => &material.client_share,
        }
    }

    /// Consume the initiator state and combine it with the server's share to
    /// produce the shared secret (32 bytes classical, 64 bytes hybrid).
    pub fn agree(self, server_share: &[u8]) -> Result<SharedSecret, Error> {
        match self.material {
            OwnedMaterial::X25519(material) => {
                agree_classical(KexGroup::X25519, material, server_share)
            }
            OwnedMaterial::Secp256r1(material) => {
                agree_classical(KexGroup::Secp256r1, material, server_share)
            }
            OwnedMaterial::Hybrid(material) => agree_hybrid(material.private, server_share),
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
    let mut client_share = array::CopyInline::new();
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
) -> Result<(HybridPrivate, array::CopyInline<u8, MAX_CLIENT_SHARE_LEN>), Error> {
    use ml_kem::Seed;
    let mut seed = [0u8; 64];
    rng.fill(&mut seed).map_err(|_| Error::Generate)?;
    let mlkem_dk = ml_kem_768::DecapsulationKey::from_seed(Seed::from(seed));
    seed.zeroize();
    let x25519 = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)
        .map_err(|_| Error::Generate)?;
    let x25519_pk = x25519.compute_public_key().map_err(|_| Error::Generate)?;
    let mut client_share = array::CopyInline::new();
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
    pub fn respond<'output, R: rand::SecureRandom>(
        self,
        client_share: &[u8],
        rng: &R,
        output: &'output mut [u8],
    ) -> Result<ServerResponse<'output>, Error> {
        let responder = responder::Responder::new(self);
        let respond: Respond<R> = match self {
            KexGroup::X25519 | KexGroup::Secp256r1 => responder::Responder::classical::<R>,
            KexGroup::X25519Mlkem768 => responder::Responder::hybrid::<R>,
        };
        respond(responder, client_share, rng, output)
    }
}
