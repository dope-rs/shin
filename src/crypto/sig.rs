use crate::identity::cert;
use crate::memory::threadbound;
use alloc::vec;
use o3::collections::fixed::array;
use ring::rand;
use ring::signature::KeyPair as _;

use ring::signature;

pub const PUBKEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const SEED_LEN: usize = 32;
pub const ECDSA_P256_PUBKEY_LEN: usize = 65;
pub const ECDSA_P384_PUBKEY_LEN: usize = 97;
pub(crate) const MAX_SIGNATURE_LEN: usize = 1024;

/// A TLS SignatureScheme code point with a private outbound representation.
/// Wire decoding preserves unknown registry entries for policy validation.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureScheme(u16);

impl SignatureScheme {
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);
    pub const ED25519: Self = Self(0x0807);

    pub const fn wire_id(self) -> u16 {
        self.0
    }

    pub(crate) const fn from_wire_id(id: u16) -> Self {
        Self(id)
    }
}

const _: () = assert!(core::mem::size_of::<SignatureScheme>() == core::mem::size_of::<u16>());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidSeed,
    InvalidKey,
    VerifyFailed,
}

/// ```compile_fail
/// use shin::crypto::sig::SigningKey;
/// fn assert_send<T: Send>() {}
/// assert_send::<SigningKey>();
/// ```
pub struct SigningKey {
    inner: SigningKeyInner,
    _thread: threadbound::ThreadBound,
}

enum SigningKeyInner {
    Ed25519(Ed25519Inner),
    EcdsaP256(EcdsaP256Inner),
    EcdsaP384(EcdsaP384Inner),
    Rsa(RsaInner),
}

struct Ed25519Inner {
    inner: signature::Ed25519KeyPair,
    pubkey: [u8; PUBKEY_LEN],
}

struct EcdsaP256Inner {
    inner: signature::EcdsaKeyPair,
    pubkey_uncompressed: vec::Vec<u8>,
}

struct EcdsaP384Inner {
    inner: signature::EcdsaKeyPair,
    pubkey_uncompressed: vec::Vec<u8>,
}

struct RsaInner {
    inner: signature::RsaKeyPair,
    public_key_der: vec::Vec<u8>,
}

impl SigningKey {
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, Error> {
        let inner =
            signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| Error::InvalidSeed)?;
        let mut pubkey = [0u8; PUBKEY_LEN];
        pubkey.copy_from_slice(inner.public_key().as_ref());
        Ok(Self {
            inner: SigningKeyInner::Ed25519(Ed25519Inner { inner, pubkey }),
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn from_ecdsa_p256_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let rng = rand::SystemRandom::new();
        let inner =
            signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
                .map_err(|_| Error::InvalidKey)?;
        let pubkey_uncompressed = inner.public_key().as_ref().to_vec();
        Ok(Self {
            inner: SigningKeyInner::EcdsaP256(EcdsaP256Inner {
                inner,
                pubkey_uncompressed,
            }),
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn from_ecdsa_p384_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        use ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING;
        let rng = rand::SystemRandom::new();
        let inner =
            signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8, &rng)
                .map_err(|_| Error::InvalidKey)?;
        let pubkey_uncompressed = inner.public_key().as_ref().to_vec();
        Ok(Self {
            inner: SigningKeyInner::EcdsaP384(EcdsaP384Inner {
                inner,
                pubkey_uncompressed,
            }),
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn from_rsa_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        let inner = signature::RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| Error::InvalidKey)?;
        let public_key_der = inner.public_key().as_ref().to_vec();
        Ok(Self {
            inner: SigningKeyInner::Rsa(RsaInner {
                inner,
                public_key_der,
            }),
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn pubkey(&self) -> Option<&[u8; PUBKEY_LEN]> {
        match &self.inner {
            SigningKeyInner::Ed25519(k) => Some(&k.pubkey),
            _ => None,
        }
    }

    pub fn ecdsa_p256_pubkey(&self) -> Option<&[u8]> {
        match &self.inner {
            SigningKeyInner::EcdsaP256(k) => Some(&k.pubkey_uncompressed),
            _ => None,
        }
    }

    pub fn ecdsa_p384_pubkey(&self) -> Option<&[u8]> {
        match &self.inner {
            SigningKeyInner::EcdsaP384(k) => Some(&k.pubkey_uncompressed),
            _ => None,
        }
    }

    pub fn rsa_public_key_der(&self) -> Option<&[u8]> {
        match &self.inner {
            SigningKeyInner::Rsa(k) => Some(&k.public_key_der),
            _ => None,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<vec::Vec<u8>, Error> {
        Ok(self.sign_fixed(msg)?.into_iter().collect())
    }

    pub(crate) fn sign_fixed(
        &self,
        msg: &[u8],
    ) -> Result<array::CopyInline<u8, MAX_SIGNATURE_LEN>, Error> {
        match &self.inner {
            SigningKeyInner::Ed25519(k) => {
                let signature = k.inner.sign(msg);
                let mut out = array::CopyInline::new();
                out.try_extend_from_slice(signature.as_ref())
                    .map_err(|_| Error::InvalidKey)?;
                Ok(out)
            }
            SigningKeyInner::EcdsaP256(k) => {
                let rng = rand::SystemRandom::new();
                let signature = k.inner.sign(&rng, msg).map_err(|_| Error::InvalidKey)?;
                let mut out = array::CopyInline::new();
                out.try_extend_from_slice(signature.as_ref())
                    .map_err(|_| Error::InvalidKey)?;
                Ok(out)
            }
            SigningKeyInner::EcdsaP384(k) => {
                let rng = rand::SystemRandom::new();
                let signature = k.inner.sign(&rng, msg).map_err(|_| Error::InvalidKey)?;
                let mut out = array::CopyInline::new();
                out.try_extend_from_slice(signature.as_ref())
                    .map_err(|_| Error::InvalidKey)?;
                Ok(out)
            }
            SigningKeyInner::Rsa(k) => {
                use ring::signature::RSA_PSS_SHA256;
                let rng = rand::SystemRandom::new();
                let signature_len = k.inner.public().modulus_len();
                if signature_len > MAX_SIGNATURE_LEN {
                    return Err(Error::InvalidKey);
                }
                let mut sig = array::CopyInline::new();
                for _ in 0..signature_len {
                    sig.push(0).map_err(|_| Error::InvalidKey)?;
                }
                k.inner
                    .sign(&RSA_PSS_SHA256, &rng, msg, sig.as_mut_slice())
                    .map_err(|_| Error::InvalidKey)?;
                Ok(sig)
            }
        }
    }

    pub fn sig_scheme(&self) -> SignatureScheme {
        match &self.inner {
            SigningKeyInner::Ed25519(_) => SignatureScheme::ED25519,
            SigningKeyInner::EcdsaP256(_) => SignatureScheme::ECDSA_SECP256R1_SHA256,
            SigningKeyInner::EcdsaP384(_) => SignatureScheme::ECDSA_SECP384R1_SHA384,
            SigningKeyInner::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
        }
    }

    pub(crate) fn signature_len_upper_bound(&self) -> usize {
        match &self.inner {
            SigningKeyInner::Ed25519(_) => ED25519_SIGNATURE_LEN,
            SigningKeyInner::EcdsaP256(_) => 72,
            SigningKeyInner::EcdsaP384(_) => 104,
            SigningKeyInner::Rsa(key) => key.inner.public().modulus_len(),
        }
    }

    pub(crate) fn is_ed25519(&self) -> bool {
        matches!(&self.inner, SigningKeyInner::Ed25519(_))
    }

    pub(crate) fn matches_spki(&self, spki: &cert::SubjectPublicKeyInfo<'_>) -> bool {
        use cert::algorithm::NamedCurve;
        use cert::algorithm::PublicKey;
        match &self.inner {
            SigningKeyInner::Ed25519(key) => {
                spki.algorithm == PublicKey::Ed25519
                    && spki.subject_public_key == key.pubkey.as_slice()
            }
            SigningKeyInner::EcdsaP256(key) => {
                spki.algorithm == PublicKey::Ec(NamedCurve::P256)
                    && spki.subject_public_key == key.pubkey_uncompressed
            }
            SigningKeyInner::EcdsaP384(key) => {
                spki.algorithm == PublicKey::Ec(NamedCurve::P384)
                    && spki.subject_public_key == key.pubkey_uncompressed
            }
            SigningKeyInner::Rsa(key) => {
                spki.algorithm == PublicKey::Rsa && spki.subject_public_key == key.public_key_der
            }
        }
    }

    pub(crate) fn matches_x509_chain(&self, chain_der: &[vec::Vec<u8>]) -> bool {
        use crate::identity::cert::Cert;
        let Some(leaf_der) = chain_der.first() else {
            return false;
        };
        let Ok(leaf) = Cert::parse(leaf_der) else {
            return false;
        };
        self.matches_spki(&leaf.tbs.spki)
            && chain_der
                .iter()
                .skip(1)
                .all(|certificate| Cert::parse(certificate).is_ok())
    }
}

pub enum VerifyingKey<'a> {
    Ed25519(&'a [u8; PUBKEY_LEN]),
    EcdsaP256(&'a [u8]),
    EcdsaP384(&'a [u8]),
    RsaPssSha256(&'a [u8]),
    RsaPssSha384(&'a [u8]),
    RsaPssSha512(&'a [u8]),
}

impl VerifyingKey<'_> {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        use ring::signature::ECDSA_P256_SHA256_ASN1;
        use ring::signature::ECDSA_P384_SHA384_ASN1;
        use ring::signature::RSA_PSS_2048_8192_SHA256;
        use ring::signature::RSA_PSS_2048_8192_SHA384;
        use ring::signature::RSA_PSS_2048_8192_SHA512;
        use ring::signature::UnparsedPublicKey;
        let bad = || Error::VerifyFailed;
        match self {
            Self::Ed25519(pk) => UnparsedPublicKey::new(&signature::ED25519, &pk[..])
                .verify(msg, sig)
                .map_err(|_| bad()),
            Self::EcdsaP256(pk) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pk)
                .verify(msg, sig)
                .map_err(|_| bad()),
            Self::EcdsaP384(pk) => UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pk)
                .verify(msg, sig)
                .map_err(|_| bad()),
            Self::RsaPssSha256(pk) => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, pk)
                .verify(msg, sig)
                .map_err(|_| bad()),
            Self::RsaPssSha384(pk) => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, pk)
                .verify(msg, sig)
                .map_err(|_| bad()),
            Self::RsaPssSha512(pk) => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, pk)
                .verify(msg, sig)
                .map_err(|_| bad()),
        }
    }
}
