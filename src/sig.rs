use alloc::vec::Vec;

use ring::rand::SystemRandom;
use ring::signature::{
    self, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256,
    RsaKeyPair, UnparsedPublicKey,
};

use crate::cert::{Cert, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION, SubjectPublicKeyInfo};
use crate::marker::ThreadBound;

pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const SEED_LEN: usize = 32;
pub const ECDSA_P256_PUBKEY_LEN: usize = 65;
pub const ECDSA_P384_PUBKEY_LEN: usize = 97;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    InvalidSeed,
    InvalidKey,
    VerifyFailed,
}

/// ```compile_fail
/// use shin::sig::SigningKey;
/// fn assert_send<T: Send>() {}
/// assert_send::<SigningKey>();
/// ```
pub struct SigningKey {
    inner: SigningKeyInner,
    _thread: ThreadBound,
}

enum SigningKeyInner {
    Ed25519(Ed25519Inner),
    EcdsaP256(EcdsaP256Inner),
    EcdsaP384(EcdsaP384Inner),
    Rsa(RsaInner),
}

struct Ed25519Inner {
    inner: Ed25519KeyPair,
    pubkey: [u8; PUBKEY_LEN],
}

struct EcdsaP256Inner {
    inner: EcdsaKeyPair,
    pubkey_uncompressed: Vec<u8>,
}

struct EcdsaP384Inner {
    inner: EcdsaKeyPair,
    pubkey_uncompressed: Vec<u8>,
}

struct RsaInner {
    inner: RsaKeyPair,
    public_key_der: Vec<u8>,
}

impl SigningKey {
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, SigError> {
        let inner = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| SigError::InvalidSeed)?;
        let mut pubkey = [0u8; PUBKEY_LEN];
        pubkey.copy_from_slice(inner.public_key().as_ref());
        Ok(Self {
            inner: SigningKeyInner::Ed25519(Ed25519Inner { inner, pubkey }),
            _thread: ThreadBound::NEW,
        })
    }

    pub fn from_ecdsa_p256_pkcs8(pkcs8: &[u8]) -> Result<Self, SigError> {
        let rng = SystemRandom::new();
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
            .map_err(|_| SigError::InvalidKey)?;
        let pubkey_uncompressed = inner.public_key().as_ref().to_vec();
        Ok(Self {
            inner: SigningKeyInner::EcdsaP256(EcdsaP256Inner {
                inner,
                pubkey_uncompressed,
            }),
            _thread: ThreadBound::NEW,
        })
    }

    pub fn from_ecdsa_p384_pkcs8(pkcs8: &[u8]) -> Result<Self, SigError> {
        let rng = SystemRandom::new();
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8, &rng)
            .map_err(|_| SigError::InvalidKey)?;
        let pubkey_uncompressed = inner.public_key().as_ref().to_vec();
        Ok(Self {
            inner: SigningKeyInner::EcdsaP384(EcdsaP384Inner {
                inner,
                pubkey_uncompressed,
            }),
            _thread: ThreadBound::NEW,
        })
    }

    pub fn from_rsa_pkcs8(pkcs8: &[u8]) -> Result<Self, SigError> {
        let inner = RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| SigError::InvalidKey)?;
        let public_key_der = inner.public_key().as_ref().to_vec();
        Ok(Self {
            inner: SigningKeyInner::Rsa(RsaInner {
                inner,
                public_key_der,
            }),
            _thread: ThreadBound::NEW,
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

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SigError> {
        match &self.inner {
            SigningKeyInner::Ed25519(k) => Ok(k.inner.sign(msg).as_ref().to_vec()),
            SigningKeyInner::EcdsaP256(k) => {
                let rng = SystemRandom::new();
                Ok(k.inner
                    .sign(&rng, msg)
                    .map_err(|_| SigError::InvalidKey)?
                    .as_ref()
                    .to_vec())
            }
            SigningKeyInner::EcdsaP384(k) => {
                let rng = SystemRandom::new();
                Ok(k.inner
                    .sign(&rng, msg)
                    .map_err(|_| SigError::InvalidKey)?
                    .as_ref()
                    .to_vec())
            }
            SigningKeyInner::Rsa(k) => {
                let rng = SystemRandom::new();
                let mut sig = alloc::vec![0u8; k.inner.public().modulus_len()];
                k.inner
                    .sign(&RSA_PSS_SHA256, &rng, msg, &mut sig)
                    .map_err(|_| SigError::InvalidKey)?;
                Ok(sig)
            }
        }
    }

    pub fn sig_scheme(&self) -> u16 {
        match &self.inner {
            SigningKeyInner::Ed25519(_) => 0x0807,
            SigningKeyInner::EcdsaP256(_) => 0x0403,
            SigningKeyInner::EcdsaP384(_) => 0x0503,
            SigningKeyInner::Rsa(_) => 0x0804,
        }
    }

    pub(crate) fn is_ed25519(&self) -> bool {
        matches!(&self.inner, SigningKeyInner::Ed25519(_))
    }

    pub(crate) fn matches_spki(&self, spki: &SubjectPublicKeyInfo<'_>) -> bool {
        match &self.inner {
            SigningKeyInner::Ed25519(key) => {
                spki.algorithm.oid == OID_ED25519
                    && spki.subject_public_key == key.pubkey.as_slice()
            }
            SigningKeyInner::EcdsaP256(key) => {
                spki.algorithm.oid == OID_EC_PUBLIC_KEY
                    && spki.subject_public_key == key.pubkey_uncompressed
            }
            SigningKeyInner::EcdsaP384(key) => {
                spki.algorithm.oid == OID_EC_PUBLIC_KEY
                    && spki.subject_public_key == key.pubkey_uncompressed
            }
            SigningKeyInner::Rsa(key) => {
                spki.algorithm.oid == OID_RSA_ENCRYPTION
                    && spki.subject_public_key == key.public_key_der
            }
        }
    }

    pub(crate) fn matches_x509_chain(&self, chain_der: &[Vec<u8>]) -> bool {
        let Some(leaf_der) = chain_der.first() else {
            return false;
        };
        let Ok(leaf) = Cert::parse(leaf_der) else {
            return false;
        };
        self.matches_spki(&leaf.spki)
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
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), SigError> {
        let bad = || SigError::VerifyFailed;
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
