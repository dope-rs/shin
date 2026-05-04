use alloc::vec::Vec;

use ring::rand::SystemRandom;
use ring::signature::{
    self, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256,
    RsaKeyPair, UnparsedPublicKey,
};

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

pub enum SigningKey {
    Ed25519(Ed25519Inner),
    EcdsaP256(EcdsaP256Inner),
    EcdsaP384(EcdsaP384Inner),
    Rsa(RsaInner),
}

pub struct Ed25519Inner {
    seed: [u8; SEED_LEN],
    inner: Ed25519KeyPair,
    pubkey: [u8; PUBKEY_LEN],
}

pub struct EcdsaP256Inner {
    pkcs8: Vec<u8>,
    inner: EcdsaKeyPair,
    pubkey_uncompressed: Vec<u8>,
}

pub struct EcdsaP384Inner {
    pkcs8: Vec<u8>,
    inner: EcdsaKeyPair,
    pubkey_uncompressed: Vec<u8>,
}

pub struct RsaInner {
    pkcs8: Vec<u8>,
    inner: RsaKeyPair,
    public_key_der: Vec<u8>,
}

impl SigningKey {
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, SigError> {
        let inner = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| SigError::InvalidSeed)?;
        let mut pubkey = [0u8; PUBKEY_LEN];
        pubkey.copy_from_slice(inner.public_key().as_ref());
        Ok(Self::Ed25519(Ed25519Inner {
            seed: *seed,
            inner,
            pubkey,
        }))
    }

    pub fn from_ecdsa_p256_pkcs8(pkcs8: &[u8]) -> Result<Self, SigError> {
        let rng = SystemRandom::new();
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
            .map_err(|_| SigError::InvalidKey)?;
        let pubkey_uncompressed = inner.public_key().as_ref().to_vec();
        Ok(Self::EcdsaP256(EcdsaP256Inner {
            pkcs8: pkcs8.to_vec(),
            inner,
            pubkey_uncompressed,
        }))
    }

    pub fn from_ecdsa_p384_pkcs8(pkcs8: &[u8]) -> Result<Self, SigError> {
        let rng = SystemRandom::new();
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8, &rng)
            .map_err(|_| SigError::InvalidKey)?;
        let pubkey_uncompressed = inner.public_key().as_ref().to_vec();
        Ok(Self::EcdsaP384(EcdsaP384Inner {
            pkcs8: pkcs8.to_vec(),
            inner,
            pubkey_uncompressed,
        }))
    }

    pub fn from_rsa_pkcs8(pkcs8: &[u8]) -> Result<Self, SigError> {
        let inner = RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| SigError::InvalidKey)?;
        let public_key_der = inner.public_key().as_ref().to_vec();
        Ok(Self::Rsa(RsaInner {
            pkcs8: pkcs8.to_vec(),
            inner,
            public_key_der,
        }))
    }

    pub fn pubkey(&self) -> &[u8; PUBKEY_LEN] {
        match self {
            Self::Ed25519(k) => &k.pubkey,
            _ => panic!("pubkey() is Ed25519-only"),
        }
    }

    pub fn ecdsa_p256_pubkey(&self) -> Option<&[u8]> {
        match self {
            Self::EcdsaP256(k) => Some(&k.pubkey_uncompressed),
            _ => None,
        }
    }

    pub fn ecdsa_p384_pubkey(&self) -> Option<&[u8]> {
        match self {
            Self::EcdsaP384(k) => Some(&k.pubkey_uncompressed),
            _ => None,
        }
    }

    pub fn rsa_public_key_der(&self) -> Option<&[u8]> {
        match self {
            Self::Rsa(k) => Some(&k.public_key_der),
            _ => None,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(k) => k.inner.sign(msg).as_ref().to_vec(),
            Self::EcdsaP256(k) => {
                let rng = SystemRandom::new();
                k.inner
                    .sign(&rng, msg)
                    .expect("ECDSA sign")
                    .as_ref()
                    .to_vec()
            }
            Self::EcdsaP384(k) => {
                let rng = SystemRandom::new();
                k.inner
                    .sign(&rng, msg)
                    .expect("ECDSA sign")
                    .as_ref()
                    .to_vec()
            }
            Self::Rsa(k) => {
                let rng = SystemRandom::new();
                let mut sig = alloc::vec![0u8; k.inner.public().modulus_len()];
                k.inner
                    .sign(&RSA_PSS_SHA256, &rng, msg, &mut sig)
                    .expect("RSA sign");
                sig
            }
        }
    }

    pub fn sig_scheme(&self) -> u16 {
        match self {
            Self::Ed25519(_) => 0x0807,
            Self::EcdsaP256(_) => 0x0403,
            Self::EcdsaP384(_) => 0x0503,
            Self::Rsa(_) => 0x0804,
        }
    }
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        match self {
            Self::Ed25519(k) => Self::from_seed(&k.seed).expect("seed validated"),
            Self::EcdsaP256(k) => Self::from_ecdsa_p256_pkcs8(&k.pkcs8).expect("pkcs8 validated"),
            Self::EcdsaP384(k) => Self::from_ecdsa_p384_pkcs8(&k.pkcs8).expect("pkcs8 validated"),
            Self::Rsa(k) => Self::from_rsa_pkcs8(&k.pkcs8).expect("pkcs8 validated"),
        }
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
