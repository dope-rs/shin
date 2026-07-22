//! Shared peer-key extraction and CertificateVerify checking. Centralizing the
//! key-kind/signature-scheme pairing keeps both handshake directions identical.

use alloc::vec::Vec;

use crate::Error;
use crate::cert::{Cert, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION};
use crate::proto::{
    SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_ED25519, SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512,
};
use crate::sig::{self, VerifyingKey};
use crate::spki::SubjectPublicKey;

#[derive(Clone)]
pub(crate) struct LeafKey {
    pub(crate) kind: LeafKeyKind,
    pub(crate) raw: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafKeyKind {
    Ed25519,
    Ecdsa,
    Rsa,
}

impl LeafKey {
    /// Verify a TLS 1.3 CertificateVerify signature over `msg` with this leaf's
    /// public key. The `(kind, scheme)` pairing is enforced: a scheme that does
    /// not match the key kind is rejected rather than coerced.
    pub(crate) fn verify(&self, scheme: u16, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let bad = || Error::BadCertificateVerify;
        match (self.kind, scheme) {
            (LeafKeyKind::Ed25519, SIG_ED25519) => {
                if self.raw.len() != sig::PUBKEY_LEN {
                    return Err(bad());
                }
                let mut pk = [0u8; sig::PUBKEY_LEN];
                pk.copy_from_slice(&self.raw);
                VerifyingKey::Ed25519(&pk)
                    .verify(msg, sig)
                    .map_err(|_| bad())
            }
            (LeafKeyKind::Ecdsa, SIG_ECDSA_SECP256R1_SHA256) => VerifyingKey::EcdsaP256(&self.raw)
                .verify(msg, sig)
                .map_err(|_| bad()),
            (LeafKeyKind::Ecdsa, SIG_ECDSA_SECP384R1_SHA384) => VerifyingKey::EcdsaP384(&self.raw)
                .verify(msg, sig)
                .map_err(|_| bad()),
            (LeafKeyKind::Rsa, SIG_RSA_PSS_RSAE_SHA256) => VerifyingKey::RsaPssSha256(&self.raw)
                .verify(msg, sig)
                .map_err(|_| bad()),
            (LeafKeyKind::Rsa, SIG_RSA_PSS_RSAE_SHA384) => VerifyingKey::RsaPssSha384(&self.raw)
                .verify(msg, sig)
                .map_err(|_| bad()),
            (LeafKeyKind::Rsa, SIG_RSA_PSS_RSAE_SHA512) => VerifyingKey::RsaPssSha512(&self.raw)
                .verify(msg, sig)
                .map_err(|_| bad()),
            _ => Err(Error::UnsupportedSigScheme),
        }
    }

    pub(crate) fn from_spki(spki_der: &[u8]) -> Result<Self, Error> {
        match SubjectPublicKey::decode(spki_der).map_err(|_| Error::Spki)? {
            SubjectPublicKey::Ed25519(pk) => Ok(Self {
                kind: LeafKeyKind::Ed25519,
                raw: pk.to_vec(),
            }),
            SubjectPublicKey::EcdsaP256(uncompressed) => Ok(Self {
                kind: LeafKeyKind::Ecdsa,
                raw: uncompressed,
            }),
            SubjectPublicKey::EcdsaP384(uncompressed) => Ok(Self {
                kind: LeafKeyKind::Ecdsa,
                raw: uncompressed,
            }),
        }
    }

    pub(crate) fn parse_x509(leaf_der: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        let cert = Cert::parse(leaf_der).map_err(Error::BadCertificateParse)?;
        let spki = cert.spki;
        let kind = if spki.algorithm.oid == OID_ED25519 {
            LeafKeyKind::Ed25519
        } else if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
            LeafKeyKind::Ecdsa
        } else if spki.algorithm.oid == OID_RSA_ENCRYPTION {
            LeafKeyKind::Rsa
        } else {
            return Err(Error::UnsupportedSigScheme);
        };
        Ok((
            Self {
                kind,
                raw: spki.subject_public_key.to_vec(),
            },
            spki.raw_der.to_vec(),
        ))
    }
}
