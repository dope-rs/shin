//! Peer-certificate public-key extraction and CertificateVerify signature
//! checking, shared by the client (verifying the server) and the server
//! (verifying a client under mutual TLS). Keeping the verify match in one place
//! means the security-critical (key-kind, signature-scheme) pairing is reviewed
//! and tested once.

use alloc::vec::Vec;

use crate::Error;
use crate::cert::Cert;
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
}

/// Extract the leaf key from a RawPublicKey (RFC 7250) certificate entry, whose
/// `cert_data` is a bare SubjectPublicKeyInfo.
pub(crate) fn raw_public_key_leaf(spki_der: &[u8]) -> Result<LeafKey, Error> {
    match SubjectPublicKey::decode(spki_der).map_err(|_| Error::Spki)? {
        SubjectPublicKey::Ed25519(pk) => Ok(LeafKey {
            kind: LeafKeyKind::Ed25519,
            raw: pk.to_vec(),
        }),
        SubjectPublicKey::EcdsaP256(uncompressed) => Ok(LeafKey {
            kind: LeafKeyKind::Ecdsa,
            raw: uncompressed,
        }),
        SubjectPublicKey::EcdsaP384(uncompressed) => Ok(LeafKey {
            kind: LeafKeyKind::Ecdsa,
            raw: uncompressed,
        }),
    }
}

/// Parse an X.509 leaf certificate and extract its public key plus the raw
/// SubjectPublicKeyInfo DER (a uniform pinning target across key types). This
/// does NOT validate a chain or trust anchors — the caller pins the returned
/// key/SPKI (the `authorized_keys` model).
pub(crate) fn x509_leaf_key(leaf_der: &[u8]) -> Result<(LeafKey, Vec<u8>), Error> {
    let cert = Cert::parse(leaf_der).map_err(Error::BadCertificateParse)?;
    let spki = cert.spki;
    let kind = if spki.algorithm.oid == crate::cert::OID_ED25519 {
        LeafKeyKind::Ed25519
    } else if spki.algorithm.oid == crate::cert::OID_EC_PUBLIC_KEY {
        LeafKeyKind::Ecdsa
    } else if spki.algorithm.oid == crate::cert::OID_RSA_ENCRYPTION {
        LeafKeyKind::Rsa
    } else {
        return Err(Error::UnsupportedSigScheme);
    };
    Ok((
        LeafKey {
            kind,
            raw: spki.subject_public_key.to_vec(),
        },
        spki.raw_der.to_vec(),
    ))
}
