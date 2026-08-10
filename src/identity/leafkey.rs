//! Shared peer-key extraction and CertificateVerify checking. Centralizing the
//! key-kind/signature-scheme pairing keeps both handshake directions identical.

use crate::connection;

use crate::crypto::sig;
use crate::wire::protocols;

#[derive(Clone)]
pub(crate) struct LeafKey {
    pub(crate) kind: LeafKeyKind,
    raw: arrayvec::ArrayVec<u8, MAX_PEER_KEY_LEN>,
}

const MAX_PEER_KEY_LEN: usize = 2048;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafKeyKind {
    Ed25519,
    Ecdsa,
    Rsa,
}

impl LeafKey {
    pub(crate) fn from_raw(kind: LeafKeyKind, raw: &[u8]) -> Result<Self, connection::Error> {
        let mut stored = arrayvec::ArrayVec::new();
        stored
            .try_extend_from_slice(raw)
            .map_err(|_| connection::Error::UnsupportedSigScheme)?;
        Ok(Self { kind, raw: stored })
    }

    /// Verify a TLS 1.3 CertificateVerify signature over `msg` with this leaf's
    /// public key. The `(kind, scheme)` pairing is enforced: a scheme that does
    /// not match the key kind is rejected rather than coerced.
    pub(crate) fn verify(
        &self,
        scheme: u16,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), connection::Error> {
        use crate::crypto::sig::VerifyingKey;
        let bad = || connection::Error::BadCertificateVerify;
        match (self.kind, scheme) {
            (LeafKeyKind::Ed25519, protocols::SIG_ED25519) => {
                if self.raw.len() != sig::PUBKEY_LEN {
                    return Err(bad());
                }
                let mut pk = [0u8; sig::PUBKEY_LEN];
                pk.copy_from_slice(&self.raw);
                VerifyingKey::Ed25519(&pk)
                    .verify(msg, sig)
                    .map_err(|_| bad())
            }
            (LeafKeyKind::Ecdsa, protocols::SIG_ECDSA_SECP256R1_SHA256) => {
                VerifyingKey::EcdsaP256(&self.raw)
                    .verify(msg, sig)
                    .map_err(|_| bad())
            }
            (LeafKeyKind::Ecdsa, protocols::SIG_ECDSA_SECP384R1_SHA384) => {
                VerifyingKey::EcdsaP384(&self.raw)
                    .verify(msg, sig)
                    .map_err(|_| bad())
            }
            (LeafKeyKind::Rsa, protocols::SIG_RSA_PSS_RSAE_SHA256) => {
                VerifyingKey::RsaPssSha256(&self.raw)
                    .verify(msg, sig)
                    .map_err(|_| bad())
            }
            (LeafKeyKind::Rsa, protocols::SIG_RSA_PSS_RSAE_SHA384) => {
                VerifyingKey::RsaPssSha384(&self.raw)
                    .verify(msg, sig)
                    .map_err(|_| bad())
            }
            (LeafKeyKind::Rsa, protocols::SIG_RSA_PSS_RSAE_SHA512) => {
                VerifyingKey::RsaPssSha512(&self.raw)
                    .verify(msg, sig)
                    .map_err(|_| bad())
            }
            _ => Err(connection::Error::UnsupportedSigScheme),
        }
    }

    pub(crate) fn from_spki(spki_der: &[u8]) -> Result<Self, connection::Error> {
        use crate::identity::spki::SubjectPublicKey;
        match SubjectPublicKey::decode(spki_der).map_err(|_| connection::Error::Spki)? {
            SubjectPublicKey::Ed25519(pk) => Ok(Self {
                kind: LeafKeyKind::Ed25519,
                raw: arrayvec::ArrayVec::from_iter(pk),
            }),
            SubjectPublicKey::EcdsaP256(uncompressed) => {
                Self::from_raw(LeafKeyKind::Ecdsa, &uncompressed)
            }
            SubjectPublicKey::EcdsaP384(uncompressed) => {
                Self::from_raw(LeafKeyKind::Ecdsa, &uncompressed)
            }
        }
    }

    pub(crate) fn parse_x509(leaf_der: &[u8]) -> Result<(Self, &[u8]), connection::Error> {
        use crate::identity::cert::Cert;
        use crate::identity::cert::OID_EC_PUBLIC_KEY;
        use crate::identity::cert::OID_ED25519;
        use crate::identity::cert::OID_RSA_ENCRYPTION;
        let cert = Cert::parse(leaf_der).map_err(connection::Error::BadCertificateParse)?;
        let spki = cert.tbs.spki;
        let kind = if spki.algorithm.oid == OID_ED25519 {
            LeafKeyKind::Ed25519
        } else if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
            LeafKeyKind::Ecdsa
        } else if spki.algorithm.oid == OID_RSA_ENCRYPTION {
            LeafKeyKind::Rsa
        } else {
            return Err(connection::Error::UnsupportedSigScheme);
        };
        Ok((Self::from_raw(kind, spki.subject_public_key)?, spki.raw_der))
    }
}
