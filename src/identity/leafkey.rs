//! Shared borrowed peer-key extraction and CertificateVerify checking.
//! Keeping the key tied to its backing bytes makes ownership a handshake-
//! state concern rather than paying a fixed per-connection copy.

use crate::connection;
use crate::crypto::sig;
use crate::identity::cert;
use core::mem;

#[derive(Clone, Copy)]
pub(crate) enum LeafKey<'a> {
    Ed25519(&'a [u8; sig::PUBKEY_LEN]),
    EcdsaP256(&'a [u8]),
    EcdsaP384(&'a [u8]),
    Rsa(&'a [u8]),
}

pub(crate) const MAX_PEER_KEY_LEN: usize = 2048;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafKeyKind {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa,
}

const _: () = assert!(mem::size_of::<LeafKey<'static>>() <= 3 * mem::size_of::<usize>());

impl<'a> LeafKey<'a> {
    pub(crate) fn from_raw(kind: LeafKeyKind, raw: &'a [u8]) -> Result<Self, connection::Error> {
        if raw.is_empty() || raw.len() > MAX_PEER_KEY_LEN {
            return Err(connection::Error::UnsupportedSigScheme);
        }
        match kind {
            LeafKeyKind::Ed25519 => Ok(Self::Ed25519(
                raw.try_into()
                    .map_err(|_| connection::Error::UnsupportedSigScheme)?,
            )),
            LeafKeyKind::EcdsaP256
                if raw.len() == sig::ECDSA_P256_PUBKEY_LEN && raw.first() == Some(&0x04) =>
            {
                Ok(Self::EcdsaP256(raw))
            }
            LeafKeyKind::EcdsaP384
                if raw.len() == sig::ECDSA_P384_PUBKEY_LEN && raw.first() == Some(&0x04) =>
            {
                Ok(Self::EcdsaP384(raw))
            }
            LeafKeyKind::Rsa => Ok(Self::Rsa(raw)),
            LeafKeyKind::EcdsaP256 | LeafKeyKind::EcdsaP384 => {
                Err(connection::Error::UnsupportedSigScheme)
            }
        }
    }

    pub(crate) fn kind(self) -> LeafKeyKind {
        match self {
            Self::Ed25519(_) => LeafKeyKind::Ed25519,
            Self::EcdsaP256(_) => LeafKeyKind::EcdsaP256,
            Self::EcdsaP384(_) => LeafKeyKind::EcdsaP384,
            Self::Rsa(_) => LeafKeyKind::Rsa,
        }
    }

    pub(crate) fn raw(self) -> &'a [u8] {
        match self {
            Self::Ed25519(raw) => raw,
            Self::EcdsaP256(raw) | Self::EcdsaP384(raw) | Self::Rsa(raw) => raw,
        }
    }

    /// Verify a TLS 1.3 CertificateVerify signature over `msg` with this leaf's
    /// public key. The enum makes an invalid key-kind/key-bytes pairing
    /// unrepresentable; this match enforces its permitted signature scheme.
    pub(crate) fn verify(
        self,
        scheme: sig::SignatureScheme,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), connection::Error> {
        use crate::crypto::sig::VerifyingKey;
        let key = match (self, scheme) {
            (Self::Ed25519(key), sig::SignatureScheme::ED25519) => VerifyingKey::Ed25519(key),
            (Self::EcdsaP256(key), sig::SignatureScheme::ECDSA_SECP256R1_SHA256) => {
                VerifyingKey::EcdsaP256(key)
            }
            (Self::EcdsaP384(key), sig::SignatureScheme::ECDSA_SECP384R1_SHA384) => {
                VerifyingKey::EcdsaP384(key)
            }
            (Self::Rsa(key), sig::SignatureScheme::RSA_PSS_RSAE_SHA256) => {
                VerifyingKey::RsaPssSha256(key)
            }
            (Self::Rsa(key), sig::SignatureScheme::RSA_PSS_RSAE_SHA384) => {
                VerifyingKey::RsaPssSha384(key)
            }
            (Self::Rsa(key), sig::SignatureScheme::RSA_PSS_RSAE_SHA512) => {
                VerifyingKey::RsaPssSha512(key)
            }
            _ => return Err(connection::Error::UnsupportedSigScheme),
        };
        key.verify(msg, signature)
            .map_err(|_| connection::Error::BadCertificateVerify)
    }

    pub(crate) fn from_spki(spki_der: &'a [u8]) -> Result<Self, connection::Error> {
        use cert::algorithm::PublicKey;
        let spki = cert::SubjectPublicKeyInfo::parse_standalone(spki_der)
            .map_err(|_| connection::Error::Spki)?;
        match spki.algorithm {
            PublicKey::Ed25519 | PublicKey::Ec(_) => Self::from_x509_spki(spki),
            _ => Err(connection::Error::Spki),
        }
    }

    pub(crate) fn from_x509_spki(
        spki: cert::SubjectPublicKeyInfo<'a>,
    ) -> Result<Self, connection::Error> {
        use cert::algorithm::NamedCurve;
        use cert::algorithm::PublicKey;
        let kind = match spki.algorithm {
            PublicKey::Ed25519 => LeafKeyKind::Ed25519,
            PublicKey::Ec(NamedCurve::P256) => LeafKeyKind::EcdsaP256,
            PublicKey::Ec(NamedCurve::P384) => LeafKeyKind::EcdsaP384,
            PublicKey::Rsa => LeafKeyKind::Rsa,
            PublicKey::RsaPss(_)
            | PublicKey::Ec(NamedCurve::Unsupported)
            | PublicKey::Unsupported => {
                return Err(connection::Error::UnsupportedSigScheme);
            }
        };
        Self::from_raw(kind, spki.subject_public_key)
    }

    pub(crate) fn parse_x509(leaf_der: &'a [u8]) -> Result<(Self, &'a [u8]), connection::Error> {
        use crate::identity::cert::Cert;
        let cert = Cert::parse(leaf_der).map_err(connection::Error::BadCertificateParse)?;
        let spki = cert.tbs.spki;
        Ok((Self::from_x509_spki(spki)?, spki.raw_der))
    }
}
