use alloc::vec::Vec;

use crate::Error;
use crate::cert::{Cert, SubjectPublicKeyInfo};
use crate::chain::TrustAnchor;
use crate::proto::{
    SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_ED25519, SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512,
};
use crate::sig::{self, VerifyingKey};

#[derive(Clone)]
pub struct Config {
    pub verifier: Verifier,
    pub transport_params: Vec<u8>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub resumption: Option<Resumption>,
    pub enable_early_data: bool,
}

#[derive(Clone, Debug)]
pub struct Resumption {
    pub psk: [u8; 32],
    pub ticket: Vec<u8>,
    pub ticket_age_add: u32,
    pub age_millis: u32,
}

#[derive(Clone)]
pub enum Verifier {
    RawPublicKey {
        expected_pubkey: [u8; sig::PUBKEY_LEN],
    },
    X509 {
        anchors: Vec<OwnedTrustAnchor>,
        hostname: Vec<u8>,
        now_seconds: u64,
    },
}

#[derive(Clone)]
pub struct OwnedTrustAnchor {
    pub subject_der: Vec<u8>,
    pub spki_der: Vec<u8>,
}

impl OwnedTrustAnchor {
    pub fn from_cert_der(cert_der: &[u8]) -> Result<Self, crate::cert::CertError> {
        let cert = Cert::parse(cert_der)?;
        Ok(Self {
            subject_der: cert.subject_der.to_vec(),
            spki_der: cert.spki.raw_der.to_vec(),
        })
    }

    pub(super) fn view(&self) -> Result<TrustAnchor<'_>, Error> {
        let spki = SubjectPublicKeyInfo::parse_standalone(&self.spki_der)
            .map_err(|_| Error::BadCertificate)?;
        Ok(TrustAnchor {
            subject_der: &self.subject_der,
            spki,
        })
    }
}

#[derive(Clone)]
pub(super) struct LeafKey {
    pub(super) kind: LeafKeyKind,
    pub(super) raw: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LeafKeyKind {
    Ed25519,
    Ecdsa,
    Rsa,
}

impl LeafKey {
    pub(super) fn verify(&self, scheme: u16, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
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
