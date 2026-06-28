use alloc::vec::Vec;

use crate::Error;
use crate::cert::{Cert, SubjectPublicKeyInfo};
use crate::chain::TrustAnchor;
use crate::proto::{CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509};
use crate::sig::{self, SigningKey};

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
    },
}

impl Config {
    /// Reject obviously-broken configuration before a handshake starts: an X.509
    /// verifier needs at least one trust anchor and a non-empty server name, and
    /// lengths that would overflow their wire encodings (and thus panic during
    /// ClientHello construction) are refused up front.
    pub fn validate(&self) -> Result<(), Error> {
        if let Verifier::X509 { anchors, hostname } = &self.verifier
            && (anchors.is_empty() || hostname.is_empty())
        {
            return Err(Error::BadConfig);
        }
        if self.transport_params.len() > u16::MAX as usize {
            return Err(Error::BadConfig);
        }
        let mut alpn_total = 0usize;
        for p in &self.alpn_protocols {
            if p.is_empty() || p.len() > u8::MAX as usize {
                return Err(Error::BadConfig);
            }
            alpn_total += 1 + p.len();
        }
        if alpn_total > u16::MAX as usize {
            return Err(Error::BadConfig);
        }
        Ok(())
    }
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

/// A client identity to present when the server requests client authentication
/// (mutual TLS). Mirrors the server's [`CertSource`](crate::server::CertSource).
#[derive(Clone)]
pub enum ClientCertSource {
    /// Bare public key (RFC 7250). The signing key must be Ed25519 (the only
    /// RawPublicKey type shin encodes as a SubjectPublicKeyInfo).
    RawPublicKey { signing_key: SigningKey },
    /// X.509 chain, leaf first, with the leaf's private key.
    X509 {
        chain_der: Vec<Vec<u8>>,
        signing_key: SigningKey,
    },
}

impl ClientCertSource {
    pub(super) fn signing_key(&self) -> &SigningKey {
        match self {
            Self::RawPublicKey { signing_key } => signing_key,
            Self::X509 { signing_key, .. } => signing_key,
        }
    }

    pub(super) fn cert_type(&self) -> u8 {
        match self {
            Self::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            Self::X509 { .. } => CERT_TYPE_X509,
        }
    }
}
