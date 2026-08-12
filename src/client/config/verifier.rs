use crate::crypto::sig;
use crate::identity;
use crate::wire::{handshake, record};
use alloc::vec;

/// Explicit upper bound for a peer's encoded TLS Certificate message.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateLimit(u32);

struct CertificateBound<const BYTES: usize>;

impl<const BYTES: usize> CertificateBound<BYTES> {
    const VALID: () = {
        assert!(BYTES >= record::MAX_PLAINTEXT_BODY);
        assert!(BYTES <= handshake::MAX_SIZE);
    };
}

impl CertificateLimit {
    pub const ONE_RECORD: Self = Self(record::MAX_PLAINTEXT_BODY as u32);
    pub const MAXIMUM: Self = Self(handshake::MAX_SIZE as u32);

    /// Creates a compile-time checked certificate-message bound.
    pub const fn new<const BYTES: usize>() -> Self {
        let () = CertificateBound::<BYTES>::VALID;
        Self(BYTES as u32)
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone)]
pub enum Verifier {
    RawPublicKey {
        expected_pubkey: [u8; sig::PUBKEY_LEN],
    },
    X509 {
        anchors: vec::Vec<super::OwnedTrustAnchor>,
        hostname: vec::Vec<u8>,
        certificate_limit: CertificateLimit,
    },
    /// X.509 verification backed by a reusable, issuer-indexed trust store.
    X509Store {
        roots: super::TrustStore,
        hostname: vec::Vec<u8>,
        certificate_limit: CertificateLimit,
    },
}

impl Verifier {
    pub(crate) fn dns_hostname(&self) -> Option<&[u8]> {
        match self {
            Self::X509 { hostname, .. } | Self::X509Store { hostname, .. }
                if !identity::Hostname::new(hostname).is_ip_literal() =>
            {
                Some(hostname)
            }
            Self::RawPublicKey { .. } | Self::X509 { .. } | Self::X509Store { .. } => None,
        }
    }

    pub(super) fn prepare(self) -> Result<Self, super::Error> {
        match self {
            Self::X509 {
                anchors,
                hostname,
                certificate_limit,
            } => Ok(Self::X509Store {
                roots: super::TrustStore::new(anchors)?,
                hostname,
                certificate_limit,
            }),
            verifier => Ok(verifier),
        }
    }

    pub(super) const fn certificate_limit(&self) -> CertificateLimit {
        match self {
            Self::RawPublicKey { .. } => CertificateLimit::ONE_RECORD,
            Self::X509 {
                certificate_limit, ..
            }
            | Self::X509Store {
                certificate_limit, ..
            } => *certificate_limit,
        }
    }
}
