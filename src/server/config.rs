use alloc::vec::Vec;

use crate::connection::Error;
use crate::crypto::sig::SigningKey;
use crate::crypto::ticket::TicketKeys;
use crate::wire::handshake::messages::Certificate;
use crate::wire::handshake::views::CertificateEntries;

pub struct Config {
    pub source: CertSource,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub ticket_keys: Option<TicketKeys>,
}

impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .alpn_protocols
            .iter()
            .any(|protocol| protocol.is_empty() || protocol.len() > u8::MAX as usize)
        {
            return Err(Error::BadConfig);
        }
        let identity_is_valid = match &self.source {
            CertSource::RawPublicKey { signing_key } => signing_key.is_ed25519(),
            CertSource::X509 {
                chain_der,
                signing_key,
            } => Certificate::chain_fits(chain_der) && signing_key.matches_x509_chain(chain_der),
        };
        if !identity_is_valid {
            return Err(Error::BadConfig);
        }
        Ok(())
    }
}

pub struct ConnectionConfig {
    pub transport_params: Vec<u8>,
}

impl ConnectionConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.transport_params.len() > u16::MAX as usize {
            return Err(Error::BadConfig);
        }
        Ok(())
    }
}

/// Replay store required for safe 0-RTT. Without one, early data is refused even
/// when configured because single-use cannot be proved (RFC 8446 §8).
pub trait EarlyDataGuard {
    #[doc(hidden)]
    const ACCEPTS_EARLY_DATA: bool = true;

    /// Record a single-use token (the PSK binder); `false` means it was already
    /// seen — a replay. Tokens need only be kept for `TICKET_LIFETIME_SECS`.
    fn register(&mut self, token: &[u8]) -> bool;
}

/// Default guard for servers that never accept 0-RTT: reports every token as
/// already-seen, so early data is always refused.
pub struct NoGuard;

impl EarlyDataGuard for NoGuard {
    const ACCEPTS_EARLY_DATA: bool = false;

    fn register(&mut self, _token: &[u8]) -> bool {
        false
    }
}

pub enum CertSource {
    RawPublicKey {
        signing_key: SigningKey,
    },
    X509 {
        chain_der: Vec<Vec<u8>>,
        signing_key: SigningKey,
    },
}

impl CertSource {
    pub(super) fn signing_key(&self) -> &SigningKey {
        match self {
            Self::RawPublicKey { signing_key } => signing_key,
            Self::X509 { signing_key, .. } => signing_key,
        }
    }
}

/// Mutual-TLS policy: `Requested` permits an empty Certificate while `Required`
/// rejects one; presented identities still pass [`ClientCertVerifier`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    Requested,
    Required,
}

/// Default [`ClientCertVerifier`] for a server that does not authenticate
/// clients; its [`verify`](ClientCertVerifier::verify) is never reached.
pub struct NoClientAuth;

impl ClientCertVerifier for NoClientAuth {
    fn verify(&self, _identity: &ClientIdentity<'_>) -> bool {
        false
    }
}

/// Authorizes a possession-proven client identity, typically by pinning
/// `spki_der`; CertificateVerify authenticity has already succeeded.
pub trait ClientCertVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool;
}

/// A signature-verified client identity handed to [`ClientCertVerifier`].
pub struct ClientIdentity<'a> {
    /// `CERT_TYPE_X509` (0) or `CERT_TYPE_RAW_PUBLIC_KEY` (2).
    pub cert_type: u8,
    /// The leaf SubjectPublicKeyInfo DER — a uniform pinning target across key
    /// types. For RawPublicKey this is the entire certificate.
    pub spki_der: &'a [u8],
    /// The presented X.509 chain (leaf first); empty for RawPublicKey.
    pub chain_der: ClientCertificateChain<'a>,
}

#[derive(Clone, Copy)]
pub struct ClientCertificateChain<'a> {
    pub(super) entries: Option<CertificateEntries<'a>>,
}

impl<'a> ClientCertificateChain<'a> {
    pub fn len(self) -> usize {
        self.entries.map_or(0, CertificateEntries::len)
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub fn iter(self) -> impl Iterator<Item = &'a [u8]> {
        self.entries
            .into_iter()
            .flat_map(CertificateEntries::iter)
            .map(|entry| entry.cert_data)
    }
}
