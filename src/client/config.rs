use alloc::{rc::Rc, vec::Vec};
use core::{fmt, mem::size_of, ops::Deref};

use crate::connection::Error;
use crate::crypto::kx::MAX_CLIENT_SHARE_LEN;
use crate::crypto::sig::{self, SigningKey};
use crate::identity::cert::{Cert, CertError, SubjectPublicKeyInfo};
use crate::identity::chain::TrustAnchor;
use crate::memory::bound::ThreadBound;
use crate::wire::handshake::messages::Certificate;
use crate::wire::proto::{CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509};
use crate::wire::record::MAX_PLAINTEXT_BODY;
use zeroize::Zeroize;

pub const MAX_TRUST_ANCHORS: usize = 256;

// Exact upper bound for every non-configurable byte in an initial ClientHello:
// fixed fields, all supported suites/groups/signatures, the largest supported
// key share, and every optional extension header. Keeping the variable portion
// below the remainder proves that the initial flight fits one TLSPlaintext.
const MAX_CLIENT_HELLO_FIXED_BYTES: usize =
    83 + 7 + 12 + 18 + (10 + MAX_CLIENT_SHARE_LEN) + 6 + 6 + 4 + 9 + 6 + 4 + 6 + 47;
const MAX_CLIENT_HELLO_CONFIG_BYTES: usize = MAX_PLAINTEXT_BODY - MAX_CLIENT_HELLO_FIXED_BYTES;

pub struct Config {
    pub verifier: Verifier,
    pub transport_params: Vec<u8>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub resumption: Option<Resumption>,
    pub enable_early_data: bool,
}

/// Immutable, cheaply cloned client configuration shared by connections that
/// use the same endpoint policy. Resumption remains connection-local and is
/// deliberately split out when a [`Config`] becomes a template.
#[derive(Clone)]
pub struct ConfigTemplate {
    inner: Rc<StaticConfig>,
}

struct StaticConfig {
    verifier: Verifier,
    transport_params: Vec<u8>,
    alpn_protocols: Vec<Vec<u8>>,
    enable_early_data: bool,
}

const _: () = assert!(size_of::<ConfigTemplate>() == size_of::<usize>());

/// ```compile_fail
/// use shin::client::config::Resumption;
/// fn assert_send<T: Send>() {}
/// assert_send::<Resumption>();
/// ```
pub struct Resumption {
    pub psk: [u8; 32],
    pub ticket: Vec<u8>,
    pub ticket_age_add: u32,
    pub age_millis: u32,
    _thread: ThreadBound,
}

impl Resumption {
    pub fn new(psk: [u8; 32], ticket: Vec<u8>, ticket_age_add: u32, age_millis: u32) -> Self {
        Self {
            psk,
            ticket,
            ticket_age_add,
            age_millis,
            _thread: ThreadBound::NEW,
        }
    }
}

impl Drop for Resumption {
    fn drop(&mut self) {
        self.psk.zeroize();
    }
}

impl fmt::Debug for Resumption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resumption")
            .field("psk", &"[redacted]")
            .field("ticket_len", &self.ticket.len())
            .field("ticket_age_add", &self.ticket_age_add)
            .field("age_millis", &self.age_millis)
            .finish()
    }
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
    /// Reject unusable trust, identity, or wire-length settings before the
    /// handshake starts.
    pub fn validate(&self) -> Result<(), Error> {
        if let Verifier::X509 { anchors, hostname } = &self.verifier
            && (anchors.is_empty()
                || anchors.len() > MAX_TRUST_ANCHORS
                || hostname.is_empty()
                || hostname.len() > u16::MAX as usize - 3
                || anchors.iter().any(|anchor| anchor.view().is_err()))
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
        if self.resumption.as_ref().is_some_and(|resumption| {
            resumption.ticket.is_empty() || resumption.ticket.len() > u16::MAX as usize
        }) {
            return Err(Error::BadConfig);
        }
        let hostname_len = match &self.verifier {
            Verifier::RawPublicKey { .. } => 0,
            Verifier::X509 { hostname, .. } => hostname.len(),
        };
        let ticket_len = self
            .resumption
            .as_ref()
            .map_or(0, |resumption| resumption.ticket.len());
        let client_hello_config_bytes = self
            .transport_params
            .len()
            .checked_add(alpn_total)
            .and_then(|bytes| bytes.checked_add(hostname_len))
            .and_then(|bytes| bytes.checked_add(ticket_len))
            .ok_or(Error::BadConfig)?;
        if client_hello_config_bytes > MAX_CLIENT_HELLO_CONFIG_BYTES {
            return Err(Error::BadConfig);
        }
        Ok(())
    }

    /// Validates reusable endpoint policy once, then splits it from the
    /// single-use resumption ticket.
    pub fn try_into_template(self) -> Result<(ConfigTemplate, Option<Resumption>), Error> {
        self.validate()?;
        Ok(self.split_template())
    }

    fn split_template(mut self) -> (ConfigTemplate, Option<Resumption>) {
        let resumption = self.resumption.take();
        let inner = StaticConfig {
            verifier: self.verifier,
            transport_params: self.transport_params,
            alpn_protocols: self.alpn_protocols,
            enable_early_data: self.enable_early_data,
        };
        (
            ConfigTemplate {
                inner: Rc::new(inner),
            },
            resumption,
        )
    }
}

impl ConfigTemplate {
    pub(crate) fn verifier(&self) -> &Verifier {
        &self.inner.verifier
    }

    pub(crate) fn transport_params(&self) -> &[u8] {
        &self.inner.transport_params
    }

    pub(crate) fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.inner.alpn_protocols
    }

    pub(crate) fn enable_early_data(&self) -> bool {
        self.inner.enable_early_data
    }
}

#[derive(Clone)]
pub struct OwnedTrustAnchor {
    pub subject_der: Vec<u8>,
    pub spki_der: Vec<u8>,
}

impl OwnedTrustAnchor {
    pub fn from_cert_der(cert_der: &[u8]) -> Result<Self, CertError> {
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

/// A validated client identity shared by every connection from an mTLS
/// endpoint. The signing key is immutable, so sharing avoids reparsing or
/// duplicating private-key material on each dial.
#[derive(Clone)]
pub struct ClientCertTemplate {
    source: Rc<ClientCertSource>,
}

const _: () = assert!(size_of::<ClientCertTemplate>() == size_of::<usize>());

impl ClientCertSource {
    pub(super) fn validate(&self) -> Result<(), Error> {
        let valid = match self {
            Self::RawPublicKey { signing_key } => signing_key.is_ed25519(),
            Self::X509 {
                chain_der,
                signing_key,
            } => Certificate::chain_fits(chain_der) && signing_key.matches_x509_chain(chain_der),
        };
        if valid { Ok(()) } else { Err(Error::BadConfig) }
    }

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

    pub fn try_into_template(self) -> Result<ClientCertTemplate, Error> {
        self.validate()?;
        Ok(ClientCertTemplate {
            source: Rc::new(self),
        })
    }
}

impl ClientCertTemplate {
    pub(crate) fn cert_type(&self) -> u8 {
        self.source.cert_type()
    }
}

impl Deref for ClientCertTemplate {
    type Target = ClientCertSource;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}
