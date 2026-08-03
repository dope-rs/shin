use alloc::{rc::Rc, vec::Vec};
use core::{fmt, mem::size_of, ops::Deref};

use crate::connection;
use crate::crypto::sig::{self, SigningKey};
use crate::identity::cert::{Cert, CertError, SubjectPublicKeyInfo};
use crate::identity::chain::TrustAnchor;
use crate::identity::hostname::Hostname;
use crate::memory::bound::ThreadBound;
use crate::wire::handshake::messages::Certificate;
use crate::wire::proto::{CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509};
use crate::wire::record::MAX_PLAINTEXT_BODY;
use zeroize::Zeroize;

pub const MAX_TRUST_ANCHORS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    MissingTrustAnchors,
    TooManyTrustAnchors {
        count: usize,
        maximum: usize,
    },
    MalformedTrustAnchor {
        index: usize,
    },
    MissingServerName,
    InvalidServerName,
    TransportParametersTooLong {
        len: usize,
        maximum: usize,
    },
    EmptyAlpnProtocol {
        index: usize,
    },
    AlpnProtocolTooLong {
        index: usize,
        len: usize,
        maximum: usize,
    },
    AlpnListTooLong {
        len: usize,
        maximum: usize,
    },
    EmptyResumptionTicket,
    ResumptionTicketTooLong {
        len: usize,
        maximum: usize,
    },
    ClientHelloEncodingOverflow,
    ClientHelloTooLarge {
        len: usize,
        maximum: usize,
    },
    InvalidClientIdentity,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTrustAnchors => formatter.write_str("X.509 trust anchor set is empty"),
            Self::TooManyTrustAnchors { count, maximum } => write!(
                formatter,
                "X.509 trust anchor count {count} exceeds maximum {maximum}"
            ),
            Self::MalformedTrustAnchor { index } => {
                write!(formatter, "X.509 trust anchor {index} is malformed")
            }
            Self::MissingServerName => formatter.write_str("X.509 server name is empty"),
            Self::InvalidServerName => formatter.write_str("X.509 server name is invalid"),
            Self::TransportParametersTooLong { len, maximum } => write!(
                formatter,
                "transport parameters length {len} exceeds maximum {maximum}"
            ),
            Self::EmptyAlpnProtocol { index } => {
                write!(formatter, "ALPN protocol {index} is empty")
            }
            Self::AlpnProtocolTooLong {
                index,
                len,
                maximum,
            } => write!(
                formatter,
                "ALPN protocol {index} length {len} exceeds maximum {maximum}"
            ),
            Self::AlpnListTooLong { len, maximum } => {
                write!(
                    formatter,
                    "ALPN list length {len} exceeds maximum {maximum}"
                )
            }
            Self::EmptyResumptionTicket => formatter.write_str("resumption ticket is empty"),
            Self::ResumptionTicketTooLong { len, maximum } => write!(
                formatter,
                "resumption ticket length {len} exceeds maximum {maximum}"
            ),
            Self::ClientHelloEncodingOverflow => {
                formatter.write_str("initial ClientHello length field overflow")
            }
            Self::ClientHelloTooLarge { len, maximum } => write!(
                formatter,
                "initial ClientHello length {len} exceeds TLSPlaintext maximum {maximum}"
            ),
            Self::InvalidClientIdentity => formatter.write_str("client identity is invalid"),
        }
    }
}

impl core::error::Error for ConfigError {}

impl From<ConfigError> for connection::Error {
    fn from(_: ConfigError) -> Self {
        Self::BadConfig
    }
}

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

/// A validated endpoint template and connection-local resumption state.
///
/// Its private fields prove that the exact pair fits the initial TLS record;
/// runtime client construction therefore cannot combine a valid template with
/// an incompatible ticket.
pub struct PreparedConfig {
    pub(super) template: ConfigTemplate,
    pub(super) resumption: Option<Resumption>,
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
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Verifier::X509 { anchors, hostname } = &self.verifier {
            if anchors.is_empty() {
                return Err(ConfigError::MissingTrustAnchors);
            }
            if anchors.len() > MAX_TRUST_ANCHORS {
                return Err(ConfigError::TooManyTrustAnchors {
                    count: anchors.len(),
                    maximum: MAX_TRUST_ANCHORS,
                });
            }
            for (index, anchor) in anchors.iter().enumerate() {
                if anchor.view().is_err() {
                    return Err(ConfigError::MalformedTrustAnchor { index });
                }
            }
            if hostname.is_empty() {
                return Err(ConfigError::MissingServerName);
            }
            if !Hostname::new(hostname).is_valid_reference() {
                return Err(ConfigError::InvalidServerName);
            }
        }
        if self.transport_params.len() > u16::MAX as usize {
            return Err(ConfigError::TransportParametersTooLong {
                len: self.transport_params.len(),
                maximum: u16::MAX as usize,
            });
        }
        let mut alpn_total = 0usize;
        for (index, protocol) in self.alpn_protocols.iter().enumerate() {
            if protocol.is_empty() {
                return Err(ConfigError::EmptyAlpnProtocol { index });
            }
            if protocol.len() > u8::MAX as usize {
                return Err(ConfigError::AlpnProtocolTooLong {
                    index,
                    len: protocol.len(),
                    maximum: u8::MAX as usize,
                });
            }
            alpn_total = alpn_total
                .checked_add(1 + protocol.len())
                .ok_or(ConfigError::ClientHelloEncodingOverflow)?;
        }
        if alpn_total > u16::MAX as usize {
            return Err(ConfigError::AlpnListTooLong {
                len: alpn_total,
                maximum: u16::MAX as usize,
            });
        }
        validate_resumption(self.resumption.as_ref())?;
        validate_client_hello(
            &self.verifier,
            &self.transport_params,
            &self.alpn_protocols,
            self.resumption.as_ref(),
        )?;
        Ok(())
    }

    /// Validates reusable endpoint policy once, then splits it from the
    /// single-use resumption ticket.
    pub fn try_into_template(self) -> Result<(ConfigTemplate, Option<Resumption>), ConfigError> {
        self.validate()?;
        Ok(self.split_template())
    }

    /// Validates the exact first-connection configuration once.
    pub fn try_into_prepared(self) -> Result<PreparedConfig, ConfigError> {
        self.validate()?;
        let (template, resumption) = self.split_template();
        Ok(PreparedConfig {
            template,
            resumption,
        })
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
    /// Attaches connection-local state while preserving the encoded-size proof.
    pub fn with_resumption(
        self,
        resumption: Option<Resumption>,
    ) -> Result<PreparedConfig, ConfigError> {
        validate_resumption(resumption.as_ref())?;
        validate_client_hello(
            &self.inner.verifier,
            &self.inner.transport_params,
            &self.inner.alpn_protocols,
            resumption.as_ref(),
        )?;
        Ok(PreparedConfig {
            template: self,
            resumption,
        })
    }

    /// Removing resumption can only reduce a previously validated ClientHello.
    pub fn without_resumption(self) -> PreparedConfig {
        PreparedConfig {
            template: self,
            resumption: None,
        }
    }

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

impl PreparedConfig {
    /// Returns the validated reusable policy without exposing resumption state.
    pub fn template(&self) -> ConfigTemplate {
        self.template.clone()
    }
}

fn validate_resumption(resumption: Option<&Resumption>) -> Result<(), ConfigError> {
    let Some(resumption) = resumption else {
        return Ok(());
    };
    if resumption.ticket.is_empty() {
        return Err(ConfigError::EmptyResumptionTicket);
    }
    if resumption.ticket.len() > u16::MAX as usize {
        return Err(ConfigError::ResumptionTicketTooLong {
            len: resumption.ticket.len(),
            maximum: u16::MAX as usize,
        });
    }
    Ok(())
}

fn validate_client_hello(
    verifier: &Verifier,
    transport_params: &[u8],
    alpn_protocols: &[Vec<u8>],
    resumption: Option<&Resumption>,
) -> Result<(), ConfigError> {
    let len = super::offer::ClientHelloConfig::maximum_initial_len(
        verifier,
        transport_params,
        alpn_protocols,
        resumption,
    )
    .map_err(|_| ConfigError::ClientHelloEncodingOverflow)?;
    if len > MAX_PLAINTEXT_BODY {
        return Err(ConfigError::ClientHelloTooLarge {
            len,
            maximum: MAX_PLAINTEXT_BODY,
        });
    }
    Ok(())
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

    pub(super) fn view(&self) -> Result<TrustAnchor<'_>, connection::Error> {
        let spki = SubjectPublicKeyInfo::parse_standalone(&self.spki_der)
            .map_err(|_| connection::Error::BadCertificate)?;
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
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        let valid = match self {
            Self::RawPublicKey { signing_key } => signing_key.is_ed25519(),
            Self::X509 {
                chain_der,
                signing_key,
            } => Certificate::chain_fits(chain_der) && signing_key.matches_x509_chain(chain_der),
        };
        if valid {
            Ok(())
        } else {
            Err(ConfigError::InvalidClientIdentity)
        }
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

    pub fn try_into_template(self) -> Result<ClientCertTemplate, ConfigError> {
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
