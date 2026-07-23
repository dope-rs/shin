#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use crate::alert::{Alert, AlertDescription};
use crate::cert::CertError;
use crate::chain::ChainError;
use crate::codec::{DecodeError, EncodeError};
use crate::hash::Digest;
use crate::kdf::HkdfError;

pub mod aead;
pub mod alert;
pub mod asn1;
pub mod cert;
pub mod chain;
pub mod codec;
pub mod extension;
pub mod handshake;
pub mod hash;
pub mod hostname;
pub mod kdf;
pub mod kx;
pub mod psk;
pub mod record;
pub mod schedule;
pub mod sig;
pub mod spki;
pub mod ticket;
pub mod time;

mod marker;
mod peer;
mod proto;
mod uninit;

pub mod client;
pub mod server;

/// Per-connection wall clock, milliseconds since the UNIX epoch. Any
/// `Fn() -> u64` is a `Clock`: `Client::new(config, || now_ms())`.
pub trait Clock {
    fn now_ms(&self) -> u64;

    fn now_secs(&self) -> u64 {
        self.now_ms() / 1000
    }
}

impl<F: Fn() -> u64> Clock for F {
    fn now_ms(&self) -> u64 {
        self()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Epoch {
    Plaintext,
    EarlyData,
    Handshake,
    Application,
}

/// ```compile_fail
/// use shin::Event;
/// fn assert_send<T: Send>() {}
/// assert_send::<Event>();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub enum Event {
    Send {
        epoch: Epoch,
        data: Vec<u8>,
    },
    KeysReady {
        epoch: Epoch,
        read_secret: Digest,
        write_secret: Digest,
    },
    PeerExtension {
        ty: u16,
        data: Vec<u8>,
    },
    KeyUpdate {
        direction: KeyDirection,
        secret: Digest,
    },
    NewSessionTicket {
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: Vec<u8>,
        ticket: Vec<u8>,
        max_early_data: Option<u32>,
    },
    ResumptionSecret {
        psk: [u8; 32],
    },
    ZeroRttKeysReady {
        secret: Digest,
    },
    EarlyDataAccepted,
    EarlyDataRejected,
    Done,
}

/// Redacts secret material from logs as required by RFC 8446 §C.2.
impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const REDACTED: &str = "[redacted]";
        match self {
            Self::Send { epoch, data } => f
                .debug_struct("Send")
                .field("epoch", epoch)
                .field("data_len", &data.len())
                .finish(),
            Self::KeysReady { epoch, .. } => f
                .debug_struct("KeysReady")
                .field("epoch", epoch)
                .field("read_secret", &REDACTED)
                .field("write_secret", &REDACTED)
                .finish(),
            Self::PeerExtension { ty, data } => f
                .debug_struct("PeerExtension")
                .field("ty", ty)
                .field("data_len", &data.len())
                .finish(),
            Self::KeyUpdate { direction, .. } => f
                .debug_struct("KeyUpdate")
                .field("direction", direction)
                .field("secret", &REDACTED)
                .finish(),
            Self::NewSessionTicket {
                ticket_lifetime,
                ticket_age_add,
                max_early_data,
                ..
            } => f
                .debug_struct("NewSessionTicket")
                .field("ticket_lifetime", ticket_lifetime)
                .field("ticket_age_add", ticket_age_add)
                .field("max_early_data", max_early_data)
                .field("ticket", &REDACTED)
                .finish(),
            Self::ResumptionSecret { .. } => f
                .debug_struct("ResumptionSecret")
                .field("psk", &REDACTED)
                .finish(),
            Self::ZeroRttKeysReady { .. } => f
                .debug_struct("ZeroRttKeysReady")
                .field("secret", &REDACTED)
                .finish(),
            Self::EarlyDataAccepted => f.write_str("EarlyDataAccepted"),
            Self::EarlyDataRejected => f.write_str("EarlyDataRejected"),
            Self::Done => f.write_str("Done"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Malformed wire encoding — wrong length, truncation (alert `decode_error`).
    Decode,
    /// Well-formed but disallowed value — out-of-range selection, forbidden legacy
    /// field, downgrade sentinel (alert `illegal_parameter`).
    IllegalParameter,
    UnexpectedMessage,
    /// The client sent more 0-RTT early data than the advertised
    /// max_early_data_size, or sent it outside the early-data window
    /// (alert `unexpected_message`, RFC 8446 §4.6.1).
    EarlyDataLimitExceeded,
    UnsupportedCipherSuite,
    UnsupportedGroup,
    UnsupportedSigScheme,
    BadVersion,
    DowngradeDetected,
    HelloRetryRequest,
    UnsolicitedExtension,
    SigSchemeNotOffered,
    MissingExtension,
    KeyShareNotFound,
    NoApplicationProtocol,
    BadCertificate,
    BadCertificateParse(CertError),
    BadCertificateChain(ChainError),
    NoTrustAnchorForIssuer(Vec<u8>),
    BadCertificateVerify,
    /// Client auth was `Required` but the client sent an empty Certificate
    /// (alert `certificate_required`, RFC 8446 §4.4.2.4).
    ClientCertRequired,
    /// The embedder's client-certificate verifier rejected an otherwise valid,
    /// possession-proven client identity (alert `access_denied`).
    AccessDenied,
    BadFinished,
    Kx,
    Sig,
    Spki,
    Rng,
    Encode,
    /// Configuration that cannot authenticate a peer, surfaced by client or
    /// server `Config::validate` before handshake work begins.
    BadConfig,
    /// An operation requiring a completed handshake was attempted too early
    /// (e.g. exporting keying material before the handshake finishes).
    NotReady,
}

impl Error {
    /// The fatal TLS alert to send the peer for this error (RFC 8446 §6.2).
    pub fn alert(&self) -> Alert {
        let d = match self {
            Self::Decode => AlertDescription::DecodeError,
            Self::IllegalParameter | Self::DowngradeDetected | Self::SigSchemeNotOffered => {
                AlertDescription::IllegalParameter
            }
            Self::UnexpectedMessage | Self::EarlyDataLimitExceeded => {
                AlertDescription::UnexpectedMessage
            }
            Self::UnsupportedCipherSuite | Self::UnsupportedGroup | Self::UnsupportedSigScheme => {
                AlertDescription::HandshakeFailure
            }
            Self::BadVersion => AlertDescription::ProtocolVersion,
            Self::HelloRetryRequest => AlertDescription::InternalError,
            Self::UnsolicitedExtension => AlertDescription::UnsupportedExtension,
            Self::MissingExtension => AlertDescription::MissingExtension,
            Self::KeyShareNotFound => AlertDescription::HandshakeFailure,
            Self::NoApplicationProtocol => AlertDescription::NoApplicationProtocol,
            Self::BadCertificate | Self::BadCertificateParse(_) => AlertDescription::BadCertificate,
            Self::BadCertificateChain(ChainError::Expired | ChainError::NotYetValid) => {
                AlertDescription::CertificateExpired
            }
            Self::NoTrustAnchorForIssuer(_)
            | Self::BadCertificateChain(ChainError::NoTrustAnchor) => AlertDescription::UnknownCa,
            Self::BadCertificateChain(_) => AlertDescription::BadCertificate,
            Self::ClientCertRequired => AlertDescription::CertificateRequired,
            Self::AccessDenied => AlertDescription::AccessDenied,
            Self::BadCertificateVerify | Self::BadFinished => AlertDescription::DecryptError,
            Self::Kx => AlertDescription::IllegalParameter,
            Self::Sig
            | Self::Spki
            | Self::Rng
            | Self::Encode
            | Self::BadConfig
            | Self::NotReady => AlertDescription::InternalError,
        };
        Alert::fatal(d)
    }
}

impl From<DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Self::Decode
    }
}

impl From<EncodeError> for Error {
    fn from(_: EncodeError) -> Self {
        Self::Encode
    }
}

impl From<HkdfError> for Error {
    fn from(_: HkdfError) -> Self {
        Self::Encode
    }
}
