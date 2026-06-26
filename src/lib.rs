#![no_std]

extern crate alloc;

use alloc::vec::Vec;

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

mod proto;

pub mod client;
pub mod server;

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Send {
        epoch: Epoch,
        data: Vec<u8>,
    },
    KeysReady {
        epoch: Epoch,
        read_secret: [u8; 32],
        write_secret: [u8; 32],
    },
    PeerExtension {
        ty: u16,
        data: Vec<u8>,
    },
    KeyUpdate {
        direction: KeyDirection,
        secret: [u8; 32],
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
        secret: [u8; 32],
    },
    EarlyDataAccepted,
    EarlyDataRejected,
    Done,
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
    BadCertificateParse(crate::cert::CertError),
    BadCertificateChain(crate::chain::ChainError),
    NoTrustAnchorForIssuer(Vec<u8>),
    BadCertificateVerify,
    BadFinished,
    Kx,
    Sig,
    Spki,
    Rng,
    Encode,
    /// Configuration that cannot authenticate a peer (e.g. X.509 verifier with no
    /// trust anchors). Surfaced by [`Config::validate`](crate::client::Config::validate).
    BadConfig,
}

impl Error {
    /// The fatal TLS alert to send the peer for this error (RFC 8446 §6.2).
    pub fn alert(&self) -> crate::alert::Alert {
        use crate::alert::{Alert, AlertDescription as D};
        use crate::chain::ChainError;
        let d = match self {
            Self::Decode => D::DecodeError,
            Self::IllegalParameter | Self::DowngradeDetected | Self::SigSchemeNotOffered => {
                D::IllegalParameter
            }
            Self::UnexpectedMessage => D::UnexpectedMessage,
            Self::UnsupportedCipherSuite | Self::UnsupportedGroup | Self::UnsupportedSigScheme => {
                D::HandshakeFailure
            }
            Self::BadVersion => D::ProtocolVersion,
            Self::HelloRetryRequest => D::InternalError,
            Self::UnsolicitedExtension => D::UnsupportedExtension,
            Self::MissingExtension => D::MissingExtension,
            Self::KeyShareNotFound => D::HandshakeFailure,
            Self::NoApplicationProtocol => D::NoApplicationProtocol,
            Self::BadCertificate | Self::BadCertificateParse(_) => D::BadCertificate,
            Self::BadCertificateChain(ChainError::Expired | ChainError::NotYetValid) => {
                D::CertificateExpired
            }
            Self::NoTrustAnchorForIssuer(_)
            | Self::BadCertificateChain(ChainError::NoTrustAnchor) => D::UnknownCa,
            Self::BadCertificateChain(_) => D::BadCertificate,
            Self::BadCertificateVerify | Self::BadFinished => D::DecryptError,
            Self::Kx => D::IllegalParameter,
            Self::Sig | Self::Spki | Self::Rng | Self::Encode | Self::BadConfig => D::InternalError,
        };
        Alert::fatal(d)
    }
}

impl From<crate::codec::DecodeError> for Error {
    fn from(_: crate::codec::DecodeError) -> Self {
        Self::Decode
    }
}

impl From<crate::codec::EncodeError> for Error {
    fn from(_: crate::codec::EncodeError) -> Self {
        Self::Encode
    }
}
