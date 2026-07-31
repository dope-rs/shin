use core::fmt;

use crate::crypto::hash::Digest;
use crate::crypto::kdf::HkdfError;
use crate::identity::cert::CertError;
use crate::identity::chain::ChainError;
use crate::wire::alert::{Alert, AlertDescription};
use crate::wire::codec::{DecodeError, EncodeError};
use crate::wire::record::CipherSuite;

/// Per-connection wall clock in milliseconds since the UNIX epoch.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRegion {
    FragmentedMessage,
    OutboundFlight,
    PeerIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Decode,
    IllegalParameter,
    UnexpectedMessage,
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
    NoTrustAnchorForIssuer,
    BadCertificateVerify,
    ClientCertRequired,
    AccessDenied,
    BadFinished,
    Kx,
    Sig,
    Spki,
    Rng,
    WorkspaceExhausted(WorkspaceRegion),
    Encode,
    BadConfig,
    NotReady,
}

impl Error {
    pub fn alert(&self) -> Alert {
        let description = match self {
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
            Self::NoTrustAnchorForIssuer | Self::BadCertificateChain(ChainError::NoTrustAnchor) => {
                AlertDescription::UnknownCa
            }
            Self::BadCertificateChain(_) => AlertDescription::BadCertificate,
            Self::ClientCertRequired => AlertDescription::CertificateRequired,
            Self::AccessDenied => AlertDescription::AccessDenied,
            Self::BadCertificateVerify | Self::BadFinished => AlertDescription::DecryptError,
            Self::Kx => AlertDescription::IllegalParameter,
            Self::Sig
            | Self::Spki
            | Self::Rng
            | Self::WorkspaceExhausted(_)
            | Self::Encode
            | Self::BadConfig
            | Self::NotReady => AlertDescription::InternalError,
        };
        Alert::fatal(description)
    }
}

impl From<DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Self::Decode
    }
}

impl From<EncodeError> for Error {
    fn from(error: EncodeError) -> Self {
        match error {
            EncodeError::Capacity => Self::WorkspaceExhausted(WorkspaceRegion::OutboundFlight),
            EncodeError::Overflow => Self::Encode,
        }
    }
}

impl From<HkdfError> for Error {
    fn from(_: HkdfError) -> Self {
        Self::Encode
    }
}

/// One synchronously emitted state-machine event.
///
/// Wire bytes borrow the encoder's storage and cannot escape the callback.
/// Events carrying protocol-owned values transfer those values to the sink.
///
/// ```compile_fail
/// use shin::connection::Event;
/// fn assert_send<T: Send>() {}
/// assert_send::<Event<'static>>();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub enum Event<'a> {
    Send {
        epoch: Epoch,
        data: &'a [u8],
    },
    KeysReady {
        epoch: Epoch,
        read_secret: Digest,
        write_secret: Digest,
    },
    PeerExtension {
        ty: u16,
        data: &'a [u8],
    },
    KeyUpdate {
        direction: KeyDirection,
        secret: Digest,
    },
    NewSessionTicket {
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: &'a [u8],
        ticket: &'a [u8],
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

/// State-machine context accompanying one synchronously emitted event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventContext {
    cipher_suite: Option<CipherSuite>,
}

impl EventContext {
    pub(crate) fn new(cipher_suite: Option<CipherSuite>) -> Self {
        Self { cipher_suite }
    }

    pub(crate) fn emit<S: EventSink + ?Sized>(
        sink: &mut S,
        cipher_suite: Option<CipherSuite>,
        event: Event<'_>,
    ) -> Result<(), DriveError<S::Error>> {
        sink.event(event, Self::new(cipher_suite))
            .map_err(DriveError::Sink)
    }

    /// The negotiated record-protection suite, when negotiation has completed.
    pub fn cipher_suite(self) -> Option<CipherSuite> {
        self.cipher_suite
    }
}

/// Statically separates a TLS protocol failure from a consumer failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveError<E> {
    Protocol(Error),
    Sink(E),
}

impl<E> From<Error> for DriveError<E> {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}

impl<E> From<DecodeError> for DriveError<E> {
    fn from(error: DecodeError) -> Self {
        Self::Protocol(error.into())
    }
}

impl<E> From<EncodeError> for DriveError<E> {
    fn from(error: EncodeError) -> Self {
        Self::Protocol(error.into())
    }
}

impl<E> From<HkdfError> for DriveError<E> {
    fn from(error: HkdfError) -> Self {
        Self::Protocol(error.into())
    }
}

/// Consumes events synchronously; a sink failure stops with [`DriveError::Sink`].
pub trait EventSink {
    type Error;

    /// Consumes one event and its state-machine context before returning.
    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error>;
}

/// Redacts secret material from logs as required by RFC 8446 §C.2.
impl fmt::Debug for Event<'_> {
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
