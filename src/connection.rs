use crate::crypto::material;
use crate::crypto::{hash, kdf};
use crate::wire::alert;
use crate::wire::codec;
use crate::wire::record;
use core::fmt;

use crate::identity::cert;
use crate::identity::chain;

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
    BadCertificateParse(cert::Error),
    BadCertificateChain(chain::Error),
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
    /// This endpoint observed a fatal protocol, policy, or event-sink failure
    /// and can no longer be driven safely.
    ConnectionFailed,
}

impl Error {
    pub fn alert(&self) -> alert::Alert {
        use crate::wire::alert::Description;
        let description = match self {
            Self::Decode => Description::DecodeError,
            Self::IllegalParameter | Self::DowngradeDetected | Self::SigSchemeNotOffered => {
                Description::IllegalParameter
            }
            Self::UnexpectedMessage | Self::EarlyDataLimitExceeded => {
                Description::UnexpectedMessage
            }
            Self::UnsupportedCipherSuite | Self::UnsupportedGroup | Self::UnsupportedSigScheme => {
                Description::HandshakeFailure
            }
            Self::BadVersion => Description::ProtocolVersion,
            Self::HelloRetryRequest => Description::InternalError,
            Self::UnsolicitedExtension => Description::UnsupportedExtension,
            Self::MissingExtension => Description::MissingExtension,
            Self::KeyShareNotFound => Description::HandshakeFailure,
            Self::NoApplicationProtocol => Description::NoApplicationProtocol,
            Self::BadCertificate | Self::BadCertificateParse(_) => Description::BadCertificate,
            Self::BadCertificateChain(chain::Error::Expired | chain::Error::NotYetValid) => {
                Description::CertificateExpired
            }
            Self::NoTrustAnchorForIssuer
            | Self::BadCertificateChain(chain::Error::NoTrustAnchor) => Description::UnknownCa,
            Self::BadCertificateChain(_) => Description::BadCertificate,
            Self::ClientCertRequired => Description::CertificateRequired,
            Self::AccessDenied => Description::AccessDenied,
            Self::BadCertificateVerify | Self::BadFinished => Description::DecryptError,
            Self::Kx => Description::IllegalParameter,
            Self::Sig
            | Self::Spki
            | Self::Rng
            | Self::WorkspaceExhausted(_)
            | Self::Encode
            | Self::BadConfig
            | Self::NotReady
            | Self::ConnectionFailed => Description::InternalError,
        };
        alert::Alert::fatal(description)
    }
}

impl From<codec::DecodeError> for Error {
    fn from(_: codec::DecodeError) -> Self {
        Self::Decode
    }
}

impl From<codec::EncodeError> for Error {
    fn from(error: codec::EncodeError) -> Self {
        match error {
            codec::EncodeError::Capacity => {
                Self::WorkspaceExhausted(WorkspaceRegion::OutboundFlight)
            }
            codec::EncodeError::Overflow => Self::Encode,
        }
    }
}

impl From<kdf::HkdfError> for Error {
    fn from(_: kdf::HkdfError) -> Self {
        Self::Encode
    }
}

impl From<hash::TranscriptError> for Error {
    fn from(_: hash::TranscriptError) -> Self {
        Self::ConnectionFailed
    }
}

/// One synchronously emitted state-machine event.
///
/// Wire bytes borrow the encoder's storage and cannot escape the callback.
/// Secret-bearing events borrow protocol-owned values for the duration of the
/// callback, so secrets cannot escape without an explicit copy into a
/// zeroizing owner.
///
/// ```compile_fail
/// use shin::connection::Event;
/// fn assert_send<T: Send>() {}
/// assert_send::<Event<'static>>();
/// ```
///
/// ```compile_fail
/// use shin::connection::Event;
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<Event<'static>>();
/// ```
pub enum Event<'a> {
    Send {
        epoch: Epoch,
        data: &'a [u8],
    },
    KeysReady {
        epoch: Epoch,
        read_secret: &'a material::TrafficSecret,
        write_secret: &'a material::TrafficSecret,
    },
    PeerExtension {
        ty: u16,
        data: &'a [u8],
    },
    KeyUpdate {
        direction: KeyDirection,
        secret: &'a material::TrafficSecret,
    },
    NewSessionTicket {
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: &'a [u8],
        ticket: &'a [u8],
        max_early_data: Option<u32>,
    },
    ResumptionSecret {
        psk: &'a material::ResumptionPsk,
    },
    ZeroRttKeysReady {
        secret: &'a material::TrafficSecret,
    },
    EarlyDataAccepted,
    EarlyDataRejected,
    Done,
}

/// State-machine context accompanying one synchronously emitted event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventContext {
    cipher_suite: Option<record::CipherSuite>,
}

impl EventContext {
    pub(crate) fn new(cipher_suite: Option<record::CipherSuite>) -> Self {
        Self { cipher_suite }
    }

    pub(crate) fn emit<S: EventSink + ?Sized>(
        sink: &mut S,
        cipher_suite: Option<record::CipherSuite>,
        event: Event<'_>,
    ) -> Result<(), DriveError<S::Error>> {
        sink.event(event, Self::new(cipher_suite))
            .map_err(DriveError::Sink)
    }

    /// The negotiated record-protection suite, when negotiation has completed.
    pub fn cipher_suite(self) -> Option<record::CipherSuite> {
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

impl<E> From<codec::DecodeError> for DriveError<E> {
    fn from(error: codec::DecodeError) -> Self {
        Self::Protocol(error.into())
    }
}

impl<E> From<codec::EncodeError> for DriveError<E> {
    fn from(error: codec::EncodeError) -> Self {
        Self::Protocol(error.into())
    }
}

impl<E> From<kdf::HkdfError> for DriveError<E> {
    fn from(error: kdf::HkdfError) -> Self {
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
