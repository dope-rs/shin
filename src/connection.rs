use crate::client;
use crate::crypto::material;
use crate::crypto::{hash, kdf};
use crate::wire::alert;
use crate::wire::codec;
use crate::wire::handshake;
use crate::wire::record;
use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use core::{fmt, marker};

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

/// Borrowed writer over storage whose allocation is retained by a pool.
/// Growth past the configured limit is rejected before touching the vector.
pub struct RetainedBytes<'a> {
    bytes: &'a mut Vec<u8>,
    limit: usize,
}

impl<'a> RetainedBytes<'a> {
    pub(crate) fn new(bytes: &'a mut Vec<u8>, limit: usize) -> Self {
        debug_assert!(bytes.capacity() >= limit);
        debug_assert!(bytes.len() <= limit);
        Self { bytes, limit }
    }

    pub fn try_extend(&mut self, value: &[u8]) -> Result<(), Error> {
        let len = self
            .bytes
            .len()
            .checked_add(value.len())
            .filter(|len| *len <= self.limit)
            .ok_or(Error::BadConfig)?;
        debug_assert!(len <= self.bytes.capacity());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.limit - self.bytes.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Epoch {
    Plaintext,
    EarlyData,
    Handshake,
    Application,
}

/// Validated cumulative storage required by each outbound handshake epoch.
///
/// Multiple flights in one epoch are included in the corresponding bound. In
/// particular, `plaintext` covers both ClientHellos (or HRR plus ServerHello)
/// when a HelloRetryRequest occurs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboundLayout {
    plaintext: usize,
    handshake: usize,
    application: usize,
}

impl OutboundLayout {
    pub const fn new(plaintext: usize, handshake: usize, application: usize) -> Self {
        Self {
            plaintext,
            handshake,
            application,
        }
    }

    pub const fn plaintext(self) -> usize {
        self.plaintext
    }

    pub const fn handshake(self) -> usize {
        self.handshake
    }

    pub const fn application(self) -> usize {
        self.application
    }
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
    BadPskBinder,
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
            Self::BadCertificateVerify | Self::BadPskBinder | Self::BadFinished => {
                Description::DecryptError
            }
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
    NewSessionTicket(client::Ticket<'a>),
    ZeroRttKeysReady {
        secret: &'a material::TrafficSecret,
        max_early_data: u32,
        alpn: Option<&'a [u8]>,
    },
    EarlyDataAccepted,
    EarlyDataRejected,
    Done,
}

/// State-machine context accompanying one synchronously emitted event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventContext {
    cipher_suite: Option<record::CipherSuite>,
    key_update_response_requested: bool,
}

impl EventContext {
    pub(crate) fn new(cipher_suite: Option<record::CipherSuite>) -> Self {
        Self {
            cipher_suite,
            key_update_response_requested: false,
        }
    }

    pub(crate) fn emit<S: EventSink + ?Sized>(
        sink: &mut S,
        cipher_suite: Option<record::CipherSuite>,
        event: Event<'_>,
    ) -> Result<(), DriveError<S::Error>> {
        sink.event(event, Self::new(cipher_suite))
            .map_err(DriveError::Sink)
    }

    pub(crate) fn begin_send<'a, S: EventSink + ?Sized>(
        sink: &'a mut S,
        cipher_suite: Option<record::CipherSuite>,
        epoch: Epoch,
        maximum: usize,
    ) -> Result<Option<OutboundFlight<'a>>, DriveError<S::Error>> {
        sink.begin_send(epoch, maximum, Self::new(cipher_suite))
            .map_err(DriveError::Sink)
    }

    /// The record-protection suite negotiated for the connection or authorized
    /// by a resumption ticket for this 0-RTT event.
    pub fn cipher_suite(self) -> Option<record::CipherSuite> {
        self.cipher_suite
    }

    /// Whether this KeyUpdate event came from a peer request that requires a
    /// reciprocal update.
    pub fn key_update_response_requested(self) -> bool {
        self.key_update_response_requested
    }

    fn emit_key_update<S: EventSink + ?Sized>(
        sink: &mut S,
        cipher_suite: Option<record::CipherSuite>,
        event: Event<'_>,
        response_requested: bool,
    ) -> Result<(), DriveError<S::Error>> {
        sink.event(
            event,
            Self {
                cipher_suite,
                key_update_response_requested: response_requested,
            },
        )
        .map_err(DriveError::Sink)
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

    /// Optionally lends storage that will own the next encoded TLS flight.
    ///
    /// Returning a flight consumes the corresponding [`Event::Send`]: shin
    /// encodes directly into the lent owner and does not emit a second event.
    /// The default preserves the borrowed-event API without requiring storage.
    fn begin_send(
        &mut self,
        _epoch: Epoch,
        _maximum: usize,
        _context: EventContext,
    ) -> Result<Option<OutboundFlight<'_>>, Self::Error> {
        Ok(None)
    }

    /// Consumes one event and its state-machine context before returning.
    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error>;
}

/// Event sink that always lends the final owner of an encoded TLS flight.
///
/// Framed transports use this stronger contract so their connection-local TLS
/// workspace never reserves a duplicate outbound buffer. The returned borrow
/// cannot outlive the sink, while the backing allocation remains owned by the
/// transport after the borrow ends.
pub trait LendingEventSink: EventSink {
    fn lend_send(
        &mut self,
        epoch: Epoch,
        context: EventContext,
    ) -> Result<OutboundFlight<'_>, Self::Error>;
}

pub(crate) struct RequiredFlightSink<'a, S: ?Sized>(&'a mut S);

impl<'a, S: LendingEventSink + ?Sized> RequiredFlightSink<'a, S> {
    pub(crate) fn new(sink: &'a mut S) -> Self {
        Self(sink)
    }
}

impl<S: LendingEventSink + ?Sized> EventSink for RequiredFlightSink<'_, S> {
    type Error = S::Error;

    fn begin_send(
        &mut self,
        epoch: Epoch,
        _maximum: usize,
        context: EventContext,
    ) -> Result<Option<OutboundFlight<'_>>, Self::Error> {
        self.0.lend_send(epoch, context).map(Some)
    }

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        self.0.event(event, context)
    }
}

/// Transactional lease into a consumer-owned contiguous TLS flight store.
///
/// Capacity is reserved before shin receives the lease, so encoding cannot
/// allocate. Existing bytes remain available for transport retransmission;
/// failed encoding rolls the appended range back automatically.
pub struct OutboundFlight<'a> {
    pub(crate) bytes: &'a mut Vec<u8>,
    pub(crate) base: usize,
    pub(crate) maximum: usize,
}

impl<'a> OutboundFlight<'a> {
    /// Lends already-reserved storage without invoking the allocator.
    pub fn from_reserved(bytes: &'a mut Vec<u8>, maximum: usize) -> Option<Self> {
        (bytes.capacity().saturating_sub(bytes.len()) >= maximum).then(|| {
            let base = bytes.len();
            Self {
                bytes,
                base,
                maximum,
            }
        })
    }

    pub fn try_append(bytes: &'a mut Vec<u8>, maximum: usize) -> Result<Self, TryReserveError> {
        bytes.try_reserve_exact(maximum)?;
        let base = bytes.len();
        Ok(Self {
            bytes,
            base,
            maximum,
        })
    }
}

pub(crate) trait KeyUpdateRole {
    const READ_SIDE: material::Side;
    const WRITE_SIDE: material::Side;
}

pub(crate) struct ClientRole;

impl KeyUpdateRole for ClientRole {
    const READ_SIDE: material::Side = material::Side::Server;
    const WRITE_SIDE: material::Side = material::Side::Client;
}

pub(crate) struct ServerRole;

impl KeyUpdateRole for ServerRole {
    const READ_SIDE: material::Side = material::Side::Client;
    const WRITE_SIDE: material::Side = material::Side::Server;
}

pub(crate) struct KeyUpdateCore<'traffic, R> {
    traffic: &'traffic mut material::State,
    role: marker::PhantomData<R>,
}

impl<'traffic, R: KeyUpdateRole> KeyUpdateCore<'traffic, R> {
    pub(crate) fn new(traffic: &'traffic mut material::State) -> Self {
        Self {
            traffic,
            role: marker::PhantomData,
        }
    }

    pub(crate) fn receive<S: EventSink + ?Sized>(
        &mut self,
        request: handshake::KeyUpdateRequest,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        if !self.traffic.consume_update() {
            return Err(Error::UnexpectedMessage.into());
        }
        let suite = self.traffic.suite();
        let secret = self.traffic.advance(R::READ_SIDE)?;
        EventContext::emit_key_update(
            events,
            suite,
            Event::KeyUpdate {
                direction: KeyDirection::Read,
                secret,
            },
            request == handshake::KeyUpdateRequest::Requested,
        )?;
        if request == handshake::KeyUpdateRequest::Requested {
            self.traffic.request_key_update_response();
        }
        Ok(())
    }

    pub(crate) fn send<S: EventSink + ?Sized>(
        &mut self,
        request: handshake::KeyUpdateRequest,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        use crate::wire::handshake::messages::KeyUpdate;

        let suite = self.traffic.suite();
        let bytes = KeyUpdate { request }.encode_framed();
        EventContext::emit(
            events,
            suite,
            Event::Send {
                epoch: Epoch::Application,
                data: &bytes,
            },
        )?;
        let secret = self.traffic.advance(R::WRITE_SIDE)?;
        EventContext::emit(
            events,
            suite,
            Event::KeyUpdate {
                direction: KeyDirection::Write,
                secret,
            },
        )?;
        if request == handshake::KeyUpdateRequest::NotRequested {
            self.traffic.clear_key_update_response();
        }
        Ok(())
    }
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
            Self::NewSessionTicket(ticket) => ticket.fmt(f),
            Self::ZeroRttKeysReady {
                max_early_data,
                alpn,
                ..
            } => f
                .debug_struct("ZeroRttKeysReady")
                .field("secret", &REDACTED)
                .field("max_early_data", max_early_data)
                .field("alpn", alpn)
                .finish(),
            Self::EarlyDataAccepted => f.write_str("EarlyDataAccepted"),
            Self::EarlyDataRejected => f.write_str("EarlyDataRejected"),
            Self::Done => f.write_str("Done"),
        }
    }
}
