use crate::connection;
use core::error;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
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
    TransportParametersInTls {
        len: usize,
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
    InvalidResumptionLifetime,
    ResumptionKeyDerivation,
    InvalidEarlyDataEntitlement,
    ClientHelloEncodingOverflow,
    ClientHelloTooLarge {
        len: usize,
        maximum: usize,
    },
    InvalidIdentity,
}

impl fmt::Display for Error {
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
            Self::TransportParametersInTls { len } => write!(
                formatter,
                "TLS mode cannot carry {len} bytes of QUIC transport parameters"
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
            Self::InvalidResumptionLifetime => {
                formatter.write_str("resumption ticket lifetime is invalid")
            }
            Self::ResumptionKeyDerivation => {
                formatter.write_str("resumption PSK derivation failed")
            }
            Self::InvalidEarlyDataEntitlement => {
                formatter.write_str("early-data entitlement is incompatible with this profile")
            }
            Self::ClientHelloEncodingOverflow => {
                formatter.write_str("initial ClientHello length field overflow")
            }
            Self::ClientHelloTooLarge { len, maximum } => write!(
                formatter,
                "initial ClientHello length {len} exceeds TLSPlaintext maximum {maximum}"
            ),
            Self::InvalidIdentity => formatter.write_str("client identity is invalid"),
        }
    }
}

impl error::Error for Error {}

impl From<Error> for connection::Error {
    fn from(_: Error) -> Self {
        Self::BadConfig
    }
}
