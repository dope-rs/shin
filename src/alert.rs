use alloc::vec::Vec;

use crate::record::{ContentType, PlaintextRecord, RecordError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

impl AlertLevel {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Warning),
            2 => Some(Self::Fatal),
            _ => None,
        }
    }
}

/// TLS 1.3 alert descriptions (RFC 8446 §6). All alerts except `close_notify`
/// and `user_canceled` are fatal in TLS 1.3 regardless of the level byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

impl AlertDescription {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::CloseNotify,
            10 => Self::UnexpectedMessage,
            20 => Self::BadRecordMac,
            22 => Self::RecordOverflow,
            40 => Self::HandshakeFailure,
            42 => Self::BadCertificate,
            43 => Self::UnsupportedCertificate,
            44 => Self::CertificateRevoked,
            45 => Self::CertificateExpired,
            46 => Self::CertificateUnknown,
            47 => Self::IllegalParameter,
            48 => Self::UnknownCa,
            49 => Self::AccessDenied,
            50 => Self::DecodeError,
            51 => Self::DecryptError,
            70 => Self::ProtocolVersion,
            71 => Self::InsufficientSecurity,
            80 => Self::InternalError,
            86 => Self::InappropriateFallback,
            90 => Self::UserCanceled,
            109 => Self::MissingExtension,
            110 => Self::UnsupportedExtension,
            112 => Self::UnrecognizedName,
            113 => Self::BadCertificateStatusResponse,
            115 => Self::UnknownPskIdentity,
            116 => Self::CertificateRequired,
            120 => Self::NoApplicationProtocol,
            _ => return None,
        })
    }

    /// `close_notify` and `user_canceled` are the only non-fatal alerts in
    /// TLS 1.3; every other alert terminates the connection (RFC 8446 §6.1).
    pub fn is_fatal(self) -> bool {
        !matches!(self, Self::CloseNotify | Self::UserCanceled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub fn fatal(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    pub fn close_notify() -> Self {
        Self {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }
    }

    pub fn body(self) -> [u8; 2] {
        [self.level as u8, self.description as u8]
    }

    /// Parse a 2-byte alert fragment. An unknown description byte is reported as
    /// a decode error rather than guessed at.
    pub fn parse(body: &[u8]) -> Result<Self, AlertParseError> {
        if body.len() != 2 {
            return Err(AlertParseError::BadLength);
        }
        let level = AlertLevel::from_u8(body[0]).ok_or(AlertParseError::BadLevel)?;
        let description =
            AlertDescription::from_u8(body[1]).ok_or(AlertParseError::UnknownDescription)?;
        Ok(Self { level, description })
    }

    /// Encode this alert as a plaintext alert record (content type 21). Used for
    /// alerts sent before the handshake traffic keys are established; later
    /// alerts must be sealed under the current epoch instead.
    pub fn to_plaintext_record(self) -> Vec<u8> {
        PlaintextRecord::encode(ContentType::Alert, &self.body())
            .expect("2-byte alert body fits a plaintext record")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertParseError {
    BadLength,
    BadLevel,
    UnknownDescription,
}

impl From<AlertParseError> for RecordError {
    fn from(_: AlertParseError) -> Self {
        RecordError::BadContentType
    }
}
