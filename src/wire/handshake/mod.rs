use crate::wire::codec;

mod frame;
pub mod messages;
pub(crate) mod reassemblers;
pub mod storage;
pub mod views;

pub use frame::Frame;

/// Whether a TLS KeyUpdate asks the peer to update its write key.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateRequest {
    NotRequested = 0,
    Requested = 1,
}

impl KeyUpdateRequest {
    pub(crate) fn from_u8(b: u8) -> Result<Self, codec::DecodeError> {
        match b {
            0 => Ok(Self::NotRequested),
            1 => Ok(Self::Requested),
            _ => Err(codec::DecodeError::InvalidEnum),
        }
    }
}

const _: () = assert!(core::mem::size_of::<KeyUpdateRequest>() == 1);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl Type {
    pub fn from_u8(b: u8) -> Result<Self, codec::DecodeError> {
        Ok(match b {
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            4 => Self::NewSessionTicket,
            5 => Self::EndOfEarlyData,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            13 => Self::CertificateRequest,
            15 => Self::CertificateVerify,
            20 => Self::Finished,
            24 => Self::KeyUpdate,
            254 => Self::MessageHash,
            _ => return Err(codec::DecodeError::InvalidEnum),
        })
    }
}

pub const RANDOM_LEN: usize = 32;
pub const TLS_1_3: u16 = 0x0304;
pub const TLS_1_2: u16 = 0x0303;

pub const HELLO_RETRY_REQUEST_RANDOM: [u8; RANDOM_LEN] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub const MAX_CERTIFICATE_ENTRIES: usize = 16;
pub const MAX_SIZE: usize = 256 * 1024;
pub const MAX_KEY_UPDATES_PER_RECORD: u32 = 8;
pub const MAX_KEY_UPDATES_WITHOUT_APP_DATA: u32 = 8;

/// Returns the complete encoded length named by a TLS handshake header.
#[inline]
pub fn encoded_message_len(header: &[u8]) -> Result<usize, codec::DecodeError> {
    let &[_, high, middle, low, ..] = header else {
        return Err(codec::DecodeError::Underflow);
    };
    let total = 4 + u32::from_be_bytes([0, high, middle, low]) as usize;
    if total > MAX_SIZE {
        return Err(codec::DecodeError::HandshakeTooLarge);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_length_has_one_bounded_wire_definition() {
        assert_eq!(
            encoded_message_len(&[Type::ClientHello as u8, 0, 0, 3]),
            Ok(7)
        );
        assert_eq!(
            encoded_message_len(&[Type::ClientHello as u8, 0, 0]),
            Err(codec::DecodeError::Underflow)
        );
        assert_eq!(
            encoded_message_len(&[Type::Certificate as u8, 4, 0, 0]),
            Err(codec::DecodeError::HandshakeTooLarge)
        );
    }
}
