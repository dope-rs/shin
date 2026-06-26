use alloc::vec::Vec;

use crate::codec::{DecodeError, Encode, Reader};
use crate::extension::Extension;
use crate::{Epoch, Error};

pub const RANDOM_LEN: usize = 32;
pub const TLS_1_3: u16 = 0x0304;
pub const TLS_1_2: u16 = 0x0303;

pub const MAX_CERTIFICATE_ENTRIES: usize = 16;

/// Bounds peer-pinned memory while reassembling a fragmented message.
pub const MAX_HANDSHAKE_SIZE: usize = 256 * 1024;

/// Anti-amplification cap on KeyUpdates accepted per record, bounding rekey
/// churn from KeyUpdates coalesced into a single record.
pub const MAX_KEY_UPDATES_PER_RECORD: u32 = 8;

/// Inbound handshake message source: reassembles messages fragmented across or
/// coalesced within records (RFC 8446 §5.1), then hands them back decoded one at
/// a time alongside their raw bytes (which feed the transcript). A single message
/// may not span a record epoch change.
#[derive(Default)]
pub struct HsReassembler {
    buf: Vec<u8>,
    /// Read cursor into `buf`; the consumed prefix is compacted away on `push`,
    /// so draining is O(remaining) per record rather than O(n) per message.
    pos: usize,
    epoch: Option<Epoch>,
    key_updates: u32,
}

impl HsReassembler {
    /// Appends a record's handshake bytes, first compacting the prefix consumed
    /// by previous reads so only the pending partial message is retained.
    pub fn push(&mut self, epoch: Epoch, data: &[u8]) -> Result<(), DecodeError> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        if !self.buf.is_empty() && self.epoch != Some(epoch) {
            return Err(DecodeError::HandshakeSpansEpoch);
        }
        self.buf.extend_from_slice(data);
        self.epoch = Some(epoch);
        self.key_updates = 0;
        Ok(())
    }

    /// Returns the next message with its raw bytes, or `None` until the buffer
    /// holds a complete message.
    pub fn next_message(&mut self) -> Result<Option<(Handshake, Vec<u8>)>, Error> {
        let buf = &self.buf[self.pos..];
        if buf.len() < 4 {
            return Ok(None);
        }
        let msg_len = 4 + u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        if msg_len > MAX_HANDSHAKE_SIZE {
            return Err(DecodeError::HandshakeTooLarge.into());
        }
        if buf.len() < msg_len {
            return Ok(None);
        }
        let raw = buf[..msg_len].to_vec();
        self.pos += msg_len;

        let mut r = Reader::new(&raw);
        let msg = Handshake::decode(&mut r)?;
        r.finish()?;
        if matches!(msg, Handshake::KeyUpdate(_)) {
            self.key_updates += 1;
            if self.key_updates > MAX_KEY_UPDATES_PER_RECORD {
                return Err(Error::UnexpectedMessage);
            }
        }
        Ok(Some((msg, raw)))
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
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

impl HandshakeType {
    pub fn from_u8(b: u8) -> Result<Self, DecodeError> {
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
            _ => return Err(DecodeError::InvalidEnum),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; RANDOM_LEN],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.legacy_version);
        out.put_slice(&self.random);
        out.put_vec_u8(|o| o.put_slice(&self.legacy_session_id));
        out.put_vec_u16(|o| {
            for cs in &self.cipher_suites {
                o.put_u16(*cs);
            }
        });
        out.put_vec_u8(|o| o.put_slice(&self.legacy_compression_methods));
        Extension::encode_list(&self.extensions, out);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let legacy_version = r.u16()?;
        let mut random = [0u8; RANDOM_LEN];
        random.copy_from_slice(r.take(RANDOM_LEN)?);
        let legacy_session_id = r.vec_u8()?.to_vec();
        let mut cs_sub = r.sub_u16()?;
        let mut cipher_suites = Vec::new();
        while !cs_sub.is_empty() {
            cipher_suites.push(cs_sub.u16()?);
        }
        let legacy_compression_methods = r.vec_u8()?.to_vec();
        let extensions = Extension::decode_list(r)?;
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; RANDOM_LEN],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.legacy_version);
        out.put_slice(&self.random);
        out.put_vec_u8(|o| o.put_slice(&self.legacy_session_id_echo));
        out.put_u16(self.cipher_suite);
        out.put_u8(self.legacy_compression_method);
        Extension::encode_list(&self.extensions, out);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let legacy_version = r.u16()?;
        let mut random = [0u8; RANDOM_LEN];
        random.copy_from_slice(r.take(RANDOM_LEN)?);
        let legacy_session_id_echo = r.vec_u8()?.to_vec();
        let cipher_suite = r.u16()?;
        let legacy_compression_method = r.u8()?;
        let extensions = Extension::decode_list(r)?;
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,
}

impl EncryptedExtensions {
    pub fn encode(&self, out: &mut Vec<u8>) {
        Extension::encode_list(&self.extensions, out);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let extensions = Extension::decode_list(r)?;
        Ok(Self { extensions })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntry {
    pub cert_data: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl CertificateEntry {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_vec_u24(|o| o.put_slice(&self.cert_data));
        Extension::encode_list(&self.extensions, out);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let cert_data = r.vec_u24()?.to_vec();
        let extensions = Extension::decode_list(r)?;
        Ok(Self {
            cert_data,
            extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub certificate_request_context: Vec<u8>,
    pub certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_vec_u8(|o| o.put_slice(&self.certificate_request_context));
        out.put_vec_u24(|o| {
            for entry in &self.certificate_list {
                entry.encode(o);
            }
        });
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let certificate_request_context = r.vec_u8()?.to_vec();
        let mut sub = r.sub_u24()?;
        let mut certificate_list = Vec::new();
        while !sub.is_empty() {
            if certificate_list.len() >= MAX_CERTIFICATE_ENTRIES {
                return Err(DecodeError::TooManyCertificates);
            }
            certificate_list.push(CertificateEntry::decode(&mut sub)?);
        }
        Ok(Self {
            certificate_request_context,
            certificate_list,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    pub algorithm: u16,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.algorithm);
        out.put_vec_u16(|o| o.put_slice(&self.signature));
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let algorithm = r.u16()?;
        let signature = r.vec_u16()?.to_vec();
        Ok(Self {
            algorithm,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_slice(&self.verify_data);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            verify_data: r.take_all().to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUpdate {
    pub request_update: u8,
}

impl KeyUpdate {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.request_update);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let request_update = r.u8()?;
        if request_update > 1 {
            return Err(DecodeError::InvalidEnum);
        }
        Ok(Self { request_update })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSessionTicket {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl NewSessionTicket {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.ticket_lifetime);
        out.put_u32(self.ticket_age_add);
        out.put_vec_u8(|o| o.put_slice(&self.ticket_nonce));
        out.put_vec_u16(|o| o.put_slice(&self.ticket));
        Extension::encode_list(&self.extensions, out);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let ticket_lifetime = r.u32()?;
        let ticket_age_add = r.u32()?;
        let ticket_nonce = r.vec_u8()?.to_vec();
        let ticket = r.vec_u16()?.to_vec();
        let extensions = Extension::decode_list(r)?;
        Ok(Self {
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket,
            extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EncryptedExtensions(EncryptedExtensions),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    KeyUpdate(KeyUpdate),
    NewSessionTicket(NewSessionTicket),
}

impl Handshake {
    pub fn msg_type(&self) -> HandshakeType {
        match self {
            Self::ClientHello(_) => HandshakeType::ClientHello,
            Self::ServerHello(_) => HandshakeType::ServerHello,
            Self::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            Self::Certificate(_) => HandshakeType::Certificate,
            Self::CertificateVerify(_) => HandshakeType::CertificateVerify,
            Self::Finished(_) => HandshakeType::Finished,
            Self::KeyUpdate(_) => HandshakeType::KeyUpdate,
            Self::NewSessionTicket(_) => HandshakeType::NewSessionTicket,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.msg_type() as u8);
        out.put_vec_u24(|o| match self {
            Self::ClientHello(m) => m.encode(o),
            Self::ServerHello(m) => m.encode(o),
            Self::EncryptedExtensions(m) => m.encode(o),
            Self::Certificate(m) => m.encode(o),
            Self::CertificateVerify(m) => m.encode(o),
            Self::Finished(m) => m.encode(o),
            Self::KeyUpdate(m) => m.encode(o),
            Self::NewSessionTicket(m) => m.encode(o),
        });
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let ty = HandshakeType::from_u8(r.u8()?)?;
        let mut body = r.sub_u24()?;
        let m = match ty {
            HandshakeType::ClientHello => Self::ClientHello(ClientHello::decode(&mut body)?),
            HandshakeType::ServerHello => Self::ServerHello(ServerHello::decode(&mut body)?),
            HandshakeType::EncryptedExtensions => {
                Self::EncryptedExtensions(EncryptedExtensions::decode(&mut body)?)
            }
            HandshakeType::Certificate => Self::Certificate(Certificate::decode(&mut body)?),
            HandshakeType::CertificateVerify => {
                Self::CertificateVerify(CertificateVerify::decode(&mut body)?)
            }
            HandshakeType::Finished => Self::Finished(Finished::decode(&mut body)?),
            HandshakeType::KeyUpdate => Self::KeyUpdate(KeyUpdate::decode(&mut body)?),
            HandshakeType::NewSessionTicket => {
                Self::NewSessionTicket(NewSessionTicket::decode(&mut body)?)
            }
            HandshakeType::EndOfEarlyData
            | HandshakeType::CertificateRequest
            | HandshakeType::MessageHash => return Err(DecodeError::InvalidEnum),
        };
        body.finish()?;
        Ok(m)
    }
}
