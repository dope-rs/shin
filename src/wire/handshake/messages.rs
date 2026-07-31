use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::iter::repeat_n;

use ring::hmac::{self, Key};

use crate::crypto::hash::{Digest, HashAlg, MAX_HASH_LEN};
use crate::crypto::kdf::{Hkdf, HkdfError};
use crate::wire::codec::{DecodeError, Encode, EncodeError, Reader};
use crate::wire::extension::Extension;
use zeroize::Zeroize;

use super::{MAX_CERTIFICATE_ENTRIES, MAX_HANDSHAKE_SIZE, RANDOM_LEN};

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
    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_u16(self.legacy_version);
        out.put_slice(&self.random);
        out.put_vec_u8(|o| {
            o.put_slice(&self.legacy_session_id);
            Ok(())
        })?;
        out.put_vec_u16(|o| {
            for cs in &self.cipher_suites {
                o.put_u16(*cs);
            }
            Ok(())
        })?;
        out.put_vec_u8(|o| {
            o.put_slice(&self.legacy_compression_methods);
            Ok(())
        })?;
        Extension::encode_list(&self.extensions, out)
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
    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_u16(self.legacy_version);
        out.put_slice(&self.random);
        out.put_vec_u8(|o| {
            o.put_slice(&self.legacy_session_id_echo);
            Ok(())
        })?;
        out.put_u16(self.cipher_suite);
        out.put_u8(self.legacy_compression_method);
        Extension::encode_list(&self.extensions, out)
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
    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_vec_u16(|encoded| {
            for extension in &self.extensions {
                extension.encode(encoded)?;
            }
            Ok(())
        })
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
    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_vec_u24(|o| {
            o.put_slice(&self.cert_data);
            Ok(())
        })?;
        Extension::encode_list(&self.extensions, out)
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
    pub(crate) fn chain_fits(chain_der: &[Vec<u8>]) -> bool {
        const FIXED_MESSAGE_BYTES: usize = 4 + 1 + 3;
        const ENTRY_FRAMING_BYTES: usize = 3 + 2;
        if chain_der.len() > MAX_CERTIFICATE_ENTRIES {
            return false;
        }
        chain_der
            .iter()
            .try_fold(FIXED_MESSAGE_BYTES, |message_len, certificate| {
                message_len.checked_add(ENTRY_FRAMING_BYTES + certificate.len())
            })
            .is_some_and(|message_len| message_len <= MAX_HANDSHAKE_SIZE)
    }

    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_vec_u8(|o| {
            o.put_slice(&self.certificate_request_context);
            Ok(())
        })?;
        out.put_vec_u24(|o| {
            for entry in &self.certificate_list {
                entry.encode(o)?;
            }
            Ok(())
        })
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

/// TLS 1.3 client-auth context and extensions; `signature_algorithms` declares
/// schemes accepted for CertificateVerify (RFC 8446 §4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    pub certificate_request_context: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl CertificateRequest {
    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_vec_u8(|o| {
            o.put_slice(&self.certificate_request_context);
            Ok(())
        })?;
        Extension::encode_list(&self.extensions, out)
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let certificate_request_context = r.vec_u8()?.to_vec();
        let extensions = Extension::decode_list(r)?;
        Ok(Self {
            certificate_request_context,
            extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    pub algorithm: u16,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub(crate) fn message(
        transcript_hash: &[u8],
        from_server: bool,
    ) -> Result<ArrayVec<u8, { 64 + 33 + 1 + MAX_HASH_LEN }>, EncodeError> {
        let context = if from_server {
            b"TLS 1.3, server CertificateVerify".as_slice()
        } else {
            b"TLS 1.3, client CertificateVerify".as_slice()
        };
        let mut msg = ArrayVec::new();
        msg.extend(repeat_n(0x20, 64));
        msg.try_extend_from_slice(context)
            .map_err(|_| EncodeError::Overflow)?;
        msg.push(0x00);
        msg.try_extend_from_slice(transcript_hash)
            .map_err(|_| EncodeError::Overflow)?;
        Ok(msg)
    }

    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_u16(self.algorithm);
        out.put_vec_u16(|o| {
            o.put_slice(&self.signature);
            Ok(())
        })
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
    pub(crate) fn verify_data(
        alg: HashAlg,
        traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Digest, HkdfError> {
        let mut fkey_buf = [0u8; MAX_HASH_LEN];
        let fkey = &mut fkey_buf[..alg.output_len()];
        Hkdf::new(alg).expand_label(traffic_secret, "finished", &[], fkey)?;
        let key = Key::new(alg.hmac(), fkey);
        let mac = Digest::from_slice(hmac::sign(&key, transcript_hash).as_ref());
        fkey.zeroize();
        Ok(mac)
    }

    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_slice(&self.verify_data);
        Ok(())
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
    pub(crate) const ENCODED_LEN: usize = 5;

    pub(crate) fn encode_framed(self) -> [u8; Self::ENCODED_LEN] {
        [HandshakeType::KeyUpdate as u8, 0, 0, 1, self.request_update]
    }

    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_u8(self.request_update);
        Ok(())
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
    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_u32(self.ticket_lifetime);
        out.put_u32(self.ticket_age_add);
        out.put_vec_u8(|o| {
            o.put_slice(&self.ticket_nonce);
            Ok(())
        })?;
        out.put_vec_u16(|o| {
            o.put_slice(&self.ticket);
            Ok(())
        })?;
        Extension::encode_list(&self.extensions, out)
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
