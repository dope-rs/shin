use crate::crypto::hash;
use crate::crypto::kdf;
use crate::crypto::material;
use crate::crypto::sig;
use crate::wire::codec;
use crate::wire::codec::Encode as _;
use crate::wire::extension;
use alloc::vec;
use o3::collections::fixed::array;

use ring::hmac;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; super::RANDOM_LEN],
    pub legacy_session_id: vec::Vec<u8>,
    pub cipher_suites: vec::Vec<u16>,
    pub legacy_compression_methods: vec::Vec<u8>,
    pub extensions: vec::Vec<extension::Extension>,
}

impl ClientHello {
    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        out.put_u16(self.legacy_version);
        out.put_slice(&self.random);
        let mut session = out.begin_u8()?;
        session.put_slice(&self.legacy_session_id);
        session.finish()?;
        let mut suites = out.begin_u16()?;
        for suite in &self.cipher_suites {
            suites.put_u16(*suite);
        }
        suites.finish()?;
        let mut compression = out.begin_u8()?;
        compression.put_slice(&self.legacy_compression_methods);
        compression.finish()?;
        extension::Extension::encode_list(&self.extensions, out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; super::RANDOM_LEN],
    pub legacy_session_id_echo: vec::Vec<u8>,
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    pub extensions: vec::Vec<extension::Extension>,
}

impl ServerHello {
    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        out.put_u16(self.legacy_version);
        out.put_slice(&self.random);
        let mut session = out.begin_u8()?;
        session.put_slice(&self.legacy_session_id_echo);
        session.finish()?;
        out.put_u16(self.cipher_suite);
        out.put_u8(self.legacy_compression_method);
        extension::Extension::encode_list(&self.extensions, out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedExtensions {
    pub extensions: vec::Vec<extension::Extension>,
}

impl EncryptedExtensions {
    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        let mut encoded = out.begin_u16()?;
        for extension in &self.extensions {
            extension.encode(&mut encoded)?;
        }
        encoded.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntry {
    pub cert_data: vec::Vec<u8>,
    pub extensions: vec::Vec<extension::Extension>,
}

impl CertificateEntry {
    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        let mut data = out.begin_u24()?;
        data.put_slice(&self.cert_data);
        data.finish()?;
        extension::Extension::encode_list(&self.extensions, out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub certificate_request_context: vec::Vec<u8>,
    pub certificate_list: vec::Vec<CertificateEntry>,
}

impl Certificate {
    pub(crate) fn chain_message_len(chain_der: &[vec::Vec<u8>]) -> Option<usize> {
        const FIXED_MESSAGE_BYTES: usize = 4 + 1 + 3;
        const ENTRY_FRAMING_BYTES: usize = 3 + 2;
        if chain_der.len() > super::MAX_CERTIFICATE_ENTRIES {
            return None;
        }
        chain_der
            .iter()
            .try_fold(FIXED_MESSAGE_BYTES, |message_len, certificate| {
                message_len.checked_add(ENTRY_FRAMING_BYTES + certificate.len())
            })
    }

    pub(crate) fn chain_fits(chain_der: &[vec::Vec<u8>]) -> bool {
        use crate::wire::handshake::MAX_SIZE;
        Self::chain_message_len(chain_der).is_some_and(|message_len| message_len <= MAX_SIZE)
    }

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        let mut context = out.begin_u8()?;
        context.put_slice(&self.certificate_request_context);
        context.finish()?;
        let mut entries = out.begin_u24()?;
        for entry in &self.certificate_list {
            entry.encode(&mut entries)?;
        }
        entries.finish()
    }
}

/// TLS 1.3 client-auth context and extensions; `signature_algorithms` declares
/// schemes accepted for CertificateVerify (RFC 8446 §4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    pub certificate_request_context: vec::Vec<u8>,
    pub extensions: vec::Vec<extension::Extension>,
}

impl CertificateRequest {
    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        let mut context = out.begin_u8()?;
        context.put_slice(&self.certificate_request_context);
        context.finish()?;
        extension::Extension::encode_list(&self.extensions, out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    pub algorithm: sig::SignatureScheme,
    pub signature: vec::Vec<u8>,
}

impl CertificateVerify {
    /// Encoded handshake-frame length for a signature of `signature_len` bytes.
    pub(crate) const fn frame_len(signature_len: usize) -> usize {
        const HANDSHAKE_HEADER_LEN: usize = 4;
        const ALGORITHM_LEN: usize = 2;
        const SIGNATURE_VECTOR_LEN: usize = 2;

        HANDSHAKE_HEADER_LEN + ALGORITHM_LEN + SIGNATURE_VECTOR_LEN + signature_len
    }

    pub(crate) fn message(
        transcript_hash: &[u8],
        from_server: bool,
    ) -> Result<array::CopyInline<u8, { 64 + 33 + 1 + hash::MAX_LEN }>, codec::EncodeError> {
        let context = if from_server {
            b"TLS 1.3, server CertificateVerify".as_slice()
        } else {
            b"TLS 1.3, client CertificateVerify".as_slice()
        };
        let mut msg = array::CopyInline::new();
        msg.try_extend_from_slice(&[0x20; 64])
            .map_err(|_| codec::EncodeError::Overflow)?;
        msg.try_extend_from_slice(context)
            .map_err(|_| codec::EncodeError::Overflow)?;
        msg.push(0x00).map_err(|_| codec::EncodeError::Overflow)?;
        msg.try_extend_from_slice(transcript_hash)
            .map_err(|_| codec::EncodeError::Overflow)?;
        Ok(msg)
    }

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        Self::encode_fields(self.algorithm, &self.signature, out)
    }

    pub(crate) fn encode_fields(
        algorithm: sig::SignatureScheme,
        signature_bytes: &[u8],
        out: &mut impl codec::Encode,
    ) -> Result<(), codec::EncodeError> {
        out.put_u16(algorithm.wire_id());
        let mut signature = out.begin_u16()?;
        signature.put_slice(signature_bytes);
        signature.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub verify_data: vec::Vec<u8>,
}

impl Finished {
    pub(crate) fn verify_data(
        alg: hash::Algorithm,
        traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<material::FinishedVerifyData, kdf::HkdfError> {
        use crate::crypto::kdf::Hkdf;
        use ring::hmac::Key;
        let mut raw_key =
            hash::Secret::zeroed(alg.output_len()).map_err(|_| kdf::HkdfError::OutputTooLong)?;
        Hkdf::new(alg).expand_label(traffic_secret, "finished", &[], raw_key.as_mut_slice())?;
        let finished_key = material::FinishedKey::from_secret(raw_key);
        let key = Key::new(alg.hmac(), finished_key.as_slice());
        Ok(material::FinishedVerifyData::from_secret(
            hash::Secret::from_bounded_slice(hmac::sign(&key, transcript_hash).as_ref()),
        ))
    }

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        Self::encode_verify_data(&self.verify_data, out);
        Ok(())
    }

    pub(crate) fn encode_verify_data(verify_data: &[u8], out: &mut impl codec::Encode) {
        out.put_slice(verify_data);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUpdate {
    pub request: super::KeyUpdateRequest,
}

impl KeyUpdate {
    pub(crate) const ENCODED_LEN: usize = 5;

    pub(crate) fn encode_framed(self) -> [u8; Self::ENCODED_LEN] {
        use crate::wire::handshake::Type;
        [Type::KeyUpdate as u8, 0, 0, 1, self.request as u8]
    }

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        out.put_u8(self.request as u8);
        Ok(())
    }

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            request: super::KeyUpdateRequest::from_u8(r.u8()?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSessionTicket {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: vec::Vec<u8>,
    pub ticket: vec::Vec<u8>,
    pub extensions: vec::Vec<extension::Extension>,
}

impl NewSessionTicket {
    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        out.put_u32(self.ticket_lifetime);
        out.put_u32(self.ticket_age_add);
        let mut nonce = out.begin_u8()?;
        nonce.put_slice(&self.ticket_nonce);
        nonce.finish()?;
        let mut ticket = out.begin_u16()?;
        ticket.put_slice(&self.ticket);
        ticket.finish()?;
        extension::Extension::encode_list(&self.extensions, out)
    }
}
