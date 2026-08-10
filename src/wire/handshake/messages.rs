use crate::crypto::hash;
use crate::crypto::kdf;
use crate::crypto::material;
use crate::wire::codec;
use crate::wire::codec::Encode as _;
use crate::wire::extension;
use crate::wire::handshake::views;
use alloc::vec;

use ring::hmac;

fn own_extensions(extensions: extension::Extensions<'_>) -> vec::Vec<extension::Extension> {
    extensions
        .iter()
        .map(|extension| extension::Extension::new(extension.ty, extension.data.to_vec()))
        .collect()
}

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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::ClientHelloRef::decode(r)?.into())
    }
}

impl From<views::ClientHelloRef<'_>> for ClientHello {
    fn from(message: views::ClientHelloRef<'_>) -> Self {
        Self {
            legacy_version: message.legacy_version,
            random: message.random,
            legacy_session_id: message.legacy_session_id.to_vec(),
            cipher_suites: message.cipher_suites.iter().collect(),
            legacy_compression_methods: message.legacy_compression_methods.to_vec(),
            extensions: own_extensions(message.extensions),
        }
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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::ServerHelloRef::decode(r)?.into())
    }
}

impl From<views::ServerHelloRef<'_>> for ServerHello {
    fn from(message: views::ServerHelloRef<'_>) -> Self {
        Self {
            legacy_version: message.legacy_version,
            random: message.random,
            legacy_session_id_echo: message.legacy_session_id_echo.to_vec(),
            cipher_suite: message.cipher_suite,
            legacy_compression_method: message.legacy_compression_method,
            extensions: own_extensions(message.extensions),
        }
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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::EncryptedExtensionsRef::decode(r)?.into())
    }
}

impl From<views::EncryptedExtensionsRef<'_>> for EncryptedExtensions {
    fn from(message: views::EncryptedExtensionsRef<'_>) -> Self {
        Self {
            extensions: own_extensions(message.extensions),
        }
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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::CertificateEntryRef::decode(r)?.into())
    }
}

impl From<views::CertificateEntryRef<'_>> for CertificateEntry {
    fn from(entry: views::CertificateEntryRef<'_>) -> Self {
        Self {
            cert_data: entry.cert_data.to_vec(),
            extensions: own_extensions(entry.extensions),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub certificate_request_context: vec::Vec<u8>,
    pub certificate_list: vec::Vec<CertificateEntry>,
}

impl Certificate {
    pub(crate) fn chain_fits(chain_der: &[vec::Vec<u8>]) -> bool {
        use crate::wire::handshake::MAX_SIZE;
        const FIXED_MESSAGE_BYTES: usize = 4 + 1 + 3;
        const ENTRY_FRAMING_BYTES: usize = 3 + 2;
        if chain_der.len() > super::MAX_CERTIFICATE_ENTRIES {
            return false;
        }
        chain_der
            .iter()
            .try_fold(FIXED_MESSAGE_BYTES, |message_len, certificate| {
                message_len.checked_add(ENTRY_FRAMING_BYTES + certificate.len())
            })
            .is_some_and(|message_len| message_len <= MAX_SIZE)
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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::CertificateRef::decode(r)?.into())
    }
}

impl From<views::CertificateRef<'_>> for Certificate {
    fn from(message: views::CertificateRef<'_>) -> Self {
        Self {
            certificate_request_context: message.certificate_request_context.to_vec(),
            certificate_list: message.certificate_list.iter().map(Into::into).collect(),
        }
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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::CertificateRequestRef::decode(r)?.into())
    }
}

impl From<views::CertificateRequestRef<'_>> for CertificateRequest {
    fn from(message: views::CertificateRequestRef<'_>) -> Self {
        Self {
            certificate_request_context: message.certificate_request_context.to_vec(),
            extensions: own_extensions(message.extensions),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    pub algorithm: u16,
    pub signature: vec::Vec<u8>,
}

impl CertificateVerify {
    pub(crate) fn message(
        transcript_hash: &[u8],
        from_server: bool,
    ) -> Result<arrayvec::ArrayVec<u8, { 64 + 33 + 1 + hash::MAX_LEN }>, codec::EncodeError> {
        use core::iter::repeat_n;
        let context = if from_server {
            b"TLS 1.3, server CertificateVerify".as_slice()
        } else {
            b"TLS 1.3, client CertificateVerify".as_slice()
        };
        let mut msg = arrayvec::ArrayVec::new();
        msg.extend(repeat_n(0x20, 64));
        msg.try_extend_from_slice(context)
            .map_err(|_| codec::EncodeError::Overflow)?;
        msg.push(0x00);
        msg.try_extend_from_slice(transcript_hash)
            .map_err(|_| codec::EncodeError::Overflow)?;
        Ok(msg)
    }

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        Self::encode_fields(self.algorithm, &self.signature, out)
    }

    pub(crate) fn encode_fields(
        algorithm: u16,
        signature_bytes: &[u8],
        out: &mut impl codec::Encode,
    ) -> Result<(), codec::EncodeError> {
        out.put_u16(algorithm);
        let mut signature = out.begin_u16()?;
        signature.put_slice(signature_bytes);
        signature.finish()
    }

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::CertificateVerifyRef::decode(r)?.into())
    }
}

impl From<views::CertificateVerifyRef<'_>> for CertificateVerify {
    fn from(message: views::CertificateVerifyRef<'_>) -> Self {
        Self {
            algorithm: message.algorithm,
            signature: message.signature.to_vec(),
        }
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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
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
        use crate::wire::handshake::Type;
        [Type::KeyUpdate as u8, 0, 0, 1, self.request_update]
    }

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        out.put_u8(self.request_update);
        Ok(())
    }

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        let request_update = r.u8()?;
        if request_update > 1 {
            return Err(codec::DecodeError::InvalidEnum);
        }
        Ok(Self { request_update })
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

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(views::NewSessionTicketRef::decode(r)?.into())
    }
}

impl From<views::NewSessionTicketRef<'_>> for NewSessionTicket {
    fn from(message: views::NewSessionTicketRef<'_>) -> Self {
        Self {
            ticket_lifetime: message.ticket_lifetime,
            ticket_age_add: message.ticket_age_add,
            ticket_nonce: message.ticket_nonce.to_vec(),
            ticket: message.ticket.to_vec(),
            extensions: own_extensions(message.extensions),
        }
    }
}
