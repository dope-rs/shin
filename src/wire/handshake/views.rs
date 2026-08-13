use crate::crypto::sig;
use crate::wire::codec;
use crate::wire::extension;
use crate::wire::handshake::messages;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U16List<'a> {
    encoded: &'a [u8],
}

impl<'a> U16List<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let encoded = codec::FramedVector::<2, 2>::decode_u16(reader)?.as_slice();
        Ok(Self { encoded })
    }

    pub fn contains(self, needle: u16) -> bool {
        self.iter().any(|value| value == needle)
    }

    pub fn is_empty(self) -> bool {
        self.encoded.is_empty()
    }

    pub fn len(self) -> usize {
        self.encoded.len() / 2
    }

    pub fn iter(self) -> U16s<'a> {
        U16s {
            reader: codec::Reader::new(self.encoded),
        }
    }
}

pub struct U16s<'a> {
    reader: codec::Reader<'a>,
}

impl Iterator for U16s<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        self.reader.u16().ok()
    }
}

/// Allocation-free view of a validated ClientHello body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHelloRef<'a> {
    pub legacy_version: u16,
    pub random: [u8; super::RANDOM_LEN],
    pub legacy_session_id: &'a [u8],
    pub cipher_suites: U16List<'a>,
    pub legacy_compression_methods: &'a [u8],
    pub extensions: extension::Extensions<'a>,
}

impl<'a> ClientHelloRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let legacy_version = reader.u16()?;
        let mut random = [0; super::RANDOM_LEN];
        random.copy_from_slice(reader.take(super::RANDOM_LEN)?);
        let legacy_session_id = reader.vec_u8()?;
        let cipher_suites = U16List::decode(reader)?;
        let legacy_compression_methods = reader.vec_u8()?;
        let extensions = extension::Extensions::decode(reader)?;
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }

    pub fn into_owned(self) -> messages::ClientHello {
        messages::ClientHello {
            legacy_version: self.legacy_version,
            random: self.random,
            legacy_session_id: self.legacy_session_id.to_vec(),
            cipher_suites: self.cipher_suites.iter().collect(),
            legacy_compression_methods: self.legacy_compression_methods.to_vec(),
            extensions: self.extensions.into_owned(),
        }
    }
}

/// Allocation-free view of a validated ServerHello body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHelloRef<'a> {
    pub legacy_version: u16,
    pub random: [u8; super::RANDOM_LEN],
    pub legacy_session_id_echo: &'a [u8],
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    pub extensions: extension::Extensions<'a>,
}

impl<'a> ServerHelloRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let legacy_version = reader.u16()?;
        let mut random = [0; super::RANDOM_LEN];
        random.copy_from_slice(reader.take(super::RANDOM_LEN)?);
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo: reader.vec_u8()?,
            cipher_suite: reader.u16()?,
            legacy_compression_method: reader.u8()?,
            extensions: extension::Extensions::decode(reader)?,
        })
    }

    pub fn into_owned(self) -> messages::ServerHello {
        messages::ServerHello {
            legacy_version: self.legacy_version,
            random: self.random,
            legacy_session_id_echo: self.legacy_session_id_echo.to_vec(),
            cipher_suite: self.cipher_suite,
            legacy_compression_method: self.legacy_compression_method,
            extensions: self.extensions.into_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedExtensionsRef<'a> {
    pub extensions: extension::Extensions<'a>,
}

impl<'a> EncryptedExtensionsRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            extensions: extension::Extensions::decode(reader)?,
        })
    }

    pub fn into_owned(self) -> messages::EncryptedExtensions {
        messages::EncryptedExtensions {
            extensions: self.extensions.into_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateEntryRef<'a> {
    pub cert_data: &'a [u8],
    pub extensions: extension::Extensions<'a>,
}

impl<'a> CertificateEntryRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            cert_data: codec::FramedVector::<1, 1>::decode_u24(reader)?.as_slice(),
            extensions: extension::Extensions::decode(reader)?,
        })
    }

    pub fn into_owned(self) -> messages::CertificateEntry {
        messages::CertificateEntry {
            cert_data: self.cert_data.to_vec(),
            extensions: self.extensions.into_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateEntries<'a> {
    encoded: &'a [u8],
    len: u8,
}

impl<'a> CertificateEntries<'a> {
    pub fn decode(encoded: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(encoded);
        let mut len = 0usize;
        while !reader.is_empty() {
            use crate::wire::handshake::MAX_CERTIFICATE_ENTRIES;
            if len == MAX_CERTIFICATE_ENTRIES {
                return Err(codec::DecodeError::TooManyCertificates);
            }
            CertificateEntryRef::decode(&mut reader)?;
            len += 1;
        }
        Ok(Self {
            encoded,
            len: len as u8,
        })
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn len(self) -> usize {
        self.len as usize
    }

    pub fn first(self) -> Option<CertificateEntryRef<'a>> {
        self.iter().next()
    }

    pub fn iter(self) -> CertificateEntryRefs<'a> {
        CertificateEntryRefs {
            reader: codec::Reader::new(self.encoded),
        }
    }
}

pub struct CertificateEntryRefs<'a> {
    reader: codec::Reader<'a>,
}

impl<'a> Iterator for CertificateEntryRefs<'a> {
    type Item = CertificateEntryRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        CertificateEntryRef::decode(&mut self.reader).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateRef<'a> {
    pub certificate_request_context: &'a [u8],
    pub certificate_list: CertificateEntries<'a>,
}

impl<'a> CertificateRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            certificate_request_context: reader.vec_u8()?,
            certificate_list: CertificateEntries::decode(reader.vec_u24()?)?,
        })
    }

    pub fn into_owned(self) -> messages::Certificate {
        messages::Certificate {
            certificate_request_context: self.certificate_request_context.to_vec(),
            certificate_list: self
                .certificate_list
                .iter()
                .map(CertificateEntryRef::into_owned)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateRequestRef<'a> {
    pub certificate_request_context: &'a [u8],
    pub extensions: extension::Extensions<'a>,
}

impl<'a> CertificateRequestRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            certificate_request_context: reader.vec_u8()?,
            extensions: extension::Extensions::decode(reader)?,
        })
    }

    pub fn into_owned(self) -> messages::CertificateRequest {
        messages::CertificateRequest {
            certificate_request_context: self.certificate_request_context.to_vec(),
            extensions: self.extensions.into_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateVerifyRef<'a> {
    pub algorithm: sig::SignatureScheme,
    pub signature: &'a [u8],
}

impl<'a> CertificateVerifyRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            algorithm: sig::SignatureScheme::from_wire_id(reader.u16()?),
            signature: reader.vec_u16()?,
        })
    }

    pub fn into_owned(self) -> messages::CertificateVerify {
        messages::CertificateVerify {
            algorithm: self.algorithm,
            signature: self.signature.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewSessionTicketRef<'a> {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: &'a [u8],
    pub ticket: &'a [u8],
    pub extensions: extension::Extensions<'a>,
}

impl<'a> NewSessionTicketRef<'a> {
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            ticket_lifetime: reader.u32()?,
            ticket_age_add: reader.u32()?,
            ticket_nonce: reader.vec_u8()?,
            ticket: codec::FramedVector::<1, 1>::decode_u16(reader)?.as_slice(),
            extensions: extension::Extensions::decode(reader)?,
        })
    }

    pub fn into_owned(self) -> messages::NewSessionTicket {
        messages::NewSessionTicket {
            ticket_lifetime: self.ticket_lifetime,
            ticket_age_add: self.ticket_age_add,
            ticket_nonce: self.ticket_nonce.to_vec(),
            ticket: self.ticket.to_vec(),
            extensions: self.extensions.into_owned(),
        }
    }
}

/// Allocation-free view of one validated framed handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRef<'a> {
    ClientHello(ClientHelloRef<'a>),
    ServerHello(ServerHelloRef<'a>),
    EncryptedExtensions(EncryptedExtensionsRef<'a>),
    CertificateRequest(CertificateRequestRef<'a>),
    Certificate(CertificateRef<'a>),
    CertificateVerify(CertificateVerifyRef<'a>),
    Finished(&'a [u8]),
    EndOfEarlyData,
    KeyUpdate(messages::KeyUpdate),
    NewSessionTicket(NewSessionTicketRef<'a>),
}

impl<'a> MessageRef<'a> {
    /// Decodes exactly one complete message without allocating or copying.
    pub fn decode(raw: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(raw);
        let message = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(message)
    }

    /// Decodes one message and leaves subsequent messages in `reader`.
    pub fn decode_from(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        use crate::wire::handshake::Type;
        let ty = Type::from_u8(reader.u8()?)?;
        let mut body = reader.sub_u24()?;
        let message = match ty {
            Type::ClientHello => Self::ClientHello(ClientHelloRef::decode(&mut body)?),
            Type::ServerHello => Self::ServerHello(ServerHelloRef::decode(&mut body)?),
            Type::EncryptedExtensions => {
                Self::EncryptedExtensions(EncryptedExtensionsRef::decode(&mut body)?)
            }
            Type::CertificateRequest => {
                Self::CertificateRequest(CertificateRequestRef::decode(&mut body)?)
            }
            Type::Certificate => Self::Certificate(CertificateRef::decode(&mut body)?),
            Type::CertificateVerify => {
                Self::CertificateVerify(CertificateVerifyRef::decode(&mut body)?)
            }
            Type::Finished => Self::Finished(body.take_all()),
            Type::EndOfEarlyData => Self::EndOfEarlyData,
            Type::KeyUpdate => Self::KeyUpdate(messages::KeyUpdate::decode(&mut body)?),
            Type::NewSessionTicket => {
                Self::NewSessionTicket(NewSessionTicketRef::decode(&mut body)?)
            }
            Type::MessageHash => return Err(codec::DecodeError::InvalidEnum),
        };
        body.finish()?;
        Ok(message)
    }

    pub fn msg_type(self) -> super::Type {
        match self {
            Self::ClientHello(_) => super::Type::ClientHello,
            Self::ServerHello(_) => super::Type::ServerHello,
            Self::EncryptedExtensions(_) => super::Type::EncryptedExtensions,
            Self::CertificateRequest(_) => super::Type::CertificateRequest,
            Self::Certificate(_) => super::Type::Certificate,
            Self::CertificateVerify(_) => super::Type::CertificateVerify,
            Self::Finished(_) => super::Type::Finished,
            Self::EndOfEarlyData => super::Type::EndOfEarlyData,
            Self::KeyUpdate(_) => super::Type::KeyUpdate,
            Self::NewSessionTicket(_) => super::Type::NewSessionTicket,
        }
    }

    /// Materializes this borrowed message for mutation or storage.
    pub fn into_owned(self) -> super::Frame {
        match self {
            Self::ClientHello(message) => super::Frame::ClientHello(message.into_owned()),
            Self::ServerHello(message) => super::Frame::ServerHello(message.into_owned()),
            Self::EncryptedExtensions(message) => {
                super::Frame::EncryptedExtensions(message.into_owned())
            }
            Self::CertificateRequest(message) => {
                super::Frame::CertificateRequest(message.into_owned())
            }
            Self::Certificate(message) => super::Frame::Certificate(message.into_owned()),
            Self::CertificateVerify(message) => {
                super::Frame::CertificateVerify(message.into_owned())
            }
            Self::Finished(verify_data) => super::Frame::Finished(messages::Finished {
                verify_data: verify_data.to_vec(),
            }),
            Self::EndOfEarlyData => super::Frame::EndOfEarlyData,
            Self::KeyUpdate(message) => super::Frame::KeyUpdate(message),
            Self::NewSessionTicket(message) => super::Frame::NewSessionTicket(message.into_owned()),
        }
    }
}
