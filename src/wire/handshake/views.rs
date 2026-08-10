use crate::wire::codec;
use crate::wire::extension;
use crate::wire::handshake::messages;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct U16List<'a> {
    encoded: &'a [u8],
}

impl<'a> U16List<'a> {
    pub(crate) fn decode(encoded: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(encoded);
        while !reader.is_empty() {
            reader.u16()?;
        }
        Ok(Self { encoded })
    }

    pub(crate) fn contains(self, needle: u16) -> bool {
        self.iter().any(|value| value == needle)
    }

    pub(crate) fn iter(self) -> U16s<'a> {
        U16s {
            reader: codec::Reader::new(self.encoded),
        }
    }
}

pub(crate) struct U16s<'a> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientHelloRef<'a> {
    pub(crate) legacy_version: u16,
    pub(crate) random: [u8; super::RANDOM_LEN],
    pub(crate) legacy_session_id: &'a [u8],
    pub(crate) cipher_suites: U16List<'a>,
    pub(crate) legacy_compression_methods: &'a [u8],
    pub(crate) extensions: extension::Extensions<'a>,
}

impl<'a> ClientHelloRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let legacy_version = reader.u16()?;
        let mut random = [0; super::RANDOM_LEN];
        random.copy_from_slice(reader.take(super::RANDOM_LEN)?);
        let legacy_session_id = reader.vec_u8()?;
        let cipher_suites = U16List::decode(reader.vec_u16()?)?;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerHelloRef<'a> {
    pub(crate) legacy_version: u16,
    pub(crate) random: [u8; super::RANDOM_LEN],
    pub(crate) legacy_session_id_echo: &'a [u8],
    pub(crate) cipher_suite: u16,
    pub(crate) legacy_compression_method: u8,
    pub(crate) extensions: extension::Extensions<'a>,
}

impl<'a> ServerHelloRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptedExtensionsRef<'a> {
    pub(crate) extensions: extension::Extensions<'a>,
}

impl<'a> EncryptedExtensionsRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            extensions: extension::Extensions::decode(reader)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CertificateEntryRef<'a> {
    pub(crate) cert_data: &'a [u8],
    pub(crate) extensions: extension::Extensions<'a>,
}

impl<'a> CertificateEntryRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            cert_data: reader.vec_u24()?,
            extensions: extension::Extensions::decode(reader)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CertificateEntries<'a> {
    encoded: &'a [u8],
    len: u8,
}

impl<'a> CertificateEntries<'a> {
    fn decode(encoded: &'a [u8]) -> Result<Self, codec::DecodeError> {
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

    pub(crate) fn is_empty(self) -> bool {
        self.len == 0
    }

    pub(crate) fn len(self) -> usize {
        self.len as usize
    }

    pub(crate) fn first(self) -> Option<CertificateEntryRef<'a>> {
        self.iter().next()
    }

    pub(crate) fn iter(self) -> CertificateEntryRefs<'a> {
        CertificateEntryRefs {
            reader: codec::Reader::new(self.encoded),
        }
    }
}

pub(crate) struct CertificateEntryRefs<'a> {
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
pub(crate) struct CertificateRef<'a> {
    pub(crate) certificate_request_context: &'a [u8],
    pub(crate) certificate_list: CertificateEntries<'a>,
}

impl<'a> CertificateRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            certificate_request_context: reader.vec_u8()?,
            certificate_list: CertificateEntries::decode(reader.vec_u24()?)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CertificateRequestRef<'a> {
    pub(crate) certificate_request_context: &'a [u8],
    pub(crate) extensions: extension::Extensions<'a>,
}

impl<'a> CertificateRequestRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            certificate_request_context: reader.vec_u8()?,
            extensions: extension::Extensions::decode(reader)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CertificateVerifyRef<'a> {
    pub(crate) algorithm: u16,
    pub(crate) signature: &'a [u8],
}

impl<'a> CertificateVerifyRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            algorithm: reader.u16()?,
            signature: reader.vec_u16()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NewSessionTicketRef<'a> {
    pub(crate) ticket_lifetime: u32,
    pub(crate) ticket_age_add: u32,
    pub(crate) ticket_nonce: &'a [u8],
    pub(crate) ticket: &'a [u8],
    pub(crate) extensions: extension::Extensions<'a>,
}

impl<'a> NewSessionTicketRef<'a> {
    pub(crate) fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            ticket_lifetime: reader.u32()?,
            ticket_age_add: reader.u32()?,
            ticket_nonce: reader.vec_u8()?,
            ticket: reader.vec_u16()?,
            extensions: extension::Extensions::decode(reader)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageRef<'a> {
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
    pub(crate) fn decode(raw: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(raw);
        let message = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(message)
    }

    pub(crate) fn decode_from(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
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
}
