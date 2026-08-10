use crate::wire::codec;
use crate::wire::handshake::messages;
use crate::wire::handshake::views;

/// Allocation-free view of one framed handshake message. This is the same
/// acceptance path used by the live client and server state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Borrowed<'a>(views::MessageRef<'a>);

impl<'a> Borrowed<'a> {
    /// Decodes one message and leaves any following framed messages in `reader`.
    pub fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self(views::MessageRef::decode_from(reader)?))
    }

    /// Decodes exactly one complete framed message.
    pub fn decode_exact(raw: &'a [u8]) -> Result<Self, codec::DecodeError> {
        Ok(Self(views::MessageRef::decode(raw)?))
    }

    pub fn into_owned(self) -> Frame {
        self.0.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    ClientHello(messages::ClientHello),
    ServerHello(messages::ServerHello),
    EncryptedExtensions(messages::EncryptedExtensions),
    CertificateRequest(messages::CertificateRequest),
    Certificate(messages::Certificate),
    CertificateVerify(messages::CertificateVerify),
    Finished(messages::Finished),
    EndOfEarlyData,
    KeyUpdate(messages::KeyUpdate),
    NewSessionTicket(messages::NewSessionTicket),
}

impl Frame {
    pub(crate) fn encode_finished(
        verify_data: &[u8],
        out: &mut impl codec::Encode,
    ) -> Result<(), codec::EncodeError> {
        out.put_u8(super::Type::Finished as u8);
        let mut body = out.begin_u24()?;
        messages::Finished::encode_verify_data(verify_data, &mut body);
        body.finish()
    }

    pub(crate) fn encode_certificate_verify(
        algorithm: u16,
        signature: &[u8],
        out: &mut impl codec::Encode,
    ) -> Result<(), codec::EncodeError> {
        out.put_u8(super::Type::CertificateVerify as u8);
        let mut body = out.begin_u24()?;
        messages::CertificateVerify::encode_fields(algorithm, signature, &mut body)?;
        body.finish()
    }

    pub fn msg_type(&self) -> super::Type {
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

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        out.put_u8(self.msg_type() as u8);
        let mut body = out.begin_u24()?;
        match self {
            Self::ClientHello(m) => m.encode(&mut body)?,
            Self::ServerHello(m) => m.encode(&mut body)?,
            Self::EncryptedExtensions(m) => m.encode(&mut body)?,
            Self::CertificateRequest(m) => m.encode(&mut body)?,
            Self::Certificate(m) => m.encode(&mut body)?,
            Self::CertificateVerify(m) => m.encode(&mut body)?,
            Self::Finished(m) => m.encode(&mut body)?,
            Self::EndOfEarlyData => {}
            Self::KeyUpdate(m) => m.encode(&mut body)?,
            Self::NewSessionTicket(m) => m.encode(&mut body)?,
        }
        body.finish()
    }

    pub fn decode(r: &mut codec::Reader<'_>) -> Result<Self, codec::DecodeError> {
        Ok(Borrowed::decode(r)?.into_owned())
    }
}

impl From<views::MessageRef<'_>> for Frame {
    fn from(message: views::MessageRef<'_>) -> Self {
        match message {
            views::MessageRef::ClientHello(message) => Self::ClientHello(message.into()),
            views::MessageRef::ServerHello(message) => Self::ServerHello(message.into()),
            views::MessageRef::EncryptedExtensions(message) => {
                Self::EncryptedExtensions(message.into())
            }
            views::MessageRef::CertificateRequest(message) => {
                Self::CertificateRequest(message.into())
            }
            views::MessageRef::Certificate(message) => Self::Certificate(message.into()),
            views::MessageRef::CertificateVerify(message) => {
                Self::CertificateVerify(message.into())
            }
            views::MessageRef::Finished(verify_data) => Self::Finished(messages::Finished {
                verify_data: verify_data.to_vec(),
            }),
            views::MessageRef::EndOfEarlyData => Self::EndOfEarlyData,
            views::MessageRef::KeyUpdate(message) => Self::KeyUpdate(message),
            views::MessageRef::NewSessionTicket(message) => Self::NewSessionTicket(message.into()),
        }
    }
}
