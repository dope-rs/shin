use crate::crypto::sig;
use crate::wire::codec;
use crate::wire::handshake::messages;
use crate::wire::handshake::views;

pub use views::{
    CertificateEntries, CertificateEntryRef, CertificateEntryRefs, CertificateRef,
    CertificateRequestRef, CertificateVerifyRef, ClientHelloRef, EncryptedExtensionsRef,
    MessageRef, NewSessionTicketRef, ServerHelloRef, U16List, U16s,
};

/// Owned handshake representation for construction, mutation, and retention.
/// Decode through [`MessageRef`] and cross this allocation boundary explicitly
/// with [`MessageRef::into_owned`] only when ownership is required.
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
        algorithm: sig::SignatureScheme,
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
}

impl MessageRef<'_> {
    /// Materializes this borrowed message for mutation or storage.
    pub fn into_owned(self) -> Frame {
        match self {
            Self::ClientHello(message) => Frame::ClientHello(message.into_owned()),
            Self::ServerHello(message) => Frame::ServerHello(message.into_owned()),
            Self::EncryptedExtensions(message) => Frame::EncryptedExtensions(message.into_owned()),
            Self::CertificateRequest(message) => Frame::CertificateRequest(message.into_owned()),
            Self::Certificate(message) => Frame::Certificate(message.into_owned()),
            Self::CertificateVerify(message) => Frame::CertificateVerify(message.into_owned()),
            Self::Finished(verify_data) => Frame::Finished(messages::Finished {
                verify_data: verify_data.to_vec(),
            }),
            Self::EndOfEarlyData => Frame::EndOfEarlyData,
            Self::KeyUpdate(message) => Frame::KeyUpdate(message),
            Self::NewSessionTicket(message) => Frame::NewSessionTicket(message.into_owned()),
        }
    }
}
