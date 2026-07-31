use crate::wire::codec::{DecodeError, Encode, EncodeError, Reader};

use super::messages::{
    Certificate, CertificateRequest, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
    HandshakeType, KeyUpdate, NewSessionTicket, ServerHello,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EncryptedExtensions(EncryptedExtensions),
    CertificateRequest(CertificateRequest),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    EndOfEarlyData,
    KeyUpdate(KeyUpdate),
    NewSessionTicket(NewSessionTicket),
}

impl Frame {
    pub(crate) fn encode_finished(
        verify_data: &[u8],
        out: &mut impl Encode,
    ) -> Result<(), EncodeError> {
        out.put_u8(HandshakeType::Finished as u8);
        out.put_vec_u24(|body| {
            body.put_slice(verify_data);
            Ok(())
        })
    }

    pub(crate) fn encode_certificate_verify(
        algorithm: u16,
        signature: &[u8],
        out: &mut impl Encode,
    ) -> Result<(), EncodeError> {
        out.put_u8(HandshakeType::CertificateVerify as u8);
        out.put_vec_u24(|body| {
            body.put_u16(algorithm);
            body.put_vec_u16(|signature_body| {
                signature_body.put_slice(signature);
                Ok(())
            })
        })
    }

    pub fn msg_type(&self) -> HandshakeType {
        match self {
            Self::ClientHello(_) => HandshakeType::ClientHello,
            Self::ServerHello(_) => HandshakeType::ServerHello,
            Self::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            Self::CertificateRequest(_) => HandshakeType::CertificateRequest,
            Self::Certificate(_) => HandshakeType::Certificate,
            Self::CertificateVerify(_) => HandshakeType::CertificateVerify,
            Self::Finished(_) => HandshakeType::Finished,
            Self::EndOfEarlyData => HandshakeType::EndOfEarlyData,
            Self::KeyUpdate(_) => HandshakeType::KeyUpdate,
            Self::NewSessionTicket(_) => HandshakeType::NewSessionTicket,
        }
    }

    pub fn encode(&self, out: &mut impl Encode) -> Result<(), EncodeError> {
        out.put_u8(self.msg_type() as u8);
        out.put_vec_u24(|o| match self {
            Self::ClientHello(m) => m.encode(o),
            Self::ServerHello(m) => m.encode(o),
            Self::EncryptedExtensions(m) => m.encode(o),
            Self::CertificateRequest(m) => m.encode(o),
            Self::Certificate(m) => m.encode(o),
            Self::CertificateVerify(m) => m.encode(o),
            Self::Finished(m) => m.encode(o),
            Self::EndOfEarlyData => Ok(()),
            Self::KeyUpdate(m) => m.encode(o),
            Self::NewSessionTicket(m) => m.encode(o),
        })
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
            HandshakeType::CertificateRequest => {
                Self::CertificateRequest(CertificateRequest::decode(&mut body)?)
            }
            HandshakeType::Certificate => Self::Certificate(Certificate::decode(&mut body)?),
            HandshakeType::CertificateVerify => {
                Self::CertificateVerify(CertificateVerify::decode(&mut body)?)
            }
            HandshakeType::Finished => Self::Finished(Finished::decode(&mut body)?),
            HandshakeType::EndOfEarlyData => Self::EndOfEarlyData,
            HandshakeType::KeyUpdate => Self::KeyUpdate(KeyUpdate::decode(&mut body)?),
            HandshakeType::NewSessionTicket => {
                Self::NewSessionTicket(NewSessionTicket::decode(&mut body)?)
            }
            HandshakeType::MessageHash => {
                return Err(DecodeError::InvalidEnum);
            }
        };
        body.finish()?;
        Ok(m)
    }
}
