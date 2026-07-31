use alloc::vec::Vec;
use arrayvec::ArrayVec;

use crate::connection::Error;
use crate::wire::extension::{ExtensionType, Extensions};
use crate::wire::proto::{Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, CertificateTypes};

use super::CertSource;

/// Parsed peer offers that gate response extensions independently of server
/// configuration.
pub(super) struct ClientHelloOffers<'a> {
    alpn: Option<&'a [u8]>,
    server_cert_types: Option<CertificateTypes<'a>>,
    client_cert_types: Option<CertificateTypes<'a>>,
    quic_transport_parameters: Option<&'a [u8]>,
    early_data: bool,
}

impl<'a> ClientHelloOffers<'a> {
    pub(super) fn parse(extensions: Extensions<'a>) -> Result<Self, Error> {
        let mut offers = Self {
            alpn: None,
            server_cert_types: None,
            client_cert_types: None,
            quic_transport_parameters: None,
            early_data: false,
        };

        for extension in extensions.iter() {
            match extension.ty {
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    offers.alpn = Some(extension.data);
                }
                ExtensionType::SERVER_CERTIFICATE_TYPE => {
                    offers.server_cert_types =
                        Some(CertificateTypes::decode(extension.data).map_err(|_| Error::Decode)?);
                }
                ExtensionType::CLIENT_CERTIFICATE_TYPE => {
                    offers.client_cert_types =
                        Some(CertificateTypes::decode(extension.data).map_err(|_| Error::Decode)?);
                }
                ExtensionType::QUIC_TRANSPORT_PARAMETERS => {
                    offers.quic_transport_parameters = Some(extension.data);
                }
                ExtensionType::EARLY_DATA => offers.early_data = true,
                _ => {}
            }
        }

        Ok(offers)
    }

    pub(super) fn select_alpn(
        &self,
        supported: &[Vec<u8>],
    ) -> Result<Option<ArrayVec<u8, 255>>, Error> {
        if supported.is_empty() {
            return Ok(None);
        }
        let Some(encoded) = self.alpn else {
            return Ok(None);
        };
        let offered = Alpn::decode(encoded).map_err(|_| Error::Decode)?;
        let selected = supported
            .iter()
            .find(|candidate| offered.iter().any(|offer| offer == candidate.as_slice()));
        if selected.is_none() && !offered.is_empty() {
            return Err(Error::NoApplicationProtocol);
        }
        selected
            .map(|protocol| ArrayVec::try_from(protocol.as_slice()).map_err(|_| Error::BadConfig))
            .transpose()
    }

    pub(super) fn certificate_negotiation(
        &self,
        source: &CertSource,
    ) -> Result<CertificateNegotiation, Error> {
        CertificateNegotiation::new(self, source)
    }

    pub(super) fn peer_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.quic_transport_parameters
    }

    pub(super) fn early_data(&self) -> bool {
        self.early_data
    }

    pub(super) fn offered_server_certificate_type(&self) -> bool {
        self.server_cert_types.is_some()
    }

    pub(super) fn offered_client_certificate_type(&self) -> bool {
        self.client_cert_types.is_some()
    }

    pub(super) fn offered_quic_transport_parameters(&self) -> bool {
        self.quic_transport_parameters.is_some()
    }
}

#[derive(Clone, Copy)]
pub(super) struct CertificateNegotiation {
    pub(super) server_type: u8,
    pub(super) client_type: u8,
}

impl CertificateNegotiation {
    fn new(offers: &ClientHelloOffers<'_>, source: &CertSource) -> Result<Self, Error> {
        let server_type = match source {
            CertSource::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            CertSource::X509 { .. } => CERT_TYPE_X509,
        };
        if let Some(types) = offers.server_cert_types
            && !types.contains(server_type)
        {
            return Err(Error::UnexpectedMessage);
        }

        let client_type = offers
            .client_cert_types
            .and_then(CertificateTypes::select)
            .unwrap_or(CERT_TYPE_X509);

        Ok(Self {
            server_type,
            client_type,
        })
    }
}
