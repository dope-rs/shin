use alloc::vec::Vec;
use core::slice::from_ref;

use crate::Error;
use crate::extension::{Extension, ExtensionType};
use crate::proto::{Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, CertType};

use super::CertSource;

/// Parsed peer offers that gate response extensions independently of server
/// configuration.
pub(super) struct ClientHelloOffers {
    alpn: Option<Vec<u8>>,
    server_cert_types: Option<Vec<u8>>,
    client_cert_types: Option<Vec<u8>>,
    quic_transport_parameters: Option<Vec<u8>>,
    early_data: bool,
}

impl ClientHelloOffers {
    pub(super) fn parse(extensions: &[Extension]) -> Result<Self, Error> {
        let mut offers = Self {
            alpn: None,
            server_cert_types: None,
            client_cert_types: None,
            quic_transport_parameters: None,
            early_data: false,
        };

        for extension in extensions {
            match extension.ty {
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    offers.alpn = Some(extension.data.clone());
                }
                ExtensionType::SERVER_CERTIFICATE_TYPE => {
                    offers.server_cert_types =
                        Some(CertType::decode_list(&extension.data).map_err(|_| Error::Decode)?);
                }
                ExtensionType::CLIENT_CERTIFICATE_TYPE => {
                    offers.client_cert_types =
                        Some(CertType::decode_list(&extension.data).map_err(|_| Error::Decode)?);
                }
                ExtensionType::QUIC_TRANSPORT_PARAMETERS => {
                    offers.quic_transport_parameters = Some(extension.data.clone());
                }
                ExtensionType::EARLY_DATA => offers.early_data = true,
                _ => {}
            }
        }

        Ok(offers)
    }

    pub(super) fn select_alpn(&self, supported: &[Vec<u8>]) -> Result<Option<Vec<u8>>, Error> {
        if supported.is_empty() {
            return Ok(None);
        }
        let Some(encoded) = &self.alpn else {
            return Ok(None);
        };
        let offered = Alpn::decode(encoded).map_err(|_| Error::Decode)?;
        let selected = supported
            .iter()
            .find(|candidate| offered.iter().any(|offer| offer == *candidate))
            .cloned();
        if selected.is_none() && !offered.is_empty() {
            return Err(Error::NoApplicationProtocol);
        }
        Ok(selected)
    }

    pub(super) fn certificate_negotiation(
        &self,
        source: &CertSource,
    ) -> Result<CertificateNegotiation, Error> {
        CertificateNegotiation::new(self, source)
    }

    pub(super) fn peer_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.quic_transport_parameters.as_deref()
    }

    pub(super) fn early_data(&self) -> bool {
        self.early_data
    }

    pub(super) fn encrypted_extensions(
        &self,
        certificates: CertificateNegotiation,
        transport_parameters: &[u8],
        selected_alpn: Option<&Vec<u8>>,
        early_data_accepted: bool,
    ) -> Result<Vec<Extension>, Error> {
        let mut extensions = Vec::new();
        if self.server_cert_types.is_some() {
            extensions.push(Extension::new(
                ExtensionType::SERVER_CERTIFICATE_TYPE,
                CertType::new(certificates.server_type).encode_single(),
            ));
        }
        if self.client_cert_types.is_some() {
            extensions.push(Extension::new(
                ExtensionType::CLIENT_CERTIFICATE_TYPE,
                CertType::new(certificates.client_type).encode_single(),
            ));
        }
        if self.quic_transport_parameters.is_some() {
            extensions.push(Extension::new(
                ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                transport_parameters.to_vec(),
            ));
        }
        if let Some(protocol) = selected_alpn {
            extensions.push(Extension::new(
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                Alpn::new(from_ref(protocol)).encode()?,
            ));
        }
        if early_data_accepted {
            extensions.push(Extension::new(ExtensionType::EARLY_DATA, Vec::new()));
        }
        Ok(extensions)
    }
}

#[derive(Clone, Copy)]
pub(super) struct CertificateNegotiation {
    pub(super) server_type: u8,
    pub(super) client_type: u8,
}

impl CertificateNegotiation {
    fn new(offers: &ClientHelloOffers, source: &CertSource) -> Result<Self, Error> {
        let server_type = match source {
            CertSource::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            CertSource::X509 { .. } => CERT_TYPE_X509,
        };
        if offers
            .server_cert_types
            .as_ref()
            .is_some_and(|types| !types.contains(&server_type))
        {
            return Err(Error::UnexpectedMessage);
        }

        let client_type = offers
            .client_cert_types
            .as_ref()
            .and_then(|types| {
                types
                    .iter()
                    .copied()
                    .find(|ty| *ty == CERT_TYPE_X509 || *ty == CERT_TYPE_RAW_PUBLIC_KEY)
            })
            .unwrap_or(CERT_TYPE_X509);

        Ok(Self {
            server_type,
            client_type,
        })
    }
}
