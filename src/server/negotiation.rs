use crate::connection;
use crate::server::config;
use crate::wire::extension;
use crate::wire::protocols;
use alloc::vec;

/// Parsed peer offers that gate response extensions independently of server
/// configuration.
pub(super) struct ClientHelloOffers<'a> {
    alpn: Option<&'a [u8]>,
    server_cert_types: Option<protocols::CertificateTypes<'a>>,
    client_cert_types: Option<protocols::CertificateTypes<'a>>,
    quic_transport_parameters: Option<&'a [u8]>,
    early_data: bool,
}

impl<'a> ClientHelloOffers<'a> {
    pub(super) fn parse(extensions: extension::Extensions<'a>) -> Result<Self, connection::Error> {
        let mut offers = Self {
            alpn: None,
            server_cert_types: None,
            client_cert_types: None,
            quic_transport_parameters: None,
            early_data: false,
        };

        for extension in extensions.iter() {
            use crate::wire::extension::Type;
            match extension.ty {
                Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    offers.alpn = Some(extension.data);
                }
                Type::SERVER_CERTIFICATE_TYPE => {
                    offers.server_cert_types = Some(
                        protocols::CertificateTypes::decode(extension.data)
                            .map_err(|_| connection::Error::Decode)?,
                    );
                }
                Type::CLIENT_CERTIFICATE_TYPE => {
                    offers.client_cert_types = Some(
                        protocols::CertificateTypes::decode(extension.data)
                            .map_err(|_| connection::Error::Decode)?,
                    );
                }
                Type::QUIC_TRANSPORT_PARAMETERS => {
                    offers.quic_transport_parameters = Some(extension.data);
                }
                Type::EARLY_DATA => offers.early_data = true,
                _ => {}
            }
        }

        Ok(offers)
    }

    pub(super) fn select_alpn(
        &self,
        supported: &[vec::Vec<u8>],
    ) -> Result<Option<arrayvec::ArrayVec<u8, 255>>, connection::Error> {
        use crate::wire::protocols::Alpn;
        if supported.is_empty() {
            return Ok(None);
        }
        let Some(encoded) = self.alpn else {
            return Ok(None);
        };
        let offered = Alpn::decode(encoded).map_err(|_| connection::Error::Decode)?;
        let selected = supported
            .iter()
            .find(|candidate| offered.iter().any(|offer| offer == candidate.as_slice()));
        if selected.is_none() && !offered.is_empty() {
            return Err(connection::Error::NoApplicationProtocol);
        }
        selected
            .map(|protocol| {
                arrayvec::ArrayVec::try_from(protocol.as_slice())
                    .map_err(|_| connection::Error::BadConfig)
            })
            .transpose()
    }

    pub(super) fn certificate_negotiation(
        &self,
        source: &config::CertSource,
    ) -> Result<Negotiation, connection::Error> {
        Negotiation::new(self, source)
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
}

#[derive(Clone, Copy)]
pub(super) struct Negotiation {
    pub(super) server_type: u8,
    pub(super) client_type: u8,
}

impl Negotiation {
    fn new(
        offers: &ClientHelloOffers<'_>,
        source: &config::CertSource,
    ) -> Result<Self, connection::Error> {
        use crate::wire::protocols::CERT_TYPE_RAW_PUBLIC_KEY;
        use crate::wire::protocols::CERT_TYPE_X509;
        let server_type = match source {
            config::CertSource::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            config::CertSource::X509 { .. } => CERT_TYPE_X509,
        };
        if let Some(types) = offers.server_cert_types
            && !types.contains(server_type)
        {
            return Err(connection::Error::UnexpectedMessage);
        }

        let client_type = offers
            .client_cert_types
            .and_then(protocols::CertificateTypes::select)
            .unwrap_or(CERT_TYPE_X509);

        Ok(Self {
            server_type,
            client_type,
        })
    }
}
