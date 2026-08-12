use crate::connection;
use crate::crypto::kx;
use crate::identity;
use crate::server::config;
use crate::wire::codec;
use crate::wire::extension;
use crate::wire::protocols;
use crate::wire::psk;

const _: () = assert!(kx::KexGroup::SUPPORTED.len() <= u8::BITS as usize);

/// Parsed peer offers that gate response extensions independently of server
/// configuration.
pub(super) struct ClientHelloOffers<'a> {
    alpn: Option<&'a [u8]>,
    server_cert_types: Option<protocols::CertificateTypeList<'a>>,
    client_cert_types: Option<protocols::CertificateTypeList<'a>>,
    quic_transport_parameters: Option<&'a [u8]>,
    psk: Option<psk::Tail<'a>>,
    kx: ClientKx<'a>,
    early_data: Option<protocols::EarlyDataSignal>,
}

impl<'a> ClientHelloOffers<'a> {
    pub(super) fn parse(
        extensions: extension::Extensions<'a>,
        client_hello: &'a [u8],
    ) -> Result<Self, connection::Error> {
        let mut alpn = None;
        let mut server_cert_types = None;
        let mut client_cert_types = None;
        let mut quic_transport_parameters = None;
        let mut supported_groups = None;
        let mut key_shares = None;
        let mut psk_modes = None;
        let mut offered_psks = None;
        let mut early_data = None;

        let mut extensions = extensions.iter().peekable();
        while let Some(extension) = extensions.next() {
            use crate::wire::extension::Type;
            match extension.ty {
                Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    alpn = Some(extension.data);
                }
                Type::SERVER_CERTIFICATE_TYPE => {
                    server_cert_types = Some(
                        protocols::CertificateTypeList::decode(extension.data)
                            .map_err(|_| connection::Error::Decode)?,
                    );
                }
                Type::CLIENT_CERTIFICATE_TYPE => {
                    client_cert_types = Some(
                        protocols::CertificateTypeList::decode(extension.data)
                            .map_err(|_| connection::Error::Decode)?,
                    );
                }
                Type::QUIC_TRANSPORT_PARAMETERS => {
                    quic_transport_parameters = Some(extension.data);
                }
                Type::SUPPORTED_GROUPS => supported_groups = Some(extension.data),
                Type::KEY_SHARE => key_shares = Some(extension.data),
                Type::PSK_KEY_EXCHANGE_MODES => {
                    psk_modes = Some(psk::KxModesRef::decode(extension.data)?);
                }
                Type::PRE_SHARED_KEY => {
                    if extensions.peek().is_some() {
                        return Err(connection::Error::IllegalParameter);
                    }
                    offered_psks = Some(psk::OfferedPsks::decode(extension.data)?);
                }
                Type::EARLY_DATA => {
                    early_data = Some(protocols::EarlyDataSignal::decode(extension.data)?);
                }
                _ => {}
            }
        }

        let psk = if let Some(offered) = offered_psks {
            let modes = psk_modes.ok_or(connection::Error::MissingExtension)?;
            if modes.contains(psk::KX_MODE_DHE) {
                Some(offered.bind_tail(client_hello)?)
            } else {
                None
            }
        } else {
            None
        };
        let supported_groups = supported_groups.ok_or(connection::Error::MissingExtension)?;
        let key_shares = key_shares.ok_or(connection::Error::MissingExtension)?;
        let kx = ClientKx::parse(supported_groups, key_shares)?;

        Ok(Self {
            alpn,
            server_cert_types,
            client_cert_types,
            quic_transport_parameters,
            psk,
            kx,
            early_data,
        })
    }

    pub(super) fn select_alpn(
        &self,
        supported: &protocols::PreparedAlpn,
    ) -> Result<Option<protocols::AlpnId>, connection::Error> {
        use crate::wire::protocols::Alpn;
        if supported.is_empty() {
            return Ok(None);
        }
        let Some(encoded) = self.alpn else {
            return Ok(None);
        };
        let offered = Alpn::decode(encoded).map_err(|_| connection::Error::Decode)?;
        let mut selected = None;
        for protocol in offered.iter() {
            if let Some(candidate) = supported.find(protocol) {
                selected = Some(selected.map_or(candidate, |current: protocols::AlpnId| {
                    current.min(candidate)
                }));
            }
        }
        if selected.is_none() && !offered.is_empty() {
            return Err(connection::Error::NoApplicationProtocol);
        }
        Ok(selected)
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

    pub(super) fn early_data(&self) -> Option<protocols::EarlyDataSignal> {
        self.early_data
    }

    pub(super) fn psk(&self) -> Option<psk::Tail<'a>> {
        self.psk
    }

    pub(super) fn kx(&self) -> ClientKx<'a> {
        self.kx
    }

    pub(super) fn offered_server_certificate_type(&self) -> bool {
        self.server_cert_types.is_some()
    }

    pub(super) fn offered_client_certificate_type(&self) -> bool {
        self.client_cert_types.is_some()
    }
}

/// A server key-exchange decision whose peer share remains tied to the
/// ClientHello storage it was validated from.
#[derive(Clone, Copy)]
pub(super) struct ClientKx<'hello> {
    selected: Option<PeerShare<'hello>>,
    retry_group: kx::KexGroup,
    share_count: u16,
}

impl<'hello> ClientKx<'hello> {
    fn parse(supported_groups: &[u8], key_shares: &'hello [u8]) -> Result<Self, connection::Error> {
        let mut encoded_groups = codec::Reader::new(supported_groups);
        let groups = codec::FramedVector::<2, 2>::decode_u16(&mut encoded_groups)?;
        encoded_groups.finish()?;
        let mut groups = groups.reader();

        let mut encoded_shares = codec::Reader::new(key_shares);
        let shares = codec::FramedVector::<0, 1>::decode_u16(&mut encoded_shares)?;
        encoded_shares.finish()?;
        let mut shares = shares.reader();

        let mut supported_mask = 0u8;
        let mut shared_mask = 0u8;
        let mut selected = None;
        let mut selected_rank = u8::MAX;
        let mut share_count = 0u16;

        while !shares.is_empty() {
            let group_id = shares.u16()?;
            let key_exchange = codec::FramedVector::<1, 1>::decode_u16(&mut shares)?.as_slice();
            share_count += 1;

            let mut matched = false;
            while !groups.is_empty() {
                let supported = groups.u16()?;
                note_supported(supported, &mut supported_mask)?;
                if supported == group_id {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(connection::Error::IllegalParameter);
            }

            if let Some((rank, group)) = local_group(group_id) {
                let bit = 1u8 << rank;
                if shared_mask & bit != 0 {
                    return Err(connection::Error::IllegalParameter);
                }
                shared_mask |= bit;
                if rank < selected_rank {
                    selected = Some(PeerShare {
                        group,
                        key_exchange,
                    });
                    selected_rank = rank;
                }
            }
        }
        while !groups.is_empty() {
            note_supported(groups.u16()?, &mut supported_mask)?;
        }

        let retry_group = kx::KexGroup::SUPPORTED
            .iter()
            .copied()
            .enumerate()
            .find_map(|(rank, group)| (supported_mask & (1u8 << rank) != 0).then_some(group))
            .ok_or(connection::Error::UnsupportedGroup)?;
        Ok(Self {
            selected,
            retry_group,
            share_count,
        })
    }

    pub(super) fn selected(self) -> Option<PeerShare<'hello>> {
        self.selected
    }

    pub(super) fn retry_group(self) -> kx::KexGroup {
        self.retry_group
    }

    pub(super) fn require_retry(self, requested: kx::KexGroup) -> Result<(), connection::Error> {
        if self.share_count != 1 || self.selected.is_none_or(|share| share.group != requested) {
            return Err(connection::Error::IllegalParameter);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct PeerShare<'hello> {
    group: kx::KexGroup,
    key_exchange: &'hello [u8],
}

impl<'hello> PeerShare<'hello> {
    pub(super) fn group(self) -> kx::KexGroup {
        self.group
    }

    pub(super) fn key_exchange(self) -> &'hello [u8] {
        self.key_exchange
    }
}

fn note_supported(group: u16, mask: &mut u8) -> Result<(), connection::Error> {
    if let Some((rank, _)) = local_group(group) {
        let bit = 1u8 << rank;
        if *mask & bit != 0 {
            return Err(connection::Error::IllegalParameter);
        }
        *mask |= bit;
    }
    Ok(())
}

fn local_group(group: u16) -> Option<(u8, kx::KexGroup)> {
    kx::KexGroup::SUPPORTED
        .iter()
        .copied()
        .enumerate()
        .find_map(|(rank, candidate)| {
            (candidate.wire_id() == group).then_some((rank as u8, candidate))
        })
}

#[derive(Clone, Copy)]
pub(super) struct Negotiation {
    pub(super) server_type: identity::CertificateType,
    pub(super) client_type: identity::CertificateType,
}

impl Negotiation {
    fn new(
        offers: &ClientHelloOffers<'_>,
        source: &config::CertSource,
    ) -> Result<Self, connection::Error> {
        use crate::identity::CertificateType;
        let server_type = source.cert_type();
        if let Some(types) = offers.server_cert_types
            && !types.contains(server_type)
        {
            return Err(connection::Error::UnexpectedMessage);
        }

        let client_type = offers
            .client_cert_types
            .and_then(protocols::CertificateTypeList::select)
            .unwrap_or(CertificateType::X509);

        Ok(Self {
            server_type,
            client_type,
        })
    }
}
