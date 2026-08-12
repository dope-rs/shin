use crate::client::config;
use crate::client::config::resumption;
use crate::client::session;
use crate::connection;
use crate::crypto::hash;
use crate::crypto::kx;
use crate::identity;
use crate::transport;
use crate::wire::codec;
use crate::wire::codec::Encode as _;
use crate::wire::extension;
use crate::wire::record;
use alloc::vec;

use crate::wire::handshake;
use crate::wire::handshake::workspace;
use crate::wire::protocols;

#[derive(Clone, Copy)]
pub(super) struct Offer<'a> {
    policy: HelloPolicy<'a>,
    core: HelloCore<'a>,
    extensions: HelloExtensions<'a>,
}

#[derive(Clone, Copy)]
struct HelloPolicy<'a> {
    verifier: &'a config::Verifier,
    transport_mode: transport::Mode,
    transport_params: &'a [u8],
    alpn_protocols: &'a [vec::Vec<u8>],
}

#[derive(Clone, Copy)]
struct HelloCore<'a> {
    suites: &'a [record::CipherSuite],
    group: kx::KexGroup,
    random: &'a [u8; handshake::RANDOM_LEN],
    session_id: &'a [u8],
    kx_pubkey: &'a [u8],
}

#[derive(Clone, Copy)]
struct HelloExtensions<'a> {
    cookie: Option<protocols::Cookie<'a>>,
    resumption: Option<resumption::Offer<'a>>,
    offer_early_data: bool,
    certificate_types: session::CertificateTypeOffers,
}

#[derive(Clone, Copy)]
pub(super) struct BinderSlot {
    prefix_end: usize,
    binder_start: usize,
    binder_end: usize,
}

pub(super) struct Request<'a> {
    pub(super) certificate_types: session::CertificateTypeOffers,
    pub(super) kx_pubkey: &'a [u8],
    pub(super) cookie: Option<protocols::Cookie<'a>>,
    pub(super) resumption: Option<resumption::Offer<'a>>,
    pub(super) offer_early_data: bool,
}

impl<'a> Offer<'a> {
    fn encode(
        self,
        out: &mut impl codec::Encode,
    ) -> Result<Option<BinderSlot>, codec::EncodeError> {
        use crate::wire::extension::Extension;
        use crate::wire::handshake::TLS_1_2;
        use crate::wire::protocols::SignatureAlgorithms;
        use crate::wire::protocols::TLS_1_3;
        let hostname = self.policy.verifier.dns_hostname();
        let signature_algorithms = match self.policy.verifier {
            config::Verifier::RawPublicKey { .. } => SignatureAlgorithms::rpk().as_slice(),
            config::Verifier::X509 { .. } | config::Verifier::X509Store { .. } => {
                SignatureAlgorithms::x509().as_slice()
            }
        };

        out.put_u8(handshake::Type::ClientHello as u8);
        let mut hello = out.begin_u24()?;
        hello.put_u16(TLS_1_2);
        hello.put_slice(self.core.random);
        let mut session = hello.begin_u8()?;
        session.put_slice(self.core.session_id);
        session.finish()?;
        let mut encoded_suites = hello.begin_u16()?;
        for suite in self.core.suites {
            encoded_suites.put_u16(suite.wire_id());
        }
        encoded_suites.finish()?;
        let mut compression = hello.begin_u8()?;
        compression.put_u8(0);
        compression.finish()?;
        let mut extensions = hello.begin_u16()?;

        let mut version = Extension::begin(&mut extensions, extension::Type::SUPPORTED_VERSIONS)?;
        let mut versions = version.begin_u8()?;
        versions.put_u16(TLS_1_3);
        versions.finish()?;
        version.finish()?;

        let mut groups = Extension::begin(&mut extensions, extension::Type::SUPPORTED_GROUPS)?;
        let mut encoded_groups = groups.begin_u16()?;
        for supported in kx::KexGroup::SUPPORTED {
            encoded_groups.put_u16(supported.wire_id());
        }
        encoded_groups.finish()?;
        groups.finish()?;

        let mut algorithms =
            Extension::begin(&mut extensions, extension::Type::SIGNATURE_ALGORITHMS)?;
        let mut encoded_algorithms = algorithms.begin_u16()?;
        for algorithm in signature_algorithms {
            encoded_algorithms.put_u16(algorithm.wire_id());
        }
        encoded_algorithms.finish()?;
        algorithms.finish()?;

        let mut shares = Extension::begin(&mut extensions, extension::Type::KEY_SHARE)?;
        let mut entries = shares.begin_u16()?;
        entries.put_u16(self.core.group.wire_id());
        let mut key = entries.begin_u16()?;
        key.put_slice(self.core.kx_pubkey);
        key.finish()?;
        entries.finish()?;
        shares.finish()?;

        if let Some(cert_type) = self.extensions.certificate_types.server {
            let mut types =
                Extension::begin(&mut extensions, extension::Type::SERVER_CERTIFICATE_TYPE)?;
            let mut list = types.begin_u8()?;
            list.put_u8(cert_type.wire_id());
            list.finish()?;
            types.finish()?;
        }
        if let Some(cert_type) = self.extensions.certificate_types.client {
            let mut types =
                Extension::begin(&mut extensions, extension::Type::CLIENT_CERTIFICATE_TYPE)?;
            let mut list = types.begin_u8()?;
            list.put_u8(cert_type.wire_id());
            list.finish()?;
            types.finish()?;
        }
        if self.policy.transport_mode.is_quic() {
            let mut parameters =
                Extension::begin(&mut extensions, extension::Type::QUIC_TRANSPORT_PARAMETERS)?;
            parameters.put_slice(self.policy.transport_params);
            parameters.finish()?;
        }
        if let Some(hostname) = hostname {
            let mut names = Extension::begin(&mut extensions, extension::Type::SERVER_NAME)?;
            let mut list = names.begin_u16()?;
            list.put_u8(0);
            let mut name = list.begin_u16()?;
            name.put_slice(hostname);
            name.finish()?;
            list.finish()?;
            names.finish()?;
        }
        if !self.policy.alpn_protocols.is_empty() {
            let mut protocols = Extension::begin(
                &mut extensions,
                extension::Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            )?;
            let mut list = protocols.begin_u16()?;
            for protocol in self.policy.alpn_protocols {
                let mut encoded = list.begin_u8()?;
                encoded.put_slice(protocol);
                encoded.finish()?;
            }
            list.finish()?;
            protocols.finish()?;
        }
        if let Some(cookie) = self.extensions.cookie {
            let mut encoded = Extension::begin(&mut extensions, extension::Type::COOKIE)?;
            encoded.put_slice(cookie.encoded());
            encoded.finish()?;
        }
        if self.extensions.offer_early_data {
            Extension::begin(&mut extensions, extension::Type::EARLY_DATA)?.finish()?;
        }
        let mut binder_slot = None;
        if let Some(resumption) = self.extensions.resumption {
            use crate::wire::psk::KX_MODE_DHE;
            let mut modes =
                Extension::begin(&mut extensions, extension::Type::PSK_KEY_EXCHANGE_MODES)?;
            let mut list = modes.begin_u8()?;
            list.put_u8(KX_MODE_DHE);
            list.finish()?;
            modes.finish()?;

            let mut offer = Extension::begin(&mut extensions, extension::Type::PRE_SHARED_KEY)?;
            let mut identities = offer.begin_u16()?;
            let mut identity = identities.begin_u16()?;
            identity.put_slice(resumption.identity);
            identity.finish()?;
            identities.put_u32(resumption.obfuscated_ticket_age);
            identities.finish()?;
            let prefix_end = offer.encoded_len();
            let mut binders = offer.begin_u16()?;
            let mut binder = binders.begin_u8()?;
            let binder_start = binder.encoded_len();
            binder.put_slice(&[0; 32]);
            let binder_end = binder.encoded_len();
            binder.finish()?;
            binders.finish()?;
            offer.finish()?;
            binder_slot = Some(BinderSlot {
                prefix_end,
                binder_start,
                binder_end,
            });
        }
        extensions.finish()?;
        hello.finish()?;
        Ok(binder_slot)
    }

    pub(super) fn maximum_initial_len(
        transport_mode: transport::Mode,
        verifier: &config::Verifier,
        transport_params: &[u8],
        alpn_protocols: &[vec::Vec<u8>],
        resumption: Option<&resumption::Active>,
    ) -> Result<usize, codec::EncodeError> {
        use crate::crypto::kx::MAX_CLIENT_SHARE_LEN;
        use crate::wire::codec::EncodedSize;
        const MAX_CLIENT_SHARE: [u8; MAX_CLIENT_SHARE_LEN] = [0; MAX_CLIENT_SHARE_LEN];
        const RANDOM: [u8; handshake::RANDOM_LEN] = [0; handshake::RANDOM_LEN];
        const SESSION_ID: [u8; 32] = [0; 32];
        let session_id = if transport_mode.uses_legacy_session_id() {
            SESSION_ID.as_slice()
        } else {
            &[]
        };

        let mut size = EncodedSize::default();
        Offer {
            policy: HelloPolicy {
                verifier,
                transport_mode,
                transport_params,
                alpn_protocols,
            },
            core: HelloCore {
                suites: &record::CipherSuite::SUPPORTED,
                group: kx::KexGroup::X25519,
                random: &RANDOM,
                session_id,
                kx_pubkey: &MAX_CLIENT_SHARE,
            },
            extensions: HelloExtensions {
                cookie: None,
                resumption: resumption.map(resumption::Active::encoding_offer),
                offer_early_data: true,
                certificate_types: session::CertificateTypeOffers {
                    server: matches!(verifier, config::Verifier::RawPublicKey { .. })
                        .then_some(identity::CertificateType::RawPublicKey),
                    client: Some(identity::CertificateType::X509),
                },
            },
        }
        .encode(&mut size)?;
        size.finish()
    }
}

impl Request<'_> {
    pub(super) fn encode(
        self,
        offer: &session::OfferSettings,
        handshake: &session::Handshake,
        flight: &mut workspace::BoundedBuffer,
    ) -> Result<Option<BinderSlot>, connection::Error> {
        let session_id = if offer.config.transport_mode().uses_legacy_session_id() {
            handshake.session_id.as_slice()
        } else {
            &[]
        };
        let hello = Offer {
            policy: HelloPolicy {
                verifier: offer.config.verifier(),
                transport_mode: offer.config.transport_mode(),
                transport_params: offer.config.transport_params(),
                alpn_protocols: offer.config.alpn_protocols(),
            },
            core: HelloCore {
                suites: &offer.offered_suites,
                group: offer.kex_group,
                random: &handshake.client_random,
                session_id,
                kx_pubkey: self.kx_pubkey,
            },
            extensions: HelloExtensions {
                cookie: self.cookie,
                resumption: self.resumption,
                offer_early_data: self.offer_early_data,
                certificate_types: self.certificate_types,
            },
        };
        flight.clear();
        hello.encode(flight).map_err(Into::into)
    }
}

impl BinderSlot {
    /// Splices a resumption binder over the truncated ClientHello transcript.
    pub(super) fn splice(
        self,
        transcript: &hash::Transcript,
        ch_bytes: &mut [u8],
        psk: &[u8; 32],
    ) -> Result<(), connection::Error> {
        use crate::wire::psk::RESUMPTION_HASH;
        use crate::wire::psk::ResumptionBinder;
        let prefix = ch_bytes
            .get(..self.prefix_end)
            .ok_or(connection::Error::Encode)?;
        let mut t = transcript.fork();
        t.update(prefix);
        let partial_hash = t.hash(RESUMPTION_HASH).map_err(connection::Error::from)?;
        let binder = ResumptionBinder::compute(psk, partial_hash.as_slice())?;
        let target = ch_bytes
            .get_mut(self.binder_start..self.binder_end)
            .filter(|target| target.len() == binder.as_slice().len())
            .ok_or(connection::Error::Encode)?;
        target.copy_from_slice(binder.as_slice());
        Ok(())
    }
}
