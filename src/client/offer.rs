use crate::client;
use crate::client::config;
use crate::connection;
use crate::crypto::hash;
use crate::crypto::kx;
use crate::identity;
use crate::transport;
use crate::wire::codec;
use crate::wire::codec::Encode as _;
use crate::wire::extension;
use crate::wire::protocols;
use crate::wire::record;
use alloc::vec;

use crate::wire::handshake;
use crate::wire::psk;

#[derive(Clone, Copy)]
pub(super) struct Hello<'a> {
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
    cookie: Option<&'a [u8]>,
    resumption: Option<&'a config::Resumption>,
    offer_early_data: bool,
    client_cert_type_offer: Option<u8>,
}

impl<'a> Hello<'a> {
    fn hostname(self) -> Option<&'a [u8]> {
        match self.policy.verifier {
            config::Verifier::X509 { hostname, .. }
                if !identity::Hostname::new(hostname).is_ip_literal() =>
            {
                Some(hostname)
            }
            config::Verifier::RawPublicKey { .. } | config::Verifier::X509 { .. } => None,
        }
    }

    fn record_encrypted_extension_offers(
        self,
        offered: &mut arrayvec::ArrayVec<extension::Type, 16>,
    ) -> Result<(), connection::Error> {
        let mut record = |ty| offered.try_push(ty).map_err(|_| connection::Error::Encode);
        record(extension::Type::SUPPORTED_GROUPS)?;
        if matches!(self.policy.verifier, config::Verifier::RawPublicKey { .. }) {
            record(extension::Type::SERVER_CERTIFICATE_TYPE)?;
        }
        if self.extensions.client_cert_type_offer.is_some() {
            record(extension::Type::CLIENT_CERTIFICATE_TYPE)?;
        }
        if self.policy.transport_mode.is_quic() {
            record(extension::Type::QUIC_TRANSPORT_PARAMETERS)?;
        }
        if self.hostname().is_some() {
            record(extension::Type::SERVER_NAME)?;
        }
        if !self.policy.alpn_protocols.is_empty() {
            record(extension::Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)?;
        }
        if self.extensions.offer_early_data {
            record(extension::Type::EARLY_DATA)?;
        }
        Ok(())
    }

    fn encode(self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        use crate::wire::extension::Extension;
        use crate::wire::handshake::TLS_1_2;
        use crate::wire::protocols::SignatureAlgorithms;
        use crate::wire::protocols::TLS_1_3;
        let server_cert_type = match self.policy.verifier {
            config::Verifier::RawPublicKey { .. } => protocols::CERT_TYPE_RAW_PUBLIC_KEY,
            config::Verifier::X509 { .. } => protocols::CERT_TYPE_X509,
        };
        let hostname = self.hostname();
        let signature_algorithms = match self.policy.verifier {
            config::Verifier::RawPublicKey { .. } => SignatureAlgorithms::rpk().as_slice(),
            config::Verifier::X509 { .. } => SignatureAlgorithms::x509().as_slice(),
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
            encoded_algorithms.put_u16(*algorithm);
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

        if matches!(self.policy.verifier, config::Verifier::RawPublicKey { .. }) {
            let mut types =
                Extension::begin(&mut extensions, extension::Type::SERVER_CERTIFICATE_TYPE)?;
            let mut list = types.begin_u8()?;
            list.put_u8(server_cert_type);
            list.finish()?;
            types.finish()?;
        }
        if let Some(cert_type) = self.extensions.client_cert_type_offer {
            let mut types =
                Extension::begin(&mut extensions, extension::Type::CLIENT_CERTIFICATE_TYPE)?;
            let mut list = types.begin_u8()?;
            list.put_u8(cert_type);
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
            encoded.put_slice(cookie);
            encoded.finish()?;
        }
        if self.extensions.offer_early_data {
            Extension::begin(&mut extensions, extension::Type::EARLY_DATA)?.finish()?;
        }
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
            identity.put_slice(&resumption.ticket);
            identity.finish()?;
            identities.put_u32(
                resumption
                    .age_millis
                    .wrapping_add(resumption.ticket_age_add),
            );
            identities.finish()?;
            let mut binders = offer.begin_u16()?;
            let mut binder = binders.begin_u8()?;
            binder.put_slice(&[0; 32]);
            binder.finish()?;
            binders.finish()?;
            offer.finish()?;
        }
        extensions.finish()?;
        hello.finish()
    }

    pub(super) fn maximum_initial_len(
        transport_mode: transport::Mode,
        verifier: &config::Verifier,
        transport_params: &[u8],
        alpn_protocols: &[vec::Vec<u8>],
        resumption: Option<&config::Resumption>,
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
        Hello {
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
                resumption,
                offer_early_data: true,
                client_cert_type_offer: Some(protocols::CERT_TYPE_X509),
            },
        }
        .encode(&mut size)?;
        size.finish()
    }
}

pub(super) trait Offer {
    fn encode_client_hello(
        &mut self,
        kx_pubkey: &[u8],
        cookie: Option<&[u8]>,
        resumption: Option<&config::Resumption>,
        offer_early_data: bool,
    ) -> Result<(), connection::Error>;
    fn splice_psk_binder(
        transcript: &hash::Transcript,
        ch_bytes: &mut [u8],
        psk: &[u8; 32],
    ) -> Result<(), connection::Error>;
}
impl<C: connection::Clock> Offer for client::Client<C> {
    fn encode_client_hello(
        &mut self,
        kx_pubkey: &[u8],
        cookie: Option<&[u8]>,
        resumption: Option<&config::Resumption>,
        offer_early_data: bool,
    ) -> Result<(), connection::Error> {
        let client_cert_type_offer = match &self.session.credentials.identity {
            Some(source) => Some(source.cert_type()),
            None if matches!(
                self.session.offer.config.verifier(),
                config::Verifier::RawPublicKey { .. }
            ) =>
            {
                Some(protocols::CERT_TYPE_RAW_PUBLIC_KEY)
            }
            None => None,
        };
        let session_id = if self
            .session
            .offer
            .config
            .transport_mode()
            .uses_legacy_session_id()
        {
            self.session.handshake.session_id.as_slice()
        } else {
            &[]
        };
        let hello = Hello {
            policy: HelloPolicy {
                verifier: self.session.offer.config.verifier(),
                transport_mode: self.session.offer.config.transport_mode(),
                transport_params: self.session.offer.config.transport_params(),
                alpn_protocols: self.session.offer.config.alpn_protocols(),
            },
            core: HelloCore {
                suites: &self.session.offer.offered_suites,
                group: self.session.offer.kex_group,
                random: &self.session.handshake.client_random,
                session_id,
                kx_pubkey,
            },
            extensions: HelloExtensions {
                cookie,
                resumption,
                offer_early_data,
                client_cert_type_offer,
            },
        };
        self.session.extensions.ee_offered.clear();
        hello.record_encrypted_extension_offers(&mut self.session.extensions.ee_offered)?;
        let flight = &mut self.session.buffers.flight;
        flight.clear();
        hello.encode(flight)?;
        Ok(())
    }

    /// Splice a resumption binder over `Truncate(ClientHello)`, prefixed by
    /// `message_hash(CH1) ‖ HRR` after a retry (RFC 8446 §4.2.11.2).
    fn splice_psk_binder(
        transcript: &hash::Transcript,
        ch_bytes: &mut [u8],
        psk: &[u8; 32],
    ) -> Result<(), connection::Error> {
        use crate::wire::psk::RESUMPTION_HASH;
        use crate::wire::psk::ResumptionBinder;
        let prefix_len = psk::Offer::binder_transcript_prefix(ch_bytes, psk.len())
            .ok_or(connection::Error::Encode)?
            .len();
        let mut t = transcript.fork();
        t.update(&ch_bytes[..prefix_len]);
        let partial_hash = t.hash(RESUMPTION_HASH).map_err(connection::Error::from)?;
        let binder = ResumptionBinder::compute(psk, partial_hash.as_slice())?;
        let binder_start = ch_bytes.len() - psk.len();
        ch_bytes[binder_start..].copy_from_slice(binder.as_slice());
        Ok(())
    }
}
