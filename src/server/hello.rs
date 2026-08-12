use crate::connection;
use crate::server;
use crate::server::config;
use crate::server::resumption::Resumption as _;
use crate::server::retry;
use crate::server::retry::Retry as _;
use crate::transport;
use crate::wire::codec::Encode as _;
use crate::wire::codec::Reserve as _;
use crate::wire::extension;
use crate::wire::handshake;
use crate::wire::handshake::views;
use crate::wire::protocols;
use ring::rand::SecureRandom as _;
pub(super) trait Hello {
    fn handle_client_hello<G, V, S, const DOMAIN: u8>(
        &mut self,
        ch: views::ClientHelloRef<'_>,
        raw: &[u8],
        shard: &mut server::Shard<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized;
}
impl<C: connection::Clock, const SERVER_DOMAIN: u8> Hello for server::Server<C, SERVER_DOMAIN> {
    fn handle_client_hello<G, V, S, const DOMAIN: u8>(
        &mut self,
        ch: views::ClientHelloRef<'_>,
        raw: &[u8],
        shard: &mut server::Shard<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        use crate::crypto::schedule::Schedule;
        use crate::server::negotiation::ClientHelloOffers;
        use crate::server::session::State;
        use crate::wire::handshake::RANDOM_LEN;
        use crate::wire::handshake::frame::Frame;
        use crate::wire::handshake::messages::Finished;
        use crate::wire::protocols::SignatureAlgorithms;
        use crate::wire::protocols::SupportedVersions;
        use crate::wire::psk::RESUMPTION_HASH;
        use crate::wire::record::CipherSuite;
        if ch.legacy_version != handshake::TLS_1_2 {
            return Err(connection::Error::IllegalParameter.into());
        }
        let offers = ClientHelloOffers::parse(ch.extensions, raw)?;
        let client_kx = offers.kx();
        if let Some(invariant) = self.session.handshake.hrr_invariant {
            invariant.validate(ch, client_kx)?;
        }
        let selected_suite = CipherSuite::SUPPORTED
            .iter()
            .copied()
            .find(|s| ch.cipher_suites.contains(s.wire_id()))
            .ok_or(connection::Error::UnsupportedCipherSuite)?;
        let hash_alg = selected_suite.hash_alg();
        self.session
            .handshake
            .transcript
            .select(hash_alg)
            .map_err(connection::Error::from)?;
        self.session.application.traffic.select(selected_suite)?;
        if ch.legacy_compression_methods != [0] {
            return Err(connection::Error::IllegalParameter.into());
        }
        if self.session.transport_mode.uses_legacy_session_id() {
            if ch.legacy_session_id.len() > 32 {
                return Err(connection::Error::Decode.into());
            }
        } else if !ch.legacy_session_id.is_empty() {
            return Err(connection::Error::IllegalParameter.into());
        }
        let sv = ch
            .extensions
            .find(extension::Type::SUPPORTED_VERSIONS)
            .ok_or(connection::Error::MissingExtension)?;
        if !SupportedVersions::decode_client(sv.data)?.contains(protocols::TLS_1_3) {
            return Err(connection::Error::BadVersion.into());
        }
        let hrr_group = client_kx.retry_group();
        let sigs = ch
            .extensions
            .find(extension::Type::SIGNATURE_ALGORITHMS)
            .ok_or(connection::Error::MissingExtension)?;
        let local_sig_scheme = shard.policy.source.signing_key().sig_scheme();
        if !SignatureAlgorithms::accepts(sigs.data, Some(local_sig_scheme))? {
            return Err(connection::Error::UnsupportedSigScheme.into());
        }
        match (
            self.session.transport_mode,
            offers.peer_quic_transport_parameters(),
        ) {
            (transport::Mode::Quic, None) => {
                return Err(connection::Error::MissingExtension.into());
            }
            (transport::Mode::Tls, Some(_)) => {
                return Err(connection::Error::UnsolicitedExtension.into());
            }
            _ => {}
        }
        let peer_share = match client_kx.selected() {
            Some(share) => share,
            None if !self.session.handshake.hrr_done => {
                let invariant = retry::ClientHelloInvariant::capture(ch, hrr_group)?;
                return self.send_hello_retry_request(
                    raw,
                    ch.legacy_session_id,
                    hrr_group,
                    invariant,
                    events,
                );
            }
            None => return Err(connection::Error::MissingExtension.into()),
        };
        let kex_group = peer_share.group();
        let peer_pubkey = peer_share.key_exchange();

        self.session.peer.selected_alpn = offers.select_alpn(&shard.policy.alpn)?;
        if let Some(parameters) = offers.peer_quic_transport_parameters() {
            connection::EventContext::emit(
                events,
                self.session.application.traffic.suite(),
                connection::Event::PeerExtension {
                    ty: extension::Type::QUIC_TRANSPORT_PARAMETERS.0,
                    data: parameters,
                },
            )?;
        }

        let psk_accepted = if hash_alg == RESUMPTION_HASH
            && let Some(psk) = offers.psk()
        {
            self.try_accept_psk(
                psk,
                shard.policy.ticket_keys.as_ref(),
                self.session.peer.selected_alpn(&shard.policy.alpn),
                shard.prepared.replay_domain.id(),
            )?
        } else {
            None
        };
        let now_ms = self.session.runtime.clock.now_ms();
        let early_accepted = self.session.peer.early_data.admit(
            &mut shard.policy.guard,
            offers.early_data(),
            psk_accepted.as_ref(),
            self.session.application.traffic.suite(),
            now_ms,
        );
        self.session.handshake.transcript.update(raw);
        if let (Some(p), true) = (psk_accepted.as_ref(), early_accepted) {
            let h_ch = self
                .session
                .handshake
                .transcript
                .hash(RESUMPTION_HASH)
                .map_err(connection::Error::from)?;
            let cets = Schedule::client_early_traffic_secret(p.psk.as_slice(), h_ch.as_slice())?;
            connection::EventContext::emit(
                events,
                self.session.application.traffic.suite(),
                connection::Event::ZeroRttKeysReady {
                    secret: &cets,
                    max_early_data: p
                        .ticket
                        .max_early_data
                        .ok_or(connection::Error::UnexpectedMessage)?,
                    alpn: self.session.peer.selected_alpn(&shard.policy.alpn),
                },
            )?;
        }

        let mut server_random = [0u8; RANDOM_LEN];
        self.session
            .runtime
            .rng
            .fill(&mut server_random)
            .map_err(|_| connection::Error::Rng)?;

        self.session.buffers.flight.clear();
        self.session
            .buffers
            .flight
            .put_u8(handshake::Type::ServerHello as u8);
        let mut hello = self.session.buffers.flight.begin_u24()?;
        hello.put_u16(handshake::TLS_1_2);
        hello.put_slice(&server_random);
        let mut session = hello.begin_u8()?;
        session.put_slice(ch.legacy_session_id);
        session.finish()?;
        hello.put_u16(selected_suite.wire_id());
        hello.put_u8(0);
        let mut extensions = hello.begin_u16()?;
        let mut version =
            extension::Extension::begin(&mut extensions, extension::Type::SUPPORTED_VERSIONS)?;
        version.put_u16(protocols::TLS_1_3);
        version.finish()?;
        let mut share = extension::Extension::begin(&mut extensions, extension::Type::KEY_SHARE)?;
        share.put_u16(kex_group.wire_id());
        let mut key = share.begin_u16()?;
        let dhe = kex_group
            .respond(
                peer_pubkey,
                &self.session.runtime.rng,
                key.reserve_slice(kex_group.server_share_len())?,
            )
            .map_err(|_| connection::Error::Kx)?
            .into_secret();
        key.finish()?;
        share.finish()?;
        if psk_accepted.is_some() {
            let mut identity =
                extension::Extension::begin(&mut extensions, extension::Type::PRE_SHARED_KEY)?;
            identity.put_u16(0);
            identity.finish()?;
        }
        extensions.finish()?;
        hello.finish()?;
        self.session
            .handshake
            .transcript
            .update(&self.session.buffers.flight);

        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::Send {
                epoch: connection::Epoch::Plaintext,
                data: &self.session.buffers.flight,
            },
        )?;

        let ks_handshake = match &psk_accepted {
            Some(p) => Schedule::new_psk(RESUMPTION_HASH, p.psk.as_slice())
                .into_handshake(dhe.as_slice())?,
            None => Schedule::new(hash_alg).into_handshake(dhe.as_slice())?,
        };
        let h_chsh = self
            .session
            .handshake
            .transcript
            .hash(hash_alg)
            .map_err(connection::Error::from)?;
        let c_hs = ks_handshake.client_handshake_traffic_secret(h_chsh.as_slice())?;
        let s_hs = ks_handshake.server_handshake_traffic_secret(h_chsh.as_slice())?;

        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::KeysReady {
                epoch: connection::Epoch::Handshake,
                read_secret: &c_hs,
                write_secret: &s_hs,
            },
        )?;

        let certificate_negotiation = offers.certificate_negotiation(&shard.policy.source)?;
        self.session.peer.client_cert_type = certificate_negotiation.client_type;
        self.session.buffers.flight.clear();
        let ee_start = self.session.buffers.flight.len();
        self.session
            .buffers
            .flight
            .put_u8(handshake::Type::EncryptedExtensions as u8);
        let mut encrypted_extensions = self.session.buffers.flight.begin_u24()?;
        let mut extensions = encrypted_extensions.begin_u16()?;
        if offers.offered_server_certificate_type() {
            let mut cert_type = extension::Extension::begin(
                &mut extensions,
                extension::Type::SERVER_CERTIFICATE_TYPE,
            )?;
            cert_type.put_u8(certificate_negotiation.server_type.wire_id());
            cert_type.finish()?;
        }
        if offers.offered_client_certificate_type() {
            let mut cert_type = extension::Extension::begin(
                &mut extensions,
                extension::Type::CLIENT_CERTIFICATE_TYPE,
            )?;
            cert_type.put_u8(certificate_negotiation.client_type.wire_id());
            cert_type.finish()?;
        }
        if self.session.transport_mode.is_quic() {
            let mut parameters = extension::Extension::begin(
                &mut extensions,
                extension::Type::QUIC_TRANSPORT_PARAMETERS,
            )?;
            parameters.put_slice(&self.session.connection.transport_params);
            parameters.finish()?;
        }
        if let Some(protocol) = self.session.peer.selected_alpn(&shard.policy.alpn) {
            let mut protocols = extension::Extension::begin(
                &mut extensions,
                extension::Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            )?;
            let mut list = protocols.begin_u16()?;
            let mut encoded = list.begin_u8()?;
            encoded.put_slice(protocol);
            encoded.finish()?;
            list.finish()?;
            protocols.finish()?;
        }
        if early_accepted {
            extension::Extension::begin(&mut extensions, extension::Type::EARLY_DATA)?.finish()?;
        }
        extensions.finish()?;
        encrypted_extensions.finish()?;
        self.session
            .handshake
            .transcript
            .update(&self.session.buffers.flight[ee_start..]);

        if psk_accepted.is_none() && shard.policy.client_auth.is_some() {
            let cr_start = self.session.buffers.flight.len();
            self.session
                .buffers
                .flight
                .put_u8(handshake::Type::CertificateRequest as u8);
            let mut request = self.session.buffers.flight.begin_u24()?;
            request.begin_u8()?.finish()?;
            let mut extensions = request.begin_u16()?;
            let mut algorithms = extension::Extension::begin(
                &mut extensions,
                extension::Type::SIGNATURE_ALGORITHMS,
            )?;
            let mut encoded = algorithms.begin_u16()?;
            for algorithm in SignatureAlgorithms::x509().as_slice() {
                encoded.put_u16(algorithm.wire_id());
            }
            encoded.finish()?;
            algorithms.finish()?;
            extensions.finish()?;
            request.finish()?;
            self.session
                .handshake
                .transcript
                .update(&self.session.buffers.flight[cr_start..]);
        }

        if psk_accepted.is_none() {
            use crate::server::config::CertSource;
            use crate::wire::codec::EncodeError;
            use crate::wire::handshake::messages::CertificateVerify;
            let raw_public_key = match &shard.policy.source {
                CertSource::RawPublicKey { signing_key } => {
                    use crate::identity::spki::SubjectPublicKey;
                    Some(SubjectPublicKey::encoded_ed25519(
                        signing_key.pubkey().ok_or(connection::Error::Sig)?,
                    ))
                }
                CertSource::X509 { .. } => None,
            };
            let cert_start = self.session.buffers.flight.len();
            self.session
                .buffers
                .flight
                .put_u8(handshake::Type::Certificate as u8);
            let mut certificate = self.session.buffers.flight.begin_u24()?;
            certificate.begin_u8()?.finish()?;
            let mut entries = certificate.begin_u24()?;
            match (&shard.policy.source, raw_public_key) {
                (CertSource::RawPublicKey { .. }, Some(public_key)) => {
                    let mut data = entries.begin_u24()?;
                    data.put_slice(&public_key);
                    data.finish()?;
                    entries.begin_u16()?.finish()?;
                }
                (CertSource::X509 { chain_der, .. }, _) => {
                    for der in chain_der {
                        let mut data = entries.begin_u24()?;
                        data.put_slice(der);
                        data.finish()?;
                        entries.begin_u16()?.finish()?;
                    }
                }
                (CertSource::RawPublicKey { .. }, None) => return Err(EncodeError::Overflow.into()),
            }
            entries.finish()?;
            certificate.finish()?;
            self.session
                .handshake
                .transcript
                .update(&self.session.buffers.flight[cert_start..]);

            let h_pre_cv = self
                .session
                .handshake
                .transcript
                .hash(hash_alg)
                .map_err(connection::Error::from)?;
            let cv_msg = CertificateVerify::message(h_pre_cv.as_slice(), true)?;
            let sig = shard
                .policy
                .source
                .signing_key()
                .sign_fixed(&cv_msg)
                .map_err(|_| connection::Error::Sig)?;
            let cv_start = self.session.buffers.flight.len();
            Frame::encode_certificate_verify(
                shard.policy.source.signing_key().sig_scheme(),
                &sig,
                &mut self.session.buffers.flight,
            )?;
            self.session
                .handshake
                .transcript
                .update(&self.session.buffers.flight[cv_start..]);
        }

        let h_pre_sf = self
            .session
            .handshake
            .transcript
            .hash(hash_alg)
            .map_err(connection::Error::from)?;
        let sf_data = Finished::verify_data(hash_alg, s_hs.as_slice(), h_pre_sf.as_slice())?;
        let sf_start = self.session.buffers.flight.len();
        Frame::encode_finished(sf_data.as_slice(), &mut self.session.buffers.flight)?;
        self.session
            .handshake
            .transcript
            .update(&self.session.buffers.flight[sf_start..]);
        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::Send {
                epoch: connection::Epoch::Handshake,
                data: &self.session.buffers.flight,
            },
        )?;

        let h_sf = self
            .session
            .handshake
            .transcript
            .hash(hash_alg)
            .map_err(connection::Error::from)?;
        let ks_master = ks_handshake.into_master()?;
        let c_ap = ks_master.client_application_traffic_secret(h_sf.as_slice())?;
        let s_ap = ks_master.server_application_traffic_secret(h_sf.as_slice())?;
        let exporter_master = ks_master.exporter_master_secret(h_sf.as_slice())?;
        self.session.application.traffic.activate(c_ap, s_ap)?;
        self.session.application.exporter_master = Some(exporter_master);
        self.session.application.master = Some(ks_master);

        let (read_secret, write_secret) = self.session.application.traffic_secrets()?;
        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::KeysReady {
                epoch: connection::Epoch::Application,
                read_secret,
                write_secret,
            },
        )?;

        if early_accepted && self.session.transport_mode.uses_end_of_early_data() {
            self.session.handshake.state = State::ExpectEndOfEarlyData {
                client_handshake_traffic: c_hs,
            };
        } else if psk_accepted.is_none() && shard.policy.client_auth.is_some() {
            self.session.handshake.state = State::ExpectClientCertificate {
                client_handshake_traffic: c_hs,
            };
        } else {
            let verify_data = Finished::verify_data(hash_alg, c_hs.as_slice(), h_sf.as_slice())?;
            self.session.handshake.state = State::ExpectClientFinished { verify_data };
        }
        Ok(())
    }
}
