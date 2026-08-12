use crate::client;
use crate::client::config;
use crate::client::session;
use crate::client::state;
use crate::connection;
use crate::crypto::hash;
use crate::crypto::material;
use crate::crypto::sig;
use crate::identity::leafkey;
use crate::identity::spki;
use crate::wire::codec::Encode as _;
use crate::wire::handshake::frame;
use crate::wire::handshake::messages;
use crate::wire::handshake::views;

use crate::identity::chain;

use crate::wire::handshake;

pub(super) trait Authentication {
    fn handle_certificate_request(
        &mut self,
        cr: views::CertificateRequestRef<'_>,
        raw: &[u8],
    ) -> Result<(), connection::Error>;
    fn append_client_auth_flight(
        &mut self,
        alg: hash::Algorithm,
        response: session::CertificateResponse,
    ) -> Result<(), connection::Error>;
    fn handle_certificate(
        &mut self,
        cert: views::CertificateRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
    ) -> Result<(), connection::Error>;
    fn offered_sig_scheme(&self, scheme: sig::SignatureScheme) -> bool;
    fn handle_certificate_verify(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        server_leaf: state::ServerLeaf,
    ) -> Result<(), connection::Error>;
    fn handle_server_finished<S: connection::EventSink + ?Sized>(
        &mut self,
        sf: &[u8],
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}
impl<C: connection::Clock, K> Authentication for client::Client<C, K> {
    /// Select the client-auth response from a borrowed main-handshake request;
    /// the identity flight is sent only after server authentication succeeds.
    fn handle_certificate_request(
        &mut self,
        cr: views::CertificateRequestRef<'_>,
        raw: &[u8],
    ) -> Result<(), connection::Error> {
        use crate::client::session::CertificateResponse;
        use crate::wire::extension::Type;
        use crate::wire::protocols::SignatureAlgorithms;
        if self.session.credentials.certificate_response.is_some() {
            return Err(connection::Error::UnexpectedMessage);
        }
        if !cr.certificate_request_context.is_empty() {
            return Err(connection::Error::IllegalParameter);
        }
        let sigs = cr
            .extensions
            .iter()
            .find(|e| e.ty == Type::SIGNATURE_ALGORITHMS)
            .ok_or(connection::Error::MissingExtension)?;
        let signing_scheme = self
            .session
            .credentials
            .identity
            .as_ref()
            .map(|source| source.signing_key().sig_scheme());
        let signing_scheme_accepted = SignatureAlgorithms::accepts(sigs.data, signing_scheme)?;
        self.session.credentials.certificate_response = Some(
            if self.session.credentials.identity.is_some() && signing_scheme_accepted {
                CertificateResponse::Identity
            } else {
                CertificateResponse::Empty
            },
        );
        self.session.handshake.transcript.update(raw);
        Ok(())
    }

    /// Build our client Certificate (+ CertificateVerify if we hold an identity)
    /// in response to a CertificateRequest, appending each to the transcript so
    /// the subsequent client Finished covers them.
    fn append_client_auth_flight(
        &mut self,
        alg: hash::Algorithm,
        response: session::CertificateResponse,
    ) -> Result<(), connection::Error> {
        use crate::client::config::Identity;
        use crate::client::session::CertificateResponse;
        let identity = match response {
            CertificateResponse::Empty => None,
            CertificateResponse::Identity => Some(
                self.session
                    .credentials
                    .identity
                    .as_deref()
                    .ok_or(connection::Error::BadConfig)?,
            ),
        };
        let cert_start = self.session.buffers.flight.len();
        self.session
            .buffers
            .flight
            .put_u8(handshake::Type::Certificate as u8);
        let mut certificate = self.session.buffers.flight.begin_u24()?;
        certificate.begin_u8()?.finish()?;
        let mut entries = certificate.begin_u24()?;
        match identity {
            Some(Identity::RawPublicKey { signing_key }) => {
                use crate::wire::codec::EncodeError;
                let pubkey = signing_key.pubkey().ok_or(EncodeError::Overflow)?;
                let spki = spki::SubjectPublicKey::encoded_ed25519(pubkey);
                let mut data = entries.begin_u24()?;
                data.put_slice(&spki);
                data.finish()?;
                entries.begin_u16()?.finish()?;
            }
            Some(Identity::X509 { chain_der, .. }) => {
                for der in chain_der {
                    let mut data = entries.begin_u24()?;
                    data.put_slice(der);
                    data.finish()?;
                    entries.begin_u16()?.finish()?;
                }
            }
            None => {}
        }
        entries.finish()?;
        certificate.finish()?;
        self.session
            .handshake
            .transcript
            .update(&self.session.buffers.flight[cert_start..]);

        if let Some(src) = identity {
            let scheme = src.signing_key().sig_scheme();
            let h = self
                .session
                .handshake
                .transcript
                .hash(alg)
                .map_err(connection::Error::from)?;
            let cv_msg = messages::CertificateVerify::message(h.as_slice(), false)?;
            let signature = src
                .signing_key()
                .sign_fixed(&cv_msg)
                .map_err(|_| connection::Error::Sig)?;
            let cv_start = self.session.buffers.flight.len();
            frame::Frame::encode_certificate_verify(
                scheme,
                &signature,
                &mut self.session.buffers.flight,
            )?;
            self.session
                .handshake
                .transcript
                .update(&self.session.buffers.flight[cv_start..]);
        }
        Ok(())
    }

    fn handle_certificate(
        &mut self,
        cert: views::CertificateRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
    ) -> Result<(), connection::Error> {
        let server_leaf = match self.session.offer.config.verifier() {
            config::Verifier::RawPublicKey { expected_pubkey } => {
                if cert.certificate_list.len() != 1 {
                    return Err(connection::Error::BadCertificate);
                }
                let entry = cert
                    .certificate_list
                    .first()
                    .ok_or(connection::Error::BadCertificate)?;
                let leafkey::LeafKey::Ed25519(server_pk) =
                    leafkey::LeafKey::from_spki(entry.cert_data)?
                else {
                    return Err(connection::Error::BadCertificate);
                };
                if server_pk != expected_pubkey {
                    return Err(connection::Error::BadCertificate);
                }
                state::ServerLeaf::PinnedEd25519
            }
            config::Verifier::X509 { .. } => return Err(connection::Error::BadConfig),
            config::Verifier::X509Store {
                roots, hostname, ..
            } => {
                use crate::identity::UnixTime;
                use crate::identity::chain::Chain;
                let now = UnixTime::from_secs(self.session.runtime.clock.now_secs());
                if cert.certificate_list.is_empty() {
                    return Err(connection::Error::BadCertificate);
                }
                let mut chain = Chain::empty();
                for entry in cert.certificate_list.iter() {
                    use crate::identity::cert::Cert;

                    let parsed_cert = Cert::parse(entry.cert_data)
                        .map_err(connection::Error::BadCertificateParse)?;
                    chain.try_push(parsed_cert).map_err(|_| {
                        connection::Error::BadCertificateChain(chain::Error::ChainTooLong)
                    })?;
                }
                let validated = chain
                    .validate_with_anchor_verifier(now, hostname, |subject| {
                        roots.verify_subject(subject)
                    })
                    .map_err(|e| match e {
                        chain::Error::NoTrustAnchor => connection::Error::NoTrustAnchorForIssuer,
                        _ => connection::Error::BadCertificateChain(e),
                    })?;
                let leaf_spki = validated.spki();
                let leaf = leafkey::LeafKey::from_x509_spki(leaf_spki)?;
                let server_leaf = state::ServerLeaf::Flight(leaf.kind());
                self.session.buffers.flight.clear();
                self.session
                    .buffers
                    .flight
                    .try_extend(leaf.raw())
                    .map_err(|_| {
                        connection::Error::WorkspaceExhausted(
                            connection::WorkspaceRegion::PeerIdentity,
                        )
                    })?;
                server_leaf
            }
        };
        self.session.handshake.transcript.update(raw);
        self.session.handshake.state =
            state::State::expect_certificate_verify(secrets, server_leaf);
        Ok(())
    }

    fn offered_sig_scheme(&self, scheme: sig::SignatureScheme) -> bool {
        match self.session.offer.config.verifier() {
            config::Verifier::RawPublicKey { .. } => scheme == sig::SignatureScheme::ED25519,
            config::Verifier::X509 { .. } | config::Verifier::X509Store { .. } => {
                use crate::wire::protocols::SignatureAlgorithms;
                SignatureAlgorithms::x509_supported(scheme)
            }
        }
    }

    fn handle_certificate_verify(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        server_leaf: state::ServerLeaf,
    ) -> Result<(), connection::Error> {
        if !self.offered_sig_scheme(cv.algorithm) {
            return Err(connection::Error::SigSchemeNotOffered);
        }
        let h_pre_cv = self
            .session
            .handshake
            .transcript
            .hash(self.session.application.hash_alg()?)
            .map_err(connection::Error::from)?;
        let msg = messages::CertificateVerify::message(h_pre_cv.as_slice(), true)?;
        let leaf = match (server_leaf, self.session.offer.config.verifier()) {
            (
                state::ServerLeaf::PinnedEd25519,
                config::Verifier::RawPublicKey { expected_pubkey },
            ) => leafkey::LeafKey::from_raw(
                leafkey::LeafKeyKind::Ed25519,
                expected_pubkey.as_slice(),
            )?,
            (state::ServerLeaf::Flight(kind), config::Verifier::X509Store { .. }) => {
                leafkey::LeafKey::from_raw(kind, self.session.buffers.flight.as_slice())?
            }
            _ => return Err(connection::Error::BadConfig),
        };
        leaf.verify(cv.algorithm, &msg, cv.signature)?;
        self.session.buffers.flight.clear();
        self.session.handshake.transcript.update(raw);
        self.session.handshake.state = state::State::expect_server_finished(secrets);
        Ok(())
    }

    fn handle_server_finished<S: connection::EventSink + ?Sized>(
        &mut self,
        sf: &[u8],
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::client::session::EarlyData;
        use crate::connection::Epoch;
        use crate::connection::Event;
        use crate::connection::EventContext;
        use crate::wire::handshake::messages::Finished;
        let alg = self.session.application.hash_alg()?;
        let h_pre_sf = self
            .session
            .handshake
            .transcript
            .hash(alg)
            .map_err(connection::Error::from)?;
        let expected =
            Finished::verify_data(alg, secrets.server_traffic.as_slice(), h_pre_sf.as_slice())?;
        if !expected.ct_eq(sf) {
            return Err(connection::Error::BadFinished.into());
        }
        self.session.handshake.transcript.update(raw);

        let h_sf = self
            .session
            .handshake
            .transcript
            .hash(alg)
            .map_err(connection::Error::from)?;

        let master = secrets.schedule.into_master()?;
        let c_ap = master.client_application_traffic_secret(h_sf.as_slice())?;
        let s_ap = master.server_application_traffic_secret(h_sf.as_slice())?;
        let exporter_master = master.exporter_master_secret(h_sf.as_slice())?;
        self.session.application.traffic.activate(c_ap, s_ap)?;
        self.session.application.exporter_master = Some(exporter_master);
        let suite = self.session.application.traffic.suite();
        let read_secret = self
            .session
            .application
            .traffic
            .secret(material::Side::Server)?;
        let write_secret = self
            .session
            .application
            .traffic
            .secret(material::Side::Client)?;

        EventContext::emit(
            events,
            suite,
            Event::KeysReady {
                epoch: Epoch::Application,
                read_secret,
                write_secret,
            },
        )?;

        if matches!(self.session.extensions.early_data, EarlyData::Accepted)
            && self
                .session
                .offer
                .config
                .transport_mode()
                .uses_end_of_early_data()
        {
            const END_OF_EARLY_DATA: [u8; 4] = [handshake::Type::EndOfEarlyData as u8, 0, 0, 0];
            self.session.handshake.transcript.update(&END_OF_EARLY_DATA);
            EventContext::emit(
                events,
                self.session.application.traffic.suite(),
                Event::Send {
                    epoch: Epoch::Handshake,
                    data: &END_OF_EARLY_DATA,
                },
            )?;
        }

        self.session.buffers.flight.clear();
        if let Some(response) = self.session.credentials.certificate_response.take() {
            self.append_client_auth_flight(alg, response)?;
        }

        let h_pre_cf = self
            .session
            .handshake
            .transcript
            .hash(alg)
            .map_err(connection::Error::from)?;
        let cf_data =
            Finished::verify_data(alg, secrets.client_traffic.as_slice(), h_pre_cf.as_slice())?;
        let cf_start = self.session.buffers.flight.len();
        frame::Frame::encode_finished(cf_data.as_slice(), &mut self.session.buffers.flight)?;
        self.session
            .handshake
            .transcript
            .update(&self.session.buffers.flight[cf_start..]);
        let h_cf = self
            .session
            .handshake
            .transcript
            .hash(alg)
            .map_err(connection::Error::from)?;
        let rms = master.resumption_master_secret(h_cf.as_slice())?;
        self.session.application.resumption_master = Some(rms);

        EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            Event::Send {
                epoch: Epoch::Handshake,
                data: &self.session.buffers.flight,
            },
        )?;
        EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            Event::Done,
        )?;

        self.session.handshake.state = state::State::done();
        Ok(())
    }
}
