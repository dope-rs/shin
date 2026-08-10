use crate::client;
use crate::client::config;
use crate::client::state;
use crate::connection;
use crate::crypto::hash;
use crate::crypto::material;
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
    fn append_client_auth_flight(&mut self, alg: hash::Algorithm) -> Result<(), connection::Error>;
    fn handle_certificate(
        &mut self,
        cert: views::CertificateRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
    ) -> Result<(), connection::Error>;
    fn offered_sig_scheme(&self, scheme: u16) -> bool;
    fn handle_certificate_verify(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        server_leaf_key: &leafkey::LeafKey,
    ) -> Result<(), connection::Error>;
    fn handle_server_finished<S: connection::EventSink + ?Sized>(
        &mut self,
        sf: &[u8],
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}
impl<C: connection::Clock> Authentication for client::Client<C> {
    /// Record the server's client-auth context and accepted signature schemes;
    /// the identity flight is sent only after server authentication succeeds.
    fn handle_certificate_request(
        &mut self,
        cr: views::CertificateRequestRef<'_>,
        raw: &[u8],
    ) -> Result<(), connection::Error> {
        use crate::client::session::CertRequest;
        use crate::wire::extension::Type;
        use crate::wire::protocols::SignatureAlgorithms;
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
            .map_or(u16::MAX, |source| source.signing_key().sig_scheme());
        let signing_scheme_accepted = SignatureAlgorithms::contains(sigs.data, signing_scheme)?;
        let context = arrayvec::ArrayVec::try_from(cr.certificate_request_context)
            .map_err(|_| connection::Error::IllegalParameter)?;
        self.session.credentials.cert_request = Some(CertRequest {
            context,
            signing_scheme_accepted,
        });
        self.session.handshake.transcript.update(raw);
        Ok(())
    }

    /// Build our client Certificate (+ CertificateVerify if we hold an identity)
    /// in response to a CertificateRequest, appending each to the transcript so
    /// the subsequent client Finished covers them (RFC 8446 §4.4).
    fn append_client_auth_flight(&mut self, alg: hash::Algorithm) -> Result<(), connection::Error> {
        use crate::client::config::Identity;
        let req = self
            .session
            .credentials
            .cert_request
            .as_ref()
            .ok_or(connection::Error::UnexpectedMessage)?;
        let cert_start = self.session.buffers.flight.len();
        self.session
            .buffers
            .flight
            .put_u8(handshake::Type::Certificate as u8);
        let mut certificate = self.session.buffers.flight.begin_u24()?;
        let mut context = certificate.begin_u8()?;
        context.put_slice(&req.context);
        context.finish()?;
        let mut entries = certificate.begin_u24()?;
        match self.session.credentials.identity.as_deref() {
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

        if let Some(src) = &self.session.credentials.identity {
            let scheme = src.signing_key().sig_scheme();
            if !req.signing_scheme_accepted {
                return Err(connection::Error::SigSchemeNotOffered);
            }
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
        use crate::identity::leafkey::LeafKeyKind;
        let server_leaf_key = match self.session.offer.config.verifier() {
            config::Verifier::RawPublicKey { expected_pubkey } => {
                if cert.certificate_list.len() != 1 {
                    return Err(connection::Error::BadCertificate);
                }
                let entry = cert
                    .certificate_list
                    .first()
                    .ok_or(connection::Error::BadCertificate)?;
                let spki::SubjectPublicKey::Ed25519(server_pk) =
                    spki::SubjectPublicKey::decode(entry.cert_data)
                        .map_err(|_| connection::Error::Spki)?
                else {
                    return Err(connection::Error::BadCertificate);
                };
                if server_pk != *expected_pubkey {
                    return Err(connection::Error::BadCertificate);
                }
                leafkey::LeafKey::from_raw(LeafKeyKind::Ed25519, &server_pk)?
            }
            config::Verifier::X509 { anchors, hostname } => {
                use crate::identity::UnixTime;
                use crate::identity::cert::Cert;
                use crate::identity::cert::OID_EC_PUBLIC_KEY;
                use crate::identity::cert::OID_ED25519;
                use crate::identity::cert::OID_RSA_ENCRYPTION;
                use crate::identity::chain::Chain;
                let now_seconds = self.session.runtime.clock.now_ms() / 1000;
                if cert.certificate_list.is_empty() {
                    return Err(connection::Error::BadCertificate);
                }
                let mut parsed = arrayvec::ArrayVec::<Cert<'_>, { chain::MAX_LEN }>::new();
                for entry in cert.certificate_list.iter() {
                    let parsed_cert = Cert::parse(entry.cert_data)
                        .map_err(connection::Error::BadCertificateParse)?;
                    parsed.try_push(parsed_cert).map_err(|_| {
                        connection::Error::BadCertificateChain(chain::Error::ChainTooLong)
                    })?;
                }
                Chain::new(&parsed)
                    .validate_with_anchor_verifier(UnixTime(now_seconds), hostname, |subject| {
                        for anchor in anchors {
                            if anchor.subject_der != subject.tbs.issuer_der {
                                continue;
                            }
                            let view = anchor.view()?;
                            if let Some(anchor_match) = view.verify_subject(subject)? {
                                return Ok(Some(anchor_match));
                            }
                        }
                        Ok(None)
                    })
                    .map_err(|e| match e {
                        chain::Error::NoTrustAnchor => connection::Error::NoTrustAnchorForIssuer,
                        _ => connection::Error::BadCertificateChain(e),
                    })?;
                let leaf_spki = parsed[0].tbs.spki;
                let kind = if leaf_spki.algorithm.oid == OID_ED25519 {
                    LeafKeyKind::Ed25519
                } else if leaf_spki.algorithm.oid == OID_EC_PUBLIC_KEY {
                    LeafKeyKind::Ecdsa
                } else if leaf_spki.algorithm.oid == OID_RSA_ENCRYPTION {
                    LeafKeyKind::Rsa
                } else {
                    return Err(connection::Error::UnsupportedSigScheme);
                };
                leafkey::LeafKey::from_raw(kind, leaf_spki.subject_public_key)?
            }
        };
        self.session.handshake.transcript.update(raw);
        self.session.handshake.state =
            state::State::expect_certificate_verify(secrets, server_leaf_key);
        Ok(())
    }

    fn offered_sig_scheme(&self, scheme: u16) -> bool {
        use crate::wire::protocols::{
            SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_ED25519,
            SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512,
        };
        match self.session.offer.config.verifier() {
            config::Verifier::RawPublicKey { .. } => scheme == SIG_ED25519,
            config::Verifier::X509 { .. } => matches!(
                scheme,
                SIG_ECDSA_SECP256R1_SHA256
                    | SIG_ECDSA_SECP384R1_SHA384
                    | SIG_RSA_PSS_RSAE_SHA256
                    | SIG_RSA_PSS_RSAE_SHA384
                    | SIG_RSA_PSS_RSAE_SHA512
                    | SIG_ED25519
            ),
        }
    }

    fn handle_certificate_verify(
        &mut self,
        cv: views::CertificateVerifyRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        server_leaf_key: &leafkey::LeafKey,
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
        server_leaf_key.verify(cv.algorithm, &msg, cv.signature)?;
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
        if self.session.credentials.cert_request.is_some() {
            self.append_client_auth_flight(alg)?;
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
