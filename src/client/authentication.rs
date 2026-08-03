use super::*;

pub(super) trait Authentication {
    fn handle_certificate_request(
        &mut self,
        cr: CertificateRequestRef<'_>,
        raw: &[u8],
    ) -> Result<(), Error>;
    fn append_client_auth_flight(&mut self, alg: HashAlg) -> Result<(), Error>;
    fn handle_certificate(
        &mut self,
        cert: CertificateRef<'_>,
        raw: &[u8],
        secrets: HandshakeSecrets,
    ) -> Result<(), Error>;
    fn offered_sig_scheme(&self, scheme: u16) -> bool;
    fn handle_certificate_verify(
        &mut self,
        cv: CertificateVerifyRef<'_>,
        raw: &[u8],
        secrets: HandshakeSecrets,
        server_leaf_key: &LeafKey,
    ) -> Result<(), Error>;
    fn handle_server_finished<S: EventSink + ?Sized>(
        &mut self,
        sf: &[u8],
        raw: &[u8],
        secrets: HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
}
impl<C: Clock> Authentication for Client<C> {
    /// Record the server's client-auth context and accepted signature schemes;
    /// the identity flight is sent only after server authentication succeeds.
    fn handle_certificate_request(
        &mut self,
        cr: CertificateRequestRef<'_>,
        raw: &[u8],
    ) -> Result<(), Error> {
        let sigs = cr
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::MissingExtension)?;
        let signing_scheme = self
            .client_cert
            .as_ref()
            .map_or(u16::MAX, |source| source.signing_key().sig_scheme());
        let signing_scheme_accepted = SignatureAlgorithms::contains(sigs.data, signing_scheme)?;
        let context = ArrayVec::try_from(cr.certificate_request_context)
            .map_err(|_| Error::IllegalParameter)?;
        self.cert_request = Some(CertRequest {
            context,
            signing_scheme_accepted,
        });
        self.transcript.update(raw);
        Ok(())
    }

    /// Build our client Certificate (+ CertificateVerify if we hold an identity)
    /// in response to a CertificateRequest, appending each to the transcript so
    /// the subsequent client Finished covers them (RFC 8446 §4.4).
    fn append_client_auth_flight(&mut self, alg: HashAlg) -> Result<(), Error> {
        let req = self.cert_request.as_ref().ok_or(Error::UnexpectedMessage)?;
        let cert_start = self.flight.len();
        self.flight.put_u8(HandshakeType::Certificate as u8);
        self.flight.put_vec_u24(|certificate| {
            certificate.put_vec_u8(|context| {
                context.put_slice(&req.context);
                Ok(())
            })?;
            certificate.put_vec_u24(|entries| {
                match self.client_cert.as_deref() {
                    Some(ClientCertSource::RawPublicKey { signing_key }) => {
                        let pubkey = signing_key.pubkey().ok_or(EncodeError::Overflow)?;
                        let spki = SubjectPublicKey::encoded_ed25519(pubkey);
                        entries.put_vec_u24(|data| {
                            data.put_slice(&spki);
                            Ok(())
                        })?;
                        entries.put_vec_u16(|_| Ok(()))?;
                    }
                    Some(ClientCertSource::X509 { chain_der, .. }) => {
                        for der in chain_der {
                            entries.put_vec_u24(|data| {
                                data.put_slice(der);
                                Ok(())
                            })?;
                            entries.put_vec_u16(|_| Ok(()))?;
                        }
                    }
                    None => {}
                }
                Ok(())
            })
        })?;
        self.transcript.update(&self.flight[cert_start..]);

        if let Some(src) = &self.client_cert {
            let scheme = src.signing_key().sig_scheme();
            if !req.signing_scheme_accepted {
                return Err(Error::SigSchemeNotOffered);
            }
            let h = self.transcript.hash(alg);
            let cv_msg = CertificateVerify::message(h.as_slice(), false)?;
            let signature = src
                .signing_key()
                .sign_fixed(&cv_msg)
                .map_err(|_| Error::Sig)?;
            let cv_start = self.flight.len();
            Frame::encode_certificate_verify(scheme, &signature, &mut self.flight)?;
            self.transcript.update(&self.flight[cv_start..]);
        }
        Ok(())
    }

    fn handle_certificate(
        &mut self,
        cert: CertificateRef<'_>,
        raw: &[u8],
        secrets: HandshakeSecrets,
    ) -> Result<(), Error> {
        let server_leaf_key = match self.config.verifier() {
            Verifier::RawPublicKey { expected_pubkey } => {
                if cert.certificate_list.len() != 1 {
                    return Err(Error::BadCertificate);
                }
                let entry = cert.certificate_list.first().ok_or(Error::BadCertificate)?;
                let SubjectPublicKey::Ed25519(server_pk) =
                    SubjectPublicKey::decode(entry.cert_data).map_err(|_| Error::Spki)?
                else {
                    return Err(Error::BadCertificate);
                };
                if server_pk != *expected_pubkey {
                    return Err(Error::BadCertificate);
                }
                LeafKey::from_raw(LeafKeyKind::Ed25519, &server_pk)?
            }
            Verifier::X509 { anchors, hostname } => {
                let now_seconds = self.clock.now_ms() / 1000;
                if cert.certificate_list.is_empty() {
                    return Err(Error::BadCertificate);
                }
                let mut parsed = ArrayVec::<Cert<'_>, MAX_CHAIN_LEN>::new();
                for entry in cert.certificate_list.iter() {
                    let parsed_cert =
                        Cert::parse(entry.cert_data).map_err(Error::BadCertificateParse)?;
                    parsed
                        .try_push(parsed_cert)
                        .map_err(|_| Error::BadCertificateChain(ChainError::ChainTooLong))?;
                }
                Chain::new(&parsed)
                    .validate_with_anchor_verifier(UnixTime(now_seconds), hostname, |subject| {
                        for anchor in anchors {
                            if anchor.subject_der != subject.issuer_der {
                                continue;
                            }
                            let view = anchor.view().map_err(|_| ChainError::Parse)?;
                            if subject.verify_signature(&view.spki).is_ok() {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    })
                    .map_err(|e| match e {
                        ChainError::NoTrustAnchor => Error::NoTrustAnchorForIssuer,
                        _ => Error::BadCertificateChain(e),
                    })?;
                let leaf_spki = parsed[0].spki;
                let kind = if leaf_spki.algorithm.oid == OID_ED25519 {
                    LeafKeyKind::Ed25519
                } else if leaf_spki.algorithm.oid == OID_EC_PUBLIC_KEY {
                    LeafKeyKind::Ecdsa
                } else if leaf_spki.algorithm.oid == OID_RSA_ENCRYPTION {
                    LeafKeyKind::Rsa
                } else {
                    return Err(Error::UnsupportedSigScheme);
                };
                LeafKey::from_raw(kind, leaf_spki.subject_public_key)?
            }
        };
        self.transcript.update(raw);
        self.state = State::ExpectCertificateVerify {
            secrets,
            server_leaf_key,
        };
        Ok(())
    }

    fn offered_sig_scheme(&self, scheme: u16) -> bool {
        use crate::wire::proto::{
            SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_ED25519,
            SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512,
        };
        match self.config.verifier() {
            Verifier::RawPublicKey { .. } => scheme == SIG_ED25519,
            Verifier::X509 { .. } => matches!(
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
        cv: CertificateVerifyRef<'_>,
        raw: &[u8],
        secrets: HandshakeSecrets,
        server_leaf_key: &LeafKey,
    ) -> Result<(), Error> {
        if !self.offered_sig_scheme(cv.algorithm) {
            return Err(Error::SigSchemeNotOffered);
        }
        let h_pre_cv = self.transcript.hash(self.hash_alg());
        let msg = CertificateVerify::message(h_pre_cv.as_slice(), true)?;
        server_leaf_key.verify(cv.algorithm, &msg, cv.signature)?;
        self.transcript.update(raw);
        self.state = State::ExpectServerFinished { secrets };
        Ok(())
    }

    fn handle_server_finished<S: EventSink + ?Sized>(
        &mut self,
        sf: &[u8],
        raw: &[u8],
        secrets: HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        let alg = self.hash_alg();
        let h_pre_sf = self.transcript.hash(alg);
        let expected =
            Finished::verify_data(alg, secrets.server_traffic.as_slice(), h_pre_sf.as_slice())?;
        if !expected.ct_eq(sf) {
            return Err(Error::BadFinished.into());
        }
        self.transcript.update(raw);

        let h_sf = self.transcript.hash(alg);

        let hkdf = Hkdf::new(alg);
        let derived_for_master = hkdf.derive_secret(
            secrets.handshake.as_slice(),
            "derived",
            Transcript::hash_empty(alg).as_slice(),
        )?;
        let zero = [0u8; MAX_HASH_LEN];
        let master = hkdf.extract(derived_for_master.as_slice(), &zero[..alg.output_len()]);
        let c_ap = hkdf
            .derive_secret(master.as_slice(), "c ap traffic", h_sf.as_slice())?
            .to_digest();
        let s_ap = hkdf
            .derive_secret(master.as_slice(), "s ap traffic", h_sf.as_slice())?
            .to_digest();
        self.c_ap_traffic = Some(c_ap);
        self.s_ap_traffic = Some(s_ap);
        self.exporter_master = Some(
            hkdf.derive_secret(master.as_slice(), "exp master", h_sf.as_slice())?
                .to_digest(),
        );

        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::KeysReady {
                epoch: Epoch::Application,
                read_secret: s_ap,
                write_secret: c_ap,
            },
        )?;

        if self.early_data_accepted {
            const END_OF_EARLY_DATA: [u8; 4] = [HandshakeType::EndOfEarlyData as u8, 0, 0, 0];
            self.transcript.update(&END_OF_EARLY_DATA);
            EventContext::emit(
                events,
                self.negotiated_suite,
                Event::Send {
                    epoch: Epoch::EarlyData,
                    data: &END_OF_EARLY_DATA,
                },
            )?;
        }

        self.flight.clear();
        if self.cert_request.is_some() {
            self.append_client_auth_flight(alg)?;
        }

        let h_pre_cf = self.transcript.hash(alg);
        let cf_data =
            Finished::verify_data(alg, secrets.client_traffic.as_slice(), h_pre_cf.as_slice())?;
        let cf_start = self.flight.len();
        Frame::encode_finished(cf_data.as_slice(), &mut self.flight)?;
        self.transcript.update(&self.flight[cf_start..]);
        let h_cf = self.transcript.hash(alg);
        let rms = hkdf
            .derive_secret(master.as_slice(), "res master", h_cf.as_slice())?
            .to_digest();
        self.resumption_master = Some(rms);

        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::Send {
                epoch: Epoch::Handshake,
                data: &self.flight,
            },
        )?;
        EventContext::emit(events, self.negotiated_suite, Event::Done)?;

        self.state = State::Done;
        Ok(())
    }
}
