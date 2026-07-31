use super::resumption::Resumption as _;
use super::*;

pub(super) trait Hello {
    fn handle_client_hello<G, V, S>(
        &mut self,
        ch: ClientHelloRef<'_>,
        raw: &[u8],
        shard: &mut Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized;
    fn send_hello_retry_request<S: EventSink + ?Sized>(
        &mut self,
        ch_raw: &[u8],
        session_id_echo: &[u8],
        request_group: KexGroup,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
}
impl<C: Clock> Hello for Server<C> {
    fn handle_client_hello<G, V, S>(
        &mut self,
        ch: ClientHelloRef<'_>,
        raw: &[u8],
        shard: &mut Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized,
    {
        self.config.validate()?;
        shard.config.validate()?;
        let selected_suite = CipherSuite::SUPPORTED
            .iter()
            .copied()
            .find(|s| ch.cipher_suites.contains(s.wire_id()))
            .ok_or(Error::UnsupportedCipherSuite)?;
        self.negotiated_suite = Some(selected_suite);
        let hash_alg = selected_suite.hash_alg();
        if ch.legacy_compression_methods != [0] {
            return Err(Error::IllegalParameter.into());
        }
        if ch.legacy_session_id.len() > 32 {
            return Err(Error::Decode.into());
        }
        let sv = ch
            .extensions
            .find(ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::MissingExtension)?;
        if !SupportedVersions::decode_client(sv.data)?.contains(TLS_1_3) {
            return Err(Error::BadVersion.into());
        }
        let groups = ch
            .extensions
            .find(ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::MissingExtension)?;
        let supported_groups = SupportedGroups::decode(groups.data)?;
        let mut hrr_group = None;
        for group in KexGroup::SUPPORTED {
            if supported_groups.contains(group.wire_id()) {
                hrr_group = Some(group);
                break;
            }
        }
        let hrr_group = hrr_group.ok_or(Error::UnsupportedGroup)?;
        let sigs = ch
            .extensions
            .find(ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::MissingExtension)?;
        let local_sig_scheme = shard.config.source.signing_key().sig_scheme();
        if !SignatureAlgorithms::contains(sigs.data, local_sig_scheme)? {
            return Err(Error::UnsupportedSigScheme.into());
        }
        let chosen_share = ch
            .extensions
            .find(ExtensionType::KEY_SHARE)
            .map(|ks| {
                KeyShares::decode_client(ks.data)
                    .map(|shares| shares.select_client_entry(&KexGroup::SUPPORTED))
            })
            .transpose()?
            .flatten();
        let (kex_group, peer_pubkey) = match chosen_share {
            Some(v) => v,
            None if !self.hrr_done => {
                return self.send_hello_retry_request(raw, ch.legacy_session_id, hrr_group, events);
            }
            None => return Err(Error::MissingExtension.into()),
        };

        let offers = ClientHelloOffers::parse(ch.extensions)?;
        self.selected_alpn = offers.select_alpn(&shard.config.alpn_protocols)?;
        if let Some(parameters) = offers.peer_quic_transport_parameters() {
            EventContext::emit(
                events,
                self.negotiated_suite,
                Event::PeerExtension {
                    ty: ExtensionType::QUIC_TRANSPORT_PARAMETERS.0,
                    data: parameters,
                },
            )?;
        }

        let psk_accepted = if hash_alg == RESUMPTION_HASH {
            self.try_accept_psk(&ch, raw, shard.config.ticket_keys.as_ref())
        } else {
            None
        };
        let now_ms = self.now_ms();
        let early_accepted = self.early_data.admit(
            &mut shard.guard,
            offers.early_data(),
            psk_accepted.as_ref(),
            self.selected_alpn.as_deref(),
            self.negotiated_suite,
            now_ms,
        );

        self.transcript.update(raw);

        if let (Some(p), true) = (psk_accepted.as_ref(), early_accepted) {
            let h_ch = self.transcript.hash(RESUMPTION_HASH);
            let cets =
                KeySchedule::client_early_traffic_secret(&p.psk, h_ch.as_slice())?.to_digest();
            EventContext::emit(
                events,
                self.negotiated_suite,
                Event::ZeroRttKeysReady { secret: cets },
            )?;
        }

        let (server_share, dhe) = kex_group
            .respond(peer_pubkey, &self.rng)
            .map_err(|_| Error::Kx)?;
        let mut server_random = [0u8; RANDOM_LEN];
        self.rng.fill(&mut server_random).map_err(|_| Error::Rng)?;

        self.flight.clear();
        self.flight.put_u8(HandshakeType::ServerHello as u8);
        self.flight.put_vec_u24(|hello| {
            hello.put_u16(TLS_1_2);
            hello.put_slice(&server_random);
            hello.put_vec_u8(|session| {
                session.put_slice(ch.legacy_session_id);
                Ok(())
            })?;
            hello.put_u16(selected_suite.wire_id());
            hello.put_u8(0);
            hello.put_vec_u16(|extensions| {
                Extension::encode_with(extensions, ExtensionType::SUPPORTED_VERSIONS, |version| {
                    version.put_u16(TLS_1_3);
                    Ok(())
                })?;
                Extension::encode_with(extensions, ExtensionType::KEY_SHARE, |share| {
                    share.put_u16(kex_group.wire_id());
                    share.put_vec_u16(|key| {
                        key.put_slice(&server_share);
                        Ok(())
                    })
                })?;
                if psk_accepted.is_some() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::PRE_SHARED_KEY,
                        |identity| {
                            identity.put_u16(0);
                            Ok(())
                        },
                    )?;
                }
                Ok(())
            })
        })?;
        self.transcript.update(&self.flight);

        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::Send {
                epoch: Epoch::Plaintext,
                data: &self.flight,
            },
        )?;

        let ks_handshake = match &psk_accepted {
            Some(p) => {
                KeySchedule::new_psk(RESUMPTION_HASH, &p.psk).into_handshake(dhe.as_slice())?
            }
            None => KeySchedule::new(hash_alg).into_handshake(dhe.as_slice())?,
        };
        let h_chsh = self.transcript.hash(hash_alg);
        let c_hs = ks_handshake
            .client_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();
        let s_hs = ks_handshake
            .server_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();

        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::KeysReady {
                epoch: Epoch::Handshake,
                read_secret: c_hs,
                write_secret: s_hs,
            },
        )?;

        let certificate_negotiation = offers.certificate_negotiation(&shard.config.source)?;
        self.negotiated_client_cert_type = certificate_negotiation.client_type;
        self.flight.clear();
        let ee_start = self.flight.len();
        self.flight.put_u8(HandshakeType::EncryptedExtensions as u8);
        self.flight.put_vec_u24(|encrypted_extensions| {
            encrypted_extensions.put_vec_u16(|extensions| {
                if offers.offered_server_certificate_type() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::SERVER_CERTIFICATE_TYPE,
                        |cert_type| {
                            cert_type.put_u8(certificate_negotiation.server_type);
                            Ok(())
                        },
                    )?;
                }
                if offers.offered_client_certificate_type() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::CLIENT_CERTIFICATE_TYPE,
                        |cert_type| {
                            cert_type.put_u8(certificate_negotiation.client_type);
                            Ok(())
                        },
                    )?;
                }
                if offers.offered_quic_transport_parameters() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                        |parameters| {
                            parameters.put_slice(&self.config.transport_params);
                            Ok(())
                        },
                    )?;
                }
                if let Some(protocol) = self.selected_alpn.as_deref() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                        |protocols| {
                            protocols.put_vec_u16(|list| {
                                list.put_vec_u8(|encoded| {
                                    encoded.put_slice(protocol);
                                    Ok(())
                                })
                            })
                        },
                    )?;
                }
                if early_accepted {
                    Extension::encode_with(extensions, ExtensionType::EARLY_DATA, |_| Ok(()))?;
                }
                Ok(())
            })
        })?;
        self.transcript.update(&self.flight[ee_start..]);

        if psk_accepted.is_none() && shard.client_auth.is_some() {
            let cr_start = self.flight.len();
            self.flight.put_u8(HandshakeType::CertificateRequest as u8);
            self.flight.put_vec_u24(|request| {
                request.put_vec_u8(|_| Ok(()))?;
                request.put_vec_u16(|extensions| {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::SIGNATURE_ALGORITHMS,
                        |algorithms| {
                            algorithms.put_vec_u16(|encoded| {
                                for algorithm in SignatureAlgorithms::x509().as_slice() {
                                    encoded.put_u16(*algorithm);
                                }
                                Ok(())
                            })
                        },
                    )
                })
            })?;
            self.transcript.update(&self.flight[cr_start..]);
        }

        if psk_accepted.is_none() {
            let raw_public_key = match &shard.config.source {
                CertSource::RawPublicKey { signing_key } => Some(
                    SubjectPublicKey::encoded_ed25519(signing_key.pubkey().ok_or(Error::Sig)?),
                ),
                CertSource::X509 { .. } => None,
            };
            let cert_start = self.flight.len();
            self.flight.put_u8(HandshakeType::Certificate as u8);
            self.flight.put_vec_u24(|certificate| {
                certificate.put_vec_u8(|_| Ok(()))?;
                certificate.put_vec_u24(|entries| match (&shard.config.source, raw_public_key) {
                    (CertSource::RawPublicKey { .. }, Some(public_key)) => {
                        entries.put_vec_u24(|data| {
                            data.put_slice(&public_key);
                            Ok(())
                        })?;
                        entries.put_vec_u16(|_| Ok(()))
                    }
                    (CertSource::X509 { chain_der, .. }, _) => {
                        for der in chain_der {
                            entries.put_vec_u24(|data| {
                                data.put_slice(der);
                                Ok(())
                            })?;
                            entries.put_vec_u16(|_| Ok(()))?;
                        }
                        Ok(())
                    }
                    (CertSource::RawPublicKey { .. }, None) => Err(EncodeError::Overflow),
                })
            })?;
            self.transcript.update(&self.flight[cert_start..]);

            let h_pre_cv = self.transcript.hash(hash_alg);
            let cv_msg = CertificateVerify::message(h_pre_cv.as_slice(), true)?;
            let sig = shard
                .config
                .source
                .signing_key()
                .sign_fixed(&cv_msg)
                .map_err(|_| Error::Sig)?;
            let cv_start = self.flight.len();
            Frame::encode_certificate_verify(
                shard.config.source.signing_key().sig_scheme(),
                &sig,
                &mut self.flight,
            )?;
            self.transcript.update(&self.flight[cv_start..]);
        }

        let h_pre_sf = self.transcript.hash(hash_alg);
        let sf_data = Finished::verify_data(hash_alg, s_hs.as_slice(), h_pre_sf.as_slice())?;
        let sf_start = self.flight.len();
        Frame::encode_finished(sf_data.as_slice(), &mut self.flight)?;
        self.transcript.update(&self.flight[sf_start..]);
        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::Send {
                epoch: Epoch::Handshake,
                data: &self.flight,
            },
        )?;

        let h_sf = self.transcript.hash(hash_alg);
        let ks_master = ks_handshake.into_master()?;
        let c_ap = ks_master
            .client_application_traffic_secret(h_sf.as_slice())?
            .to_digest();
        let s_ap = ks_master
            .server_application_traffic_secret(h_sf.as_slice())?
            .to_digest();
        self.c_ap_traffic = Some(c_ap);
        self.s_ap_traffic = Some(s_ap);
        self.exporter_master = Some(
            ks_master
                .exporter_master_secret(h_sf.as_slice())?
                .to_digest(),
        );
        self.master = Some(ks_master);

        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::KeysReady {
                epoch: Epoch::Application,
                read_secret: c_ap,
                write_secret: s_ap,
            },
        )?;

        if early_accepted {
            self.state = State::ExpectEndOfEarlyData {
                client_handshake_traffic: c_hs,
            };
        } else if psk_accepted.is_none() && shard.client_auth.is_some() {
            self.state = State::ExpectClientCertificate {
                client_handshake_traffic: c_hs,
            };
        } else {
            let verify_data = Finished::verify_data(hash_alg, c_hs.as_slice(), h_sf.as_slice())?;
            self.state = State::ExpectClientFinished { verify_data };
        }
        Ok(())
    }

    /// RFC 8446 §4.1.4: ask for a retry (one only) when the ClientHello carried
    /// no usable key_share, rewriting the transcript to `message_hash(CH1)`.
    fn send_hello_retry_request<S: EventSink + ?Sized>(
        &mut self,
        ch_raw: &[u8],
        session_id_echo: &[u8],
        request_group: KexGroup,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        let suite = self.negotiated_suite.ok_or(Error::UnsupportedCipherSuite)?;
        self.flight.clear();
        self.flight.put_u8(HandshakeType::ServerHello as u8);
        self.flight.put_vec_u24(|hello| {
            hello.put_u16(TLS_1_2);
            hello.put_slice(&HELLO_RETRY_REQUEST_RANDOM);
            hello.put_vec_u8(|session| {
                session.put_slice(session_id_echo);
                Ok(())
            })?;
            hello.put_u16(suite.wire_id());
            hello.put_u8(0);
            hello.put_vec_u16(|extensions| {
                Extension::encode_with(extensions, ExtensionType::SUPPORTED_VERSIONS, |version| {
                    version.put_u16(TLS_1_3);
                    Ok(())
                })?;
                Extension::encode_with(extensions, ExtensionType::KEY_SHARE, |group| {
                    group.put_u16(request_group.wire_id());
                    Ok(())
                })
            })
        })?;

        let mut t = Transcript::new();
        t.update(ch_raw);
        self.transcript = Transcript::restart_with_message_hash(&t.hash(self.hash_alg()));
        self.transcript.update(&self.flight);

        self.hrr_done = true;
        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::Send {
                epoch: Epoch::Plaintext,
                data: &self.flight,
            },
        )?;
        Ok(())
    }
}
