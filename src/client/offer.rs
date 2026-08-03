use super::*;

pub(super) trait ClientOffer {
    fn encode_client_hello(
        &mut self,
        kx_pubkey: &[u8],
        cookie: Option<&[u8]>,
        resumption: Option<&Resumption>,
        offer_early_data: bool,
    ) -> Result<(), Error>;
    fn splice_psk_binder(
        transcript: &Transcript,
        ch_bytes: &mut [u8],
        psk: &[u8; 32],
    ) -> Result<(), Error>;
}
impl<C: Clock> ClientOffer for Client<C> {
    fn encode_client_hello(
        &mut self,
        kx_pubkey: &[u8],
        cookie: Option<&[u8]>,
        resumption: Option<&Resumption>,
        offer_early_data: bool,
    ) -> Result<(), Error> {
        let server_cert_type = match self.config.verifier() {
            Verifier::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            Verifier::X509 { .. } => CERT_TYPE_X509,
        };
        let client_cert_type_offer = match &self.client_cert {
            Some(source) => Some(source.cert_type()),
            None if matches!(self.config.verifier(), Verifier::RawPublicKey { .. }) => {
                Some(CERT_TYPE_RAW_PUBLIC_KEY)
            }
            None => None,
        };
        let hostname = match self.config.verifier() {
            Verifier::X509 { hostname, .. } if !Hostname::new(hostname).is_ip_literal() => {
                Some(hostname.as_slice())
            }
            Verifier::RawPublicKey { .. } | Verifier::X509 { .. } => None,
        };
        let signature_algorithms = match self.config.verifier() {
            Verifier::RawPublicKey { .. } => SignatureAlgorithms::rpk().as_slice(),
            Verifier::X509 { .. } => SignatureAlgorithms::x509().as_slice(),
        };

        self.ee_offered.clear();
        self.ee_offered
            .try_push(ExtensionType::SUPPORTED_GROUPS)
            .map_err(|_| Error::Encode)?;
        if matches!(self.config.verifier(), Verifier::RawPublicKey { .. }) {
            self.ee_offered
                .try_push(ExtensionType::SERVER_CERTIFICATE_TYPE)
                .map_err(|_| Error::Encode)?;
        }
        if client_cert_type_offer.is_some() {
            self.ee_offered
                .try_push(ExtensionType::CLIENT_CERTIFICATE_TYPE)
                .map_err(|_| Error::Encode)?;
        }
        if !self.config.transport_params().is_empty() {
            self.ee_offered
                .try_push(ExtensionType::QUIC_TRANSPORT_PARAMETERS)
                .map_err(|_| Error::Encode)?;
        }
        if hostname.is_some() {
            self.ee_offered
                .try_push(ExtensionType::SERVER_NAME)
                .map_err(|_| Error::Encode)?;
        }
        if !self.config.alpn_protocols().is_empty() {
            self.ee_offered
                .try_push(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
                .map_err(|_| Error::Encode)?;
        }
        if offer_early_data {
            self.ee_offered
                .try_push(ExtensionType::EARLY_DATA)
                .map_err(|_| Error::Encode)?;
        }

        let config = &self.config;
        let suites = &self.offered_suites;
        let group = self.kex_group;
        let random = self.client_random;
        let session_id = self.session_id;
        let flight = &mut self.flight;
        flight.clear();
        flight.put_u8(HandshakeType::ClientHello as u8);
        flight.put_vec_u24(|hello| {
            hello.put_u16(TLS_1_2);
            hello.put_slice(&random);
            hello.put_vec_u8(|session| {
                session.put_slice(&session_id);
                Ok(())
            })?;
            hello.put_vec_u16(|encoded_suites| {
                for suite in suites {
                    encoded_suites.put_u16(suite.wire_id());
                }
                Ok(())
            })?;
            hello.put_vec_u8(|compression| {
                compression.put_u8(0);
                Ok(())
            })?;
            hello.put_vec_u16(|extensions| {
                Extension::encode_with(extensions, ExtensionType::SUPPORTED_VERSIONS, |version| {
                    version.put_vec_u8(|versions| {
                        versions.put_u16(TLS_1_3);
                        Ok(())
                    })
                })?;
                Extension::encode_with(extensions, ExtensionType::SUPPORTED_GROUPS, |groups| {
                    groups.put_vec_u16(|encoded_groups| {
                        for supported in KexGroup::SUPPORTED {
                            encoded_groups.put_u16(supported.wire_id());
                        }
                        Ok(())
                    })
                })?;
                Extension::encode_with(
                    extensions,
                    ExtensionType::SIGNATURE_ALGORITHMS,
                    |algorithms| {
                        algorithms.put_vec_u16(|encoded_algorithms| {
                            for algorithm in signature_algorithms {
                                encoded_algorithms.put_u16(*algorithm);
                            }
                            Ok(())
                        })
                    },
                )?;
                Extension::encode_with(extensions, ExtensionType::KEY_SHARE, |shares| {
                    shares.put_vec_u16(|entries| {
                        entries.put_u16(group.wire_id());
                        entries.put_vec_u16(|key| {
                            key.put_slice(kx_pubkey);
                            Ok(())
                        })
                    })
                })?;
                if matches!(config.verifier(), Verifier::RawPublicKey { .. }) {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::SERVER_CERTIFICATE_TYPE,
                        |types| {
                            types.put_vec_u8(|list| {
                                list.put_u8(server_cert_type);
                                Ok(())
                            })
                        },
                    )?;
                }
                if let Some(cert_type) = client_cert_type_offer {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::CLIENT_CERTIFICATE_TYPE,
                        |types| {
                            types.put_vec_u8(|list| {
                                list.put_u8(cert_type);
                                Ok(())
                            })
                        },
                    )?;
                }
                if !config.transport_params().is_empty() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                        |parameters| {
                            parameters.put_slice(config.transport_params());
                            Ok(())
                        },
                    )?;
                }
                if let Some(hostname) = hostname {
                    Extension::encode_with(extensions, ExtensionType::SERVER_NAME, |names| {
                        names.put_vec_u16(|list| {
                            list.put_u8(0);
                            list.put_vec_u16(|name| {
                                name.put_slice(hostname);
                                Ok(())
                            })
                        })
                    })?;
                }
                if !config.alpn_protocols().is_empty() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                        |protocols| {
                            protocols.put_vec_u16(|list| {
                                for protocol in config.alpn_protocols() {
                                    list.put_vec_u8(|encoded| {
                                        encoded.put_slice(protocol);
                                        Ok(())
                                    })?;
                                }
                                Ok(())
                            })
                        },
                    )?;
                }
                if let Some(cookie) = cookie {
                    Extension::encode_with(extensions, ExtensionType::COOKIE, |encoded| {
                        encoded.put_slice(cookie);
                        Ok(())
                    })?;
                }
                if offer_early_data {
                    Extension::encode_with(extensions, ExtensionType::EARLY_DATA, |_| Ok(()))?;
                }
                if let Some(resumption) = resumption {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::PSK_KEY_EXCHANGE_MODES,
                        |modes| {
                            modes.put_vec_u8(|list| {
                                list.put_u8(KX_MODE_PSK_DHE);
                                Ok(())
                            })
                        },
                    )?;
                    Extension::encode_with(extensions, ExtensionType::PRE_SHARED_KEY, |offer| {
                        offer.put_vec_u16(|identities| {
                            identities.put_vec_u16(|identity| {
                                identity.put_slice(&resumption.ticket);
                                Ok(())
                            })?;
                            identities.put_u32(
                                resumption
                                    .age_millis
                                    .wrapping_add(resumption.ticket_age_add),
                            );
                            Ok(())
                        })?;
                        offer.put_vec_u16(|binders| {
                            binders.put_vec_u8(|binder| {
                                binder.put_slice(&[0; 32]);
                                Ok(())
                            })
                        })
                    })?;
                }
                Ok(())
            })
        })?;
        Ok(())
    }

    /// Splice a resumption binder over `Truncate(ClientHello)`, prefixed by
    /// `message_hash(CH1) ‖ HRR` after a retry (RFC 8446 §4.2.11.2).
    fn splice_psk_binder(
        transcript: &Transcript,
        ch_bytes: &mut [u8],
        psk: &[u8; 32],
    ) -> Result<(), Error> {
        let prefix_len = Offer::binder_transcript_prefix(ch_bytes, psk.len())
            .ok_or(Error::Encode)?
            .len();
        let mut t = transcript.fork();
        t.update(&ch_bytes[..prefix_len]);
        let partial_hash = t.hash(RESUMPTION_HASH);
        let binder = ResumptionBinder::compute(psk, partial_hash.as_slice())?;
        let binder_start = ch_bytes.len() - psk.len();
        ch_bytes[binder_start..].copy_from_slice(binder.as_slice());
        Ok(())
    }
}
