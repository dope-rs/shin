use alloc::vec::Vec;

use super::*;
use crate::crypto::kx::MAX_CLIENT_SHARE_LEN;
use crate::wire::codec::EncodedSize;

#[derive(Clone, Copy)]
pub(super) struct ClientHelloConfig<'a> {
    verifier: &'a Verifier,
    transport_params: &'a [u8],
    alpn_protocols: &'a [Vec<u8>],
}

#[derive(Clone, Copy)]
struct ClientHelloFields<'a> {
    suites: &'a [CipherSuite],
    group: KexGroup,
    random: &'a [u8; RANDOM_LEN],
    session_id: &'a [u8; 32],
    kx_pubkey: &'a [u8],
    cookie: Option<&'a [u8]>,
    resumption: Option<&'a Resumption>,
    offer_early_data: bool,
    client_cert_type_offer: Option<u8>,
}

impl ClientHelloConfig<'_> {
    fn encode(
        self,
        out: &mut impl Encode,
        fields: ClientHelloFields<'_>,
    ) -> Result<(), EncodeError> {
        let server_cert_type = match self.verifier {
            Verifier::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            Verifier::X509 { .. } => CERT_TYPE_X509,
        };
        let hostname = match self.verifier {
            Verifier::X509 { hostname, .. } if !Hostname::new(hostname).is_ip_literal() => {
                Some(hostname.as_slice())
            }
            Verifier::RawPublicKey { .. } | Verifier::X509 { .. } => None,
        };
        let signature_algorithms = match self.verifier {
            Verifier::RawPublicKey { .. } => SignatureAlgorithms::rpk().as_slice(),
            Verifier::X509 { .. } => SignatureAlgorithms::x509().as_slice(),
        };

        out.put_u8(HandshakeType::ClientHello as u8);
        out.put_vec_u24(|hello| {
            hello.put_u16(TLS_1_2);
            hello.put_slice(fields.random);
            hello.put_vec_u8(|session| {
                session.put_slice(fields.session_id);
                Ok(())
            })?;
            hello.put_vec_u16(|encoded_suites| {
                for suite in fields.suites {
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
                        entries.put_u16(fields.group.wire_id());
                        entries.put_vec_u16(|key| {
                            key.put_slice(fields.kx_pubkey);
                            Ok(())
                        })
                    })
                })?;
                if matches!(self.verifier, Verifier::RawPublicKey { .. }) {
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
                if let Some(cert_type) = fields.client_cert_type_offer {
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
                if !self.transport_params.is_empty() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                        |parameters| {
                            parameters.put_slice(self.transport_params);
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
                if !self.alpn_protocols.is_empty() {
                    Extension::encode_with(
                        extensions,
                        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                        |protocols| {
                            protocols.put_vec_u16(|list| {
                                for protocol in self.alpn_protocols {
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
                if let Some(cookie) = fields.cookie {
                    Extension::encode_with(extensions, ExtensionType::COOKIE, |encoded| {
                        encoded.put_slice(cookie);
                        Ok(())
                    })?;
                }
                if fields.offer_early_data {
                    Extension::encode_with(extensions, ExtensionType::EARLY_DATA, |_| Ok(()))?;
                }
                if let Some(resumption) = fields.resumption {
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
        })
    }

    pub(super) fn maximum_initial_len(
        verifier: &Verifier,
        transport_params: &[u8],
        alpn_protocols: &[Vec<u8>],
        resumption: Option<&Resumption>,
    ) -> Result<usize, EncodeError> {
        const MAX_CLIENT_SHARE: [u8; MAX_CLIENT_SHARE_LEN] = [0; MAX_CLIENT_SHARE_LEN];
        const RANDOM: [u8; RANDOM_LEN] = [0; RANDOM_LEN];
        const SESSION_ID: [u8; 32] = [0; 32];

        let mut size = EncodedSize::default();
        ClientHelloConfig {
            verifier,
            transport_params,
            alpn_protocols,
        }
        .encode(
            &mut size,
            ClientHelloFields {
                suites: &CipherSuite::SUPPORTED,
                group: KexGroup::X25519,
                random: &RANDOM,
                session_id: &SESSION_ID,
                kx_pubkey: &MAX_CLIENT_SHARE,
                cookie: None,
                resumption,
                offer_early_data: true,
                client_cert_type_offer: Some(CERT_TYPE_X509),
            },
        )?;
        size.finish()
    }
}

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
        let client_cert_type_offer = match &self.client_cert {
            Some(source) => Some(source.cert_type()),
            None if matches!(self.config.verifier(), Verifier::RawPublicKey { .. }) => {
                Some(CERT_TYPE_RAW_PUBLIC_KEY)
            }
            None => None,
        };
        let sends_server_name = matches!(
            self.config.verifier(),
            Verifier::X509 { hostname, .. } if !Hostname::new(hostname).is_ip_literal()
        );

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
        if sends_server_name {
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

        let flight = &mut self.flight;
        flight.clear();
        ClientHelloConfig {
            verifier: self.config.verifier(),
            transport_params: self.config.transport_params(),
            alpn_protocols: self.config.alpn_protocols(),
        }
        .encode(
            flight,
            ClientHelloFields {
                suites: &self.offered_suites,
                group: self.kex_group,
                random: &self.client_random,
                session_id: &self.session_id,
                kx_pubkey,
                cookie,
                resumption,
                offer_early_data,
                client_cert_type_offer,
            },
        )?;
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
