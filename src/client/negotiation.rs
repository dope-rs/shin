use super::offer::ClientOffer as _;
use super::*;

pub(super) trait Negotiation {
    fn handle_server_hello<S: EventSink + ?Sized>(
        &mut self,
        sh: ServerHelloRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
    fn handle_hello_retry_request<S: EventSink + ?Sized>(
        &mut self,
        hrr: ServerHelloRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
    fn handle_encrypted_extensions<S: EventSink + ?Sized>(
        &mut self,
        ee: EncryptedExtensionsRef<'_>,
        raw: &[u8],
        secrets: HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
}
impl<C: Clock> Negotiation for Client<C> {
    fn handle_server_hello<S: EventSink + ?Sized>(
        &mut self,
        sh: ServerHelloRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        let suite = CipherSuite::from_u16(sh.cipher_suite).ok_or(Error::UnsupportedCipherSuite)?;
        if !self.offered_suites.contains(&suite) {
            return Err(Error::IllegalParameter.into());
        }
        if let Some(prev) = self.negotiated_suite
            && prev != suite
        {
            return Err(Error::IllegalParameter.into());
        }
        self.negotiated_suite = Some(suite);
        if sh.random == HELLO_RETRY_REQUEST_RANDOM {
            return self.handle_hello_retry_request(sh, raw, events);
        }
        const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
        const DOWNGRADE_TLS11: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];
        let tail = &sh.random[RANDOM_LEN - 8..];
        if tail == DOWNGRADE_TLS12 || tail == DOWNGRADE_TLS11 {
            return Err(Error::DowngradeDetected.into());
        }
        if sh.legacy_version != TLS_1_2 {
            return Err(Error::IllegalParameter.into());
        }
        if sh.legacy_compression_method != 0 {
            return Err(Error::IllegalParameter.into());
        }
        if sh.legacy_session_id_echo != self.session_id {
            return Err(Error::IllegalParameter.into());
        }
        let sv_data = sh
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::MissingExtension)?
            .data;
        if SupportedVersions::decode_server(sv_data)? != TLS_1_3 {
            return Err(Error::BadVersion.into());
        }
        let ks_data = sh
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::KEY_SHARE)
            .ok_or(Error::MissingExtension)?
            .data;
        let (server_group, server_pubkey) = KeyShares::decode_server(ks_data)?;

        for ext in sh.extensions.iter() {
            if !matches!(
                ext.ty,
                ExtensionType::SUPPORTED_VERSIONS
                    | ExtensionType::KEY_SHARE
                    | ExtensionType::PRE_SHARED_KEY
            ) {
                return Err(Error::UnsolicitedExtension.into());
            }
        }

        let psk_ext = sh
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY);
        if let Some(ext) = psk_ext {
            if self.active_resumption.is_none() {
                return Err(Error::UnexpectedMessage.into());
            }
            let selected =
                SelectedIdentity::decode(ext.data).map_err(|_| Error::IllegalParameter)?;
            if selected.get() != 0 {
                return Err(Error::IllegalParameter.into());
            }
        }
        self.psk_used = psk_ext.is_some();

        self.transcript.update(raw);

        let eph = self.eph.take().ok_or(Error::UnexpectedMessage)?;
        if eph.group().wire_id() != server_group {
            return Err(Error::IllegalParameter.into());
        }
        let dhe = eph.agree(server_pubkey).map_err(|_| Error::Kx)?;

        let alg = self.hash_alg();
        let ks_handshake = if self.psk_used {
            let psk = self
                .active_resumption
                .as_ref()
                .ok_or(Error::UnexpectedMessage)?
                .psk;
            KeySchedule::new_psk(alg, &psk).into_handshake(dhe.as_slice())?
        } else {
            KeySchedule::new(alg).into_handshake(dhe.as_slice())?
        };
        let h_chsh = self.transcript.hash(alg);
        let c_hs = ks_handshake
            .client_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();
        let s_hs = ks_handshake
            .server_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();

        let secrets = HandshakeSecrets {
            handshake: ks_handshake.secret().to_digest(),
            client_traffic: c_hs,
            server_traffic: s_hs,
        };

        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::KeysReady {
                epoch: Epoch::Handshake,
                read_secret: s_hs,
                write_secret: c_hs,
            },
        )?;

        self.state = State::ExpectEncryptedExtensions { secrets };
        Ok(())
    }

    /// Resend ClientHello after one HRR, echoing its cookie and rebinding PSK to
    /// `message_hash(CH1) ‖ HRR ‖ Truncate(CH2)` (RFC 8446 §4.2.11.2).
    fn handle_hello_retry_request<S: EventSink + ?Sized>(
        &mut self,
        hrr: ServerHelloRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        if self.hrr_done {
            return Err(Error::UnexpectedMessage.into());
        }

        let mut saw_supported_versions = false;
        let mut selected_group = None;
        let mut cookie = None;
        for ext in hrr.extensions.iter() {
            match ext.ty {
                ExtensionType::SUPPORTED_VERSIONS => {
                    if SupportedVersions::decode_server(ext.data)? != TLS_1_3 {
                        return Err(Error::BadVersion.into());
                    }
                    saw_supported_versions = true;
                }
                ExtensionType::KEY_SHARE => {
                    selected_group = Some(KeyShares::decode_hrr(ext.data)?);
                }
                ExtensionType::COOKIE => cookie = Some(ext.data),
                _ => return Err(Error::UnsolicitedExtension.into()),
            }
        }
        if !saw_supported_versions {
            return Err(Error::MissingExtension.into());
        }
        let selected = selected_group.ok_or(Error::MissingExtension)?;
        let group = KexGroup::from_u16(selected)
            .filter(|g| KexGroup::SUPPORTED.contains(g))
            .ok_or(Error::UnsupportedGroup)?;

        let h1 = self.transcript.hash(self.hash_alg());
        self.transcript = Transcript::restart_with_message_hash(&h1);
        self.transcript.update(raw);

        if self.eph.as_ref().map(|e| e.group()) != Some(group) {
            self.eph = Some(EphemeralKey::generate(group, &self.rng).map_err(|_| Error::Kx)?);
            self.kex_group = group;
        }
        let eph_share = self
            .eph
            .as_ref()
            .ok_or(Error::UnexpectedMessage)?
            .copied_client_share();
        let resumption = self.active_resumption.take();
        let encode_result =
            self.encode_client_hello(&eph_share, cookie, resumption.as_ref(), false);
        self.active_resumption = resumption;
        encode_result?;

        if let Some(r) = &self.active_resumption {
            Self::splice_psk_binder(&self.transcript, self.flight.as_mut_slice(), &r.psk)?;
        }

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

    fn handle_encrypted_extensions<S: EventSink + ?Sized>(
        &mut self,
        ee: EncryptedExtensionsRef<'_>,
        raw: &[u8],
        secrets: HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        for ext in ee.extensions.iter() {
            if !self.ee_offered.contains(&ext.ty) {
                return Err(Error::UnsolicitedExtension.into());
            }

            if ext.ty == ExtensionType::QUIC_TRANSPORT_PARAMETERS {
                EventContext::emit(
                    events,
                    self.negotiated_suite,
                    Event::PeerExtension {
                        ty: ext.ty.0,
                        data: ext.data,
                    },
                )?;
            } else if ext.ty == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION {
                let chosen = Alpn::decode(ext.data).map_err(|_| Error::Decode)?;
                if chosen.len() != 1 {
                    return Err(Error::IllegalParameter.into());
                }
                let pick = chosen.iter().next().ok_or(Error::IllegalParameter)?;
                if !self.config.alpn_protocols.iter().any(|p| p == pick) {
                    return Err(Error::IllegalParameter.into());
                }
                self.selected_alpn =
                    Some(ArrayVec::try_from(pick).map_err(|_| Error::IllegalParameter)?);
            } else if ext.ty == ExtensionType::EARLY_DATA {
                if !self.early_data_offered || !ext.data.is_empty() {
                    return Err(Error::UnsolicitedExtension.into());
                }
                self.early_data_accepted = true;
            }
        }
        if self.early_data_offered {
            EventContext::emit(
                events,
                self.negotiated_suite,
                if self.early_data_accepted {
                    Event::EarlyDataAccepted
                } else {
                    Event::EarlyDataRejected
                },
            )?;
        }
        self.transcript.update(raw);
        self.state = if self.psk_used {
            State::ExpectServerFinished { secrets }
        } else {
            State::ExpectCertificate { secrets }
        };
        Ok(())
    }
}
