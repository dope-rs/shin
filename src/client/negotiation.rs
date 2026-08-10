use crate::client;
use crate::client::offer::Offer as _;
use crate::client::state;
use crate::connection;
use crate::crypto::kx;
use crate::wire::extension;
use crate::wire::handshake::views;
use crate::wire::protocols;

pub(super) trait Negotiation {
    fn handle_server_hello<S: connection::EventSink + ?Sized>(
        &mut self,
        sh: views::ServerHelloRef<'_>,
        raw: &[u8],
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
    fn handle_hello_retry_request<S: connection::EventSink + ?Sized>(
        &mut self,
        hrr: views::ServerHelloRef<'_>,
        raw: &[u8],
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
    fn finish_hello_retry_request<S: connection::EventSink + ?Sized>(
        &mut self,
        group: kx::KexGroup,
        cookie: Option<&[u8]>,
        eph: kx::EphemeralKey,
        in_place_share: Option<&[u8]>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
    fn handle_encrypted_extensions<S: connection::EventSink + ?Sized>(
        &mut self,
        ee: views::EncryptedExtensionsRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}
impl<C: connection::Clock> Negotiation for client::Client<C> {
    fn handle_server_hello<S: connection::EventSink + ?Sized>(
        &mut self,
        sh: views::ServerHelloRef<'_>,
        raw: &[u8],
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::crypto::schedule::Schedule;
        use crate::wire::handshake::HELLO_RETRY_REQUEST_RANDOM;
        use crate::wire::handshake::RANDOM_LEN;
        use crate::wire::handshake::TLS_1_2;
        use crate::wire::record::CipherSuite;
        if sh.legacy_version != TLS_1_2 {
            return Err(connection::Error::IllegalParameter.into());
        }
        if sh.legacy_compression_method != 0 {
            return Err(connection::Error::IllegalParameter.into());
        }
        let expected_session_id = if self
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
        if sh.legacy_session_id_echo != expected_session_id {
            return Err(connection::Error::IllegalParameter.into());
        }
        let suite = CipherSuite::from_u16(sh.cipher_suite)
            .ok_or(connection::Error::UnsupportedCipherSuite)?;
        if !self.session.offer.offered_suites.contains(&suite) {
            return Err(connection::Error::IllegalParameter.into());
        }
        let alg = suite.hash_alg();
        self.session
            .handshake
            .transcript
            .select(alg)
            .map_err(connection::Error::from)?;
        self.session.application.traffic.select(suite)?;
        if sh.random == HELLO_RETRY_REQUEST_RANDOM {
            return self.handle_hello_retry_request(sh, raw, hybrid_workspace, events);
        }
        const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
        const DOWNGRADE_TLS11: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];
        let tail = &sh.random[RANDOM_LEN - 8..];
        if tail == DOWNGRADE_TLS12 || tail == DOWNGRADE_TLS11 {
            return Err(connection::Error::DowngradeDetected.into());
        }
        let sv_data = sh
            .extensions
            .iter()
            .find(|e| e.ty == extension::Type::SUPPORTED_VERSIONS)
            .ok_or(connection::Error::MissingExtension)?
            .data;
        if protocols::SupportedVersions::decode_server(sv_data)? != protocols::TLS_1_3 {
            return Err(connection::Error::BadVersion.into());
        }
        let ks_data = sh
            .extensions
            .iter()
            .find(|e| e.ty == extension::Type::KEY_SHARE)
            .ok_or(connection::Error::MissingExtension)?
            .data;
        let (server_group, server_pubkey) = protocols::KeyShares::decode_server(ks_data)?;

        for ext in sh.extensions.iter() {
            if !matches!(
                ext.ty,
                extension::Type::SUPPORTED_VERSIONS
                    | extension::Type::KEY_SHARE
                    | extension::Type::PRE_SHARED_KEY
            ) {
                return Err(connection::Error::UnsolicitedExtension.into());
            }
        }

        let psk_ext = sh
            .extensions
            .iter()
            .find(|e| e.ty == extension::Type::PRE_SHARED_KEY);
        if let Some(ext) = psk_ext {
            use crate::wire::psk::SelectedIdentity;
            if self.session.handshake.active_resumption.is_none() {
                return Err(connection::Error::UnexpectedMessage.into());
            }
            let selected = SelectedIdentity::decode(ext.data)
                .map_err(|_| connection::Error::IllegalParameter)?;
            if selected.get() != 0 {
                return Err(connection::Error::IllegalParameter.into());
            }
        }
        self.session.handshake.psk_used = psk_ext.is_some();

        self.session.handshake.transcript.update(raw);

        let eph = self
            .session
            .handshake
            .eph
            .take()
            .ok_or(connection::Error::UnexpectedMessage)?;
        if eph.group().wire_id() != server_group {
            return Err(connection::Error::IllegalParameter.into());
        }
        let dhe = match hybrid_workspace {
            Some(workspace) => eph.agree_in(workspace.slot_mut(), server_pubkey),
            None => eph.agree(server_pubkey),
        }
        .map_err(|_| connection::Error::Kx)?;

        let ks_handshake = if self.session.handshake.psk_used {
            let psk = self
                .session
                .handshake
                .active_resumption
                .as_ref()
                .ok_or(connection::Error::UnexpectedMessage)?
                .psk
                .as_slice();
            Schedule::new_psk(alg, psk).into_handshake(dhe.as_slice())?
        } else {
            Schedule::new(alg).into_handshake(dhe.as_slice())?
        };
        let h_chsh = self
            .session
            .handshake
            .transcript
            .hash(alg)
            .map_err(connection::Error::from)?;
        let c_hs = ks_handshake.client_handshake_traffic_secret(h_chsh.as_slice())?;
        let s_hs = ks_handshake.server_handshake_traffic_secret(h_chsh.as_slice())?;

        let secrets = state::HandshakeSecrets {
            schedule: ks_handshake,
            client_traffic: c_hs,
            server_traffic: s_hs,
        };

        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::KeysReady {
                epoch: connection::Epoch::Handshake,
                read_secret: &secrets.server_traffic,
                write_secret: &secrets.client_traffic,
            },
        )?;

        self.session.handshake.state = state::State::expect_encrypted_extensions(secrets);
        Ok(())
    }

    /// Resend ClientHello after one HRR, echoing its cookie and rebinding PSK to
    /// `message_hash(CH1) ‖ HRR ‖ Truncate(CH2)` (RFC 8446 §4.2.11.2).
    fn handle_hello_retry_request<S: connection::EventSink + ?Sized>(
        &mut self,
        hrr: views::ServerHelloRef<'_>,
        raw: &[u8],
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::crypto::hash::Transcript;
        use crate::crypto::kx::KexGroup;
        if self.session.handshake.hrr_done {
            return Err(connection::Error::UnexpectedMessage.into());
        }

        let mut saw_supported_versions = false;
        let mut selected_group = None;
        let mut cookie = None;
        for ext in hrr.extensions.iter() {
            match ext.ty {
                extension::Type::SUPPORTED_VERSIONS => {
                    if protocols::SupportedVersions::decode_server(ext.data)? != protocols::TLS_1_3
                    {
                        return Err(connection::Error::BadVersion.into());
                    }
                    saw_supported_versions = true;
                }
                extension::Type::KEY_SHARE => {
                    selected_group = Some(protocols::KeyShares::decode_hrr(ext.data)?);
                }
                extension::Type::COOKIE => cookie = Some(ext.data),
                _ => return Err(connection::Error::UnsolicitedExtension.into()),
            }
        }
        if !saw_supported_versions {
            return Err(connection::Error::MissingExtension.into());
        }
        let selected = selected_group.ok_or(connection::Error::MissingExtension)?;
        let group = KexGroup::from_u16(selected)
            .filter(|g| KexGroup::SUPPORTED.contains(g))
            .ok_or(connection::Error::UnsupportedGroup)?;
        if self.session.handshake.eph.as_ref().map(|eph| eph.group()) == Some(group) {
            return Err(connection::Error::IllegalParameter.into());
        }

        let alg = self.session.application.hash_alg()?;
        let h1 = self
            .session
            .handshake
            .transcript
            .hash(alg)
            .map_err(connection::Error::from)?;
        self.session.handshake.transcript =
            Transcript::restart_with_message_hash(alg, &h1).map_err(connection::Error::from)?;
        self.session.handshake.transcript.update(raw);

        match hybrid_workspace {
            Some(workspace) => {
                let (eph, share) = kx::EphemeralKey::generate_in(
                    group,
                    &self.session.runtime.rng,
                    workspace.slot_mut(),
                )
                .map_err(|_| connection::Error::Kx)?;
                self.finish_hello_retry_request(group, cookie, eph, Some(&share), events)
            }
            None => {
                let eph = kx::EphemeralKey::generate(group, &self.session.runtime.rng)
                    .map_err(|_| connection::Error::Kx)?;
                self.finish_hello_retry_request(group, cookie, eph, None, events)
            }
        }
    }

    fn finish_hello_retry_request<S: connection::EventSink + ?Sized>(
        &mut self,
        group: kx::KexGroup,
        cookie: Option<&[u8]>,
        eph: kx::EphemeralKey,
        in_place_share: Option<&[u8]>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.session.offer.kex_group = group;
        let resumption = self.session.handshake.active_resumption.take();
        let client_share = in_place_share.unwrap_or_else(|| eph.client_share());
        let encode_result =
            self.encode_client_hello(client_share, cookie, resumption.as_ref(), false);
        self.session.handshake.active_resumption = resumption;
        encode_result?;

        if let Some(r) = &self.session.handshake.active_resumption {
            Self::splice_psk_binder(
                &self.session.handshake.transcript,
                self.session.buffers.flight.as_mut_slice(),
                r.psk.as_array(),
            )?;
        }

        self.session
            .handshake
            .transcript
            .update(&self.session.buffers.flight);
        self.session.handshake.eph = Some(eph);
        self.session.handshake.hrr_done = true;
        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::Send {
                epoch: connection::Epoch::Plaintext,
                data: &self.session.buffers.flight,
            },
        )?;
        Ok(())
    }

    fn handle_encrypted_extensions<S: connection::EventSink + ?Sized>(
        &mut self,
        ee: views::EncryptedExtensionsRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::client::session::EarlyData;
        let mut saw_quic_transport_parameters = false;
        for ext in ee.extensions.iter() {
            if !self.session.extensions.ee_offered.contains(&ext.ty) {
                return Err(connection::Error::UnsolicitedExtension.into());
            }

            if ext.ty == extension::Type::QUIC_TRANSPORT_PARAMETERS {
                saw_quic_transport_parameters = true;
                connection::EventContext::emit(
                    events,
                    self.session.application.traffic.suite(),
                    connection::Event::PeerExtension {
                        ty: ext.ty.0,
                        data: ext.data,
                    },
                )?;
            } else if ext.ty == extension::Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION {
                use crate::wire::protocols::Alpn;
                use arrayvec::ArrayVec;
                let chosen = Alpn::decode(ext.data).map_err(|_| connection::Error::Decode)?;
                if chosen.len() != 1 {
                    return Err(connection::Error::IllegalParameter.into());
                }
                let pick = chosen
                    .iter()
                    .next()
                    .ok_or(connection::Error::IllegalParameter)?;
                if !self
                    .session
                    .offer
                    .config
                    .alpn_protocols()
                    .iter()
                    .any(|protocol| protocol == pick)
                {
                    return Err(connection::Error::IllegalParameter.into());
                }
                self.session.extensions.selected_alpn = Some(
                    ArrayVec::try_from(pick).map_err(|_| connection::Error::IllegalParameter)?,
                );
            } else if ext.ty == extension::Type::EARLY_DATA {
                if !matches!(self.session.extensions.early_data, EarlyData::Offered)
                    || !ext.data.is_empty()
                {
                    return Err(connection::Error::UnsolicitedExtension.into());
                }
                self.session.extensions.early_data = EarlyData::Accepted;
            }
        }
        if self.session.offer.config.transport_mode().is_quic() && !saw_quic_transport_parameters {
            return Err(connection::Error::MissingExtension.into());
        }
        if !matches!(self.session.extensions.early_data, EarlyData::NotOffered) {
            connection::EventContext::emit(
                events,
                self.session.application.traffic.suite(),
                if matches!(self.session.extensions.early_data, EarlyData::Accepted) {
                    connection::Event::EarlyDataAccepted
                } else {
                    connection::Event::EarlyDataRejected
                },
            )?;
        }
        self.session.handshake.transcript.update(raw);
        self.session.handshake.state = if self.session.handshake.psk_used {
            state::State::expect_server_finished(secrets)
        } else {
            state::State::expect_certificate(secrets)
        };
        Ok(())
    }
}
