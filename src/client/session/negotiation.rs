use crate::client;
use crate::client::session;
use crate::client::session::state;
use crate::connection;
use crate::crypto::kx;
use crate::wire::extension;
use crate::wire::handshake::views;
use crate::wire::protocols;
use core::mem;

pub(super) struct Negotiation<'session, 'policy, C, K> {
    machine: &'session mut session::Session<C, K>,
    policy: &'policy client::config::Policy<'policy>,
}

const _: () =
    assert!(mem::size_of::<Negotiation<'static, 'static, (), ()>>() == 2 * mem::size_of::<usize>());

impl<'session, 'policy, C: connection::Clock, K: kx::Initiator>
    Negotiation<'session, 'policy, C, K>
{
    pub(super) fn new(
        machine: &'session mut session::Session<C, K>,
        policy: &'policy client::config::Policy<'policy>,
    ) -> Self {
        Self { machine, policy }
    }

    pub(super) fn handle_server_hello<S: connection::EventSink + ?Sized>(
        self,
        sh: views::ServerHelloRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        let Self { machine, policy } = self;
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
        let expected_session_id = if policy.template().transport_mode().uses_legacy_session_id() {
            machine.handshake.session_id.as_slice()
        } else {
            &[]
        };
        if sh.legacy_session_id_echo != expected_session_id {
            return Err(connection::Error::IllegalParameter.into());
        }
        let suite = CipherSuite::from_u16(sh.cipher_suite)
            .ok_or(connection::Error::UnsupportedCipherSuite)?;
        if !machine.offer.offered_suites.contains(&suite) {
            return Err(connection::Error::IllegalParameter.into());
        }
        let alg = suite.hash_alg();
        machine
            .handshake
            .transcript
            .select(alg)
            .map_err(connection::Error::from)?;
        machine.application.traffic.select(suite)?;
        if sh.random == HELLO_RETRY_REQUEST_RANDOM {
            return Self::handle_hello_retry_request(machine, policy, sh, raw, events);
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
        let server_share = protocols::ServerKeyShare::decode(ks_data)?;

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
            use crate::wire::psk::RESUMPTION_HASH;
            use crate::wire::psk::SelectedIdentity;
            if machine.handshake.resumption.is_none() {
                return Err(connection::Error::UnexpectedMessage.into());
            }
            if alg != RESUMPTION_HASH {
                return Err(connection::Error::IllegalParameter.into());
            }
            let selected = SelectedIdentity::decode(ext.data)
                .map_err(|_| connection::Error::IllegalParameter)?;
            if selected.get() != 0 {
                return Err(connection::Error::IllegalParameter.into());
            }
        }
        machine.handshake.psk_used = psk_ext.is_some();

        machine.handshake.transcript.update(raw);

        if machine.kx.pending_group().map(kx::KexGroup::wire_id) != Some(server_share.group()) {
            return Err(connection::Error::IllegalParameter.into());
        }
        let dhe = machine
            .kx
            .agree(server_share.key_exchange())
            .map_err(|_| connection::Error::Kx)?;

        let active_resumption = machine.handshake.resumption.take();
        let ks_handshake = if machine.handshake.psk_used {
            let resumption = active_resumption
                .as_ref()
                .ok_or(connection::Error::UnexpectedMessage)?;
            Schedule::new_psk(alg, resumption.psk().as_slice()).into_handshake(dhe.as_slice())?
        } else {
            Schedule::new(alg).into_handshake(dhe.as_slice())?
        };
        drop(active_resumption);
        let h_chsh = machine
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
            machine.application.traffic.suite(),
            connection::Event::KeysReady {
                epoch: connection::Epoch::Handshake,
                read_secret: &secrets.server_traffic,
                write_secret: &secrets.client_traffic,
            },
        )?;

        machine.handshake.state = state::State::expect_encrypted_extensions(secrets);
        Ok(())
    }

    /// Resend ClientHello after one HRR, echoing its cookie and rebinding PSK to
    /// `message_hash(CH1) ‖ HRR ‖ Truncate(CH2)` (RFC 8446 §4.2.11.2).
    fn handle_hello_retry_request<S: connection::EventSink + ?Sized>(
        machine: &mut session::Session<C, K>,
        policy: &client::config::Policy<'_>,
        hrr: views::ServerHelloRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::crypto::hash::Transcript;
        use crate::crypto::kx::KexGroup;
        if machine.handshake.hrr_done {
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
                    selected_group = Some(protocols::RetryKeyShare::decode(ext.data)?.group());
                }
                extension::Type::COOKIE => cookie = Some(protocols::Cookie::decode(ext.data)?),
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
        if machine.kx.pending_group() == Some(group) {
            return Err(connection::Error::IllegalParameter.into());
        }

        let alg = machine.application.hash_alg()?;
        let h1 = machine
            .handshake
            .transcript
            .hash(alg)
            .map_err(connection::Error::from)?;
        machine.handshake.transcript =
            Transcript::restart_with_message_hash(alg, &h1).map_err(connection::Error::from)?;
        machine.handshake.transcript.update(raw);

        Self::finish_hello_retry_request(machine, policy, group, cookie, events)
    }

    fn finish_hello_retry_request<S: connection::EventSink + ?Sized>(
        machine: &mut session::Session<C, K>,
        policy: &client::config::Policy<'_>,
        group: kx::KexGroup,
        cookie: Option<protocols::Cookie<'_>>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use client::offer::Request;
        machine.offer.kex_group = group;
        let mut resumption = machine.handshake.resumption.take();
        let now_ms = connection::Clock::now_ms(&machine.runtime.clock);
        let ticket_age = resumption
            .as_ref()
            .and_then(|resumption| resumption.obfuscated_ticket_age(now_ms));
        if ticket_age.is_none() {
            resumption = None;
        }
        let offer = resumption
            .as_ref()
            .zip(ticket_age)
            .map(|(resumption, ticket_age)| resumption.offer(ticket_age));
        let certificate_types = machine.certificate_type_offers(policy);
        let session = machine;
        let client_share = session
            .kx
            .generate(group, &session.runtime.rng)
            .map_err(|_| connection::Error::Kx)?;
        let suite = session.application.traffic.suite();
        let outbound = connection::EventContext::begin_send(
            events,
            suite,
            connection::Epoch::Plaintext,
            session.buffers.flight.capacity(),
        )?;
        let mut flight = session.buffers.flight.flight(outbound);
        let binder_slot = Request {
            certificate_types,
            kx_pubkey: client_share.as_ref(),
            cookie,
            resumption: offer,
            offer_early_data: false,
        }
        .encode(
            policy.template(),
            policy.transport_params(),
            &session.offer,
            &session.handshake,
            &mut flight,
        )?;
        drop(client_share);

        match (resumption.as_ref(), binder_slot) {
            (Some(resumption), Some(slot)) => slot.splice(
                &session.handshake.transcript,
                flight.as_mut_slice(),
                resumption.psk().as_array(),
            )?,
            (None, None) => {}
            _ => return Err(connection::Error::Encode.into()),
        }
        session.handshake.resumption = resumption;

        session.handshake.transcript.update(flight.as_slice());
        let direct = flight.commit();
        session.handshake.hrr_done = true;
        if !direct {
            connection::EventContext::emit(
                events,
                suite,
                connection::Event::Send {
                    epoch: connection::Epoch::Plaintext,
                    data: &session.buffers.flight,
                },
            )?;
        }
        Ok(())
    }

    pub(super) fn handle_encrypted_extensions<S: connection::EventSink + ?Sized>(
        self,
        ee: views::EncryptedExtensionsRef<'_>,
        raw: &[u8],
        secrets: state::HandshakeSecrets,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        let Self { machine, policy } = self;
        let offered_early_data = match machine.extensions.early_data {
            session::EarlyData::Offered(authority) => Some(authority),
            session::EarlyData::NotOffered | session::EarlyData::Accepted => None,
        };
        let negotiated = session::NegotiatedExtensions::decode(
            ee.extensions,
            policy.template(),
            machine.certificate_type_offers(policy),
            offered_early_data.is_some() && !machine.handshake.hrr_done,
        )?;
        let (next_early_data, early_data_event) = match (offered_early_data, negotiated.early_data)
        {
            (Some(authority), Some(_)) => {
                let selected_suite = machine
                    .application
                    .traffic
                    .suite()
                    .ok_or(connection::Error::UnexpectedMessage)?;
                if machine.handshake.hrr_done
                    || !machine.handshake.psk_used
                    || selected_suite != authority.suite
                    || negotiated.alpn != authority.alpn
                {
                    return Err(connection::Error::IllegalParameter.into());
                }
                (
                    Some(session::EarlyData::Accepted),
                    Some(connection::Event::EarlyDataAccepted),
                )
            }
            (Some(_), None) => (
                Some(session::EarlyData::NotOffered),
                Some(connection::Event::EarlyDataRejected),
            ),
            (None, None) => (None, None),
            (None, Some(_)) => return Err(connection::Error::UnsolicitedExtension.into()),
        };
        machine.extensions.selected_alpn = negotiated.alpn;
        if let Some(next) = next_early_data {
            machine.extensions.early_data = next;
        }
        if let Some(data) = negotiated.quic_params {
            connection::EventContext::emit(
                events,
                machine.application.traffic.suite(),
                connection::Event::PeerExtension {
                    ty: extension::Type::QUIC_TRANSPORT_PARAMETERS.0,
                    data,
                },
            )?;
        }
        if let Some(event) = early_data_event {
            connection::EventContext::emit(events, machine.application.traffic.suite(), event)?;
        }
        machine.handshake.transcript.update(raw);
        machine.handshake.state = if machine.handshake.psk_used {
            state::State::expect_server_finished(secrets)
        } else {
            state::State::expect_certificate(secrets)
        };
        Ok(())
    }
}
