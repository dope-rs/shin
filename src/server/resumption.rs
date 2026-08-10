use crate::connection;
use crate::crypto::material;
use crate::crypto::ticket;
use crate::server;
use crate::server::config;
use crate::server::session;
use crate::wire::codec::Encode as _;
use crate::wire::extension;
use crate::wire::handshake::views;
use crate::wire::psk;
use ring::rand::SecureRandom as _;
use subtle::ConstantTimeEq as _;

use core::mem;

use crate::wire::handshake;

pub(super) trait Resumption {
    fn try_accept_psk(
        &self,
        ch: &views::ClientHelloRef<'_>,
        raw: &[u8],
        keys: Option<&ticket::Keys>,
        replay_domain: &[u8; ticket::REPLAY_DOMAIN_LEN],
    ) -> Option<session::AcceptedPsk>;
    fn handle_client_finished<G, V, S>(
        &mut self,
        f: &[u8],
        raw: &[u8],
        expected: material::FinishedVerifyData,
        shard: &server::Shard<G, V>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized;
    fn emit_session_ticket<S: connection::EventSink + ?Sized>(
        &mut self,
        keys: Option<&ticket::Keys>,
        replay_domain: [u8; ticket::REPLAY_DOMAIN_LEN],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}
impl<C: connection::Clock> Resumption for server::Server<C> {
    fn try_accept_psk(
        &self,
        ch: &views::ClientHelloRef<'_>,
        raw: &[u8],
        keys: Option<&ticket::Keys>,
        replay_domain: &[u8; ticket::REPLAY_DOMAIN_LEN],
    ) -> Option<session::AcceptedPsk> {
        use crate::memory::threadbound::ThreadBound;
        use crate::wire::psk::KX_MODE_DHE;
        use crate::wire::psk::KxModes;
        use crate::wire::psk::Offer;
        use crate::wire::psk::ResumptionBinder;
        let keys = keys?;
        let now = self.session.runtime.clock.now_ms();
        let kx_ext = ch
            .extensions
            .find(extension::Type::PSK_KEY_EXCHANGE_MODES)?;
        if !KxModes::contains(kx_ext.data, KX_MODE_DHE).ok()? {
            return None;
        }
        let psk_ext = ch.extensions.find(extension::Type::PRE_SHARED_KEY)?;
        let offer = Offer::decode_first(psk_ext.data).ok()??;
        let bind = offer.binder;
        if bind.len() != 32 {
            return None;
        }
        let mut dt = keys.decrypt(offer.identity).ok()?;
        let suite = dt.suite;
        let max_early_data = dt.context.early_data_for_replay_domain(
            self.session.transport_mode,
            &self.session.connection.transport_params,
            replay_domain,
        );
        let (psk, age_add, issued_at_ms, alpn) =
            (dt.psk, dt.age_add, dt.issued_at_ms, mem::take(&mut dt.alpn));
        if !session::AcceptedPsk::issued_at_is_resumable(issued_at_ms, now) {
            return None;
        }
        let binder_prefix = Offer::binder_transcript_prefix(raw, bind.len())?;
        let mut t = self.session.handshake.transcript.fork();
        t.update(binder_prefix);
        let partial_hash = t.hash(psk::RESUMPTION_HASH).ok()?;
        let expected = ResumptionBinder::compute(psk.as_array(), partial_hash.as_slice()).ok()?;
        if expected.as_slice().len() != bind.len() || !bool::from(expected.as_slice().ct_eq(bind)) {
            return None;
        }
        Some(session::AcceptedPsk {
            psk,
            ticket: session::Ticket {
                age_add,
                issued_at_ms,
                suite,
                obfuscated_age: offer.obfuscated_ticket_age,
                max_early_data,
            },
            binder: bind.try_into().ok()?,
            alpn,
            _thread: ThreadBound::NEW,
        })
    }

    fn handle_client_finished<G, V, S>(
        &mut self,
        f: &[u8],
        raw: &[u8],
        expected: material::FinishedVerifyData,
        shard: &server::Shard<G, V>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        use crate::server::session::State;
        if !expected.ct_eq(f) {
            return Err(connection::Error::BadFinished.into());
        }
        self.session.peer.early_data.close();
        self.session.handshake.transcript.update(raw);
        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::Done,
        )?;
        self.session.handshake.state = State::Done;
        self.emit_session_ticket(
            shard.policy.config.ticket_keys.as_ref(),
            *shard.prepared.replay_domain.id(),
            events,
        )?;
        Ok(())
    }

    fn emit_session_ticket<S: connection::EventSink + ?Sized>(
        &mut self,
        keys: Option<&ticket::Keys>,
        replay_domain: [u8; ticket::REPLAY_DOMAIN_LEN],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::connection::Epoch;
        use crate::crypto::schedule::ResumptionMaster;
        use crate::server::session::TICKET_LIFETIME_SECS;
        let Some(master) = self.session.application.master.as_ref() else {
            return Ok(());
        };
        let Some(keys) = keys else {
            return Ok(());
        };
        if master.hash_alg() != psk::RESUMPTION_HASH {
            return Ok(());
        }
        let issued_at_ms = self.session.runtime.clock.now_ms();
        let h_cf = self
            .session
            .handshake
            .transcript
            .hash(psk::RESUMPTION_HASH)
            .map_err(connection::Error::from)?;
        let rms = master.resumption_master_secret(h_cf.as_slice())?;
        let mut nonce = [0u8; 8];
        let mut age_add_bytes = [0u8; 4];
        self.session
            .runtime
            .rng
            .fill(&mut nonce)
            .map_err(|_| connection::Error::Rng)?;
        self.session
            .runtime
            .rng
            .fill(&mut age_add_bytes)
            .map_err(|_| connection::Error::Rng)?;
        let age_add = u32::from_be_bytes(age_add_bytes);
        let psk = ResumptionMaster::from_secret(&rms).psk(&nonce)?;
        let alpn = self
            .session
            .peer
            .selected_alpn
            .as_deref()
            .unwrap_or_default();
        let suite = self
            .session
            .application
            .traffic
            .suite()
            .ok_or(connection::Error::UnexpectedMessage)?
            .wire_id();
        let max_early_data = self
            .session
            .peer
            .early_data
            .advertised_size(self.session.transport_mode);
        let context = ticket::Context::new_with_replay_domain(
            self.session.transport_mode,
            max_early_data,
            &self.session.connection.transport_params,
            replay_domain,
        );
        let ticket = keys
            .encrypt_claims(
                ticket::Claims {
                    psk: &psk,
                    age_add,
                    issued_at_ms,
                    suite,
                    alpn,
                    context,
                },
                &self.session.runtime.rng,
            )
            .map_err(|_| connection::Error::Rng)?;
        self.session.buffers.flight.clear();
        self.session
            .buffers
            .flight
            .put_u8(handshake::Type::NewSessionTicket as u8);
        let mut nst = self.session.buffers.flight.begin_u24()?;
        nst.put_u32(TICKET_LIFETIME_SECS);
        nst.put_u32(age_add);
        let mut ticket_nonce = nst.begin_u8()?;
        ticket_nonce.put_slice(&nonce);
        ticket_nonce.finish()?;
        let mut encoded_ticket = nst.begin_u16()?;
        encoded_ticket.put_slice(&ticket);
        encoded_ticket.finish()?;
        let mut extensions = nst.begin_u16()?;
        if let Some(maximum) = max_early_data {
            use crate::wire::extension::Extension;
            let mut body = Extension::begin(&mut extensions, extension::Type::EARLY_DATA)?;
            body.put_u32(maximum);
            body.finish()?;
        }
        extensions.finish()?;
        nst.finish()?;
        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::Send {
                epoch: Epoch::Application,
                data: &self.session.buffers.flight,
            },
        )?;
        connection::EventContext::emit(
            events,
            self.session.application.traffic.suite(),
            connection::Event::ResumptionSecret { psk: &psk },
        )?;
        Ok(())
    }
}
