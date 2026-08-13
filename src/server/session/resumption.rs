use crate::connection;
use crate::crypto::material;
use crate::crypto::ticket;
use crate::server;
use crate::server::config;
use crate::server::session;
use crate::wire::codec::Encode as _;
use crate::wire::extension;
use crate::wire::psk;
use core::mem;
use ring::rand::SecureRandom as _;
use subtle::ConstantTimeEq as _;

use crate::wire::handshake;

pub(super) struct Resumption<'session, C> {
    session: &'session mut session::Session<C>,
}

const _: () = assert!(mem::size_of::<Resumption<'static, ()>>() == mem::size_of::<usize>());

impl<'session, C: connection::Clock> Resumption<'session, C> {
    pub(super) fn new(session: &'session mut session::Session<C>) -> Self {
        Self { session }
    }

    pub(super) fn try_accept_psk(
        self,
        offer: psk::Tail<'_>,
        keys: Option<&ticket::Keys>,
        selected_alpn: Option<&[u8]>,
        replay_domain: &[u8; ticket::REPLAY_DOMAIN_LEN],
    ) -> Result<Option<session::AcceptedPsk>, connection::Error> {
        use crate::memory::threadbound::ThreadBound;
        use crate::wire::psk::ResumptionBinder;
        let Some(keys) = keys else {
            return Ok(None);
        };
        let now = self.session.runtime.clock.now_ms();
        let selected_alpn = selected_alpn.unwrap_or_default();
        let opened = match keys.decrypt_resumption(offer.identity(), selected_alpn) {
            Ok(opened) => opened,
            Err(_) => return Ok(None),
        };
        if !session::AcceptedPsk::issued_at_is_resumable(opened.issued_at_ms, now) {
            return Ok(None);
        }
        let bind = offer.binder();
        let binder: [u8; 32] = bind
            .try_into()
            .map_err(|_| connection::Error::BadPskBinder)?;
        let accepted = session::AcceptedPsk {
            psk: opened.psk,
            ticket: session::Ticket {
                age_add: opened.age_add,
                issued_at_ms: opened.issued_at_ms,
                suite: opened.suite,
                obfuscated_age: offer.obfuscated_ticket_age(),
                max_early_data: opened.context.early_data_for_replay_domain(
                    self.session.transport_mode,
                    &self.session.connection.transport_params,
                    replay_domain,
                ),
            },
            binder,
            alpn_matches: opened.alpn_matches,
            _thread: ThreadBound::NEW,
        };
        let mut t = self.session.handshake.transcript.fork();
        t.update(offer.transcript_prefix());
        let partial_hash = t.hash(psk::RESUMPTION_HASH)?;
        let expected = ResumptionBinder::compute(accepted.psk.as_array(), partial_hash.as_slice())?;
        if expected.as_slice().len() != bind.len() || !bool::from(expected.as_slice().ct_eq(bind)) {
            return Err(connection::Error::BadPskBinder);
        }
        Ok(Some(accepted))
    }

    pub(super) fn handle_client_finished<G, V, S, const DOMAIN: u8>(
        self,
        f: &[u8],
        raw: &[u8],
        expected: material::FinishedVerifyData,
        authority: &server::Authority<G, V, DOMAIN>,
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
        self.emit_session_ticket(authority, events)?;
        Ok(())
    }

    fn emit_session_ticket<G, V, S, const DOMAIN: u8>(
        self,
        authority: &server::Authority<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        use crate::connection::Epoch;
        use crate::crypto::schedule::ResumptionMaster;
        use crate::server::session::TICKET_LIFETIME_SECS;
        let Some(master) = self.session.application.master.as_ref() else {
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
            .selected_alpn(&authority.alpn)
            .unwrap_or_default();
        let suite = self
            .session
            .application
            .traffic
            .suite()
            .ok_or(connection::Error::UnexpectedMessage)?;
        let max_early_data = self
            .session
            .peer
            .early_data
            .advertised_size(self.session.transport_mode);
        let context = ticket::Context::new_with_replay_domain(
            self.session.transport_mode,
            max_early_data,
            &self.session.connection.transport_params,
            *authority.replay_domain.id(),
        );
        let ticket = {
            let keys = authority.ticket_keys.borrow();
            let Some(keys) = keys.as_ref() else {
                return Ok(());
            };
            keys.encrypt_claims(
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
            .map_err(|_| connection::Error::Rng)?
        };
        let suite_context = self.session.application.traffic.suite();
        let outbound = connection::EventContext::begin_send(
            events,
            suite_context,
            Epoch::Application,
            self.session.buffers.flight.capacity(),
        )?;
        let mut flight = self.session.buffers.flight.flight(outbound);
        flight.clear();
        flight.put_u8(handshake::Type::NewSessionTicket as u8);
        let mut nst = flight.begin_u24()?;
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
        let direct = flight.commit();
        if !direct {
            connection::EventContext::emit(
                events,
                suite_context,
                connection::Event::Send {
                    epoch: Epoch::Application,
                    data: &self.session.buffers.flight,
                },
            )?;
        }
        Ok(())
    }
}
