use super::*;
use core::mem;
use subtle::ConstantTimeEq;

pub(super) trait Resumption {
    fn try_accept_psk(
        &self,
        ch: &ClientHelloRef<'_>,
        raw: &[u8],
        keys: Option<&TicketKeys>,
    ) -> Option<AcceptedPsk>;
    fn handle_client_finished<G, V, S>(
        &mut self,
        f: &[u8],
        raw: &[u8],
        expected: Digest,
        shard: &Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized;
    fn emit_session_ticket<S: EventSink + ?Sized>(
        &mut self,
        keys: Option<&TicketKeys>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
}
impl<C: Clock> Resumption for Server<C> {
    fn try_accept_psk(
        &self,
        ch: &ClientHelloRef<'_>,
        raw: &[u8],
        keys: Option<&TicketKeys>,
    ) -> Option<AcceptedPsk> {
        let keys = keys?;
        let now = self.now_ms();
        let kx_ext = ch.extensions.find(ExtensionType::PSK_KEY_EXCHANGE_MODES)?;
        if !KxModes::contains(kx_ext.data, KX_MODE_PSK_DHE).ok()? {
            return None;
        }
        let psk_ext = ch.extensions.find(ExtensionType::PRE_SHARED_KEY)?;
        let offer = Offer::decode_first(psk_ext.data).ok()??;
        let bind = offer.binder;
        if bind.len() != 32 {
            return None;
        }
        let mut dt = keys.decrypt(offer.identity).ok()?;
        let suite = dt.suite;
        let (psk, age_add, issued_at_ms, alpn) =
            (dt.psk, dt.age_add, dt.issued_at_ms, mem::take(&mut dt.alpn));
        if !AcceptedPsk::issued_at_is_resumable(issued_at_ms, now) {
            return None;
        }
        let binder_prefix = Offer::binder_transcript_prefix(raw, bind.len())?;
        let mut t = if self.hrr_done {
            self.transcript.fork()
        } else {
            Transcript::new()
        };
        t.update(binder_prefix);
        let partial_hash = t.hash(RESUMPTION_HASH);
        let expected = ResumptionBinder::compute(&psk, partial_hash.as_slice()).ok()?;
        if expected.as_slice().len() != bind.len() || !bool::from(expected.as_slice().ct_eq(bind)) {
            return None;
        }
        Some(AcceptedPsk {
            psk,
            age_add,
            issued_at_ms,
            suite,
            obfuscated_ticket_age: offer.obfuscated_ticket_age,
            binder: bind.try_into().ok()?,
            alpn,
            _thread: ThreadBound::NEW,
        })
    }

    fn handle_client_finished<G, V, S>(
        &mut self,
        f: &[u8],
        raw: &[u8],
        expected: Digest,
        shard: &Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized,
    {
        if !expected.ct_eq(f) {
            return Err(Error::BadFinished.into());
        }
        self.transcript.update(raw);
        EventContext::emit(events, self.negotiated_suite, Event::Done)?;
        self.state = State::Done;
        self.emit_session_ticket(shard.config.ticket_keys.as_ref(), events)?;
        Ok(())
    }

    fn emit_session_ticket<S: EventSink + ?Sized>(
        &mut self,
        keys: Option<&TicketKeys>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        use ring::rand::SecureRandom;
        let Some(master) = self.master.as_ref() else {
            return Ok(());
        };
        let Some(keys) = keys else {
            return Ok(());
        };
        if master.hash_alg() != RESUMPTION_HASH {
            return Ok(());
        }
        let issued_at_ms = self.now_ms();
        let h_cf = self.transcript.hash(RESUMPTION_HASH);
        let rms_digest = master
            .resumption_master_secret(h_cf.as_slice())?
            .to_digest();
        let mut nonce = [0u8; 8];
        let mut age_add_bytes = [0u8; 4];
        self.rng.fill(&mut nonce).map_err(|_| Error::Rng)?;
        self.rng.fill(&mut age_add_bytes).map_err(|_| Error::Rng)?;
        let age_add = u32::from_be_bytes(age_add_bytes);
        let psk = ResumptionMaster::from_secret(&rms_digest).psk(&nonce)?;
        let alpn = self.selected_alpn.as_deref().unwrap_or_default();
        let suite = self
            .negotiated_suite
            .ok_or(Error::UnexpectedMessage)?
            .wire_id();
        let ticket = keys
            .encrypt(&psk, age_add, issued_at_ms, suite, alpn, &self.rng)
            .map_err(|_| Error::Rng)?;
        self.flight.clear();
        self.flight.put_u8(HandshakeType::NewSessionTicket as u8);
        self.flight.put_vec_u24(|nst| {
            nst.put_u32(TICKET_LIFETIME_SECS);
            nst.put_u32(age_add);
            nst.put_vec_u8(|ticket_nonce| {
                ticket_nonce.put_slice(&nonce);
                Ok(())
            })?;
            nst.put_vec_u16(|encoded_ticket| {
                encoded_ticket.put_slice(&ticket);
                Ok(())
            })?;
            nst.put_vec_u16(|extensions| {
                if let Some(maximum) = self.early_data.advertised_size() {
                    Extension::encode_with(extensions, ExtensionType::EARLY_DATA, |body| {
                        body.put_u32(maximum);
                        Ok(())
                    })?;
                }
                Ok(())
            })
        })?;
        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::Send {
                epoch: Epoch::Application,
                data: &self.flight,
            },
        )?;
        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::ResumptionSecret { psk },
        )?;
        Ok(())
    }
}
