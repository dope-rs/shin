use crate::client;
use crate::client::session;
use crate::connection;
use crate::crypto::kx;
use crate::crypto::schedule;
use crate::wire::handshake;
use crate::wire::handshake::reassemblers;
use core::mem;
use ring::rand::SecureRandom as _;

pub(super) struct Drive<'session, 'policy, C, K> {
    machine: &'session mut session::Session<C, K>,
    policy: &'policy client::config::Policy<'policy>,
}

const _: () =
    assert!(mem::size_of::<Drive<'static, 'static, (), ()>>() == 2 * mem::size_of::<usize>());

impl<'session, 'policy, C: connection::Clock, K: kx::Initiator> Drive<'session, 'policy, C, K> {
    pub(super) fn new(
        machine: &'session mut session::Session<C, K>,
        policy: &'policy client::config::Policy<'policy>,
    ) -> Self {
        Self { machine, policy }
    }

    pub(super) fn start<S>(
        self,
        transport_params: Option<&[u8]>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        S: connection::EventSink + ?Sized,
    {
        let Self { machine, policy } = self;
        use client::offer::Request;
        use client::session::EarlyData;
        let mut client_random = [0u8; handshake::RANDOM_LEN];
        machine
            .runtime
            .rng
            .fill(&mut client_random)
            .map_err(|_| connection::Error::Rng)?;
        let mut session_id = [0u8; 32];
        if policy.template().transport_mode().uses_legacy_session_id() {
            machine
                .runtime
                .rng
                .fill(&mut session_id)
                .map_err(|_| connection::Error::Rng)?;
        }
        machine.handshake.client_random = client_random;
        machine.handshake.session_id = session_id;

        use crate::wire::psk::RESUMPTION_HASH;
        let mut resumption = machine.handshake.resumption.take().filter(|_| {
            machine
                .offer
                .offered_suites
                .iter()
                .any(|suite| suite.hash_alg() == RESUMPTION_HASH)
        });
        let now_ms = machine.runtime.clock.now_ms();
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
        let early_data = if offer.is_some() && machine.offer.enable_early_data {
            resumption
                .as_ref()
                .and_then(|resumption| resumption.early_data_offer(&machine.offer.offered_suites))
        } else {
            None
        };
        let early_data_offered = early_data.is_some();
        machine.extensions.early_data = early_data
            .map(EarlyData::Offered)
            .unwrap_or(EarlyData::NotOffered);
        let certificate_types = machine.certificate_type_offers(policy);
        let session = machine;
        let client_share = session
            .kx
            .generate(session.offer.kex_group, &session.runtime.rng)
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
            cookie: None,
            resumption: offer,
            offer_early_data: early_data_offered,
        }
        .encode(
            policy.template(),
            transport_params.unwrap_or_else(|| policy.transport_params()),
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

        session.handshake.transcript.update(flight.as_slice());
        let direct = flight.commit();
        session.handshake.resumption = resumption;

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
        if let (Some(resumption), Some(authority)) =
            (session.handshake.resumption.as_ref(), early_data)
        {
            let client_hello_hash = session
                .handshake
                .transcript
                .hash(RESUMPTION_HASH)
                .map_err(connection::Error::from)?;
            let secret = schedule::Schedule::client_early_traffic_secret(
                resumption.psk().as_slice(),
                client_hello_hash.as_slice(),
            )?;
            connection::EventContext::emit(
                events,
                Some(authority.suite),
                connection::Event::ZeroRttKeysReady {
                    secret: &secret,
                    max_early_data: authority.maximum,
                    alpn: authority.alpn.and_then(|alpn| policy.template().alpn(alpn)),
                },
            )?;
        }

        session.handshake.expect_server_hello();
        Ok(())
    }

    pub(super) fn read<S>(
        self,
        reassembler: &mut reassemblers::HsReassembler,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        S: connection::EventSink + ?Sized,
    {
        let Self { machine, policy } = self;
        reassembler.read(epoch, data, |raw| {
            use crate::wire::handshake::views::MessageRef;
            let message = MessageRef::decode(raw)?;
            machine.dispatch(policy, epoch, message, raw, events)
        })
    }
}
