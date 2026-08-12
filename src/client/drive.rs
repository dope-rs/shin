use crate::client;
use crate::connection;
use crate::crypto::kx;
use crate::crypto::schedule;
use crate::wire::handshake;
use ring::rand::SecureRandom as _;

pub(super) trait Drive {
    fn start<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn read<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn poison(&mut self);
}

impl<C: connection::Clock, K: kx::Initiator> Drive for client::Client<C, K> {
    fn start<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if matches!(self.session.handshake.state, client::state::State::Failed) {
            return Err(connection::Error::ConnectionFailed.into());
        }
        self.session.handshake.require_initial()?;
        let result = start(self, events);
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn read<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if matches!(self.session.handshake.state, client::state::State::Failed) {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let result = read(self, epoch, data, events);
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn poison(&mut self) {
        use client::session::EarlyData;
        self.session.handshake.state.fail();
        self.session.kx.clear();
        self.session.handshake.resumption = None;
        self.session.extensions.early_data = EarlyData::NotOffered;
        self.session.application.zeroize_secrets();
        self.session.buffers.reasm.discard();
        self.session.buffers.flight.clear();
    }
}

fn start<C, K, S>(
    client: &mut client::Client<C, K>,
    events: &mut S,
) -> Result<(), connection::DriveError<S::Error>>
where
    C: connection::Clock,
    K: kx::Initiator,
    S: connection::EventSink + ?Sized,
{
    use client::offer::Request;
    use client::session::EarlyData;
    use client::state::State;
    let mut client_random = [0u8; handshake::RANDOM_LEN];
    client
        .session
        .runtime
        .rng
        .fill(&mut client_random)
        .map_err(|_| connection::Error::Rng)?;
    let mut session_id = [0u8; 32];
    if client
        .session
        .offer
        .config
        .transport_mode()
        .uses_legacy_session_id()
    {
        client
            .session
            .runtime
            .rng
            .fill(&mut session_id)
            .map_err(|_| connection::Error::Rng)?;
    }
    client.session.handshake.client_random = client_random;
    client.session.handshake.session_id = session_id;

    use crate::wire::psk::RESUMPTION_HASH;
    let mut resumption = client.session.handshake.resumption.take().filter(|_| {
        client
            .session
            .offer
            .offered_suites
            .iter()
            .any(|suite| suite.hash_alg() == RESUMPTION_HASH)
    });
    let now_ms = client.session.runtime.clock.now_ms();
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
    let early_data = if offer.is_some() && client.session.offer.enable_early_data {
        resumption.as_ref().and_then(|resumption| {
            resumption.early_data_offer(&client.session.offer.offered_suites)
        })
    } else {
        None
    };
    let early_data_offered = early_data.is_some();
    client.session.extensions.early_data = early_data
        .map(EarlyData::Offered)
        .unwrap_or(EarlyData::NotOffered);
    let certificate_types = client.session.certificate_type_offers();
    let session = &mut client.session;
    let client_share = session
        .kx
        .generate(session.offer.kex_group, &session.runtime.rng)
        .map_err(|_| connection::Error::Kx)?;
    let binder_slot = Request {
        certificate_types,
        kx_pubkey: client_share.as_ref(),
        cookie: None,
        resumption: offer,
        offer_early_data: early_data_offered,
    }
    .encode(
        &session.offer,
        &session.handshake,
        &mut session.buffers.flight,
    )?;
    drop(client_share);

    match (resumption.as_ref(), binder_slot) {
        (Some(resumption), Some(slot)) => slot.splice(
            &session.handshake.transcript,
            session.buffers.flight.as_mut_slice(),
            resumption.psk().as_array(),
        )?,
        (None, None) => {}
        _ => return Err(connection::Error::Encode.into()),
    }

    session.handshake.transcript.update(&session.buffers.flight);
    session.handshake.resumption = resumption;

    connection::EventContext::emit(
        events,
        session.application.traffic.suite(),
        connection::Event::Send {
            epoch: connection::Epoch::Plaintext,
            data: &session.buffers.flight,
        },
    )?;
    if let (Some(resumption), Some(authority)) = (session.handshake.resumption.as_ref(), early_data)
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
                alpn: authority
                    .alpn
                    .and_then(|alpn| session.offer.config.alpn(alpn)),
            },
        )?;
    }

    session.handshake.state = State::expect_server_hello();
    Ok(())
}

fn read<C, K, S>(
    client: &mut client::Client<C, K>,
    epoch: connection::Epoch,
    data: &[u8],
    events: &mut S,
) -> Result<(), connection::DriveError<S::Error>>
where
    C: connection::Clock,
    K: kx::Initiator,
    S: connection::EventSink + ?Sized,
{
    client.session.buffers.reasm.begin_record(epoch)?;
    let mut input = data;
    while let Some(raw) = client
        .session
        .buffers
        .reasm
        .next_record(epoch, &mut input)?
    {
        use crate::wire::handshake::views::MessageRef;
        use client::session::Session;
        let message = MessageRef::decode(raw.as_ref())?;
        Session::dispatch(client, epoch, message, raw.as_ref(), events)?;
        client.session.buffers.reasm.recycle(raw);
    }
    Ok(())
}
