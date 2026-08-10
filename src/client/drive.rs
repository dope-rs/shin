use crate::client;
use crate::client::offer::Offer as _;
use crate::connection;
use crate::crypto::kx;
use crate::crypto::schedule;
use crate::wire::handshake;
use ring::rand::SecureRandom as _;

pub(super) trait Drive {
    fn start_with_workspace<S: connection::EventSink + ?Sized>(
        &mut self,
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn read_with_workspace<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn send_key_update<S: connection::EventSink + ?Sized>(
        &mut self,
        request_update: bool,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}

impl<C: connection::Clock> Drive for client::Client<C> {
    fn start_with_workspace<S: connection::EventSink + ?Sized>(
        &mut self,
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use client::state::StateKind;
        if self.session.handshake.state.kind() == StateKind::Failed {
            return Err(connection::Error::ConnectionFailed.into());
        }
        self.session.handshake.require_initial()?;
        let result = start(self, hybrid_workspace, events);
        if result.is_err() {
            poison(self);
        }
        result
    }

    fn read_with_workspace<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use client::state::StateKind;
        if self.session.handshake.state.kind() == StateKind::Failed {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let result = read(self, epoch, data, hybrid_workspace, events);
        if result.is_err() {
            poison(self);
        }
        result
    }

    fn send_key_update<S: connection::EventSink + ?Sized>(
        &mut self,
        request_update: bool,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use client::state::StateKind;
        if self.session.handshake.state.kind() == StateKind::Failed {
            return Err(connection::Error::ConnectionFailed.into());
        }
        if !self
            .session
            .offer
            .config
            .transport_mode()
            .allows_tls_key_update()
            || self.session.handshake.state.kind() != StateKind::Done
        {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        let result = send_key_update(self, request_update, events);
        if result.is_err() {
            poison(self);
        }
        result
    }
}

fn start<C, S>(
    client: &mut client::Client<C>,
    hybrid_workspace: Option<&mut kx::HybridWorkspace>,
    events: &mut S,
) -> Result<(), connection::DriveError<S::Error>>
where
    C: connection::Clock,
    S: connection::EventSink + ?Sized,
{
    match hybrid_workspace {
        Some(workspace) => {
            let (eph, share) = kx::EphemeralKey::generate_in(
                client.session.offer.kex_group,
                &client.session.runtime.rng,
                workspace.slot_mut(),
            )
            .map_err(|_| connection::Error::Kx)?;
            start_with_ephemeral(client, eph, Some(&share), events)
        }
        None => {
            let eph = kx::EphemeralKey::generate(
                client.session.offer.kex_group,
                &client.session.runtime.rng,
            )
            .map_err(|_| connection::Error::Kx)?;
            start_with_ephemeral(client, eph, None, events)
        }
    }
}

fn start_with_ephemeral<C, S>(
    client: &mut client::Client<C>,
    eph: kx::EphemeralKey,
    in_place_share: Option<&[u8]>,
    events: &mut S,
) -> Result<(), connection::DriveError<S::Error>>
where
    C: connection::Clock,
    S: connection::EventSink + ?Sized,
{
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

    let resumption = client.session.offer.resumption.take();
    let early_data_offered = client.session.offer.config.enable_early_data()
        && resumption.as_ref().is_some_and(|resumption| {
            resumption.permits_early_data(client.session.offer.config.transport_mode())
        });
    client.session.extensions.early_data = if early_data_offered {
        EarlyData::Offered
    } else {
        EarlyData::NotOffered
    };
    let client_share = in_place_share.unwrap_or_else(|| eph.client_share());
    client.encode_client_hello(client_share, None, resumption.as_ref(), early_data_offered)?;

    if let Some(resumption) = &resumption {
        client::Client::<C>::splice_psk_binder(
            &client.session.handshake.transcript,
            client.session.buffers.flight.as_mut_slice(),
            resumption.psk.as_array(),
        )?;
    }

    client
        .session
        .handshake
        .transcript
        .update(&client.session.buffers.flight);
    client.session.handshake.active_resumption = resumption;

    connection::EventContext::emit(
        events,
        client.session.application.traffic.suite(),
        connection::Event::Send {
            epoch: connection::Epoch::Plaintext,
            data: &client.session.buffers.flight,
        },
    )?;
    if let Some(resumption) = client
        .session
        .handshake
        .active_resumption
        .as_ref()
        .filter(|_| early_data_offered)
    {
        use crate::wire::psk::RESUMPTION_HASH;
        let client_hello_hash = client
            .session
            .handshake
            .transcript
            .hash(RESUMPTION_HASH)
            .map_err(connection::Error::from)?;
        let secret = schedule::Schedule::client_early_traffic_secret(
            resumption.psk.as_slice(),
            client_hello_hash.as_slice(),
        )?;
        connection::EventContext::emit(
            events,
            client.session.application.traffic.suite(),
            connection::Event::ZeroRttKeysReady { secret: &secret },
        )?;
    }

    client.session.handshake.eph = Some(eph);
    client.session.handshake.state = State::expect_server_hello();
    Ok(())
}

fn read<C, S>(
    client: &mut client::Client<C>,
    epoch: connection::Epoch,
    data: &[u8],
    mut hybrid_workspace: Option<&mut kx::HybridWorkspace>,
    events: &mut S,
) -> Result<(), connection::DriveError<S::Error>>
where
    C: connection::Clock,
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
        Session::dispatch(
            client,
            epoch,
            message,
            raw.as_ref(),
            hybrid_workspace.as_deref_mut(),
            events,
        )?;
        client.session.buffers.reasm.recycle(raw);
    }
    Ok(())
}

fn send_key_update<C, S>(
    client: &mut client::Client<C>,
    request_update: bool,
    events: &mut S,
) -> Result<(), connection::DriveError<S::Error>>
where
    C: connection::Clock,
    S: connection::EventSink + ?Sized,
{
    use crate::connection::KeyDirection;
    use crate::crypto::material;
    use crate::wire::handshake::messages::KeyUpdate;
    let application = &mut client.session.application;
    let suite = application.traffic.suite();

    let bytes = KeyUpdate {
        request_update: u8::from(request_update),
    }
    .encode_framed();
    connection::EventContext::emit(
        events,
        suite,
        connection::Event::Send {
            epoch: connection::Epoch::Application,
            data: &bytes,
        },
    )?;
    connection::EventContext::emit(
        events,
        suite,
        connection::Event::KeyUpdate {
            direction: KeyDirection::Write,
            secret: application.traffic.advance(material::Side::Client)?,
        },
    )?;
    Ok(())
}

fn poison<C: connection::Clock>(client: &mut client::Client<C>) {
    use client::session::EarlyData;
    client.session.handshake.state.fail();
    client.session.handshake.eph = None;
    client.session.handshake.active_resumption = None;
    client.session.extensions.early_data = EarlyData::NotOffered;
    client.session.application.zeroize_secrets();
    client.session.buffers.reasm.discard();
    client.session.buffers.flight.clear();
    client.session.buffers.identity_workspace.clear();
}
