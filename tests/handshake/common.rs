use std::convert::Infallible;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

use ring::rand::{SecureRandom, SystemRandom};

use shin::connection::{
    self, Clock, DriveError, Epoch, Error, EventContext, EventSink, KeyDirection,
};
use shin::crypto::hash::Digest;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::Keys;
use shin::server::{
    self, ReplayDomain, Shard, config, config::CertSource, config::ClientAuth,
    config::ClientCertVerifier, config::Connection, config::EarlyDataGuard, config::NoClientAuth,
    config::NoGuard,
};
use shin::transport::Mode;

static REPLAY_DOMAIN: OnceLock<ReplayDomain> = OnceLock::new();

pub fn replay_domain() -> ReplayDomain {
    REPLAY_DOMAIN
        .get_or_init(|| ReplayDomain::random().expect("test replay domain"))
        .clone()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Send {
        epoch: Epoch,
        data: Vec<u8>,
    },
    KeysReady {
        epoch: Epoch,
        read_secret: Digest,
        write_secret: Digest,
    },
    PeerExtension {
        ty: u16,
        data: Vec<u8>,
    },
    KeyUpdate {
        direction: KeyDirection,
        secret: Digest,
    },
    NewSessionTicket {
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: Vec<u8>,
        ticket: Vec<u8>,
        max_early_data: Option<u32>,
    },
    ResumptionSecret {
        psk: [u8; 32],
    },
    ZeroRttKeysReady {
        secret: Digest,
    },
    EarlyDataAccepted,
    EarlyDataRejected,
    Done,
}

#[derive(Default)]
struct Events(Vec<Event>);

impl EventSink for Events {
    type Error = Infallible;

    fn event(
        &mut self,
        event: connection::Event<'_>,
        _context: EventContext,
    ) -> Result<(), Self::Error> {
        let event = match event {
            connection::Event::Send { epoch, data } => Event::Send {
                epoch,
                data: data.to_vec(),
            },
            connection::Event::KeysReady {
                epoch,
                read_secret,
                write_secret,
            } => Event::KeysReady {
                epoch,
                read_secret: Digest::try_from_slice(read_secret.as_slice()).unwrap(),
                write_secret: Digest::try_from_slice(write_secret.as_slice()).unwrap(),
            },
            connection::Event::PeerExtension { ty, data } => Event::PeerExtension {
                ty,
                data: data.to_vec(),
            },
            connection::Event::KeyUpdate { direction, secret } => Event::KeyUpdate {
                direction,
                secret: Digest::try_from_slice(secret.as_slice()).unwrap(),
            },
            connection::Event::NewSessionTicket {
                ticket_lifetime,
                ticket_age_add,
                ticket_nonce,
                ticket,
                max_early_data,
            } => Event::NewSessionTicket {
                ticket_lifetime,
                ticket_age_add,
                ticket_nonce: ticket_nonce.to_vec(),
                ticket: ticket.to_vec(),
                max_early_data,
            },
            connection::Event::ResumptionSecret { psk } => Event::ResumptionSecret {
                psk: *psk.as_array(),
            },
            connection::Event::ZeroRttKeysReady { secret } => Event::ZeroRttKeysReady {
                secret: Digest::try_from_slice(secret.as_slice()).unwrap(),
            },
            connection::Event::EarlyDataAccepted => Event::EarlyDataAccepted,
            connection::Event::EarlyDataRejected => Event::EarlyDataRejected,
            connection::Event::Done => Event::Done,
        };
        self.0.push(event);
        Ok(())
    }
}

fn collect(
    run: impl FnOnce(&mut Events) -> Result<(), DriveError<Infallible>>,
) -> Result<Vec<Event>, Error> {
    let mut events = Events::default();
    match run(&mut events) {
        Ok(()) => Ok(events.0),
        Err(DriveError::Protocol(error)) => Err(error),
        Err(DriveError::Sink(never)) => match never {},
    }
}

pub trait CollectEvents {
    fn start(&mut self) -> Result<Vec<Event>, Error>;
    fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error>;
}

impl<C: Clock> CollectEvents for shin::client::Client<C> {
    fn start(&mut self) -> Result<Vec<Event>, Error> {
        collect(|events| self.start_into(events))
    }

    fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        collect(|events| self.read_into(epoch, data, events))
    }
}

pub trait CollectServerEvents<G: EarlyDataGuard, V: ClientCertVerifier> {
    fn read(
        &mut self,
        epoch: Epoch,
        data: &[u8],
        shard: &mut Shard<G, V>,
    ) -> Result<Vec<Event>, Error>;
}

impl<C, G, V> CollectServerEvents<G, V> for server::Server<C>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn read(
        &mut self,
        epoch: Epoch,
        data: &[u8],
        shard: &mut Shard<G, V>,
    ) -> Result<Vec<Event>, Error> {
        collect(|events| self.read_into(epoch, data, shard, events))
    }
}

pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

pub fn find_send(events: &[Event], epoch: Epoch) -> Option<Vec<u8>> {
    events.iter().find_map(|e| match e {
        Event::Send { epoch: ep, data } if *ep == epoch => Some(data.clone()),
        _ => None,
    })
}

pub fn send(events: &[Event], epoch: Epoch) -> Vec<u8> {
    find_send(events, epoch).expect("expected a Send")
}

pub fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done))
}

pub fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    SigningKey::from_seed(&seed).unwrap()
}

pub struct ServerConfig {
    pub source: CertSource,
    pub transport_params: Vec<u8>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub ticket_keys: Option<Keys>,
    pub accept_early_data: bool,
}

impl ServerConfig {
    fn split(self) -> (config::Config, Connection, bool) {
        (
            config::Config {
                source: self.source,
                alpn_protocols: self.alpn_protocols,
                ticket_keys: self.ticket_keys,
            },
            Connection {
                transport_params: self.transport_params,
            },
            self.accept_early_data,
        )
    }

    pub fn validate(self) -> Result<(), Error> {
        self.validate_with_transport(Mode::Tls)
    }

    pub fn validate_with_transport(self, transport_mode: Mode) -> Result<(), Error> {
        let (shard, connection, _) = self.split();
        shard.validate()?;
        connection.validate_with_transport(transport_mode)
    }
}

trait Policy<C: Clock> {
    fn read(
        &mut self,
        connection: &mut server::Server<C>,
        epoch: Epoch,
        data: &[u8],
        events: &mut Events,
    ) -> Result<(), DriveError<Infallible>>;
}

struct OwnedShard<G: EarlyDataGuard, V: ClientCertVerifier>(Shard<G, V>);

impl<C, G, V> Policy<C> for OwnedShard<G, V>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn read(
        &mut self,
        connection: &mut server::Server<C>,
        epoch: Epoch,
        data: &[u8],
        events: &mut Events,
    ) -> Result<(), DriveError<Infallible>> {
        connection.read_into(epoch, data, &mut self.0, events)
    }
}

pub struct Server<C: Clock, G = NoGuard, V = NoClientAuth> {
    connection: server::Server<C>,
    policy: Box<dyn Policy<C>>,
    _types: PhantomData<fn() -> (G, V)>,
}

impl<C: Clock> Server<C> {
    pub fn new(config: ServerConfig, clock: C) -> Self {
        Self::new_with_transport(config, Mode::Tls, clock)
    }

    pub fn new_with_transport(config: ServerConfig, transport_mode: Mode, clock: C) -> Self {
        let (shard_config, connection_config, _) = config.split();
        Self::build(
            connection_config,
            transport_mode,
            clock,
            OwnedShard(Shard::new(shard_config)),
        )
    }
}

impl<C, G> Server<C, G>
where
    C: Clock,
    G: EarlyDataGuard + 'static,
{
    pub fn with_early_data_guard(config: ServerConfig, clock: C, guard: G) -> Self {
        Self::with_early_data_guard_and_transport(config, Mode::Tls, clock, guard)
    }

    pub fn with_early_data_guard_and_transport(
        config: ServerConfig,
        transport_mode: Mode,
        clock: C,
        guard: G,
    ) -> Self {
        let (shard_config, connection_config, accept_early_data) = config.split();
        let connection =
            server::Server::new_with_transport(connection_config, transport_mode, clock);
        let policy: Box<dyn Policy<C>> = if accept_early_data {
            Box::new(OwnedShard(Shard::with_early_data_guard_in_replay_domain(
                shard_config,
                replay_domain(),
                guard,
            )))
        } else {
            Box::new(OwnedShard(Shard::new(shard_config)))
        };
        Self {
            connection,
            policy,
            _types: PhantomData,
        }
    }
}

impl<C, V> Server<C, NoGuard, V>
where
    C: Clock,
    V: ClientCertVerifier + 'static,
{
    pub fn with_client_auth(config: ServerConfig, clock: C, mode: ClientAuth, verifier: V) -> Self {
        let (shard_config, connection_config, _) = config.split();
        Self::build(
            connection_config,
            Mode::Tls,
            clock,
            OwnedShard(Shard::with_client_auth(shard_config, mode, verifier)),
        )
    }
}

impl<C: Clock, G, V> Server<C, G, V> {
    fn build<P>(connection_config: Connection, transport_mode: Mode, clock: C, policy: P) -> Self
    where
        P: Policy<C> + 'static,
    {
        Self {
            connection: server::Server::new_with_transport(
                connection_config,
                transport_mode,
                clock,
            ),
            policy: Box::new(policy),
            _types: PhantomData,
        }
    }

    pub fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        collect(|events| self.policy.read(&mut self.connection, epoch, data, events))
    }
}

impl<C: Clock, G, V> Deref for Server<C, G, V> {
    type Target = server::Server<C>;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl<C: Clock, G, V> DerefMut for Server<C, G, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}
