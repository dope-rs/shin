use std::convert::Infallible;
use std::ops::Deref;
use std::sync::OnceLock;

use ring::rand::{SecureRandom, SystemRandom};

use shin::client::config::{NegotiatedAlpn, Restore};
use shin::connection::{
    self, Clock, DriveError, Epoch, Error, EventContext, EventSink, KeyDirection,
};
use shin::crypto::hash::Digest;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::Keys;
use shin::identity::cert::Cert;
use shin::server::{
    self, ReplayDomain, Shard, config, config::CertSource, config::ClientAuth,
    config::ClientAuthVerifier, config::ClientCertVerifier, config::Connection,
    config::EarlyDataGuard, config::NoClientAuth, config::NoGuard,
};
use shin::transport::Mode;

static REPLAY_DOMAIN: OnceLock<ReplayDomain> = OnceLock::new();

pub fn replay_domain() -> ReplayDomain {
    REPLAY_DOMAIN
        .get_or_init(|| ReplayDomain::random().expect("test replay domain"))
        .clone()
}

pub fn cert_validity_midpoint(cert_der: &[u8]) -> u64 {
    let validity = Cert::parse(cert_der)
        .expect("test certificate parses")
        .tbs
        .validity;
    shin::identity::UnixTime((validity.not_before.0 + validity.not_after.0) / 2)
        .as_secs()
        .expect("test certificate validity is after the UNIX epoch")
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
        ticket: Vec<u8>,
        psk: [u8; 32],
        max_early_data: Option<u32>,
        suite: shin::wire::record::CipherSuite,
        transport_mode: shin::transport::Mode,
        alpn: Option<Vec<u8>>,
    },
    ZeroRttKeysReady {
        secret: Digest,
        max_early_data: u32,
        alpn: Option<Vec<u8>>,
    },
    EarlyDataAccepted,
    EarlyDataRejected,
    Done,
}

impl Event {
    pub fn into_restore(self) -> Option<Restore<'static>> {
        let Self::NewSessionTicket {
            ticket_lifetime,
            ticket_age_add,
            ticket,
            psk,
            max_early_data,
            suite,
            transport_mode,
            alpn,
        } = self
        else {
            return None;
        };
        let restore = Restore::try_new(psk, ticket, ticket_age_add, 0, ticket_lifetime).ok()?;
        match max_early_data {
            Some(maximum) => restore
                .try_with_early_data(
                    maximum,
                    suite,
                    transport_mode,
                    alpn.map_or(NegotiatedAlpn::Absent, |protocol| {
                        NegotiatedAlpn::Protocol(protocol.into())
                    }),
                )
                .ok(),
            None => Some(restore),
        }
    }
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
            connection::Event::NewSessionTicket(ticket) => {
                let suite = ticket.cipher_suite();
                let transport_mode = ticket.transport_mode();
                let alpn = ticket.alpn().map(<[u8]>::to_vec);
                let resumption = ticket.try_retain().unwrap();
                Event::NewSessionTicket {
                    ticket_lifetime: resumption.ticket_lifetime_secs(),
                    ticket_age_add: resumption.ticket_age_add(),
                    ticket: resumption.ticket().to_vec(),
                    psk: *resumption.psk().as_array(),
                    max_early_data: resumption.max_early_data(),
                    suite,
                    transport_mode,
                    alpn,
                }
            }
            connection::Event::ZeroRttKeysReady {
                secret,
                max_early_data,
                alpn,
            } => Event::ZeroRttKeysReady {
                secret: Digest::try_from_slice(secret.as_slice()).unwrap(),
                max_early_data,
                alpn: alpn.map(<[u8]>::to_vec),
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

pub trait CollectServerEvents {
    fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error>;
}

impl<C, G, V, const DOMAIN: u8> CollectServerEvents for server::Connection<'_, C, G, V, DOMAIN>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        collect(|events| self.read_into(epoch, data, events))
    }
}

impl<C, G, V, const DOMAIN: u8> CollectServerEvents for server::OwnedConnection<C, G, V, DOMAIN>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        collect(|events| self.read_into(epoch, data, events))
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

enum Policy<C, G, V>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    Configured(server::OwnedConnection<C, G, V>),
    Default(server::OwnedConnection<C>),
}

impl<C, G, V> Policy<C, G, V>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn read(
        &mut self,
        epoch: Epoch,
        data: &[u8],
        events: &mut Events,
    ) -> Result<(), DriveError<Infallible>> {
        match self {
            Self::Configured(connection) => connection.read_into(epoch, data, events),
            Self::Default(connection) => connection.read_into(epoch, data, events),
        }
    }

    fn server(&self) -> &server::Server<C> {
        match self {
            Self::Configured(connection) => connection,
            Self::Default(connection) => connection,
        }
    }

    fn note_early_data(&mut self, len: usize) -> Result<(), Error> {
        match self {
            Self::Configured(connection) => connection.note_early_data(len),
            Self::Default(connection) => connection.note_early_data(len),
        }
    }

    fn key_updates(&mut self) -> server::Updates<'_, C, 0> {
        match self {
            Self::Configured(connection) => connection.key_updates(),
            Self::Default(connection) => connection.key_updates(),
        }
    }

    fn selected_alpn(&self) -> Option<&[u8]> {
        match self {
            Self::Configured(connection) => connection.selected_alpn(),
            Self::Default(connection) => connection.selected_alpn(),
        }
    }
}

pub struct Server<C, G = NoGuard, V = NoClientAuth>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    policy: Policy<C, G, V>,
}

impl<C: Clock> Server<C> {
    pub fn new(config: ServerConfig, clock: C) -> Self {
        Self::new_with_transport(config, Mode::Tls, clock)
    }

    pub fn new_with_transport(config: ServerConfig, transport_mode: Mode, clock: C) -> Self {
        let (shard_config, connection_config, _) = config.split();
        Self::configured(
            connection_config,
            transport_mode,
            clock,
            Shard::new(shard_config).unwrap(),
        )
    }
}

impl<C, G> Server<C, G>
where
    C: Clock,
    G: EarlyDataGuard,
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
        let policy = if accept_early_data {
            Self::bind_configured(
                connection_config,
                transport_mode,
                clock,
                Shard::with_early_data_guard_in_replay_domain(shard_config, replay_domain(), guard)
                    .unwrap(),
            )
        } else {
            Self::bind_default(
                connection_config,
                transport_mode,
                clock,
                Shard::new(shard_config).unwrap(),
            )
        };
        Self { policy }
    }
}

impl<C, V> Server<C, NoGuard, ClientAuthVerifier<V>>
where
    C: Clock,
    V: ClientCertVerifier,
{
    pub fn with_client_auth(config: ServerConfig, clock: C, mode: ClientAuth, verifier: V) -> Self {
        let (shard_config, connection_config, _) = config.split();
        Self::configured(
            connection_config,
            Mode::Tls,
            clock,
            Shard::with_client_auth(shard_config, mode, verifier).unwrap(),
        )
    }
}

impl<C, G, V> Server<C, G, V>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn bind_configured(
        connection_config: Connection,
        transport_mode: Mode,
        clock: C,
        shard: Shard<G, V>,
    ) -> Policy<C, G, V> {
        let server =
            server::Server::new_with_transport(connection_config, transport_mode, clock).unwrap();
        Policy::Configured(server::OwnedConnection::new(server, shard).unwrap())
    }

    fn bind_default(
        connection_config: Connection,
        transport_mode: Mode,
        clock: C,
        shard: Shard,
    ) -> Policy<C, G, V> {
        let server =
            server::Server::new_with_transport(connection_config, transport_mode, clock).unwrap();
        Policy::Default(server::OwnedConnection::new(server, shard).unwrap())
    }

    fn configured(
        connection_config: Connection,
        transport_mode: Mode,
        clock: C,
        shard: Shard<G, V>,
    ) -> Self {
        Self {
            policy: Self::bind_configured(connection_config, transport_mode, clock, shard),
        }
    }

    pub fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        collect(|events| self.policy.read(epoch, data, events))
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.policy.selected_alpn()
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), Error> {
        self.policy.note_early_data(len)
    }

    pub fn key_updates(&mut self) -> server::Updates<'_, C, 0> {
        self.policy.key_updates()
    }
}

impl<C, G, V> Deref for Server<C, G, V>
where
    C: Clock,
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    type Target = server::Server<C>;

    fn deref(&self) -> &Self::Target {
        self.policy.server()
    }
}
