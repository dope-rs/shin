#![allow(dead_code)]

use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use ring::rand::{SecureRandom, SystemRandom};

use shin::server::{
    CertSource, ClientAuth, ClientCertVerifier, Config as ShardConfig, ConnectionConfig,
    EarlyDataGuard, NoClientAuth, NoGuard, Server as Connection, Shard,
};
use shin::sig::SigningKey;
use shin::ticket::TicketKeys;
use shin::{Clock, Epoch, Error, Event};

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
    pub ticket_keys: Option<TicketKeys>,
    pub accept_early_data: bool,
}

impl ServerConfig {
    fn split(self) -> (ShardConfig, ConnectionConfig, bool) {
        (
            ShardConfig {
                source: self.source,
                alpn_protocols: self.alpn_protocols,
                ticket_keys: self.ticket_keys,
            },
            ConnectionConfig {
                transport_params: self.transport_params,
            },
            self.accept_early_data,
        )
    }

    pub fn validate(self) -> Result<(), Error> {
        let (shard, connection, _) = self.split();
        shard.validate()?;
        connection.validate()
    }
}

trait Policy<C: Clock> {
    fn read(
        &mut self,
        connection: &mut Connection<C>,
        epoch: Epoch,
        data: &[u8],
    ) -> Result<Vec<Event>, Error>;
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
        connection: &mut Connection<C>,
        epoch: Epoch,
        data: &[u8],
    ) -> Result<Vec<Event>, Error> {
        connection.read(epoch, data, &mut self.0)
    }
}

pub struct Server<C: Clock, G = NoGuard, V = NoClientAuth> {
    connection: Connection<C>,
    policy: Box<dyn Policy<C>>,
    _types: PhantomData<fn() -> (G, V)>,
}

impl<C: Clock> Server<C> {
    pub fn new(config: ServerConfig, clock: C) -> Self {
        let (shard_config, connection_config, _) = config.split();
        Self::build(
            connection_config,
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
        let (shard_config, connection_config, accept_early_data) = config.split();
        let connection = Connection::new(connection_config, clock);
        let policy: Box<dyn Policy<C>> = if accept_early_data {
            Box::new(OwnedShard(Shard::with_early_data_guard(
                shard_config,
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
            clock,
            OwnedShard(Shard::with_client_auth(shard_config, mode, verifier)),
        )
    }
}

impl<C: Clock, G, V> Server<C, G, V> {
    fn build<P>(connection_config: ConnectionConfig, clock: C, policy: P) -> Self
    where
        P: Policy<C> + 'static,
    {
        Self {
            connection: Connection::new(connection_config, clock),
            policy: Box::new(policy),
            _types: PhantomData,
        }
    }

    pub fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        self.policy.read(&mut self.connection, epoch, data)
    }
}

impl<C: Clock, G, V> Deref for Server<C, G, V> {
    type Target = Connection<C>;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl<C: Clock, G, V> DerefMut for Server<C, G, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}
