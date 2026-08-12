use crate::connection;
use crate::crypto::ticket;
use crate::memory::threadbound;
use crate::server;
use crate::server::config;
use crate::wire::protocols;
use alloc::rc;

/// Per-core prepared server shard policy and replay guard.
///
/// ```compile_fail
/// use shin::server::Shard;
/// use shin::server::config::{ClientCertVerifier, EarlyDataGuard};
///
/// fn cross_domain<G, V>(shard: Shard<G, V, 1>) -> Shard<G, V, 2>
/// where
///     G: EarlyDataGuard,
///     V: ClientCertVerifier,
/// {
///     shard
/// }
/// ```
///
/// A server is statically tied to the same domain as its bound shard.
///
/// ```compile_fail
/// use shin::connection::Clock;
/// use shin::server::{Server, Shard};
/// use shin::server::config::{ClientCertVerifier, EarlyDataGuard};
///
/// fn drive_from_another_domain<C, G, V>(
///     server: Server<C, 1>,
///     shard: &mut Shard<G, V, 2>,
/// ) where
///     C: Clock,
///     G: EarlyDataGuard,
///     V: ClientCertVerifier,
/// {
///     let _ = shard.bind(server);
/// }
/// ```
pub struct Shard<
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
> {
    pub(in crate::server) policy: Policy<G, V>,
    pub(in crate::server) prepared: Prepared,
    _thread: threadbound::ThreadBound,
}

pub(in crate::server) struct Policy<G, V> {
    pub(in crate::server) source: config::CertSource,
    pub(in crate::server) alpn: rc::Rc<protocols::PreparedAlpn>,
    pub(in crate::server) ticket_keys: Option<ticket::Keys>,
    pub(in crate::server) guard: G,
    pub(in crate::server) client_auth: Option<config::ClientAuth>,
    pub(in crate::server) verifier: V,
}

pub(in crate::server) struct Prepared {
    pub(in crate::server) replay_domain: server::ReplayDomain,
    pub(in crate::server) flight: config::FlightProfile,
}

impl Shard<config::NoGuard, config::NoClientAuth> {
    /// Builds a fully validated shard prepared for connection preflight.
    pub fn new(config: config::Config) -> Result<Self, connection::Error> {
        Self::build(config, config::NoGuard, None, config::NoClientAuth, None)
    }
}

impl<G: config::EarlyDataGuard> Shard<G, config::NoClientAuth> {
    pub fn with_early_data_guard(
        config: config::Config,
        guard: G,
    ) -> Result<Self, connection::Error> {
        Self::build(config, guard, None, config::NoClientAuth, None)
    }

    pub fn with_early_data_guard_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
    ) -> Result<Self, connection::Error> {
        Self::build(
            config,
            guard,
            None,
            config::NoClientAuth,
            Some(replay_domain),
        )
    }
}

impl<V: config::ClientCertVerifier> Shard<config::NoGuard, config::ClientAuthVerifier<V>> {
    pub fn with_client_auth(
        config: config::Config,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        Self::build(
            config,
            config::NoGuard,
            Some(mode),
            config::ClientAuthVerifier::new(verifier),
            None,
        )
    }
}

impl<G: config::EarlyDataGuard, V: config::ClientCertVerifier, const DOMAIN: u8>
    Shard<G, V, DOMAIN>
{
    /// Relabels this prepared shard before it accepts connections.
    pub fn into_domain<const TARGET: u8>(self) -> Shard<G, V, TARGET> {
        Shard {
            policy: self.policy,
            prepared: self.prepared,
            _thread: self._thread,
        }
    }

    /// Binds one server to this shard for the server's entire remaining
    /// lifetime. Policy and exact flight bounds are validated once here.
    ///
    /// The shard cannot be mutated while its connection is alive:
    ///
    /// ```compile_fail
    /// use shin::connection::Clock;
    /// use shin::server::{Server, Shard};
    /// use shin::server::config::{ClientCertVerifier, EarlyDataGuard};
    ///
    /// fn rotate_mid_connection<C, G, V>(server: Server<C>, shard: &mut Shard<G, V>)
    /// where
    ///     C: Clock,
    ///     G: EarlyDataGuard,
    ///     V: ClientCertVerifier,
    /// {
    ///     let Ok(connection) = shard.bind(server) else { return };
    ///     shard.replace_ticket_keys(None);
    ///     drop(connection);
    /// }
    /// ```
    pub fn bind<C>(
        &mut self,
        server: server::Server<C, DOMAIN>,
    ) -> Result<server::Connection<'_, C, G, V, DOMAIN>, connection::Error>
    where
        C: connection::Clock,
    {
        server::Connection::new(server, self)
    }

    /// Binds a connection that can coexist with other connections admitted by
    /// this shard. Every drive verifies the exact admitting shard instance.
    pub fn bind_multiplexed<C>(
        &self,
        server: server::Server<C, DOMAIN>,
    ) -> Result<server::MultiplexedConnection<C, DOMAIN>, connection::Error>
    where
        C: connection::Clock,
    {
        server.validate_shard(self)?;
        Ok(server::MultiplexedConnection::new(
            server,
            rc::Rc::clone(&self.policy.alpn),
        ))
    }

    /// Returns the exact fully reserved workspace plan for a TLS connection.
    pub fn tls_workspace_layout(&self) -> server::WorkspaceLayout<V> {
        server::WorkspaceLayout::new(
            self.prepared.flight.tls_flight_len(),
            self.prepared.flight.peer_identity_capacity::<V>(),
        )
    }

    /// Returns the exact fully reserved workspace plan for this connection.
    pub fn workspace_layout(
        &self,
        config: &config::Connection,
        transport_mode: crate::transport::Mode,
    ) -> Result<server::WorkspaceLayout<V>, connection::Error> {
        config.validate_with_transport(transport_mode)?;
        let flight = self
            .prepared
            .flight
            .flight_len(transport_mode, config.transport_params.len())
            .ok_or(connection::Error::BadConfig)?;
        Ok(server::WorkspaceLayout::new(
            flight,
            self.prepared.flight.peer_identity_capacity::<V>(),
        ))
    }

    /// Constructs and binds a multiplexed connection with the reservation
    /// profile proved by this shard's client-auth type.
    pub fn new_multiplexed<C>(
        &self,
        config: config::Connection,
        transport_mode: crate::transport::Mode,
        clock: C,
    ) -> Result<server::MultiplexedConnection<C, DOMAIN>, connection::Error>
    where
        C: connection::Clock,
        V: server::WorkspaceProfile,
    {
        let workspace = self.workspace_layout(&config, transport_mode)?.allocate();
        let server =
            server::Server::from_validated(config, transport_mode, clock, workspace.into_scratch());
        Ok(server::MultiplexedConnection::new(
            server,
            rc::Rc::clone(&self.policy.alpn),
        ))
    }

    /// Admits an allocation-free TLS connection using an opaque, fully
    /// reserved workspace. Pool initialization binds the exact layout once;
    /// its lease keeps that layout alive with the connection.
    #[doc(hidden)]
    pub fn tls_with_workspace<C>(
        &self,
        clock: C,
        workspace: server::Workspace<V>,
    ) -> server::PooledConnection<C, DOMAIN, V>
    where
        C: connection::Clock,
    {
        let server = server::Server::tls_with_workspace(clock, workspace);
        server::PooledConnection::new(server, rc::Rc::clone(&self.policy.alpn))
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<ticket::Keys>) {
        self.policy.ticket_keys = keys;
    }

    fn build(
        config: config::Config,
        guard: G,
        client_auth: Option<config::ClientAuth>,
        verifier: V,
        replay_domain: Option<server::ReplayDomain>,
    ) -> Result<Self, connection::Error> {
        let flight = config.prepare_for(client_auth.is_some(), G::ACCEPTS_EARLY_DATA)?;
        let peer_identity_capacity = flight.peer_identity_capacity::<V>();
        if peer_identity_capacity > crate::wire::handshake::MAX_SIZE {
            return Err(connection::Error::BadConfig);
        }
        let config::Config {
            source,
            alpn_protocols,
            ticket_keys,
        } = config;
        let alpn = rc::Rc::new(
            protocols::PreparedAlpn::prepare(alpn_protocols)
                .map_err(|()| connection::Error::BadConfig)?,
        );
        let replay_domain = match replay_domain {
            Some(domain) => domain,
            None => server::ReplayDomain::random()?,
        };
        Ok(Self {
            policy: Policy {
                source,
                alpn,
                ticket_keys,
                guard,
                client_auth,
                verifier,
            },
            prepared: Prepared {
                replay_domain,
                flight,
            },
            _thread: threadbound::ThreadBound::NEW,
        })
    }
}

impl<G: config::EarlyDataGuard, V: config::ClientCertVerifier, const DOMAIN: u8>
    Shard<G, config::ClientAuthVerifier<V>, DOMAIN>
{
    pub fn with_early_data_guard_and_client_auth(
        config: config::Config,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        Self::build(
            config,
            guard,
            Some(mode),
            config::ClientAuthVerifier::new(verifier),
            None,
        )
    }

    /// Shares a domain only when the guard shares its replay store.
    pub fn with_early_data_guard_and_client_auth_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        Self::build(
            config,
            guard,
            Some(mode),
            config::ClientAuthVerifier::new(verifier),
            Some(replay_domain),
        )
    }
}
