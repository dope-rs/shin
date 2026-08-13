use crate::connection;
use crate::crypto::ticket;
use crate::memory::threadbound;
use crate::server::{self, config, workspace};
use crate::transport;
use crate::wire::{handshake, protocols};
use alloc::rc;
use core::{cell, marker, ops};

struct Domain<const DOMAIN: u8>;

#[repr(transparent)]
pub(in crate::server) struct Authority<G, V, const DOMAIN: u8> {
    core: rc::Rc<AuthorityCore<G, V>>,
    _domain: marker::PhantomData<fn() -> Domain<DOMAIN>>,
}

pub(in crate::server) struct AuthorityCore<G, V> {
    pub(in crate::server) source: config::CertSource,
    pub(in crate::server) alpn: protocols::PreparedAlpn,
    pub(in crate::server) ticket_keys: cell::RefCell<Option<ticket::Keys>>,
    pub(in crate::server) guard: G,
    pub(in crate::server) client_auth: Option<config::ClientAuth>,
    pub(in crate::server) verifier: V,
    pub(in crate::server) replay_domain: server::ReplayDomain,
    pub(in crate::server) flight: config::FlightProfile,
}

impl<G, V, const DOMAIN: u8> ops::Deref for Authority<G, V, DOMAIN> {
    type Target = AuthorityCore<G, V>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<G, V, const DOMAIN: u8> Clone for Authority<G, V, DOMAIN> {
    fn clone(&self) -> Self {
        Self {
            core: rc::Rc::clone(&self.core),
            _domain: marker::PhantomData,
        }
    }
}

impl<G, V, const DOMAIN: u8> Authority<G, V, DOMAIN> {
    pub(in crate::server) fn outbound_layout(
        &self,
        transport_mode: transport::Mode,
        transport_parameters_len: usize,
    ) -> Result<connection::OutboundLayout, connection::Error> {
        self.flight
            .outbound_layout(transport_mode, transport_parameters_len)
            .ok_or(connection::Error::BadConfig)
    }

    pub(in crate::server) fn ptr_eq(&self, other: &Self) -> bool {
        rc::Rc::ptr_eq(&self.core, &other.core)
    }

    #[cfg(test)]
    pub(in crate::server) fn strong_count(&self) -> usize {
        rc::Rc::strong_count(&self.core)
    }
}

/// Validated server authority before its one-time domain binding.
///
/// Only a domain-bound [`Shard`] can admit connections or create pool
/// profiles. Consuming this value binds its authority to exactly one domain.
///
/// ```compile_fail
/// use shin::server::PreparedShard;
///
/// fn bind_twice(prepared: PreparedShard) {
///     let _first = prepared.bind_domain::<1>();
///     let _second = prepared.bind_domain::<2>();
/// }
/// ```
#[repr(transparent)]
pub struct PreparedShard<
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
> {
    authority: rc::Rc<AuthorityCore<G, V>>,
    _thread: threadbound::ThreadBound,
}

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
/// Bound shards expose no relabel operation.
///
/// ```compile_fail
/// use shin::server::Shard;
/// use shin::server::config::{ClientCertVerifier, EarlyDataGuard};
///
/// fn relabel<G, V>(shard: Shard<G, V, 1>) -> Shard<G, V, 2>
/// where
///     G: EarlyDataGuard,
///     V: ClientCertVerifier,
/// {
///     shard.into_domain::<2>()
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
#[repr(transparent)]
pub struct Shard<
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
> {
    pub(in crate::server) authority: Authority<G, V, DOMAIN>,
    _thread: threadbound::ThreadBound,
}

impl PreparedShard<config::NoGuard, config::NoClientAuth> {
    /// Builds fully validated authority ready for one-time domain binding.
    pub fn new(config: config::Config) -> Result<Self, connection::Error> {
        Self::build(config, config::NoGuard, None, config::NoClientAuth, None)
    }
}

impl<G: config::EarlyDataGuard> PreparedShard<G, config::NoClientAuth> {
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

impl<V: config::ClientCertVerifier> PreparedShard<config::NoGuard, config::ClientAuthVerifier<V>> {
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

impl Shard<config::NoGuard, config::NoClientAuth> {
    /// Builds a fully validated shard bound directly to this domain.
    pub fn new(config: config::Config) -> Result<Self, connection::Error> {
        PreparedShard::new(config).map(PreparedShard::bind_domain)
    }
}

impl<G: config::EarlyDataGuard> Shard<G, config::NoClientAuth> {
    pub fn with_early_data_guard(
        config: config::Config,
        guard: G,
    ) -> Result<Self, connection::Error> {
        PreparedShard::with_early_data_guard(config, guard).map(PreparedShard::bind_domain)
    }

    pub fn with_early_data_guard_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
    ) -> Result<Self, connection::Error> {
        PreparedShard::with_early_data_guard_in_replay_domain(config, replay_domain, guard)
            .map(PreparedShard::bind_domain)
    }
}

impl<V: config::ClientCertVerifier> Shard<config::NoGuard, config::ClientAuthVerifier<V>> {
    pub fn with_client_auth(
        config: config::Config,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        PreparedShard::with_client_auth(config, mode, verifier).map(PreparedShard::bind_domain)
    }
}

impl<G: config::EarlyDataGuard, V: config::ClientCertVerifier, const DOMAIN: u8>
    Shard<G, V, DOMAIN>
{
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
    ///     let Ok(connection) = shard.bind(server).into_result() else { return };
    ///     shard.replace_ticket_keys(None);
    ///     drop(connection);
    /// }
    /// ```
    pub fn bind<C>(
        &mut self,
        server: server::Server<C, DOMAIN>,
    ) -> server::Binding<server::Connection<'_, C, G, V, DOMAIN>, server::Server<C, DOMAIN>>
    where
        C: connection::Clock,
    {
        server::Connection::new(server, self)
    }

    /// Binds a connection that can coexist with other connections admitted by
    /// this shard. The connection owns this exact authority after admission.
    pub fn bind_multiplexed<C>(
        &self,
        server: server::Server<C, DOMAIN>,
    ) -> server::Binding<server::MultiplexedConnection<C, DOMAIN, G, V>, server::Server<C, DOMAIN>>
    where
        C: connection::Clock,
    {
        if let Err(error) = server.validate_shard(self) {
            return server::Binding::rejected(error, server);
        }
        server::Binding::bound(server::MultiplexedConnection::new(
            server,
            self.authority.clone(),
        ))
    }

    /// Returns the exact fully reserved workspace plan for a TLS connection.
    pub fn tls_workspace_layout(&self) -> workspace::Layout<V> {
        workspace::Layout::new(
            self.authority.flight.tls_flight_len(),
            self.authority.flight.peer_identity_capacity::<V>(),
        )
    }

    /// Binds an exact reusable TLS admission profile to this shard instance.
    pub fn tls_profile(&self) -> workspace::Profile<V, DOMAIN, G> {
        workspace::Profile::new(self.tls_workspace_layout(), self.authority.clone())
    }

    /// Binds the authority to a pool whose embedder already frames QUIC
    /// handshake messages and owns connection-local transport parameters.
    pub fn quic_profile(
        &self,
        maximum_transport_params: usize,
    ) -> Result<workspace::QuicProfile<V, DOMAIN, G>, connection::Error> {
        self.authority
            .outbound_layout(transport::Mode::Quic, maximum_transport_params)?;
        Ok(workspace::QuicProfile::new(
            workspace::Layout::framed(0, self.authority.flight.peer_identity_capacity::<V>()),
            self.authority.clone(),
            maximum_transport_params,
        ))
    }

    /// Returns the exact fully reserved workspace plan for this connection.
    pub fn workspace_layout(
        &self,
        config: &config::Connection,
        transport_mode: transport::Mode,
    ) -> Result<workspace::Layout<V>, connection::Error> {
        config.validate_with_transport(transport_mode)?;
        let flight = self
            .authority
            .flight
            .flight_len(transport_mode, config.transport_params.len())
            .ok_or(connection::Error::BadConfig)?;
        Ok(workspace::Layout::new(
            flight,
            self.authority.flight.peer_identity_capacity::<V>(),
        ))
    }

    /// Constructs and binds a multiplexed connection with the reservation
    /// profile proved by this shard's client-auth type.
    pub fn new_multiplexed<C>(
        &self,
        config: config::Connection,
        transport_mode: transport::Mode,
        clock: C,
    ) -> Result<server::MultiplexedConnection<C, DOMAIN, G, V>, connection::Error>
    where
        C: connection::Clock,
    {
        let workspace = self.workspace_layout(&config, transport_mode)?.allocate();
        let server =
            server::Server::from_validated(config, transport_mode, clock, workspace.into_scratch());
        Ok(server::MultiplexedConnection::new(
            server,
            self.authority.clone(),
        ))
    }

    /// Constructs an owned QUIC connection with only peer-identity scratch;
    /// all outbound CRYPTO bytes live in the lending transport.
    pub fn new_quic<C>(
        &self,
        config: config::Connection,
        clock: C,
    ) -> Result<server::QuicConnection<C, DOMAIN, G, V>, connection::Error>
    where
        C: connection::Clock,
    {
        config.validate_with_transport(transport::Mode::Quic)?;
        self.authority
            .outbound_layout(transport::Mode::Quic, config.transport_params.len())?;
        let workspace =
            workspace::Layout::<V>::framed(0, self.authority.flight.peer_identity_capacity::<V>())
                .allocate();
        let server = server::Server::quic_with_workspace(clock, config.transport_params, workspace);
        Ok(server::QuicConnection::new(server, self.authority.clone()))
    }

    pub fn replace_ticket_keys(&self, keys: Option<ticket::Keys>) {
        *self.authority.ticket_keys.borrow_mut() = keys;
    }
}

impl<G: config::EarlyDataGuard, V: config::ClientCertVerifier> PreparedShard<G, V> {
    /// Consumes the unique prepared authority and binds it to one domain.
    pub fn bind_domain<const DOMAIN: u8>(self) -> Shard<G, V, DOMAIN> {
        Shard {
            authority: Authority {
                core: self.authority,
                _domain: marker::PhantomData,
            },
            _thread: self._thread,
        }
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
        if peer_identity_capacity > handshake::MAX_SIZE {
            return Err(connection::Error::BadConfig);
        }
        let config::Config {
            source,
            alpn_protocols,
            ticket_keys,
        } = config;
        let alpn = protocols::PreparedAlpn::prepare(alpn_protocols)
            .map_err(|()| connection::Error::BadConfig)?;
        let replay_domain = match replay_domain {
            Some(domain) => domain,
            None => server::ReplayDomain::random()?,
        };
        Ok(Self {
            authority: rc::Rc::new(AuthorityCore {
                source,
                alpn,
                ticket_keys: cell::RefCell::new(ticket_keys),
                guard,
                client_auth,
                verifier,
                replay_domain,
                flight,
            }),
            _thread: threadbound::ThreadBound::NEW,
        })
    }
}

impl<G: config::EarlyDataGuard, V: config::ClientCertVerifier>
    PreparedShard<G, config::ClientAuthVerifier<V>>
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

impl<G: config::EarlyDataGuard, V: config::ClientCertVerifier>
    Shard<G, config::ClientAuthVerifier<V>>
{
    pub fn with_early_data_guard_and_client_auth(
        config: config::Config,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        PreparedShard::with_early_data_guard_and_client_auth(config, guard, mode, verifier)
            .map(PreparedShard::bind_domain)
    }

    pub fn with_early_data_guard_and_client_auth_in_replay_domain(
        config: config::Config,
        replay_domain: server::ReplayDomain,
        guard: G,
        mode: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, connection::Error> {
        PreparedShard::with_early_data_guard_and_client_auth_in_replay_domain(
            config,
            replay_domain,
            guard,
            mode,
            verifier,
        )
        .map(PreparedShard::bind_domain)
    }
}
