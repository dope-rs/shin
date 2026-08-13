use crate::connection;
use crate::server;
use crate::server::config;
use crate::wire::handshake;
use crate::wire::handshake::storage;
use crate::wire::record;
use alloc::vec::Vec;
use core::{marker, mem};
use o3::collections::slab::{self, recycle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Capacities {
    fragmented_message: usize,
    outbound_flight: usize,
    peer_identity: usize,
}

/// Exact, validated reservation plan for one server connection.
pub struct Layout<V: config::ClientCertVerifier = config::NoClientAuth> {
    capacities: Capacities,
    _profile: marker::PhantomData<fn(V) -> V>,
}

impl<V: config::ClientCertVerifier> Copy for Layout<V> {}

impl<V: config::ClientCertVerifier> Clone for Layout<V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: config::ClientCertVerifier> Layout<V> {
    pub(super) fn new(outbound_flight: usize, peer_identity: usize) -> Self {
        let one_record = record::MAX_PLAINTEXT_BODY;
        Self {
            capacities: Capacities {
                fragmented_message: one_record.max(peer_identity),
                outbound_flight: one_record.max(outbound_flight),
                peer_identity,
            },
            _profile: marker::PhantomData,
        }
    }

    pub(in crate::server) fn framed(outbound_flight: usize, peer_identity: usize) -> Self {
        Self {
            capacities: Capacities {
                fragmented_message: 0,
                outbound_flight,
                peer_identity,
            },
            _profile: marker::PhantomData,
        }
    }

    /// Allocates every byte described by this plan before admission.
    pub fn allocate(self) -> Workspace<V> {
        Workspace::new(storage::Scratch::new(
            self.capacities.fragmented_message,
            self.capacities.outbound_flight,
            self.capacities.peer_identity,
        ))
    }

    pub fn capacities(self) -> (usize, usize, usize) {
        (
            self.capacities.fragmented_message,
            self.capacities.outbound_flight,
            self.capacities.peer_identity,
        )
    }
}

impl<V: config::ClientCertVerifier> PartialEq for Layout<V> {
    fn eq(&self, other: &Self) -> bool {
        self.capacities == other.capacities
    }
}

impl<V: config::ClientCertVerifier> Eq for Layout<V> {}

/// Opaque, fully reserved storage for one validated server profile.
///
/// ```compile_fail
/// use shin::server::{config, workspace::Workspace};
///
/// struct Verifier;
/// impl config::ClientCertVerifier for Verifier {
///     fn verify(&self, _: &config::ClientIdentity<'_>) -> bool { true }
/// }
///
/// fn erase(
///     workspace: Workspace<config::ClientAuthVerifier<Verifier>>,
/// ) -> Workspace {
///     workspace
/// }
/// ```
///
/// ```compile_fail
/// use shin::server::workspace::Workspace;
/// use shin::wire::handshake::storage::Scratch;
///
/// fn bypass(scratch: Scratch) -> Workspace {
///     scratch
/// }
/// ```
pub struct Workspace<V: config::ClientCertVerifier = config::NoClientAuth> {
    scratch: storage::Scratch,
    _profile: marker::PhantomData<fn(V) -> V>,
}

impl<V: config::ClientCertVerifier> Workspace<V> {
    pub(super) fn new(scratch: storage::Scratch) -> Self {
        Self {
            scratch,
            _profile: marker::PhantomData,
        }
    }

    pub(super) fn into_scratch(self) -> storage::Scratch {
        self.scratch
    }
}

const _: () = assert!(mem::size_of::<Workspace>() == mem::size_of::<storage::Scratch>());
const _: () = assert!(record::MAX_PLAINTEXT_BODY <= handshake::MAX_SIZE);

/// Exact TLS pool profile bound to one shard instance.
pub struct Profile<
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
> {
    layout: Layout<V>,
    authority: server::Authority<G, V, DOMAIN>,
}

/// Exact QUIC profile for already-framed handshake messages.
pub struct QuicProfile<
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
> {
    layout: Layout<V>,
    authority: server::Authority<G, V, DOMAIN>,
    transport_params_capacity: usize,
}

impl<G, V, const DOMAIN: u8> Profile<V, DOMAIN, G>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(super) fn new(layout: Layout<V>, authority: server::Authority<G, V, DOMAIN>) -> Self {
        Self { layout, authority }
    }

    /// Creates a fixed pool that owns this authority exactly once.
    pub fn into_pool<C: connection::Clock>(
        self,
        capacity: slab::Capacity,
    ) -> Pool<C, V, DOMAIN, G> {
        let layout = self.layout;
        let slots = recycle::Pool::with_capacity(capacity, || layout.allocate());
        Pool {
            profile: self,
            slots,
        }
    }

    pub fn capacities(&self) -> (usize, usize, usize) {
        self.layout.capacities()
    }
}

impl<G, V, const DOMAIN: u8> QuicProfile<V, DOMAIN, G>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(super) fn new(
        layout: Layout<V>,
        authority: server::Authority<G, V, DOMAIN>,
        transport_params_capacity: usize,
    ) -> Self {
        Self {
            layout,
            authority,
            transport_params_capacity,
        }
    }

    pub fn into_pool<C: connection::Clock>(
        self,
        capacity: slab::Capacity,
    ) -> QuicPool<C, V, DOMAIN, G> {
        let layout = self.layout;
        let transport_params_capacity = self.transport_params_capacity;
        let slots = recycle::Pool::with_capacity(capacity, || QuicSeed {
            workspace: layout.allocate(),
            transport_params: Vec::with_capacity(transport_params_capacity),
        });
        QuicPool {
            profile: self,
            transport_params_capacity,
            slots,
        }
    }

    pub fn capacities(&self) -> (usize, usize, usize) {
        self.layout.capacities()
    }
}

impl<G, V, const DOMAIN: u8> PartialEq for Profile<V, DOMAIN, G>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    fn eq(&self, other: &Self) -> bool {
        self.layout == other.layout && self.authority.ptr_eq(&other.authority)
    }
}

impl<G, V, const DOMAIN: u8> Eq for Profile<V, DOMAIN, G>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
}

/// Fixed server pool whose active connections borrow one shared authority.
pub struct Pool<
    C: connection::Clock,
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
> {
    profile: Profile<V, DOMAIN, G>,
    slots: recycle::Pool<Stored<C, V, DOMAIN>>,
}

/// Fixed QUIC server pool whose active handshakes borrow one authority.
pub struct QuicPool<
    C: connection::Clock,
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
> {
    profile: QuicProfile<V, DOMAIN, G>,
    transport_params_capacity: usize,
    slots: recycle::Pool<QuicStored<C, V, DOMAIN>>,
}

pub struct QuicReservation<
    'pool,
    C: connection::Clock,
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
> {
    pool: &'pool QuicPool<C, V, DOMAIN, G>,
    vacant: recycle::VacantEntry<'pool, QuicStored<C, V, DOMAIN>>,
}

pub(in crate::server) struct QuicSeed<V: config::ClientCertVerifier> {
    workspace: Workspace<V>,
    transport_params: Vec<u8>,
}

impl<C, G, V, const DOMAIN: u8> Pool<C, V, DOMAIN, G>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    /// Borrows this pool's authority for exactly one recyclable lease.
    pub fn connect(&self, clock: C) -> Option<server::PooledConnection<'_, C, DOMAIN, V, G>> {
        let vacant = self.slots.vacant_entry()?;
        let lease = vacant.insert_with(|workspace| Stored {
            server: server::Server::tls_with_workspace(clock, workspace),
            _profile: marker::PhantomData,
        });
        Some(server::PooledConnection::new(
            lease,
            &self.profile.authority,
        ))
    }

    /// Checks an already initialized pool without cloning its authority.
    pub fn matches_shard(&self, shard: &server::Shard<G, V, DOMAIN>) -> bool {
        self.profile.layout == shard.tls_workspace_layout()
            && self.profile.authority.ptr_eq(&shard.authority)
    }

    pub fn capacities(&self) -> (usize, usize, usize) {
        self.profile.capacities()
    }
}

impl<C, G, V, const DOMAIN: u8> QuicPool<C, V, DOMAIN, G>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub fn reserve(&self) -> Option<QuicReservation<'_, C, V, DOMAIN, G>> {
        let mut vacant = self.slots.vacant_entry()?;
        vacant.seed_mut().transport_params.clear();
        Some(QuicReservation { pool: self, vacant })
    }

    pub fn capacities(&self) -> (usize, usize, usize, usize) {
        let (reassembly, flight, identity) = self.profile.capacities();
        (reassembly, flight, identity, self.transport_params_capacity)
    }

    pub fn matches_shard(&self, shard: &server::Shard<G, V, DOMAIN>) -> bool {
        self.profile.authority.ptr_eq(&shard.authority)
    }
}

impl<'pool, C, G, V, const DOMAIN: u8> QuicReservation<'pool, C, V, DOMAIN, G>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub fn transport_params(&mut self) -> connection::RetainedBytes<'_> {
        connection::RetainedBytes::new(
            &mut self.vacant.seed_mut().transport_params,
            self.pool.transport_params_capacity,
        )
    }

    pub fn connect(self, clock: C) -> server::QuicPooledConnection<'pool, C, DOMAIN, V, G> {
        let pool = self.pool;
        let lease = self.vacant.insert_with(|seed| QuicStored {
            server: server::Server::quic_with_workspace(
                clock,
                seed.transport_params,
                seed.workspace,
            ),
            _profile: marker::PhantomData,
        });
        server::QuicPooledConnection::new(lease, &pool.profile.authority)
    }
}

pub(in crate::server) struct Stored<
    C: connection::Clock,
    V: config::ClientCertVerifier,
    const DOMAIN: u8,
> {
    pub(in crate::server) server: server::Server<C, DOMAIN>,
    _profile: marker::PhantomData<fn(V) -> V>,
}

pub(in crate::server) struct QuicStored<
    C: connection::Clock,
    V: config::ClientCertVerifier,
    const DOMAIN: u8,
> {
    pub(in crate::server) server: server::QuicServer<C, DOMAIN>,
    _profile: marker::PhantomData<fn(V) -> V>,
}

impl<C, V, const DOMAIN: u8> recycle::Recycle for Stored<C, V, DOMAIN>
where
    C: connection::Clock,
    V: config::ClientCertVerifier,
{
    type Seed = Workspace<V>;

    fn into_seed(self) -> Self::Seed {
        Workspace::new(self.server.into_workspace())
    }
}

impl<C, V, const DOMAIN: u8> recycle::Recycle for QuicStored<C, V, DOMAIN>
where
    C: connection::Clock,
    V: config::ClientCertVerifier,
{
    type Seed = QuicSeed<V>;

    fn into_seed(mut self) -> Self::Seed {
        let mut transport_params = mem::take(&mut self.server.session.connection.transport_params);
        transport_params.clear();
        QuicSeed {
            workspace: Workspace::new(self.server.into_workspace()),
            transport_params,
        }
    }
}

const _: () = assert!(
    mem::size_of::<Stored<fn() -> u64, config::NoClientAuth, 0>>()
        == mem::size_of::<server::Server<fn() -> u64>>()
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sig::SigningKey;
    use crate::server::config::{CertSource, Config};

    fn now() -> u64 {
        0
    }

    #[test]
    fn pool_and_connections_share_exactly_one_authority_owner() {
        let shard = server::Shard::new(Config {
            source: CertSource::RawPublicKey {
                signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
            },
            alpn_protocols: alloc::vec::Vec::new(),
            ticket_keys: None,
        })
        .unwrap();
        assert_eq!(shard.authority.strong_count(), 1);

        let profile = shard.tls_profile();
        assert_eq!(shard.authority.strong_count(), 2);

        let pool = profile.into_pool::<fn() -> u64>(slab::Capacity::try_from(64).unwrap());
        assert_eq!(shard.authority.strong_count(), 2);

        let connection = pool.connect(now as fn() -> u64).unwrap();
        assert_eq!(shard.authority.strong_count(), 2);
        drop(connection);
        assert_eq!(shard.authority.strong_count(), 2);

        drop(pool);
        assert_eq!(shard.authority.strong_count(), 1);
    }
}
