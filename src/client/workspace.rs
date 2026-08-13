use crate::client::{self, config};
use crate::connection;
use crate::wire::handshake::storage;
use crate::wire::record;
use alloc::vec::Vec;
use core::{cell, error, fmt, mem};
use o3::collections::slab::{self, recycle};

/// Exact reservation plan for one client handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    fragmented_message: usize,
    outbound_flight: usize,
}

impl Layout {
    const fn new(fragmented_message: usize, outbound_flight: usize) -> Self {
        Self {
            fragmented_message,
            outbound_flight,
        }
    }

    pub(crate) fn prepared(maximum_certificate_message: usize, outbound_flight: usize) -> Self {
        Self::new(
            maximum_certificate_message.max(record::MAX_PLAINTEXT_BODY),
            outbound_flight.max(record::MAX_PLAINTEXT_BODY),
        )
    }

    pub(in crate::client) const fn framed(peer_identity: usize) -> Self {
        Self::new(0, peer_identity)
    }

    /// Allocates every byte described by this plan before construction.
    pub fn allocate(self) -> Workspace {
        Workspace {
            reassembly: storage::BoundedBuffer::with_capacity(self.fragmented_message),
            flight: storage::BoundedBuffer::with_capacity(self.outbound_flight),
        }
    }

    pub const fn capacities(self) -> (usize, usize) {
        (self.fragmented_message, self.outbound_flight)
    }

    pub(in crate::client) fn admit(self, workspace: Workspace) -> Result<Workspace, Rejection> {
        let actual = workspace.layout();
        if actual.fragmented_message < self.fragmented_message
            || actual.outbound_flight < self.outbound_flight
        {
            return Err(Rejection {
                required: self,
                workspace,
            });
        }
        Ok(workspace)
    }
}

/// Capacity mismatch detected before a client can enter the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mismatch {
    required: Layout,
    actual: Layout,
}

impl Mismatch {
    pub const fn required(self) -> Layout {
        self.required
    }

    pub const fn actual(self) -> Layout {
        self.actual
    }
}

impl fmt::Display for Mismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (required_reassembly, required_flight) = self.required.capacities();
        let (actual_reassembly, actual_flight) = self.actual.capacities();
        write!(
            formatter,
            "client workspace capacities ({actual_reassembly}, {actual_flight}) are smaller than required ({required_reassembly}, {required_flight})"
        )
    }
}

impl error::Error for Mismatch {}

/// Rejected workspace together with the allocation that remains reusable.
pub struct Rejection {
    required: Layout,
    workspace: Workspace,
}

impl Rejection {
    pub const fn mismatch(&self) -> Mismatch {
        Mismatch {
            required: self.required,
            actual: self.workspace.layout(),
        }
    }

    pub fn into_parts(self) -> (Mismatch, Workspace) {
        let mismatch = self.mismatch();
        (mismatch, self.workspace)
    }
}

impl fmt::Debug for Rejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.mismatch().fmt(formatter)
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.mismatch().fmt(formatter)
    }
}

impl error::Error for Rejection {}

/// Opaque, fully reserved storage for one client handshake.
pub struct Workspace {
    pub(crate) reassembly: storage::BoundedBuffer,
    pub(crate) flight: storage::BoundedBuffer,
}

impl Workspace {
    pub(crate) fn from_buffers(
        mut reassembly: storage::BoundedBuffer,
        mut flight: storage::BoundedBuffer,
    ) -> Self {
        reassembly.clear();
        flight.clear();
        Self { reassembly, flight }
    }

    pub fn capacities(&self) -> (usize, usize) {
        (self.reassembly.capacity(), self.flight.capacity())
    }

    const fn layout(&self) -> Layout {
        Layout::new(self.reassembly.capacity(), self.flight.capacity())
    }
}

const _: () = assert!(mem::size_of::<Workspace>() == 2 * mem::size_of::<storage::BoundedBuffer>());

/// Fixed client pool whose active connections borrow one endpoint policy.
pub struct Pool<C: connection::Clock> {
    authority: config::Authority,
    first: cell::Cell<Option<config::resumptions::Active>>,
    enable_early_data: bool,
    slots: recycle::Pool<Stored<C>>,
}

/// Fixed pool for transports that already frame handshake messages.
pub struct FramedPool<C: connection::Clock> {
    authority: config::Authority,
    layout: Layout,
    first: cell::Cell<Option<config::resumptions::Active>>,
    enable_early_data: bool,
    transport_params_capacity: usize,
    slots: recycle::Pool<FramedStored<C>>,
}

/// Exclusive admission reservation exposing its retained transport-parameter
/// buffer before infallible connection construction.
pub struct FramedReservation<'pool, C: connection::Clock> {
    pool: &'pool FramedPool<C>,
    vacant: recycle::VacantEntry<'pool, FramedStored<C>>,
    resumption: Option<config::resumptions::Active>,
}

pub(in crate::client) struct FramedSeed {
    workspace: Workspace,
    transport_params: Vec<u8>,
}

impl<C: connection::Clock> Pool<C> {
    pub(in crate::client) fn new(
        prepared: config::Prepared,
        identity: Option<config::IdentityTemplate>,
        capacity: slab::Capacity,
    ) -> Self {
        let config::Prepared {
            template,
            resumption,
            enable_early_data,
        } = prepared;
        let authority = config::Authority::new(template, identity);
        let layout = authority.workspace_layout();
        Self {
            authority,
            first: cell::Cell::new(resumption),
            enable_early_data,
            slots: recycle::Pool::with_capacity(capacity, || layout.allocate()),
        }
    }

    /// Borrows this pool's policy for exactly one recyclable lease.
    pub fn connect(&self, clock: C) -> Option<client::PooledConnection<'_, C>> {
        let vacant = self.slots.vacant_entry()?;
        let lease = vacant.insert_with(|workspace| Stored {
            core: client::Core::new(clock, workspace, self.first.take(), self.enable_early_data),
        });
        Some(client::PooledConnection::new(lease, &self.authority))
    }

    pub fn capacities(&self) -> (usize, usize) {
        self.authority.workspace_layout().capacities()
    }
}

impl<C: connection::Clock> FramedPool<C> {
    pub(in crate::client) fn new(
        prepared: config::Prepared,
        identity: Option<config::IdentityTemplate>,
        capacity: slab::Capacity,
        transport_params_capacity: usize,
    ) -> Self {
        let config::Prepared {
            template,
            resumption,
            enable_early_data,
        } = prepared;
        let authority = config::Authority::new(template, identity);
        // A framed transport owns every outbound flight. shin retains only the
        // peer key between Certificate and CertificateVerify.
        let layout = Layout::new(0, authority.template().verifier().peer_identity_capacity());
        Self {
            authority,
            layout,
            first: cell::Cell::new(resumption),
            enable_early_data,
            transport_params_capacity,
            slots: recycle::Pool::with_capacity(capacity, || FramedSeed {
                workspace: layout.allocate(),
                transport_params: Vec::with_capacity(transport_params_capacity),
            }),
        }
    }

    /// Reserves one slot before the caller encodes connection-local transport
    /// parameters into its retained buffer.
    pub fn reserve(&self) -> Option<FramedReservation<'_, C>> {
        let mut vacant = self.slots.vacant_entry()?;
        vacant.seed_mut().transport_params.clear();
        Some(FramedReservation {
            pool: self,
            vacant,
            resumption: None,
        })
    }

    /// Binds one connection-local ticket to this pool's exact endpoint policy
    /// without cloning the shared authority.
    pub fn reserve_restored(
        &self,
        restore: config::Restore<'_>,
    ) -> Result<Option<FramedReservation<'_, C>>, config::Error> {
        let resumption = self
            .authority
            .restore(restore, self.transport_params_capacity)?;
        let Some(mut vacant) = self.slots.vacant_entry() else {
            return Ok(None);
        };
        vacant.seed_mut().transport_params.clear();
        Ok(Some(FramedReservation {
            pool: self,
            vacant,
            resumption: Some(resumption),
        }))
    }

    pub fn capacities(&self) -> (usize, usize, usize) {
        let (reassembly, flight) = self.layout.capacities();
        (reassembly, flight, self.transport_params_capacity)
    }
}

impl<'pool, C: connection::Clock> FramedReservation<'pool, C> {
    /// Returns the allocation retained by this exact reserved slot.
    pub fn transport_params(&mut self) -> connection::RetainedBytes<'_> {
        connection::RetainedBytes::new(
            &mut self.vacant.seed_mut().transport_params,
            self.pool.transport_params_capacity,
        )
    }

    /// Constructs the connection without validation, allocation, or a
    /// fallible slab closure after the caller has prepared the buffer.
    pub fn connect(self, clock: C) -> client::FramedConnection<'pool, C> {
        let pool = self.pool;
        let resumption = self.resumption.or_else(|| pool.first.take());
        let lease = self.vacant.insert_with(|seed| FramedStored {
            core: client::FramedCore::new(
                clock,
                seed.workspace,
                resumption,
                pool.enable_early_data,
            ),
            transport_params: seed.transport_params,
        });
        client::FramedConnection::new(lease, &pool.authority)
    }
}

pub(in crate::client) struct Stored<C: connection::Clock> {
    pub(in crate::client) core: client::Core<C>,
}

pub(in crate::client) struct FramedStored<C: connection::Clock> {
    pub(in crate::client) core: client::FramedCore<C>,
    pub(in crate::client) transport_params: Vec<u8>,
}

impl<C: connection::Clock> recycle::Recycle for Stored<C> {
    type Seed = Workspace;

    fn into_seed(self) -> Self::Seed {
        self.core.into_workspace()
    }
}

impl<C: connection::Clock> recycle::Recycle for FramedStored<C> {
    type Seed = FramedSeed;

    fn into_seed(mut self) -> Self::Seed {
        self.transport_params.clear();
        FramedSeed {
            workspace: self.core.into_workspace(),
            transport_params: self.transport_params,
        }
    }
}

const _: () =
    assert!(mem::size_of::<Stored<fn() -> u64>>() == mem::size_of::<client::Core<fn() -> u64>>());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::config::{Config, Identity, Verifier};
    use crate::crypto::sig::SigningKey;
    use core::cell::Cell;

    struct BorrowedClock<'a>(&'a Cell<u64>);

    impl connection::Clock for BorrowedClock<'_> {
        fn now_ms(&self) -> u64 {
            self.0.get()
        }
    }

    #[test]
    fn pool_and_connections_share_one_policy_and_preserve_clock_borrows() {
        let prepared = Config {
            verifier: Verifier::RawPublicKey {
                expected_pubkey: [7; 32],
            },
            transport_params: alloc::vec::Vec::new(),
            alpn_protocols: alloc::vec::Vec::new(),
            enable_early_data: false,
        }
        .try_into_prepared()
        .unwrap();
        let identity = Identity::RawPublicKey {
            signing_key: SigningKey::from_seed(&[9; 32]).unwrap(),
        }
        .try_into_template()
        .unwrap();
        let now = Cell::new(0);
        let pool = prepared
            .into_pool::<BorrowedClock<'_>>(Some(identity), slab::Capacity::try_from(64).unwrap());
        assert_eq!(pool.authority.strong_counts(), (1, Some(1)));

        let connection = pool.connect(BorrowedClock(&now)).unwrap();
        assert_eq!(pool.authority.strong_counts(), (1, Some(1)));
        drop(connection);
        assert_eq!(pool.authority.strong_counts(), (1, Some(1)));

        drop(pool);
        now.set(1);
        assert_eq!(now.get(), 1);
    }
}
