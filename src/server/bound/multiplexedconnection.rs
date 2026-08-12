use crate::connection;
use crate::server;
use crate::server::config;
use crate::wire::protocols;
use alloc::rc;
use core::{marker, ops};

/// Server connection carrying the exact identity of its admitting shard.
pub struct MultiplexedConnection<C: connection::Clock, const DOMAIN: u8 = 0> {
    server: server::Server<C, DOMAIN>,
    alpn: rc::Rc<protocols::PreparedAlpn>,
}

/// Multiplexed connection proven to own a recyclable server workspace.
///
/// The admitted server cannot be replaced through mutable dereferencing:
///
/// ```compile_fail
/// use shin::connection::Clock;
/// use shin::server::{PooledConnection, Server};
///
/// fn replace<C: Clock>(pooled: &mut PooledConnection<C>, server: Server<C>) {
///     **pooled = server;
/// }
/// ```
///
/// Recycling preserves the client-auth reservation profile:
///
/// ```compile_fail
/// use shin::connection::Clock;
/// use shin::server::{PooledConnection, Workspace, config};
///
/// fn erase<C: Clock, V: config::ClientCertVerifier>(
///     pooled: PooledConnection<C, 0, config::ClientAuthVerifier<V>>,
/// ) -> Workspace {
///     pooled.into_workspace()
/// }
/// ```
#[repr(transparent)]
pub struct PooledConnection<
    C: connection::Clock,
    const DOMAIN: u8 = 0,
    V: config::ClientCertVerifier = config::NoClientAuth,
>(
    MultiplexedConnection<C, DOMAIN>,
    marker::PhantomData<fn() -> V>,
);

impl<C, const DOMAIN: u8> MultiplexedConnection<C, DOMAIN>
where
    C: connection::Clock,
{
    pub(super) fn new(
        server: server::Server<C, DOMAIN>,
        alpn: rc::Rc<protocols::PreparedAlpn>,
    ) -> Self {
        Self { server, alpn }
    }

    pub fn read_into<G, V, S>(
        &mut self,
        shard: &mut server::Shard<G, V, DOMAIN>,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        if !rc::Rc::ptr_eq(&self.alpn, &shard.policy.alpn) {
            use crate::server::session::Drive as _;
            self.server.poison();
            return Err(connection::Error::ConnectionFailed.into());
        }
        self.server.read_bound(epoch, data, shard, events)
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.server.session.peer.selected_alpn(&self.alpn)
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.server.note_early_data(len)
    }

    pub fn key_updates(&mut self) -> server::Updates<'_, C, DOMAIN> {
        self.server.key_updates()
    }
}

impl<C, const DOMAIN: u8, V> PooledConnection<C, DOMAIN, V>
where
    C: connection::Clock,
    V: config::ClientCertVerifier,
{
    pub(super) fn new(
        server: server::Server<C, DOMAIN>,
        alpn: rc::Rc<protocols::PreparedAlpn>,
    ) -> Self {
        Self(
            MultiplexedConnection::new(server, alpn),
            marker::PhantomData,
        )
    }

    pub fn read_into<G, S>(
        &mut self,
        shard: &mut server::Shard<G, V, DOMAIN>,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        S: connection::EventSink + ?Sized,
    {
        self.0.read_into(shard, epoch, data, events)
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.0.note_early_data(len)
    }

    pub fn key_updates(&mut self) -> server::Updates<'_, C, DOMAIN> {
        self.0.key_updates()
    }

    /// Returns the same opaque capability after clearing protocol bytes.
    pub fn into_workspace(self) -> server::Workspace<V> {
        server::Workspace::from_recycled(self.0.server.into_workspace())
    }
}

impl<C, const DOMAIN: u8> ops::Deref for MultiplexedConnection<C, DOMAIN>
where
    C: connection::Clock,
{
    type Target = server::Server<C, DOMAIN>;

    fn deref(&self) -> &Self::Target {
        &self.server
    }
}

impl<C, const DOMAIN: u8, V> ops::Deref for PooledConnection<C, DOMAIN, V>
where
    C: connection::Clock,
    V: config::ClientCertVerifier,
{
    type Target = MultiplexedConnection<C, DOMAIN>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
