use crate::connection;
use crate::server::config;
use crate::server::{self, workspace};
use core::ops;
use o3::collections::slab::recycle;

/// Server connection owning the exact authority of its admitting shard.
pub struct MultiplexedConnection<
    C: connection::Clock,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
> {
    server: server::Server<C, DOMAIN>,
    authority: server::Authority<G, V, DOMAIN>,
}

/// Owned QUIC server whose framed transport lends final outbound storage.
pub struct QuicConnection<
    C: connection::Clock,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
> {
    server: server::QuicServer<C, DOMAIN>,
    authority: server::Authority<G, V, DOMAIN>,
}

/// Recyclable server connection borrowing its pool's exact authority.
///
/// The admitted server cannot be replaced through mutable dereferencing:
///
/// ```compile_fail
/// use shin::connection::Clock;
/// use shin::server::{PooledConnection, Server};
///
/// fn replace<C: Clock>(pooled: &mut PooledConnection<'_, C>, server: Server<C>) {
///     **pooled = server;
/// }
/// ```
///
/// A pooled connection cannot escape the authority-owning pool:
///
/// ```compile_fail
/// use shin::connection::Clock;
/// use shin::server::{PooledConnection, config};
///
/// fn escape<C: Clock, V: config::ClientCertVerifier>(
///     pooled: PooledConnection<'_, C, 0, config::ClientAuthVerifier<V>>,
/// ) -> PooledConnection<'static, C, 0, config::ClientAuthVerifier<V>> {
///     pooled
/// }
/// ```
pub struct PooledConnection<
    'pool,
    C: connection::Clock,
    const DOMAIN: u8 = 0,
    V: config::ClientCertVerifier = config::NoClientAuth,
    G: config::EarlyDataGuard = config::NoGuard,
> {
    lease: recycle::Lease<'pool, workspace::Stored<C, V, DOMAIN>>,
    authority: &'pool server::Authority<G, V, DOMAIN>,
}

/// Recyclable QUIC server driven with complete handshake frames.
pub struct QuicPooledConnection<
    'pool,
    C: connection::Clock,
    const DOMAIN: u8 = 0,
    V: config::ClientCertVerifier = config::NoClientAuth,
    G: config::EarlyDataGuard = config::NoGuard,
> {
    lease: recycle::Lease<'pool, workspace::QuicStored<C, V, DOMAIN>>,
    authority: &'pool server::Authority<G, V, DOMAIN>,
}

impl<C, G, V, const DOMAIN: u8> MultiplexedConnection<C, DOMAIN, G, V>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    /// Validated maximum storage required by one outbound handshake flight.
    pub fn outbound_flight_capacity(&self) -> usize {
        self.server.outbound_flight_capacity()
    }

    pub fn outbound_layout(&self) -> Result<connection::OutboundLayout, connection::Error> {
        self.authority.outbound_layout(
            self.server.session.transport_mode,
            self.server.session.connection.transport_params.len(),
        )
    }

    pub(super) fn new(
        server: server::Server<C, DOMAIN>,
        authority: server::Authority<G, V, DOMAIN>,
    ) -> Self {
        Self { server, authority }
    }

    pub fn read_into<S>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        S: connection::EventSink + ?Sized,
    {
        self.server
            .read_authorized(epoch, data, &self.authority, events)
    }

    /// Processes exactly one complete encoded handshake message.
    pub fn read_framed_into<S>(
        &mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        S: connection::LendingEventSink + ?Sized,
    {
        self.server
            .read_authorized_framed(epoch, raw, &self.authority, events)
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.server.session.peer.selected_alpn(&self.authority.alpn)
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.server.note_early_data(len)
    }

    pub fn key_updates(&mut self) -> server::Updates<'_, C, DOMAIN> {
        self.server.key_updates()
    }
}

impl<C, G, V, const DOMAIN: u8> QuicConnection<C, DOMAIN, G, V>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(super) fn new(
        server: server::QuicServer<C, DOMAIN>,
        authority: server::Authority<G, V, DOMAIN>,
    ) -> Self {
        Self { server, authority }
    }

    pub fn outbound_layout(&self) -> Result<connection::OutboundLayout, connection::Error> {
        self.authority.outbound_layout(
            self.server.session.transport_mode,
            self.server.session.connection.transport_params.len(),
        )
    }

    pub fn read_framed_into<S: connection::LendingEventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.server
            .read_authorized_framed(epoch, raw, &self.authority, events)
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.server.session.peer.selected_alpn(&self.authority.alpn)
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.server.note_early_data(len)
    }

    pub fn is_done(&self) -> bool {
        self.server.session.handshake.is_done()
    }
}

impl<'pool, C, G, V, const DOMAIN: u8> PooledConnection<'pool, C, DOMAIN, V, G>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(in crate::server) fn new(
        lease: recycle::Lease<'pool, workspace::Stored<C, V, DOMAIN>>,
        authority: &'pool server::Authority<G, V, DOMAIN>,
    ) -> Self {
        Self { lease, authority }
    }

    pub fn read_into<S>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        S: connection::EventSink + ?Sized,
    {
        self.lease
            .server
            .read_authorized(epoch, data, self.authority, events)
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.lease
            .server
            .session
            .peer
            .selected_alpn(&self.authority.alpn)
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.lease.server.note_early_data(len)
    }

    pub fn key_updates(&mut self) -> server::Updates<'_, C, DOMAIN> {
        self.lease.server.key_updates()
    }
}

impl<'pool, C, G, V, const DOMAIN: u8> QuicPooledConnection<'pool, C, DOMAIN, V, G>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(in crate::server) fn new(
        lease: recycle::Lease<'pool, workspace::QuicStored<C, V, DOMAIN>>,
        authority: &'pool server::Authority<G, V, DOMAIN>,
    ) -> Self {
        Self { lease, authority }
    }

    pub fn read_framed_into<S>(
        &mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        S: connection::LendingEventSink + ?Sized,
    {
        self.lease
            .server
            .read_authorized_framed(epoch, raw, self.authority, events)
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.lease
            .server
            .session
            .peer
            .selected_alpn(&self.authority.alpn)
    }

    pub fn outbound_layout(&self) -> Result<connection::OutboundLayout, connection::Error> {
        self.authority.outbound_layout(
            self.lease.server.session.transport_mode,
            self.lease.server.session.connection.transport_params.len(),
        )
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.lease.server.note_early_data(len)
    }

    pub fn is_done(&self) -> bool {
        self.lease.server.is_done()
    }
}

const _: () = assert!(
    core::mem::size_of::<QuicPooledConnection<'static, fn() -> u64>>()
        == 2 * core::mem::size_of::<usize>()
);

impl<C, G, V, const DOMAIN: u8> ops::Deref for MultiplexedConnection<C, DOMAIN, G, V>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    type Target = server::Server<C, DOMAIN>;

    fn deref(&self) -> &Self::Target {
        &self.server
    }
}

impl<C, G, V, const DOMAIN: u8> ops::Deref for PooledConnection<'_, C, DOMAIN, V, G>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    type Target = server::Server<C, DOMAIN>;

    fn deref(&self) -> &Self::Target {
        &self.lease.server
    }
}
