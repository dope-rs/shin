use crate::connection;
use crate::server;
use crate::server::config;
use crate::transport;
use crate::wire::handshake::storage;
use core::ops;

/// Server connection statically bound to one borrowed shard for its entire
/// lifetime. Dropping this value drops the server, so it cannot be rebound to
/// a different policy midway through a handshake.
pub struct Connection<
    'shard,
    C: connection::Clock,
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
> {
    server: server::Server<C, DOMAIN>,
    shard: &'shard mut server::Shard<G, V, DOMAIN>,
}

impl<'shard, C, G, V, const DOMAIN: u8> Connection<'shard, C, G, V, DOMAIN>
where
    C: connection::Clock,
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    /// Prepares exact storage before binding this borrowed shard infallibly.
    pub fn prepare(
        shard: &'shard mut server::Shard<G, V, DOMAIN>,
        config: config::Connection,
        transport_mode: transport::Mode,
        clock: C,
    ) -> Result<Self, connection::Error> {
        let workspace = shard.workspace_layout(&config, transport_mode)?.allocate();
        let server =
            server::Server::from_validated(config, transport_mode, clock, workspace.into_scratch());
        Ok(Self::from_validated(server, shard))
    }

    pub(super) fn new(
        server: server::Server<C, DOMAIN>,
        shard: &'shard mut server::Shard<G, V, DOMAIN>,
    ) -> server::Binding<Self, server::Server<C, DOMAIN>> {
        if let Err(error) = server.validate_shard(shard) {
            return server::Binding::rejected(error, server);
        }
        server::Binding::bound(Self::from_validated(server, shard))
    }

    pub(super) fn from_validated(
        server: server::Server<C, DOMAIN>,
        shard: &'shard mut server::Shard<G, V, DOMAIN>,
    ) -> Self {
        Self { server, shard }
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.server
            .session
            .peer
            .selected_alpn(&self.shard.authority.alpn)
    }

    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.server
            .read_authorized(epoch, data, &self.shard.authority, events)
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.server.note_early_data(len)
    }

    pub fn key_updates(&mut self) -> server::Updates<'_, C, DOMAIN> {
        self.server.key_updates()
    }

    pub fn into_workspace(self) -> storage::Scratch {
        self.server.into_workspace()
    }
}

impl<C, G, V, const DOMAIN: u8> ops::Deref for Connection<'_, C, G, V, DOMAIN>
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
