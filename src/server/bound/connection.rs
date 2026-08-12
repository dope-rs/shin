use crate::connection;
use crate::server;
use crate::server::config;
use crate::wire::handshake::workspace;
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
    pub(super) fn new(
        server: server::Server<C, DOMAIN>,
        shard: &'shard mut server::Shard<G, V, DOMAIN>,
    ) -> Result<Self, connection::Error> {
        server.validate_shard(shard)?;
        Ok(Self { server, shard })
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.server
            .session
            .peer
            .selected_alpn(&self.shard.policy.alpn)
    }

    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.server
            .read_bound(epoch, data, &mut *self.shard, events)
    }

    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        self.server.note_early_data(len)
    }

    pub fn key_updates(&mut self) -> server::Updates<'_, C, DOMAIN> {
        self.server.key_updates()
    }

    pub fn into_workspace(self) -> workspace::Scratch {
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
