use crate::connection;
use crate::server;
use crate::wire::handshake;

/// Exclusive post-handshake KeyUpdate capability.
/// Its borrow prevents the server from being driven concurrently.
///
/// ```compile_fail
/// use shin::connection::Clock;
/// use shin::server::Server;
///
/// fn reborrow<C: Clock, const DOMAIN: u8>(server: &mut Server<C, DOMAIN>) {
///     let updates = server.key_updates();
///     let _ = server.is_done();
///     drop(updates);
/// }
/// ```
pub struct Updates<'server, C: connection::Clock, const DOMAIN: u8> {
    server: &'server mut server::Server<C, DOMAIN>,
}

impl<'server, C: connection::Clock, const DOMAIN: u8> Updates<'server, C, DOMAIN> {
    pub(in crate::server) fn new(server: &'server mut server::Server<C, DOMAIN>) -> Self {
        Self { server }
    }

    /// Marks application-data progress and resets the consecutive-update budget.
    pub fn note_application_data(&mut self) {
        self.server.session.application.traffic.reset_updates();
    }

    /// Returns whether a coalesced peer-requested response is pending.
    pub fn response_pending(&self) -> bool {
        self.server
            .session
            .application
            .traffic
            .key_update_response_pending()
    }

    /// Emits one pending response, or does nothing when no response is pending.
    pub fn send_pending_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if !self.response_pending() {
            return Ok(());
        }
        self.send_into(handshake::KeyUpdateRequest::NotRequested, events)
    }

    /// Emits a KeyUpdate directly into `events`.
    pub fn send_into<S: connection::EventSink + ?Sized>(
        &mut self,
        request: handshake::KeyUpdateRequest,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.server.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        if !self.server.session.transport_mode.allows_tls_key_update()
            || !self.server.session.handshake.is_done()
        {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        let result = connection::KeyUpdateCore::<connection::ServerRole>::new(
            &mut self.server.session.application.traffic,
        )
        .send(request, events);
        if result.is_err() {
            self.server.poison();
        }
        result
    }
}
