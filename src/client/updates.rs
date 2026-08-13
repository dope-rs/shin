use crate::client;
use crate::connection;
use crate::crypto::kx;
use crate::wire::handshake;

/// Exclusive post-handshake KeyUpdate capability.
/// Its borrow prevents the client from being driven concurrently.
///
/// ```compile_fail
/// use shin::client::Client;
/// use shin::connection::Clock;
///
/// fn reborrow<C: Clock>(client: &mut Client<C>) {
///     let updates = client.key_updates();
///     let _ = client.is_done();
///     drop(updates);
/// }
/// ```
pub struct Updates<'client, C: connection::Clock, K = kx::Owned> {
    core: &'client mut client::Core<C, K>,
    authority: &'client client::config::Authority,
}

impl<'client, C: connection::Clock, K: kx::Initiator> Updates<'client, C, K> {
    pub(super) fn new(
        core: &'client mut client::Core<C, K>,
        authority: &'client client::config::Authority,
    ) -> Self {
        Self { core, authority }
    }

    /// Marks application-data progress and resets the consecutive-update budget.
    pub fn note_application_data(&mut self) {
        self.core.session.application.traffic.reset_updates();
    }

    /// Returns whether a coalesced peer-requested response is pending.
    pub fn response_pending(&self) -> bool {
        self.core
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
        if self.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        if !self
            .authority
            .template()
            .transport_mode()
            .allows_tls_key_update()
            || !self.core.session.handshake.is_done()
        {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        let result = connection::KeyUpdateCore::<connection::ClientRole>::new(
            &mut self.core.session.application.traffic,
        )
        .send(request, events);
        if result.is_err() {
            self.core.poison();
        }
        result
    }
}
