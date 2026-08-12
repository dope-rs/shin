use crate::connection;
use crate::crypto::kx;
use crate::crypto::schedule;
use crate::transport;
use crate::wire::record;

use o3::collections::fixed::array;

mod authentication;
pub mod config;
mod drive;
mod negotiation;
mod offer;
mod session;
mod state;
mod updates;
mod workspace;

pub use config::Ticket;
pub use updates::Updates;
pub use workspace::{Workspace, WorkspaceLayout, WorkspaceMismatch, WorkspaceRejection};

use drive::Drive as _;

/// ```compile_fail
/// use shin::client::Client;
/// fn assert_send<T: Send>() {}
/// assert_send::<Client<fn() -> u64>>();
/// ```
pub struct Client<C: connection::Clock, K = kx::Owned> {
    session: session::Session<C, K>,
}

/// Opt-in client whose hybrid private state lives in caller-owned storage.
///
/// The workspace borrow spans the entire connection, so the in-place key token
/// cannot outlive or be driven with a different workspace. Unlike the
/// compatibility `Client::set_kex_group(X25519Mlkem768)` path, the hybrid
/// handshake performs no heap allocation for its ephemeral key material.
///
/// ```compile_fail
/// use shin::client::Hybrid;
/// fn assert_send<T: Send>() {}
/// assert_send::<Hybrid<'static, fn() -> u64>>();
/// ```
///
/// ```compile_fail
/// use shin::client::{Client, Hybrid};
/// use shin::connection::Clock;
/// use shin::crypto::kx::HybridWorkspace;
///
/// fn bind_twice<C: Clock>(
///     first: Client<C>,
///     second: Client<C>,
///     workspace: &mut HybridWorkspace,
/// ) {
///     let first = Hybrid::from_client(first, workspace).unwrap();
///     let second = Hybrid::from_client(second, workspace).unwrap();
///     drop((first, second));
/// }
/// ```
pub struct Hybrid<'workspace, C: connection::Clock> {
    client: Client<C, kx::Workspace<'workspace>>,
}

impl<C: connection::Clock> Client<C> {
    /// Creates a TLS-over-stream client.
    pub fn new(config: config::Config, clock: C) -> Result<Self, config::Error> {
        Self::new_with_transport(config, transport::Mode::Tls, clock)
    }

    /// Creates a client for the explicitly selected transport.
    pub fn new_with_transport(
        config: config::Config,
        transport_mode: transport::Mode,
        clock: C,
    ) -> Result<Self, config::Error> {
        let config = config.try_into_prepared_with_transport(transport_mode)?;
        let workspace = config.workspace_layout(None).allocate();
        Ok(config.build_client(None, clock, workspace))
    }

    /// Creates a mutually authenticated TLS-over-stream client and reserves
    /// its exact identity flight before construction.
    pub fn mutual(
        config: config::Config,
        identity: config::Identity,
        clock: C,
    ) -> Result<Self, config::Error> {
        Self::mutual_with_transport(config, identity, transport::Mode::Tls, clock)
    }

    /// Creates a mutually authenticated client for the selected transport.
    pub fn mutual_with_transport(
        config: config::Config,
        identity: config::Identity,
        transport_mode: transport::Mode,
        clock: C,
    ) -> Result<Self, config::Error> {
        let config = config.try_into_prepared_with_transport(transport_mode)?;
        let identity = identity.try_into_template()?;
        let workspace = config.workspace_layout(Some(&identity)).allocate();
        Ok(config.build_client(Some(identity), clock, workspace))
    }

    /// Creates a client for the retained ticket's endpoint and transport.
    pub fn resume(
        resumption: config::Resumption,
        enable_early_data: bool,
        clock: C,
    ) -> Result<Self, config::Error> {
        let config = config::Prepared::from_retained(resumption, enable_early_data)?;
        let workspace = config.workspace_layout(None).allocate();
        Ok(config.build_client(None, clock, workspace))
    }

    /// Returns the caller-owned handshake storage after clearing protocol bytes.
    pub fn into_workspace(self) -> Workspace {
        self.session.release_workspace()
    }

    /// Choose the (EC)DHE group to offer (default X25519). Must be set before
    /// `start`.
    pub fn set_kex_group(&mut self, group: kx::KexGroup) -> Result<(), connection::Error> {
        self.session.handshake.require_initial()?;
        self.session.offer.kex_group = group;
        Ok(())
    }
}

impl<C: connection::Clock, K: kx::Initiator> Client<C, K> {
    /// Restrict the cipher suites offered (default: all supported, AES-128
    /// first). Must be set before `start`.
    pub fn set_cipher_suites(
        &mut self,
        suites: &[record::CipherSuite],
    ) -> Result<(), connection::Error> {
        self.session.handshake.require_initial()?;
        let mut offered_suites = array::CopyInline::<_, 3>::new();
        for suite in record::CipherSuite::SUPPORTED {
            if suites.contains(&suite) {
                offered_suites
                    .push(suite)
                    .map_err(|_| connection::Error::BadConfig)?;
            }
        }
        if offered_suites.is_empty() {
            return Err(connection::Error::BadConfig);
        }
        self.session.offer.offered_suites = offered_suites;
        Ok(())
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.session
            .extensions
            .selected_alpn
            .and_then(|selected| self.session.offer.config.alpn(selected))
    }

    /// Suite selected by ServerHello for constructing the record
    /// [`Sealer`](crate::wire::record::Sealer) and [`Opener`](crate::wire::record::Opener).
    pub fn negotiated_cipher_suite(&self) -> Option<record::CipherSuite> {
        self.session.application.traffic.suite()
    }

    /// RFC 5705 / RFC 8446 §7.5 exported keying material. Available only after
    /// the handshake completes (the server Finished has been processed).
    pub fn export_keying_material(
        &self,
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), connection::Error> {
        let em = self
            .session
            .application
            .exporter_master
            .as_ref()
            .ok_or(connection::Error::NotReady)?;
        schedule::Schedule::export_keying_material(
            self.session.application.hash_alg()?,
            em.as_slice(),
            label,
            context,
            out,
        )?;
        Ok(())
    }

    /// Starts the handshake and emits each event directly into `events`.
    pub fn start_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.start(events)
    }

    /// Processes one record payload and emits events without an intermediate batch.
    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.read(epoch, data, events)
    }

    /// Borrows exclusive post-handshake KeyUpdate control.
    pub fn key_updates(&mut self) -> Updates<'_, C, K> {
        Updates::new(self)
    }

    pub fn is_done(&self) -> bool {
        matches!(self.session.handshake.state, state::State::Done)
    }
}

impl<'workspace, C: connection::Clock> Hybrid<'workspace, C> {
    /// Converts an unstarted client to the allocation-free hybrid profile.
    pub fn from_client(
        mut client: Client<C>,
        hybrid_workspace: &'workspace mut kx::HybridWorkspace,
    ) -> Result<Self, connection::Error> {
        client.set_kex_group(kx::KexGroup::X25519Mlkem768)?;
        let session = client.session.with_kx(kx::Workspace::new(hybrid_workspace));
        Ok(Self {
            client: Client { session },
        })
    }

    pub fn set_cipher_suites(
        &mut self,
        suites: &[record::CipherSuite],
    ) -> Result<(), connection::Error> {
        self.client.set_cipher_suites(suites)
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.client.selected_alpn()
    }

    pub fn negotiated_cipher_suite(&self) -> Option<record::CipherSuite> {
        self.client.negotiated_cipher_suite()
    }

    pub fn export_keying_material(
        &self,
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), connection::Error> {
        self.client.export_keying_material(label, context, out)
    }

    pub fn start_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.client.start_into(events)
    }

    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.client.read_into(epoch, data, events)
    }

    pub fn key_updates(&mut self) -> Updates<'_, C, kx::Workspace<'workspace>> {
        Updates::new(&mut self.client)
    }

    pub fn is_done(&self) -> bool {
        self.client.is_done()
    }

    /// Clears hybrid private state and returns the ordinary handshake storage.
    pub fn into_workspace(self) -> Workspace {
        self.client.session.release_workspace()
    }
}
