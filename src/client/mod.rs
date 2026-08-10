use crate::connection;
use crate::crypto::kx;
use crate::crypto::schedule;
use crate::transport;
use crate::wire::handshake;
use crate::wire::handshake::workspace;
use crate::wire::record;

use core::mem;

mod authentication;
pub mod config;
mod drive;
mod negotiation;
mod offer;
mod session;
mod state;

use drive::Drive as _;

/// RFC 8446 §4.6.1: a client MUST NOT cache a ticket longer than 7 days, and a
/// server MUST NOT send a larger lifetime.
const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

/// ```compile_fail
/// use shin::client::Client;
/// fn assert_send<T: Send>() {}
/// assert_send::<Client<fn() -> u64>>();
/// ```
pub struct Client<C: connection::Clock> {
    session: session::Session<C>,
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
pub struct Hybrid<'workspace, C: connection::Clock> {
    client: Client<C>,
    workspace: &'workspace mut kx::HybridWorkspace,
}

impl<C: connection::Clock> Client<C> {
    /// Creates a TLS-over-stream client.
    pub fn new(config: config::Config, clock: C) -> Result<Self, config::Error> {
        Self::with_transport_workspace(
            config,
            transport::Mode::Tls,
            clock,
            workspace::Scratch::for_client(),
        )
    }

    /// Creates a client for the explicitly selected transport.
    pub fn new_with_transport(
        config: config::Config,
        transport_mode: transport::Mode,
        clock: C,
    ) -> Result<Self, config::Error> {
        Self::with_transport_workspace(
            config,
            transport_mode,
            clock,
            workspace::Scratch::for_client(),
        )
    }

    /// Creates a client with caller-owned storage for an explicit transport.
    pub fn with_transport_workspace(
        config: config::Config,
        transport_mode: transport::Mode,
        clock: C,
        workspace: workspace::Scratch,
    ) -> Result<Self, config::Error> {
        let config = config.try_into_prepared_with_transport(transport_mode)?;
        Ok(Self::with_prepared_workspace(
            config, None, clock, workspace,
        ))
    }

    pub fn with_prepared_workspace(
        config: config::Prepared,
        identity: Option<config::IdentityTemplate>,
        clock: C,
        workspace: workspace::Scratch,
    ) -> Self {
        use crate::crypto::hash::Transcript;
        use crate::crypto::material;
        use crate::memory::threadbound::ThreadBound;
        use crate::wire::handshake::reassemblers::HsReassembler;
        use ring::rand::SystemRandom;
        use session::Application;
        use session::Buffers;
        use session::Credentials;
        use session::Extensions;
        use session::Handshake;
        use session::OfferSettings;
        use session::Runtime;
        let config::Prepared {
            template: config,
            resumption,
        } = config;
        let workspace::Scratch {
            reassembly,
            flight,
            identity: identity_workspace,
        } = workspace;
        Self {
            session: session::Session {
                offer: OfferSettings {
                    config,
                    resumption,
                    kex_group: kx::KexGroup::X25519,
                    offered_suites: record::CipherSuite::SUPPORTED.into_iter().collect(),
                },
                handshake: Handshake {
                    state: state::State::initial(),
                    transcript: Transcript::new(),
                    eph: None,
                    client_random: [0u8; handshake::RANDOM_LEN],
                    session_id: [0; 32],
                    hrr_done: false,
                    active_resumption: None,
                    psk_used: false,
                },
                extensions: Extensions {
                    ee_offered: arrayvec::ArrayVec::new(),
                    selected_alpn: None,
                    early_data: session::EarlyData::NotOffered,
                },
                credentials: Credentials {
                    identity,
                    cert_request: None,
                },
                application: Application {
                    traffic: material::State::default(),
                    resumption_master: None,
                    exporter_master: None,
                },
                buffers: Buffers {
                    reasm: HsReassembler::with_buffer(reassembly),
                    flight,
                    identity_workspace,
                },
                runtime: Runtime {
                    clock,
                    rng: SystemRandom::new(),
                    _thread: ThreadBound::NEW,
                },
            },
        }
    }

    /// Returns the caller-owned handshake storage after clearing protocol bytes.
    pub fn into_workspace(mut self) -> workspace::Scratch {
        workspace::Scratch::from_buffers(
            self.session.buffers.reasm.release_buffer(),
            mem::take(&mut self.session.buffers.flight),
            mem::take(&mut self.session.buffers.identity_workspace),
        )
    }

    /// Choose the (EC)DHE group to offer (default X25519). Must be set before
    /// `start`.
    pub fn set_kex_group(&mut self, group: kx::KexGroup) -> Result<(), connection::Error> {
        self.session.handshake.require_initial()?;
        self.session.offer.kex_group = group;
        Ok(())
    }

    /// Restrict the cipher suites offered (default: all supported, AES-128
    /// first). Must be set before `start`.
    pub fn set_cipher_suites(
        &mut self,
        suites: &[record::CipherSuite],
    ) -> Result<(), connection::Error> {
        self.session.handshake.require_initial()?;
        let offered_suites: arrayvec::ArrayVec<_, 3> = record::CipherSuite::SUPPORTED
            .into_iter()
            .filter(|suite| suites.contains(suite))
            .collect();
        if offered_suites.is_empty() {
            return Err(connection::Error::BadConfig);
        }
        self.session.offer.offered_suites = offered_suites;
        Ok(())
    }

    /// Present this identity if the server requests client authentication
    /// (mutual TLS). Must be set before `start`. Without it, a server that only
    /// *requests* (not requires) client auth gets an empty Certificate.
    pub fn set_identity(&mut self, source: config::Identity) -> Result<(), connection::Error> {
        self.session.handshake.require_initial()?;
        let source = source.try_into_template()?;
        self.session.credentials.identity = Some(source);
        Ok(())
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.session.extensions.selected_alpn.as_deref()
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
        self.start_with_workspace(None, events)
    }

    /// Processes one record payload and emits events without an intermediate batch.
    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.read_with_workspace(epoch, data, None, events)
    }

    /// Marks application-data progress and resets the KeyUpdate budget.
    /// Call once per decrypted application record.
    pub fn note_application_data(&mut self) {
        self.session.application.traffic.reset_updates();
    }

    pub fn is_done(&self) -> bool {
        self.session.handshake.state.kind() == state::StateKind::Done
    }

    /// Emits a KeyUpdate directly into `events`.
    pub fn send_key_update_into<S: connection::EventSink + ?Sized>(
        &mut self,
        request_update: bool,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.send_key_update(request_update, events)
    }
}

impl<'workspace, C: connection::Clock> Hybrid<'workspace, C> {
    /// Converts an unstarted client to the allocation-free hybrid profile.
    pub fn from_client(
        mut client: Client<C>,
        hybrid_workspace: &'workspace mut kx::HybridWorkspace,
    ) -> Result<Self, connection::Error> {
        client.set_kex_group(kx::KexGroup::X25519Mlkem768)?;
        Ok(Self {
            client,
            workspace: hybrid_workspace,
        })
    }

    pub fn set_cipher_suites(
        &mut self,
        suites: &[record::CipherSuite],
    ) -> Result<(), connection::Error> {
        self.client.set_cipher_suites(suites)
    }

    pub fn set_identity(&mut self, source: config::Identity) -> Result<(), connection::Error> {
        self.client.set_identity(source)
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
        let result = self
            .client
            .start_with_workspace(Some(&mut *self.workspace), events);
        if result.is_err() {
            self.workspace.clear();
        }
        result
    }

    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        let result =
            self.client
                .read_with_workspace(epoch, data, Some(&mut *self.workspace), events);
        if result.is_err() {
            self.workspace.clear();
        }
        result
    }

    pub fn note_application_data(&mut self) {
        self.client.note_application_data();
    }

    pub fn is_done(&self) -> bool {
        self.client.is_done()
    }

    pub fn send_key_update_into<S: connection::EventSink + ?Sized>(
        &mut self,
        request_update: bool,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.client.send_key_update_into(request_update, events)
    }

    /// Clears hybrid private state and returns the ordinary handshake storage.
    pub fn into_workspace(self) -> workspace::Scratch {
        self.workspace.clear();
        self.client.into_workspace()
    }
}
