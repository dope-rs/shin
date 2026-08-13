use crate::connection;
use crate::crypto::kx;
use crate::crypto::material;
use crate::crypto::schedule;
use crate::transport;
use crate::wire::handshake::reassemblers;
use crate::wire::protocols;
use crate::wire::record;
use o3::collections::fixed::array;
use o3::collections::slab::recycle;

pub mod config;
mod drive;
mod offer;
mod session;
mod updates;
pub mod workspace;

pub use config::Ticket;
pub use updates::Updates;

/// ```compile_fail
/// use shin::client::Client;
/// fn assert_send<T: Send>() {}
/// assert_send::<Client<fn() -> u64>>();
/// ```
pub struct Client<C: connection::Clock, K = kx::Owned> {
    core: Core<C, K>,
    authority: config::Authority,
}

pub(in crate::client) struct Core<C: connection::Clock, K = kx::Owned> {
    reassembler: reassemblers::HsReassembler,
    session: session::Session<C, K>,
}

pub(in crate::client) struct FramedCore<C: connection::Clock> {
    session: session::Session<C, kx::Owned>,
}

/// Recyclable client connection borrowing its pool's exact endpoint policy.
///
/// A pooled client cannot escape the authority-owning pool:
///
/// ```compile_fail
/// use shin::client::PooledConnection;
/// use shin::connection::Clock;
///
/// fn escape<C: Clock>(pooled: PooledConnection<'_, C>) -> PooledConnection<'static, C> {
///     pooled
/// }
/// ```
pub struct PooledConnection<'pool, C: connection::Clock> {
    lease: recycle::Lease<'pool, workspace::Stored<C>>,
    authority: &'pool config::Authority,
}

/// Recyclable client for a transport that supplies one complete handshake
/// frame per read. Connection-local transport parameters remain in the leased
/// seed and return to the pool on transition or drop.
pub struct FramedConnection<'pool, C: connection::Clock> {
    lease: recycle::Lease<'pool, workspace::FramedStored<C>>,
    authority: &'pool config::Authority,
}

/// Owned client for a framed transport that lends final outbound storage.
pub struct FramedClient<C: connection::Clock> {
    pub(in crate::client) core: FramedCore<C>,
    pub(in crate::client) authority: config::Authority,
}

/// Compact QUIC ticket receiver left after releasing the full handshake core.
pub struct QuicPostHandshake<'pool, C: connection::Clock> {
    authority: &'pool config::Authority,
    master: Option<material::ResumptionMasterSecret>,
    suite: record::CipherSuite,
    selected_alpn: Option<protocols::AlpnId>,
    clock: C,
}

const _: () = assert!(
    core::mem::size_of::<FramedConnection<'static, fn() -> u64>>()
        == 2 * core::mem::size_of::<usize>()
);

const _: () = assert!(
    core::mem::size_of::<FramedClient<fn() -> u64>>()
        == core::mem::size_of::<FramedCore<fn() -> u64>>()
            + core::mem::size_of::<config::Authority>()
);

const _: () = assert!(
    core::mem::size_of::<Client<fn() -> u64>>()
        == core::mem::size_of::<Core<fn() -> u64>>() + core::mem::size_of::<config::Authority>()
);

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
    pub fn into_workspace(self) -> workspace::Workspace {
        self.core.into_workspace()
    }

    /// Choose the (EC)DHE group to offer (default X25519). Must be set before
    /// `start`.
    pub fn set_kex_group(&mut self, group: kx::KexGroup) -> Result<(), connection::Error> {
        self.core.session.handshake.require_initial()?;
        self.core.session.offer.kex_group = group;
        Ok(())
    }
}

impl<C: connection::Clock, K: kx::Initiator> Client<C, K> {
    /// Validated maximum storage required by one outbound handshake flight.
    pub fn outbound_flight_capacity(&self) -> usize {
        self.core.session.buffers.flight.capacity()
    }

    /// Validated cumulative QUIC CRYPTO storage required by each send epoch.
    /// Must be queried before the handshake starts.
    pub fn outbound_layout(&self) -> Result<connection::OutboundLayout, connection::Error> {
        let policy = self.authority.policy(None);
        outbound_layout(&self.core.session, &policy)
    }

    /// Restrict the cipher suites offered (default: all supported, AES-128
    /// first). Must be set before `start`.
    pub fn set_cipher_suites(
        &mut self,
        suites: &[record::CipherSuite],
    ) -> Result<(), connection::Error> {
        self.core.session.handshake.require_initial()?;
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
        self.core.session.offer.offered_suites = offered_suites;
        Ok(())
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.core
            .session
            .extensions
            .selected_alpn
            .and_then(|selected| self.authority.template().alpn(selected))
    }

    /// Suite selected by ServerHello for constructing the record
    /// [`Sealer`](crate::wire::record::Sealer) and [`Opener`](crate::wire::record::Opener).
    pub fn negotiated_cipher_suite(&self) -> Option<record::CipherSuite> {
        self.core.session.application.traffic.suite()
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
            .core
            .session
            .application
            .exporter_master
            .as_ref()
            .ok_or(connection::Error::NotReady)?;
        schedule::Schedule::export_keying_material(
            self.core.session.application.hash_alg()?,
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
        if self.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        self.core.session.handshake.require_initial()?;
        let policy = self.authority.policy(None);
        let result = self.core.start_into(&policy, None, events);
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Processes one record payload and emits events without an intermediate batch.
    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let policy = self.authority.policy(None);
        let result = self.core.read_into(&policy, epoch, data, events);
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Processes exactly one complete encoded handshake message.
    pub fn read_framed_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let policy = self.authority.policy(None);
        let result = self.core.read_framed_into(&policy, epoch, raw, events);
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Borrows exclusive post-handshake KeyUpdate control.
    pub fn key_updates(&mut self) -> Updates<'_, C, K> {
        Updates::new(&mut self.core, &self.authority)
    }

    pub fn is_done(&self) -> bool {
        self.core.session.handshake.is_done()
    }

    fn poison(&mut self) {
        self.core.poison();
    }
}

impl<C: connection::Clock> Core<C> {
    pub(in crate::client) fn new(
        clock: C,
        storage: workspace::Workspace,
        resumption: Option<config::resumptions::Active>,
        enable_early_data: bool,
    ) -> Self {
        use crate::client::session;
        use crate::crypto::material;
        use crate::memory::threadbound::ThreadBound;
        use crate::wire::handshake::reassemblers::HsReassembler;
        use ring::rand::SystemRandom;
        use session::Runtime;
        use session::{Application, Buffers, Credentials, Extensions, Handshake, OfferSettings};

        let workspace::Workspace { reassembly, flight } = storage;
        Self {
            reassembler: HsReassembler::with_buffer(reassembly),
            session: session::Session {
                offer: OfferSettings {
                    enable_early_data,
                    kex_group: kx::KexGroup::X25519,
                    offered_suites: array::CopyInline::from_array(record::CipherSuite::SUPPORTED),
                },
                handshake: Handshake::initial(resumption),
                kx: kx::Owned::new(),
                extensions: Extensions {
                    selected_alpn: None,
                    early_data: session::EarlyData::NotOffered,
                },
                credentials: Credentials {
                    certificate_response: None,
                },
                application: Application {
                    traffic: material::State::default(),
                    resumption_master: None,
                    exporter_master: None,
                },
                buffers: Buffers { flight },
                runtime: Runtime {
                    clock,
                    rng: SystemRandom::new(),
                    _thread: ThreadBound::NEW,
                },
            },
        }
    }
}

impl<C: connection::Clock> FramedCore<C> {
    pub(in crate::client) fn new(
        clock: C,
        storage: workspace::Workspace,
        resumption: Option<config::resumptions::Active>,
        enable_early_data: bool,
    ) -> Self {
        let Core { session, .. } = Core::new(clock, storage, resumption, enable_early_data);
        Self { session }
    }

    fn start_into<S: connection::LendingEventSink + ?Sized>(
        &mut self,
        policy: &config::Policy<'_>,
        transport_params: Option<&[u8]>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        let mut events = connection::RequiredFlightSink::new(events);
        drive::Drive::new(&mut self.session, policy).start(transport_params, &mut events)
    }

    fn read_framed_into<S: connection::LendingEventSink + ?Sized>(
        &mut self,
        policy: &config::Policy<'_>,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        let mut events = connection::RequiredFlightSink::new(events);
        dispatch_framed(&mut self.session, policy, epoch, raw, &mut events)
    }

    fn poison(&mut self) {
        self.session.poison();
    }

    pub(in crate::client) fn into_workspace(self) -> workspace::Workspace {
        self.session.release_framed_workspace()
    }
}

impl<C: connection::Clock, K: kx::Initiator> Core<C, K> {
    fn start_into<S: connection::EventSink + ?Sized>(
        &mut self,
        policy: &config::Policy<'_>,
        transport_params: Option<&[u8]>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        drive::Drive::new(&mut self.session, policy).start(transport_params, events)
    }

    fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        policy: &config::Policy<'_>,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        drive::Drive::new(&mut self.session, policy).read(
            &mut self.reassembler,
            epoch,
            data,
            events,
        )
    }

    fn read_framed_into<S: connection::EventSink + ?Sized>(
        &mut self,
        policy: &config::Policy<'_>,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        dispatch_framed(&mut self.session, policy, epoch, raw, events)
    }

    fn poison(&mut self) {
        self.session.poison();
        self.reassembler.discard();
    }

    pub(in crate::client) fn into_workspace(self) -> workspace::Workspace {
        self.session.release_workspace(self.reassembler)
    }
}

fn dispatch_framed<C, K, S>(
    session: &mut session::Session<C, K>,
    policy: &config::Policy<'_>,
    epoch: connection::Epoch,
    raw: &[u8],
    events: &mut S,
) -> Result<(), connection::DriveError<S::Error>>
where
    C: connection::Clock,
    K: kx::Initiator,
    S: connection::EventSink + ?Sized,
{
    use crate::wire::handshake::views::MessageRef;

    let message = MessageRef::decode(raw)?;
    session.dispatch(policy, epoch, message, raw, events)
}

impl<'pool, C: connection::Clock> PooledConnection<'pool, C> {
    pub(in crate::client) fn new(
        lease: recycle::Lease<'pool, workspace::Stored<C>>,
        authority: &'pool config::Authority,
    ) -> Self {
        Self { lease, authority }
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.lease
            .core
            .session
            .extensions
            .selected_alpn
            .and_then(|selected| self.authority.template().alpn(selected))
    }

    pub fn start_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.lease.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        self.lease.core.session.handshake.require_initial()?;
        let policy = self.authority.policy(None);
        let result = self.lease.core.start_into(&policy, None, events);
        if result.is_err() {
            self.lease.core.poison();
        }
        result
    }

    pub fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.lease.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let policy = self.authority.policy(None);
        let result = self.lease.core.read_into(&policy, epoch, data, events);
        if result.is_err() {
            self.lease.core.poison();
        }
        result
    }

    pub fn key_updates(&mut self) -> Updates<'_, C> {
        Updates::new(&mut self.lease.core, self.authority)
    }
}

impl<'pool, C: connection::Clock> FramedConnection<'pool, C> {
    pub(in crate::client) fn new(
        lease: recycle::Lease<'pool, workspace::FramedStored<C>>,
        authority: &'pool config::Authority,
    ) -> Self {
        Self { lease, authority }
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.lease
            .core
            .session
            .extensions
            .selected_alpn
            .and_then(|selected| self.authority.template().alpn(selected))
    }

    /// Validated cumulative QUIC CRYPTO storage required by each send epoch.
    /// Must be queried before the handshake starts.
    pub fn outbound_layout(&self) -> Result<connection::OutboundLayout, connection::Error> {
        let policy = self
            .authority
            .policy(Some(self.lease.transport_params.as_slice()));
        outbound_layout(&self.lease.core.session, &policy)
    }

    pub fn start_into<S: connection::LendingEventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.lease.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        self.lease.core.session.handshake.require_initial()?;
        let stored = &mut *self.lease;
        let policy = self
            .authority
            .policy(Some(stored.transport_params.as_slice()));
        let result = stored.core.start_into(&policy, None, events);
        if result.is_err() {
            self.lease.core.poison();
        }
        result
    }

    /// Processes exactly one complete encoded handshake message.
    pub fn read_framed_into<S: connection::LendingEventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.lease.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let stored = &mut *self.lease;
        let policy = self
            .authority
            .policy(Some(stored.transport_params.as_slice()));
        let result = stored.core.read_framed_into(&policy, epoch, raw, events);
        if result.is_err() {
            self.lease.core.poison();
        }
        result
    }

    pub fn is_done(&self) -> bool {
        self.lease.core.session.handshake.is_done()
    }
}

impl<C: connection::Clock> FramedClient<C> {
    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.core
            .session
            .extensions
            .selected_alpn
            .and_then(|selected| self.authority.template().alpn(selected))
    }

    pub fn outbound_layout(&self) -> Result<connection::OutboundLayout, connection::Error> {
        let policy = self.authority.policy(None);
        outbound_layout(&self.core.session, &policy)
    }

    pub fn start_into<S: connection::LendingEventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        self.core.session.handshake.require_initial()?;
        let policy = self.authority.policy(None);
        let result = self.core.start_into(&policy, None, events);
        if result.is_err() {
            self.core.poison();
        }
        result
    }

    pub fn read_framed_into<S: connection::LendingEventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if self.core.session.handshake.is_failed() {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let policy = self.authority.policy(None);
        let result = self.core.read_framed_into(&policy, epoch, raw, events);
        if result.is_err() {
            self.core.poison();
        }
        result
    }

    pub fn is_done(&self) -> bool {
        self.core.session.handshake.is_done()
    }
}

fn outbound_layout<C, K>(
    session: &session::Session<C, K>,
    policy: &config::Policy<'_>,
) -> Result<connection::OutboundLayout, connection::Error> {
    use crate::crypto::hash;

    session.handshake.require_initial()?;
    let hello = offer::Offer::maximum_initial_len_for_transport_params(
        policy.template().transport_mode(),
        policy.template().verifier(),
        policy.transport_params().len(),
        policy.template().alpn_protocols(),
        session.handshake.resumption.as_ref(),
    )
    .map_err(connection::Error::from)?;
    // CH2 may echo a peer-provided HRR cookie. Encoding remains bounded to one
    // plaintext record, matching the existing client admission policy.
    let plaintext = hello
        .checked_add(record::MAX_PLAINTEXT_BODY)
        .ok_or(connection::Error::BadConfig)?;

    const EMPTY_CERTIFICATE: usize = 4 + 1 + 3;
    const FINISHED: usize = 4 + hash::MAX_LEN;
    let authenticated = policy
        .identity()
        .map_or(EMPTY_CERTIFICATE + FINISHED, |identity| {
            identity.outbound_flight_capacity()
        });
    let end_of_early_data = usize::from(
        policy.template().transport_mode().uses_end_of_early_data()
            && session.offer.enable_early_data
            && session
                .handshake
                .resumption
                .as_ref()
                .and_then(|resumption| resumption.early_data_offer(&session.offer.offered_suites))
                .is_some(),
    ) * 4;
    let handshake = authenticated
        .checked_add(end_of_early_data)
        .ok_or(connection::Error::BadConfig)?;

    Ok(connection::OutboundLayout::new(plaintext, handshake, 0))
}

impl<'pool, C: connection::Clock + Copy> FramedConnection<'pool, C> {
    /// Releases the large handshake lease while retaining only QUIC session
    /// ticket derivation state and the pool-owned endpoint authority.
    pub fn into_quic_post_handshake(
        mut self,
    ) -> Result<QuicPostHandshake<'pool, C>, connection::Error> {
        if !self.authority.template().transport_mode().is_quic()
            || !self.lease.core.session.handshake.is_done()
        {
            return Err(connection::Error::UnexpectedMessage);
        }
        let suite = self
            .lease
            .core
            .session
            .application
            .traffic
            .suite()
            .ok_or(connection::Error::NotReady)?;
        let master = self.lease.core.session.application.resumption_master.take();
        let selected_alpn = self.lease.core.session.extensions.selected_alpn;
        let clock = self.lease.core.session.runtime.clock;
        let authority = self.authority;
        drop(self);
        Ok(QuicPostHandshake {
            authority,
            master,
            suite,
            selected_alpn,
            clock,
        })
    }
}

impl<C: connection::Clock> QuicPostHandshake<'_, C> {
    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn
            .and_then(|selected| self.authority.template().alpn(selected))
    }

    /// Processes a complete QUIC post-handshake message without reacquiring a
    /// handshake workspace.
    pub fn read_framed_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::wire::handshake::views::MessageRef;

        if epoch != connection::Epoch::Application {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        match MessageRef::decode(raw)? {
            MessageRef::NewSessionTicket(ticket) => {
                let policy = self.authority.policy(None);
                session::handle_new_session_ticket(
                    &policy,
                    self.master.as_ref(),
                    Some(self.suite),
                    self.selected_alpn,
                    self.clock.now_ms(),
                    ticket,
                    events,
                )
            }
            _ => Err(connection::Error::UnexpectedMessage.into()),
        }
    }
}

impl<'workspace, C: connection::Clock> Hybrid<'workspace, C> {
    /// Converts an unstarted client to the allocation-free hybrid profile.
    pub fn from_client(
        mut client: Client<C>,
        hybrid_workspace: &'workspace mut kx::HybridWorkspace,
    ) -> Result<Self, connection::Error> {
        client.set_kex_group(kx::KexGroup::X25519Mlkem768)?;
        let Client { core, authority } = client;
        let Core {
            reassembler,
            session,
        } = core;
        let session = session.with_kx(kx::Workspace::new(hybrid_workspace));
        Ok(Self {
            client: Client {
                core: Core {
                    reassembler,
                    session,
                },
                authority,
            },
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
        Updates::new(&mut self.client.core, &self.client.authority)
    }

    pub fn is_done(&self) -> bool {
        self.client.is_done()
    }

    /// Clears hybrid private state and returns the ordinary handshake storage.
    pub fn into_workspace(self) -> workspace::Workspace {
        self.client
            .core
            .session
            .release_workspace(self.client.core.reassembler)
    }
}
