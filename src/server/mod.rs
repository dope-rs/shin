use crate::connection;
use crate::crypto::material;
use crate::crypto::ticket;
use crate::memory::threadbound;
use crate::transport;
use crate::wire::handshake::views;
use crate::wire::handshake::workspace as handshake_workspace;
use crate::wire::record;
use authentication::Authentication as _;
use core::mem;
use hello::Hello as _;
use rand::SecureRandom as _;
use resumption::Resumption as _;
use ring::rand;
use session::Drive as _;

mod authentication;
mod bound;
pub mod config;
mod hello;
mod negotiation;
mod resumption;
mod retry;
mod session;
mod workspace;

pub use bound::connection::Connection;
pub use bound::multiplexedconnection::MultiplexedConnection;
pub use bound::multiplexedconnection::PooledConnection;
pub use bound::ownedconnection::OwnedConnection;
pub use bound::shard::Shard;
pub use session::updates::Updates;
pub use workspace::Workspace;
pub use workspace::WorkspaceLayout;
pub use workspace::WorkspaceProfile;

/// Authenticated namespace for deployment-wide 0-RTT replay decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayDomain([u8; ticket::REPLAY_DOMAIN_LEN]);

impl ReplayDomain {
    /// Creates the stable ID shared by shards using one replay store.
    /// Multi-process deployments must rotate it whenever that store resets.
    pub const fn new(id: [u8; ticket::REPLAY_DOMAIN_LEN]) -> Self {
        Self(id)
    }

    /// Generates a fail-safe namespace for one independently guarded shard.
    pub fn random() -> Result<Self, connection::Error> {
        let mut id = [0; ticket::REPLAY_DOMAIN_LEN];
        rand::SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| connection::Error::Rng)?;
        Ok(Self(id))
    }

    pub(super) fn id(&self) -> &[u8; ticket::REPLAY_DOMAIN_LEN] {
        &self.0
    }
}

/// ```compile_fail
/// use shin::server::Shard;
/// use shin::server::config::{CertSource, Config};
/// use shin::crypto::sig::SigningKey;
/// fn assert_send<T: Send>() {}
/// let config = Config {
///     source: CertSource::RawPublicKey {
///         signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
///     },
///     alpn_protocols: Vec::new(),
///     ticket_keys: None,
/// };
/// assert_send::<Shard>();
/// ```
///
/// ```compile_fail
/// use shin::server::Shard;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<Shard>();
/// ```
/// ```compile_fail
/// use shin::server::Server;
/// fn assert_send<T: Send>() {}
/// assert_send::<Server<fn() -> u64>>();
/// ```
pub struct Server<C: connection::Clock, const DOMAIN: u8 = 0> {
    session: session::Session<C>,
}

impl<C: connection::Clock, const DOMAIN: u8> session::Drive<DOMAIN> for Server<C, DOMAIN> {
    fn drive_record<G, V, S>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        shard: &mut Shard<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        self.session.buffers.reasm.begin_record(epoch)?;
        let mut input = data;
        while let Some(raw) = self.session.buffers.reasm.next_record(epoch, &mut input)? {
            let message = views::MessageRef::decode(raw.as_ref())?;
            self.process(epoch, message, raw.as_ref(), shard, events)?;
            self.session.buffers.reasm.recycle(raw);
        }
        Ok(())
    }

    fn process<G, V, S>(
        &mut self,
        epoch: connection::Epoch,
        message: views::MessageRef<'_>,
        raw: &[u8],
        shard: &mut Shard<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        let state = mem::replace(&mut self.session.handshake.state, session::State::Failed);
        match (state, message) {
            (session::State::ExpectClientHello, views::MessageRef::ClientHello(hello))
                if epoch == connection::Epoch::Plaintext =>
            {
                self.session.handshake.state = session::State::ExpectClientHello;
                self.handle_client_hello(hello, raw, shard, events)
            }
            (
                session::State::ExpectEndOfEarlyData {
                    client_handshake_traffic,
                },
                views::MessageRef::EndOfEarlyData,
            ) if epoch == connection::Epoch::Handshake => {
                self.handle_end_of_early_data(raw, client_handshake_traffic)?;
                Ok(())
            }
            (
                session::State::ExpectClientCertificate {
                    client_handshake_traffic,
                },
                views::MessageRef::Certificate(certificate),
            ) if epoch == connection::Epoch::Handshake => {
                self.handle_client_certificate(
                    certificate,
                    raw,
                    client_handshake_traffic,
                    shard.policy.client_auth,
                )?;
                Ok(())
            }
            (
                session::State::ExpectClientCertVerify {
                    client_handshake_traffic,
                },
                views::MessageRef::CertificateVerify(verify),
            ) if epoch == connection::Epoch::Handshake => {
                self.handle_client_cert_verify(verify, raw, client_handshake_traffic, shard)?;
                Ok(())
            }
            (
                session::State::ExpectClientFinished { verify_data },
                views::MessageRef::Finished(finished),
            ) if epoch == connection::Epoch::Handshake => {
                self.handle_client_finished(finished, raw, verify_data, shard, events)
            }
            (session::State::Done, views::MessageRef::KeyUpdate(update))
                if epoch == connection::Epoch::Application =>
            {
                self.session.handshake.state = session::State::Done;
                self.session.handle_key_update(update, events)
            }
            _ => Err(connection::Error::UnexpectedMessage.into()),
        }
    }

    fn poison(&mut self) {
        self.session.handshake.state.fail();
        self.session.application.zeroize_secrets();
        self.session.peer.early_data.close();
        self.session.buffers.reasm.discard();
        self.session.buffers.flight.clear();
        self.session.buffers.identity_workspace.clear();
    }
}

impl<C: connection::Clock, const DOMAIN: u8> Server<C, DOMAIN> {
    pub(in crate::server) fn tls_with_workspace<V>(clock: C, workspace: Workspace<V>) -> Self
    where
        V: config::ClientCertVerifier,
    {
        use alloc::vec::Vec;

        Self::from_validated(
            config::Connection {
                transport_params: Vec::new(),
            },
            transport::Mode::Tls,
            clock,
            workspace.into_scratch(),
        )
    }

    /// Creates a TLS-over-stream connection.
    pub fn new(config: config::Connection, clock: C) -> Result<Self, connection::Error> {
        Self::with_workspace(config, clock, handshake_workspace::Scratch::for_server())
    }

    /// Creates a connection for the explicitly selected transport.
    pub fn new_with_transport(
        config: config::Connection,
        transport_mode: transport::Mode,
        clock: C,
    ) -> Result<Self, connection::Error> {
        Self::with_transport_workspace(
            config,
            transport_mode,
            clock,
            handshake_workspace::Scratch::for_server(),
        )
    }

    pub fn with_workspace(
        config: config::Connection,
        clock: C,
        workspace: handshake_workspace::Scratch,
    ) -> Result<Self, connection::Error> {
        Self::with_transport_workspace(config, transport::Mode::Tls, clock, workspace)
    }

    /// Creates a connection with caller-owned storage for an explicit
    /// transport.
    pub fn with_transport_workspace(
        config: config::Connection,
        transport_mode: transport::Mode,
        clock: C,
        workspace: handshake_workspace::Scratch,
    ) -> Result<Self, connection::Error> {
        config.validate_with_transport(transport_mode)?;
        Ok(Self::from_validated(
            config,
            transport_mode,
            clock,
            workspace,
        ))
    }

    pub(in crate::server) fn from_validated(
        config: config::Connection,
        transport_mode: transport::Mode,
        clock: C,
        workspace: handshake_workspace::Scratch,
    ) -> Self {
        use crate::crypto::hash::Transcript;
        use crate::identity::CertificateType;
        use crate::wire::handshake::reassemblers::HsReassembler;
        use ring::rand::SystemRandom;
        use session::Application;
        use session::Buffers;
        use session::EarlyData;
        use session::Handshake;
        use session::Peer;
        use session::Runtime;
        let handshake_workspace::Scratch {
            reassembly,
            flight,
            identity,
        } = workspace;
        Self {
            session: session::Session {
                connection: config,
                transport_mode,
                handshake: Handshake {
                    state: session::State::ExpectClientHello,
                    transcript: Transcript::new(),
                    hrr_done: false,
                    hrr_invariant: None,
                },
                peer: Peer {
                    selected_alpn: None,
                    early_data: EarlyData::new(),
                    client_cert_type: CertificateType::X509,
                },
                application: Application {
                    traffic: material::State::default(),
                    master: None,
                    exporter_master: None,
                },
                buffers: Buffers {
                    reasm: HsReassembler::with_buffer(reassembly),
                    flight,
                    identity_workspace: identity,
                },
                runtime: Runtime {
                    clock,
                    rng: SystemRandom::new(),
                    _thread: threadbound::ThreadBound::NEW,
                },
            },
        }
    }

    /// Returns the caller-owned handshake storage after clearing protocol bytes.
    pub fn into_workspace(mut self) -> handshake_workspace::Scratch {
        handshake_workspace::Scratch::from_buffers(
            self.session.buffers.reasm.release_buffer(),
            mem::take(&mut self.session.buffers.flight),
            mem::take(&mut self.session.buffers.identity_workspace),
        )
    }

    /// RFC 5705 / RFC 8446 §7.5 exported keying material. Available only after
    /// the handshake completes (the server Finished has been sent).
    pub fn export_keying_material(
        &self,
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), connection::Error> {
        use crate::crypto::schedule::Schedule;
        let em = self
            .session
            .application
            .exporter_master
            .as_ref()
            .ok_or(connection::Error::NotReady)?;
        let algorithm = self.session.application.hash_alg()?;
        Schedule::export_keying_material(algorithm, em.as_slice(), label, context, out)?;
        Ok(())
    }

    /// The negotiated record-protection suite, available once the ClientHello is
    /// processed. The embedder builds its record sealer/opener for this suite.
    pub fn negotiated_cipher_suite(&self) -> Option<record::CipherSuite> {
        self.session.application.traffic.suite()
    }

    /// Advertised 0-RTT budget while its window is open. Because shin is sans-IO,
    /// call [`note_early_data`](Self::note_early_data) for every decrypted chunk.
    pub fn max_early_data_size(&self) -> Option<u32> {
        self.session
            .peer
            .early_data
            .open_size(self.session.transport_mode)
    }

    /// Checks the exact prepared workspace layout once before shard admission.
    fn validate_shard<G, V>(&self, shard: &Shard<G, V, DOMAIN>) -> Result<(), connection::Error>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
    {
        let required =
            shard.workspace_layout(&self.session.connection, self.session.transport_mode)?;
        let (fragmented_message, outbound_flight, peer_identity) = required.capacities();
        if self.session.buffers.reasm.capacity() < fragmented_message
            || self.session.buffers.flight.capacity() < outbound_flight
            || self.session.buffers.identity_workspace.capacity() < peer_identity
        {
            return Err(connection::Error::BadConfig);
        }
        Ok(())
    }

    /// Charge decrypted 0-RTT plaintext before delivery. A closed or exceeded
    /// window returns [`Error::EarlyDataLimitExceeded`](connection::Error::EarlyDataLimitExceeded)
    /// and closes permanently.
    pub fn note_early_data(&mut self, len: usize) -> Result<(), connection::Error> {
        if self.session.handshake.state == session::State::Failed {
            return Err(connection::Error::ConnectionFailed);
        }
        let result = self
            .session
            .peer
            .early_data
            .charge(len, self.session.transport_mode);
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn read_bound<G, V, S>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        shard: &mut Shard<G, V, DOMAIN>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized,
    {
        if self.session.handshake.state == session::State::Failed {
            return Err(connection::Error::ConnectionFailed.into());
        }
        let result = self.drive_record(epoch, data, shard, events);
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Borrows exclusive post-handshake KeyUpdate control.
    pub fn key_updates(&mut self) -> Updates<'_, C, DOMAIN> {
        Updates::new(self)
    }

    pub fn is_done(&self) -> bool {
        matches!(self.session.handshake.state, session::State::Done)
    }
}
