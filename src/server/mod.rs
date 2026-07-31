use arrayvec::ArrayVec;
use core::mem;

use ring::rand::{SecureRandom, SystemRandom};

use crate::connection::{
    Clock, DriveError, Epoch, Error, Event, EventContext, EventSink, KeyDirection, WorkspaceRegion,
};
use crate::crypto::hash::{Digest, HashAlg, Transcript};
use crate::crypto::kdf::Hkdf;
use crate::crypto::kx::KexGroup;
use crate::crypto::schedule::{KeySchedule, ResumptionMaster};
use crate::crypto::ticket::TicketKeys;
use crate::identity::peer::LeafKey;
use crate::identity::spki::SubjectPublicKey;
use crate::memory::bound::ThreadBound;
use crate::wire::codec::{Encode, EncodeError};
use crate::wire::extension::{Extension, ExtensionType};
use crate::wire::handshake::frame::Frame;
use crate::wire::handshake::messages::{CertificateVerify, Finished, HandshakeType, KeyUpdate};
use crate::wire::handshake::reassemblers::{HsReassembler, KeyUpdateBudget};
use crate::wire::handshake::views::{
    CertificateRef, CertificateVerifyRef, ClientHelloRef, HandshakeRef,
};
use crate::wire::handshake::workspace::{BoundedBuffer, HandshakeWorkspace};
use crate::wire::handshake::{
    HELLO_RETRY_REQUEST_RANDOM, MAX_KEY_UPDATES_WITHOUT_APP_DATA, RANDOM_LEN, TLS_1_2,
};
use crate::wire::proto::{
    CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, KeyShares, SignatureAlgorithms, SupportedGroups,
    SupportedVersions, TLS_1_3,
};
use crate::wire::psk::{KX_MODE_PSK_DHE, KxModes, Offer, RESUMPTION_HASH, ResumptionBinder};
use crate::wire::record::CipherSuite;
use zeroize::Zeroize;

mod authentication;
pub mod config;
mod early;
mod hello;
mod negotiation;
mod resumption;
mod state;
mod updates;

use authentication::ClientAuthentication as _;
use config::{
    CertSource, ClientAuth, ClientCertVerifier, ClientCertificateChain, ClientIdentity, Config,
    ConnectionConfig, EarlyDataGuard, NoClientAuth, NoGuard,
};
use early::{AcceptedPsk, EarlyDataAdmission, TICKET_LIFETIME_SECS};
use hello::Hello as _;
use negotiation::ClientHelloOffers;
use resumption::Resumption as _;
use state::State;
use updates::Updates as _;

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
pub struct Shard<G: EarlyDataGuard = NoGuard, V: ClientCertVerifier = NoClientAuth> {
    config: Config,
    guard: G,
    client_auth: Option<ClientAuth>,
    verifier: V,
    _thread: ThreadBound,
}

impl Shard<NoGuard, NoClientAuth> {
    pub fn new(config: Config) -> Self {
        Self::build(config, NoGuard, None, NoClientAuth)
    }
}

impl<G: EarlyDataGuard> Shard<G, NoClientAuth> {
    pub fn with_early_data_guard(config: Config, guard: G) -> Self {
        Self::build(config, guard, None, NoClientAuth)
    }
}

impl<V: ClientCertVerifier> Shard<NoGuard, V> {
    pub fn with_client_auth(config: Config, mode: ClientAuth, verifier: V) -> Self {
        Self::build(config, NoGuard, Some(mode), verifier)
    }
}

impl<G: EarlyDataGuard, V: ClientCertVerifier> Shard<G, V> {
    pub fn with_early_data_guard_and_client_auth(
        config: Config,
        guard: G,
        mode: ClientAuth,
        verifier: V,
    ) -> Self {
        Self::build(config, guard, Some(mode), verifier)
    }

    fn build(config: Config, guard: G, client_auth: Option<ClientAuth>, verifier: V) -> Self {
        Self {
            config,
            guard,
            client_auth,
            verifier,
            _thread: ThreadBound::NEW,
        }
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<TicketKeys>) {
        self.config.ticket_keys = keys;
    }
}

/// ```compile_fail
/// use shin::server::Server;
/// fn assert_send<T: Send>() {}
/// assert_send::<Server<fn() -> u64>>();
/// ```
pub struct Server<C: Clock> {
    config: ConnectionConfig,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    c_ap_traffic: Option<Digest>,
    s_ap_traffic: Option<Digest>,
    selected_alpn: Option<ArrayVec<u8, 255>>,
    master: Option<KeySchedule>,
    early_data: EarlyDataAdmission,
    clock: C,
    hrr_done: bool,
    exporter_master: Option<Digest>,
    negotiated_suite: Option<CipherSuite>,
    reasm: HsReassembler,
    /// The client_certificate_type the server expects in the client's
    /// Certificate (CERT_TYPE_X509 by default, RFC 7250 §4.2).
    negotiated_client_cert_type: u8,
    /// The client's leaf key, captured during its Certificate, used to verify
    /// its CertificateVerify.
    client_leaf: Option<LeafKey>,
    key_updates: KeyUpdateBudget<MAX_KEY_UPDATES_WITHOUT_APP_DATA>,
    flight: BoundedBuffer,
    identity_workspace: BoundedBuffer,
    _thread: ThreadBound,
}

impl<C: Clock> Drop for Server<C> {
    fn drop(&mut self) {
        self.state.zeroize_secrets();
        for b in [
            &mut self.c_ap_traffic,
            &mut self.s_ap_traffic,
            &mut self.exporter_master,
        ]
        .into_iter()
        .flatten()
        {
            b.as_mut_slice().zeroize();
        }
    }
}

impl<C: Clock> Server<C> {
    pub fn new(config: ConnectionConfig, clock: C) -> Self {
        Self::with_workspace(config, clock, HandshakeWorkspace::for_server())
    }

    pub fn with_workspace(
        config: ConnectionConfig,
        clock: C,
        workspace: HandshakeWorkspace,
    ) -> Self {
        let HandshakeWorkspace {
            reassembly,
            flight,
            identity,
        } = workspace;
        Self {
            config,
            clock,
            early_data: EarlyDataAdmission::new(),
            state: State::ExpectClientHello,
            transcript: Transcript::new(),
            rng: SystemRandom::new(),
            c_ap_traffic: None,
            s_ap_traffic: None,
            selected_alpn: None,
            master: None,
            hrr_done: false,
            exporter_master: None,
            negotiated_suite: None,
            reasm: HsReassembler::with_buffer(reassembly),
            negotiated_client_cert_type: CERT_TYPE_X509,
            client_leaf: None,
            key_updates: KeyUpdateBudget::default(),
            flight,
            identity_workspace: identity,
            _thread: ThreadBound::NEW,
        }
    }

    /// Returns the caller-owned handshake storage after clearing protocol bytes.
    pub fn into_workspace(mut self) -> HandshakeWorkspace {
        HandshakeWorkspace::from_buffers(
            self.reasm.release_buffer(),
            mem::take(&mut self.flight),
            mem::take(&mut self.identity_workspace),
        )
    }

    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// RFC 5705 / RFC 8446 §7.5 exported keying material. Available only after
    /// the handshake completes (the server Finished has been sent).
    pub fn export_keying_material(
        &self,
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let em = self.exporter_master.as_ref().ok_or(Error::NotReady)?;
        KeySchedule::export_keying_material(self.hash_alg(), em.as_slice(), label, context, out)?;
        Ok(())
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn.as_deref()
    }

    /// The negotiated record-protection suite, available once the ClientHello is
    /// processed. The embedder builds its record sealer/opener for this suite.
    pub fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }

    /// Advertised 0-RTT budget while its window is open. Because shin is sans-IO,
    /// call [`note_early_data`](Self::note_early_data) for every decrypted chunk.
    pub fn max_early_data_size(&self) -> Option<u32> {
        self.early_data.open_size()
    }

    /// Charge decrypted 0-RTT plaintext before delivery. A closed or exceeded
    /// window returns [`Error::EarlyDataLimitExceeded`] and closes permanently.
    pub fn note_early_data(&mut self, len: usize) -> Result<(), Error> {
        self.early_data.charge(len)
    }

    /// Processes one record payload and emits events without an intermediate batch.
    pub fn read_into<G, V, S>(
        &mut self,
        epoch: Epoch,
        data: &[u8],
        shard: &mut Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized,
    {
        self.reasm.begin_record(epoch)?;
        let mut input = data;
        while let Some(raw) = self.reasm.next_record(epoch, &mut input)? {
            let msg = HandshakeRef::decode(raw.as_ref())?;
            self.process(epoch, msg, raw.as_ref(), shard, events)?;
            self.reasm.recycle(raw);
        }
        Ok(())
    }

    /// Mark application-data progress and reset the consecutive KeyUpdate budget.
    /// Call once per decrypted record or the peer is aborted after
    /// [`MAX_KEY_UPDATES_WITHOUT_APP_DATA`] updates.
    pub fn note_application_data(&mut self) {
        self.key_updates.reset();
    }

    fn process<G, V, S>(
        &mut self,
        epoch: Epoch,
        msg: HandshakeRef<'_>,
        raw: &[u8],
        shard: &mut Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized,
    {
        match (self.state, msg) {
            (State::ExpectClientHello, HandshakeRef::ClientHello(ch))
                if epoch == Epoch::Plaintext =>
            {
                self.handle_client_hello(ch, raw, shard, events)
            }
            (
                State::ExpectEndOfEarlyData {
                    client_handshake_traffic,
                },
                HandshakeRef::EndOfEarlyData,
            ) if epoch == Epoch::EarlyData => {
                self.handle_end_of_early_data(raw, client_handshake_traffic)?;
                Ok(())
            }
            (
                State::ExpectClientCertificate {
                    client_handshake_traffic,
                },
                HandshakeRef::Certificate(c),
            ) if epoch == Epoch::Handshake => {
                self.handle_client_certificate(
                    c,
                    raw,
                    client_handshake_traffic,
                    shard.client_auth,
                )?;
                Ok(())
            }
            (
                State::ExpectClientCertVerify {
                    client_handshake_traffic,
                },
                HandshakeRef::CertificateVerify(cv),
            ) if epoch == Epoch::Handshake => {
                self.handle_client_cert_verify(cv, raw, client_handshake_traffic, shard)?;
                Ok(())
            }
            (State::ExpectClientFinished { verify_data }, HandshakeRef::Finished(f))
                if epoch == Epoch::Handshake =>
            {
                self.handle_client_finished(f, raw, verify_data, shard, events)
            }
            (State::Done, HandshakeRef::KeyUpdate(ku)) if epoch == Epoch::Application => {
                self.handle_key_update(ku, events)
            }
            _ => Err(Error::UnexpectedMessage.into()),
        }
    }

    fn hash_alg(&self) -> HashAlg {
        self.negotiated_suite
            .map(|s| s.hash_alg())
            .unwrap_or(HashAlg::Sha256)
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Emits a KeyUpdate directly into `events`.
    pub fn send_key_update_into<S: EventSink + ?Sized>(
        &mut self,
        request_update: bool,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        if self.state != State::Done {
            return Err(Error::UnexpectedMessage.into());
        }
        let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_s_ap = Hkdf::new(self.hash_alg())
            .traffic_update(&s_ap)?
            .to_digest();
        self.s_ap_traffic = Some(new_s_ap);

        let ku = KeyUpdate {
            request_update: u8::from(request_update),
        };
        let bytes = ku.encode_framed();
        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::Send {
                epoch: Epoch::Application,
                data: &bytes,
            },
        )?;
        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::KeyUpdate {
                direction: KeyDirection::Write,
                secret: new_s_ap,
            },
        )?;
        Ok(())
    }
}
