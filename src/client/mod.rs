use arrayvec::ArrayVec;
use core::mem;

use ring::rand::{SecureRandom, SystemRandom};

use crate::connection::{
    Clock, DriveError, Epoch, Error, Event, EventContext, EventSink, KeyDirection,
};
use crate::crypto::hash::{Digest, HashAlg, MAX_HASH_LEN, Transcript};
use crate::crypto::kdf::Hkdf;
use crate::crypto::kx::{EphemeralKey, KexGroup};
use crate::crypto::schedule::{KeySchedule, ResumptionMaster};
use crate::identity::cert::{Cert, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION};
use crate::identity::chain::{Chain, ChainError, MAX_CHAIN_LEN, TrustAnchor};
use crate::identity::hostname::Hostname;
use crate::identity::spki::SubjectPublicKey;
use crate::identity::time::UnixTime;
use crate::memory::bound::ThreadBound;
use crate::wire::codec::{Encode, EncodeError, Reader};
use crate::wire::extension::{Extension, ExtensionType};
use crate::wire::handshake::frame::Frame;
use crate::wire::handshake::messages::{CertificateVerify, Finished, HandshakeType, KeyUpdate};
use crate::wire::handshake::reassemblers::{HsReassembler, KeyUpdateBudget};
use crate::wire::handshake::views::{
    CertificateRef, CertificateRequestRef, CertificateVerifyRef, EncryptedExtensionsRef,
    HandshakeRef, ServerHelloRef,
};
use crate::wire::handshake::workspace::{BoundedBuffer, HandshakeWorkspace};
use crate::wire::handshake::{
    HELLO_RETRY_REQUEST_RANDOM, MAX_KEY_UPDATES_WITHOUT_APP_DATA, RANDOM_LEN, TLS_1_2,
};
use crate::wire::proto::{
    Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, KeyShares, SignatureAlgorithms,
    SupportedVersions, TLS_1_3,
};
use crate::wire::psk::{
    KX_MODE_PSK_DHE, Offer, RESUMPTION_HASH, ResumptionBinder, SelectedIdentity,
};
use crate::wire::record::CipherSuite;
use zeroize::Zeroize;

mod authentication;
pub mod config;
mod negotiation;
mod offer;
mod state;
mod updates;

/// RFC 8446 §4.6.1: a client MUST NOT cache a ticket longer than 7 days, and a
/// server MUST NOT send a larger lifetime.
const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

use authentication::Authentication as _;
use config::{ClientCertSource, Config, Resumption, Verifier};
use negotiation::Negotiation as _;
use offer::ClientOffer as _;
use state::{HandshakeSecrets, State, StateKind};
use updates::Updates as _;

use crate::identity::peer::{LeafKey, LeafKeyKind};

/// ```compile_fail
/// use shin::client::Client;
/// fn assert_send<T: Send>() {}
/// assert_send::<Client<fn() -> u64>>();
/// ```
pub struct Client<C: Clock> {
    config: Config,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    eph: Option<EphemeralKey>,
    kex_group: KexGroup,
    offered_suites: ArrayVec<CipherSuite, 3>,
    c_ap_traffic: Option<Digest>,
    s_ap_traffic: Option<Digest>,
    selected_alpn: Option<ArrayVec<u8, 255>>,
    active_resumption: Option<Resumption>,
    resumption_master: Option<Digest>,
    exporter_master: Option<Digest>,
    negotiated_suite: Option<CipherSuite>,
    psk_used: bool,
    early_data_offered: bool,
    early_data_accepted: bool,
    ee_offered: ArrayVec<ExtensionType, 16>,
    clock: C,
    client_random: [u8; RANDOM_LEN],
    session_id: [u8; 32],
    hrr_done: bool,
    reasm: HsReassembler,
    /// Identity to present if the server sends a CertificateRequest (mutual TLS).
    client_cert: Option<ClientCertSource>,
    /// Set when the server requested client auth; carries the context to echo
    /// and the signature schemes it will accept in our CertificateVerify.
    cert_request: Option<CertRequest>,
    key_updates: KeyUpdateBudget<MAX_KEY_UPDATES_WITHOUT_APP_DATA>,
    flight: BoundedBuffer,
    identity_workspace: BoundedBuffer,
    _thread: ThreadBound,
}

struct CertRequest {
    context: ArrayVec<u8, 255>,
    signing_scheme_accepted: bool,
}

impl<C: Clock> Drop for Client<C> {
    fn drop(&mut self) {
        self.state.zeroize_secrets();
        for b in [
            &mut self.c_ap_traffic,
            &mut self.s_ap_traffic,
            &mut self.resumption_master,
            &mut self.exporter_master,
        ]
        .into_iter()
        .flatten()
        {
            b.as_mut_slice().zeroize();
        }
    }
}

impl<C: Clock> Client<C> {
    pub fn new(config: Config, clock: C) -> Self {
        Self::with_workspace(config, clock, HandshakeWorkspace::for_client())
    }

    pub fn with_workspace(config: Config, clock: C, workspace: HandshakeWorkspace) -> Self {
        let HandshakeWorkspace {
            reassembly,
            flight,
            identity,
        } = workspace;
        Self {
            config,
            clock,
            state: State::Initial,
            transcript: Transcript::new(),
            rng: SystemRandom::new(),
            eph: None,
            kex_group: KexGroup::X25519,
            offered_suites: CipherSuite::SUPPORTED.into_iter().collect(),
            c_ap_traffic: None,
            s_ap_traffic: None,
            selected_alpn: None,
            active_resumption: None,
            resumption_master: None,
            exporter_master: None,
            negotiated_suite: None,
            psk_used: false,
            early_data_offered: false,
            early_data_accepted: false,
            ee_offered: ArrayVec::new(),
            client_random: [0u8; RANDOM_LEN],
            session_id: [0; 32],
            hrr_done: false,
            reasm: HsReassembler::with_buffer(reassembly),
            client_cert: None,
            cert_request: None,
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

    /// Choose the (EC)DHE group to offer (default X25519). Must be set before
    /// `start`.
    pub fn set_kex_group(&mut self, group: KexGroup) {
        self.kex_group = group;
    }

    /// Restrict the cipher suites offered (default: all supported, AES-128
    /// first). Must be set before `start`.
    pub fn set_cipher_suites(&mut self, suites: &[CipherSuite]) {
        self.offered_suites.clear();
        self.offered_suites.extend(
            CipherSuite::SUPPORTED
                .into_iter()
                .filter(|suite| suites.contains(suite)),
        );
    }

    /// Present this identity if the server requests client authentication
    /// (mutual TLS). Must be set before `start`. Without it, a server that only
    /// *requests* (not requires) client auth gets an empty Certificate.
    pub fn set_client_cert(&mut self, source: ClientCertSource) {
        self.client_cert = Some(source);
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn.as_deref()
    }

    /// Suite selected by ServerHello for constructing the record
    /// [`Sealer`](crate::wire::record::Sealer) and [`Opener`](crate::wire::record::Opener).
    pub fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }

    /// RFC 5705 / RFC 8446 §7.5 exported keying material. Available only after
    /// the handshake completes (the server Finished has been processed).
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

    fn hash_alg(&self) -> HashAlg {
        self.negotiated_suite
            .map(|s| s.hash_alg())
            .unwrap_or(HashAlg::Sha256)
    }

    /// Starts the handshake and emits each event directly into `events`.
    pub fn start_into<S: EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        if self.state.kind() != StateKind::Initial {
            return Err(Error::UnexpectedMessage.into());
        }
        self.config.validate()?;
        if let Some(identity) = &self.client_cert {
            identity.validate()?;
        }
        let eph = EphemeralKey::generate(self.kex_group, &self.rng).map_err(|_| Error::Kx)?;

        let mut client_random = [0u8; RANDOM_LEN];
        self.rng.fill(&mut client_random).map_err(|_| Error::Rng)?;
        let mut session_id = [0u8; 32];
        self.rng.fill(&mut session_id).map_err(|_| Error::Rng)?;
        self.client_random = client_random;
        self.session_id = session_id;

        let resumption = self.config.resumption.take();
        let early_data_offered = self.config.enable_early_data && resumption.is_some();
        self.early_data_offered = early_data_offered;
        self.encode_client_hello(
            eph.client_share(),
            None,
            resumption.as_ref(),
            early_data_offered,
        )?;

        if let Some(r) = &resumption {
            Self::splice_psk_binder(&self.transcript, self.flight.as_mut_slice(), &r.psk)?;
        }

        self.transcript.update(&self.flight);
        self.active_resumption = resumption;

        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::Send {
                epoch: Epoch::Plaintext,
                data: &self.flight,
            },
        )?;
        if let Some(r) = self
            .active_resumption
            .as_ref()
            .filter(|_| early_data_offered)
        {
            let psk = r.psk;
            let h_ch = self.transcript.hash(RESUMPTION_HASH);
            let cets = KeySchedule::client_early_traffic_secret(&psk, h_ch.as_slice())?.to_digest();
            EventContext::emit(
                events,
                self.negotiated_suite,
                Event::ZeroRttKeysReady { secret: cets },
            )?;
        }

        self.eph = Some(eph);
        self.state = State::ExpectServerHello;

        Ok(())
    }

    /// Processes one record payload and emits events without an intermediate batch.
    pub fn read_into<S: EventSink + ?Sized>(
        &mut self,
        epoch: Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        self.reasm.begin_record(epoch)?;
        let mut input = data;
        while let Some(raw) = self.reasm.next_record(epoch, &mut input)? {
            let msg = HandshakeRef::decode(raw.as_ref())?;
            self.process(epoch, msg, raw.as_ref(), events)?;
            self.reasm.recycle(raw);
        }
        Ok(())
    }

    /// Mark application-data progress and reset the consecutive KeyUpdate budget.
    /// Call once per decrypted application record; otherwise the peer is aborted
    /// after [`MAX_KEY_UPDATES_WITHOUT_APP_DATA`] consecutive updates.
    pub fn note_application_data(&mut self) {
        self.key_updates.reset();
    }

    fn process<S: EventSink + ?Sized>(
        &mut self,
        epoch: Epoch,
        msg: HandshakeRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        match (self.state.kind(), msg) {
            (StateKind::ExpectServerHello, HandshakeRef::ServerHello(sh))
                if epoch == Epoch::Plaintext =>
            {
                self.handle_server_hello(sh, raw, events)
            }
            (StateKind::ExpectEncryptedExtensions, HandshakeRef::EncryptedExtensions(ee))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                self.handle_encrypted_extensions(ee, raw, secrets, events)
            }
            (StateKind::ExpectCertificate, HandshakeRef::CertificateRequest(cr))
                if epoch == Epoch::Handshake =>
            {
                self.handle_certificate_request(cr, raw)?;
                Ok(())
            }
            (StateKind::ExpectCertificate, HandshakeRef::Certificate(c))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                self.handle_certificate(c, raw, secrets)?;
                Ok(())
            }
            (StateKind::ExpectCertificateVerify, HandshakeRef::CertificateVerify(cv))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                let server_leaf_key = self
                    .state
                    .server_leaf_key()
                    .ok_or(Error::UnexpectedMessage)?;
                self.handle_certificate_verify(cv, raw, secrets, &server_leaf_key)?;
                Ok(())
            }
            (StateKind::ExpectServerFinished, HandshakeRef::Finished(f))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                self.handle_server_finished(f, raw, secrets, events)
            }
            (StateKind::Done, HandshakeRef::KeyUpdate(ku)) if epoch == Epoch::Application => {
                self.handle_key_update(ku, events)
            }
            (StateKind::Done, HandshakeRef::NewSessionTicket(nst))
                if epoch == Epoch::Application =>
            {
                if nst.ticket_lifetime > MAX_TICKET_LIFETIME_SECS {
                    return Err(Error::IllegalParameter.into());
                }
                if let Some(rms) = self.resumption_master.as_ref()
                    && self.hash_alg() == RESUMPTION_HASH
                {
                    let psk = ResumptionMaster::from_secret(rms).psk(nst.ticket_nonce)?;
                    EventContext::emit(
                        events,
                        self.negotiated_suite,
                        Event::ResumptionSecret { psk },
                    )?;
                }
                let max_early_data = nst
                    .extensions
                    .iter()
                    .find(|e| e.ty == ExtensionType::EARLY_DATA)
                    .map(|e| {
                        let mut r = Reader::new(e.data);
                        let v = r.u32().map_err(Error::from)?;
                        r.finish().map_err(Error::from)?;
                        Ok::<u32, Error>(v)
                    })
                    .transpose()?;
                EventContext::emit(
                    events,
                    self.negotiated_suite,
                    Event::NewSessionTicket {
                        ticket_lifetime: nst.ticket_lifetime,
                        ticket_age_add: nst.ticket_age_add,
                        ticket_nonce: nst.ticket_nonce,
                        ticket: nst.ticket,
                        max_early_data,
                    },
                )?;
                Ok(())
            }
            _ => Err(Error::UnexpectedMessage.into()),
        }
    }

    pub fn is_done(&self) -> bool {
        self.state.kind() == StateKind::Done
    }

    /// Emits a KeyUpdate directly into `events`.
    pub fn send_key_update_into<S: EventSink + ?Sized>(
        &mut self,
        request_update: bool,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        if self.state.kind() != StateKind::Done {
            return Err(Error::UnexpectedMessage.into());
        }
        let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_c_ap = Hkdf::new(self.hash_alg())
            .traffic_update(&c_ap)?
            .to_digest();
        self.c_ap_traffic = Some(new_c_ap);

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
                secret: new_c_ap,
            },
        )?;
        Ok(())
    }
}
