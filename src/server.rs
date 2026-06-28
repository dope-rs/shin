use alloc::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};

use crate::codec::Encode;
use crate::extension::{Extension, ExtensionType};
use crate::handshake::{
    Certificate, CertificateEntry, CertificateRequest, CertificateVerify, ClientHello,
    EncryptedExtensions, Finished, HELLO_RETRY_REQUEST_RANDOM, Handshake, HsReassembler,
    NewSessionTicket, RANDOM_LEN, ServerHello, TLS_1_2,
};
use crate::hash::{Digest, HashAlg, Transcript};
use crate::kx::KexGroup;
use crate::peer::{self, LeafKey};
use crate::proto::{
    Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, CertType, CertVerify,
    Finished as FinishedProto, KeyShare, SignatureAlgorithms, SupportedGroups, SupportedVersions,
    TLS_1_3,
};
use crate::psk::RESUMPTION_HASH;
use crate::record::CipherSuite;
use crate::schedule::KeySchedule;
use crate::sig::SigningKey;
use crate::spki;
use crate::ticket::TicketKeys;
use crate::{Clock, Epoch, Error, Event};

#[derive(Clone)]
pub struct Config {
    pub source: CertSource,
    pub transport_params: Vec<u8>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub ticket_keys: Option<TicketKeys>,
    pub accept_early_data: bool,
}

/// Embedder-supplied clock + replay store that makes 0-RTT early data safe.
///
/// Without a guard the server refuses early data even when `accept_early_data`
/// is set: neither the freshness window nor the single-use check can run
/// (RFC 8446 §8).
pub trait EarlyDataGuard {
    /// Record a single-use token (the PSK binder); `false` means it was already
    /// seen — a replay. Tokens need only be kept for `TICKET_LIFETIME_SECS`.
    fn register(&mut self, token: &[u8]) -> bool;
}

/// Default guard for servers that never accept 0-RTT: reports every token as
/// already-seen, so early data is always refused.
pub struct NoGuard;

impl EarlyDataGuard for NoGuard {
    fn register(&mut self, _token: &[u8]) -> bool {
        false
    }
}

/// Allowed skew between client-claimed and server-measured ticket age (RFC 8446 §8.2).
const MAX_TICKET_AGE_SKEW_MS: u64 = 10_000;

/// max_early_data_size advertised in NewSessionTicket when 0-RTT is accepted.
const MAX_EARLY_DATA_SIZE: u32 = 16384;

/// NewSessionTicket lifetime and upper bound of the 0-RTT freshness window.
const TICKET_LIFETIME_SECS: u32 = 7200;
const TICKET_LIFETIME_MS: u64 = TICKET_LIFETIME_SECS as u64 * 1000;

struct AcceptedPsk {
    psk: [u8; 32],
    age_add: u32,
    issued_at_ms: u64,
    suite: u16,
    obfuscated_ticket_age: u32,
    binder: Vec<u8>,
    alpn: Vec<u8>,
}

#[derive(Clone)]
pub enum CertSource {
    RawPublicKey {
        signing_key: SigningKey,
    },
    X509 {
        chain_der: Vec<Vec<u8>>,
        signing_key: SigningKey,
    },
}

impl CertSource {
    fn signing_key(&self) -> &SigningKey {
        match self {
            Self::RawPublicKey { signing_key } => signing_key,
            Self::X509 { signing_key, .. } => signing_key,
        }
    }
}

/// Whether the server authenticates the client (mutual TLS). `Requested` allows
/// an anonymous client (empty Certificate); `Required` rejects one. Either way a
/// presented identity is signature-verified and then passed to the embedder's
/// [`ClientCertVerifier`] for pinning.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    Requested,
    Required,
}

/// Default [`ClientCertVerifier`] for a server that does not authenticate
/// clients; its [`verify`](ClientCertVerifier::verify) is never reached.
pub struct NoClientAuth;

impl ClientCertVerifier for NoClientAuth {
    fn verify(&self, _identity: &ClientIdentity<'_>) -> bool {
        false
    }
}

/// Embedder hook that decides whether a signature-verified client identity is
/// authorized (the `authorized_keys` model: pin on `spki_der`). Verification of
/// possession (the CertificateVerify signature) has already passed when this is
/// called; this decides *authorization*, not authenticity.
pub trait ClientCertVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool;
}

/// A signature-verified client identity handed to [`ClientCertVerifier`].
pub struct ClientIdentity<'a> {
    /// `CERT_TYPE_X509` (0) or `CERT_TYPE_RAW_PUBLIC_KEY` (2).
    pub cert_type: u8,
    /// The leaf SubjectPublicKeyInfo DER — a uniform pinning target across key
    /// types. For RawPublicKey this is the entire certificate.
    pub spki_der: &'a [u8],
    /// The presented X.509 chain (leaf first); empty for RawPublicKey.
    pub chain_der: &'a [Vec<u8>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    ExpectClientHello,
    ExpectEndOfEarlyData,
    ExpectClientCertificate,
    ExpectClientCertVerify,
    ExpectClientFinished,
    Done,
}

pub struct Server<C: Clock, G: EarlyDataGuard = NoGuard, V: ClientCertVerifier = NoClientAuth> {
    config: Config,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    c_hs_traffic: Option<Digest>,
    expected_client_finished: Option<Digest>,
    c_ap_traffic: Option<Digest>,
    s_ap_traffic: Option<Digest>,
    selected_alpn: Option<Vec<u8>>,
    master: Option<KeySchedule>,
    early_data_guard: Option<G>,
    early_data_remaining: Option<u32>,
    clock: C,
    hrr_done: bool,
    exporter_master: Option<Digest>,
    negotiated_suite: Option<crate::record::CipherSuite>,
    reasm: HsReassembler,
    client_auth: Option<ClientAuth>,
    verifier: V,
    /// The client_certificate_type the server expects in the client's
    /// Certificate (CERT_TYPE_X509 by default, RFC 7250 §4.2).
    negotiated_client_cert_type: u8,
    /// The client's leaf key, captured during its Certificate, used to verify
    /// its CertificateVerify.
    client_leaf: Option<LeafKey>,
    client_spki_der: Vec<u8>,
    client_cert_chain: Vec<Vec<u8>>,
    /// Post-handshake KeyUpdates received since the last application-data record;
    /// reset by `note_application_data`. Bounds rekey flooding across records.
    key_updates_since_app_data: u32,
}

impl<C: Clock, G: EarlyDataGuard, V: ClientCertVerifier> Drop for Server<C, G, V> {
    fn drop(&mut self) {
        for b in [
            &mut self.c_hs_traffic,
            &mut self.expected_client_finished,
            &mut self.c_ap_traffic,
            &mut self.s_ap_traffic,
            &mut self.exporter_master,
        ]
        .into_iter()
        .flatten()
        {
            crate::schedule::zeroize(b.as_mut_slice());
        }
    }
}

impl<C: Clock> Server<C, NoGuard, NoClientAuth> {
    /// A server that never accepts 0-RTT and does not authenticate clients. For
    /// 0-RTT use [`with_early_data_guard`](Server::with_early_data_guard); for
    /// mutual TLS use [`with_client_auth`](Server::with_client_auth).
    pub fn new(config: Config, clock: C) -> Self {
        Self::build(config, clock, None, None, NoClientAuth)
    }
}

impl<C: Clock, G: EarlyDataGuard> Server<C, G, NoClientAuth> {
    /// A server that accepts 0-RTT, gated by `guard` (replay store + freshness).
    pub fn with_early_data_guard(config: Config, clock: C, guard: G) -> Self {
        Self::build(config, clock, Some(guard), None, NoClientAuth)
    }
}

impl<C: Clock, V: ClientCertVerifier> Server<C, NoGuard, V> {
    /// A server that authenticates the client (mutual TLS). `verifier` decides
    /// authorization of each possession-proven identity (the `authorized_keys`
    /// model); `mode` chooses whether an anonymous client is tolerated.
    pub fn with_client_auth(config: Config, clock: C, mode: ClientAuth, verifier: V) -> Self {
        Self::build(config, clock, None, Some(mode), verifier)
    }
}

impl<C: Clock, G: EarlyDataGuard, V: ClientCertVerifier> Server<C, G, V> {
    /// Both 0-RTT (gated by `guard`) and mutual TLS (`mode` + `verifier`).
    pub fn with_early_data_guard_and_client_auth(
        config: Config,
        clock: C,
        guard: G,
        mode: ClientAuth,
        verifier: V,
    ) -> Self {
        Self::build(config, clock, Some(guard), Some(mode), verifier)
    }

    fn build(
        config: Config,
        clock: C,
        early_data_guard: Option<G>,
        client_auth: Option<ClientAuth>,
        verifier: V,
    ) -> Self {
        Self {
            config,
            clock,
            early_data_guard,
            early_data_remaining: None,
            state: State::ExpectClientHello,
            transcript: Transcript::new(),
            rng: SystemRandom::new(),
            c_hs_traffic: None,
            expected_client_finished: None,
            c_ap_traffic: None,
            s_ap_traffic: None,
            selected_alpn: None,
            master: None,
            hrr_done: false,
            exporter_master: None,
            negotiated_suite: None,
            reasm: HsReassembler::default(),
            client_auth,
            verifier,
            negotiated_client_cert_type: CERT_TYPE_X509,
            client_leaf: None,
            client_spki_der: Vec::new(),
            client_cert_chain: Vec::new(),
            key_updates_since_app_data: 0,
        }
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
        crate::schedule::export_keying_material(
            self.hash_alg(),
            em.as_slice(),
            label,
            context,
            out,
        );
        Ok(())
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn.as_deref()
    }

    /// The negotiated record-protection suite, available once the ClientHello is
    /// processed. The embedder builds its record sealer/opener for this suite.
    pub fn negotiated_cipher_suite(&self) -> Option<crate::record::CipherSuite> {
        self.negotiated_suite
    }

    /// The 0-RTT early-data byte budget the server advertised for this
    /// connection, or `None` if early data was not accepted (no
    /// [`Event::ZeroRttKeysReady`](crate::Event::ZeroRttKeysReady)) or the
    /// early-data window has already closed (EndOfEarlyData processed).
    ///
    /// shin is sans-IO: 0-RTT *application* records arrive at
    /// [`Epoch::EarlyData`](crate::Epoch) and are decrypted by the embedder, so
    /// shin never sees those plaintext bytes. Whenever this returns `Some`, the
    /// embedder MUST call [`note_early_data`](Self::note_early_data) for every
    /// early-data plaintext chunk it routes to the application; that call
    /// enforces this limit (RFC 8446 §4.6.1).
    pub fn max_early_data_size(&self) -> Option<u32> {
        self.early_data_remaining.map(|_| MAX_EARLY_DATA_SIZE)
    }

    /// Charge `len` plaintext bytes of received 0-RTT early data against the
    /// advertised [`max_early_data_size`](Self::max_early_data_size). The
    /// embedder MUST call this for every `Epoch::EarlyData` application record it
    /// decrypts, before delivering those bytes to the application.
    ///
    /// Returns [`Error::EarlyDataLimitExceeded`] (fatal; alert
    /// `unexpected_message`) once the client exceeds the limit, and likewise if
    /// called when no early-data window is open — either early data was not
    /// accepted or EndOfEarlyData already closed it (RFC 8446 §4.6.1). On error
    /// the window is closed; the embedder must abort the connection.
    pub fn note_early_data(&mut self, len: usize) -> Result<(), Error> {
        let remaining = self
            .early_data_remaining
            .as_mut()
            .ok_or(Error::EarlyDataLimitExceeded)?;
        match u32::try_from(len)
            .ok()
            .and_then(|n| remaining.checked_sub(n))
        {
            Some(left) => {
                *remaining = left;
                Ok(())
            }
            None => {
                self.early_data_remaining = None;
                Err(Error::EarlyDataLimitExceeded)
            }
        }
    }

    pub fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        self.reasm.push(epoch, data)?;
        let mut events = Vec::new();
        while let Some((msg, raw)) = self.reasm.next_message()? {
            self.process(epoch, msg, &raw, &mut events)?;
        }
        Ok(events)
    }

    /// Record that an `Epoch::Application` application-data record was received,
    /// marking forward progress that resets the post-handshake KeyUpdate flood
    /// counter (see [`MAX_KEY_UPDATES_WITHOUT_APP_DATA`]). The embedder SHOULD call
    /// this for every application-data record it decrypts; without it, a peer that
    /// floods KeyUpdates with no intervening application data is aborted once the
    /// cap is reached.
    ///
    /// [`MAX_KEY_UPDATES_WITHOUT_APP_DATA`]: crate::handshake::MAX_KEY_UPDATES_WITHOUT_APP_DATA
    pub fn note_application_data(&mut self) {
        self.key_updates_since_app_data = 0;
    }

    fn process(
        &mut self,
        epoch: Epoch,
        msg: Handshake,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        match (self.state, msg) {
            (State::ExpectClientHello, Handshake::ClientHello(ch)) if epoch == Epoch::Plaintext => {
                self.handle_client_hello(ch, raw, events)
            }
            (State::ExpectEndOfEarlyData, Handshake::EndOfEarlyData)
                if epoch == Epoch::EarlyData =>
            {
                self.handle_end_of_early_data(raw)
            }
            (State::ExpectClientCertificate, Handshake::Certificate(c))
                if epoch == Epoch::Handshake =>
            {
                self.handle_client_certificate(c, raw)
            }
            (State::ExpectClientCertVerify, Handshake::CertificateVerify(cv))
                if epoch == Epoch::Handshake =>
            {
                self.handle_client_cert_verify(cv, raw)
            }
            (State::ExpectClientFinished, Handshake::Finished(f)) if epoch == Epoch::Handshake => {
                self.handle_client_finished(f, raw, events)
            }
            (State::Done, Handshake::KeyUpdate(ku)) if epoch == Epoch::Application => {
                self.handle_key_update(ku, events)
            }
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn hash_alg(&self) -> HashAlg {
        self.negotiated_suite
            .map(|s| s.hash_alg())
            .unwrap_or(HashAlg::Sha256)
    }

    fn handle_key_update(
        &mut self,
        ku: crate::handshake::KeyUpdate,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        self.key_updates_since_app_data += 1;
        if self.key_updates_since_app_data > crate::handshake::MAX_KEY_UPDATES_WITHOUT_APP_DATA {
            return Err(Error::UnexpectedMessage);
        }
        let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_c_ap = crate::kdf::Hkdf::traffic_update(self.hash_alg(), &c_ap).to_digest();
        self.c_ap_traffic = Some(new_c_ap);
        events.push(Event::KeyUpdate {
            direction: crate::KeyDirection::Read,
            secret: new_c_ap,
        });

        if ku.request_update == 1 {
            let reply = crate::handshake::KeyUpdate { request_update: 0 };
            let mut bytes = Vec::new();
            Handshake::KeyUpdate(reply).encode(&mut bytes);
            events.push(Event::Send {
                epoch: Epoch::Application,
                data: bytes,
            });
            let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
            let new_s_ap = crate::kdf::Hkdf::traffic_update(self.hash_alg(), &s_ap).to_digest();
            self.s_ap_traffic = Some(new_s_ap);
            events.push(Event::KeyUpdate {
                direction: crate::KeyDirection::Write,
                secret: new_s_ap,
            });
        }
        Ok(())
    }

    fn handle_client_hello(
        &mut self,
        ch: ClientHello,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let selected_suite = CipherSuite::SUPPORTED
            .iter()
            .copied()
            .find(|s| ch.cipher_suites.contains(&s.to_u16()))
            .ok_or(Error::UnsupportedCipherSuite)?;
        self.negotiated_suite = Some(selected_suite);
        let hash_alg = selected_suite.hash_alg();
        if ch.legacy_compression_methods != [0] {
            return Err(Error::IllegalParameter);
        }
        if ch.legacy_session_id.len() > 32 {
            return Err(Error::Decode);
        }
        let sv = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::MissingExtension)?;
        if !SupportedVersions::client_decode(&sv.data)?.contains(&TLS_1_3) {
            return Err(Error::BadVersion);
        }
        let groups = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::MissingExtension)?;
        let client_groups = SupportedGroups::decode(&groups.data)?;
        let hrr_group = KexGroup::SUPPORTED
            .iter()
            .copied()
            .find(|g| client_groups.contains(&g.to_u16()))
            .ok_or(Error::UnsupportedGroup)?;
        let sigs = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::MissingExtension)?;
        let local_sig_scheme = self.config.source.signing_key().sig_scheme();
        if !SignatureAlgorithms::decode(&sigs.data)?.contains(&local_sig_scheme) {
            return Err(Error::UnsupportedSigScheme);
        }
        let chosen_share = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::KEY_SHARE)
            .map(|ks| KeyShare::select_client_entry(&ks.data, &KexGroup::SUPPORTED))
            .transpose()?
            .flatten();
        let (kex_group, peer_pubkey) = match chosen_share {
            Some(v) => v,
            None if !self.hrr_done => {
                return self.send_hello_retry_request(
                    raw,
                    &ch.legacy_session_id,
                    hrr_group,
                    events,
                );
            }
            None => return Err(Error::MissingExtension),
        };

        // RFC 7250 §4.1 — server MUST NOT echo the cert_type extensions
        // unless the client offered them. Same applies to RFC 9001's
        // QUIC transport_parameters: only sent over QUIC, signaled by
        // the client offering the extension. Track what the client
        // actually sent so the EE construction below can be conditional.
        let mut client_offered_server_cert_type: Option<Vec<u8>> = None;
        let mut client_offered_client_cert_type: Option<Vec<u8>> = None;
        let mut client_offered_quic_tp = false;
        for ext in &ch.extensions {
            if ext.ty == ExtensionType::QUIC_TRANSPORT_PARAMETERS {
                client_offered_quic_tp = true;
                events.push(Event::PeerExtension {
                    ty: ext.ty.0,
                    data: ext.data.clone(),
                });
            } else if ext.ty == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                && !self.config.alpn_protocols.is_empty()
            {
                let offered = Alpn::decode(&ext.data).map_err(|_| Error::Decode)?;
                self.selected_alpn = self
                    .config
                    .alpn_protocols
                    .iter()
                    .find(|s| offered.iter().any(|o| o == *s))
                    .cloned();
                if self.selected_alpn.is_none() && !offered.is_empty() {
                    return Err(Error::NoApplicationProtocol);
                }
            } else if ext.ty == ExtensionType::SERVER_CERTIFICATE_TYPE {
                client_offered_server_cert_type =
                    Some(CertType::decode_list(&ext.data).map_err(|_| Error::Decode)?);
            } else if ext.ty == ExtensionType::CLIENT_CERTIFICATE_TYPE {
                client_offered_client_cert_type =
                    Some(CertType::decode_list(&ext.data).map_err(|_| Error::Decode)?);
            }
        }

        let psk_accepted = if hash_alg == RESUMPTION_HASH {
            self.try_accept_psk(&ch, raw)
        } else {
            None
        };
        let client_offered_early = ch
            .extensions
            .iter()
            .any(|e| e.ty == ExtensionType::EARLY_DATA);
        let early_accepted = self.config.accept_early_data
            && client_offered_early
            && match psk_accepted.as_ref() {
                Some(p) => {
                    // RFC 8446 §4.2.10: reject 0-RTT unless the newly-negotiated ALPN
                    // and cipher suite both match the original session's.
                    let selected = self.selected_alpn.as_deref().unwrap_or(&[]);
                    let suite_ok = self.negotiated_suite.map(|s| s.to_u16()) == Some(p.suite);
                    selected == p.alpn.as_slice() && suite_ok && self.check_early_data_replay(p)
                }
                None => false,
            };

        self.transcript.update(raw);

        if let (Some(p), true) = (psk_accepted.as_ref(), early_accepted) {
            let h_ch = self.transcript.hash(RESUMPTION_HASH);
            let cets =
                crate::schedule::client_early_traffic_secret(&p.psk, h_ch.as_slice()).to_digest();
            events.push(Event::ZeroRttKeysReady { secret: cets });
        }

        let session_id_echo = ch.legacy_session_id.clone();

        let (server_share, dhe) =
            crate::kx::responder(kex_group, &peer_pubkey, &self.rng).map_err(|_| Error::Kx)?;
        let mut server_random = [0u8; RANDOM_LEN];
        self.rng.fill(&mut server_random).map_err(|_| Error::Rng)?;

        let mut sh_extensions = alloc::vec![
            Extension::new(
                ExtensionType::SUPPORTED_VERSIONS,
                SupportedVersions::server_encode()
            ),
            Extension::new(
                ExtensionType::KEY_SHARE,
                KeyShare::server_encode(kex_group, &server_share)
            ),
        ];
        if psk_accepted.is_some() {
            sh_extensions.push(Extension::new(
                ExtensionType::PRE_SHARED_KEY,
                crate::psk::SelectedIdentity::encode(0),
            ));
        }
        let sh = ServerHello {
            legacy_version: TLS_1_2,
            random: server_random,
            legacy_session_id_echo: session_id_echo,
            cipher_suite: self
                .negotiated_suite
                .expect("suite selected in CH")
                .to_u16(),
            legacy_compression_method: 0,
            extensions: sh_extensions,
        };
        let mut sh_bytes = Vec::new();
        Handshake::ServerHello(sh).encode(&mut sh_bytes);
        self.transcript.update(&sh_bytes);

        events.push(Event::Send {
            epoch: Epoch::Plaintext,
            data: sh_bytes,
        });

        let ks_handshake = match &psk_accepted {
            Some(p) => KeySchedule::new_psk(RESUMPTION_HASH, &p.psk).into_handshake(dhe.as_slice()),
            None => KeySchedule::new(hash_alg).into_handshake(dhe.as_slice()),
        };
        let h_chsh = self.transcript.hash(hash_alg);
        let c_hs = ks_handshake
            .client_handshake_traffic_secret(h_chsh.as_slice())
            .to_digest();
        let s_hs = ks_handshake
            .server_handshake_traffic_secret(h_chsh.as_slice())
            .to_digest();

        events.push(Event::KeysReady {
            epoch: Epoch::Handshake,
            read_secret: c_hs,
            write_secret: s_hs,
        });

        let server_cert_type = match &self.config.source {
            CertSource::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            CertSource::X509 { .. } => CERT_TYPE_X509,
        };
        // If the client offered `server_certificate_type` and the type
        // we'd send isn't in their list, fail per RFC 7250 §4.2 — better
        // to abort than ship a Certificate the peer can't parse.
        if let Some(offered) = &client_offered_server_cert_type
            && !offered.contains(&server_cert_type)
        {
            return Err(Error::UnexpectedMessage);
        }
        // RFC 7250 §4.2: client's first supported preference, default X.509.
        self.negotiated_client_cert_type = match &client_offered_client_cert_type {
            Some(list) => list
                .iter()
                .copied()
                .find(|t| *t == CERT_TYPE_X509 || *t == CERT_TYPE_RAW_PUBLIC_KEY)
                .unwrap_or(CERT_TYPE_X509),
            None => CERT_TYPE_X509,
        };
        let mut ee_exts: Vec<Extension> = Vec::new();
        if client_offered_server_cert_type.is_some() {
            ee_exts.push(Extension::new(
                ExtensionType::SERVER_CERTIFICATE_TYPE,
                CertType::encode_single(server_cert_type),
            ));
        }
        if client_offered_client_cert_type.is_some() {
            ee_exts.push(Extension::new(
                ExtensionType::CLIENT_CERTIFICATE_TYPE,
                CertType::encode_single(self.negotiated_client_cert_type),
            ));
        }
        // RFC 9001 §8.2 — `quic_transport_parameters` belongs only on
        // a QUIC handshake. The client tells us by including the
        // extension in ClientHello; if absent, this is plain TLS over
        // TCP and we MUST NOT send the extension.
        if client_offered_quic_tp {
            ee_exts.push(Extension::new(
                ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                self.config.transport_params.clone(),
            ));
        }
        if let Some(picked) = &self.selected_alpn {
            ee_exts.push(Extension::new(
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                Alpn::encode(core::slice::from_ref(picked))?,
            ));
        }
        if early_accepted {
            ee_exts.push(Extension::new(ExtensionType::EARLY_DATA, Vec::new()));
        }
        let ee = EncryptedExtensions {
            extensions: ee_exts,
        };
        let mut ee_bytes = Vec::new();
        Handshake::EncryptedExtensions(ee).encode(&mut ee_bytes);
        self.transcript.update(&ee_bytes);

        let mut hs_blob = Vec::new();
        hs_blob.extend_from_slice(&ee_bytes);

        // RFC 8446 §4.3.2: never on resumption (no Certificate flight there).
        if psk_accepted.is_none() && self.client_auth.is_some() {
            let cr = CertificateRequest {
                certificate_request_context: Vec::new(),
                extensions: alloc::vec![Extension::new(
                    ExtensionType::SIGNATURE_ALGORITHMS,
                    SignatureAlgorithms::x509_encode(),
                )],
            };
            let mut cr_bytes = Vec::new();
            Handshake::CertificateRequest(cr).encode(&mut cr_bytes);
            self.transcript.update(&cr_bytes);
            hs_blob.extend_from_slice(&cr_bytes);
        }

        if psk_accepted.is_none() {
            let certificate_list: Vec<CertificateEntry> = match &self.config.source {
                CertSource::RawPublicKey { signing_key } => {
                    let pubkey = signing_key.pubkey().ok_or(Error::Sig)?;
                    alloc::vec![CertificateEntry {
                        cert_data: spki::SubjectPublicKey::Ed25519(*pubkey)
                            .encode()
                            .map_err(|_| Error::Spki)?,
                        extensions: Vec::new(),
                    }]
                }
                CertSource::X509 { chain_der, .. } => chain_der
                    .iter()
                    .map(|der| CertificateEntry {
                        cert_data: der.clone(),
                        extensions: Vec::new(),
                    })
                    .collect(),
            };
            let cert = Certificate {
                certificate_request_context: Vec::new(),
                certificate_list,
            };
            let mut cert_bytes = Vec::new();
            Handshake::Certificate(cert).encode(&mut cert_bytes);
            self.transcript.update(&cert_bytes);

            let h_pre_cv = self.transcript.hash(hash_alg);
            let cv_msg = CertVerify::message(h_pre_cv.as_slice(), true);
            let sig = self
                .config
                .source
                .signing_key()
                .sign(&cv_msg)
                .map_err(|_| Error::Sig)?;
            let cv = CertificateVerify {
                algorithm: self.config.source.signing_key().sig_scheme(),
                signature: sig,
            };
            let mut cv_bytes = Vec::new();
            Handshake::CertificateVerify(cv).encode(&mut cv_bytes);
            self.transcript.update(&cv_bytes);

            hs_blob.extend_from_slice(&cert_bytes);
            hs_blob.extend_from_slice(&cv_bytes);
        }

        let h_pre_sf = self.transcript.hash(hash_alg);
        let sf_data = FinishedProto::verify_data(hash_alg, s_hs.as_slice(), h_pre_sf.as_slice());
        let sf = Finished {
            verify_data: sf_data.as_slice().to_vec(),
        };
        let mut sf_bytes = Vec::new();
        Handshake::Finished(sf).encode(&mut sf_bytes);
        self.transcript.update(&sf_bytes);

        hs_blob.extend_from_slice(&sf_bytes);
        events.push(Event::Send {
            epoch: Epoch::Handshake,
            data: hs_blob,
        });

        let h_sf = self.transcript.hash(hash_alg);
        let ks_master = ks_handshake.into_master();
        let c_ap = ks_master
            .client_application_traffic_secret(h_sf.as_slice())
            .to_digest();
        let s_ap = ks_master
            .server_application_traffic_secret(h_sf.as_slice())
            .to_digest();
        self.c_ap_traffic = Some(c_ap);
        self.s_ap_traffic = Some(s_ap);
        self.exporter_master = Some(
            ks_master
                .exporter_master_secret(h_sf.as_slice())
                .to_digest(),
        );
        self.master = Some(ks_master);

        events.push(Event::KeysReady {
            epoch: Epoch::Application,
            read_secret: c_ap,
            write_secret: s_ap,
        });

        self.c_hs_traffic = Some(c_hs);
        if early_accepted {
            self.early_data_remaining = Some(MAX_EARLY_DATA_SIZE);
            self.state = State::ExpectEndOfEarlyData;
        } else if psk_accepted.is_none() && self.client_auth.is_some() {
            // verify_data waits until the client's cert flight is in the transcript.
            self.state = State::ExpectClientCertificate;
        } else {
            self.expected_client_finished = Some(FinishedProto::verify_data(
                hash_alg,
                c_hs.as_slice(),
                h_sf.as_slice(),
            ));
            self.state = State::ExpectClientFinished;
        }
        Ok(())
    }

    /// RFC 8446 §4.1.4: ask for a retry (one only) when the ClientHello carried
    /// no usable key_share, rewriting the transcript to `message_hash(CH1)`.
    fn send_hello_retry_request(
        &mut self,
        ch_raw: &[u8],
        session_id_echo: &[u8],
        request_group: KexGroup,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let hrr = ServerHello {
            legacy_version: TLS_1_2,
            random: HELLO_RETRY_REQUEST_RANDOM,
            legacy_session_id_echo: session_id_echo.to_vec(),
            cipher_suite: self
                .negotiated_suite
                .expect("suite selected in CH")
                .to_u16(),
            legacy_compression_method: 0,
            extensions: alloc::vec![
                Extension::new(
                    ExtensionType::SUPPORTED_VERSIONS,
                    crate::proto::SupportedVersions::server_encode(),
                ),
                Extension::new(
                    ExtensionType::KEY_SHARE,
                    KeyShare::hrr_encode(request_group)
                ),
            ],
        };
        let mut hrr_bytes = Vec::new();
        Handshake::ServerHello(hrr).encode(&mut hrr_bytes);

        let mut t = Transcript::new();
        t.update(ch_raw);
        self.transcript = Transcript::restart_with_message_hash(&t.hash(self.hash_alg()));
        self.transcript.update(&hrr_bytes);

        self.hrr_done = true;
        events.push(Event::Send {
            epoch: Epoch::Plaintext,
            data: hrr_bytes,
        });
        Ok(())
    }

    fn handle_end_of_early_data(&mut self, raw: &[u8]) -> Result<(), Error> {
        let c_hs = self.c_hs_traffic.ok_or(Error::UnexpectedMessage)?;
        self.early_data_remaining = None;
        self.transcript.update(raw);
        let h = self.transcript.hash(self.hash_alg());
        self.expected_client_finished = Some(FinishedProto::verify_data(
            self.hash_alg(),
            c_hs.as_slice(),
            h.as_slice(),
        ));
        self.state = State::ExpectClientFinished;
        Ok(())
    }

    fn set_expected_client_finished(&mut self) -> Result<(), Error> {
        let c_hs = self.c_hs_traffic.ok_or(Error::UnexpectedMessage)?;
        let h = self.transcript.hash(self.hash_alg());
        self.expected_client_finished = Some(FinishedProto::verify_data(
            self.hash_alg(),
            c_hs.as_slice(),
            h.as_slice(),
        ));
        Ok(())
    }

    /// Mutual TLS: the client's Certificate (RFC 8446 §4.4.2). Capture the leaf
    /// key for the CertificateVerify that follows; an empty list is an anonymous
    /// client (allowed only under `Requested`).
    fn handle_client_certificate(&mut self, cert: Certificate, raw: &[u8]) -> Result<(), Error> {
        if !cert.certificate_request_context.is_empty() {
            return Err(Error::IllegalParameter);
        }
        if cert.certificate_list.is_empty() {
            if self.client_auth == Some(ClientAuth::Required) {
                return Err(Error::ClientCertRequired);
            }
            self.transcript.update(raw);
            self.set_expected_client_finished()?;
            self.state = State::ExpectClientFinished;
            return Ok(());
        }
        let leaf_entry = &cert.certificate_list[0];
        let (leaf_key, spki_der, chain) =
            if self.negotiated_client_cert_type == CERT_TYPE_RAW_PUBLIC_KEY {
                if cert.certificate_list.len() != 1 {
                    return Err(Error::BadCertificate);
                }
                let lk = peer::raw_public_key_leaf(&leaf_entry.cert_data)?;
                (lk, leaf_entry.cert_data.clone(), Vec::new())
            } else {
                let (lk, spki) = peer::x509_leaf_key(&leaf_entry.cert_data)?;
                let chain: Vec<Vec<u8>> = cert
                    .certificate_list
                    .iter()
                    .map(|e| e.cert_data.clone())
                    .collect();
                (lk, spki, chain)
            };
        self.client_leaf = Some(leaf_key);
        self.client_spki_der = spki_der;
        self.client_cert_chain = chain;
        self.transcript.update(raw);
        self.state = State::ExpectClientCertVerify;
        Ok(())
    }

    /// Mutual TLS: the client's CertificateVerify (RFC 8446 §4.4.3). Verify
    /// possession of the leaf key, then ask the embedder to authorize the
    /// pinned identity. Only then is the expected client Finished computed.
    fn handle_client_cert_verify(
        &mut self,
        cv: CertificateVerify,
        raw: &[u8],
    ) -> Result<(), Error> {
        if !SignatureAlgorithms::x509_supported(cv.algorithm) {
            return Err(Error::SigSchemeNotOffered);
        }
        let leaf = self
            .client_leaf
            .as_ref()
            .ok_or(Error::BadCertificateVerify)?;
        let h_pre_cv = self.transcript.hash(self.hash_alg());
        let msg = CertVerify::message(h_pre_cv.as_slice(), false);
        leaf.verify(cv.algorithm, &msg, &cv.signature)?;

        if self.client_auth.is_none() {
            return Err(Error::UnexpectedMessage);
        }
        let identity = ClientIdentity {
            cert_type: self.negotiated_client_cert_type,
            spki_der: &self.client_spki_der,
            chain_der: &self.client_cert_chain,
        };
        if !self.verifier.verify(&identity) {
            return Err(Error::AccessDenied);
        }

        self.transcript.update(raw);
        self.set_expected_client_finished()?;
        self.state = State::ExpectClientFinished;
        Ok(())
    }

    fn try_accept_psk(&self, ch: &ClientHello, raw: &[u8]) -> Option<AcceptedPsk> {
        let keys = self.config.ticket_keys.as_ref()?;
        let now = self.now_ms();
        let kx_ext = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PSK_KEY_EXCHANGE_MODES)?;
        let modes = crate::psk::KxModes::decode(&kx_ext.data).ok()?;
        if !modes.contains(&crate::psk::KX_MODE_PSK_DHE) {
            return None;
        }
        let psk_ext = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY)?;
        let (ids, binders) = crate::psk::Offer::decode(&psk_ext.data).ok()?;
        let id = ids.first()?;
        let bind = binders.first()?;
        if bind.len() != 32 {
            return None;
        }
        let dt = keys.decrypt(&id.identity).ok()?;
        let suite = dt.suite;
        let (psk, age_add, issued_at_ms, alpn) = (dt.psk, dt.age_add, dt.issued_at_ms, dt.alpn);
        if issued_at_ms > now.saturating_add(MAX_TICKET_AGE_SKEW_MS) {
            return None;
        }
        if now.saturating_sub(issued_at_ms) > TICKET_LIFETIME_MS {
            return None;
        }
        let n = raw.len();
        // RFC 8446 §4.2.11.2: strip the binders field (list_len 2 + binder_len 1 + binder).
        let binders_field = 2 + 1 + bind.len();
        if n < binders_field {
            return None;
        }
        let mut t = if self.hrr_done {
            self.transcript.clone()
        } else {
            Transcript::new()
        };
        t.update(&raw[..n - binders_field]);
        let partial_hash = t.hash(RESUMPTION_HASH);
        let expected = crate::psk::ResumptionBinder::compute(&psk, partial_hash.as_slice());
        if !crate::ct_eq(expected.as_slice(), bind.as_slice()) {
            return None;
        }
        Some(AcceptedPsk {
            psk,
            age_add,
            issued_at_ms,
            suite,
            obfuscated_ticket_age: id.obfuscated_ticket_age,
            binder: bind.clone(),
            alpn,
        })
    }

    // 0-RTT requires a guard, a fresh-enough ticket, and a non-replayed binder.
    fn check_early_data_replay(&mut self, p: &AcceptedPsk) -> bool {
        let now = self.now_ms();
        let Some(guard) = self.early_data_guard.as_mut() else {
            return false;
        };
        if now < p.issued_at_ms {
            return false;
        }
        let measured_age = now - p.issued_at_ms;
        if measured_age > TICKET_LIFETIME_MS {
            return false;
        }
        let claimed_age = p.obfuscated_ticket_age.wrapping_sub(p.age_add) as u64;
        if measured_age.abs_diff(claimed_age) > MAX_TICKET_AGE_SKEW_MS {
            return false;
        }
        guard.register(&p.binder)
    }

    fn handle_client_finished(
        &mut self,
        f: Finished,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let expected = self
            .expected_client_finished
            .ok_or(Error::UnexpectedMessage)?;
        if !crate::ct_eq(f.verify_data.as_slice(), expected.as_slice()) {
            return Err(Error::BadFinished);
        }
        self.transcript.update(raw);
        events.push(Event::Done);
        self.state = State::Done;
        self.emit_session_ticket(events)?;
        Ok(())
    }

    fn emit_session_ticket(&mut self, events: &mut Vec<Event>) -> Result<(), Error> {
        use ring::rand::SecureRandom;
        let Some(master) = self.master.as_ref() else {
            return Ok(());
        };
        let Some(keys) = self.config.ticket_keys.as_ref() else {
            return Ok(());
        };
        if master.hash_alg() != RESUMPTION_HASH {
            return Ok(());
        }
        let issued_at_ms = self.now_ms();
        let h_cf = self.transcript.hash(RESUMPTION_HASH);
        let rms_digest = master.resumption_master_secret(h_cf.as_slice()).to_digest();
        let mut nonce = [0u8; 8];
        let mut age_add_bytes = [0u8; 4];
        self.rng.fill(&mut nonce).map_err(|_| Error::Rng)?;
        self.rng.fill(&mut age_add_bytes).map_err(|_| Error::Rng)?;
        let age_add = u32::from_be_bytes(age_add_bytes);
        let psk = crate::schedule::ResumptionMaster::from_secret(&rms_digest).psk(&nonce);
        let alpn = self.selected_alpn.clone().unwrap_or_default();
        let suite = self
            .negotiated_suite
            .ok_or(Error::UnexpectedMessage)?
            .to_u16();
        let ticket = keys
            .encrypt(&psk, age_add, issued_at_ms, suite, &alpn, &self.rng)
            .map_err(|_| Error::Rng)?;
        let mut nst_extensions = Vec::new();
        if self.config.accept_early_data {
            let mut body = Vec::new();
            body.put_u32(MAX_EARLY_DATA_SIZE);
            nst_extensions.push(Extension::new(ExtensionType::EARLY_DATA, body));
        }
        let nst = NewSessionTicket {
            ticket_lifetime: TICKET_LIFETIME_SECS,
            ticket_age_add: age_add,
            ticket_nonce: nonce.to_vec(),
            ticket,
            extensions: nst_extensions,
        };
        let mut bytes = Vec::new();
        Handshake::NewSessionTicket(nst).encode(&mut bytes);
        events.push(Event::Send {
            epoch: Epoch::Application,
            data: bytes,
        });
        events.push(Event::ResumptionSecret { psk });
        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    pub fn send_key_update(&mut self, request_update: bool) -> Result<Vec<Event>, Error> {
        if self.state != State::Done {
            return Err(Error::UnexpectedMessage);
        }
        let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_s_ap = crate::kdf::Hkdf::traffic_update(self.hash_alg(), &s_ap).to_digest();
        self.s_ap_traffic = Some(new_s_ap);

        let ku = crate::handshake::KeyUpdate {
            request_update: u8::from(request_update),
        };
        let mut bytes = Vec::new();
        Handshake::KeyUpdate(ku).encode(&mut bytes);
        Ok(alloc::vec![
            Event::Send {
                epoch: Epoch::Application,
                data: bytes,
            },
            Event::KeyUpdate {
                direction: crate::KeyDirection::Write,
                secret: new_s_ap,
            },
        ])
    }
}
