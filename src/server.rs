use alloc::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};

use crate::codec::Encode;
use crate::extension::{Extension, ExtensionType};
use crate::handshake::{
    Certificate, CertificateEntry, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
    HELLO_RETRY_REQUEST_RANDOM, Handshake, HsReassembler, NewSessionTicket, RANDOM_LEN,
    ServerHello, TLS_1_2,
};
use crate::hash::Transcript;
use crate::kx::EphemeralKey;
use crate::proto::{
    Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, CertType, CertVerify,
    Finished as FinishedProto, GROUP_X25519, KeyShare, SUITE_AES_128_GCM_SHA256,
    SignatureAlgorithms, SupportedGroups, SupportedVersions, TLS_1_3,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    ExpectClientHello,
    ExpectEndOfEarlyData,
    ExpectClientFinished,
    Done,
}

pub struct Server<C: Clock, G: EarlyDataGuard = NoGuard> {
    config: Config,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    c_hs_traffic: Option<[u8; 32]>,
    expected_client_finished: Option<[u8; 32]>,
    c_ap_traffic: Option<[u8; 32]>,
    s_ap_traffic: Option<[u8; 32]>,
    selected_alpn: Option<Vec<u8>>,
    master: Option<KeySchedule>,
    early_data_guard: Option<G>,
    clock: C,
    hrr_done: bool,
    reasm: HsReassembler,
}

impl<C: Clock> Server<C, NoGuard> {
    /// A server that never accepts 0-RTT. For 0-RTT use
    /// [`with_early_data_guard`](Server::with_early_data_guard).
    pub fn new(config: Config, clock: C) -> Self {
        Self::build(config, clock, None)
    }
}

impl<C: Clock, G: EarlyDataGuard> Server<C, G> {
    /// A server that accepts 0-RTT, gated by `guard` (replay store + freshness).
    pub fn with_early_data_guard(config: Config, clock: C, guard: G) -> Self {
        Self::build(config, clock, Some(guard))
    }

    fn build(config: Config, clock: C, early_data_guard: Option<G>) -> Self {
        Self {
            config,
            clock,
            early_data_guard,
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
            reasm: HsReassembler::default(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn.as_deref()
    }

    pub fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        self.reasm.push(epoch, data)?;
        let mut events = Vec::new();
        while let Some((msg, raw)) = self.reasm.next_message()? {
            self.process(epoch, msg, &raw, &mut events)?;
        }
        Ok(events)
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
            (State::ExpectClientFinished, Handshake::Finished(f)) if epoch == Epoch::Handshake => {
                self.handle_client_finished(f, raw, events)
            }
            (State::Done, Handshake::KeyUpdate(ku)) if epoch == Epoch::Application => {
                self.handle_key_update(ku, events)
            }
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn handle_key_update(
        &mut self,
        ku: crate::handshake::KeyUpdate,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let mut new_c_ap = [0u8; 32];
        crate::kdf::Hkdf::expand_label(&c_ap, "traffic upd", &[], &mut new_c_ap);
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
            let mut new_s_ap = [0u8; 32];
            crate::kdf::Hkdf::expand_label(&s_ap, "traffic upd", &[], &mut new_s_ap);
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
        if !ch.cipher_suites.contains(&SUITE_AES_128_GCM_SHA256) {
            return Err(Error::UnsupportedCipherSuite);
        }
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
        if !SupportedGroups::decode(&groups.data)?.contains(&GROUP_X25519) {
            return Err(Error::UnsupportedGroup);
        }
        let sigs = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::MissingExtension)?;
        let local_sig_scheme = self.config.source.signing_key().sig_scheme();
        if !SignatureAlgorithms::decode(&sigs.data)?.contains(&local_sig_scheme) {
            return Err(Error::UnsupportedSigScheme);
        }
        let peer_pubkey = match ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::KEY_SHARE)
            .map(|ks| KeyShare::client_decode(&ks.data))
        {
            Some(Ok(pk)) => pk,
            _ if !self.hrr_done => {
                return self.send_hello_retry_request(raw, &ch.legacy_session_id, events);
            }
            _ => return Err(Error::MissingExtension),
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

        let psk_accepted = self.try_accept_psk(&ch, raw);
        let client_offered_early = ch
            .extensions
            .iter()
            .any(|e| e.ty == ExtensionType::EARLY_DATA);
        let early_accepted = self.config.accept_early_data
            && client_offered_early
            && match psk_accepted.as_ref() {
                Some(p) => {
                    // RFC 8446 §4.2.10: reject 0-RTT unless the newly-selected ALPN
                    // exactly matches the protocol negotiated by the original session.
                    let selected = self.selected_alpn.as_deref().unwrap_or(&[]);
                    selected == p.alpn.as_slice() && self.check_early_data_replay(p)
                }
                None => false,
            };

        self.transcript.update(raw);

        if let (Some(p), true) = (psk_accepted.as_ref(), early_accepted) {
            let zero = [0u8; 32];
            let early_secret = crate::kdf::Hkdf::extract(&zero, &p.psk);
            let h_ch = self.transcript.hash();
            let cets = crate::kdf::Hkdf::derive_secret(&early_secret, "c e traffic", &h_ch);
            events.push(Event::ZeroRttKeysReady { secret: cets });
        }

        let session_id_echo = ch.legacy_session_id.clone();

        let server_eph = EphemeralKey::generate(&self.rng).map_err(|_| Error::Kx)?;
        let mut server_random = [0u8; RANDOM_LEN];
        self.rng.fill(&mut server_random).map_err(|_| Error::Rng)?;

        let mut sh_extensions = alloc::vec![
            Extension::new(
                ExtensionType::SUPPORTED_VERSIONS,
                SupportedVersions::server_encode()
            ),
            Extension::new(
                ExtensionType::KEY_SHARE,
                KeyShare::server_encode(server_eph.pubkey())
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
            cipher_suite: SUITE_AES_128_GCM_SHA256,
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

        let dhe = server_eph.agree(&peer_pubkey).map_err(|_| Error::Kx)?;
        let ks_handshake = match &psk_accepted {
            Some(p) => KeySchedule::new_psk(&p.psk).into_handshake(&dhe),
            None => KeySchedule::new().into_handshake(&dhe),
        };
        let h_chsh = self.transcript.hash();
        let c_hs = ks_handshake.client_handshake_traffic_secret(&h_chsh);
        let s_hs = ks_handshake.server_handshake_traffic_secret(&h_chsh);

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
                CertType::encode_single(CERT_TYPE_RAW_PUBLIC_KEY),
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

            let h_pre_cv = self.transcript.hash();
            let cv_msg = CertVerify::message(&h_pre_cv, true);
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

        let h_pre_sf = self.transcript.hash();
        let sf_data = FinishedProto::verify_data(&s_hs, &h_pre_sf);
        let sf = Finished {
            verify_data: sf_data.to_vec(),
        };
        let mut sf_bytes = Vec::new();
        Handshake::Finished(sf).encode(&mut sf_bytes);
        self.transcript.update(&sf_bytes);

        hs_blob.extend_from_slice(&sf_bytes);
        events.push(Event::Send {
            epoch: Epoch::Handshake,
            data: hs_blob,
        });

        let h_sf = self.transcript.hash();
        let ks_master = ks_handshake.into_master();
        let c_ap = ks_master.client_application_traffic_secret(&h_sf);
        let s_ap = ks_master.server_application_traffic_secret(&h_sf);
        self.c_ap_traffic = Some(c_ap);
        self.s_ap_traffic = Some(s_ap);
        self.master = Some(ks_master);

        events.push(Event::KeysReady {
            epoch: Epoch::Application,
            read_secret: c_ap,
            write_secret: s_ap,
        });

        self.c_hs_traffic = Some(c_hs);
        if early_accepted {
            self.state = State::ExpectEndOfEarlyData;
        } else {
            self.expected_client_finished = Some(FinishedProto::verify_data(&c_hs, &h_sf));
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
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let hrr = ServerHello {
            legacy_version: TLS_1_2,
            random: HELLO_RETRY_REQUEST_RANDOM,
            legacy_session_id_echo: session_id_echo.to_vec(),
            cipher_suite: SUITE_AES_128_GCM_SHA256,
            legacy_compression_method: 0,
            extensions: alloc::vec![
                Extension::new(
                    ExtensionType::SUPPORTED_VERSIONS,
                    crate::proto::SupportedVersions::server_encode(),
                ),
                Extension::new(ExtensionType::KEY_SHARE, KeyShare::hrr_encode()),
            ],
        };
        let mut hrr_bytes = Vec::new();
        Handshake::ServerHello(hrr).encode(&mut hrr_bytes);

        let mut t = Transcript::new();
        t.update(ch_raw);
        self.transcript = Transcript::restart_with_message_hash(t.hash());
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
        self.transcript.update(raw);
        let h = self.transcript.hash();
        self.expected_client_finished = Some(FinishedProto::verify_data(&c_hs, &h));
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
        let (psk, age_add, issued_at_ms, alpn) = keys.decrypt(&id.identity).ok()?;
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
        let mut t = Transcript::new();
        t.update(&raw[..n - binders_field]);
        let partial_hash = t.hash();
        let expected = crate::psk::ResumptionBinder::compute(&psk, &partial_hash);
        if !crate::ct_eq(expected.as_slice(), bind.as_slice()) {
            return None;
        }
        Some(AcceptedPsk {
            psk,
            age_add,
            issued_at_ms,
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
        if !crate::ct_eq(f.verify_data.as_slice(), &expected) {
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
        let issued_at_ms = self.now_ms();
        let h_cf = self.transcript.hash();
        let rms = master.resumption_master_secret(&h_cf);
        let mut nonce = [0u8; 8];
        let mut age_add_bytes = [0u8; 4];
        self.rng.fill(&mut nonce).map_err(|_| Error::Rng)?;
        self.rng.fill(&mut age_add_bytes).map_err(|_| Error::Rng)?;
        let age_add = u32::from_be_bytes(age_add_bytes);
        let psk = crate::schedule::ResumptionMaster::new(rms).psk(&nonce);
        let alpn = self.selected_alpn.clone().unwrap_or_default();
        let ticket = keys
            .encrypt(&psk, age_add, issued_at_ms, &alpn, &self.rng)
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
        let mut new_s_ap = [0u8; 32];
        crate::kdf::Hkdf::expand_label(&s_ap, "traffic upd", &[], &mut new_s_ap);
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
