use alloc::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

use crate::codec::Encode;
use crate::extension::{Extension, ExtensionType};
use crate::handshake::reassemblers::KeyUpdateBudget;
use crate::handshake::{
    Certificate, CertificateEntry, CertificateRequest, CertificateVerify, ClientHello,
    EncryptedExtensions, Finished, HELLO_RETRY_REQUEST_RANDOM, Handshake, HsReassembler, KeyUpdate,
    MAX_KEY_UPDATES_WITHOUT_APP_DATA, NewSessionTicket, RANDOM_LEN, ServerHello, TLS_1_2,
};
use crate::hash::{Digest, HashAlg, Transcript};
use crate::kdf::Hkdf;
use crate::kx::KexGroup;
use crate::peer::LeafKey;
use crate::proto::{
    CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, KeyShare, SignatureAlgorithms, SupportedGroups,
    SupportedVersions, TLS_1_3,
};
use crate::psk::{
    KX_MODE_PSK_DHE, KxModes, Offer, RESUMPTION_HASH, ResumptionBinder, SelectedIdentity,
};
use crate::record::CipherSuite;
use crate::schedule::{KeySchedule, ResumptionMaster};
use crate::sig::SigningKey;
use crate::spki;
use crate::ticket::TicketKeys;
use crate::{Clock, Epoch, Error, Event, KeyDirection};
use zeroize::Zeroize;

mod early;
mod negotiation;
mod state;

use early::{AcceptedPsk, EarlyDataAdmission, TICKET_LIFETIME_SECS};
use negotiation::ClientHelloOffers;
use state::State;

#[derive(Clone)]
pub struct Config {
    pub source: CertSource,
    pub transport_params: Vec<u8>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub ticket_keys: Option<TicketKeys>,
    pub accept_early_data: bool,
}

impl Config {
    /// Check that every configured value can be encoded and that the
    /// certificate identity is internally consistent.
    pub fn validate(&self) -> Result<(), Error> {
        if self.transport_params.len() > u16::MAX as usize
            || self
                .alpn_protocols
                .iter()
                .any(|protocol| protocol.is_empty() || protocol.len() > u8::MAX as usize)
        {
            return Err(Error::BadConfig);
        }
        let identity_is_valid = match &self.source {
            CertSource::RawPublicKey { signing_key } => signing_key.is_ed25519(),
            CertSource::X509 {
                chain_der,
                signing_key,
            } => Certificate::chain_fits(chain_der) && signing_key.matches_x509_chain(chain_der),
        };
        if !identity_is_valid {
            return Err(Error::BadConfig);
        }
        Ok(())
    }
}

/// Replay store required for safe 0-RTT. Without one, early data is refused even
/// when configured because single-use cannot be proved (RFC 8446 §8).
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

/// Mutual-TLS policy: `Requested` permits an empty Certificate while `Required`
/// rejects one; presented identities still pass [`ClientCertVerifier`].
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

/// Authorizes a possession-proven client identity, typically by pinning
/// `spki_der`; CertificateVerify authenticity has already succeeded.
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

pub struct Server<C: Clock, G: EarlyDataGuard = NoGuard, V: ClientCertVerifier = NoClientAuth> {
    config: Config,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    c_ap_traffic: Option<Digest>,
    s_ap_traffic: Option<Digest>,
    selected_alpn: Option<Vec<u8>>,
    master: Option<KeySchedule>,
    early_data: EarlyDataAdmission<G>,
    clock: C,
    hrr_done: bool,
    exporter_master: Option<Digest>,
    negotiated_suite: Option<CipherSuite>,
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
    key_updates: KeyUpdateBudget<MAX_KEY_UPDATES_WITHOUT_APP_DATA>,
}

impl<C: Clock, G: EarlyDataGuard, V: ClientCertVerifier> Drop for Server<C, G, V> {
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
        let early_data = EarlyDataAdmission::new(config.accept_early_data, early_data_guard);
        Self {
            config,
            clock,
            early_data,
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
            reasm: HsReassembler::default(),
            client_auth,
            verifier,
            negotiated_client_cert_type: CERT_TYPE_X509,
            client_leaf: None,
            client_spki_der: Vec::new(),
            client_cert_chain: Vec::new(),
            key_updates: KeyUpdateBudget::default(),
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

    pub fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        self.reasm.push(epoch, data)?;
        let mut events = Vec::new();
        while let Some((msg, raw)) = self.reasm.next_message()? {
            self.process(epoch, msg, &raw, &mut events)?;
        }
        Ok(events)
    }

    /// Mark application-data progress and reset the consecutive KeyUpdate budget.
    /// Call once per decrypted record or the peer is aborted after
    /// [`MAX_KEY_UPDATES_WITHOUT_APP_DATA`] updates.
    pub fn note_application_data(&mut self) {
        self.key_updates.reset();
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
            (
                State::ExpectEndOfEarlyData {
                    client_handshake_traffic,
                },
                Handshake::EndOfEarlyData,
            ) if epoch == Epoch::EarlyData => {
                self.handle_end_of_early_data(raw, client_handshake_traffic)
            }
            (
                State::ExpectClientCertificate {
                    client_handshake_traffic,
                },
                Handshake::Certificate(c),
            ) if epoch == Epoch::Handshake => {
                self.handle_client_certificate(c, raw, client_handshake_traffic)
            }
            (
                State::ExpectClientCertVerify {
                    client_handshake_traffic,
                },
                Handshake::CertificateVerify(cv),
            ) if epoch == Epoch::Handshake => {
                self.handle_client_cert_verify(cv, raw, client_handshake_traffic)
            }
            (State::ExpectClientFinished { verify_data }, Handshake::Finished(f))
                if epoch == Epoch::Handshake =>
            {
                self.handle_client_finished(f, raw, verify_data, events)
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

    fn handle_key_update(&mut self, ku: KeyUpdate, events: &mut Vec<Event>) -> Result<(), Error> {
        if !self.key_updates.consume() {
            return Err(Error::UnexpectedMessage);
        }
        let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_c_ap = Hkdf::new(self.hash_alg())
            .traffic_update(&c_ap)?
            .to_digest();
        self.c_ap_traffic = Some(new_c_ap);
        events.push(Event::KeyUpdate {
            direction: KeyDirection::Read,
            secret: new_c_ap,
        });

        if ku.request_update == 1 {
            let reply = KeyUpdate { request_update: 0 };
            let mut bytes = Vec::new();
            Handshake::KeyUpdate(reply).encode(&mut bytes)?;
            events.push(Event::Send {
                epoch: Epoch::Application,
                data: bytes,
            });
            let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
            let new_s_ap = Hkdf::new(self.hash_alg())
                .traffic_update(&s_ap)?
                .to_digest();
            self.s_ap_traffic = Some(new_s_ap);
            events.push(Event::KeyUpdate {
                direction: KeyDirection::Write,
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
        self.config.validate()?;
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

        let offers = ClientHelloOffers::parse(&ch.extensions)?;
        self.selected_alpn = offers.select_alpn(&self.config.alpn_protocols)?;
        if let Some(parameters) = offers.peer_quic_transport_parameters() {
            events.push(Event::PeerExtension {
                ty: ExtensionType::QUIC_TRANSPORT_PARAMETERS.0,
                data: parameters.to_vec(),
            });
        }

        let psk_accepted = if hash_alg == RESUMPTION_HASH {
            self.try_accept_psk(&ch, raw)
        } else {
            None
        };
        let now_ms = self.now_ms();
        let early_accepted = self.early_data.admit(
            offers.early_data(),
            psk_accepted.as_ref(),
            self.selected_alpn.as_deref(),
            self.negotiated_suite,
            now_ms,
        );

        self.transcript.update(raw);

        if let (Some(p), true) = (psk_accepted.as_ref(), early_accepted) {
            let h_ch = self.transcript.hash(RESUMPTION_HASH);
            let cets =
                KeySchedule::client_early_traffic_secret(&p.psk, h_ch.as_slice())?.to_digest();
            events.push(Event::ZeroRttKeysReady { secret: cets });
        }

        let session_id_echo = ch.legacy_session_id.clone();

        let (server_share, dhe) = kex_group
            .respond(&peer_pubkey, &self.rng)
            .map_err(|_| Error::Kx)?;
        let mut server_random = [0u8; RANDOM_LEN];
        self.rng.fill(&mut server_random).map_err(|_| Error::Rng)?;

        let mut sh_extensions = alloc::vec![
            Extension::new(
                ExtensionType::SUPPORTED_VERSIONS,
                SupportedVersions::tls13().server_encode()
            ),
            Extension::new(
                ExtensionType::KEY_SHARE,
                KeyShare::new(kex_group, &server_share).server_encode()?
            ),
        ];
        if psk_accepted.is_some() {
            sh_extensions.push(Extension::new(
                ExtensionType::PRE_SHARED_KEY,
                SelectedIdentity::new(0).encode(),
            ));
        }
        let sh = ServerHello {
            legacy_version: TLS_1_2,
            random: server_random,
            legacy_session_id_echo: session_id_echo,
            cipher_suite: selected_suite.to_u16(),
            legacy_compression_method: 0,
            extensions: sh_extensions,
        };
        let mut sh_bytes = Vec::new();
        Handshake::ServerHello(sh).encode(&mut sh_bytes)?;
        self.transcript.update(&sh_bytes);

        events.push(Event::Send {
            epoch: Epoch::Plaintext,
            data: sh_bytes,
        });

        let ks_handshake = match &psk_accepted {
            Some(p) => {
                KeySchedule::new_psk(RESUMPTION_HASH, &p.psk).into_handshake(dhe.as_slice())?
            }
            None => KeySchedule::new(hash_alg).into_handshake(dhe.as_slice())?,
        };
        let h_chsh = self.transcript.hash(hash_alg);
        let c_hs = ks_handshake
            .client_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();
        let s_hs = ks_handshake
            .server_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();

        events.push(Event::KeysReady {
            epoch: Epoch::Handshake,
            read_secret: c_hs,
            write_secret: s_hs,
        });

        let certificate_negotiation = offers.certificate_negotiation(&self.config.source)?;
        self.negotiated_client_cert_type = certificate_negotiation.client_type;
        let ee_exts = offers.encrypted_extensions(
            certificate_negotiation,
            &self.config.transport_params,
            self.selected_alpn.as_ref(),
            early_accepted,
        )?;
        let ee = EncryptedExtensions {
            extensions: ee_exts,
        };
        let mut ee_bytes = Vec::new();
        Handshake::EncryptedExtensions(ee).encode(&mut ee_bytes)?;
        self.transcript.update(&ee_bytes);

        let mut hs_blob = Vec::new();
        hs_blob.extend_from_slice(&ee_bytes);

        if psk_accepted.is_none() && self.client_auth.is_some() {
            let cr = CertificateRequest {
                certificate_request_context: Vec::new(),
                extensions: alloc::vec![Extension::new(
                    ExtensionType::SIGNATURE_ALGORITHMS,
                    SignatureAlgorithms::x509().encode()?,
                )],
            };
            let mut cr_bytes = Vec::new();
            Handshake::CertificateRequest(cr).encode(&mut cr_bytes)?;
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
            Handshake::Certificate(cert).encode(&mut cert_bytes)?;
            self.transcript.update(&cert_bytes);

            let h_pre_cv = self.transcript.hash(hash_alg);
            let cv_msg = CertificateVerify::message(h_pre_cv.as_slice(), true);
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
            Handshake::CertificateVerify(cv).encode(&mut cv_bytes)?;
            self.transcript.update(&cv_bytes);

            hs_blob.extend_from_slice(&cert_bytes);
            hs_blob.extend_from_slice(&cv_bytes);
        }

        let h_pre_sf = self.transcript.hash(hash_alg);
        let sf_data = Finished::verify_data(hash_alg, s_hs.as_slice(), h_pre_sf.as_slice())?;
        let sf = Finished {
            verify_data: sf_data.as_slice().to_vec(),
        };
        let mut sf_bytes = Vec::new();
        Handshake::Finished(sf).encode(&mut sf_bytes)?;
        self.transcript.update(&sf_bytes);

        hs_blob.extend_from_slice(&sf_bytes);
        events.push(Event::Send {
            epoch: Epoch::Handshake,
            data: hs_blob,
        });

        let h_sf = self.transcript.hash(hash_alg);
        let ks_master = ks_handshake.into_master()?;
        let c_ap = ks_master
            .client_application_traffic_secret(h_sf.as_slice())?
            .to_digest();
        let s_ap = ks_master
            .server_application_traffic_secret(h_sf.as_slice())?
            .to_digest();
        self.c_ap_traffic = Some(c_ap);
        self.s_ap_traffic = Some(s_ap);
        self.exporter_master = Some(
            ks_master
                .exporter_master_secret(h_sf.as_slice())?
                .to_digest(),
        );
        self.master = Some(ks_master);

        events.push(Event::KeysReady {
            epoch: Epoch::Application,
            read_secret: c_ap,
            write_secret: s_ap,
        });

        if early_accepted {
            self.state = State::ExpectEndOfEarlyData {
                client_handshake_traffic: c_hs,
            };
        } else if psk_accepted.is_none() && self.client_auth.is_some() {
            self.state = State::ExpectClientCertificate {
                client_handshake_traffic: c_hs,
            };
        } else {
            let verify_data = Finished::verify_data(hash_alg, c_hs.as_slice(), h_sf.as_slice())?;
            self.state = State::ExpectClientFinished { verify_data };
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
        let suite = self.negotiated_suite.ok_or(Error::UnsupportedCipherSuite)?;
        let hrr = ServerHello {
            legacy_version: TLS_1_2,
            random: HELLO_RETRY_REQUEST_RANDOM,
            legacy_session_id_echo: session_id_echo.to_vec(),
            cipher_suite: suite.to_u16(),
            legacy_compression_method: 0,
            extensions: alloc::vec![
                Extension::new(
                    ExtensionType::SUPPORTED_VERSIONS,
                    SupportedVersions::tls13().server_encode(),
                ),
                Extension::new(
                    ExtensionType::KEY_SHARE,
                    KeyShare::new(request_group, &[]).hrr_encode()
                ),
            ],
        };
        let mut hrr_bytes = Vec::new();
        Handshake::ServerHello(hrr).encode(&mut hrr_bytes)?;

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

    fn handle_end_of_early_data(
        &mut self,
        raw: &[u8],
        client_handshake_traffic: Digest,
    ) -> Result<(), Error> {
        self.early_data.close();
        self.transcript.update(raw);
        self.expect_client_finished(client_handshake_traffic)
    }

    fn expect_client_finished(&mut self, client_handshake_traffic: Digest) -> Result<(), Error> {
        let h = self.transcript.hash(self.hash_alg());
        let verify_data = Finished::verify_data(
            self.hash_alg(),
            client_handshake_traffic.as_slice(),
            h.as_slice(),
        )?;
        self.state = State::ExpectClientFinished { verify_data };
        Ok(())
    }

    /// Mutual TLS: the client's Certificate (RFC 8446 §4.4.2). Capture the leaf
    /// key for the CertificateVerify that follows; an empty list is an anonymous
    /// client (allowed only under `Requested`).
    fn handle_client_certificate(
        &mut self,
        cert: Certificate,
        raw: &[u8],
        client_handshake_traffic: Digest,
    ) -> Result<(), Error> {
        if !cert.certificate_request_context.is_empty() {
            return Err(Error::IllegalParameter);
        }
        if cert.certificate_list.is_empty() {
            if self.client_auth == Some(ClientAuth::Required) {
                return Err(Error::ClientCertRequired);
            }
            self.transcript.update(raw);
            return self.expect_client_finished(client_handshake_traffic);
        }
        let leaf_entry = &cert.certificate_list[0];
        let (leaf_key, spki_der, chain) =
            if self.negotiated_client_cert_type == CERT_TYPE_RAW_PUBLIC_KEY {
                if cert.certificate_list.len() != 1 {
                    return Err(Error::BadCertificate);
                }
                let lk = LeafKey::from_spki(&leaf_entry.cert_data)?;
                (lk, leaf_entry.cert_data.clone(), Vec::new())
            } else {
                let (lk, spki) = LeafKey::parse_x509(&leaf_entry.cert_data)?;
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
        self.state = State::ExpectClientCertVerify {
            client_handshake_traffic,
        };
        Ok(())
    }

    /// Mutual TLS: the client's CertificateVerify (RFC 8446 §4.4.3). Verify
    /// possession of the leaf key, then ask the embedder to authorize the
    /// pinned identity. Only then is the expected client Finished computed.
    fn handle_client_cert_verify(
        &mut self,
        cv: CertificateVerify,
        raw: &[u8],
        client_handshake_traffic: Digest,
    ) -> Result<(), Error> {
        if !SignatureAlgorithms::x509_supported(cv.algorithm) {
            return Err(Error::SigSchemeNotOffered);
        }
        let leaf = self
            .client_leaf
            .as_ref()
            .ok_or(Error::BadCertificateVerify)?;
        let h_pre_cv = self.transcript.hash(self.hash_alg());
        let msg = CertificateVerify::message(h_pre_cv.as_slice(), false);
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
        self.expect_client_finished(client_handshake_traffic)
    }

    fn try_accept_psk(&self, ch: &ClientHello, raw: &[u8]) -> Option<AcceptedPsk> {
        let keys = self.config.ticket_keys.as_ref()?;
        let now = self.now_ms();
        let kx_ext = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PSK_KEY_EXCHANGE_MODES)?;
        let modes = KxModes::decode(&kx_ext.data).ok()?;
        if !modes.as_slice().contains(&KX_MODE_PSK_DHE) {
            return None;
        }
        let psk_ext = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY)?;
        let offer = Offer::decode(&psk_ext.data).ok()?;
        let id = offer.identities.first()?;
        let bind = offer.binders.first()?;
        if bind.len() != 32 {
            return None;
        }
        let dt = keys.decrypt(&id.identity).ok()?;
        let suite = dt.suite;
        let (psk, age_add, issued_at_ms, alpn) = (dt.psk, dt.age_add, dt.issued_at_ms, dt.alpn);
        if !AcceptedPsk::issued_at_is_resumable(issued_at_ms, now) {
            return None;
        }
        let binder_prefix = Offer::binder_transcript_prefix(raw, bind.len())?;
        let mut t = if self.hrr_done {
            self.transcript.clone()
        } else {
            Transcript::new()
        };
        t.update(binder_prefix);
        let partial_hash = t.hash(RESUMPTION_HASH);
        let expected = ResumptionBinder::compute(&psk, partial_hash.as_slice()).ok()?;
        if expected.as_slice().len() != bind.len()
            || !bool::from(expected.as_slice().ct_eq(bind.as_slice()))
        {
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

    fn handle_client_finished(
        &mut self,
        f: Finished,
        raw: &[u8],
        expected: Digest,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if !expected.ct_eq(f.verify_data.as_slice()) {
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
        let rms_digest = master
            .resumption_master_secret(h_cf.as_slice())?
            .to_digest();
        let mut nonce = [0u8; 8];
        let mut age_add_bytes = [0u8; 4];
        self.rng.fill(&mut nonce).map_err(|_| Error::Rng)?;
        self.rng.fill(&mut age_add_bytes).map_err(|_| Error::Rng)?;
        let age_add = u32::from_be_bytes(age_add_bytes);
        let psk = ResumptionMaster::from_secret(&rms_digest).psk(&nonce)?;
        let alpn = self.selected_alpn.clone().unwrap_or_default();
        let suite = self
            .negotiated_suite
            .ok_or(Error::UnexpectedMessage)?
            .to_u16();
        let ticket = keys
            .encrypt(&psk, age_add, issued_at_ms, suite, &alpn, &self.rng)
            .map_err(|_| Error::Rng)?;
        let mut nst_extensions = Vec::new();
        if let Some(maximum) = self.early_data.advertised_size() {
            let mut body = Vec::new();
            body.put_u32(maximum);
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
        Handshake::NewSessionTicket(nst).encode(&mut bytes)?;
        events.push(Event::Send {
            epoch: Epoch::Application,
            data: bytes,
        });
        events.push(Event::ResumptionSecret { psk });
        Ok(())
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    pub fn send_key_update(&mut self, request_update: bool) -> Result<Vec<Event>, Error> {
        if self.state != State::Done {
            return Err(Error::UnexpectedMessage);
        }
        let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_s_ap = Hkdf::new(self.hash_alg())
            .traffic_update(&s_ap)?
            .to_digest();
        self.s_ap_traffic = Some(new_s_ap);

        let ku = KeyUpdate {
            request_update: u8::from(request_update),
        };
        let mut bytes = Vec::new();
        Handshake::KeyUpdate(ku).encode(&mut bytes)?;
        Ok(alloc::vec![
            Event::Send {
                epoch: Epoch::Application,
                data: bytes,
            },
            Event::KeyUpdate {
                direction: KeyDirection::Write,
                secret: new_s_ap,
            },
        ])
    }
}
