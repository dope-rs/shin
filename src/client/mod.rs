use alloc::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};

use crate::cert::Cert;
use crate::chain::{Chain, TrustAnchor};
use crate::extension::{Extension, ExtensionType};
use crate::handshake::{
    Certificate, CertificateVerify, ClientHello, EncryptedExtensions, Finished, Handshake,
    HsReassembler, RANDOM_LEN, ServerHello, TLS_1_2,
};
use crate::hash::Transcript;
use crate::hostname::Hostname;
use crate::kx::{EphemeralKey, KexGroup};
use crate::proto::{
    Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, CertType, CertVerify,
    Finished as FinishedProto, KeyShare, ServerName, SignatureAlgorithms, SupportedGroups,
    SupportedVersions, TLS_1_3,
};
use crate::record::CipherSuite;
use crate::schedule::KeySchedule;
use crate::spki;
use crate::time::UnixTime;
use crate::{Clock, Epoch, Error, Event};

mod config;

pub use config::{Config, OwnedTrustAnchor, Resumption, Verifier};

use config::{LeafKey, LeafKeyKind};

use crate::handshake::HELLO_RETRY_REQUEST_RANDOM as HRR_RANDOM;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    ExpectServerHello,
    ExpectEncryptedExtensions,
    ExpectCertificate,
    ExpectCertificateVerify,
    ExpectServerFinished,
    Done,
}

pub struct Client<C: Clock> {
    config: Config,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    eph: Option<EphemeralKey>,
    kex_group: KexGroup,
    handshake_secret: Option<[u8; 32]>,
    c_hs_traffic: Option<[u8; 32]>,
    s_hs_traffic: Option<[u8; 32]>,
    c_ap_traffic: Option<[u8; 32]>,
    s_ap_traffic: Option<[u8; 32]>,
    server_leaf_key: Option<LeafKey>,
    selected_alpn: Option<Vec<u8>>,
    resumption_master: Option<[u8; 32]>,
    exporter_master: Option<[u8; 32]>,
    negotiated_suite: Option<CipherSuite>,
    psk_used: bool,
    early_data_offered: bool,
    early_data_accepted: bool,
    ee_offered: Vec<ExtensionType>,
    clock: C,
    client_random: [u8; RANDOM_LEN],
    session_id: Vec<u8>,
    hrr_done: bool,
    reasm: HsReassembler,
}

impl<C: Clock> Drop for Client<C> {
    fn drop(&mut self) {
        for b in [
            &mut self.handshake_secret,
            &mut self.c_hs_traffic,
            &mut self.s_hs_traffic,
            &mut self.c_ap_traffic,
            &mut self.s_ap_traffic,
            &mut self.resumption_master,
            &mut self.exporter_master,
        ]
        .into_iter()
        .flatten()
        {
            crate::schedule::zeroize(b);
        }
    }
}

impl<C: Clock> Client<C> {
    pub fn new(config: Config, clock: C) -> Self {
        Self {
            config,
            clock,
            state: State::Initial,
            transcript: Transcript::new(),
            rng: SystemRandom::new(),
            eph: None,
            kex_group: KexGroup::X25519,
            handshake_secret: None,
            c_hs_traffic: None,
            s_hs_traffic: None,
            c_ap_traffic: None,
            s_ap_traffic: None,
            server_leaf_key: None,
            selected_alpn: None,
            resumption_master: None,
            exporter_master: None,
            negotiated_suite: None,
            psk_used: false,
            early_data_offered: false,
            early_data_accepted: false,
            ee_offered: Vec::new(),
            client_random: [0u8; RANDOM_LEN],
            session_id: Vec::new(),
            hrr_done: false,
            reasm: HsReassembler::default(),
        }
    }

    /// Choose the (EC)DHE group to offer (default X25519). Must be set before
    /// `start`.
    pub fn set_kex_group(&mut self, group: KexGroup) {
        self.kex_group = group;
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn.as_deref()
    }

    /// The negotiated record-protection suite, available once the ServerHello is
    /// processed. The embedder builds its record [`Sealer`]/[`Opener`] for this
    /// suite. ([`Sealer`]: crate::record::Sealer, [`Opener`]: crate::record::Opener)
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
        crate::schedule::export_keying_material(em, label, context, out);
        Ok(())
    }

    /// Extensions shared by ClientHello1 and the HelloRetryRequest retry,
    /// optionally echoing a `cookie` (RFC 8446 §4.2.2). PSK/early-data are
    /// appended by the caller since their binders depend on the final layout.
    fn base_extensions(
        &self,
        kx_pubkey: &[u8],
        cookie: Option<&[u8]>,
    ) -> Result<Vec<Extension>, Error> {
        let server_cert_type = match self.config.verifier {
            Verifier::RawPublicKey { .. } => CERT_TYPE_RAW_PUBLIC_KEY,
            Verifier::X509 { .. } => CERT_TYPE_X509,
        };
        let mut extensions = alloc::vec![
            Extension::new(
                ExtensionType::SUPPORTED_VERSIONS,
                SupportedVersions::client_encode()
            ),
            Extension::new(ExtensionType::SUPPORTED_GROUPS, SupportedGroups::encode()),
            Extension::new(
                ExtensionType::SIGNATURE_ALGORITHMS,
                match self.config.verifier {
                    Verifier::RawPublicKey { .. } => SignatureAlgorithms::rpk_encode(),
                    Verifier::X509 { .. } => SignatureAlgorithms::x509_encode(),
                }
            ),
            Extension::new(
                ExtensionType::KEY_SHARE,
                KeyShare::client_encode(self.kex_group, kx_pubkey),
            ),
        ];

        if matches!(self.config.verifier, Verifier::RawPublicKey { .. }) {
            extensions.push(Extension::new(
                ExtensionType::SERVER_CERTIFICATE_TYPE,
                CertType::encode_list(server_cert_type),
            ));
            extensions.push(Extension::new(
                ExtensionType::CLIENT_CERTIFICATE_TYPE,
                CertType::encode_list(CERT_TYPE_RAW_PUBLIC_KEY),
            ));
        }

        if !self.config.transport_params.is_empty() {
            extensions.push(Extension::new(
                ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                self.config.transport_params.clone(),
            ));
        }

        if let Verifier::X509 { hostname, .. } = &self.config.verifier
            && !Hostname::is_ip_literal(hostname)
        {
            extensions.push(Extension::new(
                ExtensionType::SERVER_NAME,
                ServerName::encode(hostname)?,
            ));
        }

        if !self.config.alpn_protocols.is_empty() {
            extensions.push(Extension::new(
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                Alpn::encode(&self.config.alpn_protocols)?,
            ));
        }

        if let Some(c) = cookie {
            extensions.push(Extension::new(ExtensionType::COOKIE, c.to_vec()));
        }

        Ok(extensions)
    }

    fn build_client_hello(&self, extensions: Vec<Extension>) -> ClientHello {
        ClientHello {
            legacy_version: TLS_1_2,
            random: self.client_random,
            legacy_session_id: self.session_id.clone(),
            cipher_suites: CipherSuite::SUPPORTED.iter().map(|s| s.to_u16()).collect(),
            legacy_compression_methods: alloc::vec![0],
            extensions,
        }
    }

    /// Offered extensions the server may legally echo in EncryptedExtensions
    /// (RFC 8446 §4.2); EE rejects anything else.
    fn record_ee_offered(&mut self, extensions: &[Extension]) {
        self.ee_offered = extensions
            .iter()
            .map(|e| e.ty)
            .filter(|ty| Self::ee_eligible(*ty))
            .collect();
    }

    fn encode_client_hello(&mut self, extensions: Vec<Extension>) -> Vec<u8> {
        self.record_ee_offered(&extensions);
        let ch = self.build_client_hello(extensions);
        let mut ch_bytes = Vec::new();
        Handshake::ClientHello(ch).encode(&mut ch_bytes);
        ch_bytes
    }

    pub fn start(&mut self) -> Result<Vec<Event>, Error> {
        if self.state != State::Initial {
            return Err(Error::UnexpectedMessage);
        }
        self.config.validate()?;
        let eph = EphemeralKey::generate(self.kex_group, &self.rng).map_err(|_| Error::Kx)?;

        let mut client_random = [0u8; RANDOM_LEN];
        self.rng.fill(&mut client_random).map_err(|_| Error::Rng)?;
        let mut session_id = [0u8; 32];
        self.rng.fill(&mut session_id).map_err(|_| Error::Rng)?;
        self.client_random = client_random;
        self.session_id = session_id.to_vec();

        let mut extensions = self.base_extensions(eph.pubkey(), None)?;

        let resumption = self.config.resumption.clone();
        let early_data_offered = self.config.enable_early_data && resumption.is_some();
        self.early_data_offered = early_data_offered;
        if let Some(r) = &resumption {
            if early_data_offered {
                extensions.push(Extension::new(ExtensionType::EARLY_DATA, Vec::new()));
            }
            extensions.push(Extension::new(
                ExtensionType::PSK_KEY_EXCHANGE_MODES,
                crate::psk::KxModes::encode(&[crate::psk::KX_MODE_PSK_DHE]),
            ));
            let identity = crate::psk::PskIdentity {
                identity: r.ticket.clone(),
                obfuscated_ticket_age: r.age_millis.wrapping_add(r.ticket_age_add),
            };
            let placeholder = alloc::vec![0u8; 32];
            extensions.push(Extension::new(
                ExtensionType::PRE_SHARED_KEY,
                crate::psk::Offer::encode(&[identity], &[placeholder]),
            ));
            let _ = r;
        }

        let mut ch_bytes = self.encode_client_hello(extensions);

        if let Some(r) = &resumption {
            let n = ch_bytes.len();
            // RFC 8446 §4.2.11.2: binder covers the CH minus the binders field
            // (list_len 2 + binder_len 1 + binder 32).
            const BINDERS_FIELD_LEN: usize = 2 + 1 + 32;
            let partial = &ch_bytes[..n - BINDERS_FIELD_LEN];
            let mut t = Transcript::new();
            t.update(partial);
            let partial_hash = t.hash();
            let binder = crate::psk::ResumptionBinder::compute(&r.psk, &partial_hash);
            ch_bytes[n - 32..].copy_from_slice(&binder);
        }

        self.transcript.update(&ch_bytes);

        let mut events = alloc::vec![Event::Send {
            epoch: Epoch::Plaintext,
            data: ch_bytes,
        }];
        if early_data_offered {
            let psk = resumption.as_ref().expect("resumption present").psk;
            let zero = [0u8; 32];
            let early_secret = crate::kdf::Hkdf::extract(&zero, &psk);
            let h_ch = self.transcript.hash();
            let cets = crate::kdf::Hkdf::derive_secret(&early_secret, "c e traffic", &h_ch);
            events.push(Event::ZeroRttKeysReady { secret: cets });
        }

        self.eph = Some(eph);
        self.state = State::ExpectServerHello;

        Ok(events)
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
            (State::ExpectServerHello, Handshake::ServerHello(sh)) if epoch == Epoch::Plaintext => {
                self.handle_server_hello(sh, raw, events)
            }
            (State::ExpectEncryptedExtensions, Handshake::EncryptedExtensions(ee))
                if epoch == Epoch::Handshake =>
            {
                self.handle_encrypted_extensions(ee, raw, events)
            }
            (State::ExpectCertificate, Handshake::Certificate(c)) if epoch == Epoch::Handshake => {
                self.handle_certificate(c, raw)
            }
            (State::ExpectCertificateVerify, Handshake::CertificateVerify(cv))
                if epoch == Epoch::Handshake =>
            {
                self.handle_certificate_verify(cv, raw)
            }
            (State::ExpectServerFinished, Handshake::Finished(f)) if epoch == Epoch::Handshake => {
                self.handle_server_finished(f, raw, events)
            }
            (State::Done, Handshake::KeyUpdate(ku)) if epoch == Epoch::Application => {
                self.handle_key_update(ku, events)
            }
            (State::Done, Handshake::NewSessionTicket(nst)) if epoch == Epoch::Application => {
                if let Some(rms) = self.resumption_master {
                    let psk = crate::schedule::ResumptionMaster::new(rms).psk(&nst.ticket_nonce);
                    events.push(Event::ResumptionSecret { psk });
                }
                let max_early_data = nst
                    .extensions
                    .iter()
                    .find(|e| e.ty == ExtensionType::EARLY_DATA)
                    .map(|e| {
                        let mut r = crate::codec::Reader::new(&e.data);
                        let v = r.u32().map_err(Error::from)?;
                        r.finish().map_err(Error::from)?;
                        Ok::<u32, Error>(v)
                    })
                    .transpose()?;
                events.push(Event::NewSessionTicket {
                    ticket_lifetime: nst.ticket_lifetime,
                    ticket_age_add: nst.ticket_age_add,
                    ticket_nonce: nst.ticket_nonce,
                    ticket: nst.ticket,
                    max_early_data,
                });
                Ok(())
            }
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn handle_key_update(
        &mut self,
        ku: crate::handshake::KeyUpdate,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let mut new_s_ap = [0u8; 32];
        crate::kdf::Hkdf::expand_label(&s_ap, "traffic upd", &[], &mut new_s_ap);
        self.s_ap_traffic = Some(new_s_ap);
        events.push(Event::KeyUpdate {
            direction: crate::KeyDirection::Read,
            secret: new_s_ap,
        });

        if ku.request_update == 1 {
            let reply = crate::handshake::KeyUpdate { request_update: 0 };
            let mut bytes = Vec::new();
            Handshake::KeyUpdate(reply).encode(&mut bytes);
            events.push(Event::Send {
                epoch: Epoch::Application,
                data: bytes,
            });
            let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
            let mut new_c_ap = [0u8; 32];
            crate::kdf::Hkdf::expand_label(&c_ap, "traffic upd", &[], &mut new_c_ap);
            self.c_ap_traffic = Some(new_c_ap);
            events.push(Event::KeyUpdate {
                direction: crate::KeyDirection::Write,
                secret: new_c_ap,
            });
        }
        Ok(())
    }

    fn handle_server_hello(
        &mut self,
        sh: ServerHello,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let suite = CipherSuite::from_u16(sh.cipher_suite).ok_or(Error::UnsupportedCipherSuite)?;
        if sh.random == HRR_RANDOM {
            return self.handle_hello_retry_request(sh, raw, events);
        }
        self.negotiated_suite = Some(suite);
        const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
        const DOWNGRADE_TLS11: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];
        let tail = &sh.random[RANDOM_LEN - 8..];
        if tail == DOWNGRADE_TLS12 || tail == DOWNGRADE_TLS11 {
            return Err(Error::DowngradeDetected);
        }
        // RFC 8446 §4.1.3: legacy fields are fixed and the session_id echo must match.
        if sh.legacy_version != TLS_1_2 {
            return Err(Error::IllegalParameter);
        }
        if sh.legacy_compression_method != 0 {
            return Err(Error::IllegalParameter);
        }
        if sh.legacy_session_id_echo != self.session_id {
            return Err(Error::IllegalParameter);
        }
        let sv_data = sh
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::MissingExtension)?
            .data
            .as_slice();
        if SupportedVersions::server_decode(sv_data)? != TLS_1_3 {
            return Err(Error::BadVersion);
        }
        let ks_data = sh
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::KEY_SHARE)
            .ok_or(Error::MissingExtension)?
            .data
            .as_slice();
        let (server_group, server_pubkey) = KeyShare::server_decode(ks_data)?;

        // RFC 8446 §4.1.3: only these extensions are legal in ServerHello.
        for ext in &sh.extensions {
            if !matches!(
                ext.ty,
                ExtensionType::SUPPORTED_VERSIONS
                    | ExtensionType::KEY_SHARE
                    | ExtensionType::PRE_SHARED_KEY
            ) {
                return Err(Error::UnsolicitedExtension);
            }
        }

        let psk_selected = sh
            .extensions
            .iter()
            .any(|e| e.ty == ExtensionType::PRE_SHARED_KEY);
        if psk_selected && self.config.resumption.is_none() {
            return Err(Error::UnexpectedMessage);
        }
        self.psk_used = psk_selected;

        self.transcript.update(raw);

        let eph = self.eph.take().ok_or(Error::UnexpectedMessage)?;
        if eph.group().to_u16() != server_group {
            return Err(Error::IllegalParameter);
        }
        let dhe = eph.agree(&server_pubkey).map_err(|_| Error::Kx)?;

        let ks_handshake = if self.psk_used {
            let psk = self
                .config
                .resumption
                .as_ref()
                .expect("psk_used implies resumption")
                .psk;
            KeySchedule::new_psk(&psk).into_handshake(&dhe)
        } else {
            KeySchedule::new().into_handshake(&dhe)
        };
        let h_chsh = self.transcript.hash();
        let c_hs = ks_handshake.client_handshake_traffic_secret(&h_chsh);
        let s_hs = ks_handshake.server_handshake_traffic_secret(&h_chsh);

        self.handshake_secret = Some(*ks_handshake.secret());
        self.c_hs_traffic = Some(c_hs);
        self.s_hs_traffic = Some(s_hs);

        events.push(Event::KeysReady {
            epoch: Epoch::Handshake,
            read_secret: s_hs,
            write_secret: c_hs,
        });

        self.state = State::ExpectEncryptedExtensions;
        Ok(())
    }

    /// Handle a HelloRetryRequest (RFC 8446 §4.1.4): resend the ClientHello with
    /// the same key share and the echoed cookie over the rewritten transcript. At
    /// most one HRR, only for our single group; resumption + HRR is unsupported.
    fn handle_hello_retry_request(
        &mut self,
        hrr: ServerHello,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if self.hrr_done {
            return Err(Error::UnexpectedMessage);
        }
        if self.config.resumption.is_some() {
            return Err(Error::HelloRetryRequest);
        }

        let mut saw_supported_versions = false;
        let mut selected_group = None;
        let mut cookie = None;
        for ext in &hrr.extensions {
            match ext.ty {
                ExtensionType::SUPPORTED_VERSIONS => {
                    if SupportedVersions::server_decode(&ext.data)? != TLS_1_3 {
                        return Err(Error::BadVersion);
                    }
                    saw_supported_versions = true;
                }
                ExtensionType::KEY_SHARE => {
                    selected_group = Some(KeyShare::hrr_selected_group(&ext.data)?);
                }
                ExtensionType::COOKIE => cookie = Some(ext.data.clone()),
                _ => return Err(Error::UnsolicitedExtension),
            }
        }
        if !saw_supported_versions {
            return Err(Error::MissingExtension);
        }
        let selected = selected_group.ok_or(Error::MissingExtension)?;
        let group = KexGroup::from_u16(selected)
            .filter(|g| KexGroup::SUPPORTED.contains(g))
            .ok_or(Error::UnsupportedGroup)?;

        let h1 = self.transcript.hash();
        self.transcript = Transcript::restart_with_message_hash(h1);
        self.transcript.update(raw);

        if self.eph.as_ref().map(|e| e.group()) != Some(group) {
            self.eph = Some(EphemeralKey::generate(group, &self.rng).map_err(|_| Error::Kx)?);
            self.kex_group = group;
        }
        let eph_pub = self
            .eph
            .as_ref()
            .ok_or(Error::UnexpectedMessage)?
            .pubkey()
            .to_vec();
        let extensions = self.base_extensions(&eph_pub, cookie.as_deref())?;
        let ch_bytes = self.encode_client_hello(extensions);
        self.transcript.update(&ch_bytes);
        self.hrr_done = true;
        events.push(Event::Send {
            epoch: Epoch::Plaintext,
            data: ch_bytes,
        });
        Ok(())
    }

    /// Extension types this client may offer that are also legal in
    /// EncryptedExtensions (RFC 8446 §4.2).
    fn ee_eligible(ty: ExtensionType) -> bool {
        matches!(
            ty,
            ExtensionType::SERVER_NAME
                | ExtensionType::SUPPORTED_GROUPS
                | ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                | ExtensionType::SERVER_CERTIFICATE_TYPE
                | ExtensionType::CLIENT_CERTIFICATE_TYPE
                | ExtensionType::EARLY_DATA
                | ExtensionType::QUIC_TRANSPORT_PARAMETERS
        )
    }

    fn handle_encrypted_extensions(
        &mut self,
        ee: EncryptedExtensions,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        for ext in &ee.extensions {
            if !self.ee_offered.contains(&ext.ty) {
                return Err(Error::UnsolicitedExtension);
            }

            if ext.ty == ExtensionType::QUIC_TRANSPORT_PARAMETERS {
                events.push(Event::PeerExtension {
                    ty: ext.ty.0,
                    data: ext.data.clone(),
                });
            } else if ext.ty == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION {
                let chosen = Alpn::decode(&ext.data).map_err(|_| Error::Decode)?;
                if chosen.len() != 1 {
                    return Err(Error::IllegalParameter);
                }
                let pick = chosen.into_iter().next().unwrap();
                if !self.config.alpn_protocols.iter().any(|p| p == &pick) {
                    return Err(Error::IllegalParameter);
                }
                self.selected_alpn = Some(pick);
            } else if ext.ty == ExtensionType::EARLY_DATA {
                if !self.early_data_offered || !ext.data.is_empty() {
                    return Err(Error::UnsolicitedExtension);
                }
                self.early_data_accepted = true;
            }
        }
        if self.early_data_offered {
            events.push(if self.early_data_accepted {
                Event::EarlyDataAccepted
            } else {
                Event::EarlyDataRejected
            });
        }
        self.transcript.update(raw);
        self.state = if self.psk_used {
            State::ExpectServerFinished
        } else {
            State::ExpectCertificate
        };
        Ok(())
    }

    fn handle_certificate(&mut self, cert: Certificate, raw: &[u8]) -> Result<(), Error> {
        match &self.config.verifier {
            Verifier::RawPublicKey { expected_pubkey } => {
                if cert.certificate_list.len() != 1 {
                    return Err(Error::BadCertificate);
                }
                let entry = &cert.certificate_list[0];
                let spki::SubjectPublicKey::Ed25519(server_pk) =
                    spki::SubjectPublicKey::decode(&entry.cert_data).map_err(|_| Error::Spki)?
                else {
                    return Err(Error::BadCertificate);
                };
                if server_pk != *expected_pubkey {
                    return Err(Error::BadCertificate);
                }
                self.server_leaf_key = Some(LeafKey {
                    kind: LeafKeyKind::Ed25519,
                    raw: server_pk.to_vec(),
                });
            }
            Verifier::X509 { anchors, hostname } => {
                let now_seconds = self.clock.now_ms() / 1000;
                if cert.certificate_list.is_empty() {
                    return Err(Error::BadCertificate);
                }
                let parsed: Vec<_> = cert
                    .certificate_list
                    .iter()
                    .map(|e| Cert::parse(&e.cert_data))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Error::BadCertificateParse)?;
                let anchor_views: Vec<TrustAnchor<'_>> = anchors
                    .iter()
                    .map(|a| a.view())
                    .collect::<Result<Vec<_>, _>>()?;
                Chain::validate(&parsed, &anchor_views, UnixTime(now_seconds), hostname).map_err(
                    |e| match e {
                        crate::chain::ChainError::NoTrustAnchor => Error::NoTrustAnchorForIssuer(
                            parsed.last().unwrap().issuer_der.to_vec(),
                        ),
                        _ => Error::BadCertificateChain(e),
                    },
                )?;
                let leaf_spki = parsed[0].spki;
                let kind = if leaf_spki.algorithm.oid == crate::cert::OID_ED25519 {
                    LeafKeyKind::Ed25519
                } else if leaf_spki.algorithm.oid == crate::cert::OID_EC_PUBLIC_KEY {
                    LeafKeyKind::Ecdsa
                } else if leaf_spki.algorithm.oid == crate::cert::OID_RSA_ENCRYPTION {
                    LeafKeyKind::Rsa
                } else {
                    return Err(Error::UnsupportedSigScheme);
                };
                self.server_leaf_key = Some(LeafKey {
                    kind,
                    raw: leaf_spki.subject_public_key.to_vec(),
                });
            }
        }
        self.transcript.update(raw);
        self.state = State::ExpectCertificateVerify;
        Ok(())
    }

    fn offered_sig_scheme(&self, scheme: u16) -> bool {
        use crate::proto::{
            SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_ED25519,
            SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512,
        };
        match self.config.verifier {
            Verifier::RawPublicKey { .. } => scheme == SIG_ED25519,
            Verifier::X509 { .. } => matches!(
                scheme,
                SIG_ECDSA_SECP256R1_SHA256
                    | SIG_ECDSA_SECP384R1_SHA384
                    | SIG_RSA_PSS_RSAE_SHA256
                    | SIG_RSA_PSS_RSAE_SHA384
                    | SIG_RSA_PSS_RSAE_SHA512
                    | SIG_ED25519
            ),
        }
    }

    fn handle_certificate_verify(
        &mut self,
        cv: CertificateVerify,
        raw: &[u8],
    ) -> Result<(), Error> {
        // RFC 8446 §4.4.3: scheme must be one we advertised in signature_algorithms.
        if !self.offered_sig_scheme(cv.algorithm) {
            return Err(Error::SigSchemeNotOffered);
        }
        let leaf = self
            .server_leaf_key
            .as_ref()
            .ok_or(Error::BadCertificateVerify)?;
        let h_pre_cv = self.transcript.hash();
        let msg = CertVerify::message(&h_pre_cv, true);
        leaf.verify(cv.algorithm, &msg, &cv.signature)?;
        self.transcript.update(raw);
        self.state = State::ExpectServerFinished;
        Ok(())
    }

    fn handle_server_finished(
        &mut self,
        sf: Finished,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let s_hs = self.s_hs_traffic.ok_or(Error::UnexpectedMessage)?;
        let c_hs = self.c_hs_traffic.ok_or(Error::UnexpectedMessage)?;
        let hs_secret = self.handshake_secret.ok_or(Error::UnexpectedMessage)?;

        let h_pre_sf = self.transcript.hash();
        let expected = FinishedProto::verify_data(&s_hs, &h_pre_sf);
        if !crate::ct_eq(sf.verify_data.as_slice(), &expected) {
            return Err(Error::BadFinished);
        }
        self.transcript.update(raw);

        let h_sf = self.transcript.hash();

        let derived_for_master =
            crate::kdf::Hkdf::derive_secret(&hs_secret, "derived", &Transcript::hash_empty());
        let zero = [0u8; 32];
        let master = crate::kdf::Hkdf::extract(&derived_for_master, &zero);
        let c_ap = crate::kdf::Hkdf::derive_secret(&master, "c ap traffic", &h_sf);
        let s_ap = crate::kdf::Hkdf::derive_secret(&master, "s ap traffic", &h_sf);
        self.c_ap_traffic = Some(c_ap);
        self.s_ap_traffic = Some(s_ap);
        self.exporter_master = Some(crate::kdf::Hkdf::derive_secret(
            &master,
            "exp master",
            &h_sf,
        ));

        events.push(Event::KeysReady {
            epoch: Epoch::Application,
            read_secret: s_ap,
            write_secret: c_ap,
        });

        if self.early_data_accepted {
            let mut eod_bytes = Vec::new();
            Handshake::EndOfEarlyData.encode(&mut eod_bytes);
            self.transcript.update(&eod_bytes);
            events.push(Event::Send {
                epoch: Epoch::EarlyData,
                data: eod_bytes,
            });
        }

        let h_pre_cf = self.transcript.hash();
        let cf_data = FinishedProto::verify_data(&c_hs, &h_pre_cf);
        let cf = Finished {
            verify_data: cf_data.to_vec(),
        };
        let mut cf_bytes = Vec::new();
        Handshake::Finished(cf).encode(&mut cf_bytes);
        self.transcript.update(&cf_bytes);
        let h_cf = self.transcript.hash();
        let rms = crate::kdf::Hkdf::derive_secret(&master, "res master", &h_cf);
        self.resumption_master = Some(rms);

        events.push(Event::Send {
            epoch: Epoch::Handshake,
            data: cf_bytes,
        });
        events.push(Event::Done);

        self.state = State::Done;
        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    pub fn send_key_update(&mut self, request_update: bool) -> Result<Vec<Event>, Error> {
        if self.state != State::Done {
            return Err(Error::UnexpectedMessage);
        }
        let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let mut new_c_ap = [0u8; 32];
        crate::kdf::Hkdf::expand_label(&c_ap, "traffic upd", &[], &mut new_c_ap);
        self.c_ap_traffic = Some(new_c_ap);

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
                secret: new_c_ap,
            },
        ])
    }
}
