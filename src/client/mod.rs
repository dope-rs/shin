use alloc::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};

use crate::cert::{Cert, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION};
use crate::chain::{Chain, ChainError, TrustAnchor};
use crate::codec::Reader;
use crate::extension::{Extension, ExtensionType};
use crate::handshake::reassemblers::KeyUpdateBudget;
use crate::handshake::{
    Certificate, CertificateEntry, CertificateRequest, CertificateVerify, ClientHello,
    EncryptedExtensions, Finished, HELLO_RETRY_REQUEST_RANDOM, Handshake, HsReassembler, KeyUpdate,
    MAX_KEY_UPDATES_WITHOUT_APP_DATA, RANDOM_LEN, ServerHello, TLS_1_2,
};
use crate::hash::{Digest, HashAlg, MAX_HASH_LEN, Transcript};
use crate::hostname::Hostname;
use crate::kdf::Hkdf;
use crate::kx::{EphemeralKey, KexGroup};
use crate::proto::{
    Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, CertType, KeyShare, ServerName,
    SignatureAlgorithms, SupportedGroups, SupportedVersions, TLS_1_3,
};
use crate::psk::{
    KX_MODE_PSK_DHE, KxModes, Offer, PskIdentity, RESUMPTION_HASH, ResumptionBinder,
    SelectedIdentity,
};
use crate::record::CipherSuite;
use crate::schedule::{KeySchedule, ResumptionMaster};
use crate::spki::SubjectPublicKey;
use crate::time::UnixTime;
use crate::{Clock, Epoch, Error, Event, KeyDirection};
use zeroize::Zeroize;

mod config;
mod state;

/// RFC 8446 §4.6.1: a client MUST NOT cache a ticket longer than 7 days, and a
/// server MUST NOT send a larger lifetime.
const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

pub use config::{ClientCertSource, Config, OwnedTrustAnchor, Resumption, Verifier};

use state::{HandshakeSecrets, State, StateKind};

use crate::peer::{LeafKey, LeafKeyKind};

pub struct Client<C: Clock> {
    config: Config,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    eph: Option<EphemeralKey>,
    kex_group: KexGroup,
    offered_suites: Vec<CipherSuite>,
    c_ap_traffic: Option<Digest>,
    s_ap_traffic: Option<Digest>,
    selected_alpn: Option<Vec<u8>>,
    resumption_master: Option<Digest>,
    exporter_master: Option<Digest>,
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
    /// Identity to present if the server sends a CertificateRequest (mutual TLS).
    client_cert: Option<ClientCertSource>,
    /// Set when the server requested client auth; carries the context to echo
    /// and the signature schemes it will accept in our CertificateVerify.
    cert_request: Option<CertRequest>,
    key_updates: KeyUpdateBudget<MAX_KEY_UPDATES_WITHOUT_APP_DATA>,
}

struct CertRequest {
    context: Vec<u8>,
    schemes: Vec<u16>,
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
        Self {
            config,
            clock,
            state: State::Initial,
            transcript: Transcript::new(),
            rng: SystemRandom::new(),
            eph: None,
            kex_group: KexGroup::X25519,
            offered_suites: CipherSuite::SUPPORTED.to_vec(),
            c_ap_traffic: None,
            s_ap_traffic: None,
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
            client_cert: None,
            cert_request: None,
            key_updates: KeyUpdateBudget::default(),
        }
    }

    /// Choose the (EC)DHE group to offer (default X25519). Must be set before
    /// `start`.
    pub fn set_kex_group(&mut self, group: KexGroup) {
        self.kex_group = group;
    }

    /// Restrict the cipher suites offered (default: all supported, AES-128
    /// first). Must be set before `start`.
    pub fn set_cipher_suites(&mut self, suites: &[CipherSuite]) {
        self.offered_suites = suites.to_vec();
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
    /// [`Sealer`](crate::record::Sealer) and [`Opener`](crate::record::Opener).
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
                SupportedVersions::tls13().client_encode()?
            ),
            Extension::new(
                ExtensionType::SUPPORTED_GROUPS,
                SupportedGroups::supported().encode()?
            ),
            Extension::new(
                ExtensionType::SIGNATURE_ALGORITHMS,
                match self.config.verifier {
                    Verifier::RawPublicKey { .. } => SignatureAlgorithms::rpk().encode()?,
                    Verifier::X509 { .. } => SignatureAlgorithms::x509().encode()?,
                }
            ),
            Extension::new(
                ExtensionType::KEY_SHARE,
                KeyShare::new(self.kex_group, kx_pubkey).client_encode()?,
            ),
        ];

        let client_cert_type_offer = match &self.client_cert {
            Some(src) => Some(src.cert_type()),
            None if matches!(self.config.verifier, Verifier::RawPublicKey { .. }) => {
                Some(CERT_TYPE_RAW_PUBLIC_KEY)
            }
            None => None,
        };

        if matches!(self.config.verifier, Verifier::RawPublicKey { .. }) {
            extensions.push(Extension::new(
                ExtensionType::SERVER_CERTIFICATE_TYPE,
                CertType::new(server_cert_type).encode_list()?,
            ));
        }
        if let Some(ct) = client_cert_type_offer {
            extensions.push(Extension::new(
                ExtensionType::CLIENT_CERTIFICATE_TYPE,
                CertType::new(ct).encode_list()?,
            ));
        }

        if !self.config.transport_params.is_empty() {
            extensions.push(Extension::new(
                ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                self.config.transport_params.clone(),
            ));
        }

        if let Verifier::X509 { hostname, .. } = &self.config.verifier
            && !Hostname::new(hostname).is_ip_literal()
        {
            extensions.push(Extension::new(
                ExtensionType::SERVER_NAME,
                ServerName::new(hostname).encode()?,
            ));
        }

        if !self.config.alpn_protocols.is_empty() {
            extensions.push(Extension::new(
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                Alpn::new(&self.config.alpn_protocols).encode()?,
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
            cipher_suites: self.offered_suites.iter().map(|s| s.to_u16()).collect(),
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

    fn encode_client_hello(&mut self, extensions: Vec<Extension>) -> Result<Vec<u8>, Error> {
        self.record_ee_offered(&extensions);
        let ch = self.build_client_hello(extensions);
        let mut ch_bytes = Vec::new();
        Handshake::ClientHello(ch).encode(&mut ch_bytes)?;
        Ok(ch_bytes)
    }

    fn push_psk_offer(extensions: &mut Vec<Extension>, r: &Resumption) -> Result<(), Error> {
        extensions.push(Extension::new(
            ExtensionType::PSK_KEY_EXCHANGE_MODES,
            KxModes::new(alloc::vec![KX_MODE_PSK_DHE]).encode()?,
        ));
        let identity = PskIdentity {
            identity: r.ticket.clone(),
            obfuscated_ticket_age: r.age_millis.wrapping_add(r.ticket_age_add),
        };
        extensions.push(Extension::new(
            ExtensionType::PRE_SHARED_KEY,
            Offer::new(alloc::vec![identity], alloc::vec![alloc::vec![0u8; 32]]).encode()?,
        ));
        Ok(())
    }

    /// Splice a resumption binder over `Truncate(ClientHello)`, prefixed by
    /// `message_hash(CH1) ‖ HRR` after a retry (RFC 8446 §4.2.11.2).
    fn splice_psk_binder(&self, ch_bytes: &mut [u8], psk: &[u8; 32]) -> Result<(), Error> {
        let prefix_len = Offer::binder_transcript_prefix(ch_bytes, psk.len())
            .ok_or(Error::Encode)?
            .len();
        let mut t = self.transcript.clone();
        t.update(&ch_bytes[..prefix_len]);
        let partial_hash = t.hash(RESUMPTION_HASH);
        let binder = ResumptionBinder::compute(psk, partial_hash.as_slice())?;
        let binder_start = ch_bytes.len() - psk.len();
        ch_bytes[binder_start..].copy_from_slice(binder.as_slice());
        Ok(())
    }

    pub fn start(&mut self) -> Result<Vec<Event>, Error> {
        if self.state.kind() != StateKind::Initial {
            return Err(Error::UnexpectedMessage);
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
        self.session_id = session_id.to_vec();

        let mut extensions = self.base_extensions(eph.client_share(), None)?;

        let resumption = self.config.resumption.clone();
        let early_data_offered = self.config.enable_early_data && resumption.is_some();
        self.early_data_offered = early_data_offered;
        if let Some(r) = &resumption {
            if early_data_offered {
                extensions.push(Extension::new(ExtensionType::EARLY_DATA, Vec::new()));
            }
            Self::push_psk_offer(&mut extensions, r)?;
        }

        let mut ch_bytes = self.encode_client_hello(extensions)?;

        if let Some(r) = &resumption {
            self.splice_psk_binder(&mut ch_bytes, &r.psk)?;
        }

        self.transcript.update(&ch_bytes);

        let mut events = alloc::vec![Event::Send {
            epoch: Epoch::Plaintext,
            data: ch_bytes,
        }];
        if let Some(r) = resumption.as_ref().filter(|_| early_data_offered) {
            let psk = r.psk;
            let h_ch = self.transcript.hash(RESUMPTION_HASH);
            let cets = KeySchedule::client_early_traffic_secret(&psk, h_ch.as_slice())?.to_digest();
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

    /// Mark application-data progress and reset the consecutive KeyUpdate budget.
    /// Call once per decrypted application record; otherwise the peer is aborted
    /// after [`MAX_KEY_UPDATES_WITHOUT_APP_DATA`] consecutive updates.
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
        match (self.state.kind(), msg) {
            (StateKind::ExpectServerHello, Handshake::ServerHello(sh))
                if epoch == Epoch::Plaintext =>
            {
                self.handle_server_hello(sh, raw, events)
            }
            (StateKind::ExpectEncryptedExtensions, Handshake::EncryptedExtensions(ee))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                self.handle_encrypted_extensions(ee, raw, secrets, events)
            }
            (StateKind::ExpectCertificate, Handshake::CertificateRequest(cr))
                if epoch == Epoch::Handshake =>
            {
                self.handle_certificate_request(cr, raw)
            }
            (StateKind::ExpectCertificate, Handshake::Certificate(c))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                self.handle_certificate(c, raw, secrets)
            }
            (StateKind::ExpectCertificateVerify, Handshake::CertificateVerify(cv))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                let server_leaf_key = self
                    .state
                    .server_leaf_key()
                    .ok_or(Error::UnexpectedMessage)?;
                self.handle_certificate_verify(cv, raw, secrets, &server_leaf_key)
            }
            (StateKind::ExpectServerFinished, Handshake::Finished(f))
                if epoch == Epoch::Handshake =>
            {
                let secrets = self.state.secrets().ok_or(Error::UnexpectedMessage)?;
                self.handle_server_finished(f, raw, secrets, events)
            }
            (StateKind::Done, Handshake::KeyUpdate(ku)) if epoch == Epoch::Application => {
                self.handle_key_update(ku, events)
            }
            (StateKind::Done, Handshake::NewSessionTicket(nst)) if epoch == Epoch::Application => {
                if nst.ticket_lifetime > MAX_TICKET_LIFETIME_SECS {
                    return Err(Error::IllegalParameter);
                }
                if let Some(rms) = self.resumption_master.as_ref()
                    && self.hash_alg() == RESUMPTION_HASH
                {
                    let psk = ResumptionMaster::from_secret(rms).psk(&nst.ticket_nonce)?;
                    events.push(Event::ResumptionSecret { psk });
                }
                let max_early_data = nst
                    .extensions
                    .iter()
                    .find(|e| e.ty == ExtensionType::EARLY_DATA)
                    .map(|e| {
                        let mut r = Reader::new(&e.data);
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

    fn handle_key_update(&mut self, ku: KeyUpdate, events: &mut Vec<Event>) -> Result<(), Error> {
        if !self.key_updates.consume() {
            return Err(Error::UnexpectedMessage);
        }
        let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_s_ap = Hkdf::new(self.hash_alg())
            .traffic_update(&s_ap)?
            .to_digest();
        self.s_ap_traffic = Some(new_s_ap);
        events.push(Event::KeyUpdate {
            direction: KeyDirection::Read,
            secret: new_s_ap,
        });

        if ku.request_update == 1 {
            let reply = KeyUpdate { request_update: 0 };
            let mut bytes = Vec::new();
            Handshake::KeyUpdate(reply).encode(&mut bytes)?;
            events.push(Event::Send {
                epoch: Epoch::Application,
                data: bytes,
            });
            let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
            let new_c_ap = Hkdf::new(self.hash_alg())
                .traffic_update(&c_ap)?
                .to_digest();
            self.c_ap_traffic = Some(new_c_ap);
            events.push(Event::KeyUpdate {
                direction: KeyDirection::Write,
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
        if !self.offered_suites.contains(&suite) {
            return Err(Error::IllegalParameter);
        }
        if let Some(prev) = self.negotiated_suite
            && prev != suite
        {
            return Err(Error::IllegalParameter);
        }
        self.negotiated_suite = Some(suite);
        if sh.random == HELLO_RETRY_REQUEST_RANDOM {
            return self.handle_hello_retry_request(sh, raw, events);
        }
        const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
        const DOWNGRADE_TLS11: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];
        let tail = &sh.random[RANDOM_LEN - 8..];
        if tail == DOWNGRADE_TLS12 || tail == DOWNGRADE_TLS11 {
            return Err(Error::DowngradeDetected);
        }
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

        let psk_ext = sh
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::PRE_SHARED_KEY);
        if let Some(ext) = psk_ext {
            if self.config.resumption.is_none() {
                return Err(Error::UnexpectedMessage);
            }
            let selected =
                SelectedIdentity::decode(&ext.data).map_err(|_| Error::IllegalParameter)?;
            if selected.get() != 0 {
                return Err(Error::IllegalParameter);
            }
        }
        self.psk_used = psk_ext.is_some();

        self.transcript.update(raw);

        let eph = self.eph.take().ok_or(Error::UnexpectedMessage)?;
        if eph.group().to_u16() != server_group {
            return Err(Error::IllegalParameter);
        }
        let dhe = eph.agree(&server_pubkey).map_err(|_| Error::Kx)?;

        let alg = self.hash_alg();
        let ks_handshake = if self.psk_used {
            let psk = self
                .config
                .resumption
                .as_ref()
                .ok_or(Error::UnexpectedMessage)?
                .psk;
            KeySchedule::new_psk(alg, &psk).into_handshake(dhe.as_slice())?
        } else {
            KeySchedule::new(alg).into_handshake(dhe.as_slice())?
        };
        let h_chsh = self.transcript.hash(alg);
        let c_hs = ks_handshake
            .client_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();
        let s_hs = ks_handshake
            .server_handshake_traffic_secret(h_chsh.as_slice())?
            .to_digest();

        let secrets = HandshakeSecrets {
            handshake: ks_handshake.secret().to_digest(),
            client_traffic: c_hs,
            server_traffic: s_hs,
        };

        events.push(Event::KeysReady {
            epoch: Epoch::Handshake,
            read_secret: s_hs,
            write_secret: c_hs,
        });

        self.state = State::ExpectEncryptedExtensions { secrets };
        Ok(())
    }

    /// Resend ClientHello after one HRR, echoing its cookie and rebinding PSK to
    /// `message_hash(CH1) ‖ HRR ‖ Truncate(CH2)` (RFC 8446 §4.2.11.2).
    fn handle_hello_retry_request(
        &mut self,
        hrr: ServerHello,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if self.hrr_done {
            return Err(Error::UnexpectedMessage);
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

        let h1 = self.transcript.hash(self.hash_alg());
        self.transcript = Transcript::restart_with_message_hash(&h1);
        self.transcript.update(raw);

        if self.eph.as_ref().map(|e| e.group()) != Some(group) {
            self.eph = Some(EphemeralKey::generate(group, &self.rng).map_err(|_| Error::Kx)?);
            self.kex_group = group;
        }
        let eph_share = self
            .eph
            .as_ref()
            .ok_or(Error::UnexpectedMessage)?
            .client_share()
            .to_vec();
        let mut extensions = self.base_extensions(&eph_share, cookie.as_deref())?;

        let resumption = self.config.resumption.clone();
        if let Some(r) = &resumption {
            Self::push_psk_offer(&mut extensions, r)?;
        }

        let mut ch_bytes = self.encode_client_hello(extensions)?;

        if let Some(r) = &resumption {
            self.splice_psk_binder(&mut ch_bytes, &r.psk)?;
        }

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
        secrets: HandshakeSecrets,
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
                let pick = chosen.into_iter().next().ok_or(Error::IllegalParameter)?;
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
            State::ExpectServerFinished { secrets }
        } else {
            State::ExpectCertificate { secrets }
        };
        Ok(())
    }

    /// Record the server's client-auth context and accepted signature schemes;
    /// the identity flight is sent only after server authentication succeeds.
    fn handle_certificate_request(
        &mut self,
        cr: CertificateRequest,
        raw: &[u8],
    ) -> Result<(), Error> {
        let sigs = cr
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::MissingExtension)?;
        let schemes = SignatureAlgorithms::decode(&sigs.data)?;
        self.cert_request = Some(CertRequest {
            context: cr.certificate_request_context.clone(),
            schemes,
        });
        self.transcript.update(raw);
        Ok(())
    }

    /// Build our client Certificate (+ CertificateVerify if we hold an identity)
    /// in response to a CertificateRequest, appending each to the transcript so
    /// the subsequent client Finished covers them (RFC 8446 §4.4).
    fn client_auth_flight(&mut self, alg: HashAlg) -> Result<Vec<u8>, Error> {
        let req = self.cert_request.as_ref().ok_or(Error::UnexpectedMessage)?;
        let certificate_list: Vec<CertificateEntry> = match &self.client_cert {
            Some(ClientCertSource::RawPublicKey { signing_key }) => {
                let pubkey = signing_key.pubkey().ok_or(Error::Sig)?;
                alloc::vec![CertificateEntry {
                    cert_data: SubjectPublicKey::Ed25519(*pubkey)
                        .encode()
                        .map_err(|_| Error::Spki)?,
                    extensions: Vec::new(),
                }]
            }
            Some(ClientCertSource::X509 { chain_der, .. }) => chain_der
                .iter()
                .map(|der| CertificateEntry {
                    cert_data: der.clone(),
                    extensions: Vec::new(),
                })
                .collect(),
            None => Vec::new(),
        };
        let cert = Certificate {
            certificate_request_context: req.context.clone(),
            certificate_list,
        };
        let mut out = Vec::new();
        let mut cert_bytes = Vec::new();
        Handshake::Certificate(cert).encode(&mut cert_bytes)?;
        self.transcript.update(&cert_bytes);
        out.extend_from_slice(&cert_bytes);

        if let Some(src) = &self.client_cert {
            let scheme = src.signing_key().sig_scheme();
            if !req.schemes.contains(&scheme) {
                return Err(Error::SigSchemeNotOffered);
            }
            let h = self.transcript.hash(alg);
            let cv_msg = CertificateVerify::message(h.as_slice(), false);
            let signature = src.signing_key().sign(&cv_msg).map_err(|_| Error::Sig)?;
            let cv = CertificateVerify {
                algorithm: scheme,
                signature,
            };
            let mut cv_bytes = Vec::new();
            Handshake::CertificateVerify(cv).encode(&mut cv_bytes)?;
            self.transcript.update(&cv_bytes);
            out.extend_from_slice(&cv_bytes);
        }
        Ok(out)
    }

    fn handle_certificate(
        &mut self,
        cert: Certificate,
        raw: &[u8],
        secrets: HandshakeSecrets,
    ) -> Result<(), Error> {
        let server_leaf_key = match &self.config.verifier {
            Verifier::RawPublicKey { expected_pubkey } => {
                if cert.certificate_list.len() != 1 {
                    return Err(Error::BadCertificate);
                }
                let entry = &cert.certificate_list[0];
                let SubjectPublicKey::Ed25519(server_pk) =
                    SubjectPublicKey::decode(&entry.cert_data).map_err(|_| Error::Spki)?
                else {
                    return Err(Error::BadCertificate);
                };
                if server_pk != *expected_pubkey {
                    return Err(Error::BadCertificate);
                }
                LeafKey {
                    kind: LeafKeyKind::Ed25519,
                    raw: server_pk.to_vec(),
                }
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
                let last_issuer = parsed.last().ok_or(Error::BadCertificate)?.issuer_der;
                let anchor_views: Vec<TrustAnchor<'_>> = anchors
                    .iter()
                    .map(|a| a.view())
                    .collect::<Result<Vec<_>, _>>()?;
                Chain::new(&parsed)
                    .validate(&anchor_views, UnixTime(now_seconds), hostname)
                    .map_err(|e| match e {
                        ChainError::NoTrustAnchor => {
                            Error::NoTrustAnchorForIssuer(last_issuer.to_vec())
                        }
                        _ => Error::BadCertificateChain(e),
                    })?;
                let leaf_spki = parsed[0].spki;
                let kind = if leaf_spki.algorithm.oid == OID_ED25519 {
                    LeafKeyKind::Ed25519
                } else if leaf_spki.algorithm.oid == OID_EC_PUBLIC_KEY {
                    LeafKeyKind::Ecdsa
                } else if leaf_spki.algorithm.oid == OID_RSA_ENCRYPTION {
                    LeafKeyKind::Rsa
                } else {
                    return Err(Error::UnsupportedSigScheme);
                };
                LeafKey {
                    kind,
                    raw: leaf_spki.subject_public_key.to_vec(),
                }
            }
        };
        self.transcript.update(raw);
        self.state = State::ExpectCertificateVerify {
            secrets,
            server_leaf_key,
        };
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
        secrets: HandshakeSecrets,
        server_leaf_key: &LeafKey,
    ) -> Result<(), Error> {
        if !self.offered_sig_scheme(cv.algorithm) {
            return Err(Error::SigSchemeNotOffered);
        }
        let h_pre_cv = self.transcript.hash(self.hash_alg());
        let msg = CertificateVerify::message(h_pre_cv.as_slice(), true);
        server_leaf_key.verify(cv.algorithm, &msg, &cv.signature)?;
        self.transcript.update(raw);
        self.state = State::ExpectServerFinished { secrets };
        Ok(())
    }

    fn handle_server_finished(
        &mut self,
        sf: Finished,
        raw: &[u8],
        secrets: HandshakeSecrets,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let alg = self.hash_alg();
        let h_pre_sf = self.transcript.hash(alg);
        let expected =
            Finished::verify_data(alg, secrets.server_traffic.as_slice(), h_pre_sf.as_slice())?;
        if !expected.ct_eq(sf.verify_data.as_slice()) {
            return Err(Error::BadFinished);
        }
        self.transcript.update(raw);

        let h_sf = self.transcript.hash(alg);

        let hkdf = Hkdf::new(alg);
        let derived_for_master = hkdf.derive_secret(
            secrets.handshake.as_slice(),
            "derived",
            Transcript::hash_empty(alg).as_slice(),
        )?;
        let zero = [0u8; MAX_HASH_LEN];
        let master = hkdf.extract(derived_for_master.as_slice(), &zero[..alg.output_len()]);
        let c_ap = hkdf
            .derive_secret(master.as_slice(), "c ap traffic", h_sf.as_slice())?
            .to_digest();
        let s_ap = hkdf
            .derive_secret(master.as_slice(), "s ap traffic", h_sf.as_slice())?
            .to_digest();
        self.c_ap_traffic = Some(c_ap);
        self.s_ap_traffic = Some(s_ap);
        self.exporter_master = Some(
            hkdf.derive_secret(master.as_slice(), "exp master", h_sf.as_slice())?
                .to_digest(),
        );

        events.push(Event::KeysReady {
            epoch: Epoch::Application,
            read_secret: s_ap,
            write_secret: c_ap,
        });

        if self.early_data_accepted {
            let mut eod_bytes = Vec::new();
            Handshake::EndOfEarlyData.encode(&mut eod_bytes)?;
            self.transcript.update(&eod_bytes);
            events.push(Event::Send {
                epoch: Epoch::EarlyData,
                data: eod_bytes,
            });
        }

        let mut flight = Vec::new();
        if self.cert_request.is_some() {
            flight = self.client_auth_flight(alg)?;
        }

        let h_pre_cf = self.transcript.hash(alg);
        let cf_data =
            Finished::verify_data(alg, secrets.client_traffic.as_slice(), h_pre_cf.as_slice())?;
        let cf = Finished {
            verify_data: cf_data.as_slice().to_vec(),
        };
        let mut cf_bytes = Vec::new();
        Handshake::Finished(cf).encode(&mut cf_bytes)?;
        self.transcript.update(&cf_bytes);
        let h_cf = self.transcript.hash(alg);
        let rms = hkdf
            .derive_secret(master.as_slice(), "res master", h_cf.as_slice())?
            .to_digest();
        self.resumption_master = Some(rms);

        flight.extend_from_slice(&cf_bytes);
        events.push(Event::Send {
            epoch: Epoch::Handshake,
            data: flight,
        });
        events.push(Event::Done);

        self.state = State::Done;
        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.state.kind() == StateKind::Done
    }

    pub fn send_key_update(&mut self, request_update: bool) -> Result<Vec<Event>, Error> {
        if self.state.kind() != StateKind::Done {
            return Err(Error::UnexpectedMessage);
        }
        let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_c_ap = Hkdf::new(self.hash_alg())
            .traffic_update(&c_ap)?
            .to_digest();
        self.c_ap_traffic = Some(new_c_ap);

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
                secret: new_c_ap,
            },
        ])
    }
}
