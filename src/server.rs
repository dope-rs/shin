use alloc::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};

use crate::codec::Reader;
use crate::extension::{Extension, ExtensionType};
use crate::handshake::{
    Certificate, CertificateEntry, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
    Handshake, NewSessionTicket, RANDOM_LEN, ServerHello, TLS_1_2,
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
use crate::{Epoch, Error, Event};

#[derive(Clone)]
pub struct Config {
    pub source: CertSource,
    pub transport_params: Vec<u8>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub ticket_secret: Option<[u8; 32]>,
    pub accept_early_data: bool,
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
    ExpectClientFinished,
    Done,
}

pub struct Server {
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
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state: State::ExpectClientHello,
            transcript: Transcript::new(),
            rng: SystemRandom::new(),
            c_hs_traffic: None,
            expected_client_finished: None,
            c_ap_traffic: None,
            s_ap_traffic: None,
            selected_alpn: None,
            master: None,
        }
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn.as_deref()
    }

    pub fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();
        let mut r = Reader::new(data);
        while !r.is_empty() {
            let snapshot = r.remaining();
            let msg = Handshake::decode(&mut r)?;
            let consumed = snapshot.len() - r.remaining().len();
            let raw = &snapshot[..consumed];
            self.process(epoch, msg, raw, &mut events)?;
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
        let ks = ch
            .extensions
            .iter()
            .find(|e| e.ty == ExtensionType::KEY_SHARE)
            .ok_or(Error::MissingExtension)?;
        let peer_pubkey = KeyShare::client_decode(&ks.data)?;

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
        let early_accepted =
            self.config.accept_early_data && psk_accepted.is_some() && client_offered_early;

        self.transcript.update(raw);

        if let (Some(psk), true) = (psk_accepted.as_ref(), early_accepted) {
            let zero = [0u8; 32];
            let early_secret = crate::kdf::Hkdf::extract(&zero, psk);
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
            Some(psk) => KeySchedule::new_psk(psk).into_handshake(&dhe),
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
                Alpn::encode(core::slice::from_ref(picked)),
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
                CertSource::RawPublicKey { signing_key } => alloc::vec![CertificateEntry {
                    cert_data: spki::SubjectPublicKey::Ed25519(*signing_key.pubkey())
                        .encode()
                        .expect("ed25519 SPKI encode"),
                    extensions: Vec::new(),
                }],
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
            let sig = self.config.source.signing_key().sign(&cv_msg);
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
        self.expected_client_finished = Some(FinishedProto::verify_data(&c_hs, &h_sf));
        self.state = State::ExpectClientFinished;
        Ok(())
    }

    fn try_accept_psk(&self, ch: &ClientHello, raw: &[u8]) -> Option<[u8; 32]> {
        let secret = self.config.ticket_secret?;
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
        let (psk, _age_add) = crate::ticket::TicketSecret::new(secret)
            .decrypt(&id.identity)
            .ok()?;
        let n = raw.len();
        if n < 32 {
            return None;
        }
        let mut t = Transcript::new();
        t.update(&raw[..n - 32]);
        let partial_hash = t.hash();
        let expected = crate::psk::ResumptionBinder::compute(&psk, &partial_hash);
        if expected.as_slice() != bind.as_slice() {
            return None;
        }
        Some(psk)
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
        if f.verify_data.as_slice() != expected {
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
        let Some(ticket_secret) = self.config.ticket_secret else {
            return Ok(());
        };
        let h_cf = self.transcript.hash();
        let rms = master.resumption_master_secret(&h_cf);
        let mut nonce = [0u8; 8];
        let mut age_add_bytes = [0u8; 4];
        self.rng.fill(&mut nonce).map_err(|_| Error::Rng)?;
        self.rng.fill(&mut age_add_bytes).map_err(|_| Error::Rng)?;
        let age_add = u32::from_be_bytes(age_add_bytes);
        let psk = crate::schedule::ResumptionMaster::new(rms).psk(&nonce);
        let ticket = crate::ticket::TicketSecret::new(ticket_secret)
            .encrypt(&psk, age_add, &self.rng)
            .map_err(|_| Error::Rng)?;
        let nst = NewSessionTicket {
            ticket_lifetime: 7200,
            ticket_age_add: age_add,
            ticket_nonce: nonce.to_vec(),
            ticket,
            extensions: Vec::new(),
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
