use alloc::vec::Vec;

use ring::rand::{SecureRandom, SystemRandom};

use crate::cert::Cert;
use crate::chain::{Chain, TrustAnchor};
use crate::codec::Reader;
use crate::extension::{Extension, ExtensionType};
use crate::handshake::{
    Certificate, CertificateVerify, ClientHello, EncryptedExtensions, Finished, Handshake,
    RANDOM_LEN, ServerHello, TLS_1_2,
};
use crate::hash::Transcript;
use crate::hostname::Hostname;
use crate::kx::EphemeralKey;
use crate::proto::{
    Alpn, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509, CertType, CertVerify,
    Finished as FinishedProto, KeyShare, SUITE_AES_128_GCM_SHA256, ServerName, SignatureAlgorithms,
    SupportedGroups, SupportedVersions, TLS_1_3,
};
use crate::schedule::KeySchedule;
use crate::spki;
use crate::time::UnixTime;
use crate::{Epoch, Error, Event};

mod config;

pub use config::{Config, OwnedTrustAnchor, Resumption, Verifier};

use config::{LeafKey, LeafKeyKind};

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

pub struct Client {
    config: Config,
    state: State,
    transcript: Transcript,
    rng: SystemRandom,
    eph: Option<EphemeralKey>,
    handshake_secret: Option<[u8; 32]>,
    c_hs_traffic: Option<[u8; 32]>,
    s_hs_traffic: Option<[u8; 32]>,
    c_ap_traffic: Option<[u8; 32]>,
    s_ap_traffic: Option<[u8; 32]>,
    server_leaf_key: Option<LeafKey>,
    selected_alpn: Option<Vec<u8>>,
    resumption_master: Option<[u8; 32]>,
    psk_used: bool,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state: State::Initial,
            transcript: Transcript::new(),
            rng: SystemRandom::new(),
            eph: None,
            handshake_secret: None,
            c_hs_traffic: None,
            s_hs_traffic: None,
            c_ap_traffic: None,
            s_ap_traffic: None,
            server_leaf_key: None,
            selected_alpn: None,
            resumption_master: None,
            psk_used: false,
        }
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.selected_alpn.as_deref()
    }

    pub fn start(&mut self) -> Result<Vec<Event>, Error> {
        if self.state != State::Initial {
            return Err(Error::UnexpectedMessage);
        }
        let eph = EphemeralKey::generate(&self.rng).map_err(|_| Error::Kx)?;

        let mut client_random = [0u8; RANDOM_LEN];
        self.rng.fill(&mut client_random).map_err(|_| Error::Rng)?;
        let mut session_id = [0u8; 32];
        self.rng.fill(&mut session_id).map_err(|_| Error::Rng)?;

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
                KeyShare::client_encode(eph.pubkey())
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

        let resumption = self.config.resumption.clone();
        let early_data_offered = self.config.enable_early_data && resumption.is_some();
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

        let ch = ClientHello {
            legacy_version: TLS_1_2,
            random: client_random,
            legacy_session_id: session_id.to_vec(),
            cipher_suites: alloc::vec![SUITE_AES_128_GCM_SHA256],
            legacy_compression_methods: alloc::vec![0],
            extensions,
        };

        let mut ch_bytes = Vec::new();
        Handshake::ClientHello(ch).encode(&mut ch_bytes);

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
                events.push(Event::NewSessionTicket {
                    ticket_lifetime: nst.ticket_lifetime,
                    ticket_age_add: nst.ticket_age_add,
                    ticket_nonce: nst.ticket_nonce,
                    ticket: nst.ticket,
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
        if sh.cipher_suite != SUITE_AES_128_GCM_SHA256 {
            return Err(Error::UnsupportedCipherSuite);
        }
        const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
        const DOWNGRADE_TLS11: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];
        let tail = &sh.random[RANDOM_LEN - 8..];
        if tail == DOWNGRADE_TLS12 || tail == DOWNGRADE_TLS11 {
            return Err(Error::DowngradeDetected);
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
        let server_pubkey = KeyShare::server_decode(ks_data)?;

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

    fn handle_encrypted_extensions(
        &mut self,
        ee: EncryptedExtensions,
        raw: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        for ext in &ee.extensions {
            if ext.ty == ExtensionType::QUIC_TRANSPORT_PARAMETERS {
                events.push(Event::PeerExtension {
                    ty: ext.ty.0,
                    data: ext.data.clone(),
                });
            } else if ext.ty == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION {
                let chosen = Alpn::decode(&ext.data).map_err(|_| Error::Decode)?;
                if chosen.len() != 1 {
                    return Err(Error::Decode);
                }
                let pick = chosen.into_iter().next().unwrap();
                if !self.config.alpn_protocols.iter().any(|p| p == &pick) {
                    return Err(Error::UnexpectedMessage);
                }
                self.selected_alpn = Some(pick);
            }
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
            Verifier::X509 {
                anchors,
                hostname,
                now_seconds,
            } => {
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
                Chain::validate(&parsed, &anchor_views, UnixTime(*now_seconds), hostname).map_err(
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

    fn handle_certificate_verify(
        &mut self,
        cv: CertificateVerify,
        raw: &[u8],
    ) -> Result<(), Error> {
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

        events.push(Event::KeysReady {
            epoch: Epoch::Application,
            read_secret: s_ap,
            write_secret: c_ap,
        });

        let cf_data = FinishedProto::verify_data(&c_hs, &h_sf);
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
