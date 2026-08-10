use crate::client;
use crate::client::authentication::Authentication as _;
use crate::client::config;
use crate::client::negotiation::Negotiation as _;
use crate::client::state;
use crate::connection;
use crate::crypto::hash;
use crate::crypto::kx;
use crate::crypto::material;
use crate::memory::threadbound;
use crate::wire::extension;
use crate::wire::handshake;
use crate::wire::handshake::messages;
use crate::wire::handshake::reassemblers;
use crate::wire::handshake::views;
use crate::wire::handshake::workspace;
use crate::wire::record;
use ring::rand;

pub(super) struct Session<C> {
    pub(super) offer: OfferSettings,
    pub(super) handshake: Handshake,
    pub(super) extensions: Extensions,
    pub(super) credentials: Credentials,
    pub(super) application: Application,
    pub(super) buffers: Buffers,
    pub(super) runtime: Runtime<C>,
}

pub(super) struct OfferSettings {
    pub(super) config: config::Template,
    pub(super) resumption: Option<config::Resumption>,
    pub(super) kex_group: kx::KexGroup,
    pub(super) offered_suites: arrayvec::ArrayVec<record::CipherSuite, 3>,
}

pub(super) struct Handshake {
    pub(super) state: state::State,
    pub(super) transcript: hash::Transcript,
    pub(super) eph: Option<kx::EphemeralKey>,
    pub(super) client_random: [u8; handshake::RANDOM_LEN],
    pub(super) session_id: [u8; 32],
    pub(super) hrr_done: bool,
    pub(super) active_resumption: Option<config::Resumption>,
    pub(super) psk_used: bool,
}

impl Handshake {
    pub(super) fn require_initial(&self) -> Result<(), connection::Error> {
        match self.state.kind() {
            state::StateKind::Initial => Ok(()),
            state::StateKind::Failed => Err(connection::Error::ConnectionFailed),
            _ => Err(connection::Error::UnexpectedMessage),
        }
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.state.zeroize_secrets();
    }
}

#[derive(Clone, Copy)]
pub(super) enum EarlyData {
    NotOffered,
    Offered,
    Accepted,
}

pub(super) struct Extensions {
    pub(super) ee_offered: arrayvec::ArrayVec<extension::Type, 16>,
    pub(super) selected_alpn: Option<arrayvec::ArrayVec<u8, 255>>,
    pub(super) early_data: EarlyData,
}

pub(super) struct Credentials {
    /// Identity to present if the server sends a CertificateRequest (mutual TLS).
    pub(super) identity: Option<config::IdentityTemplate>,
    /// Set when the server requested client auth; carries the context to echo
    /// and the signature schemes it will accept in our CertificateVerify.
    pub(super) cert_request: Option<CertRequest>,
}

pub(super) struct CertRequest {
    pub(super) context: arrayvec::ArrayVec<u8, 255>,
    pub(super) signing_scheme_accepted: bool,
}

pub(super) struct Application {
    pub(super) traffic: material::State,
    pub(super) resumption_master: Option<material::ResumptionMasterSecret>,
    pub(super) exporter_master: Option<material::ExporterMasterSecret>,
}

impl Application {
    pub(super) fn hash_alg(&self) -> Result<hash::Algorithm, connection::Error> {
        self.traffic.algorithm()
    }

    pub(super) fn zeroize_secrets(&mut self) {
        self.traffic.clear();
        self.resumption_master = None;
        self.exporter_master = None;
    }
}

impl Drop for Application {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

pub(super) struct Buffers {
    pub(super) reasm: reassemblers::HsReassembler,
    pub(super) flight: workspace::BoundedBuffer,
    pub(super) identity_workspace: workspace::BoundedBuffer,
}

pub(super) struct Runtime<C> {
    pub(super) clock: C,
    pub(super) rng: rand::SystemRandom,
    pub(super) _thread: threadbound::ThreadBound,
}

impl<C: connection::Clock> Session<C> {
    pub(super) fn dispatch<S: connection::EventSink + ?Sized>(
        client: &mut client::Client<C>,
        epoch: connection::Epoch,
        msg: views::MessageRef<'_>,
        raw: &[u8],
        hybrid_workspace: Option<&mut kx::HybridWorkspace>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        match (client.session.handshake.state.kind(), msg) {
            (state::StateKind::ExpectServerHello, views::MessageRef::ServerHello(sh))
                if epoch == connection::Epoch::Plaintext =>
            {
                client.handle_server_hello(sh, raw, hybrid_workspace, events)
            }
            (
                state::StateKind::ExpectEncryptedExtensions,
                views::MessageRef::EncryptedExtensions(ee),
            ) if epoch == connection::Epoch::Handshake => {
                let secrets = client
                    .session
                    .handshake
                    .state
                    .take_secrets()
                    .ok_or(connection::Error::UnexpectedMessage)?;
                client.handle_encrypted_extensions(ee, raw, secrets, events)
            }
            (state::StateKind::ExpectCertificate, views::MessageRef::CertificateRequest(cr))
                if epoch == connection::Epoch::Handshake =>
            {
                client.handle_certificate_request(cr, raw)?;
                Ok(())
            }
            (state::StateKind::ExpectCertificate, views::MessageRef::Certificate(c))
                if epoch == connection::Epoch::Handshake =>
            {
                let secrets = client
                    .session
                    .handshake
                    .state
                    .take_secrets()
                    .ok_or(connection::Error::UnexpectedMessage)?;
                client.handle_certificate(c, raw, secrets)?;
                Ok(())
            }
            (
                state::StateKind::ExpectCertificateVerify,
                views::MessageRef::CertificateVerify(cv),
            ) if epoch == connection::Epoch::Handshake => {
                let secrets = client
                    .session
                    .handshake
                    .state
                    .take_secrets()
                    .ok_or(connection::Error::UnexpectedMessage)?;
                let server_leaf_key = client
                    .session
                    .handshake
                    .state
                    .server_leaf_key()
                    .ok_or(connection::Error::UnexpectedMessage)?;
                client.handle_certificate_verify(cv, raw, secrets, &server_leaf_key)?;
                Ok(())
            }
            (state::StateKind::ExpectServerFinished, views::MessageRef::Finished(f))
                if epoch == connection::Epoch::Handshake =>
            {
                let secrets = client
                    .session
                    .handshake
                    .state
                    .take_secrets()
                    .ok_or(connection::Error::UnexpectedMessage)?;
                client.handle_server_finished(f, raw, secrets, events)
            }
            (state::StateKind::Done, views::MessageRef::KeyUpdate(ku))
                if epoch == connection::Epoch::Application =>
            {
                Self::handle_key_update(client, ku, events)
            }
            (state::StateKind::Done, views::MessageRef::NewSessionTicket(nst))
                if epoch == connection::Epoch::Application =>
            {
                use crate::client::MAX_TICKET_LIFETIME_SECS;
                use crate::wire::psk::RESUMPTION_HASH;
                if nst.ticket_lifetime > MAX_TICKET_LIFETIME_SECS {
                    return Err(connection::Error::IllegalParameter.into());
                }
                if let Some(rms) = client.session.application.resumption_master.as_ref()
                    && client.session.application.hash_alg()? == RESUMPTION_HASH
                {
                    use crate::crypto::schedule::ResumptionMaster;
                    let psk = ResumptionMaster::from_secret(rms).psk(nst.ticket_nonce)?;
                    connection::EventContext::emit(
                        events,
                        client.session.application.traffic.suite(),
                        connection::Event::ResumptionSecret { psk: &psk },
                    )?;
                }
                let max_early_data = nst
                    .extensions
                    .iter()
                    .find(|extension| extension.ty == extension::Type::EARLY_DATA)
                    .map(|extension| {
                        use crate::wire::codec::Reader;
                        let mut reader = Reader::new(extension.data);
                        let value = reader.u32().map_err(connection::Error::from)?;
                        reader.finish().map_err(connection::Error::from)?;
                        Ok::<u32, connection::Error>(value)
                    })
                    .transpose()?;
                if client.session.offer.config.transport_mode().is_quic()
                    && max_early_data.is_some_and(|maximum| maximum != u32::MAX)
                {
                    return Err(connection::Error::IllegalParameter.into());
                }
                connection::EventContext::emit(
                    events,
                    client.session.application.traffic.suite(),
                    connection::Event::NewSessionTicket {
                        ticket_lifetime: nst.ticket_lifetime,
                        ticket_age_add: nst.ticket_age_add,
                        ticket_nonce: nst.ticket_nonce,
                        ticket: nst.ticket,
                        max_early_data,
                    },
                )?;
                Ok(())
            }
            _ => Err(connection::Error::UnexpectedMessage.into()),
        }
    }

    fn handle_key_update<S: connection::EventSink + ?Sized>(
        client: &mut client::Client<C>,
        update: messages::KeyUpdate,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::connection::KeyDirection;
        if !client
            .session
            .offer
            .config
            .transport_mode()
            .allows_tls_key_update()
        {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        if !client.session.application.traffic.consume_update() {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        let suite = client.session.application.traffic.suite();
        let read = client
            .session
            .application
            .traffic
            .advance(material::Side::Server)?;
        connection::EventContext::emit(
            events,
            suite,
            connection::Event::KeyUpdate {
                direction: KeyDirection::Read,
                secret: read,
            },
        )?;

        if update.request_update == 1 {
            let reply = messages::KeyUpdate { request_update: 0 };
            let bytes = reply.encode_framed();
            connection::EventContext::emit(
                events,
                suite,
                connection::Event::Send {
                    epoch: connection::Epoch::Application,
                    data: &bytes,
                },
            )?;
            let write = client
                .session
                .application
                .traffic
                .advance(material::Side::Client)?;
            connection::EventContext::emit(
                events,
                suite,
                connection::Event::KeyUpdate {
                    direction: KeyDirection::Write,
                    secret: write,
                },
            )?;
        }
        Ok(())
    }
}
