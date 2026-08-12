use crate::client;
use crate::client::authentication::Authentication as _;
use crate::client::config;
use crate::client::config::resumption;
use crate::client::negotiation::Negotiation as _;
use crate::client::state;
use crate::connection;
use crate::crypto::hash;
use crate::crypto::kx;
use crate::crypto::material;
use crate::identity;
use crate::memory::threadbound;
use crate::wire::extension;
use crate::wire::handshake;
use crate::wire::handshake::messages;
use crate::wire::handshake::reassemblers;
use crate::wire::handshake::views;
use crate::wire::handshake::workspace;
use crate::wire::protocols;
use crate::wire::record;
use core::mem;
use o3::collections::fixed::array;
use ring::rand;

pub(super) struct Session<C, K> {
    pub(super) offer: OfferSettings,
    pub(super) handshake: Handshake,
    pub(super) kx: K,
    pub(super) extensions: Extensions,
    pub(super) credentials: Credentials,
    pub(super) application: Application,
    pub(super) buffers: Buffers,
    pub(super) runtime: Runtime<C>,
}

pub(super) struct OfferSettings {
    pub(super) config: config::Template,
    pub(super) enable_early_data: bool,
    pub(super) kex_group: kx::KexGroup,
    pub(super) offered_suites: array::CopyInline<record::CipherSuite, 3>,
}

pub(super) struct Handshake {
    pub(super) state: state::State,
    pub(super) transcript: hash::Transcript,
    pub(super) client_random: [u8; handshake::RANDOM_LEN],
    pub(super) session_id: [u8; 32],
    pub(super) hrr_done: bool,
    /// Single ticket slot shared by the pre-start and in-flight phases.
    pub(super) resumption: Option<resumption::Active>,
    pub(super) psk_used: bool,
}

impl Handshake {
    pub(super) fn require_initial(&self) -> Result<(), connection::Error> {
        match self.state {
            state::State::Initial => Ok(()),
            state::State::Failed => Err(connection::Error::ConnectionFailed),
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
    Offered(resumption::BoundEarlyData),
    Accepted,
}

pub(super) struct Extensions {
    pub(super) selected_alpn: Option<protocols::AlpnId>,
    pub(super) early_data: EarlyData,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CertificateTypeOffers {
    pub(super) server: Option<identity::CertificateType>,
    pub(super) client: Option<identity::CertificateType>,
}

const _: () = assert!(mem::size_of::<CertificateTypeOffers>() == 2);

pub(super) struct NegotiatedExtensions<'wire> {
    pub(super) quic_params: Option<&'wire [u8]>,
    pub(super) alpn: Option<protocols::AlpnId>,
    pub(super) early_data: Option<protocols::EarlyDataSignal>,
}

impl<'wire> NegotiatedExtensions<'wire> {
    pub(super) fn decode(
        extensions: extension::Extensions<'wire>,
        config: &config::Template,
        certificate_types: CertificateTypeOffers,
        allow_early_data: bool,
    ) -> Result<Self, connection::Error> {
        let mut negotiated = Self {
            quic_params: None,
            alpn: None,
            early_data: None,
        };
        let mut confirmed_certificate_types = CertificateTypeOffers::default();

        for extension in extensions.iter() {
            match extension.ty {
                extension::Type::SERVER_NAME => {
                    if config.verifier().dns_hostname().is_none() {
                        return Err(connection::Error::UnsolicitedExtension);
                    }
                    protocols::ServerNameAck::decode(extension.data)?;
                }
                extension::Type::SUPPORTED_GROUPS => {
                    protocols::ServerSupportedGroups::decode(extension.data)?;
                }
                extension::Type::SERVER_CERTIFICATE_TYPE => {
                    let expected = certificate_types
                        .server
                        .ok_or(connection::Error::UnsolicitedExtension)?;
                    let selected = protocols::CertificateTypeList::decode_selection(extension.data)
                        .map_err(|_| connection::Error::IllegalParameter)?;
                    if selected != expected {
                        return Err(connection::Error::IllegalParameter);
                    }
                    confirmed_certificate_types.server = Some(selected);
                }
                extension::Type::CLIENT_CERTIFICATE_TYPE => {
                    let expected = certificate_types
                        .client
                        .ok_or(connection::Error::UnsolicitedExtension)?;
                    let selected = protocols::CertificateTypeList::decode_selection(extension.data)
                        .map_err(|_| connection::Error::IllegalParameter)?;
                    if selected != expected {
                        return Err(connection::Error::IllegalParameter);
                    }
                    confirmed_certificate_types.client = Some(selected);
                }
                extension::Type::QUIC_TRANSPORT_PARAMETERS => {
                    if !config.transport_mode().is_quic() {
                        return Err(connection::Error::UnsolicitedExtension);
                    }
                    negotiated.quic_params = Some(extension.data);
                }
                extension::Type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    if config.alpn_protocols().is_empty() {
                        return Err(connection::Error::UnsolicitedExtension);
                    }
                    let chosen = protocols::Alpn::decode(extension.data)
                        .map_err(|_| connection::Error::Decode)?;
                    if chosen.len() != 1 {
                        return Err(connection::Error::IllegalParameter);
                    }
                    let selected = chosen
                        .iter()
                        .next()
                        .and_then(|protocol| config.find_alpn(protocol))
                        .ok_or(connection::Error::IllegalParameter)?;
                    negotiated.alpn = Some(selected);
                }
                extension::Type::EARLY_DATA => {
                    if !allow_early_data {
                        return Err(connection::Error::UnsolicitedExtension);
                    }
                    negotiated.early_data =
                        Some(protocols::EarlyDataSignal::decode(extension.data)?);
                }
                _ => return Err(connection::Error::UnsolicitedExtension),
            }
        }

        if confirmed_certificate_types != certificate_types {
            return Err(connection::Error::MissingExtension);
        }
        if config.transport_mode().is_quic() && negotiated.quic_params.is_none() {
            return Err(connection::Error::MissingExtension);
        }
        Ok(negotiated)
    }
}

pub(super) struct Credentials {
    /// Identity to present if the server sends a CertificateRequest (mutual TLS).
    pub(super) identity: Option<config::IdentityTemplate>,
    /// Main-handshake client-auth response selected from the borrowed request.
    pub(super) certificate_response: Option<CertificateResponse>,
}

#[derive(Clone, Copy)]
pub(super) enum CertificateResponse {
    Empty,
    Identity,
}

const _: () = assert!(mem::size_of::<Option<CertificateResponse>>() == 1);
const _: () = assert!(mem::size_of::<Credentials>() <= 2 * mem::size_of::<usize>());

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
    /// Outbound flight storage, phase-reused for an X.509 server leaf between
    /// Certificate and CertificateVerify when no outbound bytes are live.
    pub(super) flight: workspace::BoundedBuffer,
}

pub(super) struct Runtime<C> {
    pub(super) clock: C,
    pub(super) rng: rand::SystemRandom,
    pub(super) _thread: threadbound::ThreadBound,
}

impl<C, K> Session<C, K> {
    pub(super) fn with_kx<N>(self, kx: N) -> Session<C, N> {
        let Self {
            offer,
            handshake,
            kx: _,
            extensions,
            credentials,
            application,
            buffers,
            runtime,
        } = self;
        Session {
            offer,
            handshake,
            kx,
            extensions,
            credentials,
            application,
            buffers,
            runtime,
        }
    }

    pub(super) fn certificate_type_offers(&self) -> CertificateTypeOffers {
        use crate::identity::CertificateType;
        let server = matches!(
            self.offer.config.verifier(),
            config::Verifier::RawPublicKey { .. }
        )
        .then_some(CertificateType::RawPublicKey);
        CertificateTypeOffers {
            server,
            client: self
                .credentials
                .identity
                .as_ref()
                .map(config::IdentityTemplate::cert_type)
                .or(server),
        }
    }
}

impl<C: connection::Clock, K: kx::Initiator> Session<C, K> {
    pub(super) fn release_workspace(mut self) -> client::Workspace {
        self.kx.clear();
        client::Workspace::from_buffers(
            self.buffers.reasm.release_buffer(),
            mem::take(&mut self.buffers.flight),
        )
    }

    pub(super) fn dispatch<S: connection::EventSink + ?Sized>(
        client: &mut client::Client<C, K>,
        epoch: connection::Epoch,
        msg: views::MessageRef<'_>,
        raw: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        let state = mem::replace(&mut client.session.handshake.state, state::State::Failed);
        match (state, msg) {
            (state::State::ExpectServerHello, views::MessageRef::ServerHello(sh))
                if epoch == connection::Epoch::Plaintext =>
            {
                client.session.handshake.state = state::State::ExpectServerHello;
                client.handle_server_hello(sh, raw, events)
            }
            (
                state::State::ExpectEncryptedExtensions { secrets },
                views::MessageRef::EncryptedExtensions(ee),
            ) if epoch == connection::Epoch::Handshake => {
                client.handle_encrypted_extensions(ee, raw, secrets, events)
            }
            (
                state::State::ExpectCertificate { secrets },
                views::MessageRef::CertificateRequest(cr),
            ) if epoch == connection::Epoch::Handshake => {
                client.session.handshake.state = state::State::ExpectCertificate { secrets };
                client.handle_certificate_request(cr, raw)?;
                Ok(())
            }
            (state::State::ExpectCertificate { secrets }, views::MessageRef::Certificate(c))
                if epoch == connection::Epoch::Handshake =>
            {
                client.handle_certificate(c, raw, secrets)?;
                Ok(())
            }
            (
                state::State::ExpectCertificateVerify {
                    secrets,
                    server_leaf,
                },
                views::MessageRef::CertificateVerify(cv),
            ) if epoch == connection::Epoch::Handshake => {
                client.handle_certificate_verify(cv, raw, secrets, server_leaf)?;
                Ok(())
            }
            (state::State::ExpectServerFinished { secrets }, views::MessageRef::Finished(f))
                if epoch == connection::Epoch::Handshake =>
            {
                client.handle_server_finished(f, raw, secrets, events)
            }
            (state::State::Done, views::MessageRef::KeyUpdate(ku))
                if epoch == connection::Epoch::Application =>
            {
                client.session.handshake.state = state::State::Done;
                Self::handle_key_update(client, ku, events)
            }
            (state::State::Done, views::MessageRef::NewSessionTicket(nst))
                if epoch == connection::Epoch::Application =>
            {
                client.session.handshake.state = state::State::Done;
                use crate::client::config::resumption::MAX_TICKET_LIFETIME_SECS;
                use crate::wire::psk::RESUMPTION_HASH;
                if nst.ticket_lifetime > MAX_TICKET_LIFETIME_SECS {
                    return Err(connection::Error::IllegalParameter.into());
                }
                let mut max_early_data = nst
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
                if client.session.offer.config.transport_mode().is_tls()
                    && max_early_data.is_some_and(|maximum| maximum == 0 || maximum == u32::MAX)
                {
                    max_early_data = None;
                }
                if nst.ticket_lifetime == 0
                    || client.session.application.hash_alg()? != RESUMPTION_HASH
                {
                    return Ok(());
                }
                let Some(master) = client.session.application.resumption_master.as_ref() else {
                    return Ok(());
                };
                let suite = client
                    .session
                    .application
                    .traffic
                    .suite()
                    .ok_or(connection::Error::UnexpectedMessage)?;
                let ticket = client::Ticket {
                    template: &client.session.offer.config,
                    master,
                    nonce: nst.ticket_nonce,
                    identity: nst.ticket,
                    timing: resumption::TicketTiming {
                        lifetime_secs: nst.ticket_lifetime,
                        age_add: nst.ticket_age_add,
                        received_at_ms: connection::Clock::now_ms(&client.session.runtime.clock),
                    },
                    profile: resumption::IssuedProfile {
                        max_early_data,
                        suite,
                        alpn: client.session.extensions.selected_alpn,
                    },
                };
                connection::EventContext::emit(
                    events,
                    Some(suite),
                    connection::Event::NewSessionTicket(ticket),
                )?;
                Ok(())
            }
            _ => Err(connection::Error::UnexpectedMessage.into()),
        }
    }

    fn handle_key_update<S: connection::EventSink + ?Sized>(
        client: &mut client::Client<C, K>,
        update: messages::KeyUpdate,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if !client
            .session
            .offer
            .config
            .transport_mode()
            .allows_tls_key_update()
        {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        connection::KeyUpdateCore::<connection::ClientRole>::new(
            &mut client.session.application.traffic,
        )
        .receive(update.request, events)
    }
}
