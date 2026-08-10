use crate::connection;
use crate::crypto::hash;
use crate::crypto::material;
use crate::crypto::schedule;
use crate::identity::leafkey;
use crate::memory::threadbound;
use crate::server;
use crate::server::config;
use crate::server::retry;
use crate::transport;
use crate::wire::handshake::messages;
use crate::wire::handshake::reassemblers;
use crate::wire::handshake::views;
use crate::wire::handshake::workspace;
use crate::wire::record;
use ring::rand;

const MAX_TICKET_AGE_SKEW_MS: u64 = 10_000;
const MAX_EARLY_DATA_SIZE: u32 = 16_384;
pub(super) const TICKET_LIFETIME_SECS: u32 = 7_200;
const TICKET_LIFETIME_MS: u64 = TICKET_LIFETIME_SECS as u64 * 1_000;

pub(super) struct Session<C> {
    pub(super) connection: config::Connection,
    pub(super) connection_validation_error: Option<connection::Error>,
    pub(super) transport_mode: transport::Mode,
    pub(super) handshake: Handshake,
    pub(super) peer: Peer,
    pub(super) application: Application,
    pub(super) buffers: Buffers,
    pub(super) runtime: Runtime<C>,
}

pub(super) trait Drive {
    fn drive_record<G, V, S>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        shard: &mut server::Shard<G, V>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized;

    fn process<G, V, S>(
        &mut self,
        epoch: connection::Epoch,
        message: views::MessageRef<'_>,
        raw: &[u8],
        shard: &mut server::Shard<G, V>,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>
    where
        G: config::EarlyDataGuard,
        V: config::ClientCertVerifier,
        S: connection::EventSink + ?Sized;

    fn send_key_update<S: connection::EventSink + ?Sized>(
        &mut self,
        request_update: bool,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn poison(&mut self);
}

pub(super) struct AcceptedPsk {
    pub(super) psk: material::ResumptionPsk,
    pub(super) ticket: Ticket,
    pub(super) binder: [u8; 32],
    pub(super) alpn: arrayvec::ArrayVec<u8, 255>,
    pub(super) _thread: threadbound::ThreadBound,
}

pub(super) struct Ticket {
    pub(super) age_add: u32,
    pub(super) issued_at_ms: u64,
    pub(super) suite: u16,
    pub(super) obfuscated_age: u32,
    pub(super) max_early_data: Option<u32>,
}

impl AcceptedPsk {
    pub(super) fn issued_at_is_resumable(issued_at_ms: u64, now_ms: u64) -> bool {
        issued_at_ms <= now_ms.saturating_add(MAX_TICKET_AGE_SKEW_MS)
            && now_ms.saturating_sub(issued_at_ms) <= TICKET_LIFETIME_MS
    }
}

pub(super) struct EarlyData {
    enabled: bool,
    remaining: Option<u32>,
    maximum: Option<u32>,
}

impl EarlyData {
    pub(super) fn new() -> Self {
        Self {
            enabled: false,
            remaining: None,
            maximum: None,
        }
    }

    pub(super) fn admit<G: config::EarlyDataGuard>(
        &mut self,
        guard: &mut G,
        offered: bool,
        psk: Option<&AcceptedPsk>,
        selected_alpn: Option<&[u8]>,
        suite: Option<record::CipherSuite>,
        now_ms: u64,
    ) -> bool {
        let enabled = G::ACCEPTS_EARLY_DATA;
        self.remaining = None;
        self.maximum = None;
        self.enabled = enabled;
        if !enabled || !offered {
            return false;
        }
        let Some(psk) = psk else {
            return false;
        };
        let Some(maximum) = psk.ticket.max_early_data else {
            return false;
        };
        let selected_alpn = selected_alpn.unwrap_or_default();
        if selected_alpn != psk.alpn.as_slice()
            || suite.map(record::CipherSuite::wire_id) != Some(psk.ticket.suite)
        {
            return false;
        }
        if now_ms < psk.ticket.issued_at_ms {
            return false;
        }
        let measured_age = now_ms - psk.ticket.issued_at_ms;
        let claimed_age = psk.ticket.obfuscated_age.wrapping_sub(psk.ticket.age_add) as u64;
        if measured_age > TICKET_LIFETIME_MS
            || measured_age.abs_diff(claimed_age) > MAX_TICKET_AGE_SKEW_MS
        {
            return false;
        }
        if !guard.register(&psk.binder) {
            return false;
        }
        self.remaining = Some(maximum);
        self.maximum = Some(maximum);
        true
    }

    pub(super) fn advertised_size(&self, mode: transport::Mode) -> Option<u32> {
        self.enabled
            .then_some(mode.advertised_early_data_size(MAX_EARLY_DATA_SIZE))
    }

    pub(super) fn open_size(&self, _mode: transport::Mode) -> Option<u32> {
        self.maximum
    }

    pub(super) fn charge(
        &mut self,
        len: usize,
        mode: transport::Mode,
    ) -> Result<(), connection::Error> {
        let Some(remaining) = self.remaining.as_mut() else {
            return Err(connection::Error::EarlyDataLimitExceeded);
        };
        if mode.is_quic() {
            return Ok(());
        }
        let Some(left) = u32::try_from(len)
            .ok()
            .and_then(|len| remaining.checked_sub(len))
        else {
            self.remaining = None;
            self.maximum = None;
            return Err(connection::Error::EarlyDataLimitExceeded);
        };
        *remaining = left;
        Ok(())
    }

    pub(super) fn close(&mut self) {
        self.remaining = None;
        self.maximum = None;
    }
}

pub(super) struct Handshake {
    pub(super) state: State,
    pub(super) transcript: hash::Transcript,
    pub(super) hrr_done: bool,
    pub(super) hrr_invariant: Option<retry::ClientHelloInvariant>,
    pub(super) shard_identity: Option<u64>,
}

pub(super) struct Peer {
    pub(super) selected_alpn: Option<arrayvec::ArrayVec<u8, 255>>,
    pub(super) early_data: EarlyData,
    pub(super) client_cert_type: u8,
    pub(super) client_leaf: Option<leafkey::LeafKey>,
}

pub(super) struct Application {
    pub(super) traffic: material::State,
    pub(super) master: Option<schedule::Schedule>,
    pub(super) exporter_master: Option<material::ExporterMasterSecret>,
}

impl Application {
    pub(super) fn hash_alg(&self) -> Result<hash::Algorithm, connection::Error> {
        self.traffic.algorithm()
    }

    pub(super) fn zeroize_secrets(&mut self) {
        self.traffic.clear();
        self.exporter_master = None;
        self.master = None;
    }

    pub(super) fn traffic_secrets(
        &self,
    ) -> Result<(&material::TrafficSecret, &material::TrafficSecret), connection::Error> {
        let read = self.traffic.secret(material::Side::Client)?;
        let write = self.traffic.secret(material::Side::Server)?;
        Ok((read, write))
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

/// Server phase carrying the traffic secret or Finished verifier required by
/// its next input.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum State {
    ExpectClientHello,
    ExpectEndOfEarlyData {
        client_handshake_traffic: material::TrafficSecret,
    },
    ExpectClientCertificate {
        client_handshake_traffic: material::TrafficSecret,
    },
    ExpectClientCertVerify {
        client_handshake_traffic: material::TrafficSecret,
    },
    ExpectClientFinished {
        verify_data: material::FinishedVerifyData,
    },
    Done,
    Failed,
}

impl State {
    pub(super) fn fail(&mut self) {
        *self = Self::Failed;
    }
}

impl<C: connection::Clock> Session<C> {
    pub(super) fn handle_key_update<S: connection::EventSink + ?Sized>(
        &mut self,
        ku: messages::KeyUpdate,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        use crate::connection::Error;
        use crate::connection::Event;
        use crate::connection::EventContext;
        use crate::connection::KeyDirection;
        if !self.transport_mode.allows_tls_key_update() {
            return Err(Error::UnexpectedMessage.into());
        }
        if !self.application.traffic.consume_update() {
            return Err(Error::UnexpectedMessage.into());
        }
        let suite = self.application.traffic.suite();
        let read = self.application.traffic.advance(material::Side::Client)?;
        EventContext::emit(
            events,
            suite,
            Event::KeyUpdate {
                direction: KeyDirection::Read,
                secret: read,
            },
        )?;

        if ku.request_update == 1 {
            use crate::connection::Epoch;
            let reply = messages::KeyUpdate { request_update: 0 };
            let bytes = reply.encode_framed();
            EventContext::emit(
                events,
                suite,
                Event::Send {
                    epoch: Epoch::Application,
                    data: &bytes,
                },
            )?;
            let write = self.application.traffic.advance(material::Side::Server)?;
            EventContext::emit(
                events,
                suite,
                Event::KeyUpdate {
                    direction: KeyDirection::Write,
                    secret: write,
                },
            )?;
        }
        Ok(())
    }
}
