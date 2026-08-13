use crate::connection;
use crate::crypto::hash;
use crate::crypto::material;
use crate::crypto::schedule;
use crate::identity;
use crate::memory::threadbound;
use crate::server::config;
use crate::transport;
use crate::wire::handshake::messages;
use crate::wire::handshake::storage;
use crate::wire::protocols;
use crate::wire::record;
use core::mem;
use ring::rand;

mod authentication;
pub(super) mod drive;
mod hello;
mod negotiation;
mod resumption;
mod retry;
pub(super) mod updates;

const MAX_TICKET_AGE_SKEW_MS: u64 = 10_000;
const MAX_EARLY_DATA_SIZE: u32 = 16_384;
pub(super) const TICKET_LIFETIME_SECS: u32 = 7_200;
const TICKET_LIFETIME_MS: u64 = TICKET_LIFETIME_SECS as u64 * 1_000;

pub(super) struct Session<C> {
    pub(super) connection: config::Connection,
    pub(super) transport_mode: transport::Mode,
    pub(super) handshake: Handshake,
    pub(super) peer: Peer,
    pub(super) application: Application,
    pub(super) buffers: Buffers,
    pub(super) runtime: Runtime<C>,
}

pub(super) struct AcceptedPsk {
    pub(super) psk: material::ResumptionPsk,
    pub(super) ticket: Ticket,
    pub(super) binder: [u8; 32],
    pub(super) alpn_matches: bool,
    pub(super) _thread: threadbound::ThreadBound,
}

const _: () = assert!(mem::size_of::<AcceptedPsk>() <= 104);

pub(super) struct Ticket {
    pub(super) age_add: u32,
    pub(super) issued_at_ms: u64,
    pub(super) suite: record::CipherSuite,
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
        guard: &G,
        offered: Option<protocols::EarlyDataSignal>,
        psk: Option<&AcceptedPsk>,
        suite: Option<record::CipherSuite>,
        now_ms: u64,
    ) -> bool {
        let enabled = G::ACCEPTS_EARLY_DATA;
        self.remaining = None;
        self.maximum = None;
        self.enabled = enabled;
        if !enabled || offered.is_none() {
            return false;
        }
        let Some(psk) = psk else {
            return false;
        };
        let Some(maximum) = psk.ticket.max_early_data else {
            return false;
        };
        if !psk.alpn_matches || suite != Some(psk.ticket.suite) {
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
    state: State,
    transcript: hash::Transcript,
    hrr_done: bool,
    hrr_invariant: Option<retry::ClientHelloInvariant>,
}

pub(super) struct Peer {
    pub(super) selected_alpn: Option<protocols::AlpnId>,
    pub(super) early_data: EarlyData,
    pub(super) client_cert_type: identity::CertificateType,
}

const _: () = assert!(mem::size_of::<Peer>() <= 40);

impl Peer {
    pub(super) fn selected_alpn<'a>(
        &self,
        protocols: &'a protocols::PreparedAlpn,
    ) -> Option<&'a [u8]> {
        self.selected_alpn
            .and_then(|selected| protocols.get(selected))
    }
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
    pub(super) flight: storage::BoundedBuffer,
    pub(super) identity_workspace: storage::BoundedBuffer,
}

pub(super) struct Runtime<C> {
    pub(super) clock: C,
    pub(super) rng: rand::SystemRandom,
    pub(super) _thread: threadbound::ThreadBound,
}

/// Server phase carrying the traffic secret or Finished verifier required by
/// its next input.
#[derive(Debug, PartialEq, Eq)]
enum State {
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

impl Handshake {
    pub(super) fn initial() -> Self {
        Self {
            state: State::ExpectClientHello,
            transcript: hash::Transcript::new(),
            hrr_done: false,
            hrr_invariant: None,
        }
    }

    pub(super) fn is_failed(&self) -> bool {
        self.state == State::Failed
    }

    pub(super) fn is_done(&self) -> bool {
        self.state == State::Done
    }
}

impl<C: connection::Clock> Session<C> {
    pub(super) fn poison(&mut self) {
        self.handshake.state.fail();
        self.application.zeroize_secrets();
        self.peer.early_data.close();
        self.buffers.flight.clear();
        self.buffers.identity_workspace.clear();
    }

    pub(super) fn handle_key_update<S: connection::EventSink + ?Sized>(
        &mut self,
        ku: messages::KeyUpdate,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        if !self.transport_mode.allows_tls_key_update() {
            return Err(connection::Error::UnexpectedMessage.into());
        }
        connection::KeyUpdateCore::<connection::ServerRole>::new(&mut self.application.traffic)
            .receive(ku.request, events)
    }
}
