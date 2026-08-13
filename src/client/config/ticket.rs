use crate::client::config;
use crate::client::config::resumptions;
use crate::crypto::material;
use crate::crypto::schedule;
use crate::transport;
use crate::wire::record;
use core::fmt;

/// A validated, borrow-scoped TLS 1.3 session ticket. Ignoring it performs no
/// derivation or allocation; `try_retain` explicitly creates owned state.
pub struct Ticket<'a> {
    pub(in crate::client) template: &'a config::Template,
    pub(in crate::client) master: &'a material::ResumptionMasterSecret,
    pub(in crate::client) nonce: &'a [u8],
    pub(in crate::client) identity: &'a [u8],
    pub(in crate::client) timing: resumptions::TicketTiming,
    pub(in crate::client) profile: resumptions::IssuedProfile,
}

impl Ticket<'_> {
    /// Derives the persistence PSK while every ticket field remains borrowed,
    /// so a serializer needs no intermediate ticket or ALPN allocation.
    pub fn try_psk(&self) -> Result<material::ResumptionPsk, config::Error> {
        schedule::ResumptionMaster::from_secret(self.master)
            .psk(self.nonce)
            .map_err(|_| config::Error::ResumptionKeyDerivation)
    }

    /// Derives the PSK, copies the opaque ticket once, and binds the endpoint.
    pub fn try_retain(self) -> Result<config::Resumption, config::Error> {
        let psk = self.try_psk()?;
        config::Resumption::from_issued(resumptions::Issued {
            origin: self.template.clone(),
            psk,
            ticket: self.identity,
            timing: self.timing,
            profile: self.profile,
        })
    }

    pub fn ticket(&self) -> &[u8] {
        self.identity
    }

    pub fn ticket_lifetime_secs(&self) -> u32 {
        self.timing.lifetime_secs
    }

    pub fn ticket_age_add(&self) -> u32 {
        self.timing.age_add
    }

    pub fn received_at_ms(&self) -> u64 {
        self.timing.received_at_ms
    }

    pub fn max_early_data(&self) -> Option<u32> {
        self.profile.max_early_data
    }

    pub fn cipher_suite(&self) -> record::CipherSuite {
        self.profile.suite
    }

    pub fn transport_mode(&self) -> transport::Mode {
        self.template.transport_mode()
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.profile.alpn.and_then(|alpn| self.template.alpn(alpn))
    }
}

impl fmt::Debug for Ticket<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTicket")
            .field("ticket", &"[redacted]")
            .field("ticket_lifetime_secs", &self.ticket_lifetime_secs())
            .field("ticket_age_add", &self.ticket_age_add())
            .field("received_at_ms", &self.received_at_ms())
            .field("max_early_data", &self.max_early_data())
            .field("cipher_suite", &self.cipher_suite())
            .field("alpn", &self.alpn())
            .finish()
    }
}
