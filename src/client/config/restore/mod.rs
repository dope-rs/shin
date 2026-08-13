use crate::client::config;
use crate::client::config::resumptions;
use crate::crypto::material;
use crate::transport;
use crate::wire::psk;
use crate::wire::record;
use alloc::borrow;
use core::fmt;
use core::num;

pub(super) mod alpn;

/// A one-shot restoration input whose protocol bytes only live until the
/// endpoint template has resolved them to a compact internal identifier.
pub struct Restore<'a> {
    psk: material::ResumptionPsk,
    ticket: borrow::Cow<'a, [u8]>,
    timing: resumptions::TicketTiming,
    lifetime_ms: num::NonZeroU32,
    early_data: Option<EarlyData<'a>>,
}

struct EarlyData<'a> {
    maximum: u32,
    suite: record::CipherSuite,
    transport_mode: transport::Mode,
    alpn: config::NegotiatedAlpn<'a>,
}

impl<'a> Restore<'a> {
    /// Validates persisted 1-RTT resumption material. An owned ticket is moved
    /// into the handshake without copying; a borrowed ticket is copied once.
    pub fn try_new(
        psk: impl Into<material::ResumptionPsk>,
        ticket: impl Into<borrow::Cow<'a, [u8]>>,
        ticket_age_add: u32,
        received_at_ms: u64,
        ticket_lifetime_secs: u32,
    ) -> Result<Self, config::Error> {
        let ticket = ticket.into();
        resumptions::Active::validate_ticket(&ticket)?;
        let lifetime_ms = resumptions::Active::lifetime_ms(ticket_lifetime_secs)?;
        Ok(Self {
            psk: psk.into(),
            ticket,
            timing: resumptions::TicketTiming {
                lifetime_secs: ticket_lifetime_secs,
                age_add: ticket_age_add,
                received_at_ms,
            },
            lifetime_ms,
            early_data: None,
        })
    }

    /// Adds complete 0-RTT authority. The ALPN value is mandatory metadata;
    /// callers must explicitly state that the issuing connection had no ALPN.
    pub fn try_with_early_data(
        mut self,
        maximum: u32,
        suite: record::CipherSuite,
        transport_mode: transport::Mode,
        alpn: config::NegotiatedAlpn<'a>,
    ) -> Result<Self, config::Error> {
        let valid_alpn = match alpn {
            config::NegotiatedAlpn::Absent => true,
            config::NegotiatedAlpn::Protocol(ref protocol) => {
                !protocol.is_empty() && protocol.len() <= u8::MAX as usize
            }
        };
        if self.early_data.is_some()
            || !resumptions::Active::valid_early_data(maximum, transport_mode)
            || suite.hash_alg() != psk::RESUMPTION_HASH
            || !valid_alpn
        {
            return Err(config::Error::InvalidEarlyDataEntitlement);
        }
        self.early_data = Some(EarlyData {
            maximum,
            suite,
            transport_mode,
            alpn,
        });
        Ok(self)
    }

    pub(super) fn bind(self, template: &config::Template) -> resumptions::Active {
        let early_data = self.early_data.and_then(|restored| {
            if restored.transport_mode != template.transport_mode() {
                return None;
            }
            let alpn = match restored.alpn {
                config::NegotiatedAlpn::Absent => None,
                config::NegotiatedAlpn::Protocol(protocol) => Some(template.find_alpn(&protocol)?),
            };
            Some(resumptions::BoundEarlyData {
                maximum: restored.maximum,
                suite: restored.suite,
                alpn,
            })
        });
        resumptions::Active {
            psk: self.psk,
            ticket: self.ticket.into_owned(),
            ticket_age_add: self.timing.age_add,
            received_at_ms: self.timing.received_at_ms,
            lifetime_ms: self.lifetime_ms,
            early_data,
        }
    }
}

impl fmt::Debug for Restore<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Restore")
            .field("psk", &"[redacted]")
            .field("ticket_len", &self.ticket.len())
            .field("ticket_age_add", &self.timing.age_add)
            .field("received_at_ms", &self.timing.received_at_ms)
            .field("ticket_lifetime_secs", &self.timing.lifetime_secs)
            .field(
                "max_early_data",
                &self.early_data.as_ref().map(|authority| authority.maximum),
            )
            .finish()
    }
}
