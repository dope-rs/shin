use crate::crypto::material;
use crate::transport;
use crate::wire::protocols;
use crate::wire::psk;
use crate::wire::record;
use alloc::vec;
use core::fmt;
use core::mem;
use core::num;

pub(crate) const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

/// A single-use live ticket bound to the endpoint that issued it.
///
/// Persisted material must cross [`super::Template::restore`], so unresolved
/// ALPN bytes can never reach the handshake state.
///
/// ```compile_fail
/// use shin::client::config::Resumption;
/// fn assert_send<T: Send>() {}
/// assert_send::<Resumption>();
/// ```
pub struct Resumption {
    active: Active,
    origin: super::Template,
}

pub(crate) struct Active {
    pub(super) psk: material::ResumptionPsk,
    pub(super) ticket: vec::Vec<u8>,
    pub(super) ticket_age_add: u32,
    pub(super) received_at_ms: u64,
    pub(super) lifetime_ms: num::NonZeroU32,
    pub(super) early_data: Option<BoundEarlyData>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundEarlyData {
    pub(crate) maximum: u32,
    pub(crate) suite: record::CipherSuite,
    pub(crate) alpn: Option<protocols::AlpnId>,
}

#[derive(Clone, Copy)]
pub(crate) struct Offer<'a> {
    pub(crate) identity: &'a [u8],
    pub(crate) obfuscated_ticket_age: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct TicketTiming {
    pub(crate) lifetime_secs: u32,
    pub(crate) age_add: u32,
    pub(crate) received_at_ms: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct IssuedProfile {
    pub(crate) suite: record::CipherSuite,
    pub(crate) max_early_data: Option<u32>,
    pub(crate) alpn: Option<protocols::AlpnId>,
}

pub(crate) struct Issued<'a> {
    pub(crate) origin: super::Template,
    pub(crate) psk: material::ResumptionPsk,
    pub(crate) ticket: &'a [u8],
    pub(crate) timing: TicketTiming,
    pub(crate) profile: IssuedProfile,
}

const _: () = assert!(mem::size_of::<BoundEarlyData>() == 8);
const _: () = assert!(mem::size_of::<Option<BoundEarlyData>>() == 8);
const _: () = assert!(mem::size_of::<Resumption>() <= 128);

impl Resumption {
    pub fn ticket(&self) -> &[u8] {
        self.active.ticket()
    }

    pub fn psk(&self) -> &material::ResumptionPsk {
        self.active.psk()
    }

    pub fn ticket_age_add(&self) -> u32 {
        self.active.ticket_age_add
    }

    pub fn received_at_ms(&self) -> u64 {
        self.active.received_at_ms
    }

    pub fn ticket_lifetime_secs(&self) -> u32 {
        self.active.ticket_lifetime_secs()
    }

    pub fn max_early_data(&self) -> Option<u32> {
        self.active.early_data.map(|authority| authority.maximum)
    }

    pub fn early_data_transport_mode(&self) -> Option<transport::Mode> {
        self.active.early_data.map(|_| self.origin.transport_mode())
    }

    pub fn early_data_cipher_suite(&self) -> Option<record::CipherSuite> {
        self.active.early_data.map(|authority| authority.suite)
    }

    pub fn early_data_alpn(&self) -> Option<&[u8]> {
        self.active
            .early_data
            .and_then(|authority| authority.alpn)
            .and_then(|alpn| self.origin.alpn(alpn))
    }

    pub(crate) fn from_issued(issued: Issued<'_>) -> Result<Self, super::Error> {
        let Issued {
            origin,
            psk,
            ticket,
            timing,
            profile,
        } = issued;
        Active::validate_ticket(ticket)?;
        let lifetime_ms = Active::lifetime_ms(timing.lifetime_secs)?;
        let early_data = profile
            .max_early_data
            .filter(|maximum| Active::valid_early_data(*maximum, origin.transport_mode()))
            .filter(|_| profile.suite.hash_alg() == psk::RESUMPTION_HASH)
            .map(|maximum| BoundEarlyData {
                maximum,
                suite: profile.suite,
                alpn: profile.alpn,
            });
        Ok(Self {
            active: Active {
                psk,
                ticket: ticket.to_vec(),
                ticket_age_add: timing.age_add,
                received_at_ms: timing.received_at_ms,
                lifetime_ms,
                early_data,
            },
            origin,
        })
    }

    pub(crate) fn into_parts(self) -> (super::Template, Active) {
        (self.origin, self.active)
    }
}

impl Active {
    pub(super) fn validate_ticket(ticket: &[u8]) -> Result<(), super::Error> {
        if ticket.is_empty() {
            return Err(super::Error::EmptyResumptionTicket);
        }
        if ticket.len() > u16::MAX as usize {
            return Err(super::Error::ResumptionTicketTooLong {
                len: ticket.len(),
                maximum: u16::MAX as usize,
            });
        }
        Ok(())
    }

    pub(super) fn lifetime_ms(ticket_lifetime_secs: u32) -> Result<num::NonZeroU32, super::Error> {
        if ticket_lifetime_secs == 0 || ticket_lifetime_secs > MAX_TICKET_LIFETIME_SECS {
            return Err(super::Error::InvalidResumptionLifetime);
        }
        ticket_lifetime_secs
            .checked_mul(1_000)
            .and_then(num::NonZeroU32::new)
            .ok_or(super::Error::InvalidResumptionLifetime)
    }

    pub(super) fn valid_early_data(maximum: u32, transport_mode: transport::Mode) -> bool {
        maximum != 0
            && match transport_mode {
                transport::Mode::Tls => maximum != u32::MAX,
                transport::Mode::Quic => maximum == u32::MAX,
            }
    }

    pub(crate) fn ticket(&self) -> &[u8] {
        &self.ticket
    }

    pub(crate) fn psk(&self) -> &material::ResumptionPsk {
        &self.psk
    }

    pub(crate) fn ticket_lifetime_secs(&self) -> u32 {
        self.lifetime_ms.get() / 1_000
    }

    pub(crate) fn obfuscated_ticket_age(&self, now_ms: u64) -> Option<u32> {
        let age = now_ms.checked_sub(self.received_at_ms)?;
        if age > u64::from(self.lifetime_ms.get()) {
            return None;
        }
        let age = u32::try_from(age).ok()?;
        Some(age.wrapping_add(self.ticket_age_add))
    }

    pub(crate) fn offer(&self, obfuscated_ticket_age: u32) -> Offer<'_> {
        Offer {
            identity: &self.ticket,
            obfuscated_ticket_age,
        }
    }

    pub(crate) fn encoding_offer(&self) -> Offer<'_> {
        Offer {
            identity: &self.ticket,
            obfuscated_ticket_age: self.ticket_age_add,
        }
    }

    pub(crate) fn early_data_offer(
        &self,
        offered_suites: &[record::CipherSuite],
    ) -> Option<BoundEarlyData> {
        self.early_data
            .filter(|authority| offered_suites.contains(&authority.suite))
    }
}

impl fmt::Debug for Resumption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Resumption")
            .field("psk", &"[redacted]")
            .field("ticket_len", &self.ticket().len())
            .field("ticket_age_add", &self.ticket_age_add())
            .field("received_at_ms", &self.received_at_ms())
            .field("ticket_lifetime_secs", &self.ticket_lifetime_secs())
            .field("max_early_data", &self.max_early_data())
            .field(
                "early_data_transport_mode",
                &self.early_data_transport_mode(),
            )
            .field("early_data_cipher_suite", &self.early_data_cipher_suite())
            .field("early_data_alpn", &self.early_data_alpn())
            .finish()
    }
}
