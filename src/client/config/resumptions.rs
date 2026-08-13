use crate::crypto::material;
use crate::transport;
use crate::wire::protocols;
use crate::wire::record;
use alloc::vec;
use core::{mem, num};

pub(in crate::client) const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

pub(in crate::client) struct Active {
    pub(super) psk: material::ResumptionPsk,
    pub(super) ticket: vec::Vec<u8>,
    pub(super) ticket_age_add: u32,
    pub(super) received_at_ms: u64,
    pub(super) lifetime_ms: num::NonZeroU32,
    pub(super) early_data: Option<BoundEarlyData>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::client) struct BoundEarlyData {
    pub(in crate::client) maximum: u32,
    pub(in crate::client) suite: record::CipherSuite,
    pub(in crate::client) alpn: Option<protocols::AlpnId>,
}

#[derive(Clone, Copy)]
pub(in crate::client) struct Offer<'a> {
    pub(in crate::client) identity: &'a [u8],
    pub(in crate::client) obfuscated_ticket_age: u32,
}

#[derive(Clone, Copy)]
pub(in crate::client) struct TicketTiming {
    pub(in crate::client) lifetime_secs: u32,
    pub(in crate::client) age_add: u32,
    pub(in crate::client) received_at_ms: u64,
}

#[derive(Clone, Copy)]
pub(in crate::client) struct IssuedProfile {
    pub(in crate::client) suite: record::CipherSuite,
    pub(in crate::client) max_early_data: Option<u32>,
    pub(in crate::client) alpn: Option<protocols::AlpnId>,
}

pub(super) struct Issued<'a> {
    pub(super) origin: super::Template,
    pub(super) psk: material::ResumptionPsk,
    pub(super) ticket: &'a [u8],
    pub(super) timing: TicketTiming,
    pub(super) profile: IssuedProfile,
}

const _: () = assert!(mem::size_of::<BoundEarlyData>() == 8);
const _: () = assert!(mem::size_of::<Option<BoundEarlyData>>() == 8);

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

    pub(in crate::client) fn ticket(&self) -> &[u8] {
        &self.ticket
    }

    pub(in crate::client) fn psk(&self) -> &material::ResumptionPsk {
        &self.psk
    }

    pub(in crate::client) fn ticket_lifetime_secs(&self) -> u32 {
        self.lifetime_ms.get() / 1_000
    }

    pub(in crate::client) fn obfuscated_ticket_age(&self, now_ms: u64) -> Option<u32> {
        let age = now_ms.checked_sub(self.received_at_ms)?;
        if age > u64::from(self.lifetime_ms.get()) {
            return None;
        }
        let age = u32::try_from(age).ok()?;
        Some(age.wrapping_add(self.ticket_age_add))
    }

    pub(in crate::client) fn offer(&self, obfuscated_ticket_age: u32) -> Offer<'_> {
        Offer {
            identity: &self.ticket,
            obfuscated_ticket_age,
        }
    }

    pub(in crate::client) fn encoding_offer(&self) -> Offer<'_> {
        Offer {
            identity: &self.ticket,
            obfuscated_ticket_age: self.ticket_age_add,
        }
    }

    pub(in crate::client) fn early_data_offer(
        &self,
        offered_suites: &[record::CipherSuite],
    ) -> Option<BoundEarlyData> {
        self.early_data
            .filter(|authority| offered_suites.contains(&authority.suite))
    }
}
