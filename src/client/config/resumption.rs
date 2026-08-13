use crate::client::config;
use crate::client::config::resumptions;
use crate::crypto::material;
use crate::transport;
use crate::wire::{psk, record};
use core::{fmt, mem};

/// A single-use live ticket bound to the endpoint that issued it.
///
/// Persisted material must cross [`config::Template::restore`], so unresolved ALPN
/// bytes can never reach the handshake state.
///
/// ```compile_fail
/// use shin::client::config::Resumption;
/// fn assert_send<T: Send>() {}
/// assert_send::<Resumption>();
/// ```
pub struct Resumption {
    active: resumptions::Active,
    origin: config::Template,
}

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

    pub(super) fn from_issued(issued: resumptions::Issued<'_>) -> Result<Self, config::Error> {
        let resumptions::Issued {
            origin,
            psk,
            ticket,
            timing,
            profile,
        } = issued;
        resumptions::Active::validate_ticket(ticket)?;
        let lifetime_ms = resumptions::Active::lifetime_ms(timing.lifetime_secs)?;
        let early_data = profile
            .max_early_data
            .filter(|maximum| {
                resumptions::Active::valid_early_data(*maximum, origin.transport_mode())
            })
            .filter(|_| profile.suite.hash_alg() == psk::RESUMPTION_HASH)
            .map(|maximum| resumptions::BoundEarlyData {
                maximum,
                suite: profile.suite,
                alpn: profile.alpn,
            });
        Ok(Self {
            active: resumptions::Active {
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

    pub(super) fn into_parts(self) -> (config::Template, resumptions::Active) {
        (self.origin, self.active)
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

const _: () = assert!(mem::size_of::<Resumption>() <= 128);
