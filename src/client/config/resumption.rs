use crate::crypto::material;
use crate::memory::threadbound;
use crate::transport;
use alloc::vec;
use core::fmt;

/// ```compile_fail
/// use shin::client::config::Resumption;
/// fn assert_send<T: Send>() {}
/// assert_send::<Resumption>();
/// ```
pub struct Resumption {
    pub psk: material::ResumptionPsk,
    pub ticket: vec::Vec<u8>,
    pub ticket_age_add: u32,
    pub age_millis: u32,
    early_data: Option<EarlyDataEntitlement>,
    _thread: threadbound::ThreadBound,
}

#[derive(Clone, Copy)]
struct EarlyDataEntitlement {
    max_early_data: u32,
    transport_mode: transport::Mode,
}

impl Resumption {
    /// Constructs a resumption ticket without 0-RTT authority.
    pub fn new(
        psk: impl Into<material::ResumptionPsk>,
        ticket: vec::Vec<u8>,
        ticket_age_add: u32,
        age_millis: u32,
    ) -> Self {
        Self {
            psk: psk.into(),
            ticket,
            ticket_age_add,
            age_millis,
            early_data: None,
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    /// Constructs a ticket with explicit 0-RTT transport authority.
    pub fn new_with_early_data(
        psk: impl Into<material::ResumptionPsk>,
        ticket: vec::Vec<u8>,
        ticket_age_add: u32,
        age_millis: u32,
        max_early_data: u32,
        transport_mode: transport::Mode,
    ) -> Self {
        Self {
            psk: psk.into(),
            ticket,
            ticket_age_add,
            age_millis,
            early_data: Some(EarlyDataEntitlement {
                max_early_data,
                transport_mode,
            }),
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub fn max_early_data(&self) -> Option<u32> {
        self.early_data
            .map(|entitlement| entitlement.max_early_data)
    }

    pub fn early_data_transport_mode(&self) -> Option<transport::Mode> {
        self.early_data
            .map(|entitlement| entitlement.transport_mode)
    }

    pub(crate) fn permits_early_data(&self, transport_mode: transport::Mode) -> bool {
        self.early_data.is_some_and(|entitlement| {
            entitlement.transport_mode == transport_mode
                && entitlement.max_early_data != 0
                && match transport_mode {
                    transport::Mode::Tls => entitlement.max_early_data != u32::MAX,
                    transport::Mode::Quic => entitlement.max_early_data == u32::MAX,
                }
        })
    }
}

impl fmt::Debug for Resumption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Resumption")
            .field("psk", &"[redacted]")
            .field("ticket_len", &self.ticket.len())
            .field("ticket_age_add", &self.ticket_age_add)
            .field("age_millis", &self.age_millis)
            .field("max_early_data", &self.max_early_data())
            .field(
                "early_data_transport_mode",
                &self.early_data_transport_mode(),
            )
            .finish()
    }
}
