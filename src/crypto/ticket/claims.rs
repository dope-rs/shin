use crate::crypto::material;
use crate::crypto::ticket;

/// Values authenticated inside an issued ticket.
pub struct Claims<'a> {
    pub psk: &'a material::ResumptionPsk,
    pub age_add: u32,
    pub issued_at_ms: u64,
    pub suite: u16,
    pub alpn: &'a [u8],
    pub context: ticket::Context,
}
