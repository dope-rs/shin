use crate::crypto::material;
use crate::crypto::ticket;
use crate::wire::record;

/// Values authenticated inside an issued ticket.
pub struct Claims<'a> {
    pub psk: &'a material::ResumptionPsk,
    pub age_add: u32,
    pub issued_at_ms: u64,
    pub suite: record::CipherSuite,
    pub alpn: &'a [u8],
    pub context: ticket::Context,
}
