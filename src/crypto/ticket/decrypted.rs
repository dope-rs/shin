use crate::crypto::material;
use crate::crypto::ticket;
use crate::memory::threadbound;
use crate::wire::record;
use core::fmt;
use o3::collections::fixed::array;

#[derive(PartialEq, Eq)]
pub struct Decrypted {
    pub psk: material::ResumptionPsk,
    pub age_add: u32,
    pub issued_at_ms: u64,
    pub suite: record::CipherSuite,
    pub alpn: array::CopyInline<u8, { ticket::MAX_ALPN_LEN }>,
    pub context: ticket::Context,
    pub(super) _thread: threadbound::ThreadBound,
}

impl fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decrypted")
            .field("psk", &"[redacted]")
            .field("age_add", &self.age_add)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("suite", &self.suite)
            .field("alpn", &self.alpn)
            .field("context", &self.context)
            .finish()
    }
}
