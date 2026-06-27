use ring::digest::{Context, SHA256, SHA256_OUTPUT_LEN};

pub const HASH_LEN: usize = SHA256_OUTPUT_LEN;

pub fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    let d = ring::digest::digest(&SHA256, data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

#[derive(Clone)]
pub struct Transcript {
    inner: Context,
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            inner: Context::new(&SHA256),
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.inner.update(msg);
    }

    pub fn hash(&self) -> [u8; HASH_LEN] {
        let d = self.inner.clone().finish();
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(d.as_ref());
        out
    }

    pub fn hash_empty() -> [u8; HASH_LEN] {
        sha256(&[])
    }

    /// RFC 8446 §4.4.1: after a HelloRetryRequest the transcript restarts as
    /// `message_hash(ClientHello1)` (type 0xFE), then HRR and ClientHello2 follow.
    pub fn restart_with_message_hash(client_hello1: [u8; HASH_LEN]) -> Self {
        let mut t = Self::new();
        let mut synthetic = alloc::vec![0xFE, 0x00, 0x00, HASH_LEN as u8];
        synthetic.extend_from_slice(&client_hello1);
        t.update(&synthetic);
        t
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
