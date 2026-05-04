use ring::digest::{Context, SHA256, SHA256_OUTPUT_LEN};

pub const HASH_LEN: usize = SHA256_OUTPUT_LEN;

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
        Self::new().hash()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
