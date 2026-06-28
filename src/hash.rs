use ring::digest::{Context, SHA256, SHA256_OUTPUT_LEN, SHA384, SHA384_OUTPUT_LEN};

pub const HASH_LEN: usize = SHA256_OUTPUT_LEN;

/// Largest hash output handled (SHA-384). Fixed-size secret buffers use this so
/// one inline type spans both SHA-256 (32) and SHA-384 (48) suites.
pub const MAX_HASH_LEN: usize = SHA384_OUTPUT_LEN;

pub fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    let d = ring::digest::digest(&SHA256, data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// The transcript / key-schedule hash a cipher suite ties to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => SHA256_OUTPUT_LEN,
            Self::Sha384 => SHA384_OUTPUT_LEN,
        }
    }

    pub(crate) fn ring(self) -> &'static ring::digest::Algorithm {
        match self {
            Self::Sha256 => &SHA256,
            Self::Sha384 => &SHA384,
        }
    }

    pub fn hash(self, data: &[u8]) -> Digest {
        Digest::from_slice(ring::digest::digest(self.ring(), data).as_ref())
    }
}

/// A hash output / key-schedule secret of up to [`MAX_HASH_LEN`] bytes, carrying
/// its true length so SHA-256 and SHA-384 share one inline, heap-free type.
#[derive(Clone, Copy)]
pub struct Digest {
    bytes: [u8; MAX_HASH_LEN],
    len: usize,
}

impl Digest {
    pub fn from_slice(s: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_HASH_LEN];
        bytes[..s.len()].copy_from_slice(s);
        Self {
            bytes,
            len: s.len(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Digest {}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest([redacted; {}])", self.len)
    }
}

/// Key-schedule secret of up to [`MAX_HASH_LEN`] bytes. Intentionally not `Copy`
/// (so secret bytes are never silently duplicated) and wiped on drop; [`Digest`]
/// stays `Copy` for public transcript hashes that need neither.
pub struct Secret {
    bytes: [u8; MAX_HASH_LEN],
    len: usize,
}

impl Secret {
    pub fn from_slice(s: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_HASH_LEN];
        bytes[..s.len()].copy_from_slice(s);
        Self {
            bytes,
            len: s.len(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn to_digest(&self) -> Digest {
        Digest::from_slice(self.as_slice())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        crate::schedule::zeroize(&mut self.bytes);
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret([redacted; {}])", self.len)
    }
}

/// Running handshake transcript. The hash algorithm is fixed only once the
/// cipher suite is negotiated, so both SHA-256 and SHA-384 are advanced in
/// lockstep and the chosen one is read with [`hash`](Self::hash).
#[derive(Clone)]
pub struct Transcript {
    sha256: Context,
    sha384: Context,
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            sha256: Context::new(&SHA256),
            sha384: Context::new(&SHA384),
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.sha256.update(msg);
        self.sha384.update(msg);
    }

    pub fn hash(&self, alg: HashAlg) -> Digest {
        let d = match alg {
            HashAlg::Sha256 => self.sha256.clone().finish(),
            HashAlg::Sha384 => self.sha384.clone().finish(),
        };
        Digest::from_slice(d.as_ref())
    }

    pub fn hash_empty(alg: HashAlg) -> Digest {
        alg.hash(&[])
    }

    /// RFC 8446 §4.4.1: after a HelloRetryRequest the transcript restarts as
    /// `message_hash(ClientHello1)` (type 0xFE), then HRR and ClientHello2 follow.
    /// `client_hello1` is the digest of ClientHello1 under the negotiated hash.
    pub fn restart_with_message_hash(client_hello1: &Digest) -> Self {
        let mut t = Self::new();
        let mut synthetic = alloc::vec![0xFE, 0x00, 0x00, client_hello1.len() as u8];
        synthetic.extend_from_slice(client_hello1.as_slice());
        t.update(&synthetic);
        t
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
