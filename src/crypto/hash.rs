use crate::memory::threadbound;
use core::fmt;
use zeroize::Zeroize as _;

use ring::digest;
use ring::hmac;

pub const SHA256_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub const SHA384_LEN: usize = digest::SHA384_OUTPUT_LEN;

/// Largest hash output handled (SHA-384). Fixed-size secret buffers use this so
/// one inline type spans both SHA-256 (32) and SHA-384 (48) suites.
pub const MAX_LEN: usize = digest::SHA384_OUTPUT_LEN;

/// A byte string was too long to fit in a hash or secret value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthError {
    pub actual: usize,
    pub maximum: usize,
}

impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hash value is {} bytes, maximum is {}",
            self.actual, self.maximum
        )
    }
}

/// The transcript / key-schedule hash a cipher suite ties to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha384,
}

impl Algorithm {
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => digest::SHA256_OUTPUT_LEN,
            Self::Sha384 => digest::SHA384_OUTPUT_LEN,
        }
    }

    pub(crate) fn ring(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
        }
    }

    pub(crate) fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
        }
    }

    pub fn hash(self, data: &[u8]) -> Digest {
        Digest::from_bounded_slice(digest::digest(self.ring(), data).as_ref())
    }
}

/// A transcript operation was inconsistent with the negotiated hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptError {
    /// The transcript was already committed to a different algorithm.
    AlgorithmMismatch {
        selected: Algorithm,
        requested: Algorithm,
    },
    /// An HRR `message_hash` digest did not have the selected algorithm's size.
    DigestLengthMismatch {
        algorithm: Algorithm,
        actual: usize,
        expected: usize,
    },
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlgorithmMismatch {
                selected,
                requested,
            } => write!(
                formatter,
                "transcript uses {selected:?}, not requested {requested:?}"
            ),
            Self::DigestLengthMismatch {
                algorithm,
                actual,
                expected,
            } => write!(
                formatter,
                "{algorithm:?} transcript digest is {actual} bytes, expected {expected}"
            ),
        }
    }
}

/// A hash output / key-schedule secret of up to [`MAX_LEN`] bytes, carrying
/// its true length so SHA-256 and SHA-384 share one inline, heap-free type.
#[derive(Clone, Copy)]
pub struct Digest {
    bytes: [u8; MAX_LEN],
    len: usize,
    _thread: threadbound::ThreadBound,
}

impl Digest {
    /// Copies a checked, variable-length hash value.
    pub fn try_from_slice(s: &[u8]) -> Result<Self, LengthError> {
        if s.len() > MAX_LEN {
            return Err(LengthError {
                actual: s.len(),
                maximum: MAX_LEN,
            });
        }
        Ok(Self::from_bounded_slice(s))
    }

    pub(crate) fn from_bounded_slice(s: &[u8]) -> Self {
        debug_assert!(s.len() <= MAX_LEN);
        let mut bytes = [0u8; MAX_LEN];
        bytes[..s.len()].copy_from_slice(s);
        Self {
            bytes,
            len: s.len(),
            _thread: threadbound::ThreadBound::NEW,
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

impl TryFrom<&[u8]> for Digest {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Digest {}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest([redacted; {}])", self.len)
    }
}

/// Key-schedule secret of up to [`MAX_LEN`] bytes. Intentionally not `Copy`
/// (so secret bytes are never silently duplicated) and wiped on drop; [`Digest`]
/// stays `Copy` for public transcript hashes that need neither.
pub struct Secret {
    bytes: [u8; MAX_LEN],
    len: usize,
    _thread: threadbound::ThreadBound,
}

impl Secret {
    pub(crate) fn zeroed(len: usize) -> Result<Self, LengthError> {
        if len > MAX_LEN {
            return Err(LengthError {
                actual: len,
                maximum: MAX_LEN,
            });
        }
        Ok(Self {
            bytes: [0; MAX_LEN],
            len,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    /// Copies a checked, variable-length key-schedule secret.
    pub fn try_from_slice(s: &[u8]) -> Result<Self, LengthError> {
        if s.len() > MAX_LEN {
            return Err(LengthError {
                actual: s.len(),
                maximum: MAX_LEN,
            });
        }
        Ok(Self::from_bounded_slice(s))
    }

    pub(crate) fn from_bounded_slice(s: &[u8]) -> Self {
        debug_assert!(s.len() <= MAX_LEN);
        let mut bytes = [0u8; MAX_LEN];
        bytes[..s.len()].copy_from_slice(s);
        Self {
            bytes,
            len: s.len(),
            _thread: threadbound::ThreadBound::NEW,
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

impl TryFrom<&[u8]> for Secret {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret([redacted; {}])", self.len)
    }
}

#[derive(Clone, Copy)]
enum TranscriptState {
    Negotiating,
    Selected(Algorithm),
}

/// Running handshake transcript. Both hashes advance until [`select`](Self::select);
/// subsequent updates advance one context. Optional context presence encodes
/// the state without a separate tag or padding.
pub struct Transcript {
    sha256: Option<digest::Context>,
    sha384: Option<digest::Context>,
    _thread: threadbound::ThreadBound,
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            sha256: Some(digest::Context::new(&digest::SHA256)),
            sha384: Some(digest::Context::new(&digest::SHA384)),
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub(crate) fn fork(&self) -> Self {
        Self {
            sha256: self.sha256.clone(),
            sha384: self.sha384.clone(),
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    /// Commits to one hash. Repeating it is idempotent; selecting another
    /// algorithm is rejected instead of switching to a divergent transcript.
    pub fn select(&mut self, algorithm: Algorithm) -> Result<(), TranscriptError> {
        match self.state() {
            TranscriptState::Negotiating => {
                match algorithm {
                    Algorithm::Sha256 => self.sha384 = None,
                    Algorithm::Sha384 => self.sha256 = None,
                }
                Ok(())
            }
            TranscriptState::Selected(selected) if selected == algorithm => Ok(()),
            TranscriptState::Selected(selected) => Err(TranscriptError::AlgorithmMismatch {
                selected,
                requested: algorithm,
            }),
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        match self.state() {
            TranscriptState::Negotiating => {
                if let Some(context) = self.sha256.as_mut() {
                    context.update(msg);
                }
                if let Some(context) = self.sha384.as_mut() {
                    context.update(msg);
                }
            }
            TranscriptState::Selected(Algorithm::Sha256) => {
                if let Some(context) = self.sha256.as_mut() {
                    context.update(msg);
                }
            }
            TranscriptState::Selected(Algorithm::Sha384) => {
                if let Some(context) = self.sha384.as_mut() {
                    context.update(msg);
                }
            }
        }
    }

    pub fn hash(&self, algorithm: Algorithm) -> Result<Digest, TranscriptError> {
        if let TranscriptState::Selected(selected) = self.state()
            && selected != algorithm
        {
            return Err(TranscriptError::AlgorithmMismatch {
                selected,
                requested: algorithm,
            });
        }
        let context = match (algorithm, self.sha256.as_ref(), self.sha384.as_ref()) {
            (Algorithm::Sha256, Some(context), _) | (Algorithm::Sha384, _, Some(context)) => {
                context
            }
            _ => {
                return Err(TranscriptError::AlgorithmMismatch {
                    selected: algorithm,
                    requested: algorithm,
                });
            }
        };
        let digest = context.clone().finish();
        Ok(Digest::from_bounded_slice(digest.as_ref()))
    }

    pub fn hash_empty(alg: Algorithm) -> Digest {
        alg.hash(&[])
    }

    /// RFC 8446 §4.4.1: after a HelloRetryRequest the transcript restarts as
    /// `message_hash(ClientHello1)` (type 0xFE), then HRR and ClientHello2 follow.
    /// `client_hello1` is the digest of ClientHello1 under the negotiated hash.
    pub fn restart_with_message_hash(
        algorithm: Algorithm,
        client_hello1: &Digest,
    ) -> Result<Self, TranscriptError> {
        if client_hello1.len() != algorithm.output_len() {
            return Err(TranscriptError::DigestLengthMismatch {
                algorithm,
                actual: client_hello1.len(),
                expected: algorithm.output_len(),
            });
        }
        let mut t = Self {
            sha256: (algorithm == Algorithm::Sha256).then(|| digest::Context::new(&digest::SHA256)),
            sha384: (algorithm == Algorithm::Sha384).then(|| digest::Context::new(&digest::SHA384)),
            _thread: threadbound::ThreadBound::NEW,
        };
        let mut synthetic = [0u8; 4 + MAX_LEN];
        synthetic[..4].copy_from_slice(&[0xFE, 0x00, 0x00, client_hello1.len() as u8]);
        synthetic[4..4 + client_hello1.len()].copy_from_slice(client_hello1.as_slice());
        t.update(&synthetic[..4 + client_hello1.len()]);
        Ok(t)
    }

    fn state(&self) -> TranscriptState {
        if self.sha256.is_some() && self.sha384.is_some() {
            TranscriptState::Negotiating
        } else if self.sha256.is_some() {
            TranscriptState::Selected(Algorithm::Sha256)
        } else {
            TranscriptState::Selected(Algorithm::Sha384)
        }
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
