use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ops::Range;

use crate::aead::{AeadError, AeadKey};
use crate::hash::HashAlg;
use crate::kdf::HkdfError;
use crate::schedule::TrafficKeys;
use crate::uninit::raw::{UninitWriter, VecUninitExt};

pub const PROTOCOL_VERSION: u16 = 0x0303;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    ChaCha20Poly1305Sha256,
    Aes256GcmSha384,
}

impl CipherSuite {
    /// Server preference order (AES-128 first keeps embedders that hardcode it
    /// interoperable).
    pub const SUPPORTED: [CipherSuite; 3] = [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::ChaCha20Poly1305Sha256,
        CipherSuite::Aes256GcmSha384,
    ];

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
            Self::Aes256GcmSha384 => 0x1302,
        }
    }

    pub fn hash_alg(self) -> HashAlg {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => HashAlg::Sha256,
            Self::Aes256GcmSha384 => HashAlg::Sha384,
        }
    }
}

fn aead_for_suite(secret: &[u8], suite: CipherSuite) -> Result<AeadKey, RecordKeyError> {
    let alg = suite.hash_alg();
    match suite {
        CipherSuite::Aes128GcmSha256 => {
            let keys = TrafficKeys::<16>::derive(alg, secret)?;
            Ok(AeadKey::aes_128_gcm(&keys.key, keys.iv)?)
        }
        CipherSuite::ChaCha20Poly1305Sha256 => {
            let keys = TrafficKeys::<32>::derive(alg, secret)?;
            Ok(AeadKey::chacha20_poly1305(&keys.key, keys.iv)?)
        }
        CipherSuite::Aes256GcmSha384 => {
            let keys = TrafficKeys::<32>::derive(alg, secret)?;
            Ok(AeadKey::aes_256_gcm(&keys.key, keys.iv)?)
        }
    }
}

pub const MAX_PLAINTEXT_BODY: usize = 1 << 14;

pub const MAX_CIPHERTEXT_BODY: usize = (1 << 14) + 256;

pub const HEADER_LEN: usize = 5;
pub const AEAD_TAG_LEN: usize = 16;

/// Records sealable under one AES-128-GCM key before a KeyUpdate is due (RFC 8446
/// §5.5): 2^23, matching rustls.
pub const AEAD_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn from_u8(b: u8) -> Result<Self, RecordError> {
        Ok(match b {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => return Err(RecordError::BadContentType),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    BadContentType,
    BodyTooLarge,
    RecordOverflow,
    OpenFailed,
    SealFailed,
    AllZeroInner,
    NotCipherTextOuter,
    SeqExhausted,
    /// A decrypted record carried an inner ChangeCipherSpec, which RFC 8446 §5
    /// forbids; the connection must abort with unexpected_message.
    UnexpectedChangeCipherSpec,
    /// A prior open failed authentication; the opener rejects all further use
    /// (RFC 8446 §5.2 — a failed open is fatal).
    Poisoned,
    /// The destination buffer was smaller than the sealed record.
    BufferTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKeyError {
    Aead(AeadError),
    Kdf(HkdfError),
}

impl From<AeadError> for RecordKeyError {
    fn from(error: AeadError) -> Self {
        Self::Aead(error)
    }
}

impl From<HkdfError> for RecordKeyError {
    fn from(error: HkdfError) -> Self {
        Self::Kdf(error)
    }
}

impl From<AeadError> for RecordError {
    fn from(_: AeadError) -> Self {
        Self::SealFailed
    }
}

#[derive(Debug, Clone)]
pub struct PlaintextRecord<'a> {
    pub content_type: ContentType,
    pub body: &'a [u8],
}

impl<'a> PlaintextRecord<'a> {
    /// Encodes a plaintext record into a fresh buffer.
    ///
    /// ```
    /// use shin::record::{ContentType, HEADER_LEN, PlaintextRecord};
    /// let wire = PlaintextRecord::encode(ContentType::Alert, &[1, 2]).unwrap();
    /// assert_eq!(wire.len(), HEADER_LEN + 2);
    /// ```
    pub fn encode(content_type: ContentType, body: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        Self::encode_into(content_type, body, &mut out)?;
        Ok(out)
    }

    /// Appends a plaintext record to `out` without a fresh allocation.
    ///
    /// ```
    /// use shin::record::{ContentType, HEADER_LEN, PlaintextRecord};
    /// let mut wire = Vec::new();
    /// PlaintextRecord::encode_into(ContentType::Alert, &[1, 2], &mut wire).unwrap();
    /// assert_eq!(wire.len(), HEADER_LEN + 2);
    /// ```
    pub fn encode_into(
        content_type: ContentType,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        let total = plaintext_record_len(body)?;
        out.extend_uninit(total, |out| write_plaintext(content_type, body, out));
        Ok(())
    }

    /// Encodes a plaintext record into `out`, returning its length. No allocation.
    ///
    /// ```
    /// use shin::record::{ContentType, HEADER_LEN, PlaintextRecord};
    /// let mut wire = [0u8; 32];
    /// let n = PlaintextRecord::encode_into_slice(ContentType::Alert, &[1, 2], &mut wire).unwrap();
    /// assert_eq!(n, HEADER_LEN + 2);
    /// ```
    pub fn encode_into_slice(
        content_type: ContentType,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, RecordError> {
        let total = plaintext_record_len(body)?;
        let dst = out.get_mut(..total).ok_or(RecordError::BufferTooSmall)?;
        let mut out = UninitWriter::from_mut_slice(dst);
        write_plaintext(content_type, body, &mut out);
        Ok(total)
    }

    pub fn encode_into_uninit<'b>(
        content_type: ContentType,
        body: &[u8],
        out: &'b mut [MaybeUninit<u8>],
    ) -> Result<&'b mut [u8], RecordError> {
        let total = plaintext_record_len(body)?;
        let dst = out.get_mut(..total).ok_or(RecordError::BufferTooSmall)?;
        let mut out = UninitWriter::new(dst);
        write_plaintext(content_type, body, &mut out);
        Ok(out.into_initialized())
    }

    pub fn parse(input: &'a [u8]) -> Result<Option<(Self, usize)>, RecordError> {
        if input.len() < HEADER_LEN {
            return Ok(None);
        }
        let content_type = ContentType::from_u8(input[0])?;
        let body_len = u16::from_be_bytes([input[3], input[4]]) as usize;
        if body_len > MAX_PLAINTEXT_BODY {
            return Err(RecordError::BodyTooLarge);
        }
        let total = HEADER_LEN + body_len;
        if input.len() < total {
            return Ok(None);
        }
        Ok(Some((
            Self {
                content_type,
                body: &input[HEADER_LEN..total],
            },
            total,
        )))
    }
}

pub struct Sealer {
    aead: AeadKey,
    seq: u64,
}

impl Sealer {
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, RecordKeyError> {
        Self::with_suite(secret, CipherSuite::Aes128GcmSha256)
    }

    pub fn with_suite(secret: &[u8], suite: CipherSuite) -> Result<Self, RecordKeyError> {
        Ok(Self {
            aead: aead_for_suite(secret, suite)?,
            seq: 0,
        })
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// True once a KeyUpdate is due (see [`AEAD_CONFIDENTIALITY_LIMIT`]).
    pub fn needs_key_update(&self) -> bool {
        self.seq >= AEAD_CONFIDENTIALITY_LIMIT
    }

    pub fn seal(&mut self, inner_type: ContentType, body: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        self.seal_into(inner_type, body, &mut out)?;
        Ok(out)
    }

    /// Appends a sealed record to `out` without a per-record allocation.
    ///
    /// ```
    /// use shin::record::{ContentType, Sealer};
    /// let mut sealer = Sealer::from_secret(&[0u8; 32]).unwrap();
    /// let mut staged = Vec::new();
    /// sealer.seal_into(ContentType::ApplicationData, b"a", &mut staged).unwrap();
    /// sealer.seal_into(ContentType::ApplicationData, b"b", &mut staged).unwrap();
    /// ```
    pub fn seal_into(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        let total = sealed_record_len(body)?;
        self.check_seq()?;
        out.try_extend_uninit(total, |out| self.seal_record(inner_type, body, out))?;
        Ok(())
    }

    /// Seals one record into `out`, returning its length. No allocation.
    ///
    /// ```
    /// use shin::record::{AEAD_TAG_LEN, ContentType, HEADER_LEN, Sealer};
    /// let mut sealer = Sealer::from_secret(&[0u8; 32]).unwrap();
    /// let mut wire = [0u8; 64];
    /// let n = sealer
    ///     .seal_into_slice(ContentType::ApplicationData, b"hi", &mut wire)
    ///     .unwrap();
    /// assert_eq!(n, HEADER_LEN + b"hi".len() + 1 + AEAD_TAG_LEN);
    /// ```
    pub fn seal_into_slice(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, RecordError> {
        let total = sealed_record_len(body)?;
        let dst = out.get_mut(..total).ok_or(RecordError::BufferTooSmall)?;
        self.check_seq()?;
        let mut out = UninitWriter::from_mut_slice(dst);
        self.seal_record(inner_type, body, &mut out)?;
        Ok(total)
    }

    pub fn seal_into_uninit<'b>(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &'b mut [MaybeUninit<u8>],
    ) -> Result<&'b mut [u8], RecordError> {
        let total = sealed_record_len(body)?;
        let dst = out.get_mut(..total).ok_or(RecordError::BufferTooSmall)?;
        self.check_seq()?;
        let mut out = UninitWriter::new(dst);
        self.seal_record(inner_type, body, &mut out)?;
        Ok(out.into_initialized())
    }

    fn check_seq(&self) -> Result<(), RecordError> {
        if self.seq == u64::MAX {
            return Err(RecordError::SeqExhausted);
        }
        Ok(())
    }

    fn seal_record(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut UninitWriter<'_>,
    ) -> Result<(), RecordError> {
        debug_assert!(self.seq != u64::MAX);
        let seq = self.seq;
        self.seq += 1;
        let outer_body_len = body.len() + 1 + AEAD_TAG_LEN;

        write_header(ContentType::ApplicationData, outer_body_len as u16, out);
        out.extend_from_slice(body);
        out.push(inner_type as u8);

        let (header, plaintext) = out.initialized_mut().split_at_mut(HEADER_LEN);
        let tag = self.aead.seal_detached(seq, header, plaintext)?;
        out.extend_from_slice(&tag);
        Ok(())
    }
}

fn check_body_len(body: &[u8]) -> Result<(), RecordError> {
    if body.len() > MAX_PLAINTEXT_BODY {
        return Err(RecordError::BodyTooLarge);
    }
    Ok(())
}

fn sealed_record_len(body: &[u8]) -> Result<usize, RecordError> {
    check_body_len(body)?;
    Ok(HEADER_LEN + body.len() + 1 + AEAD_TAG_LEN)
}

fn plaintext_record_len(body: &[u8]) -> Result<usize, RecordError> {
    check_body_len(body)?;
    Ok(HEADER_LEN + body.len())
}

fn write_header(content_type: ContentType, body_len: u16, out: &mut UninitWriter<'_>) {
    out.push(content_type as u8);
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(&body_len.to_be_bytes());
}

fn write_plaintext(content_type: ContentType, body: &[u8], out: &mut UninitWriter<'_>) {
    write_header(content_type, body.len() as u16, out);
    out.extend_from_slice(body);
}

pub struct Opener {
    aead: AeadKey,
    seq: u64,
    poisoned: bool,
}

impl Opener {
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, RecordKeyError> {
        Self::with_suite(secret, CipherSuite::Aes128GcmSha256)
    }

    pub fn with_suite(secret: &[u8], suite: CipherSuite) -> Result<Self, RecordKeyError> {
        Ok(Self {
            aead: aead_for_suite(secret, suite)?,
            seq: 0,
            poisoned: false,
        })
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// True once a KeyUpdate is due (see [`AEAD_CONFIDENTIALITY_LIMIT`]).
    pub fn needs_key_update(&self) -> bool {
        self.seq >= AEAD_CONFIDENTIALITY_LIMIT
    }

    pub fn open(
        &mut self,
        input: &mut [u8],
    ) -> Result<Option<(ContentType, Range<usize>, usize)>, RecordError> {
        if self.poisoned {
            return Err(RecordError::Poisoned);
        }
        if input.len() < HEADER_LEN {
            return Ok(None);
        }
        let outer_type = input[0];
        let body_len = u16::from_be_bytes([input[3], input[4]]) as usize;
        if body_len > MAX_CIPHERTEXT_BODY {
            return Err(RecordError::BodyTooLarge);
        }
        let total = HEADER_LEN + body_len;
        if input.len() < total {
            return Ok(None);
        }
        if outer_type != ContentType::ApplicationData as u8 {
            return Err(RecordError::NotCipherTextOuter);
        }
        if self.seq == u64::MAX {
            return Err(RecordError::SeqExhausted);
        }

        let mut aad = [0u8; HEADER_LEN];
        aad.copy_from_slice(&input[..HEADER_LEN]);

        let seq = self.seq;

        let body = &mut input[HEADER_LEN..total];
        let plaintext_len = match self.aead.open(seq, &aad, body) {
            Ok(plain) => plain.len(),
            Err(_) => {
                self.poisoned = true;
                return Err(RecordError::OpenFailed);
            }
        };

        self.seq += 1;

        let inner_slice = &input[HEADER_LEN..HEADER_LEN + plaintext_len];
        let content_len = inner_slice
            .iter()
            .rposition(|&b| b != 0)
            .ok_or(RecordError::AllZeroInner)?;
        if content_len > MAX_PLAINTEXT_BODY {
            return Err(RecordError::RecordOverflow);
        }
        let inner_type = ContentType::from_u8(inner_slice[content_len])?;
        if inner_type == ContentType::ChangeCipherSpec {
            return Err(RecordError::UnexpectedChangeCipherSpec);
        }

        let plaintext_start = HEADER_LEN;
        let plaintext_end = HEADER_LEN + content_len;
        Ok(Some((inner_type, plaintext_start..plaintext_end, total)))
    }
}
