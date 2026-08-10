use crate::crypto::aead;
use crate::crypto::hash;
use crate::crypto::kdf;
use alloc::vec;
use core::ops;
use o3::buffer::write;

mod ciphertext;
mod key;
mod plaintext;

pub use plaintext::Plaintext;

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

    pub fn wire_id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
            Self::Aes256GcmSha384 => 0x1302,
        }
    }

    pub fn hash_alg(self) -> hash::Algorithm {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => hash::Algorithm::Sha256,
            Self::Aes256GcmSha384 => hash::Algorithm::Sha384,
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
    pub fn from_u8(b: u8) -> Result<Self, Error> {
        Ok(match b {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => return Err(Error::BadContentType),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadContentType,
    BodyTooLarge,
    RecordOverflow,
    OpenFailed,
    SealFailed,
    AllZeroInner,
    NotCipherTextOuter,
    BadLegacyVersion,
    SeqExhausted,
    /// The AEAD usage limit was reached; install a fresh traffic key before
    /// processing another record.
    KeyLimitReached,
    /// A decrypted record carried an inner ChangeCipherSpec, which RFC 8446 §5
    /// forbids; the connection must abort with unexpected_message.
    UnexpectedChangeCipherSpec,
    /// A prior open failed authentication; the opener rejects all further use
    /// (RFC 8446 §5.2 — a failed open is fatal).
    Poisoned,
    /// The destination buffer was smaller than the sealed record.
    BufferTooSmall,
    /// Vectored body parts did not add up to the declared body length.
    LengthMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Aead(aead::Error),
    Kdf(kdf::HkdfError),
}

impl From<aead::Error> for KeyError {
    fn from(error: aead::Error) -> Self {
        Self::Aead(error)
    }
}

impl From<kdf::HkdfError> for KeyError {
    fn from(error: kdf::HkdfError) -> Self {
        Self::Kdf(error)
    }
}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Self::SealFailed
    }
}

pub struct Sealer {
    aead: key::Key,
    seq: u64,
}

impl Sealer {
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, KeyError> {
        Self::with_suite(secret, CipherSuite::Aes128GcmSha256)
    }

    pub fn with_suite(secret: &[u8], suite: CipherSuite) -> Result<Self, KeyError> {
        Ok(Self {
            aead: key::Key::derive(secret, suite)?,
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

    pub fn seal(&mut self, inner_type: ContentType, body: &[u8]) -> Result<vec::Vec<u8>, Error> {
        let mut out = vec::Vec::new();
        self.seal_into(inner_type, body, &mut out)?;
        Ok(out)
    }

    /// Appends a sealed record to `out` without a per-record allocation.
    #[doc = include_str!("docs/seal_into.md")]
    pub fn seal_into(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut vec::Vec<u8>,
    ) -> Result<(), Error> {
        let total = sealed_len(body)?;
        self.check_seq()?;
        let start = out.len();
        out.reserve(total);
        write_header_vec(
            ContentType::ApplicationData,
            (body.len() + 1 + AEAD_TAG_LEN) as u16,
            out,
        );
        out.extend_from_slice(body);
        out.push(inner_type as u8);
        let result = self
            .seal_plaintext(&mut out[start..])
            .map(|tag| out.extend_from_slice(&tag));
        if let Err(error) = result {
            out.truncate(start);
            return Err(error);
        }
        Ok(())
    }

    /// Seals one record into `out`, returning its length. No allocation.
    #[doc = include_str!("docs/seal_into_slice.md")]
    pub fn seal_into_slice(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let total = sealed_len(body)?;
        let dst = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;
        self.check_seq()?;
        self.seal_record(inner_type, body, dst)?;
        Ok(total)
    }

    /// Appends one sealed record directly to an O3 writer.
    pub fn seal_to(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut write::SpareWriter<'_>,
    ) -> Result<(), Error> {
        let total = sealed_len(body)?;
        self.check_seq()?;
        let mut record = transaction(out, total)?;
        self.seal_record_txn(inner_type, body, &mut record)?;
        commit(record)
    }

    /// Seals `body_len` bytes from `parts` directly into caller storage.
    pub fn seal_parts_to<'p>(
        &mut self,
        inner_type: ContentType,
        body_len: usize,
        parts: impl IntoIterator<Item = &'p [u8]>,
        out: &mut write::SpareWriter<'_>,
    ) -> Result<(), Error> {
        let total = sealed_len_for(body_len)?;
        self.check_seq()?;
        let mut record = transaction(out, total)?;
        write_header_txn(
            ContentType::ApplicationData,
            (body_len + 1 + AEAD_TAG_LEN) as u16,
            &mut record,
        )?;
        let mut remaining = body_len;
        for part in parts {
            if part.len() > remaining {
                return Err(Error::LengthMismatch);
            }
            write_txn(&mut record, part)?;
            remaining -= part.len();
        }
        if remaining != 0 {
            return Err(Error::LengthMismatch);
        }
        self.seal_plaintext_txn(inner_type, &mut record)?;
        commit(record)
    }

    fn check_seq(&self) -> Result<(), Error> {
        if self.seq == u64::MAX {
            return Err(Error::SeqExhausted);
        }
        if self.seq >= AEAD_CONFIDENTIALITY_LIMIT {
            return Err(Error::KeyLimitReached);
        }
        Ok(())
    }

    fn seal_record(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let plaintext_end = out.len() - AEAD_TAG_LEN;
        write_header_slice(
            ContentType::ApplicationData,
            (body.len() + 1 + AEAD_TAG_LEN) as u16,
            &mut out[..plaintext_end],
        );
        out[HEADER_LEN..HEADER_LEN + body.len()].copy_from_slice(body);
        out[HEADER_LEN + body.len()] = inner_type as u8;
        let tag = self.seal_plaintext(&mut out[..plaintext_end])?;
        out[plaintext_end..].copy_from_slice(&tag);
        Ok(())
    }

    fn seal_plaintext(&mut self, record: &mut [u8]) -> Result<[u8; AEAD_TAG_LEN], Error> {
        debug_assert!(self.seq != u64::MAX);
        let seq = self.seq;
        self.seq += 1;
        let (header, plaintext) = record.split_at_mut(HEADER_LEN);
        let tag = self.aead.seal_detached(seq, header, plaintext)?;
        Ok(tag)
    }

    fn seal_record_txn(
        &mut self,
        inner_type: ContentType,
        body: &[u8],
        out: &mut write::Txn<'_, '_>,
    ) -> Result<(), Error> {
        write_header_txn(
            ContentType::ApplicationData,
            (body.len() + 1 + AEAD_TAG_LEN) as u16,
            out,
        )?;
        write_txn(out, body)?;
        self.seal_plaintext_txn(inner_type, out)
    }

    fn seal_plaintext_txn(
        &mut self,
        inner_type: ContentType,
        out: &mut write::Txn<'_, '_>,
    ) -> Result<(), Error> {
        write_txn(out, &[inner_type as u8])?;
        let tag = self.seal_plaintext(out.initialized_mut())?;
        write_txn(out, &tag)
    }
}

pub struct Opener {
    aead: key::Key,
    seq: u64,
    poisoned: bool,
}

impl Opener {
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, KeyError> {
        Self::with_suite(secret, CipherSuite::Aes128GcmSha256)
    }

    pub fn with_suite(secret: &[u8], suite: CipherSuite) -> Result<Self, KeyError> {
        Ok(Self {
            aead: key::Key::derive(secret, suite)?,
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
    ) -> Result<Option<(ContentType, ops::Range<usize>, usize)>, Error> {
        use ciphertext::Ciphertext;
        let ciphertext = match Ciphertext::parse(input, self.poisoned, self.seq) {
            Ok(Some(ciphertext)) => ciphertext,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let (content_type, content_len) =
            match self.open_body(&ciphertext.aad, &mut input[ciphertext.body]) {
                Ok(opened) => opened,
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            };
        Ok(Some((
            content_type,
            HEADER_LEN..HEADER_LEN + content_len,
            ciphertext.total,
        )))
    }

    fn open_body(
        &mut self,
        aad: &[u8; HEADER_LEN],
        body: &mut [u8],
    ) -> Result<(ContentType, usize), Error> {
        let seq = self.seq;
        let plaintext_len = match self.aead.open(seq, aad, body) {
            Ok(plain) => plain.len(),
            Err(_) => {
                self.poisoned = true;
                return Err(Error::OpenFailed);
            }
        };
        self.seq += 1;

        let inner_slice = &body[..plaintext_len];
        let content_len = inner_slice
            .iter()
            .rposition(|&byte| byte != 0)
            .ok_or(Error::AllZeroInner)?;
        if content_len > MAX_PLAINTEXT_BODY {
            return Err(Error::RecordOverflow);
        }
        let inner_type = ContentType::from_u8(inner_slice[content_len])?;
        if inner_type == ContentType::ChangeCipherSpec {
            return Err(Error::UnexpectedChangeCipherSpec);
        }
        Ok((inner_type, content_len))
    }
}

fn check_body_len(body: &[u8]) -> Result<(), Error> {
    if body.len() > MAX_PLAINTEXT_BODY {
        return Err(Error::BodyTooLarge);
    }
    Ok(())
}

fn sealed_len(body: &[u8]) -> Result<usize, Error> {
    sealed_len_for(body.len())
}

fn sealed_len_for(body_len: usize) -> Result<usize, Error> {
    if body_len > MAX_PLAINTEXT_BODY {
        return Err(Error::BodyTooLarge);
    }
    Ok(HEADER_LEN + body_len + 1 + AEAD_TAG_LEN)
}

fn plaintext_len(body: &[u8]) -> Result<usize, Error> {
    check_body_len(body)?;
    Ok(HEADER_LEN + body.len())
}

fn transaction<'writer, 'target>(
    out: &'writer mut write::SpareWriter<'target>,
    len: usize,
) -> Result<write::Txn<'writer, 'target>, Error> {
    out.try_transaction(len).map_err(|_| Error::BufferTooSmall)
}

fn write_txn(out: &mut write::Txn<'_, '_>, bytes: &[u8]) -> Result<(), Error> {
    out.try_extend(bytes).map_err(|_| Error::BufferTooSmall)
}

fn commit(out: write::Txn<'_, '_>) -> Result<(), Error> {
    out.commit().map_err(|_| Error::BufferTooSmall)
}

fn write_header_slice(content_type: ContentType, body_len: u16, out: &mut [u8]) {
    out[0] = content_type as u8;
    out[1..3].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out[3..HEADER_LEN].copy_from_slice(&body_len.to_be_bytes());
}

fn write_header_vec(content_type: ContentType, body_len: u16, out: &mut vec::Vec<u8>) {
    out.push(content_type as u8);
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(&body_len.to_be_bytes());
}

fn write_header_txn(
    content_type: ContentType,
    body_len: u16,
    out: &mut write::Txn<'_, '_>,
) -> Result<(), Error> {
    let version = PROTOCOL_VERSION.to_be_bytes();
    let body_len = body_len.to_be_bytes();
    write_txn(
        out,
        &[
            content_type as u8,
            version[0],
            version[1],
            body_len[0],
            body_len[1],
        ],
    )
}
