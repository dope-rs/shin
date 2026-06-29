use alloc::vec::Vec;

use crate::aead::AeadKey;
use crate::hash::HashAlg;
use crate::schedule::TrafficKeys;
use crate::uninit::VecUninitExt;

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

fn aead_for_suite(secret: &[u8], suite: CipherSuite) -> AeadKey {
    let alg = suite.hash_alg();
    match suite {
        CipherSuite::Aes128GcmSha256 => {
            let keys = TrafficKeys::<16>::derive(alg, secret);
            AeadKey::aes_128_gcm(&keys.key, keys.iv)
        }
        CipherSuite::ChaCha20Poly1305Sha256 => {
            let keys = TrafficKeys::<32>::derive(alg, secret);
            AeadKey::chacha20_poly1305(&keys.key, keys.iv)
        }
        CipherSuite::Aes256GcmSha384 => {
            let keys = TrafficKeys::<32>::derive(alg, secret);
            AeadKey::aes_256_gcm(&keys.key, keys.iv)
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

#[derive(Debug, Clone)]
pub struct PlaintextRecord<'a> {
    pub content_type: ContentType,
    pub body: &'a [u8],
}

impl<'a> PlaintextRecord<'a> {
    pub fn encode(
        content_type: ContentType,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        if body.len() > MAX_PLAINTEXT_BODY {
            return Err(RecordError::BodyTooLarge);
        }
        out.push(content_type as u8);
        out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        Ok(())
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
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self::with_suite(secret, CipherSuite::Aes128GcmSha256)
    }

    pub fn with_suite(secret: &[u8], suite: CipherSuite) -> Self {
        Self {
            aead: aead_for_suite(secret, suite),
            seq: 0,
        }
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
    /// let mut sealer = Sealer::from_secret(&[0u8; 32]);
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
        // SAFETY: `seal_record` writes all `total` bytes of its destination.
        unsafe {
            out.extend_uninit(total, |dst| self.seal_record(inner_type, body, dst));
        }
        Ok(())
    }

    /// Seals one record into `out`, returning its length. No allocation.
    ///
    /// ```
    /// use shin::record::{AEAD_TAG_LEN, ContentType, HEADER_LEN, Sealer};
    /// let mut sealer = Sealer::from_secret(&[0u8; 32]);
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
        self.seal_record(inner_type, body, dst);
        Ok(total)
    }

    fn check_seq(&self) -> Result<(), RecordError> {
        if self.seq == u64::MAX {
            return Err(RecordError::SeqExhausted);
        }
        Ok(())
    }

    fn seal_record(&mut self, inner_type: ContentType, body: &[u8], dst: &mut [u8]) {
        debug_assert_eq!(dst.len(), HEADER_LEN + body.len() + 1 + AEAD_TAG_LEN);
        debug_assert!(self.seq != u64::MAX);
        let seq = self.seq;
        self.seq += 1;
        let outer_body_len = dst.len() - HEADER_LEN;

        dst[0] = ContentType::ApplicationData as u8;
        dst[1..3].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        dst[3..HEADER_LEN].copy_from_slice(&(outer_body_len as u16).to_be_bytes());
        dst[HEADER_LEN..HEADER_LEN + body.len()].copy_from_slice(body);
        dst[HEADER_LEN + body.len()] = inner_type as u8;

        let (header, rest) = dst.split_at_mut(HEADER_LEN);
        let (plaintext, tag_dst) = rest.split_at_mut(body.len() + 1);
        let tag = self.aead.seal_detached(seq, header, plaintext);
        tag_dst.copy_from_slice(&tag);
    }
}

fn sealed_record_len(body: &[u8]) -> Result<usize, RecordError> {
    if body.len() > MAX_PLAINTEXT_BODY {
        return Err(RecordError::BodyTooLarge);
    }
    Ok(HEADER_LEN + body.len() + 1 + AEAD_TAG_LEN)
}

pub struct Opener {
    aead: AeadKey,
    seq: u64,
    poisoned: bool,
}

impl Opener {
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self::with_suite(secret, CipherSuite::Aes128GcmSha256)
    }

    pub fn with_suite(secret: &[u8], suite: CipherSuite) -> Self {
        Self {
            aead: aead_for_suite(secret, suite),
            seq: 0,
            poisoned: false,
        }
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
    ) -> Result<Option<(ContentType, core::ops::Range<usize>, usize)>, RecordError> {
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
        let inner_type_pos = inner_slice
            .iter()
            .rposition(|&b| b != 0)
            .ok_or(RecordError::AllZeroInner)?;
        // RFC 8446 §5.4: the 2^14 limit is on de-padded content, not the padded plaintext.
        if inner_type_pos > MAX_PLAINTEXT_BODY {
            return Err(RecordError::RecordOverflow);
        }
        let inner_type = ContentType::from_u8(inner_slice[inner_type_pos])?;
        if inner_type == ContentType::ChangeCipherSpec {
            return Err(RecordError::UnexpectedChangeCipherSpec);
        }

        let plaintext_start = HEADER_LEN;
        let plaintext_end = HEADER_LEN + inner_type_pos;
        Ok(Some((inner_type, plaintext_start..plaintext_end, total)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [0x42u8; 32];

    #[test]
    fn seal_refuses_at_seq_max() {
        let mut sealer = Sealer::from_secret(&SECRET);
        sealer.seq = u64::MAX;
        assert_eq!(
            sealer.seal(ContentType::ApplicationData, b"x"),
            Err(RecordError::SeqExhausted)
        );
    }

    #[test]
    fn open_refuses_at_seq_max() {
        let mut sealer = Sealer::from_secret(&SECRET);
        let mut wire = sealer.seal(ContentType::ApplicationData, b"x").unwrap();
        let mut opener = Opener::from_secret(&SECRET);
        opener.seq = u64::MAX;
        assert_eq!(opener.open(&mut wire), Err(RecordError::SeqExhausted));
    }
}
