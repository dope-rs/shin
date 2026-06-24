use alloc::vec::Vec;

use crate::aead::AeadKey;
use crate::schedule::TrafficKeys;

pub const PROTOCOL_VERSION: u16 = 0x0303;

pub const MAX_PLAINTEXT_BODY: usize = 1 << 14;

pub const MAX_CIPHERTEXT_BODY: usize = (1 << 14) + 256;

pub const HEADER_LEN: usize = 5;
pub const AEAD_TAG_LEN: usize = 16;

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
        let keys = TrafficKeys::aes_128_gcm(secret);
        Self {
            aead: AeadKey::aes_128_gcm(&keys.key, keys.iv),
            seq: 0,
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn seal(&mut self, inner_type: ContentType, body: &[u8]) -> Result<Vec<u8>, RecordError> {
        if body.len() > MAX_PLAINTEXT_BODY {
            return Err(RecordError::BodyTooLarge);
        }
        if self.seq == u64::MAX {
            return Err(RecordError::SeqExhausted);
        }

        let mut inner = Vec::with_capacity(body.len() + 1);
        inner.extend_from_slice(body);
        inner.push(inner_type as u8);

        let outer_body_len = inner.len() + AEAD_TAG_LEN;
        if outer_body_len > MAX_CIPHERTEXT_BODY {
            return Err(RecordError::BodyTooLarge);
        }

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.push(ContentType::ApplicationData as u8);
        header.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        header.extend_from_slice(&(outer_body_len as u16).to_be_bytes());

        let seq = self.seq;
        self.seq += 1;

        let ct_with_tag = self.aead.seal(seq, &header, &inner);

        let mut out = Vec::with_capacity(HEADER_LEN + ct_with_tag.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ct_with_tag);
        Ok(out)
    }
}

pub struct Opener {
    aead: AeadKey,
    seq: u64,
}

impl Opener {
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let keys = TrafficKeys::aes_128_gcm(secret);
        Self {
            aead: AeadKey::aes_128_gcm(&keys.key, keys.iv),
            seq: 0,
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn open(
        &mut self,
        input: &mut [u8],
    ) -> Result<Option<(ContentType, core::ops::Range<usize>, usize)>, RecordError> {
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
        let plaintext_len = self
            .aead
            .open(seq, &aad, body)
            .map_err(|_| RecordError::OpenFailed)?
            .len();

        self.seq += 1;

        if plaintext_len > MAX_PLAINTEXT_BODY + 1 {
            return Err(RecordError::RecordOverflow);
        }

        let inner_slice = &input[HEADER_LEN..HEADER_LEN + plaintext_len];
        let inner_type_pos = inner_slice
            .iter()
            .rposition(|&b| b != 0)
            .ok_or(RecordError::AllZeroInner)?;
        let inner_type = ContentType::from_u8(inner_slice[inner_type_pos])?;

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

    #[test]
    fn seal_refuses_oversize_body() {
        let mut sealer = Sealer::from_secret(&SECRET);
        let big = alloc::vec![0u8; MAX_PLAINTEXT_BODY + 1];
        assert_eq!(
            sealer.seal(ContentType::ApplicationData, &big),
            Err(RecordError::BodyTooLarge)
        );
    }

    #[test]
    fn encode_rejects_oversize_body_in_release() {
        let big = alloc::vec![0u8; MAX_PLAINTEXT_BODY + 1];
        let mut out = Vec::new();
        assert_eq!(
            PlaintextRecord::encode(ContentType::Handshake, &big, &mut out),
            Err(RecordError::BodyTooLarge)
        );
        assert!(out.is_empty());
    }

    fn craft_wire(seq: u64, inner_plaintext: &[u8]) -> Vec<u8> {
        let keys = TrafficKeys::aes_128_gcm(&SECRET);
        let aead = AeadKey::aes_128_gcm(&keys.key, keys.iv);
        let outer_body_len = inner_plaintext.len() + AEAD_TAG_LEN;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.push(ContentType::ApplicationData as u8);
        header.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        header.extend_from_slice(&(outer_body_len as u16).to_be_bytes());
        let ct = aead.seal(seq, &header, inner_plaintext);
        let mut wire = header;
        wire.extend_from_slice(&ct);
        wire
    }

    #[test]
    fn open_rejects_record_overflow() {
        let mut inner = alloc::vec![0u8; MAX_PLAINTEXT_BODY + 1];
        inner.push(ContentType::ApplicationData as u8);
        let mut wire = craft_wire(0, &inner);
        let mut opener = Opener::from_secret(&SECRET);
        assert_eq!(opener.open(&mut wire), Err(RecordError::RecordOverflow));
    }

    #[test]
    fn open_accepts_max_plaintext() {
        let mut inner = alloc::vec![0u8; MAX_PLAINTEXT_BODY];
        inner.push(ContentType::ApplicationData as u8);
        let mut wire = craft_wire(0, &inner);
        let mut opener = Opener::from_secret(&SECRET);
        let (inner_type, range, _) = opener.open(&mut wire).unwrap().unwrap();
        assert_eq!(inner_type, ContentType::ApplicationData);
        assert_eq!(range.len(), MAX_PLAINTEXT_BODY);
    }

    #[test]
    fn open_does_not_advance_seq_on_auth_failure() {
        let mut sealer = Sealer::from_secret(&SECRET);
        let mut tampered = sealer.seal(ContentType::ApplicationData, b"body").unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let mut opener = Opener::from_secret(&SECRET);
        assert_eq!(
            opener.open(&mut tampered).unwrap_err(),
            RecordError::OpenFailed
        );
        assert_eq!(opener.seq(), 0);

        let mut fresh = Sealer::from_secret(&SECRET);
        let mut good = fresh.seal(ContentType::ApplicationData, b"body").unwrap();
        let (_, range, _) = opener.open(&mut good).unwrap().unwrap();
        assert_eq!(&good[range], b"body");
        assert_eq!(opener.seq(), 1);
    }
}
