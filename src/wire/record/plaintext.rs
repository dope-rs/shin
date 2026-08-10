use crate::wire::record;
use alloc::vec;
use o3::buffer::write;

#[derive(Debug, Clone)]
pub struct Plaintext<'a> {
    pub content_type: record::ContentType,
    /// TLSPlaintext.legacy_record_version. TLS 1.3 normally uses `0x0303`;
    /// only an initial ClientHello is permitted to use `0x0301`.
    pub legacy_record_version: u16,
    pub body: &'a [u8],
}

impl<'a> Plaintext<'a> {
    /// Encodes a plaintext record into a fresh buffer.
    #[doc = include_str!("docs/plaintext_encode.md")]
    pub fn encode(
        content_type: record::ContentType,
        body: &[u8],
    ) -> Result<vec::Vec<u8>, record::Error> {
        let mut out = vec::Vec::new();
        Self::encode_into(content_type, body, &mut out)?;
        Ok(out)
    }

    /// Appends a plaintext record to `out` without a fresh allocation.
    #[doc = include_str!("docs/plaintext_encode_into.md")]
    pub fn encode_into(
        content_type: record::ContentType,
        body: &[u8],
        out: &mut vec::Vec<u8>,
    ) -> Result<(), record::Error> {
        record::check_body_len(body)?;
        out.reserve(record::HEADER_LEN + body.len());
        record::write_header_vec(content_type, body.len() as u16, out);
        out.extend_from_slice(body);
        Ok(())
    }

    /// Encodes a plaintext record into `out`, returning its length. No allocation.
    #[doc = include_str!("docs/plaintext_encode_into_slice.md")]
    pub fn encode_into_slice(
        content_type: record::ContentType,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, record::Error> {
        let total = record::plaintext_len(body)?;
        let dst = out.get_mut(..total).ok_or(record::Error::BufferTooSmall)?;
        record::write_header_slice(content_type, body.len() as u16, dst);
        dst[record::HEADER_LEN..].copy_from_slice(body);
        Ok(total)
    }

    /// Appends one complete plaintext record directly to an O3 writer.
    pub fn write_to(
        content_type: record::ContentType,
        body: &[u8],
        out: &mut write::SpareWriter<'_>,
    ) -> Result<(), record::Error> {
        let total = record::plaintext_len(body)?;
        let mut encoded = record::transaction(out, total)?;
        record::write_header_txn(content_type, body.len() as u16, &mut encoded)?;
        record::write_txn(&mut encoded, body)?;
        record::commit(encoded)
    }

    pub fn parse(input: &'a [u8]) -> Result<Option<(Self, usize)>, record::Error> {
        if input.len() < record::HEADER_LEN {
            return Ok(None);
        }
        let content_type = record::ContentType::from_u8(input[0])?;
        let legacy_record_version = u16::from_be_bytes([input[1], input[2]]);
        if !matches!(legacy_record_version, 0x0301 | record::PROTOCOL_VERSION) {
            return Err(record::Error::BadLegacyVersion);
        }
        let body_len = u16::from_be_bytes([input[3], input[4]]) as usize;
        if body_len > record::MAX_PLAINTEXT_BODY {
            return Err(record::Error::BodyTooLarge);
        }
        let total = record::HEADER_LEN + body_len;
        if input.len() < total {
            return Ok(None);
        }
        Ok(Some((
            Self {
                content_type,
                legacy_record_version,
                body: &input[record::HEADER_LEN..total],
            },
            total,
        )))
    }
}
