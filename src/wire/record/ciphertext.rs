use core::ops::Range;

use super::{ContentType, HEADER_LEN, MAX_CIPHERTEXT_BODY, RecordError};

pub(super) struct Ciphertext {
    pub(super) aad: [u8; HEADER_LEN],
    pub(super) body: Range<usize>,
    pub(super) total: usize,
}

impl Ciphertext {
    pub(super) fn parse(
        input: &[u8],
        poisoned: bool,
        seq: u64,
    ) -> Result<Option<Self>, RecordError> {
        if poisoned {
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
        if seq == u64::MAX {
            return Err(RecordError::SeqExhausted);
        }
        let mut aad = [0u8; HEADER_LEN];
        aad.copy_from_slice(&input[..HEADER_LEN]);
        Ok(Some(Self {
            aad,
            body: HEADER_LEN..total,
            total,
        }))
    }
}
