use core::ops;

pub(super) struct Ciphertext {
    pub(super) aad: [u8; super::HEADER_LEN],
    pub(super) body: ops::Range<usize>,
    pub(super) total: usize,
}

impl Ciphertext {
    pub(super) fn parse(
        input: &[u8],
        poisoned: bool,
        seq: u64,
    ) -> Result<Option<Self>, super::Error> {
        use crate::wire::record::ContentType;
        use crate::wire::record::MAX_CIPHERTEXT_BODY;
        if poisoned {
            return Err(super::Error::Poisoned);
        }
        if input.len() < super::HEADER_LEN {
            return Ok(None);
        }
        if input[1..3] != super::PROTOCOL_VERSION.to_be_bytes() {
            return Err(super::Error::BadLegacyVersion);
        }
        let outer_type = input[0];
        let body_len = u16::from_be_bytes([input[3], input[4]]) as usize;
        if body_len > MAX_CIPHERTEXT_BODY {
            return Err(super::Error::BodyTooLarge);
        }
        let total = super::HEADER_LEN + body_len;
        if input.len() < total {
            return Ok(None);
        }
        if outer_type != ContentType::ApplicationData as u8 {
            return Err(super::Error::NotCipherTextOuter);
        }
        if seq == u64::MAX {
            return Err(super::Error::SeqExhausted);
        }
        if seq >= super::AEAD_CONFIDENTIALITY_LIMIT {
            return Err(super::Error::KeyLimitReached);
        }
        let mut aad = [0u8; super::HEADER_LEN];
        aad.copy_from_slice(&input[..super::HEADER_LEN]);
        Ok(Some(Self {
            aad,
            body: super::HEADER_LEN..total,
            total,
        }))
    }
}
