use alloc::vec::Vec;

use crate::hash::{Digest, HashAlg, MAX_HASH_LEN, Secret};
use zeroize::Zeroize;

use ring::hmac::{self, Context, Key};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    OutputTooLong,
    LabelTooLong,
    ContextTooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hkdf {
    alg: HashAlg,
}

impl Hkdf {
    pub fn new(alg: HashAlg) -> Self {
        Self { alg }
    }

    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Secret {
        let key = Key::new(self.alg.hmac(), salt);
        Secret::from_slice(hmac::sign(&key, ikm).as_ref())
    }

    pub fn expand(self, prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
        let block_len = self.alg.output_len();
        let block_count = out.len().div_ceil(block_len);
        if block_count > u8::MAX as usize {
            return Err(HkdfError::OutputTooLong);
        }

        let key = Key::new(self.alg.hmac(), prk);
        let mut t_prev = [0u8; MAX_HASH_LEN];
        let mut t_prev_len = 0;
        let mut written = 0;
        for counter in 1..=block_count {
            let mut ctx = Context::with_key(&key);
            ctx.update(&t_prev[..t_prev_len]);
            ctx.update(info);
            ctx.update(&[counter as u8]);
            let tag = ctx.sign();
            let block = tag.as_ref();
            let take = (out.len() - written).min(block.len());
            out[written..written + take].copy_from_slice(&block[..take]);
            t_prev[..block.len()].copy_from_slice(block);
            t_prev_len = block.len();
            written += take;
        }
        t_prev.zeroize();
        Ok(())
    }

    pub fn expand_label(
        self,
        prk: &[u8],
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), HkdfError> {
        let info = Self::hkdf_label(label, context, out.len())?;
        self.expand(prk, &info, out)
    }

    pub fn derive_secret(
        self,
        prk: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> Result<Secret, HkdfError> {
        let mut buf = [0u8; MAX_HASH_LEN];
        let out = &mut buf[..self.alg.output_len()];
        self.expand_label(prk, label, transcript_hash, out)?;
        let secret = Secret::from_slice(out);
        out.zeroize();
        Ok(secret)
    }

    pub fn traffic_update(self, prev: &Digest) -> Result<Secret, HkdfError> {
        self.derive_secret(prev.as_slice(), "traffic upd", &[])
    }

    fn hkdf_label(label: &str, context: &[u8], out_len: usize) -> Result<Vec<u8>, HkdfError> {
        let total_len = u16::try_from(out_len).map_err(|_| HkdfError::OutputTooLong)?;
        let label_with_prefix_len = 6usize
            .checked_add(label.len())
            .ok_or(HkdfError::LabelTooLong)?;
        let label_len = u8::try_from(label_with_prefix_len).map_err(|_| HkdfError::LabelTooLong)?;
        let context_len = u8::try_from(context.len()).map_err(|_| HkdfError::ContextTooLong)?;
        let mut info = Vec::with_capacity(2 + 1 + label_with_prefix_len + 1 + context.len());
        info.extend_from_slice(&total_len.to_be_bytes());
        info.push(label_len);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        info.push(context_len);
        info.extend_from_slice(context);
        Ok(info)
    }
}
