use alloc::vec::Vec;

use ring::hmac;

use crate::hash::HASH_LEN;

pub struct Hkdf;

impl Hkdf {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
        let tag = hmac::sign(&key, ikm);
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(tag.as_ref());
        out
    }

    pub fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) {
        let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
        let mut t_prev: [u8; HASH_LEN] = [0; HASH_LEN];
        let mut t_prev_len = 0;
        let mut written = 0;
        let mut counter: u8 = 0;
        while written < out.len() {
            counter = counter
                .checked_add(1)
                .expect("hkdf_expand: output exceeds 255 hash blocks");
            let mut ctx = hmac::Context::with_key(&key);
            ctx.update(&t_prev[..t_prev_len]);
            ctx.update(info);
            ctx.update(&[counter]);
            let tag = ctx.sign();
            let block = tag.as_ref();
            debug_assert_eq!(block.len(), HASH_LEN);
            let take = (out.len() - written).min(block.len());
            out[written..written + take].copy_from_slice(&block[..take]);
            t_prev[..block.len()].copy_from_slice(block);
            t_prev_len = block.len();
            written += take;
        }
    }

    pub fn expand_label(prk: &[u8], label: &str, context: &[u8], out: &mut [u8]) {
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        let total_len = u16::try_from(out.len()).expect("hkdf_expand_label: output > 65535");
        info.extend_from_slice(&total_len.to_be_bytes());

        let label_with_prefix_len = 6 + label.len();
        info.push(u8::try_from(label_with_prefix_len).expect("hkdf_expand_label: label too long"));
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());

        info.push(u8::try_from(context.len()).expect("hkdf_expand_label: context too long"));
        info.extend_from_slice(context);

        Self::expand(prk, &info, out);
    }

    pub fn derive_secret(prk: &[u8], label: &str, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        Self::expand_label(prk, label, transcript_hash, &mut out);
        out
    }

    pub fn finished_key(base_secret: &[u8]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        Self::expand_label(base_secret, "finished", &[], &mut out);
        out
    }
}
