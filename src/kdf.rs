use alloc::vec::Vec;

use ring::hmac;

use crate::hash::{Digest, HashAlg, MAX_HASH_LEN, Secret};

pub(crate) fn hmac_alg(alg: HashAlg) -> hmac::Algorithm {
    match alg {
        HashAlg::Sha256 => hmac::HMAC_SHA256,
        HashAlg::Sha384 => hmac::HMAC_SHA384,
    }
}

pub struct Hkdf;

impl Hkdf {
    pub fn extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Secret {
        let key = hmac::Key::new(hmac_alg(alg), salt);
        Secret::from_slice(hmac::sign(&key, ikm).as_ref())
    }

    pub fn expand(alg: HashAlg, prk: &[u8], info: &[u8], out: &mut [u8]) {
        let key = hmac::Key::new(hmac_alg(alg), prk);
        let mut t_prev = [0u8; MAX_HASH_LEN];
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
            let take = (out.len() - written).min(block.len());
            out[written..written + take].copy_from_slice(&block[..take]);
            t_prev[..block.len()].copy_from_slice(block);
            t_prev_len = block.len();
            written += take;
        }
        crate::schedule::zeroize(&mut t_prev);
    }

    pub fn expand_label(alg: HashAlg, prk: &[u8], label: &str, context: &[u8], out: &mut [u8]) {
        let info = Self::hkdf_label(label, context, out.len());
        Self::expand(alg, prk, &info, out);
    }

    pub fn derive_secret(alg: HashAlg, prk: &[u8], label: &str, transcript_hash: &[u8]) -> Secret {
        let mut buf = [0u8; MAX_HASH_LEN];
        let out = &mut buf[..alg.output_len()];
        Self::expand_label(alg, prk, label, transcript_hash, out);
        let secret = Secret::from_slice(out);
        crate::schedule::zeroize(out);
        secret
    }

    pub fn traffic_update(alg: HashAlg, prev: &Digest) -> Secret {
        Self::derive_secret(alg, prev.as_slice(), "traffic upd", &[])
    }

    fn hkdf_label(label: &str, context: &[u8], out_len: usize) -> Vec<u8> {
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        let total_len = u16::try_from(out_len).expect("hkdf_expand_label: output > 65535");
        info.extend_from_slice(&total_len.to_be_bytes());
        let label_with_prefix_len = 6 + label.len();
        info.push(u8::try_from(label_with_prefix_len).expect("hkdf_expand_label: label too long"));
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        info.push(u8::try_from(context.len()).expect("hkdf_expand_label: context too long"));
        info.extend_from_slice(context);
        info
    }
}
