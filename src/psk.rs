use alloc::vec::Vec;

use ring::hmac;

use crate::codec::{DecodeError, Encode, Reader};
use crate::hash::{HASH_LEN, HashAlg, Transcript};
use crate::kdf::Hkdf;

pub const KX_MODE_PSK_DHE: u8 = 1;

/// Resumption PSKs are always 32-byte / SHA-256 in this implementation, so
/// SHA-384 sessions are not resumable (RFC 8446 §4.2.11).
pub(crate) const RESUMPTION_HASH: HashAlg = HashAlg::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

pub struct KxModes;

impl KxModes {
    pub fn encode(modes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + modes.len());
        out.put_vec_u8(|o| o.put_slice(modes));
        out
    }

    pub fn decode(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let mut r = Reader::new(data);
        let modes = r.vec_u8()?.to_vec();
        r.finish()?;
        Ok(modes)
    }
}

pub struct Offer;

impl Offer {
    pub fn encode(identities: &[PskIdentity], binders: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.put_vec_u16(|o| {
            for id in identities {
                o.put_vec_u16(|oo| oo.put_slice(&id.identity));
                o.put_u32(id.obfuscated_ticket_age);
            }
        });
        out.put_vec_u16(|o| {
            for b in binders {
                o.put_vec_u8(|oo| oo.put_slice(b));
            }
        });
        out
    }

    pub fn decode(data: &[u8]) -> Result<(Vec<PskIdentity>, Vec<Vec<u8>>), DecodeError> {
        let mut r = Reader::new(data);
        let mut id_sub = r.sub_u16()?;
        let mut identities = Vec::new();
        while !id_sub.is_empty() {
            let identity = id_sub.vec_u16()?.to_vec();
            let obfuscated_ticket_age = id_sub.u32()?;
            identities.push(PskIdentity {
                identity,
                obfuscated_ticket_age,
            });
        }
        let mut bs_sub = r.sub_u16()?;
        let mut binders = Vec::new();
        while !bs_sub.is_empty() {
            binders.push(bs_sub.vec_u8()?.to_vec());
        }
        r.finish()?;
        if identities.len() != binders.len() {
            return Err(DecodeError::Trailing);
        }
        Ok((identities, binders))
    }
}

pub struct SelectedIdentity;

impl SelectedIdentity {
    pub fn encode(selected_identity: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(2);
        out.put_u16(selected_identity);
        out
    }

    pub fn decode(data: &[u8]) -> Result<u16, DecodeError> {
        let mut r = Reader::new(data);
        let v = r.u16()?;
        r.finish()?;
        Ok(v)
    }
}

pub struct ResumptionBinder;

impl ResumptionBinder {
    pub fn compute(psk: &[u8; HASH_LEN], partial_ch_hash: &[u8]) -> [u8; HASH_LEN] {
        let zero = [0u8; HASH_LEN];
        let early_secret = Hkdf::extract(RESUMPTION_HASH, &zero, psk);
        let binder_key = Hkdf::derive_secret(
            RESUMPTION_HASH,
            early_secret.as_slice(),
            "res binder",
            Transcript::hash_empty(RESUMPTION_HASH).as_slice(),
        );
        let mut finished_key = [0u8; HASH_LEN];
        Hkdf::expand_label(
            RESUMPTION_HASH,
            binder_key.as_slice(),
            "finished",
            &[],
            &mut finished_key,
        );
        let key = hmac::Key::new(crate::kdf::hmac_alg(RESUMPTION_HASH), &finished_key);
        let tag = hmac::sign(&key, partial_ch_hash);
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(tag.as_ref());
        out
    }
}
