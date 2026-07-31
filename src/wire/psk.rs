use alloc::vec::Vec;

use ring::hmac::{self, Key};

use crate::crypto::hash::{HASH_LEN, HashAlg, Transcript};
use crate::crypto::kdf::{Hkdf, HkdfError};
use crate::wire::codec::{DecodeError, Encode, EncodeError, Reader};
use zeroize::Zeroize;

pub const KX_MODE_PSK_DHE: u8 = 1;

/// Resumption PSKs are always 32-byte / SHA-256 in this implementation, so
/// SHA-384 sessions are not resumable (RFC 8446 §4.2.11).
pub(crate) const RESUMPTION_HASH: HashAlg = HashAlg::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KxModes(Vec<u8>);

impl KxModes {
    pub fn new(modes: Vec<u8>) -> Self {
        Self(modes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(1 + self.0.len());
        out.put_vec_u8(|o| {
            o.put_slice(&self.0);
            Ok(())
        })?;
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let modes = r.vec_u8()?.to_vec();
        r.finish()?;
        Ok(Self(modes))
    }

    pub(crate) fn contains(data: &[u8], mode: u8) -> Result<bool, DecodeError> {
        let mut reader = Reader::new(data);
        let modes = reader.vec_u8()?;
        reader.finish()?;
        Ok(modes.contains(&mode))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PskOfferRef<'a> {
    pub(crate) identity: &'a [u8],
    pub(crate) obfuscated_ticket_age: u32,
    pub(crate) binder: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub identities: Vec<PskIdentity>,
    pub binders: Vec<Vec<u8>>,
}

impl Offer {
    pub fn new(identities: Vec<PskIdentity>, binders: Vec<Vec<u8>>) -> Self {
        Self {
            identities,
            binders,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        out.put_vec_u16(|o| {
            for id in &self.identities {
                o.put_vec_u16(|oo| {
                    oo.put_slice(&id.identity);
                    Ok(())
                })?;
                o.put_u32(id.obfuscated_ticket_age);
            }
            Ok(())
        })?;
        out.put_vec_u16(|o| {
            for b in &self.binders {
                o.put_vec_u8(|oo| {
                    oo.put_slice(b);
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
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
        Ok(Self {
            identities,
            binders,
        })
    }

    pub(crate) fn decode_first(data: &[u8]) -> Result<Option<PskOfferRef<'_>>, DecodeError> {
        let mut reader = Reader::new(data);
        let mut identities = reader.sub_u16()?;
        let mut identity_count = 0usize;
        let mut first_identity = None;
        while !identities.is_empty() {
            let identity = identities.vec_u16()?;
            let obfuscated_ticket_age = identities.u32()?;
            if first_identity.is_none() {
                first_identity = Some((identity, obfuscated_ticket_age));
            }
            identity_count = identity_count
                .checked_add(1)
                .ok_or(DecodeError::InvalidEnum)?;
        }

        let mut binders = reader.sub_u16()?;
        let mut binder_count = 0usize;
        let mut first_binder = None;
        while !binders.is_empty() {
            let binder = binders.vec_u8()?;
            if first_binder.is_none() {
                first_binder = Some(binder);
            }
            binder_count = binder_count
                .checked_add(1)
                .ok_or(DecodeError::InvalidEnum)?;
        }
        reader.finish()?;
        if identity_count != binder_count {
            return Err(DecodeError::Trailing);
        }
        Ok(first_identity
            .zip(first_binder)
            .map(|((identity, obfuscated_ticket_age), binder)| PskOfferRef {
                identity,
                obfuscated_ticket_age,
                binder,
            }))
    }

    /// ClientHello prefix covered by a single resumption binder.
    pub(crate) fn binder_transcript_prefix(
        encoded_client_hello: &[u8],
        binder_len: usize,
    ) -> Option<&[u8]> {
        const BINDER_LIST_LENGTH_BYTES: usize = 2;
        const BINDER_LENGTH_BYTES: usize = 1;
        let field_len = BINDER_LIST_LENGTH_BYTES
            .checked_add(BINDER_LENGTH_BYTES)?
            .checked_add(binder_len)?;
        encoded_client_hello.get(..encoded_client_hello.len().checked_sub(field_len)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedIdentity(u16);

impl SelectedIdentity {
    pub fn new(selected_identity: u16) -> Self {
        Self(selected_identity)
    }

    pub fn get(self) -> u16 {
        self.0
    }

    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2);
        out.put_u16(self.0);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let v = r.u16()?;
        r.finish()?;
        Ok(Self(v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumptionBinder([u8; HASH_LEN]);

impl ResumptionBinder {
    pub fn compute(psk: &[u8; HASH_LEN], partial_ch_hash: &[u8]) -> Result<Self, HkdfError> {
        let zero = [0u8; HASH_LEN];
        let hkdf = Hkdf::new(RESUMPTION_HASH);
        let early_secret = hkdf.extract(&zero, psk);
        let binder_key = hkdf.derive_secret(
            early_secret.as_slice(),
            "res binder",
            Transcript::hash_empty(RESUMPTION_HASH).as_slice(),
        )?;
        let mut finished_key = [0u8; HASH_LEN];
        hkdf.expand_label(binder_key.as_slice(), "finished", &[], &mut finished_key)?;
        let key = Key::new(RESUMPTION_HASH.hmac(), &finished_key);
        let tag = hmac::sign(&key, partial_ch_hash);
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(tag.as_ref());
        finished_key.zeroize();
        Ok(Self(out))
    }

    pub fn as_slice(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}
