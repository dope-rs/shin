use crate::crypto::hash;
use crate::crypto::kdf;
use crate::wire::codec;
use crate::wire::codec::Encode as _;
use alloc::vec;
use core::mem;
use zeroize::Zeroize as _;

use ring::hmac;

pub const KX_MODE_DHE: u8 = 1;

/// Resumption PSKs are always 32-byte / SHA-256 in this implementation, so
/// SHA-384 sessions are not resumable (RFC 8446 §4.2.11).
pub(crate) const RESUMPTION_HASH: hash::Algorithm = hash::Algorithm::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub identity: vec::Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KxModes(vec::Vec<u8>);

impl KxModes {
    pub fn new(modes: vec::Vec<u8>) -> Self {
        Self(modes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(&self) -> Result<vec::Vec<u8>, codec::EncodeError> {
        let mut out = vec::Vec::with_capacity(1 + self.0.len());
        let mut modes = out.begin_u8()?;
        modes.put_slice(&self.0);
        modes.finish()?;
        Ok(out)
    }
}

/// Allocation-free view of a validated `psk_key_exchange_modes` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KxModesRef<'a>(&'a [u8]);

impl<'a> KxModesRef<'a> {
    pub fn decode(data: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(data);
        let modes = codec::FramedVector::<1, 1>::decode_u8(&mut reader)?.as_slice();
        reader.finish()?;
        Ok(Self(modes))
    }

    pub fn as_slice(&self) -> &'a [u8] {
        self.0
    }

    pub fn contains(self, mode: u8) -> bool {
        self.0.contains(&mode)
    }

    pub fn into_owned(self) -> KxModes {
        KxModes(self.0.to_vec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfferRef<'a> {
    pub(crate) identity: &'a [u8],
    pub(crate) obfuscated_ticket_age: u32,
    pub(crate) binder: &'a [u8],
}

/// Allocation-free view of a validated `pre_shared_key` offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferedPsks<'a> {
    encoded: &'a [u8],
    identities: &'a [u8],
    binders: &'a [u8],
    first: OfferRef<'a>,
    count: u16,
    binders_wire_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityRef<'a> {
    pub identity: &'a [u8],
    pub obfuscated_ticket_age: u32,
}

pub struct IdentityRefs<'a> {
    reader: codec::Reader<'a>,
}

pub struct BinderRefs<'a> {
    reader: codec::Reader<'a>,
}

/// A syntactically valid PSK offer proven to be the final ClientHello
/// extension. Every slice is bounded by the borrowed ClientHello.
#[derive(Clone, Copy)]
pub(crate) struct Tail<'a> {
    first: OfferRef<'a>,
    transcript_prefix: &'a [u8],
}

const _: () = assert!(mem::size_of::<Tail<'_>>() <= 64);

impl<'a> OfferedPsks<'a> {
    pub fn decode(data: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(data);
        let identities = codec::FramedVector::<7, 1>::decode_u16(&mut reader)?.as_slice();
        let mut identity_reader = codec::Reader::new(identities);
        let mut first_identity = None;
        let mut identity_count = 0usize;
        while !identity_reader.is_empty() {
            let identity =
                codec::FramedVector::<1, 1>::decode_u16(&mut identity_reader)?.as_slice();
            let obfuscated_ticket_age = identity_reader.u32()?;
            if first_identity.is_none() {
                first_identity = Some((identity, obfuscated_ticket_age));
            }
            identity_count = identity_count
                .checked_add(1)
                .ok_or(codec::DecodeError::InvalidEnum)?;
        }

        let binders_wire_len = reader.remaining().len();
        let binders = codec::FramedVector::<33, 1>::decode_u16(&mut reader)?.as_slice();
        reader.finish()?;
        let mut binder_reader = codec::Reader::new(binders);
        let mut first_binder = None;
        let mut binder_count = 0usize;
        while !binder_reader.is_empty() {
            let binder =
                codec::FramedVector::<{ hash::SHA256_LEN }, 1>::decode_u8(&mut binder_reader)?
                    .as_slice();
            if first_binder.is_none() {
                first_binder = Some(binder);
            }
            binder_count = binder_count
                .checked_add(1)
                .ok_or(codec::DecodeError::InvalidEnum)?;
        }
        if identity_count == 0 || identity_count != binder_count {
            return Err(codec::DecodeError::Trailing);
        }
        let count = u16::try_from(identity_count).map_err(|_| codec::DecodeError::InvalidEnum)?;
        let ((identity, obfuscated_ticket_age), binder) = first_identity
            .zip(first_binder)
            .ok_or(codec::DecodeError::Trailing)?;
        Ok(Self {
            encoded: data,
            identities,
            binders,
            first: OfferRef {
                identity,
                obfuscated_ticket_age,
                binder,
            },
            count,
            binders_wire_len,
        })
    }

    pub fn count(self) -> u16 {
        self.count
    }

    pub(crate) fn encoded_identities(self) -> &'a [u8] {
        self.identities
    }

    pub fn identities(self) -> IdentityRefs<'a> {
        IdentityRefs {
            reader: codec::Reader::new(self.identities),
        }
    }

    pub fn binders(self) -> BinderRefs<'a> {
        BinderRefs {
            reader: codec::Reader::new(self.binders),
        }
    }

    pub(crate) fn bind_tail(self, client_hello: &'a [u8]) -> Result<Tail<'a>, codec::DecodeError> {
        if !client_hello.ends_with(self.encoded) {
            return Err(codec::DecodeError::Trailing);
        }
        let prefix_len = client_hello
            .len()
            .checked_sub(self.binders_wire_len)
            .ok_or(codec::DecodeError::Underflow)?;
        Ok(Tail {
            first: self.first,
            transcript_prefix: &client_hello[..prefix_len],
        })
    }

    pub fn into_owned(self) -> Offer {
        let identities = self
            .identities()
            .map(|identity| Identity {
                identity: identity.identity.to_vec(),
                obfuscated_ticket_age: identity.obfuscated_ticket_age,
            })
            .collect();
        let binders = self.binders().map(<[u8]>::to_vec).collect();
        Offer {
            identities,
            binders,
        }
    }
}

impl<'a> Iterator for IdentityRefs<'a> {
    type Item = IdentityRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some(IdentityRef {
            identity: self.reader.vec_u16().ok()?,
            obfuscated_ticket_age: self.reader.u32().ok()?,
        })
    }
}

impl<'a> Iterator for BinderRefs<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        self.reader.vec_u8().ok()
    }
}

impl<'a> Tail<'a> {
    pub(crate) fn identity(self) -> &'a [u8] {
        self.first.identity
    }

    pub(crate) fn obfuscated_ticket_age(self) -> u32 {
        self.first.obfuscated_ticket_age
    }

    pub(crate) fn binder(self) -> &'a [u8] {
        self.first.binder
    }

    pub(crate) fn transcript_prefix(self) -> &'a [u8] {
        self.transcript_prefix
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub identities: vec::Vec<Identity>,
    pub binders: vec::Vec<vec::Vec<u8>>,
}

impl Offer {
    pub fn new(identities: vec::Vec<Identity>, binders: vec::Vec<vec::Vec<u8>>) -> Self {
        Self {
            identities,
            binders,
        }
    }

    pub fn encode(&self) -> Result<vec::Vec<u8>, codec::EncodeError> {
        let mut out = vec::Vec::new();
        let mut identities = out.begin_u16()?;
        for id in &self.identities {
            let mut identity = identities.begin_u16()?;
            identity.put_slice(&id.identity);
            identity.finish()?;
            identities.put_u32(id.obfuscated_ticket_age);
        }
        identities.finish()?;
        let mut binders = out.begin_u16()?;
        for binder in &self.binders {
            let mut encoded = binders.begin_u8()?;
            encoded.put_slice(binder);
            encoded.finish()?;
        }
        binders.finish()?;
        Ok(out)
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

    pub fn encode(self) -> vec::Vec<u8> {
        let mut out = vec::Vec::with_capacity(2);
        out.put_u16(self.0);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, codec::DecodeError> {
        let mut r = codec::Reader::new(data);
        let v = r.u16()?;
        r.finish()?;
        Ok(Self(v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumptionBinder([u8; hash::SHA256_LEN]);

impl ResumptionBinder {
    pub fn compute(
        psk: &[u8; hash::SHA256_LEN],
        partial_ch_hash: &[u8],
    ) -> Result<Self, kdf::HkdfError> {
        use crate::crypto::hash::Transcript;
        use crate::crypto::kdf::Hkdf;
        use ring::hmac::Key;
        let zero = [0u8; hash::SHA256_LEN];
        let hkdf = Hkdf::new(RESUMPTION_HASH);
        let early_secret = hkdf.extract(&zero, psk);
        let binder_key = hkdf.derive_secret(
            early_secret.as_slice(),
            "res binder",
            Transcript::hash_empty(RESUMPTION_HASH).as_slice(),
        )?;
        let mut finished_key = [0u8; hash::SHA256_LEN];
        hkdf.expand_label(binder_key.as_slice(), "finished", &[], &mut finished_key)?;
        let key = Key::new(RESUMPTION_HASH.hmac(), &finished_key);
        let tag = hmac::sign(&key, partial_ch_hash);
        let mut out = [0u8; hash::SHA256_LEN];
        out.copy_from_slice(tag.as_ref());
        finished_key.zeroize();
        Ok(Self(out))
    }

    pub fn as_slice(&self) -> &[u8; hash::SHA256_LEN] {
        &self.0
    }
}
