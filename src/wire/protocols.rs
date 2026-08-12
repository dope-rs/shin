use crate::crypto::sig;
use crate::identity;
use crate::wire::codec;
use alloc::vec;
use core::cmp;
use core::mem;
use core::num;

pub(crate) const TLS_1_3: u16 = 0x0304;

fn require_empty(data: &[u8]) -> Result<(), codec::DecodeError> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(codec::DecodeError::Trailing)
    }
}

/// Proof that an `early_data` indication carried its required empty body.
#[derive(Clone, Copy)]
pub(crate) struct EarlyDataSignal(());

impl EarlyDataSignal {
    pub(crate) fn decode(data: &[u8]) -> Result<Self, codec::DecodeError> {
        require_empty(data)?;
        Ok(Self(()))
    }
}

const _: () = assert!(mem::size_of::<Option<EarlyDataSignal>>() <= 1);

/// Proof that a `server_name` acknowledgement carried its required empty body.
pub(crate) struct ServerNameAck(());

impl ServerNameAck {
    pub(crate) fn decode(data: &[u8]) -> Result<Self, codec::DecodeError> {
        require_empty(data)?;
        Ok(Self(()))
    }
}

/// Proof that a server `supported_groups` response is a non-empty NamedGroupList.
pub(crate) struct ServerSupportedGroups(());

impl ServerSupportedGroups {
    pub(crate) fn decode(data: &[u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(data);
        codec::FramedVector::<2, 2>::decode_u16(&mut reader)?;
        reader.finish()?;
        Ok(Self(()))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SupportedVersions<'a> {
    encoded: &'a [u8],
}

impl<'a> SupportedVersions<'a> {
    pub(crate) fn decode_client(data: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(data);
        let versions = codec::FramedVector::<2, 2>::decode_u8(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            encoded: versions.as_slice(),
        })
    }

    pub(crate) fn contains(self, version: u16) -> bool {
        let mut reader = codec::Reader::new(self.encoded);
        while !reader.is_empty() {
            if reader.u16().ok() == Some(version) {
                return true;
            }
        }
        false
    }

    pub(crate) fn decode_server(data: &[u8]) -> Result<u16, codec::DecodeError> {
        let mut r = codec::Reader::new(data);
        let v = r.u16()?;
        r.finish()?;
        Ok(v)
    }
}

pub(crate) struct SignatureAlgorithms(&'static [sig::SignatureScheme]);

impl SignatureAlgorithms {
    pub(crate) const X509: [sig::SignatureScheme; 6] = [
        sig::SignatureScheme::ECDSA_SECP256R1_SHA256,
        sig::SignatureScheme::RSA_PSS_RSAE_SHA256,
        sig::SignatureScheme::ECDSA_SECP384R1_SHA384,
        sig::SignatureScheme::RSA_PSS_RSAE_SHA384,
        sig::SignatureScheme::RSA_PSS_RSAE_SHA512,
        sig::SignatureScheme::ED25519,
    ];
    const RPK: [sig::SignatureScheme; 1] = [sig::SignatureScheme::ED25519];

    pub(crate) fn x509() -> Self {
        Self(&Self::X509)
    }

    pub(crate) fn rpk() -> Self {
        Self(&Self::RPK)
    }

    pub(crate) fn as_slice(&self) -> &'static [sig::SignatureScheme] {
        self.0
    }

    pub(crate) fn x509_supported(scheme: sig::SignatureScheme) -> bool {
        Self::X509.contains(&scheme)
    }

    pub(crate) fn accepts(
        data: &[u8],
        candidate: Option<sig::SignatureScheme>,
    ) -> Result<bool, codec::DecodeError> {
        let mut reader = codec::Reader::new(data);
        let schemes = codec::FramedVector::<2, 2>::decode_u16(&mut reader)?;
        reader.finish()?;
        let mut schemes = schemes.reader();
        let mut found = false;
        while !schemes.is_empty() {
            let scheme = schemes.u16()?;
            found |= candidate.is_some_and(|candidate| scheme == candidate.wire_id());
        }
        Ok(found)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ServerKeyShare<'a> {
    group: u16,
    key_exchange: &'a [u8],
}

impl<'a> ServerKeyShare<'a> {
    pub(crate) fn decode(data: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut r = codec::Reader::new(data);
        let group = r.u16()?;
        let key_exchange = codec::FramedVector::<1, 1>::decode_u16(&mut r)?.as_slice();
        r.finish()?;
        Ok(Self {
            group,
            key_exchange,
        })
    }

    pub(crate) fn group(self) -> u16 {
        self.group
    }

    pub(crate) fn key_exchange(self) -> &'a [u8] {
        self.key_exchange
    }
}

/// A HelloRetryRequest key_share carries only the server's selected group
/// (RFC 8446 §4.2.8), not a full KeyShareEntry.
#[derive(Clone, Copy)]
pub(crate) struct RetryKeyShare {
    group: u16,
}

impl RetryKeyShare {
    pub(crate) fn decode(data: &[u8]) -> Result<Self, codec::DecodeError> {
        let mut r = codec::Reader::new(data);
        let group = r.u16()?;
        r.finish()?;
        Ok(Self { group })
    }

    pub(crate) fn group(self) -> u16 {
        self.group
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Alpn<'a> {
    encoded: &'a [u8],
    len: usize,
}

impl<'a> Alpn<'a> {
    pub(crate) fn decode(data: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut r = codec::Reader::new(data);
        let encoded = codec::FramedVector::<2, 1>::decode_u16(&mut r)?.as_slice();
        r.finish()?;
        let mut list = codec::Reader::new(encoded);
        let mut len = 0;
        while !list.is_empty() {
            codec::FramedVector::<1, 1>::decode_u8(&mut list)?;
            len += 1;
        }
        Ok(Self { encoded, len })
    }

    pub(crate) fn len(self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(self) -> bool {
        self.len == 0
    }

    pub(crate) fn iter(self) -> AlpnIter<'a> {
        AlpnIter {
            reader: codec::Reader::new(self.encoded),
        }
    }
}

/// A validated, borrowed HelloRetryRequest cookie extension body.
#[derive(Clone, Copy)]
pub(crate) struct Cookie<'a>(&'a [u8]);

const _: () = assert!(mem::size_of::<Cookie<'_>>() == mem::size_of::<&[u8]>());

impl<'a> Cookie<'a> {
    pub(crate) fn decode(data: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(data);
        codec::FramedVector::<1, 1>::decode_u16(&mut reader)?;
        reader.finish()?;
        Ok(Self(data))
    }

    pub(crate) fn encoded(self) -> &'a [u8] {
        self.0
    }
}

pub(crate) struct AlpnIter<'a> {
    reader: codec::Reader<'a>,
}

impl<'a> Iterator for AlpnIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        self.reader.vec_u8().ok()
    }
}

pub(crate) const MAX_ALPN_PROTOCOLS: usize = u16::MAX as usize;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AlpnId(num::NonZeroU16);

impl AlpnId {
    fn from_index(index: usize) -> Option<Self> {
        let encoded = u16::try_from(index).ok()?.checked_add(1)?;
        Some(Self(num::NonZeroU16::new(encoded)?))
    }

    fn index(self) -> usize {
        usize::from(self.0.get() - 1)
    }
}

pub(crate) struct PreparedAlpn {
    preferred: vec::Vec<vec::Vec<u8>>,
    by_name: vec::Vec<AlpnId>,
}

impl PreparedAlpn {
    pub(crate) fn prepare(preferred: vec::Vec<vec::Vec<u8>>) -> Result<Self, ()> {
        Self::validate(&preferred)?;
        let mut by_name = vec::Vec::with_capacity(preferred.len());
        for index in 0..preferred.len() {
            by_name.push(AlpnId::from_index(index).ok_or(())?);
        }
        by_name.sort_unstable_by(|left, right| {
            let order = match (preferred.get(left.index()), preferred.get(right.index())) {
                (Some(left), Some(right)) => left.cmp(right),
                (None, Some(_)) => cmp::Ordering::Less,
                (Some(_), None) => cmp::Ordering::Greater,
                (None, None) => cmp::Ordering::Equal,
            };
            order.then_with(|| left.cmp(right))
        });
        by_name.dedup_by(|left, right| preferred.get(left.index()) == preferred.get(right.index()));
        Ok(Self { preferred, by_name })
    }

    pub(crate) fn validate(protocols: &[vec::Vec<u8>]) -> Result<(), ()> {
        if protocols.len() > MAX_ALPN_PROTOCOLS
            || protocols
                .iter()
                .any(|protocol| protocol.is_empty() || protocol.len() > u8::MAX as usize)
        {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn preferred(&self) -> &[vec::Vec<u8>] {
        &self.preferred
    }

    pub(crate) fn find(&self, protocol: &[u8]) -> Option<AlpnId> {
        let position = self.by_name.binary_search_by(|id| {
            self.preferred
                .get(id.index())
                .map(vec::Vec::as_slice)
                .map_or(cmp::Ordering::Less, |candidate| candidate.cmp(protocol))
        });
        position
            .ok()
            .and_then(|index| self.by_name.get(index).copied())
    }

    pub(crate) fn get(&self, id: AlpnId) -> Option<&[u8]> {
        self.preferred.get(id.index()).map(vec::Vec::as_slice)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.preferred.is_empty()
    }
}

const _: () = assert!(mem::size_of::<Option<AlpnId>>() == mem::size_of::<u16>());

#[derive(Clone, Copy)]
pub(crate) struct CertificateTypeList<'a>(&'a [u8]);

impl<'a> CertificateTypeList<'a> {
    pub(crate) fn decode(data: &'a [u8]) -> Result<Self, codec::DecodeError> {
        let mut reader = codec::Reader::new(data);
        let types = codec::FramedVector::<1, 1>::decode_u8(&mut reader)?.as_slice();
        reader.finish()?;
        Ok(Self(types))
    }

    pub(crate) fn decode_selection(
        data: &[u8],
    ) -> Result<identity::CertificateType, codec::DecodeError> {
        let [id] = data else {
            return Err(codec::DecodeError::InvalidEnum);
        };
        identity::CertificateType::from_wire_id(*id).ok_or(codec::DecodeError::InvalidEnum)
    }

    pub(crate) fn contains(self, ty: identity::CertificateType) -> bool {
        self.0.contains(&ty.wire_id())
    }

    pub(crate) fn select(self) -> Option<identity::CertificateType> {
        self.0
            .iter()
            .copied()
            .find_map(identity::CertificateType::from_wire_id)
    }
}
