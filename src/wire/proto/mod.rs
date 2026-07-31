use crate::crypto::kx::KexGroup;
use crate::wire::codec::{DecodeError, Reader};

pub(crate) const TLS_1_3: u16 = 0x0304;

pub(crate) const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub(crate) const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub(crate) const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub(crate) const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub(crate) const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub(crate) const SIG_ED25519: u16 = 0x0807;

pub(crate) const CERT_TYPE_X509: u8 = 0;
pub(crate) const CERT_TYPE_RAW_PUBLIC_KEY: u8 = 2;

#[derive(Clone, Copy)]
pub(crate) struct SupportedVersions<'a> {
    encoded: &'a [u8],
}

impl<'a> SupportedVersions<'a> {
    pub(crate) fn decode_client(data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(data);
        let mut versions = reader.sub_u8()?;
        while !versions.is_empty() {
            versions.u16()?;
        }
        reader.finish()?;
        Ok(Self { encoded: data })
    }

    pub(crate) fn contains(self, version: u16) -> bool {
        let mut reader = Reader::new(self.encoded);
        let Ok(mut versions) = reader.sub_u8() else {
            return false;
        };
        while !versions.is_empty() {
            if versions.u16().ok() == Some(version) {
                return true;
            }
        }
        false
    }

    pub(crate) fn decode_server(data: &[u8]) -> Result<u16, DecodeError> {
        let mut r = Reader::new(data);
        let v = r.u16()?;
        r.finish()?;
        Ok(v)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SupportedGroups<'a> {
    encoded: &'a [u8],
}

impl<'a> SupportedGroups<'a> {
    pub(crate) fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(data);
        let mut groups = reader.sub_u16()?;
        while !groups.is_empty() {
            groups.u16()?;
        }
        reader.finish()?;
        Ok(Self { encoded: data })
    }

    pub(crate) fn contains(self, group: u16) -> bool {
        let mut reader = Reader::new(self.encoded);
        let Ok(mut groups) = reader.sub_u16() else {
            return false;
        };
        while !groups.is_empty() {
            if groups.u16().ok() == Some(group) {
                return true;
            }
        }
        false
    }
}

pub(crate) struct SignatureAlgorithms(&'static [u16]);

impl SignatureAlgorithms {
    pub(crate) const X509: [u16; 6] = [
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_RSA_PSS_RSAE_SHA512,
        SIG_ED25519,
    ];
    const RPK: [u16; 1] = [SIG_ED25519];

    pub(crate) fn x509() -> Self {
        Self(&Self::X509)
    }

    pub(crate) fn rpk() -> Self {
        Self(&Self::RPK)
    }

    pub(crate) fn as_slice(&self) -> &'static [u16] {
        self.0
    }

    pub(crate) fn x509_supported(scheme: u16) -> bool {
        Self::X509.contains(&scheme)
    }

    pub(crate) fn contains(data: &[u8], scheme: u16) -> Result<bool, DecodeError> {
        let mut reader = Reader::new(data);
        let mut schemes = reader.sub_u16()?;
        let mut found = false;
        while !schemes.is_empty() {
            found |= schemes.u16()? == scheme;
        }
        reader.finish()?;
        Ok(found)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct KeyShares<'a> {
    encoded: &'a [u8],
}

impl<'a> KeyShares<'a> {
    pub(crate) fn decode_client(data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(data);
        let mut entries = reader.sub_u16()?;
        while !entries.is_empty() {
            entries.u16()?;
            entries.vec_u16()?;
        }
        reader.finish()?;
        Ok(Self { encoded: data })
    }

    /// The first offered entry whose group is in `prefer` (server-preference
    /// order), copying only the chosen public key.
    pub(crate) fn select_client_entry(self, prefer: &[KexGroup]) -> Option<(KexGroup, &'a [u8])> {
        let mut r = Reader::new(self.encoded);
        let mut entries = match r.sub_u16() {
            Ok(entries) => entries,
            Err(_) => return None,
        };
        let mut selected = None;
        let mut selected_rank = usize::MAX;
        while !entries.is_empty() {
            let group = entries.u16().ok()?;
            let pubkey = entries.vec_u16().ok()?;
            if let Some((rank, preferred)) = prefer
                .iter()
                .copied()
                .enumerate()
                .find(|(_, preferred)| preferred.wire_id() == group)
                && rank < selected_rank
            {
                selected = Some((preferred, pubkey));
                selected_rank = rank;
            }
        }
        selected
    }

    /// A HelloRetryRequest key_share carries only the server's selected group
    /// (RFC 8446 §4.2.8), not a full KeyShareEntry.
    pub(crate) fn decode_hrr(data: &[u8]) -> Result<u16, DecodeError> {
        let mut r = Reader::new(data);
        let group = r.u16()?;
        r.finish()?;
        Ok(group)
    }

    pub(crate) fn decode_server(data: &[u8]) -> Result<(u16, &[u8]), DecodeError> {
        let mut r = Reader::new(data);
        let group = r.u16()?;
        let pubkey = r.vec_u16()?;
        r.finish()?;
        Ok((group, pubkey))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Alpn<'a> {
    encoded: &'a [u8],
    len: usize,
}

impl<'a> Alpn<'a> {
    pub(crate) fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let encoded = r.vec_u16()?;
        r.finish()?;
        let mut list = Reader::new(encoded);
        let mut len = 0;
        while !list.is_empty() {
            let p = list.vec_u8()?;
            if p.is_empty() {
                return Err(DecodeError::InvalidEnum);
            }
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
            reader: Reader::new(self.encoded),
        }
    }
}

pub(crate) struct AlpnIter<'a> {
    reader: Reader<'a>,
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

#[derive(Clone, Copy)]
pub(crate) struct CertificateTypes<'a> {
    encoded: &'a [u8],
}

impl<'a> CertificateTypes<'a> {
    pub(crate) fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(data);
        reader.vec_u8()?;
        reader.finish()?;
        Ok(Self { encoded: data })
    }

    pub(crate) fn contains(self, ty: u8) -> bool {
        let mut reader = Reader::new(self.encoded);
        reader
            .vec_u8()
            .is_ok_and(|certificate_types| certificate_types.contains(&ty))
    }

    pub(crate) fn select(self) -> Option<u8> {
        let mut reader = Reader::new(self.encoded);
        reader
            .vec_u8()
            .ok()?
            .iter()
            .copied()
            .find(|ty| *ty == CERT_TYPE_X509 || *ty == CERT_TYPE_RAW_PUBLIC_KEY)
    }
}
