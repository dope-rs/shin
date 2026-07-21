use alloc::vec::Vec;

use crate::codec::{DecodeError, Encode, EncodeError, Reader};
use crate::kx::KexGroup;

pub(crate) const TLS_1_3: u16 = 0x0304;

pub(crate) const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub(crate) const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub(crate) const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub(crate) const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub(crate) const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub(crate) const SIG_ED25519: u16 = 0x0807;

pub(crate) const CERT_TYPE_X509: u8 = 0;
pub(crate) const CERT_TYPE_RAW_PUBLIC_KEY: u8 = 2;

pub(crate) struct SupportedVersions(u16);

impl SupportedVersions {
    pub(crate) fn tls13() -> Self {
        Self(TLS_1_3)
    }

    pub(crate) fn client_encode(self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(3);
        v.put_vec_u8(|o| {
            o.put_u16(self.0);
            Ok(())
        })?;
        Ok(v)
    }

    pub(crate) fn server_encode(self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2);
        v.put_u16(self.0);
        v
    }

    pub(crate) fn client_decode(data: &[u8]) -> Result<Vec<u16>, DecodeError> {
        let mut r = Reader::new(data);
        let mut sub = r.sub_u8()?;
        let mut out = Vec::new();
        while !sub.is_empty() {
            out.push(sub.u16()?);
        }
        r.finish()?;
        Ok(out)
    }

    pub(crate) fn server_decode(data: &[u8]) -> Result<u16, DecodeError> {
        let mut r = Reader::new(data);
        let v = r.u16()?;
        r.finish()?;
        Ok(v)
    }
}

pub(crate) struct SupportedGroups(&'static [KexGroup]);

impl SupportedGroups {
    pub(crate) fn supported() -> Self {
        Self(&KexGroup::SUPPORTED)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(6);
        v.put_vec_u16(|o| {
            for g in self.0 {
                o.put_u16(g.to_u16());
            }
            Ok(())
        })?;
        Ok(v)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Vec<u16>, DecodeError> {
        let mut r = Reader::new(data);
        let mut sub = r.sub_u16()?;
        let mut out = Vec::new();
        while !sub.is_empty() {
            out.push(sub.u16()?);
        }
        r.finish()?;
        Ok(out)
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

    pub(crate) fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(2 + self.0.len() * 2);
        v.put_vec_u16(|o| {
            for s in self.0 {
                o.put_u16(*s);
            }
            Ok(())
        })?;
        Ok(v)
    }

    pub(crate) fn x509_supported(scheme: u16) -> bool {
        Self::X509.contains(&scheme)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Vec<u16>, DecodeError> {
        let mut r = Reader::new(data);
        let mut sub = r.sub_u16()?;
        let mut out = Vec::new();
        while !sub.is_empty() {
            out.push(sub.u16()?);
        }
        r.finish()?;
        Ok(out)
    }
}

pub(crate) struct KeyShare<'a> {
    group: KexGroup,
    pubkey: &'a [u8],
}

impl<'a> KeyShare<'a> {
    pub(crate) fn new(group: KexGroup, pubkey: &'a [u8]) -> Self {
        Self { group, pubkey }
    }

    pub(crate) fn client_encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(8 + self.pubkey.len());
        v.put_vec_u16(|o| {
            o.put_u16(self.group.to_u16());
            o.put_vec_u16(|o| {
                o.put_slice(self.pubkey);
                Ok(())
            })
        })?;
        Ok(v)
    }

    pub(crate) fn server_encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(4 + self.pubkey.len());
        v.put_u16(self.group.to_u16());
        v.put_vec_u16(|o| {
            o.put_slice(self.pubkey);
            Ok(())
        })?;
        Ok(v)
    }

    /// HelloRetryRequest key_share: the selected group only (RFC 8446 §4.2.8).
    pub(crate) fn hrr_encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2);
        v.put_u16(self.group.to_u16());
        v
    }

    /// The first offered entry whose group is in `prefer` (server-preference
    /// order), copying only the chosen public key.
    pub(crate) fn select_client_entry(
        data: &[u8],
        prefer: &[KexGroup],
    ) -> Result<Option<(KexGroup, Vec<u8>)>, DecodeError> {
        let mut r = Reader::new(data);
        let mut entries = r.sub_u16()?;
        let mut offered: Vec<(u16, &[u8])> = Vec::new();
        while !entries.is_empty() {
            let group = entries.u16()?;
            offered.push((group, entries.vec_u16()?));
        }
        r.finish()?;
        Ok(prefer.iter().copied().find_map(|g| {
            offered
                .iter()
                .find(|(eg, _)| *eg == g.to_u16())
                .map(|(_, pk)| (g, pk.to_vec()))
        }))
    }

    /// A HelloRetryRequest key_share carries only the server's selected group
    /// (RFC 8446 §4.2.8), not a full KeyShareEntry.
    pub(crate) fn hrr_selected_group(data: &[u8]) -> Result<u16, DecodeError> {
        let mut r = Reader::new(data);
        let group = r.u16()?;
        r.finish()?;
        Ok(group)
    }

    pub(crate) fn server_decode(data: &[u8]) -> Result<(u16, Vec<u8>), DecodeError> {
        let mut r = Reader::new(data);
        let group = r.u16()?;
        let pubkey = r.vec_u16()?.to_vec();
        r.finish()?;
        Ok((group, pubkey))
    }
}

pub(crate) struct Alpn<'a>(&'a [Vec<u8>]);

impl<'a> Alpn<'a> {
    pub(crate) fn new(protocols: &'a [Vec<u8>]) -> Self {
        Self(protocols)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(2 + self.0.iter().map(|p| 1 + p.len()).sum::<usize>());
        v.put_vec_u16(|o| {
            for p in self.0 {
                o.put_vec_u8(|o| {
                    o.put_slice(p);
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(v)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Vec<Vec<u8>>, DecodeError> {
        let mut r = Reader::new(data);
        let mut list = r.sub_u16()?;
        let mut out = Vec::new();
        while !list.is_empty() {
            let p = list.vec_u8()?;
            out.push(p.to_vec());
        }
        r.finish()?;
        Ok(out)
    }
}

pub(crate) struct ServerName<'a>(&'a [u8]);

impl<'a> ServerName<'a> {
    pub(crate) fn new(hostname: &'a [u8]) -> Self {
        Self(hostname)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(5 + self.0.len());
        v.put_vec_u16(|o| {
            o.put_u8(0);
            o.put_vec_u16(|o| {
                o.put_slice(self.0);
                Ok(())
            })
        })?;
        Ok(v)
    }
}

pub(crate) struct CertType(u8);

impl CertType {
    pub(crate) fn new(ty: u8) -> Self {
        Self(ty)
    }

    pub(crate) fn encode_list(self) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(2);
        v.put_vec_u8(|o| {
            o.put_u8(self.0);
            Ok(())
        })?;
        Ok(v)
    }

    pub(crate) fn encode_single(self) -> Vec<u8> {
        alloc::vec![self.0]
    }

    pub(crate) fn decode_list(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let mut r = Reader::new(data);
        let mut sub = r.sub_u8()?;
        let mut out = Vec::new();
        while !sub.is_empty() {
            out.push(sub.u8()?);
        }
        r.finish()?;
        Ok(out)
    }
}
