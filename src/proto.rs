use alloc::vec::Vec;

use ring::hmac;

use crate::codec::{DecodeError, Encode, EncodeError, Reader};
use crate::hash::{Digest, HashAlg, MAX_HASH_LEN};
use crate::kdf::Hkdf;
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

pub(crate) struct SupportedVersions;

impl SupportedVersions {
    pub(crate) fn client_encode() -> Vec<u8> {
        let mut v = Vec::with_capacity(3);
        v.put_vec_u8(|o| o.put_u16(TLS_1_3));
        v
    }

    pub(crate) fn server_encode() -> Vec<u8> {
        let mut v = Vec::with_capacity(2);
        v.put_u16(TLS_1_3);
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

pub(crate) struct SupportedGroups;

impl SupportedGroups {
    pub(crate) fn encode() -> Vec<u8> {
        let mut v = Vec::with_capacity(6);
        v.put_vec_u16(|o| {
            for g in KexGroup::SUPPORTED {
                o.put_u16(g.to_u16());
            }
        });
        v
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

pub(crate) struct SignatureAlgorithms;

impl SignatureAlgorithms {
    pub(crate) const X509: [u16; 6] = [
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_RSA_PSS_RSAE_SHA512,
        SIG_ED25519,
    ];

    pub(crate) fn x509_encode() -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + Self::X509.len() * 2);
        v.put_vec_u16(|o| {
            for s in Self::X509 {
                o.put_u16(s);
            }
        });
        v
    }

    pub(crate) fn x509_supported(scheme: u16) -> bool {
        Self::X509.contains(&scheme)
    }

    pub(crate) fn rpk_encode() -> Vec<u8> {
        let mut v = Vec::with_capacity(4);
        v.put_vec_u16(|o| o.put_u16(SIG_ED25519));
        v
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

pub(crate) struct KeyShare;

impl KeyShare {
    pub(crate) fn client_encode(group: KexGroup, pubkey: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + pubkey.len());
        v.put_vec_u16(|o| {
            o.put_u16(group.to_u16());
            o.put_vec_u16(|o| o.put_slice(pubkey));
        });
        v
    }

    pub(crate) fn server_encode(group: KexGroup, pubkey: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + pubkey.len());
        v.put_u16(group.to_u16());
        v.put_vec_u16(|o| o.put_slice(pubkey));
        v
    }

    /// HelloRetryRequest key_share: the selected group only (RFC 8446 §4.2.8).
    pub(crate) fn hrr_encode(group: KexGroup) -> Vec<u8> {
        let mut v = Vec::with_capacity(2);
        v.put_u16(group.to_u16());
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

pub(crate) struct Alpn;

impl Alpn {
    pub(crate) fn encode(protocols: &[Vec<u8>]) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(2 + protocols.iter().map(|p| 1 + p.len()).sum::<usize>());
        let mut err = None;
        v.try_put_vec_u16(|o| {
            for p in protocols {
                if let Err(e) = o.try_put_vec_u8(|o| o.put_slice(p)) {
                    err = Some(e);
                }
            }
        })?;
        if let Some(e) = err {
            return Err(e);
        }
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

pub(crate) struct ServerName;

impl ServerName {
    pub(crate) fn encode(hostname: &[u8]) -> Result<Vec<u8>, EncodeError> {
        let mut v = Vec::with_capacity(5 + hostname.len());
        let mut err = None;
        v.try_put_vec_u16(|o| {
            o.put_u8(0);
            if let Err(e) = o.try_put_vec_u16(|o| o.put_slice(hostname)) {
                err = Some(e);
            }
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        Ok(v)
    }
}

pub(crate) struct CertType;

impl CertType {
    pub(crate) fn encode_list(ty: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(2);
        v.put_vec_u8(|o| o.put_u8(ty));
        v
    }

    pub(crate) fn encode_single(ty: u8) -> Vec<u8> {
        alloc::vec![ty]
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

pub(crate) struct CertVerify;

impl CertVerify {
    pub(crate) fn message(transcript_hash: &[u8], from_server: bool) -> Vec<u8> {
        let context = if from_server {
            b"TLS 1.3, server CertificateVerify".as_slice()
        } else {
            b"TLS 1.3, client CertificateVerify".as_slice()
        };
        let mut msg = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
        msg.resize(64, 0x20);
        msg.extend_from_slice(context);
        msg.push(0x00);
        msg.extend_from_slice(transcript_hash);
        msg
    }
}

pub(crate) struct Finished;

impl Finished {
    pub(crate) fn verify_data(
        alg: HashAlg,
        traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Digest {
        let mut fkey_buf = [0u8; MAX_HASH_LEN];
        let fkey = &mut fkey_buf[..alg.output_len()];
        Hkdf::expand_label(alg, traffic_secret, "finished", &[], fkey);
        let key = hmac::Key::new(crate::kdf::hmac_alg(alg), fkey);
        let mac = Digest::from_slice(hmac::sign(&key, transcript_hash).as_ref());
        crate::schedule::zeroize(fkey);
        mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_encode_ok() {
        let protocols = alloc::vec![b"h3".to_vec(), b"hq".to_vec()];
        assert!(Alpn::encode(&protocols).is_ok());
    }

    #[test]
    fn alpn_encode_oversized_protocol() {
        let protocols = alloc::vec![alloc::vec![0u8; 256]];
        assert_eq!(Alpn::encode(&protocols), Err(EncodeError::Overflow));
    }

    #[test]
    fn server_name_encode_ok() {
        assert!(ServerName::encode(b"example.com").is_ok());
    }

    #[test]
    fn server_name_encode_oversized() {
        let hostname = alloc::vec![b'a'; 65536];
        assert_eq!(ServerName::encode(&hostname), Err(EncodeError::Overflow));
    }
}
