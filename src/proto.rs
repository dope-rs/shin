use alloc::vec::Vec;

use ring::hmac;

use crate::codec::{DecodeError, Encode, EncodeError, Reader};
use crate::hash::HASH_LEN;
use crate::kdf::Hkdf;

pub(crate) const TLS_1_3: u16 = 0x0304;
pub(crate) const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
pub(crate) const GROUP_X25519: u16 = 0x001d;

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
        let mut v = Vec::with_capacity(4);
        v.put_vec_u16(|o| o.put_u16(GROUP_X25519));
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
    pub(crate) fn x509_encode() -> Vec<u8> {
        let mut v = Vec::with_capacity(14);
        v.put_vec_u16(|o| {
            o.put_u16(SIG_ECDSA_SECP256R1_SHA256);
            o.put_u16(SIG_RSA_PSS_RSAE_SHA256);
            o.put_u16(SIG_ECDSA_SECP384R1_SHA384);
            o.put_u16(SIG_RSA_PSS_RSAE_SHA384);
            o.put_u16(SIG_RSA_PSS_RSAE_SHA512);
            o.put_u16(SIG_ED25519);
        });
        v
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
    pub(crate) fn client_encode(pubkey: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(40);
        v.put_vec_u16(|o| {
            o.put_u16(GROUP_X25519);
            o.put_vec_u16(|o| o.put_slice(pubkey));
        });
        v
    }

    pub(crate) fn server_encode(pubkey: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(36);
        v.put_u16(GROUP_X25519);
        v.put_vec_u16(|o| o.put_slice(pubkey));
        v
    }

    pub(crate) fn client_decode(data: &[u8]) -> Result<[u8; 32], DecodeError> {
        let mut r = Reader::new(data);
        let mut entries = r.sub_u16()?;
        while !entries.is_empty() {
            let group = entries.u16()?;
            let pubkey_bytes = entries.vec_u16()?;
            if group == GROUP_X25519 {
                if pubkey_bytes.len() != 32 {
                    return Err(DecodeError::InvalidEnum);
                }
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(pubkey_bytes);
                return Ok(pubkey);
            }
        }
        Err(DecodeError::InvalidEnum)
    }

    pub(crate) fn server_decode(data: &[u8]) -> Result<[u8; 32], DecodeError> {
        let mut r = Reader::new(data);
        let group = r.u16()?;
        if group != GROUP_X25519 {
            return Err(DecodeError::InvalidEnum);
        }
        let pubkey_bytes = r.vec_u16()?;
        if pubkey_bytes.len() != 32 {
            return Err(DecodeError::InvalidEnum);
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(pubkey_bytes);
        r.finish()?;
        Ok(pubkey)
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
        traffic_secret: &[u8; HASH_LEN],
        transcript_hash: &[u8],
    ) -> [u8; HASH_LEN] {
        let fkey = Hkdf::finished_key(traffic_secret);
        let key = hmac::Key::new(hmac::HMAC_SHA256, &fkey);
        let tag = hmac::sign(&key, transcript_hash);
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(tag.as_ref());
        out
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
