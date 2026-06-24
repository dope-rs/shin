use alloc::vec::Vec;

use crate::codec::{DecodeError, Encode, Reader};

pub const MAX_EXTENSIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    pub const SERVER_NAME: Self = Self(0);
    pub const SUPPORTED_GROUPS: Self = Self(10);
    pub const SIGNATURE_ALGORITHMS: Self = Self(13);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(16);
    pub const CLIENT_CERTIFICATE_TYPE: Self = Self(19);
    pub const SERVER_CERTIFICATE_TYPE: Self = Self(20);
    pub const PRE_SHARED_KEY: Self = Self(41);
    pub const EARLY_DATA: Self = Self(42);
    pub const SUPPORTED_VERSIONS: Self = Self(43);
    pub const COOKIE: Self = Self(44);
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(45);
    pub const KEY_SHARE: Self = Self(51);
    pub const QUIC_TRANSPORT_PARAMETERS: Self = Self(57);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub ty: ExtensionType,
    pub data: Vec<u8>,
}

impl Extension {
    pub fn new(ty: ExtensionType, data: Vec<u8>) -> Self {
        Self { ty, data }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.ty.0);
        out.put_vec_u16(|o| o.put_slice(&self.data));
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let ty = ExtensionType(r.u16()?);
        let data = r.vec_u16()?.to_vec();
        Ok(Self { ty, data })
    }

    pub fn encode_list(exts: &[Self], out: &mut Vec<u8>) {
        out.put_vec_u16(|o| {
            for ext in exts {
                ext.encode(o);
            }
        });
    }

    pub fn decode_list(r: &mut Reader<'_>) -> Result<Vec<Self>, DecodeError> {
        let mut sub = r.sub_u16()?;
        let mut out: Vec<Self> = Vec::new();
        let mut seen: Vec<u16> = Vec::new();
        while !sub.is_empty() {
            if out.len() >= MAX_EXTENSIONS {
                return Err(DecodeError::InvalidEnum);
            }
            let ext = Self::decode(&mut sub)?;
            match seen.binary_search(&ext.ty.0) {
                Ok(_) => return Err(DecodeError::DuplicateExtension),
                Err(pos) => seen.insert(pos, ext.ty.0),
            }
            out.push(ext);
        }
        Ok(out)
    }
}
