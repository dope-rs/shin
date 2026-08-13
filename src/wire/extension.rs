use crate::wire::codec;
use crate::wire::codec::Encode as _;
use alloc::vec;
use o3::collections::fixed::array;

pub const MAX_EXTENSIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Type(pub u16);

impl Type {
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
    pub ty: Type,
    pub data: vec::Vec<u8>,
}

impl Extension {
    pub fn new(ty: Type, data: vec::Vec<u8>) -> Self {
        Self { ty, data }
    }

    pub fn encode(&self, out: &mut impl codec::Encode) -> Result<(), codec::EncodeError> {
        out.put_u16(self.ty.0);
        let mut data = out.begin_u16()?;
        data.put_slice(&self.data);
        data.finish()
    }

    pub(crate) fn begin<E: codec::Encode>(
        out: &mut E,
        ty: Type,
    ) -> Result<codec::LengthFrame<'_, E>, codec::EncodeError> {
        out.put_u16(ty.0);
        out.begin_u16()
    }

    pub fn encode_list(
        exts: &[Self],
        out: &mut impl codec::Encode,
    ) -> Result<(), codec::EncodeError> {
        let mut list = out.begin_u16()?;
        for ext in exts {
            ext.encode(&mut list)?;
        }
        list.finish()
    }
}

/// Allocation-free view of one validated extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ref<'a> {
    pub ty: Type,
    pub data: &'a [u8],
}

impl<'a> Ref<'a> {
    fn decode(r: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(Self {
            ty: Type(r.u16()?),
            data: r.vec_u16()?,
        })
    }

    pub fn into_owned(self) -> Extension {
        Extension::new(self.ty, self.data.to_vec())
    }
}

/// Validated, allocation-free view of an encoded extension list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extensions<'a> {
    encoded: &'a [u8],
}

impl<'a> Extensions<'a> {
    pub fn decode(r: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let encoded = r.vec_u16()?;
        let mut reader = codec::Reader::new(encoded);
        let mut seen = array::CopyInline::<u16, MAX_EXTENSIONS>::new();
        while !reader.is_empty() {
            let extension = Ref::decode(&mut reader)?;
            match seen.binary_search(&extension.ty.0) {
                Ok(_) => return Err(codec::DecodeError::DuplicateExtension),
                Err(position) if seen.insert(position, extension.ty.0).is_err() => {
                    return Err(codec::DecodeError::InvalidEnum);
                }
                Err(_) => {}
            }
        }
        Ok(Self { encoded })
    }

    pub fn iter(self) -> Refs<'a> {
        Refs {
            reader: codec::Reader::new(self.encoded),
        }
    }

    pub fn find(self, ty: Type) -> Option<Ref<'a>> {
        self.iter().find(|extension| extension.ty == ty)
    }

    pub fn into_owned(self) -> vec::Vec<Extension> {
        self.iter().map(Ref::into_owned).collect()
    }
}

pub struct Refs<'a> {
    reader: codec::Reader<'a>,
}

impl<'a> Iterator for Refs<'a> {
    type Item = Ref<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Ref::decode(&mut self.reader).ok()
    }
}
