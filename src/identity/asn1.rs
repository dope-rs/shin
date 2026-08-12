#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    Underflow,
    BadTag,
    BadLength,
    Trailing,
    BadInteger,
    BadOid,
    BadBitString,
    BadBool,
    NotConstructed,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag(pub u8);

impl Tag {
    pub const BOOLEAN: Self = Self(0x01);
    pub const INTEGER: Self = Self(0x02);
    pub const BIT_STRING: Self = Self(0x03);
    pub const OCTET_STRING: Self = Self(0x04);
    pub const NULL: Self = Self(0x05);
    pub const OID: Self = Self(0x06);
    pub const UTF8_STRING: Self = Self(0x0c);
    pub const PRINTABLE_STRING: Self = Self(0x13);
    pub const TELETEX_STRING: Self = Self(0x14);
    pub const IA5_STRING: Self = Self(0x16);
    pub const UTC_TIME: Self = Self(0x17);
    pub const GENERALIZED_TIME: Self = Self(0x18);
    pub const SEQUENCE: Self = Self(0x30);
    pub const SET: Self = Self(0x31);

    pub const fn context(n: u8, constructed: bool) -> Self {
        let cls = 0xa0;
        let mut byte = cls | (n & 0x1f);
        if !constructed {
            byte &= 0x9f;
        }
        Self(byte)
    }

    pub fn is_constructed(&self) -> bool {
        (self.0 & 0x20) != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub contents: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oid<'a> {
    bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uint<'a> {
    encoded: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitString<'a> {
    contents: &'a [u8],
}

pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn finish(self) -> Result<(), DerError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(DerError::Trailing)
        }
    }

    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, DerError> {
        let (tlv, rest) = Tlv::parse_one(self.bytes)?;
        self.bytes = rest;
        Ok(tlv)
    }

    pub fn read_tagged(&mut self, tag: Tag) -> Result<&'a [u8], DerError> {
        let tlv = self.read_tlv()?;
        if tlv.tag != tag {
            return Err(DerError::Mismatch);
        }
        Ok(tlv.contents)
    }

    pub fn read_oid(&mut self) -> Result<Oid<'a>, DerError> {
        Oid::from_bytes(self.read_tagged(Tag::OID)?)
    }

    pub fn read_uint(&mut self) -> Result<Uint<'a>, DerError> {
        Uint::from_bytes(self.read_tagged(Tag::INTEGER)?)
    }

    pub fn read_bool(&mut self) -> Result<bool, DerError> {
        match self.read_tagged(Tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DerError::BadBool),
        }
    }

    pub fn read_bit_string(&mut self) -> Result<BitString<'a>, DerError> {
        BitString::from_bytes(self.read_tagged(Tag::BIT_STRING)?)
    }

    pub fn read_optional_bit_string(
        &mut self,
        tag: Tag,
    ) -> Result<Option<BitString<'a>>, DerError> {
        self.read_optional(tag)?
            .map(BitString::from_bytes)
            .transpose()
    }

    pub fn peek_tag(&self) -> Option<Tag> {
        self.bytes.first().copied().map(Tag)
    }

    pub fn read_optional(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, DerError> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.read_tagged(tag)?))
        } else {
            Ok(None)
        }
    }

    pub fn bytes_remaining(&self) -> &'a [u8] {
        self.bytes
    }
}

impl<'a> Oid<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, DerError> {
        if bytes.is_empty() {
            return Err(DerError::BadOid);
        }
        let mut subidentifier_start = true;
        for byte in bytes {
            if subidentifier_start && *byte == 0x80 {
                return Err(DerError::BadOid);
            }
            subidentifier_start = byte & 0x80 == 0;
        }
        if !subidentifier_start {
            return Err(DerError::BadOid);
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn is(self, expected: &[u8]) -> bool {
        self.bytes == expected
    }
}

impl<'a> Uint<'a> {
    pub fn from_bytes(encoded: &'a [u8]) -> Result<Self, DerError> {
        if encoded.is_empty()
            || encoded[0] & 0x80 != 0
            || encoded.len() >= 2 && encoded[0] == 0 && encoded[1] & 0x80 == 0
        {
            return Err(DerError::BadInteger);
        }
        Ok(Self { encoded })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.encoded
    }

    pub fn magnitude(self) -> &'a [u8] {
        match self.encoded {
            [0, rest @ ..] if !rest.is_empty() => rest,
            encoded => encoded,
        }
    }

    pub fn is_zero(self) -> bool {
        self.encoded == [0]
    }

    pub fn to_u64(&self) -> Result<u64, DerError> {
        let bytes = self.magnitude();
        if bytes.len() > 8 {
            return Err(DerError::BadInteger);
        }
        Ok(bytes
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
    }
}

impl<'a> BitString<'a> {
    pub fn from_bytes(contents: &'a [u8]) -> Result<Self, DerError> {
        let (&unused_bits, bytes) = contents.split_first().ok_or(DerError::BadBitString)?;
        if unused_bits > 7
            || bytes.is_empty() && unused_bits != 0
            || unused_bits != 0
                && bytes
                    .last()
                    .is_some_and(|last| last & ((1 << unused_bits) - 1) != 0)
        {
            return Err(DerError::BadBitString);
        }
        Ok(Self { contents })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        &self.contents[1..]
    }

    pub fn unused_bits(self) -> u8 {
        self.contents[0]
    }

    pub fn octets(self) -> Result<&'a [u8], DerError> {
        if self.unused_bits() == 0 {
            Ok(self.as_bytes())
        } else {
            Err(DerError::BadBitString)
        }
    }
}

impl<'a> Tlv<'a> {
    pub fn parse_one(input: &'a [u8]) -> Result<(Self, &'a [u8]), DerError> {
        let &tag_byte = input.first().ok_or(DerError::Underflow)?;
        if tag_byte == 0 || tag_byte & 0x1f == 0x1f {
            return Err(DerError::BadTag);
        }
        let tag = Tag(tag_byte);
        let after_tag = &input[1..];
        let (length, after_length) = Self::parse_length(after_tag)?;
        if after_length.len() < length {
            return Err(DerError::Underflow);
        }
        let (contents, rest) = after_length.split_at(length);
        Ok((Self { tag, contents }, rest))
    }

    fn parse_length(input: &[u8]) -> Result<(usize, &[u8]), DerError> {
        use core::mem::size_of;
        let &first = input.first().ok_or(DerError::Underflow)?;
        let after = &input[1..];
        if first & 0x80 == 0 {
            return Ok((first as usize, after));
        }
        let n = (first & 0x7f) as usize;
        if n == 0 {
            return Err(DerError::BadLength);
        }
        if n > size_of::<usize>() {
            return Err(DerError::BadLength);
        }
        if after.len() < n {
            return Err(DerError::Underflow);
        }
        let (len_bytes, rest) = after.split_at(n);
        if len_bytes[0] == 0 {
            return Err(DerError::BadLength);
        }
        let mut len = 0usize;
        for &b in len_bytes {
            len = (len << 8) | (b as usize);
        }
        if len < 0x80 {
            return Err(DerError::BadLength);
        }
        Ok((len, rest))
    }
}
