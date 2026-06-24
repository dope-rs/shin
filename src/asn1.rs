use alloc::vec::Vec;

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

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Tlv<'a>, DerError> {
        let (tlv, rest) = Tlv::parse_one(self.bytes)?;
        self.bytes = rest;
        Ok(tlv)
    }

    pub fn expect(&mut self, tag: Tag) -> Result<&'a [u8], DerError> {
        let tlv = self.next()?;
        if tlv.tag != tag {
            return Err(DerError::Mismatch);
        }
        Ok(tlv.contents)
    }

    pub fn peek_tag(&self) -> Option<Tag> {
        self.bytes.first().copied().map(Tag)
    }

    pub fn read_optional(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, DerError> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.expect(tag)?))
        } else {
            Ok(None)
        }
    }

    pub fn bytes_remaining(&self) -> &'a [u8] {
        self.bytes
    }
}

impl<'a> Tlv<'a> {
    pub fn parse_one(input: &'a [u8]) -> Result<(Self, &'a [u8]), DerError> {
        let &tag_byte = input.first().ok_or(DerError::Underflow)?;
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
        let &first = input.first().ok_or(DerError::Underflow)?;
        let after = &input[1..];
        if first & 0x80 == 0 {
            return Ok((first as usize, after));
        }
        let n = (first & 0x7f) as usize;
        if n == 0 {
            return Err(DerError::BadLength);
        }
        if n > core::mem::size_of::<usize>() {
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

    pub fn integer_be(contents: &[u8]) -> Result<&[u8], DerError> {
        if contents.is_empty() {
            return Err(DerError::BadInteger);
        }
        if contents.len() >= 2 && contents[0] == 0 && contents[1] & 0x80 == 0 {
            return Err(DerError::BadInteger);
        }
        if contents[0] & 0x80 != 0 {
            return Err(DerError::BadInteger);
        }
        if contents.len() > 1 && contents[0] == 0 {
            Ok(&contents[1..])
        } else {
            Ok(contents)
        }
    }

    pub fn integer_u64(contents: &[u8]) -> Result<u64, DerError> {
        let bytes = Self::integer_be(contents)?;
        if bytes.len() > 8 {
            return Err(DerError::BadInteger);
        }
        let mut v = 0u64;
        for &b in bytes {
            v = (v << 8) | (b as u64);
        }
        Ok(v)
    }

    pub fn bit_string(contents: &[u8]) -> Result<&[u8], DerError> {
        let &unused = contents.first().ok_or(DerError::BadBitString)?;
        if unused > 7 {
            return Err(DerError::BadBitString);
        }
        if unused != 0 {
            return Err(DerError::BadBitString);
        }
        Ok(&contents[1..])
    }

    pub fn oid(contents: &[u8]) -> Result<Vec<u32>, DerError> {
        if contents.is_empty() {
            return Err(DerError::BadOid);
        }
        let mut out = Vec::with_capacity(8);
        let first = contents[0] as u32;
        out.push(first / 40);
        out.push(first % 40);
        let mut i = 1;
        while i < contents.len() {
            if contents[i] == 0x80 {
                return Err(DerError::BadOid);
            }
            let mut value: u32 = 0;
            let mut bits = 0u32;
            loop {
                let b = contents[i];
                i += 1;
                bits += 7;
                if bits > 32 {
                    return Err(DerError::BadOid);
                }
                value = (value << 7) | ((b & 0x7f) as u32);
                if b & 0x80 == 0 {
                    break;
                }
                if i >= contents.len() {
                    return Err(DerError::BadOid);
                }
            }
            out.push(value);
        }
        Ok(out)
    }

    pub fn oid_eq(contents: &[u8], expected: &[u8]) -> bool {
        contents == expected
    }

    pub fn boolean(contents: &[u8]) -> Result<bool, DerError> {
        match contents {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DerError::BadBool),
        }
    }
}
