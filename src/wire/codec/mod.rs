use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Underflow,
    InvalidEnum,
    Trailing,
    DuplicateExtension,
    TooManyCertificates,
    HandshakeTooLarge,
    HandshakeSpansEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    Overflow,
    Capacity,
}

pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.buf
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.buf.len() {
            return Err(DecodeError::Underflow);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn take_all(&mut self) -> &'a [u8] {
        let s = self.buf;
        self.buf = &[];
        s
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u24(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn vec_u8(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    pub fn vec_u16(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    pub fn vec_u24(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u24()? as usize;
        self.take(n)
    }

    pub fn sub_u8(&mut self) -> Result<Self, DecodeError> {
        Ok(Self::new(self.vec_u8()?))
    }

    pub fn sub_u16(&mut self) -> Result<Self, DecodeError> {
        Ok(Self::new(self.vec_u16()?))
    }

    pub fn sub_u24(&mut self) -> Result<Self, DecodeError> {
        Ok(Self::new(self.vec_u24()?))
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }
}

pub trait Encode {
    fn put_u8(&mut self, v: u8);
    fn put_u16(&mut self, v: u16);
    fn put_u24(&mut self, v: u32);
    fn put_u32(&mut self, v: u32);
    fn put_slice(&mut self, s: &[u8]);
    fn put_vec_u8<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>;
    fn put_vec_u16<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>;
    fn put_vec_u24<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>;
}

/// Runs a wire encoder without materializing bytes.
///
/// Length-prefixed fields use the same overflow rules as real encoders, so a
/// sizing pass cannot silently approve a message that serialization rejects.
#[derive(Default)]
pub(crate) struct EncodedSize {
    len: usize,
    overflowed: bool,
}

impl EncodedSize {
    pub(crate) fn finish(self) -> Result<usize, EncodeError> {
        if self.overflowed {
            Err(EncodeError::Overflow)
        } else {
            Ok(self.len)
        }
    }

    fn extend(&mut self, len: usize) {
        match self.len.checked_add(len) {
            Some(total) => self.len = total,
            None => self.overflowed = true,
        }
    }

    fn encode_length<F>(&mut self, width: usize, maximum: usize, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        let start = self.len;
        self.extend(width);
        let body_start = self.len;
        if let Err(error) = body(self) {
            self.len = start;
            return Err(error);
        }
        if self.overflowed || self.len - body_start > maximum {
            self.len = start;
            return Err(EncodeError::Overflow);
        }
        Ok(())
    }
}

impl Encode for EncodedSize {
    fn put_u8(&mut self, _: u8) {
        self.extend(1);
    }

    fn put_u16(&mut self, _: u16) {
        self.extend(2);
    }

    fn put_u24(&mut self, _: u32) {
        self.extend(3);
    }

    fn put_u32(&mut self, _: u32) {
        self.extend(4);
    }

    fn put_slice(&mut self, bytes: &[u8]) {
        self.extend(bytes.len());
    }

    fn put_vec_u8<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        self.encode_length(1, u8::MAX as usize, body)
    }

    fn put_vec_u16<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        self.encode_length(2, u16::MAX as usize, body)
    }

    fn put_vec_u24<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        self.encode_length(3, (1 << 24) - 1, body)
    }
}

impl Encode for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_be_bytes());
    }

    fn put_u24(&mut self, v: u32) {
        let b = v.to_be_bytes();
        self.extend_from_slice(&b[1..]);
    }

    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_be_bytes());
    }

    fn put_slice(&mut self, s: &[u8]) {
        self.extend_from_slice(s);
    }

    fn put_vec_u8<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        let len_pos = self.len();
        self.push(0);
        let body_start = self.len();
        if let Err(error) = body(self) {
            self.truncate(len_pos);
            return Err(error);
        }
        let Ok(len) = u8::try_from(self.len() - body_start) else {
            self.truncate(len_pos);
            return Err(EncodeError::Overflow);
        };
        self[len_pos] = len;
        Ok(())
    }

    fn put_vec_u16<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        let len_pos = self.len();
        self.extend_from_slice(&[0, 0]);
        let body_start = self.len();
        if let Err(error) = body(self) {
            self.truncate(len_pos);
            return Err(error);
        }
        let Ok(len) = u16::try_from(self.len() - body_start) else {
            self.truncate(len_pos);
            return Err(EncodeError::Overflow);
        };
        self[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }

    fn put_vec_u24<F>(&mut self, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        let len_pos = self.len();
        self.extend_from_slice(&[0, 0, 0]);
        let body_start = self.len();
        if let Err(error) = body(self) {
            self.truncate(len_pos);
            return Err(error);
        }
        let len = self.len() - body_start;
        let Ok(len) = u32::try_from(len) else {
            self.truncate(len_pos);
            return Err(EncodeError::Overflow);
        };
        if len >= 1 << 24 {
            self.truncate(len_pos);
            return Err(EncodeError::Overflow);
        }
        let bytes = len.to_be_bytes();
        self[len_pos..len_pos + 3].copy_from_slice(&bytes[1..]);
        Ok(())
    }
}
