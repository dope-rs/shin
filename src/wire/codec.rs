use alloc::vec;

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

    fn begin_u8(&mut self) -> Result<LengthFrame<'_, Self>, EncodeError>
    where
        Self: Sized,
    {
        LengthFrame::begin(self, 1, u8::MAX as usize)
    }

    fn begin_u16(&mut self) -> Result<LengthFrame<'_, Self>, EncodeError>
    where
        Self: Sized,
    {
        LengthFrame::begin(self, 2, u16::MAX as usize)
    }

    fn begin_u24(&mut self) -> Result<LengthFrame<'_, Self>, EncodeError>
    where
        Self: Sized,
    {
        LengthFrame::begin(self, 3, (1 << 24) - 1)
    }

    #[doc(hidden)]
    fn encoded_len(&self) -> usize;

    #[doc(hidden)]
    fn reserve_length_prefix(&mut self, width: usize) -> Result<usize, EncodeError>;

    #[doc(hidden)]
    fn rollback_to(&mut self, len: usize);

    #[doc(hidden)]
    fn patch_length_prefix(&mut self, start: usize, width: usize, len: usize);

    #[doc(hidden)]
    fn status(&self) -> Result<(), EncodeError>;
}

/// A checked length-prefixed scope: dropping it rolls back, while
/// [`finish`](Self::finish) reports wire-length overflow.
#[must_use]
pub struct LengthFrame<'a, E: Encode> {
    target: &'a mut E,
    start: usize,
    body_start: usize,
    width: usize,
    maximum: usize,
    active: bool,
}

impl<'a, E: Encode> LengthFrame<'a, E> {
    fn begin(target: &'a mut E, width: usize, maximum: usize) -> Result<Self, EncodeError> {
        target.status()?;
        let start = target.reserve_length_prefix(width)?;
        let body_start = target.encoded_len();
        Ok(Self {
            target,
            start,
            body_start,
            width,
            maximum,
            active: true,
        })
    }

    pub fn finish(mut self) -> Result<(), EncodeError> {
        if let Err(error) = self.target.status() {
            self.target.rollback_to(self.start);
            self.active = false;
            return Err(error);
        }
        let len = self.target.encoded_len() - self.body_start;
        if len > self.maximum {
            self.target.rollback_to(self.start);
            self.active = false;
            return Err(EncodeError::Overflow);
        }
        self.target.patch_length_prefix(self.start, self.width, len);
        self.active = false;
        Ok(())
    }
}

impl<E: Encode> Drop for LengthFrame<'_, E> {
    fn drop(&mut self) {
        if self.active {
            self.target.rollback_to(self.start);
        }
    }
}

impl<E: Encode> Encode for LengthFrame<'_, E> {
    fn put_u8(&mut self, v: u8) {
        self.target.put_u8(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.target.put_u16(v);
    }

    fn put_u24(&mut self, v: u32) {
        self.target.put_u24(v);
    }

    fn put_u32(&mut self, v: u32) {
        self.target.put_u32(v);
    }

    fn put_slice(&mut self, s: &[u8]) {
        self.target.put_slice(s);
    }

    fn encoded_len(&self) -> usize {
        self.target.encoded_len()
    }

    fn reserve_length_prefix(&mut self, width: usize) -> Result<usize, EncodeError> {
        self.target.reserve_length_prefix(width)
    }

    fn rollback_to(&mut self, len: usize) {
        self.target.rollback_to(len);
    }

    fn patch_length_prefix(&mut self, start: usize, width: usize, len: usize) {
        self.target.patch_length_prefix(start, width, len);
    }

    fn status(&self) -> Result<(), EncodeError> {
        self.target.status()
    }
}

/// Sizes wire encoding with the same overflow rules as serialization.
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

    fn encoded_len(&self) -> usize {
        self.len
    }

    fn reserve_length_prefix(&mut self, width: usize) -> Result<usize, EncodeError> {
        if self.overflowed {
            return Err(EncodeError::Overflow);
        }
        let start = self.len;
        self.extend(width);
        if self.overflowed {
            self.len = start;
            Err(EncodeError::Overflow)
        } else {
            Ok(start)
        }
    }

    fn rollback_to(&mut self, len: usize) {
        self.len = len;
    }

    fn patch_length_prefix(&mut self, _: usize, _: usize, _: usize) {}

    fn status(&self) -> Result<(), EncodeError> {
        (!self.overflowed)
            .then_some(())
            .ok_or(EncodeError::Overflow)
    }
}

impl Encode for vec::Vec<u8> {
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

    fn encoded_len(&self) -> usize {
        self.len()
    }

    fn reserve_length_prefix(&mut self, width: usize) -> Result<usize, EncodeError> {
        let start = self.len();
        self.resize(start + width, 0);
        Ok(start)
    }

    fn rollback_to(&mut self, len: usize) {
        self.truncate(len);
    }

    fn patch_length_prefix(&mut self, start: usize, width: usize, len: usize) {
        let bytes = (len as u32).to_be_bytes();
        self[start..start + width].copy_from_slice(&bytes[4 - width..]);
    }

    fn status(&self) -> Result<(), EncodeError> {
        Ok(())
    }
}
