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
    fn put_vec_u8<F: FnOnce(&mut Self)>(&mut self, body: F);
    fn put_vec_u16<F: FnOnce(&mut Self)>(&mut self, body: F);
    fn put_vec_u24<F: FnOnce(&mut Self)>(&mut self, body: F);
    fn try_put_vec_u8<F: FnOnce(&mut Self)>(&mut self, body: F) -> Result<(), EncodeError>;
    fn try_put_vec_u16<F: FnOnce(&mut Self)>(&mut self, body: F) -> Result<(), EncodeError>;
    fn try_put_vec_u24<F: FnOnce(&mut Self)>(&mut self, body: F) -> Result<(), EncodeError>;
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

    fn put_vec_u8<F: FnOnce(&mut Self)>(&mut self, body: F) {
        self.try_put_vec_u8(body).expect("vec_u8 body too large");
    }

    fn put_vec_u16<F: FnOnce(&mut Self)>(&mut self, body: F) {
        self.try_put_vec_u16(body).expect("vec_u16 body too large");
    }

    fn put_vec_u24<F: FnOnce(&mut Self)>(&mut self, body: F) {
        self.try_put_vec_u24(body).expect("vec_u24 body too large");
    }

    fn try_put_vec_u8<F: FnOnce(&mut Self)>(&mut self, body: F) -> Result<(), EncodeError> {
        let len_pos = self.len();
        self.push(0);
        let body_start = self.len();
        body(self);
        let len = u8::try_from(self.len() - body_start).map_err(|_| EncodeError::Overflow)?;
        self[len_pos] = len;
        Ok(())
    }

    fn try_put_vec_u16<F: FnOnce(&mut Self)>(&mut self, body: F) -> Result<(), EncodeError> {
        let len_pos = self.len();
        self.extend_from_slice(&[0, 0]);
        let body_start = self.len();
        body(self);
        let len = u16::try_from(self.len() - body_start).map_err(|_| EncodeError::Overflow)?;
        self[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }

    fn try_put_vec_u24<F: FnOnce(&mut Self)>(&mut self, body: F) -> Result<(), EncodeError> {
        let len_pos = self.len();
        self.extend_from_slice(&[0, 0, 0]);
        let body_start = self.len();
        body(self);
        let len = self.len() - body_start;
        let bytes = u32::try_from(len)
            .ok()
            .filter(|n| *n < 1 << 24)
            .ok_or(EncodeError::Overflow)?
            .to_be_bytes();
        self[len_pos..len_pos + 3].copy_from_slice(&bytes[1..]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_put_vec_u8_overflow() {
        let mut v = Vec::new();
        let big = alloc::vec![0u8; 256];
        assert_eq!(
            v.try_put_vec_u8(|o| o.put_slice(&big)),
            Err(EncodeError::Overflow)
        );
    }

    #[test]
    fn try_put_vec_u8_ok() {
        let mut v = Vec::new();
        let body = alloc::vec![7u8; 255];
        assert_eq!(v.try_put_vec_u8(|o| o.put_slice(&body)), Ok(()));
        assert_eq!(v[0], 255);
        assert_eq!(v.len(), 256);
    }

    #[test]
    fn try_put_vec_u16_overflow() {
        let mut v = Vec::new();
        let big = alloc::vec![0u8; 65536];
        assert_eq!(
            v.try_put_vec_u16(|o| o.put_slice(&big)),
            Err(EncodeError::Overflow)
        );
    }

    #[test]
    fn try_put_vec_u24_overflow() {
        let mut v = Vec::new();
        let big = alloc::vec![0u8; 1 << 24];
        assert_eq!(
            v.try_put_vec_u24(|o| o.put_slice(&big)),
            Err(EncodeError::Overflow)
        );
    }
}
