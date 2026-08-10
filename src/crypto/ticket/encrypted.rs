use crate::crypto::ticket;
use core::ops;

/// An authenticated, opaque session ticket with a protocol-bounded size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub(super) bytes: arrayvec::ArrayVec<u8, { ticket::MAX_LEN }>,
}

impl Encrypted {
    pub(super) fn new() -> Self {
        Self {
            bytes: arrayvec::ArrayVec::new(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for Encrypted {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ops::Deref for Encrypted {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
