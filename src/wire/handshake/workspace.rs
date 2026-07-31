use alloc::vec::Vec;
use core::ops::Deref;

use crate::wire::codec::{Encode, EncodeError};

use super::MAX_HANDSHAKE_SIZE;

pub(crate) struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl Default for BoundedBuffer {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl BoundedBuffer {
    fn with_capacity(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit),
            limit,
            overflowed: false,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
        self.overflowed = false;
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.limit
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(crate) fn try_extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(EncodeError::Capacity);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn reserve_encoded(&mut self, additional: usize) -> bool {
        if self.overflowed || additional > self.limit - self.bytes.len() {
            self.overflowed = true;
            return false;
        }
        true
    }

    fn encode_length<F>(&mut self, width: usize, maximum: usize, body: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        if self.overflowed {
            return Err(EncodeError::Capacity);
        }
        let start = self.bytes.len();
        if !self.reserve_encoded(width) {
            return Err(EncodeError::Capacity);
        }
        self.bytes.resize(start + width, 0);
        let body_start = self.bytes.len();
        if let Err(error) = body(self) {
            self.bytes.truncate(start);
            return Err(error);
        }
        if self.overflowed {
            self.bytes.truncate(start);
            return Err(EncodeError::Capacity);
        }
        let len = self.bytes.len() - body_start;
        if len > maximum {
            self.bytes.truncate(start);
            return Err(EncodeError::Overflow);
        }
        let encoded = (len as u32).to_be_bytes();
        self.bytes[start..start + width].copy_from_slice(&encoded[4 - width..]);
        Ok(())
    }
}

impl AsRef<[u8]> for BoundedBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for BoundedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Encode for BoundedBuffer {
    fn put_u8(&mut self, v: u8) {
        if self.reserve_encoded(1) {
            self.bytes.push(v);
        }
    }

    fn put_u16(&mut self, v: u16) {
        self.put_slice(&v.to_be_bytes());
    }

    fn put_u24(&mut self, v: u32) {
        self.put_slice(&v.to_be_bytes()[1..]);
    }

    fn put_u32(&mut self, v: u32) {
        self.put_slice(&v.to_be_bytes());
    }

    fn put_slice(&mut self, bytes: &[u8]) {
        if self.reserve_encoded(bytes.len()) {
            self.bytes.extend_from_slice(bytes);
        }
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

/// Recyclable storage allocated once for input, flights, and peer identity.
pub struct HandshakeWorkspace {
    pub(crate) reassembly: BoundedBuffer,
    pub(crate) flight: BoundedBuffer,
    pub(crate) identity: BoundedBuffer,
}

impl HandshakeWorkspace {
    pub fn new(
        fragmented_message_capacity: usize,
        outbound_flight_capacity: usize,
        peer_identity_capacity: usize,
    ) -> Self {
        Self {
            reassembly: BoundedBuffer::with_capacity(fragmented_message_capacity),
            flight: BoundedBuffer::with_capacity(outbound_flight_capacity),
            identity: BoundedBuffer::with_capacity(peer_identity_capacity),
        }
    }

    pub fn for_client() -> Self {
        Self::new(MAX_HANDSHAKE_SIZE, MAX_HANDSHAKE_SIZE, 0)
    }

    pub fn for_server() -> Self {
        Self::new(MAX_HANDSHAKE_SIZE, MAX_HANDSHAKE_SIZE, MAX_HANDSHAKE_SIZE)
    }

    pub(crate) fn from_buffers(
        reassembly: BoundedBuffer,
        flight: BoundedBuffer,
        identity: BoundedBuffer,
    ) -> Self {
        Self {
            reassembly,
            flight,
            identity,
        }
    }

    pub fn capacities(&self) -> (usize, usize, usize) {
        (
            self.reassembly.capacity(),
            self.flight.capacity(),
            self.identity.capacity(),
        )
    }
}
