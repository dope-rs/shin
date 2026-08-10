use crate::wire::{codec, record};
use alloc::vec;
use core::ops;

pub(crate) struct BoundedBuffer {
    bytes: vec::Vec<u8>,
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
        Self::with_reservation(limit, limit)
    }

    fn with_reservation(limit: usize, reservation: usize) -> Self {
        Self {
            bytes: vec::Vec::with_capacity(reservation.min(limit)),
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

    pub(crate) fn try_extend(&mut self, bytes: &[u8]) -> Result<(), codec::EncodeError> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(codec::EncodeError::Capacity);
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
}

impl AsRef<[u8]> for BoundedBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ops::Deref for BoundedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl codec::Encode for BoundedBuffer {
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

    fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    fn reserve_length_prefix(&mut self, width: usize) -> Result<usize, codec::EncodeError> {
        if self.overflowed || !self.reserve_encoded(width) {
            return Err(codec::EncodeError::Capacity);
        }
        let start = self.bytes.len();
        self.bytes.resize(start + width, 0);
        Ok(start)
    }

    fn rollback_to(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    fn patch_length_prefix(&mut self, start: usize, width: usize, len: usize) {
        let encoded = (len as u32).to_be_bytes();
        self.bytes[start..start + width].copy_from_slice(&encoded[4 - width..]);
    }

    fn status(&self) -> Result<(), codec::EncodeError> {
        (!self.overflowed)
            .then_some(())
            .ok_or(codec::EncodeError::Capacity)
    }
}

/// Recyclable bounded storage for input, flights, and peer identity.
pub struct Scratch {
    pub(crate) reassembly: BoundedBuffer,
    pub(crate) flight: BoundedBuffer,
    pub(crate) identity: BoundedBuffer,
}

impl Scratch {
    const DEFAULT_RESERVATION: usize = record::MAX_PLAINTEXT_BODY;

    /// Creates a workspace whose logical limits are fully reserved up front.
    /// This is the strict no-allocation profile for callers that know their
    /// maximum handshake sizes.
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
        Self::with_reservations(
            super::MAX_SIZE,
            super::MAX_SIZE,
            0,
            Self::DEFAULT_RESERVATION,
            Self::DEFAULT_RESERVATION,
            0,
        )
    }

    pub fn for_server() -> Self {
        Self::with_reservations(
            super::MAX_SIZE,
            super::MAX_SIZE,
            super::MAX_SIZE,
            Self::DEFAULT_RESERVATION,
            Self::DEFAULT_RESERVATION,
            0,
        )
    }

    fn with_reservations(
        fragmented_message_capacity: usize,
        outbound_flight_capacity: usize,
        peer_identity_capacity: usize,
        fragmented_message_reservation: usize,
        outbound_flight_reservation: usize,
        peer_identity_reservation: usize,
    ) -> Self {
        Self {
            reassembly: BoundedBuffer::with_reservation(
                fragmented_message_capacity,
                fragmented_message_reservation,
            ),
            flight: BoundedBuffer::with_reservation(
                outbound_flight_capacity,
                outbound_flight_reservation,
            ),
            identity: BoundedBuffer::with_reservation(
                peer_identity_capacity,
                peer_identity_reservation,
            ),
        }
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
