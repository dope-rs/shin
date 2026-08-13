use crate::wire::{codec, record};
use alloc::vec;
use core::{mem, ops};

pub(crate) struct BoundedBuffer {
    bytes: vec::Vec<u8>,
    base: usize,
    limit: usize,
    overflowed: bool,
}

impl Default for BoundedBuffer {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl BoundedBuffer {
    pub(crate) fn with_capacity(limit: usize) -> Self {
        Self {
            bytes: vec::Vec::with_capacity(limit),
            base: 0,
            limit,
            overflowed: false,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.bytes.truncate(self.base);
        self.overflowed = false;
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len() - self.base
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) const fn capacity(&self) -> usize {
        self.limit
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[self.base..]
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[self.base..]
    }

    pub(crate) fn try_extend(&mut self, bytes: &[u8]) -> Result<(), codec::EncodeError> {
        if bytes.len() > self.limit - self.len() {
            return Err(codec::EncodeError::Capacity);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn reserve_encoded(&mut self, additional: usize) -> bool {
        if self.overflowed || additional > self.limit - self.len() {
            self.overflowed = true;
            return false;
        }
        true
    }

    pub(crate) fn flight<'buffer, 'outbound>(
        &'buffer mut self,
        outbound: Option<crate::connection::OutboundFlight<'outbound>>,
    ) -> Flight<'buffer, 'outbound> {
        let saved = outbound.as_ref().map(|outbound| Saved {
            base: self.base,
            limit: self.limit,
            overflowed: self.overflowed,
            outbound_base: outbound.base,
        });
        let mut outbound = outbound;
        if let Some(outbound) = outbound.as_mut() {
            mem::swap(&mut self.bytes, outbound.bytes);
            self.base = outbound.base;
            self.limit = outbound.maximum;
            self.overflowed = false;
        }
        Flight {
            buffer: self,
            outbound,
            saved,
            committed: false,
        }
    }
}

struct Saved {
    base: usize,
    limit: usize,
    overflowed: bool,
    outbound_base: usize,
}

pub(crate) struct Flight<'buffer, 'outbound> {
    buffer: &'buffer mut BoundedBuffer,
    outbound: Option<crate::connection::OutboundFlight<'outbound>>,
    saved: Option<Saved>,
    committed: bool,
}

impl Flight<'_, '_> {
    /// Commits newly encoded bytes and reports whether the sink owns them.
    pub(crate) fn commit(mut self) -> bool {
        self.committed = true;
        self.outbound.is_some()
    }
}

impl ops::Deref for Flight<'_, '_> {
    type Target = BoundedBuffer;

    fn deref(&self) -> &Self::Target {
        self.buffer
    }
}

impl ops::DerefMut for Flight<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer
    }
}

impl Drop for Flight<'_, '_> {
    fn drop(&mut self) {
        let (Some(outbound), Some(saved)) = (self.outbound.as_mut(), self.saved.take()) else {
            return;
        };
        if !self.committed {
            self.buffer.bytes.truncate(saved.outbound_base);
        }
        mem::swap(&mut self.buffer.bytes, outbound.bytes);
        self.buffer.base = saved.base;
        self.buffer.limit = saved.limit;
        self.buffer.overflowed = saved.overflowed;
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
        self.len()
    }

    fn reserve_length_prefix(&mut self, width: usize) -> Result<usize, codec::EncodeError> {
        if self.overflowed || !self.reserve_encoded(width) {
            return Err(codec::EncodeError::Capacity);
        }
        let start = self.len();
        self.bytes.resize(self.bytes.len() + width, 0);
        Ok(start)
    }

    fn rollback_to(&mut self, len: usize) {
        self.bytes.truncate(self.base + len);
    }

    fn patch_length_prefix(&mut self, start: usize, width: usize, len: usize) {
        let encoded = (len as u32).to_be_bytes();
        let start = self.base + start;
        self.bytes[start..start + width].copy_from_slice(&encoded[4 - width..]);
    }

    fn status(&self) -> Result<(), codec::EncodeError> {
        (!self.overflowed)
            .then_some(())
            .ok_or(codec::EncodeError::Capacity)
    }
}

impl codec::Reserve for BoundedBuffer {
    fn reserve_slice(&mut self, len: usize) -> Result<&mut [u8], codec::EncodeError> {
        if !self.reserve_encoded(len) {
            return Err(codec::EncodeError::Capacity);
        }
        let start = self.bytes.len();
        self.bytes.resize(start + len, 0);
        Ok(&mut self.bytes[start..])
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

    /// Creates fully reserved, strict no-allocation handshake storage.
    /// On clients, `outbound_flight_capacity` also bounds the phase-disjoint
    /// X.509 peer-key lease.
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

    pub fn for_server() -> Self {
        Self::new(
            Self::DEFAULT_RESERVATION,
            Self::DEFAULT_RESERVATION,
            Self::DEFAULT_RESERVATION,
        )
    }

    pub(crate) fn from_buffers(
        mut reassembly: BoundedBuffer,
        mut flight: BoundedBuffer,
        mut identity: BoundedBuffer,
    ) -> Self {
        reassembly.clear();
        flight.clear();
        identity.clear();
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
