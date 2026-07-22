use alloc::vec::Vec;

use crate::codec::{DecodeError, Reader};
use crate::{Epoch, Error};

use super::{Handshake, MAX_HANDSHAKE_SIZE, MAX_KEY_UPDATES_PER_RECORD};

/// Saturating peer-triggered KeyUpdate allowance, reset at a progress boundary.
#[derive(Default)]
pub(crate) struct KeyUpdateBudget<const LIMIT: u32> {
    used: u32,
}

impl<const LIMIT: u32> KeyUpdateBudget<LIMIT> {
    pub(crate) fn consume(&mut self) -> bool {
        if self.used >= LIMIT {
            return false;
        }
        self.used += 1;
        true
    }

    pub(crate) fn reset(&mut self) {
        self.used = 0;
    }
}

/// Reassembles fragmented or coalesced handshake messages with their transcript
/// bytes; a message may not cross record epochs (RFC 8446 §5.1).
#[derive(Default)]
pub struct HsReassembler {
    buf: Vec<u8>,
    pos: usize,
    epoch: Option<Epoch>,
    key_updates: KeyUpdateBudget<MAX_KEY_UPDATES_PER_RECORD>,
}

impl HsReassembler {
    /// Append one record after compacting bytes consumed from prior records.
    pub fn push(&mut self, epoch: Epoch, data: &[u8]) -> Result<(), DecodeError> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        if !self.buf.is_empty() && self.epoch != Some(epoch) {
            return Err(DecodeError::HandshakeSpansEpoch);
        }
        self.buf.extend_from_slice(data);
        self.epoch = Some(epoch);
        self.key_updates.reset();
        Ok(())
    }

    /// Decode the next complete message and retain any remaining bytes.
    pub fn next_message(&mut self) -> Result<Option<(Handshake, Vec<u8>)>, Error> {
        let buf = &self.buf[self.pos..];
        if buf.len() < 4 {
            return Ok(None);
        }
        let msg_len = 4 + u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        if msg_len > MAX_HANDSHAKE_SIZE {
            return Err(DecodeError::HandshakeTooLarge.into());
        }
        if buf.len() < msg_len {
            return Ok(None);
        }
        let raw = buf[..msg_len].to_vec();
        self.pos += msg_len;

        let mut reader = Reader::new(&raw);
        let message = Handshake::decode(&mut reader)?;
        reader.finish()?;
        if matches!(message, Handshake::KeyUpdate(_)) && !self.key_updates.consume() {
            return Err(Error::UnexpectedMessage);
        }
        Ok(Some((message, raw)))
    }
}
