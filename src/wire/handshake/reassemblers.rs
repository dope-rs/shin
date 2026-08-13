use crate::connection;
use crate::memory::threadbound;
use crate::wire::codec;
use crate::wire::handshake::storage;
use core::mem;

/// Saturating peer-triggered KeyUpdate allowance, reset at a progress boundary.
#[derive(Default)]
pub(crate) struct KeyUpdateBudget<const LIMIT: u32> {
    state: u32,
}

impl<const LIMIT: u32> KeyUpdateBudget<LIMIT> {
    const RESPONSE_PENDING: u32 = 1 << 31;
    const VALID_LIMIT: () = assert!(LIMIT < Self::RESPONSE_PENDING);

    pub(crate) fn consume(&mut self) -> bool {
        let () = Self::VALID_LIMIT;
        let count = self.state & !Self::RESPONSE_PENDING;
        if count >= LIMIT {
            return false;
        }
        self.state = (count + 1) | (self.state & Self::RESPONSE_PENDING);
        true
    }

    pub(crate) fn reset(&mut self) {
        self.state &= Self::RESPONSE_PENDING;
    }

    pub(crate) fn response_pending(&self) -> bool {
        self.state & Self::RESPONSE_PENDING != 0
    }

    pub(crate) fn request_response(&mut self) {
        self.state |= Self::RESPONSE_PENDING;
    }

    pub(crate) fn clear_response(&mut self) {
        self.state &= !Self::RESPONSE_PENDING;
    }
}

/// Reassembles fragmented or coalesced handshake messages with their transcript
/// bytes; a message may not cross record epochs (RFC 8446 §5.1).
pub(crate) struct HsReassembler {
    buf: storage::BoundedBuffer,
    epoch: Option<connection::Epoch>,
    key_updates: KeyUpdateBudget<{ super::MAX_KEY_UPDATES_PER_RECORD }>,
    _thread: threadbound::ThreadBound,
}

impl HsReassembler {
    pub(crate) fn with_buffer(buffer: storage::BoundedBuffer) -> Self {
        Self {
            buf: buffer,
            epoch: None,
            key_updates: KeyUpdateBudget::default(),
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    fn begin_record(&mut self, epoch: connection::Epoch) -> Result<(), codec::DecodeError> {
        if !self.buf.is_empty() && self.epoch != Some(epoch) {
            return Err(codec::DecodeError::HandshakeSpansEpoch);
        }
        self.key_updates.reset();
        Ok(())
    }

    /// Processes a record while retaining fragmented-message storage.
    /// The callback lifetime prevents decoded views from escaping this scope,
    /// eliminating an external recycling protocol.
    pub(crate) fn read<E>(
        &mut self,
        epoch: connection::Epoch,
        mut input: &[u8],
        mut process: impl for<'message> FnMut(&'message [u8]) -> Result<(), connection::DriveError<E>>,
    ) -> Result<(), connection::DriveError<E>> {
        self.begin_record(epoch)?;
        loop {
            if self.buf.is_empty() {
                if input.is_empty() {
                    return Ok(());
                }
                if input.len() >= 4 {
                    let msg_len = super::encoded_message_len(input)?;
                    if input.len() >= msg_len {
                        let (raw, rest) = input.split_at(msg_len);
                        input = rest;
                        self.validate_message(raw[0])?;
                        process(raw)?;
                        continue;
                    }
                }
                self.append(input)?;
                self.epoch = Some(epoch);
                return Ok(());
            }

            debug_assert_eq!(self.epoch, Some(epoch));
            if self.buf.len() < 4 {
                let take = (4 - self.buf.len()).min(input.len());
                self.append(&input[..take])?;
                input = &input[take..];
                if self.buf.len() < 4 {
                    return Ok(());
                }
            }

            let msg_len = super::encoded_message_len(&self.buf)?;
            let needed = msg_len
                .checked_sub(self.buf.len())
                .ok_or(codec::DecodeError::Trailing)?;
            let take = needed.min(input.len());
            self.append(&input[..take])?;
            input = &input[take..];
            if self.buf.len() < msg_len {
                return Ok(());
            }

            self.epoch = None;
            let result = self
                .validate_message(self.buf.as_slice()[0])
                .map_err(connection::DriveError::from)
                .and_then(|()| process(self.buf.as_slice()));
            self.buf.clear();
            result?;
        }
    }

    pub(crate) fn release_buffer(&mut self) -> storage::BoundedBuffer {
        self.epoch = None;
        self.key_updates.reset();
        let mut buffer = mem::take(&mut self.buf);
        buffer.clear();
        buffer
    }

    pub(crate) fn discard(&mut self) {
        self.buf.clear();
        self.epoch = None;
        self.key_updates.reset();
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), connection::Error> {
        use crate::connection::WorkspaceRegion;
        self.buf
            .try_extend(bytes)
            .map_err(|_| connection::Error::WorkspaceExhausted(WorkspaceRegion::FragmentedMessage))
    }

    fn validate_message(&mut self, ty: u8) -> Result<(), connection::Error> {
        if ty == super::Type::KeyUpdate as u8 && !self.key_updates.consume() {
            return Err(connection::Error::UnexpectedMessage);
        }
        Ok(())
    }
}

impl Default for HsReassembler {
    fn default() -> Self {
        Self::with_buffer(storage::BoundedBuffer::default())
    }
}
