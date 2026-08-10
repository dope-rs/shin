use crate::connection;
use crate::memory::threadbound;
use crate::wire::codec;
use crate::wire::handshake::workspace;
use core::mem;

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
pub(crate) struct HsReassembler {
    buf: workspace::BoundedBuffer,
    epoch: Option<connection::Epoch>,
    key_updates: KeyUpdateBudget<{ super::MAX_KEY_UPDATES_PER_RECORD }>,
    _thread: threadbound::ThreadBound,
}

pub(crate) enum RecordMessage<'a> {
    Borrowed(&'a [u8]),
    Buffered(workspace::BoundedBuffer),
}

impl AsRef<[u8]> for RecordMessage<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Buffered(bytes) => bytes,
        }
    }
}

impl HsReassembler {
    pub(crate) fn with_buffer(buffer: workspace::BoundedBuffer) -> Self {
        Self {
            buf: buffer,
            epoch: None,
            key_updates: KeyUpdateBudget::default(),
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub(crate) fn begin_record(
        &mut self,
        epoch: connection::Epoch,
    ) -> Result<(), codec::DecodeError> {
        if !self.buf.is_empty() && self.epoch != Some(epoch) {
            return Err(codec::DecodeError::HandshakeSpansEpoch);
        }
        self.key_updates.reset();
        Ok(())
    }

    pub(crate) fn next_record<'a>(
        &mut self,
        epoch: connection::Epoch,
        input: &mut &'a [u8],
    ) -> Result<Option<RecordMessage<'a>>, connection::Error> {
        if self.buf.is_empty() {
            if input.is_empty() {
                return Ok(None);
            }
            if input.len() >= 4 {
                let msg_len = message_len(input)?;
                if input.len() >= msg_len {
                    let (raw, rest) = input.split_at(msg_len);
                    *input = rest;
                    self.validate_message(raw)?;
                    return Ok(Some(RecordMessage::Borrowed(raw)));
                }
            }
            self.append(input)?;
            self.epoch = Some(epoch);
            *input = &[];
            return Ok(None);
        }

        debug_assert_eq!(self.epoch, Some(epoch));
        if self.buf.len() < 4 {
            let take = (4 - self.buf.len()).min(input.len());
            self.append(&input[..take])?;
            *input = &input[take..];
            if self.buf.len() < 4 {
                return Ok(None);
            }
        }

        let msg_len = message_len(&self.buf)?;
        let needed = msg_len
            .checked_sub(self.buf.len())
            .ok_or(codec::DecodeError::Trailing)?;
        let take = needed.min(input.len());
        self.append(&input[..take])?;
        *input = &input[take..];
        if self.buf.len() < msg_len {
            return Ok(None);
        }

        let raw = mem::take(&mut self.buf);
        self.epoch = None;
        self.validate_message(raw.as_slice())?;
        Ok(Some(RecordMessage::Buffered(raw)))
    }

    pub(crate) fn recycle(&mut self, message: RecordMessage<'_>) {
        if let RecordMessage::Buffered(mut bytes) = message {
            bytes.clear();
            if self.buf.is_empty() && bytes.capacity() > self.buf.capacity() {
                self.buf = bytes;
            }
        }
    }

    pub(crate) fn release_buffer(&mut self) -> workspace::BoundedBuffer {
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

    fn validate_message(&mut self, raw: &[u8]) -> Result<(), connection::Error> {
        if raw[0] == super::Type::KeyUpdate as u8 && !self.key_updates.consume() {
            return Err(connection::Error::UnexpectedMessage);
        }
        Ok(())
    }
}

fn message_len(buf: &[u8]) -> Result<usize, codec::DecodeError> {
    use crate::wire::handshake::MAX_SIZE;
    let msg_len = 4 + u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if msg_len > MAX_SIZE {
        return Err(codec::DecodeError::HandshakeTooLarge);
    }
    Ok(msg_len)
}

impl Default for HsReassembler {
    fn default() -> Self {
        Self::with_buffer(workspace::BoundedBuffer::default())
    }
}
