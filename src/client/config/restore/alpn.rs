use alloc::borrow;

/// The exact ALPN value negotiated by the connection that issued a persisted
/// ticket. `Absent` is an authoritative absence, never missing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiatedAlpn<'a> {
    Absent,
    Protocol(borrow::Cow<'a, [u8]>),
}
