/// Protocol carrying TLS 1.3; QUIC changes wire semantics, and empty
/// transport parameters remain an explicit QUIC signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// TLS records carried by a reliable byte stream, normally TCP.
    Tls,
    /// TLS handshake messages carried by QUIC CRYPTO frames.
    Quic,
}

impl Mode {
    pub const fn is_tls(self) -> bool {
        matches!(self, Self::Tls)
    }

    pub const fn is_quic(self) -> bool {
        matches!(self, Self::Quic)
    }

    pub(crate) const fn uses_legacy_session_id(self) -> bool {
        self.is_tls()
    }

    pub(crate) const fn uses_end_of_early_data(self) -> bool {
        self.is_tls()
    }

    pub(crate) const fn allows_tls_key_update(self) -> bool {
        self.is_tls()
    }

    pub(crate) const fn advertised_early_data_size(self, tls_limit: u32) -> u32 {
        match self {
            Self::Tls => tls_limit,
            Self::Quic => u32::MAX,
        }
    }
}
