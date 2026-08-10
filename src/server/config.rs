use crate::connection;
use crate::crypto::hash;
use crate::crypto::sig;
use crate::crypto::ticket;
use crate::transport;
use crate::wire::handshake;
use crate::wire::handshake::views;
use alloc::vec;

pub struct Config {
    pub source: CertSource,
    pub alpn_protocols: vec::Vec<vec::Vec<u8>>,
    pub ticket_keys: Option<ticket::Keys>,
}

impl Config {
    pub fn validate(&self) -> Result<(), connection::Error> {
        self.prepare_for(true, true).map(|_| ())
    }

    pub(super) fn prepare_for(
        &self,
        client_auth: bool,
        early_data: bool,
    ) -> Result<FlightProfile, connection::Error> {
        if self
            .alpn_protocols
            .iter()
            .any(|protocol| protocol.is_empty() || protocol.len() > u8::MAX as usize)
        {
            return Err(connection::Error::BadConfig);
        }
        let certificate_len = self
            .source
            .validated_certificate_message_len()
            .ok_or(connection::Error::BadConfig)?;
        if certificate_len > handshake::MAX_SIZE {
            return Err(connection::Error::BadConfig);
        }
        let maximum_alpn_len = self
            .alpn_protocols
            .iter()
            .map(vec::Vec::len)
            .max()
            .unwrap_or(0);
        Ok(FlightProfile {
            certificate_len,
            maximum_alpn_len,
            client_auth,
            early_data,
        })
    }
}

pub struct Connection {
    pub transport_params: vec::Vec<u8>,
}

impl Connection {
    /// Validates a TLS-over-stream connection configuration.
    pub fn validate(&self) -> Result<(), connection::Error> {
        self.validate_with_transport(transport::Mode::Tls)
    }

    /// Validates the connection configuration for an explicit transport.
    pub fn validate_with_transport(
        &self,
        transport_mode: transport::Mode,
    ) -> Result<(), connection::Error> {
        if self.transport_params.len() > MAX_TRANSPORT_PARAMETERS_LEN {
            return Err(connection::Error::BadConfig);
        }
        if transport_mode.is_tls() && !self.transport_params.is_empty() {
            return Err(connection::Error::BadConfig);
        }
        Ok(())
    }
}

/// Maximum body that still fits its enclosing extension vector.
const MAX_TRANSPORT_PARAMETERS_LEN: usize = u16::MAX as usize - EXTENSION_HEADER_LEN;
const EXTENSION_HEADER_LEN: usize = 4;
const TWO_CERTIFICATE_TYPE_EXTENSIONS_LEN: usize = 2 * (EXTENSION_HEADER_LEN + 1);
const EMPTY_EARLY_DATA_EXTENSION_LEN: usize = EXTENSION_HEADER_LEN;

#[derive(Clone, Copy)]
pub(super) struct FlightProfile {
    certificate_len: usize,
    maximum_alpn_len: usize,
    client_auth: bool,
    early_data: bool,
}

impl FlightProfile {
    pub(super) fn fits(
        self,
        transport_mode: transport::Mode,
        transport_parameters_len: usize,
    ) -> bool {
        full_handshake_flight_fits(self, transport_mode, transport_parameters_len)
    }
}

fn full_handshake_flight_fits(
    profile: FlightProfile,
    transport_mode: transport::Mode,
    transport_parameters_len: usize,
) -> bool {
    const HANDSHAKE_HEADER_LEN: usize = 4;
    const EXTENSIONS_VECTOR_LEN: usize = 2;
    const CERTIFICATE_REQUEST_LEN: usize =
        HANDSHAKE_HEADER_LEN + 1 + EXTENSIONS_VECTOR_LEN + EXTENSION_HEADER_LEN + 2 + 2 * 6;
    const CERTIFICATE_VERIFY_MAX_LEN: usize = HANDSHAKE_HEADER_LEN + 2 + 2 + sig::MAX_SIGNATURE_LEN;
    const FINISHED_MAX_LEN: usize = HANDSHAKE_HEADER_LEN + hash::MAX_LEN;

    let transport_parameters_extension_len = if transport_mode.is_quic() {
        EXTENSION_HEADER_LEN + transport_parameters_len
    } else {
        0
    };
    let alpn_extension_len = if profile.maximum_alpn_len != 0 {
        EXTENSION_HEADER_LEN + 2 + 1 + profile.maximum_alpn_len
    } else {
        0
    };
    let early_data_extension_len = if profile.early_data {
        EMPTY_EARLY_DATA_EXTENSION_LEN
    } else {
        0
    };
    let extension_list_len = TWO_CERTIFICATE_TYPE_EXTENSIONS_LEN
        + transport_parameters_extension_len
        + alpn_extension_len
        + early_data_extension_len;
    if extension_list_len > u16::MAX as usize {
        return false;
    }
    let encrypted_extensions_len =
        HANDSHAKE_HEADER_LEN + EXTENSIONS_VECTOR_LEN + extension_list_len;
    encrypted_extensions_len
        .checked_add(if profile.client_auth {
            CERTIFICATE_REQUEST_LEN
        } else {
            0
        })
        .and_then(|len| len.checked_add(profile.certificate_len))
        .and_then(|len| len.checked_add(CERTIFICATE_VERIFY_MAX_LEN))
        .and_then(|len| len.checked_add(FINISHED_MAX_LEN))
        .is_some_and(|len| len <= handshake::MAX_SIZE)
}

/// Replay store required for safe 0-RTT. Without one, early data is refused even
/// when configured because single-use cannot be proved (RFC 8446 §8).
pub trait EarlyDataGuard {
    #[doc(hidden)]
    const ACCEPTS_EARLY_DATA: bool = true;

    /// Record a single-use token (the PSK binder); `false` means it was already
    /// seen — a replay. Tokens need only be kept for `TICKET_LIFETIME_SECS`.
    fn register(&mut self, token: &[u8]) -> bool;
}

/// Default guard for servers that never accept 0-RTT: reports every token as
/// already-seen, so early data is always refused.
pub struct NoGuard;

impl EarlyDataGuard for NoGuard {
    const ACCEPTS_EARLY_DATA: bool = false;

    fn register(&mut self, _token: &[u8]) -> bool {
        false
    }
}

pub enum CertSource {
    RawPublicKey {
        signing_key: sig::SigningKey,
    },
    X509 {
        chain_der: vec::Vec<vec::Vec<u8>>,
        signing_key: sig::SigningKey,
    },
}

impl CertSource {
    pub(super) fn signing_key(&self) -> &sig::SigningKey {
        match self {
            Self::RawPublicKey { signing_key } => signing_key,
            Self::X509 { signing_key, .. } => signing_key,
        }
    }

    fn validated_certificate_message_len(&self) -> Option<usize> {
        const FIXED_CERTIFICATE_MESSAGE_LEN: usize = 4 + 1 + 3;
        const CERTIFICATE_ENTRY_FRAMING_LEN: usize = 3 + 2;
        match self {
            Self::RawPublicKey { signing_key } => {
                use crate::identity::spki;
                if !signing_key.is_ed25519() {
                    return None;
                }
                let public_key = spki::SubjectPublicKey::encoded_ed25519(signing_key.pubkey()?);
                FIXED_CERTIFICATE_MESSAGE_LEN
                    .checked_add(CERTIFICATE_ENTRY_FRAMING_LEN + public_key.len())
            }
            Self::X509 {
                chain_der,
                signing_key,
            } => {
                if chain_der.len() > handshake::MAX_CERTIFICATE_ENTRIES
                    || !signing_key.matches_x509_chain(chain_der)
                {
                    return None;
                }
                chain_der.iter().try_fold(
                    FIXED_CERTIFICATE_MESSAGE_LEN,
                    |message_len, certificate| {
                        message_len.checked_add(CERTIFICATE_ENTRY_FRAMING_LEN + certificate.len())
                    },
                )
            }
        }
    }
}

/// Mutual-TLS policy: `Requested` permits an empty Certificate while `Required`
/// rejects one; presented identities still pass [`ClientCertVerifier`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    Requested,
    Required,
}

/// Default [`ClientCertVerifier`] for a server that does not authenticate
/// clients; its [`verify`](ClientCertVerifier::verify) is never reached.
pub struct NoClientAuth;

impl ClientCertVerifier for NoClientAuth {
    fn verify(&self, _identity: &ClientIdentity<'_>) -> bool {
        false
    }
}

/// Authorizes a possession-proven client identity, typically by pinning
/// `spki_der`; CertificateVerify authenticity has already succeeded.
pub trait ClientCertVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool;
}

/// A signature-verified client identity handed to [`ClientCertVerifier`].
pub struct ClientIdentity<'a> {
    /// `CERT_TYPE_X509` (0) or `CERT_TYPE_RAW_PUBLIC_KEY` (2).
    pub cert_type: u8,
    /// The leaf SubjectPublicKeyInfo DER — a uniform pinning target across key
    /// types. For RawPublicKey this is the entire certificate.
    pub spki_der: &'a [u8],
    /// The presented X.509 chain (leaf first); empty for RawPublicKey.
    pub chain_der: ClientCertificateChain<'a>,
}

#[derive(Clone, Copy)]
pub struct ClientCertificateChain<'a> {
    pub(super) entries: Option<views::CertificateEntries<'a>>,
}

impl<'a> ClientCertificateChain<'a> {
    pub fn len(self) -> usize {
        self.entries.map_or(0, views::CertificateEntries::len)
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub fn iter(self) -> impl Iterator<Item = &'a [u8]> {
        self.entries
            .into_iter()
            .flat_map(views::CertificateEntries::iter)
            .map(|entry| entry.cert_data)
    }
}
