#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub mod aead;
pub mod asn1;
pub mod cert;
pub mod chain;
pub mod codec;
pub mod extension;
pub mod handshake;
pub mod hash;
pub mod hostname;
pub mod kdf;
pub mod kx;
pub mod psk;
pub mod record;
pub mod schedule;
pub mod sig;
pub mod spki;
pub mod ticket;
pub mod time;

mod proto;

pub mod client;
pub mod server;

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Epoch {
    Plaintext,
    Handshake,
    Application,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Send {
        epoch: Epoch,
        data: Vec<u8>,
    },
    KeysReady {
        epoch: Epoch,
        read_secret: [u8; 32],
        write_secret: [u8; 32],
    },
    PeerExtension {
        ty: u16,
        data: Vec<u8>,
    },
    KeyUpdate {
        direction: KeyDirection,
        secret: [u8; 32],
    },
    NewSessionTicket {
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: Vec<u8>,
        ticket: Vec<u8>,
    },
    ResumptionSecret {
        psk: [u8; 32],
    },
    ZeroRttKeysReady {
        secret: [u8; 32],
    },
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Decode,
    UnexpectedMessage,
    UnsupportedCipherSuite,
    UnsupportedGroup,
    UnsupportedSigScheme,
    BadVersion,
    DowngradeDetected,
    MissingExtension,
    KeyShareNotFound,
    BadCertificate,
    BadCertificateParse(crate::cert::CertError),
    BadCertificateChain(crate::chain::ChainError),
    NoTrustAnchorForIssuer(Vec<u8>),
    BadCertificateVerify,
    BadFinished,
    Kx,
    Sig,
    Spki,
    Rng,
}

impl From<crate::codec::DecodeError> for Error {
    fn from(_: crate::codec::DecodeError) -> Self {
        Self::Decode
    }
}
