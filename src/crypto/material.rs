//! Purpose-separated secret values.
//!
//! These types deliberately implement neither `Copy` nor `Clone`, zeroize
//! their storage on drop, and inherit shin's thread affinity.
//!
//! ```compile_fail
//! use shin::crypto::material::TrafficSecret;
//! fn assert_copy<T: Copy>() {}
//! assert_copy::<TrafficSecret>();
//! ```
//!
//! ```compile_fail
//! use shin::crypto::material::TrafficSecret;
//! fn assert_clone<T: Clone>() {}
//! assert_clone::<TrafficSecret>();
//! ```
//!
//! ```compile_fail
//! use shin::crypto::material::ResumptionPsk;
//! fn assert_send<T: Send>() {}
//! assert_send::<ResumptionPsk>();
//! ```

use crate::connection;
use crate::crypto::hash;
use crate::crypto::kdf;
use crate::memory::threadbound;
use crate::wire::handshake;
use crate::wire::handshake::reassemblers;
use crate::wire::record;
use core::fmt;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

struct VariableSecret(hash::Secret);

#[derive(Clone, Copy)]
pub(crate) enum Side {
    Client,
    Server,
}

#[derive(Default)]
pub(crate) enum State {
    #[default]
    Empty,
    Selected(record::CipherSuite),
    Active(Active),
}

pub(crate) struct Active {
    suite: record::CipherSuite,
    client: TrafficSecret,
    server: TrafficSecret,
    updates: reassemblers::KeyUpdateBudget<{ handshake::MAX_KEY_UPDATES_WITHOUT_APP_DATA }>,
}

impl State {
    pub(crate) fn select(&mut self, suite: record::CipherSuite) -> Result<(), connection::Error> {
        match self {
            Self::Empty => {
                *self = Self::Selected(suite);
                Ok(())
            }
            Self::Selected(selected) if *selected == suite => Ok(()),
            Self::Active(active) if active.suite == suite => Ok(()),
            Self::Selected(_) | Self::Active(_) => Err(connection::Error::IllegalParameter),
        }
    }

    pub(crate) fn activate(
        &mut self,
        client: TrafficSecret,
        server: TrafficSecret,
    ) -> Result<(), connection::Error> {
        let Self::Selected(suite) = self else {
            return Err(connection::Error::UnexpectedMessage);
        };
        let suite = *suite;
        *self = Self::Active(Active {
            suite,
            client,
            server,
            updates: reassemblers::KeyUpdateBudget::default(),
        });
        Ok(())
    }

    pub(crate) fn suite(&self) -> Option<record::CipherSuite> {
        match self {
            Self::Empty => None,
            Self::Selected(suite) => Some(*suite),
            Self::Active(active) => Some(active.suite),
        }
    }

    pub(crate) fn algorithm(&self) -> Result<hash::Algorithm, connection::Error> {
        self.suite()
            .map(|suite| suite.hash_alg())
            .ok_or(connection::Error::UnexpectedMessage)
    }

    pub(crate) fn secret(&self, side: Side) -> Result<&TrafficSecret, connection::Error> {
        let Self::Active(active) = self else {
            return Err(connection::Error::UnexpectedMessage);
        };
        Ok(match side {
            Side::Client => &active.client,
            Side::Server => &active.server,
        })
    }

    pub(crate) fn advance(&mut self, side: Side) -> Result<&TrafficSecret, connection::Error> {
        let Self::Active(active) = self else {
            return Err(connection::Error::UnexpectedMessage);
        };
        let secret = match side {
            Side::Client => &mut active.client,
            Side::Server => &mut active.server,
        };
        *secret = kdf::Hkdf::new(active.suite.hash_alg()).traffic_update(secret)?;
        Ok(secret)
    }

    pub(crate) fn consume_update(&mut self) -> bool {
        match self {
            Self::Active(active) => active.updates.consume(),
            Self::Empty | Self::Selected(_) => false,
        }
    }

    pub(crate) fn reset_updates(&mut self) {
        if let Self::Active(active) = self {
            active.updates.reset();
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::Empty;
    }
}

impl VariableSecret {
    fn try_from_slice(bytes: &[u8]) -> Result<Self, hash::LengthError> {
        hash::Secret::try_from_slice(bytes).map(Self)
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn redacted(&self, name: &str, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{name}([redacted; {}])", self.0.len())
    }

    fn ct_eq(&self, other: &Self) -> bool {
        self.as_slice().len() == other.as_slice().len()
            && bool::from(self.as_slice().ct_eq(other.as_slice()))
    }
}

impl zeroize::ZeroizeOnDrop for VariableSecret {}

pub struct TrafficSecret(VariableSecret);

impl TrafficSecret {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, hash::LengthError> {
        VariableSecret::try_from_slice(bytes).map(Self)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn from_secret(secret: hash::Secret) -> Self {
        Self(VariableSecret(secret))
    }
}

impl fmt::Debug for TrafficSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.redacted("TrafficSecret", formatter)
    }
}

impl PartialEq for TrafficSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for TrafficSecret {}
impl zeroize::ZeroizeOnDrop for TrafficSecret {}

pub struct FinishedKey(VariableSecret);

impl FinishedKey {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, hash::LengthError> {
        VariableSecret::try_from_slice(bytes).map(Self)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn from_secret(secret: hash::Secret) -> Self {
        Self(VariableSecret(secret))
    }
}

impl fmt::Debug for FinishedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.redacted("FinishedKey", formatter)
    }
}

impl PartialEq for FinishedKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for FinishedKey {}
impl zeroize::ZeroizeOnDrop for FinishedKey {}

pub struct FinishedVerifyData(VariableSecret);

impl FinishedVerifyData {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, hash::LengthError> {
        VariableSecret::try_from_slice(bytes).map(Self)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn from_secret(secret: hash::Secret) -> Self {
        Self(VariableSecret(secret))
    }

    pub(crate) fn ct_eq(&self, candidate: &[u8]) -> bool {
        self.as_slice().len() == candidate.len() && bool::from(self.as_slice().ct_eq(candidate))
    }
}

impl fmt::Debug for FinishedVerifyData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.redacted("FinishedVerifyData", formatter)
    }
}

impl PartialEq for FinishedVerifyData {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for FinishedVerifyData {}
impl zeroize::ZeroizeOnDrop for FinishedVerifyData {}

pub struct ResumptionMasterSecret(VariableSecret);

impl ResumptionMasterSecret {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, hash::LengthError> {
        VariableSecret::try_from_slice(bytes).map(Self)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn from_secret(secret: hash::Secret) -> Self {
        Self(VariableSecret(secret))
    }
}

impl fmt::Debug for ResumptionMasterSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.redacted("ResumptionMasterSecret", formatter)
    }
}

impl PartialEq for ResumptionMasterSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for ResumptionMasterSecret {}
impl zeroize::ZeroizeOnDrop for ResumptionMasterSecret {}

pub struct ExporterMasterSecret(VariableSecret);

impl ExporterMasterSecret {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, hash::LengthError> {
        VariableSecret::try_from_slice(bytes).map(Self)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn from_secret(secret: hash::Secret) -> Self {
        Self(VariableSecret(secret))
    }
}

impl fmt::Debug for ExporterMasterSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.redacted("ExporterMasterSecret", formatter)
    }
}

impl PartialEq for ExporterMasterSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for ExporterMasterSecret {}
impl zeroize::ZeroizeOnDrop for ExporterMasterSecret {}

/// A TLS 1.3 resumption PSK, fixed to SHA-256 in shin's ticket profile.
pub struct ResumptionPsk {
    bytes: [u8; hash::SHA256_LEN],
    _thread: threadbound::ThreadBound,
}

impl ResumptionPsk {
    pub fn new(mut bytes: [u8; hash::SHA256_LEN]) -> Self {
        let value = Self {
            bytes,
            _thread: threadbound::ThreadBound::NEW,
        };
        bytes.zeroize();
        value
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, hash::LengthError> {
        if bytes.len() != hash::SHA256_LEN {
            return Err(hash::LengthError {
                actual: bytes.len(),
                maximum: hash::SHA256_LEN,
            });
        }
        let mut owned = [0u8; hash::SHA256_LEN];
        owned.copy_from_slice(bytes);
        Ok(Self {
            bytes: owned,
            _thread: threadbound::ThreadBound::NEW,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_array(&self) -> &[u8; hash::SHA256_LEN] {
        &self.bytes
    }

    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0; hash::SHA256_LEN],
            _thread: threadbound::ThreadBound::NEW,
        }
    }

    pub(crate) fn as_mut_array(&mut self) -> &mut [u8; hash::SHA256_LEN] {
        &mut self.bytes
    }
}

impl From<[u8; hash::SHA256_LEN]> for ResumptionPsk {
    fn from(bytes: [u8; hash::SHA256_LEN]) -> Self {
        Self::new(bytes)
    }
}

impl Drop for ResumptionPsk {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for ResumptionPsk {}

impl PartialEq for ResumptionPsk {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl Eq for ResumptionPsk {}

impl fmt::Debug for ResumptionPsk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResumptionPsk([redacted; 32])")
    }
}
