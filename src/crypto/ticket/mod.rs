mod claims;
mod context;
mod decrypted;
mod encrypted;
mod keys;
mod rotator;
mod secret;

pub use claims::Claims;
pub use context::Context;
pub use decrypted::Decrypted;
pub use encrypted::Encrypted;
pub use keys::Keys;
pub use rotator::Rotator;
pub use secret::Secret;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PSK_LEN: usize = 32;
const AGE_ADD_LEN: usize = 4;
const ISSUED_AT_LEN: usize = 8;
const SUITE_LEN: usize = 2;
const ALPN_LEN_LEN: usize = 1;
const MAX_ALPN_LEN: usize = 255;
const FORMAT_VERSION_LEN: usize = 1;
const TRANSPORT_MODE_LEN: usize = 1;
const EARLY_DATA_PRESENT_LEN: usize = 1;
const EARLY_DATA_SIZE_LEN: usize = 4;
const TRANSPORT_PARAMS_HASH_LEN: usize = hash::SHA256_LEN;
pub(crate) const REPLAY_DOMAIN_LEN: usize = 16;
const LEGACY_CONTEXT_LEN: usize = FORMAT_VERSION_LEN
    + TRANSPORT_MODE_LEN
    + EARLY_DATA_PRESENT_LEN
    + EARLY_DATA_SIZE_LEN
    + TRANSPORT_PARAMS_HASH_LEN;
const CONTEXT_LEN: usize = LEGACY_CONTEXT_LEN + REPLAY_DOMAIN_LEN;
const FIELDS_BEFORE_CONTEXT_LEN: usize = PSK_LEN + AGE_ADD_LEN + ISSUED_AT_LEN + SUITE_LEN;
const LEGACY_FIXED_PLAINTEXT_LEN: usize =
    FIELDS_BEFORE_CONTEXT_LEN + LEGACY_CONTEXT_LEN + ALPN_LEN_LEN;
const FIXED_PLAINTEXT_LEN: usize = FIELDS_BEFORE_CONTEXT_LEN + CONTEXT_LEN + ALPN_LEN_LEN;
const MAX_PLAINTEXT_LEN: usize = FIXED_PLAINTEXT_LEN + MAX_ALPN_LEN;
const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + TAG_LEN;

pub const MAX_LEN: usize = NONCE_LEN + MAX_CIPHERTEXT_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadFormat,
    BadAuth,
    BadKey,
}
use crate::crypto::hash;
