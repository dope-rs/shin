use alloc::vec::Vec;

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
const P384_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

pub const ED25519_SPKI_LEN: usize = 44;
pub const P256_SPKI_LEN: usize = 91;
pub const P256_PUBKEY_UNCOMPRESSED_LEN: usize = 65;
pub const P384_SPKI_LEN: usize = 120;
pub const P384_PUBKEY_UNCOMPRESSED_LEN: usize = 97;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpkiError {
    BadPrefix,
    BadLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectPublicKey {
    Ed25519([u8; 32]),
    EcdsaP256(Vec<u8>),
    EcdsaP384(Vec<u8>),
}

impl SubjectPublicKey {
    pub fn encode(&self) -> Result<Vec<u8>, SpkiError> {
        match self {
            Self::Ed25519(pk) => {
                let mut spki = Vec::with_capacity(ED25519_SPKI_LEN);
                spki.extend_from_slice(&ED25519_SPKI_PREFIX);
                spki.extend_from_slice(pk);
                Ok(spki)
            }
            Self::EcdsaP256(uncompressed) => {
                if uncompressed.len() != P256_PUBKEY_UNCOMPRESSED_LEN || uncompressed[0] != 0x04 {
                    return Err(SpkiError::BadLength);
                }
                let mut spki = Vec::with_capacity(P256_SPKI_LEN);
                spki.extend_from_slice(&P256_SPKI_PREFIX);
                spki.extend_from_slice(&uncompressed[1..]);
                Ok(spki)
            }
            Self::EcdsaP384(uncompressed) => {
                if uncompressed.len() != P384_PUBKEY_UNCOMPRESSED_LEN || uncompressed[0] != 0x04 {
                    return Err(SpkiError::BadLength);
                }
                let mut spki = Vec::with_capacity(P384_SPKI_LEN);
                spki.extend_from_slice(&P384_SPKI_PREFIX);
                spki.extend_from_slice(&uncompressed[1..]);
                Ok(spki)
            }
        }
    }

    pub fn decode(spki: &[u8]) -> Result<Self, SpkiError> {
        match spki.len() {
            ED25519_SPKI_LEN => {
                if !spki.starts_with(&ED25519_SPKI_PREFIX) {
                    return Err(SpkiError::BadPrefix);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&spki[ED25519_SPKI_PREFIX.len()..]);
                Ok(Self::Ed25519(pk))
            }
            P256_SPKI_LEN => {
                if !spki.starts_with(&P256_SPKI_PREFIX) {
                    return Err(SpkiError::BadPrefix);
                }
                let mut out = Vec::with_capacity(P256_PUBKEY_UNCOMPRESSED_LEN);
                out.push(0x04);
                out.extend_from_slice(&spki[P256_SPKI_PREFIX.len()..]);
                Ok(Self::EcdsaP256(out))
            }
            P384_SPKI_LEN => {
                if !spki.starts_with(&P384_SPKI_PREFIX) {
                    return Err(SpkiError::BadPrefix);
                }
                let mut out = Vec::with_capacity(P384_PUBKEY_UNCOMPRESSED_LEN);
                out.push(0x04);
                out.extend_from_slice(&spki[P384_SPKI_PREFIX.len()..]);
                Ok(Self::EcdsaP384(out))
            }
            _ => Err(SpkiError::BadLength),
        }
    }
}
