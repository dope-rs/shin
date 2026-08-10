use alloc::vec;

const ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const P256_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
const P384_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

pub const ED25519_LEN: usize = 44;
pub const P256_LEN: usize = 91;
pub const P256_PUBKEY_UNCOMPRESSED_LEN: usize = 65;
pub const P384_LEN: usize = 120;
pub const P384_PUBKEY_UNCOMPRESSED_LEN: usize = 97;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadPrefix,
    BadLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectPublicKey {
    Ed25519([u8; 32]),
    EcdsaP256(vec::Vec<u8>),
    EcdsaP384(vec::Vec<u8>),
}

impl SubjectPublicKey {
    pub(crate) fn encoded_ed25519(public_key: &[u8; 32]) -> [u8; ED25519_LEN] {
        let mut encoded = [0; ED25519_LEN];
        encoded[..ED25519_PREFIX.len()].copy_from_slice(&ED25519_PREFIX);
        encoded[ED25519_PREFIX.len()..].copy_from_slice(public_key);
        encoded
    }

    pub fn encode(&self) -> Result<vec::Vec<u8>, Error> {
        match self {
            Self::Ed25519(pk) => Ok(Self::encoded_ed25519(pk).into()),
            Self::EcdsaP256(uncompressed) => {
                if uncompressed.len() != P256_PUBKEY_UNCOMPRESSED_LEN || uncompressed[0] != 0x04 {
                    return Err(Error::BadLength);
                }
                let mut spki = vec::Vec::with_capacity(P256_LEN);
                spki.extend_from_slice(&P256_PREFIX);
                spki.extend_from_slice(&uncompressed[1..]);
                Ok(spki)
            }
            Self::EcdsaP384(uncompressed) => {
                if uncompressed.len() != P384_PUBKEY_UNCOMPRESSED_LEN || uncompressed[0] != 0x04 {
                    return Err(Error::BadLength);
                }
                let mut spki = vec::Vec::with_capacity(P384_LEN);
                spki.extend_from_slice(&P384_PREFIX);
                spki.extend_from_slice(&uncompressed[1..]);
                Ok(spki)
            }
        }
    }

    pub fn decode(spki: &[u8]) -> Result<Self, Error> {
        match spki.len() {
            ED25519_LEN => {
                if !spki.starts_with(&ED25519_PREFIX) {
                    return Err(Error::BadPrefix);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&spki[ED25519_PREFIX.len()..]);
                Ok(Self::Ed25519(pk))
            }
            P256_LEN => {
                if !spki.starts_with(&P256_PREFIX) {
                    return Err(Error::BadPrefix);
                }
                let mut out = vec::Vec::with_capacity(P256_PUBKEY_UNCOMPRESSED_LEN);
                out.push(0x04);
                out.extend_from_slice(&spki[P256_PREFIX.len()..]);
                Ok(Self::EcdsaP256(out))
            }
            P384_LEN => {
                if !spki.starts_with(&P384_PREFIX) {
                    return Err(Error::BadPrefix);
                }
                let mut out = vec::Vec::with_capacity(P384_PUBKEY_UNCOMPRESSED_LEN);
                out.push(0x04);
                out.extend_from_slice(&spki[P384_PREFIX.len()..]);
                Ok(Self::EcdsaP384(out))
            }
            _ => Err(Error::BadLength),
        }
    }
}
