use crate::hash::{HASH_LEN, Transcript};
use crate::kdf::Hkdf;

pub struct KeySchedule {
    secret: [u8; HASH_LEN],
}

impl KeySchedule {
    pub fn new() -> Self {
        let zero = [0u8; HASH_LEN];
        Self {
            secret: Hkdf::extract(&zero, &zero),
        }
    }

    pub fn new_psk(psk: &[u8; HASH_LEN]) -> Self {
        let zero = [0u8; HASH_LEN];
        Self {
            secret: Hkdf::extract(&zero, psk),
        }
    }

    pub fn into_handshake(self, dhe: &[u8]) -> Self {
        let derived = Hkdf::derive_secret(&self.secret, "derived", &Transcript::hash_empty());
        Self {
            secret: Hkdf::extract(&derived, dhe),
        }
    }

    pub fn into_master(self) -> Self {
        let derived = Hkdf::derive_secret(&self.secret, "derived", &Transcript::hash_empty());
        let zero = [0u8; HASH_LEN];
        Self {
            secret: Hkdf::extract(&derived, &zero),
        }
    }

    pub fn secret(&self) -> &[u8; HASH_LEN] {
        &self.secret
    }

    pub fn client_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        Hkdf::derive_secret(&self.secret, "c hs traffic", transcript_hash)
    }

    pub fn server_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        Hkdf::derive_secret(&self.secret, "s hs traffic", transcript_hash)
    }

    pub fn client_application_traffic_secret(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        Hkdf::derive_secret(&self.secret, "c ap traffic", transcript_hash)
    }

    pub fn server_application_traffic_secret(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        Hkdf::derive_secret(&self.secret, "s ap traffic", transcript_hash)
    }

    pub fn resumption_master_secret(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        Hkdf::derive_secret(&self.secret, "res master", transcript_hash)
    }
}

pub struct ResumptionMaster([u8; HASH_LEN]);

impl ResumptionMaster {
    pub fn new(secret: [u8; HASH_LEN]) -> Self {
        Self(secret)
    }

    pub fn psk(&self, nonce: &[u8]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        Hkdf::expand_label(&self.0, "resumption", nonce, &mut out);
        out
    }
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
}

impl TrafficKeys {
    pub fn aes_128_gcm(secret: &[u8]) -> Self {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        Hkdf::expand_label(secret, "key", &[], &mut key);
        Hkdf::expand_label(secret, "iv", &[], &mut iv);
        Self { key, iv }
    }
}
