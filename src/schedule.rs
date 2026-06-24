use core::sync::atomic::{Ordering, compiler_fence};

use crate::hash::{HASH_LEN, Transcript};
use crate::kdf::Hkdf;

fn zeroize(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

pub struct KeySchedule {
    secret: [u8; HASH_LEN],
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        zeroize(&mut self.secret);
    }
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

impl Drop for ResumptionMaster {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

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

pub struct TrafficKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        zeroize(&mut self.key);
        zeroize(&mut self.iv);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::ManuallyDrop;

    #[test]
    fn zeroize_overwrites_bytes() {
        let mut buf = [0xABu8; 16];
        zeroize(&mut buf);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn traffic_keys_drop_clears_material() {
        let mut tk = ManuallyDrop::new(TrafficKeys {
            key: [0x11u8; 16],
            iv: [0x22u8; 12],
        });
        let key_ptr = tk.key.as_ptr();
        let iv_ptr = tk.iv.as_ptr();
        unsafe {
            ManuallyDrop::drop(&mut tk);
            assert_eq!(core::slice::from_raw_parts(key_ptr, 16), &[0u8; 16]);
            assert_eq!(core::slice::from_raw_parts(iv_ptr, 12), &[0u8; 12]);
        }
    }

    #[test]
    fn resumption_master_drop_clears_secret() {
        let mut rm = ManuallyDrop::new(ResumptionMaster([0x33u8; HASH_LEN]));
        let ptr = rm.0.as_ptr();
        unsafe {
            ManuallyDrop::drop(&mut rm);
            assert_eq!(core::slice::from_raw_parts(ptr, HASH_LEN), &[0u8; HASH_LEN]);
        }
    }
}
