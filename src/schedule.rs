use core::sync::atomic::{Ordering, compiler_fence};

use crate::hash::{Digest, HASH_LEN, HashAlg, MAX_HASH_LEN, Secret, Transcript};
use crate::kdf::Hkdf;

pub(crate) fn zeroize(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

pub struct KeySchedule {
    alg: HashAlg,
    secret: Secret,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        zeroize(self.secret.as_mut_slice());
    }
}

impl KeySchedule {
    pub fn new(alg: HashAlg) -> Self {
        let zero = [0u8; MAX_HASH_LEN];
        let z = &zero[..alg.output_len()];
        Self {
            alg,
            secret: Hkdf::extract(alg, z, z),
        }
    }

    pub fn new_psk(alg: HashAlg, psk: &[u8]) -> Self {
        let zero = [0u8; MAX_HASH_LEN];
        let z = &zero[..alg.output_len()];
        Self {
            alg,
            secret: Hkdf::extract(alg, z, psk),
        }
    }

    pub fn hash_alg(&self) -> HashAlg {
        self.alg
    }

    pub fn into_handshake(self, dhe: &[u8]) -> Self {
        let derived = Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "derived",
            Transcript::hash_empty(self.alg).as_slice(),
        );
        Self {
            alg: self.alg,
            secret: Hkdf::extract(self.alg, derived.as_slice(), dhe),
        }
    }

    pub fn into_master(self) -> Self {
        let derived = Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "derived",
            Transcript::hash_empty(self.alg).as_slice(),
        );
        let zero = [0u8; MAX_HASH_LEN];
        let z = &zero[..self.alg.output_len()];
        Self {
            alg: self.alg,
            secret: Hkdf::extract(self.alg, derived.as_slice(), z),
        }
    }

    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    pub fn client_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Secret {
        Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "c hs traffic",
            transcript_hash,
        )
    }

    pub fn server_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Secret {
        Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "s hs traffic",
            transcript_hash,
        )
    }

    pub fn client_application_traffic_secret(&self, transcript_hash: &[u8]) -> Secret {
        Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "c ap traffic",
            transcript_hash,
        )
    }

    pub fn server_application_traffic_secret(&self, transcript_hash: &[u8]) -> Secret {
        Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "s ap traffic",
            transcript_hash,
        )
    }

    pub fn resumption_master_secret(&self, transcript_hash: &[u8]) -> Secret {
        Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "res master",
            transcript_hash,
        )
    }

    /// RFC 8446 §7.5: `exporter_master_secret`, derived from the master secret
    /// over the transcript through the server Finished.
    pub fn exporter_master_secret(&self, transcript_hash: &[u8]) -> Secret {
        Hkdf::derive_secret(
            self.alg,
            self.secret.as_slice(),
            "exp master",
            transcript_hash,
        )
    }
}

/// RFC 8446 §7.5 / RFC 5705 exported keying material:
/// `HKDF-Expand-Label(Derive-Secret(exporter_master, label, ""), "exporter",
/// Hash(context), length)`.
pub fn export_keying_material(
    alg: HashAlg,
    exporter_master: &[u8],
    label: &str,
    context: &[u8],
    out: &mut [u8],
) {
    let secret = Hkdf::derive_secret(
        alg,
        exporter_master,
        label,
        Transcript::hash_empty(alg).as_slice(),
    );
    let context_hash = alg.hash(context);
    Hkdf::expand_label(
        alg,
        secret.as_slice(),
        "exporter",
        context_hash.as_slice(),
        out,
    );
}

/// RFC 8446 §7.1: `client_early_traffic_secret` for 0-RTT, derived from the
/// resumption PSK over the transcript through ClientHello.
pub fn client_early_traffic_secret(psk: &[u8], transcript_hash: &[u8]) -> Secret {
    let zero = [0u8; HASH_LEN];
    let early = Hkdf::extract(crate::psk::RESUMPTION_HASH, &zero, psk);
    Hkdf::derive_secret(
        crate::psk::RESUMPTION_HASH,
        early.as_slice(),
        "c e traffic",
        transcript_hash,
    )
}

pub struct ResumptionMaster([u8; HASH_LEN]);

impl Drop for ResumptionMaster {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

impl ResumptionMaster {
    pub fn from_secret(secret: &Digest) -> Self {
        let mut bytes = [0u8; HASH_LEN];
        bytes.copy_from_slice(secret.as_slice());
        Self(bytes)
    }

    pub fn psk(&self, nonce: &[u8]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        Hkdf::expand_label(
            crate::psk::RESUMPTION_HASH,
            &self.0,
            "resumption",
            nonce,
            &mut out,
        );
        out
    }
}

pub struct TrafficKeys<const K: usize> {
    pub key: [u8; K],
    pub iv: [u8; 12],
}

impl<const K: usize> Drop for TrafficKeys<K> {
    fn drop(&mut self) {
        zeroize(&mut self.key);
        zeroize(&mut self.iv);
    }
}

impl<const K: usize> TrafficKeys<K> {
    pub fn derive(alg: HashAlg, secret: &[u8]) -> Self {
        let mut key = [0u8; K];
        let mut iv = [0u8; 12];
        Hkdf::expand_label(alg, secret, "key", &[], &mut key);
        Hkdf::expand_label(alg, secret, "iv", &[], &mut iv);
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
    fn secret_drop_clears_bytes() {
        let mut sec = ManuallyDrop::new(crate::hash::Secret::from_slice(&[0x5Au8; HASH_LEN]));
        let ptr = sec.as_slice().as_ptr();
        unsafe {
            ManuallyDrop::drop(&mut sec);
            assert_eq!(core::slice::from_raw_parts(ptr, HASH_LEN), &[0u8; HASH_LEN]);
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
