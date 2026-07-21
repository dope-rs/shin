use crate::hash::{Digest, HASH_LEN, HashAlg, MAX_HASH_LEN, Secret, Transcript};
use crate::kdf::{Hkdf, HkdfError};
use zeroize::Zeroize;

pub struct KeySchedule {
    alg: HashAlg,
    secret: Secret,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.secret.as_mut_slice().zeroize();
    }
}

impl KeySchedule {
    pub fn new(alg: HashAlg) -> Self {
        let zero = [0u8; MAX_HASH_LEN];
        let z = &zero[..alg.output_len()];
        Self {
            alg,
            secret: Hkdf::new(alg).extract(z, z),
        }
    }

    pub fn new_psk(alg: HashAlg, psk: &[u8]) -> Self {
        let zero = [0u8; MAX_HASH_LEN];
        let z = &zero[..alg.output_len()];
        Self {
            alg,
            secret: Hkdf::new(alg).extract(z, psk),
        }
    }

    pub fn hash_alg(&self) -> HashAlg {
        self.alg
    }

    pub fn into_handshake(self, dhe: &[u8]) -> Result<Self, HkdfError> {
        let hkdf = Hkdf::new(self.alg);
        let derived = hkdf.derive_secret(
            self.secret.as_slice(),
            "derived",
            Transcript::hash_empty(self.alg).as_slice(),
        )?;
        Ok(Self {
            alg: self.alg,
            secret: hkdf.extract(derived.as_slice(), dhe),
        })
    }

    pub fn into_master(self) -> Result<Self, HkdfError> {
        let hkdf = Hkdf::new(self.alg);
        let derived = hkdf.derive_secret(
            self.secret.as_slice(),
            "derived",
            Transcript::hash_empty(self.alg).as_slice(),
        )?;
        let zero = [0u8; MAX_HASH_LEN];
        let z = &zero[..self.alg.output_len()];
        Ok(Self {
            alg: self.alg,
            secret: hkdf.extract(derived.as_slice(), z),
        })
    }

    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    pub fn client_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Secret, HkdfError> {
        Hkdf::new(self.alg).derive_secret(self.secret.as_slice(), "c hs traffic", transcript_hash)
    }

    pub fn server_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Secret, HkdfError> {
        Hkdf::new(self.alg).derive_secret(self.secret.as_slice(), "s hs traffic", transcript_hash)
    }

    pub fn client_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Secret, HkdfError> {
        Hkdf::new(self.alg).derive_secret(self.secret.as_slice(), "c ap traffic", transcript_hash)
    }

    pub fn server_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Secret, HkdfError> {
        Hkdf::new(self.alg).derive_secret(self.secret.as_slice(), "s ap traffic", transcript_hash)
    }

    pub fn resumption_master_secret(&self, transcript_hash: &[u8]) -> Result<Secret, HkdfError> {
        Hkdf::new(self.alg).derive_secret(self.secret.as_slice(), "res master", transcript_hash)
    }

    /// RFC 8446 §7.5: `exporter_master_secret`, derived from the master secret
    /// over the transcript through the server Finished.
    pub fn exporter_master_secret(&self, transcript_hash: &[u8]) -> Result<Secret, HkdfError> {
        Hkdf::new(self.alg).derive_secret(self.secret.as_slice(), "exp master", transcript_hash)
    }

    pub(crate) fn export_keying_material(
        alg: HashAlg,
        exporter_master: &[u8],
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), HkdfError> {
        let hkdf = Hkdf::new(alg);
        let secret = hkdf.derive_secret(
            exporter_master,
            label,
            Transcript::hash_empty(alg).as_slice(),
        )?;
        let context_hash = alg.hash(context);
        hkdf.expand_label(secret.as_slice(), "exporter", context_hash.as_slice(), out)
    }

    pub(crate) fn client_early_traffic_secret(
        psk: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Secret, HkdfError> {
        let zero = [0u8; HASH_LEN];
        let hkdf = Hkdf::new(crate::psk::RESUMPTION_HASH);
        let early = hkdf.extract(&zero, psk);
        hkdf.derive_secret(early.as_slice(), "c e traffic", transcript_hash)
    }
}

pub struct ResumptionMaster([u8; HASH_LEN]);

impl Drop for ResumptionMaster {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ResumptionMaster {
    pub fn from_secret(secret: &Digest) -> Self {
        let mut bytes = [0u8; HASH_LEN];
        bytes.copy_from_slice(secret.as_slice());
        Self(bytes)
    }

    pub fn psk(&self, nonce: &[u8]) -> Result<[u8; HASH_LEN], HkdfError> {
        let mut out = [0u8; HASH_LEN];
        Hkdf::new(crate::psk::RESUMPTION_HASH).expand_label(
            &self.0,
            "resumption",
            nonce,
            &mut out,
        )?;
        Ok(out)
    }
}

pub struct TrafficKeys<const K: usize> {
    pub key: [u8; K],
    pub iv: [u8; 12],
}

impl<const K: usize> Drop for TrafficKeys<K> {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl<const K: usize> TrafficKeys<K> {
    pub fn derive(alg: HashAlg, secret: &[u8]) -> Result<Self, HkdfError> {
        let mut key = [0u8; K];
        let mut iv = [0u8; 12];
        let hkdf = Hkdf::new(alg);
        hkdf.expand_label(secret, "key", &[], &mut key)?;
        hkdf.expand_label(secret, "iv", &[], &mut iv)?;
        Ok(Self { key, iv })
    }
}
