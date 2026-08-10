use crate::crypto::hash;
use crate::crypto::kdf;
use crate::crypto::material;
use crate::memory::threadbound;
use crate::wire::psk;
use zeroize::Zeroize as _;

pub struct Schedule {
    alg: hash::Algorithm,
    secret: hash::Secret,
}

impl Drop for Schedule {
    fn drop(&mut self) {
        self.secret.as_mut_slice().zeroize();
    }
}

impl Schedule {
    pub fn new(alg: hash::Algorithm) -> Self {
        let zero = [0u8; hash::MAX_LEN];
        let z = &zero[..alg.output_len()];
        Self {
            alg,
            secret: kdf::Hkdf::new(alg).extract(z, z),
        }
    }

    pub fn new_psk(alg: hash::Algorithm, psk: &[u8]) -> Self {
        let zero = [0u8; hash::MAX_LEN];
        let z = &zero[..alg.output_len()];
        Self {
            alg,
            secret: kdf::Hkdf::new(alg).extract(z, psk),
        }
    }

    pub fn hash_alg(&self) -> hash::Algorithm {
        self.alg
    }

    pub fn into_handshake(self, dhe: &[u8]) -> Result<Self, kdf::HkdfError> {
        let hkdf = kdf::Hkdf::new(self.alg);
        let derived = hkdf.derive_secret(
            self.secret.as_slice(),
            "derived",
            hash::Transcript::hash_empty(self.alg).as_slice(),
        )?;
        Ok(Self {
            alg: self.alg,
            secret: hkdf.extract(derived.as_slice(), dhe),
        })
    }

    pub fn into_master(self) -> Result<Self, kdf::HkdfError> {
        let hkdf = kdf::Hkdf::new(self.alg);
        let derived = hkdf.derive_secret(
            self.secret.as_slice(),
            "derived",
            hash::Transcript::hash_empty(self.alg).as_slice(),
        )?;
        let zero = [0u8; hash::MAX_LEN];
        let z = &zero[..self.alg.output_len()];
        Ok(Self {
            alg: self.alg,
            secret: hkdf.extract(derived.as_slice(), z),
        })
    }

    pub fn secret(&self) -> &hash::Secret {
        &self.secret
    }

    pub fn client_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<material::TrafficSecret, kdf::HkdfError> {
        kdf::Hkdf::new(self.alg)
            .derive_secret(self.secret.as_slice(), "c hs traffic", transcript_hash)
            .map(material::TrafficSecret::from_secret)
    }

    pub fn server_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<material::TrafficSecret, kdf::HkdfError> {
        kdf::Hkdf::new(self.alg)
            .derive_secret(self.secret.as_slice(), "s hs traffic", transcript_hash)
            .map(material::TrafficSecret::from_secret)
    }

    pub fn client_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<material::TrafficSecret, kdf::HkdfError> {
        kdf::Hkdf::new(self.alg)
            .derive_secret(self.secret.as_slice(), "c ap traffic", transcript_hash)
            .map(material::TrafficSecret::from_secret)
    }

    pub fn server_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<material::TrafficSecret, kdf::HkdfError> {
        kdf::Hkdf::new(self.alg)
            .derive_secret(self.secret.as_slice(), "s ap traffic", transcript_hash)
            .map(material::TrafficSecret::from_secret)
    }

    pub fn resumption_master_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<material::ResumptionMasterSecret, kdf::HkdfError> {
        kdf::Hkdf::new(self.alg)
            .derive_secret(self.secret.as_slice(), "res master", transcript_hash)
            .map(material::ResumptionMasterSecret::from_secret)
    }

    /// RFC 8446 §7.5: `exporter_master_secret`, derived from the master secret
    /// over the transcript through the server Finished.
    pub fn exporter_master_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<material::ExporterMasterSecret, kdf::HkdfError> {
        kdf::Hkdf::new(self.alg)
            .derive_secret(self.secret.as_slice(), "exp master", transcript_hash)
            .map(material::ExporterMasterSecret::from_secret)
    }

    pub(crate) fn export_keying_material(
        alg: hash::Algorithm,
        exporter_master: &[u8],
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), kdf::HkdfError> {
        let hkdf = kdf::Hkdf::new(alg);
        let secret = hkdf.derive_secret(
            exporter_master,
            label,
            hash::Transcript::hash_empty(alg).as_slice(),
        )?;
        let context_hash = alg.hash(context);
        hkdf.expand_label(secret.as_slice(), "exporter", context_hash.as_slice(), out)
    }

    pub(crate) fn client_early_traffic_secret(
        psk: &[u8],
        transcript_hash: &[u8],
    ) -> Result<material::TrafficSecret, kdf::HkdfError> {
        let zero = [0u8; hash::SHA256_LEN];
        let hkdf = kdf::Hkdf::new(psk::RESUMPTION_HASH);
        let early = hkdf.extract(&zero, psk);
        hkdf.derive_secret(early.as_slice(), "c e traffic", transcript_hash)
            .map(material::TrafficSecret::from_secret)
    }
}

pub struct ResumptionMaster<'a>(&'a material::ResumptionMasterSecret);

impl<'a> ResumptionMaster<'a> {
    pub fn from_secret(secret: &'a material::ResumptionMasterSecret) -> Self {
        Self(secret)
    }

    pub fn psk(&self, nonce: &[u8]) -> Result<material::ResumptionPsk, kdf::HkdfError> {
        let mut out = material::ResumptionPsk::zeroed();
        kdf::Hkdf::new(psk::RESUMPTION_HASH).expand_label(
            self.0.as_slice(),
            "resumption",
            nonce,
            out.as_mut_array(),
        )?;
        Ok(out)
    }
}

pub struct TrafficKeys<const K: usize> {
    pub key: [u8; K],
    pub iv: [u8; 12],
    _thread: threadbound::ThreadBound,
}

impl<const K: usize> Drop for TrafficKeys<K> {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl<const K: usize> TrafficKeys<K> {
    pub fn derive(alg: hash::Algorithm, secret: &[u8]) -> Result<Self, kdf::HkdfError> {
        let mut key = [0u8; K];
        let mut iv = [0u8; 12];
        let hkdf = kdf::Hkdf::new(alg);
        hkdf.expand_label(secret, "key", &[], &mut key)?;
        hkdf.expand_label(secret, "iv", &[], &mut iv)?;
        Ok(Self {
            key,
            iv,
            _thread: threadbound::ThreadBound::NEW,
        })
    }
}
