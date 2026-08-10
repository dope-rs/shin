use crate::crypto::sig;
use alloc::vec;

pub(super) mod template;

/// Client authentication identity presented to a requesting server.
pub enum Identity {
    /// RFC 7250 Ed25519 SubjectPublicKeyInfo identity.
    RawPublicKey { signing_key: sig::SigningKey },
    /// Leaf-first X.509 chain and its leaf private key.
    X509 {
        chain_der: vec::Vec<vec::Vec<u8>>,
        signing_key: sig::SigningKey,
    },
}

impl Identity {
    pub(super) fn validate(&self) -> Result<(), super::Error> {
        use crate::wire::handshake::messages::Certificate;
        let valid = match self {
            Self::RawPublicKey { signing_key } => signing_key.is_ed25519(),
            Self::X509 {
                chain_der,
                signing_key,
            } => Certificate::chain_fits(chain_der) && signing_key.matches_x509_chain(chain_der),
        };
        if valid {
            Ok(())
        } else {
            Err(super::Error::InvalidIdentity)
        }
    }

    pub(in crate::client) fn signing_key(&self) -> &sig::SigningKey {
        match self {
            Self::RawPublicKey { signing_key } | Self::X509 { signing_key, .. } => signing_key,
        }
    }

    pub(super) fn cert_type(&self) -> u8 {
        use crate::wire::protocols;
        match self {
            Self::RawPublicKey { .. } => protocols::CERT_TYPE_RAW_PUBLIC_KEY,
            Self::X509 { .. } => protocols::CERT_TYPE_X509,
        }
    }

    pub fn try_into_template(self) -> Result<super::IdentityTemplate, super::Error> {
        self.validate()?;
        Ok(super::IdentityTemplate::new(self))
    }
}
