use crate::crypto::sig;
use crate::identity;
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
            } => {
                Certificate::chain_fits(chain_der)
                    && signing_key.matches_x509_chain(chain_der)
                    && self.outbound_flight_capacity() <= crate::wire::handshake::MAX_SIZE
            }
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

    pub(super) fn cert_type(&self) -> identity::CertificateType {
        use identity::CertificateType;
        match self {
            Self::RawPublicKey { .. } => CertificateType::RawPublicKey,
            Self::X509 { .. } => CertificateType::X509,
        }
    }

    pub(super) fn outbound_flight_capacity(&self) -> usize {
        use crate::crypto::hash;
        use crate::wire::handshake::messages::{Certificate, CertificateVerify};

        const FINISHED_MAX_LEN: usize = 4 + hash::MAX_LEN;

        let certificate_len = match self {
            Self::RawPublicKey { signing_key } => {
                const FIXED_MESSAGE_BYTES: usize = 4 + 1 + 3;
                const ENTRY_FRAMING_BYTES: usize = 3 + 2;
                let Some(pubkey) = signing_key.pubkey() else {
                    return crate::wire::handshake::MAX_SIZE;
                };
                let spki_len =
                    crate::identity::spki::SubjectPublicKey::encoded_ed25519(pubkey).len();
                FIXED_MESSAGE_BYTES + ENTRY_FRAMING_BYTES + spki_len
            }
            Self::X509 { chain_der, .. } => Certificate::chain_message_len(chain_der)
                .unwrap_or(crate::wire::handshake::MAX_SIZE),
        };
        certificate_len
            + CertificateVerify::frame_len(self.signing_key().signature_len_upper_bound())
            + FINISHED_MAX_LEN
    }

    pub fn try_into_template(self) -> Result<super::IdentityTemplate, super::Error> {
        self.validate()?;
        Ok(super::IdentityTemplate::new(self))
    }
}
