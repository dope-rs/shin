use crate::crypto::hash::Digest;
use crate::identity::peer::LeafKey;
use zeroize::Zeroize;

#[derive(Clone, Copy)]
pub(super) struct HandshakeSecrets {
    pub(super) handshake: Digest,
    pub(super) client_traffic: Digest,
    pub(super) server_traffic: Digest,
}

/// Client phase whose inline peer key keeps CertificateVerify allocation-free.
#[allow(clippy::large_enum_variant)]
pub(super) enum State {
    Initial,
    ExpectServerHello,
    ExpectEncryptedExtensions {
        secrets: HandshakeSecrets,
    },
    ExpectCertificate {
        secrets: HandshakeSecrets,
    },
    ExpectCertificateVerify {
        secrets: HandshakeSecrets,
        server_leaf_key: LeafKey,
    },
    ExpectServerFinished {
        secrets: HandshakeSecrets,
    },
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StateKind {
    Initial,
    ExpectServerHello,
    ExpectEncryptedExtensions,
    ExpectCertificate,
    ExpectCertificateVerify,
    ExpectServerFinished,
    Done,
}

impl State {
    pub(super) fn kind(&self) -> StateKind {
        match self {
            Self::Initial => StateKind::Initial,
            Self::ExpectServerHello => StateKind::ExpectServerHello,
            Self::ExpectEncryptedExtensions { .. } => StateKind::ExpectEncryptedExtensions,
            Self::ExpectCertificate { .. } => StateKind::ExpectCertificate,
            Self::ExpectCertificateVerify { .. } => StateKind::ExpectCertificateVerify,
            Self::ExpectServerFinished { .. } => StateKind::ExpectServerFinished,
            Self::Done => StateKind::Done,
        }
    }

    pub(super) fn secrets(&self) -> Option<HandshakeSecrets> {
        match self {
            Self::ExpectEncryptedExtensions { secrets }
            | Self::ExpectCertificate { secrets }
            | Self::ExpectCertificateVerify { secrets, .. }
            | Self::ExpectServerFinished { secrets } => Some(*secrets),
            Self::Initial | Self::ExpectServerHello | Self::Done => None,
        }
    }

    pub(super) fn server_leaf_key(&self) -> Option<LeafKey> {
        match self {
            Self::ExpectCertificateVerify {
                server_leaf_key, ..
            } => Some(server_leaf_key.clone()),
            _ => None,
        }
    }

    pub(super) fn zeroize_secrets(&mut self) {
        let secrets = match self {
            Self::ExpectEncryptedExtensions { secrets }
            | Self::ExpectCertificate { secrets }
            | Self::ExpectCertificateVerify { secrets, .. }
            | Self::ExpectServerFinished { secrets } => secrets,
            Self::Initial | Self::ExpectServerHello | Self::Done => return,
        };
        secrets.handshake.as_mut_slice().zeroize();
        secrets.client_traffic.as_mut_slice().zeroize();
        secrets.server_traffic.as_mut_slice().zeroize();
    }
}
