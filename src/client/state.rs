use crate::crypto::material;
use crate::crypto::schedule;
use crate::identity::leafkey;

pub(super) struct HandshakeSecrets {
    pub(super) schedule: schedule::Schedule,
    pub(super) client_traffic: material::TrafficSecret,
    pub(super) server_traffic: material::TrafficSecret,
}

/// Fixed client-handshake storage keeps the peer key inline without making one
/// state variant disproportionately large.
pub(super) struct State {
    kind: StateKind,
    secrets: Option<HandshakeSecrets>,
    server_leaf_key: Option<leafkey::LeafKey>,
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
    Failed,
}

impl State {
    pub(super) fn initial() -> Self {
        Self::empty(StateKind::Initial)
    }

    pub(super) fn expect_server_hello() -> Self {
        Self::empty(StateKind::ExpectServerHello)
    }

    pub(super) fn expect_encrypted_extensions(secrets: HandshakeSecrets) -> Self {
        Self::with_secrets(StateKind::ExpectEncryptedExtensions, secrets)
    }

    pub(super) fn expect_certificate(secrets: HandshakeSecrets) -> Self {
        Self::with_secrets(StateKind::ExpectCertificate, secrets)
    }

    pub(super) fn expect_certificate_verify(
        secrets: HandshakeSecrets,
        server_leaf_key: leafkey::LeafKey,
    ) -> Self {
        Self {
            kind: StateKind::ExpectCertificateVerify,
            secrets: Some(secrets),
            server_leaf_key: Some(server_leaf_key),
        }
    }

    pub(super) fn expect_server_finished(secrets: HandshakeSecrets) -> Self {
        Self::with_secrets(StateKind::ExpectServerFinished, secrets)
    }

    pub(super) fn done() -> Self {
        Self::empty(StateKind::Done)
    }

    pub(super) fn fail(&mut self) {
        self.zeroize_secrets();
        self.kind = StateKind::Failed;
        self.secrets = None;
        self.server_leaf_key = None;
    }

    fn empty(kind: StateKind) -> Self {
        Self {
            kind,
            secrets: None,
            server_leaf_key: None,
        }
    }

    fn with_secrets(kind: StateKind, secrets: HandshakeSecrets) -> Self {
        Self {
            kind,
            secrets: Some(secrets),
            server_leaf_key: None,
        }
    }

    pub(super) fn kind(&self) -> StateKind {
        self.kind
    }

    pub(super) fn take_secrets(&mut self) -> Option<HandshakeSecrets> {
        self.secrets.take()
    }

    pub(super) fn server_leaf_key(&self) -> Option<leafkey::LeafKey> {
        self.server_leaf_key.clone()
    }

    pub(super) fn zeroize_secrets(&mut self) {
        self.secrets = None;
    }
}
