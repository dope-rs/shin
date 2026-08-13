use crate::crypto::material;
use crate::crypto::schedule;
use crate::identity::leafkey;
use core::mem;

pub(super) struct HandshakeSecrets {
    pub(super) schedule: schedule::Schedule,
    pub(super) client_traffic: material::TrafficSecret,
    pub(super) server_traffic: material::TrafficSecret,
}

/// Where the authenticated server key lives until CertificateVerify. The
/// marker is connection state; the bytes remain in their natural owner.
#[derive(Clone, Copy)]
pub(super) enum ServerLeaf {
    PinnedEd25519,
    Flight(leafkey::LeafKeyKind),
}

/// Client phase with exactly the values required by the next input. Unlike a
/// flattened option bag, impossible phase/data combinations are unrepresentable.
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
        server_leaf: ServerLeaf,
    },
    ExpectServerFinished {
        secrets: HandshakeSecrets,
    },
    Done,
    Failed,
}

const _: () = assert!(mem::size_of::<ServerLeaf>() == 1);
const _: () = assert!(mem::size_of::<State>() <= 184);

impl State {
    pub(super) fn initial() -> Self {
        Self::Initial
    }

    pub(super) fn expect_server_hello() -> Self {
        Self::ExpectServerHello
    }

    pub(super) fn expect_encrypted_extensions(secrets: HandshakeSecrets) -> Self {
        Self::ExpectEncryptedExtensions { secrets }
    }

    pub(super) fn expect_certificate(secrets: HandshakeSecrets) -> Self {
        Self::ExpectCertificate { secrets }
    }

    pub(super) fn expect_certificate_verify(
        secrets: HandshakeSecrets,
        server_leaf: ServerLeaf,
    ) -> Self {
        Self::ExpectCertificateVerify {
            secrets,
            server_leaf,
        }
    }

    pub(super) fn expect_server_finished(secrets: HandshakeSecrets) -> Self {
        Self::ExpectServerFinished { secrets }
    }

    pub(super) fn done() -> Self {
        Self::Done
    }

    pub(super) fn fail(&mut self) {
        *self = Self::Failed;
    }

    pub(super) fn zeroize_secrets(&mut self) {
        self.fail();
    }
}
