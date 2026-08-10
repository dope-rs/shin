use crate::crypto::sig;
use alloc::vec;

#[derive(Clone)]
pub enum Verifier {
    RawPublicKey {
        expected_pubkey: [u8; sig::PUBKEY_LEN],
    },
    X509 {
        anchors: vec::Vec<super::OwnedTrustAnchor>,
        hostname: vec::Vec<u8>,
    },
}
