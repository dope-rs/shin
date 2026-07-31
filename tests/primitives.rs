use ring::rand::SystemRandom;

use shin::crypto::hash::{Digest, HashAlg, Transcript};
use shin::crypto::kdf::{Hkdf, HkdfError};
use shin::crypto::kx::{EphemeralKey, KexGroup, KxError};
use shin::wire::record::{CipherSuite, ContentType, Opener, Sealer};

const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const X25519_LEN: usize = 32;

#[test]
fn transcript_dual_context_matches_oneshot() {
    let mut t = Transcript::new();
    t.update(b"hello ");
    t.update(b"world");
    assert_eq!(
        t.hash(HashAlg::Sha256),
        HashAlg::Sha256.hash(b"hello world")
    );
    assert_eq!(
        t.hash(HashAlg::Sha384),
        HashAlg::Sha384.hash(b"hello world")
    );
    assert_eq!(t.hash(HashAlg::Sha256).len(), 32);
    assert_eq!(t.hash(HashAlg::Sha384).len(), 48);
}

#[test]
fn digest_equality_ignores_padding() {
    assert_eq!(
        Digest::from_slice(&[1, 2, 3]),
        Digest::from_slice(&[1, 2, 3])
    );
    assert_ne!(Digest::from_slice(&[1, 2, 3]), Digest::from_slice(&[1, 2]));
}

#[test]
fn hkdf_sha384_produces_48_byte_secrets() {
    let prk = [0x42u8; 48];
    let hkdf = Hkdf::new(HashAlg::Sha384);
    assert_eq!(hkdf.extract(b"salt", b"ikm").len(), 48);
    let d = hkdf.derive_secret(&prk, "deriv", b"").unwrap();
    assert_eq!(d.len(), 48);
    assert_ne!(d.as_slice(), [0u8; 48]);
}

#[test]
fn hkdf_rejects_oversized_inputs() {
    let hkdf = Hkdf::new(HashAlg::Sha256);
    let mut too_much_output = vec![0; 255 * 32 + 1];
    assert_eq!(
        hkdf.expand(&[0; 32], b"", &mut too_much_output),
        Err(HkdfError::OutputTooLong)
    );
    assert_eq!(
        hkdf.expand_label(&[0; 32], &"x".repeat(250), b"", &mut [0; 32]),
        Err(HkdfError::LabelTooLong)
    );
    assert_eq!(
        hkdf.expand_label(&[0; 32], "x", &[0; 256], &mut [0; 32]),
        Err(HkdfError::ContextTooLong)
    );
}

#[test]
fn each_cipher_suite_round_trips() {
    let s256 = [0x11u8; 32];
    let s384 = [0x42u8; 48];
    for (suite, secret) in [
        (CipherSuite::Aes128GcmSha256, &s256[..]),
        (CipherSuite::ChaCha20Poly1305Sha256, &s256[..]),
        (CipherSuite::Aes256GcmSha384, &s384[..]),
    ] {
        let mut sealer = Sealer::with_suite(secret, suite).unwrap();
        let mut opener = Opener::with_suite(secret, suite).unwrap();
        let mut wire = sealer
            .seal(ContentType::ApplicationData, b"payload")
            .unwrap();
        let (ty, range, _) = opener.open(&mut wire).unwrap().unwrap();
        assert_eq!(ty, ContentType::ApplicationData);
        assert_eq!(&wire[range], b"payload", "{suite:?}");
    }
}

#[test]
fn cipher_suite_u16_round_trips() {
    for s in CipherSuite::SUPPORTED {
        assert_eq!(CipherSuite::from_u16(s.wire_id()), Some(s));
    }
    assert_eq!(CipherSuite::from_u16(0x0000), None);
}

#[test]
fn kex_group_u16_round_trips() {
    for group in KexGroup::SUPPORTED {
        assert_eq!(KexGroup::from_u16(group.wire_id()), Some(group));
    }
    assert_eq!(KexGroup::from_u16(0xffff), None);
}

#[test]
fn classical_groups_round_trip() {
    let rng = SystemRandom::new();
    for group in [KexGroup::X25519, KexGroup::Secp256r1] {
        let client = EphemeralKey::generate(group, &rng).unwrap();
        let client_share = client.client_share().to_vec();
        let (server_share, server_ss) = group.respond(&client_share, &rng).unwrap();
        let client_ss = client.agree(&server_share).unwrap();
        assert_eq!(client_ss.as_slice(), server_ss.as_slice());
        assert_eq!(client_ss.as_slice().len(), 32);
    }
}

#[test]
fn hybrid_round_trips_with_64_byte_secret() {
    let rng = SystemRandom::new();
    let group = KexGroup::X25519Mlkem768;
    let client = EphemeralKey::generate(group, &rng).unwrap();
    let client_share = client.client_share().to_vec();
    assert_eq!(client_share.len(), MLKEM768_EK_LEN + X25519_LEN);

    let (server_share, server_ss) = group.respond(&client_share, &rng).unwrap();
    assert_eq!(server_share.len(), MLKEM768_CT_LEN + X25519_LEN);

    let client_ss = client.agree(&server_share).unwrap();
    assert_eq!(client_ss.as_slice(), server_ss.as_slice());
    assert_eq!(client_ss.as_slice().len(), 64);
}

#[test]
fn hybrid_rejects_malformed_shares() {
    let rng = SystemRandom::new();
    let group = KexGroup::X25519Mlkem768;
    assert_eq!(
        group.respond(&[0u8; 10], &rng).unwrap_err(),
        KxError::InvalidPubkey
    );
    let client = EphemeralKey::generate(group, &rng).unwrap();
    assert_eq!(
        client.agree(&[0u8; 10]).unwrap_err(),
        KxError::InvalidPubkey
    );
}
