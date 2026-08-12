use ring::rand::SystemRandom;
use shin::crypto::material::ResumptionPsk;
use shin::crypto::ticket::{Claims, Context, Error, Secret};
use shin::transport::Mode;
use shin::wire::record::CipherSuite;

const SECRET: [u8; 32] = [0x42u8; 32];
const SUITE: CipherSuite = CipherSuite::Aes128GcmSha256;

fn s() -> Secret {
    Secret::new(SECRET).unwrap()
}

#[test]
fn encrypt_then_decrypt_recovers_psk_age_add_and_issued_at() {
    let rng = SystemRandom::new();
    let psk = [0xABu8; 32];
    let age_add = 0x1234_5678u32;
    let issued_at = 1_700_000_000_000u64;
    let ticket = s()
        .encrypt(&psk, age_add, issued_at, SUITE, b"", &rng)
        .unwrap();
    let dt = s().decrypt(&ticket).unwrap();
    assert_eq!(dt.psk.as_array(), &psk);
    assert_eq!(dt.age_add, age_add);
    assert_eq!(dt.issued_at_ms, issued_at);
    assert_eq!(dt.suite, SUITE);
    assert_eq!(dt.alpn.as_slice(), b"");
}

#[test]
fn encrypt_then_decrypt_round_trips_alpn() {
    let rng = SystemRandom::new();
    let psk = [0xCDu8; 32];
    let ticket = s().encrypt(&psk, 7, 42, SUITE, b"h2", &rng).unwrap();
    let dt = s().decrypt(&ticket).unwrap();
    assert_eq!(dt.psk.as_array(), &psk);
    assert_eq!(dt.alpn.as_slice(), b"h2");

    let ticket2 = s().encrypt(&psk, 7, 42, SUITE, b"http/1.1", &rng).unwrap();
    let dt2 = s().decrypt(&ticket2).unwrap();
    assert_eq!(dt2.alpn.as_slice(), b"http/1.1");
}

#[test]
fn encrypt_then_decrypt_round_trips_supported_cipher_suites() {
    let rng = SystemRandom::new();
    for suite in CipherSuite::SUPPORTED {
        let ticket = s().encrypt(&[1; 32], 2, 3, suite, b"", &rng).unwrap();
        assert_eq!(s().decrypt(&ticket).unwrap().suite, suite);
    }
}

#[test]
fn encrypt_rejects_overlong_alpn() {
    let rng = SystemRandom::new();
    let too_long = [0u8; 256];
    assert_eq!(
        s().encrypt(&[0u8; 32], 0, 0, SUITE, &too_long, &rng),
        Err(Error::BadFormat)
    );
}

#[test]
fn decrypt_rejects_tampered_tail() {
    let rng = SystemRandom::new();
    let psk = [0u8; 32];
    let ticket = s().encrypt(&psk, 0, 0, SUITE, b"", &rng).unwrap();
    let mut tampered = ticket.as_slice().to_vec();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    assert_eq!(s().decrypt(&tampered), Err(Error::BadAuth));
}

#[test]
fn decrypt_rejects_wrong_secret() {
    let rng = SystemRandom::new();
    let other = Secret::new([0x00u8; 32]).unwrap();
    let ticket = s().encrypt(&[7u8; 32], 9, 0, SUITE, b"", &rng).unwrap();
    assert_eq!(other.decrypt(&ticket), Err(Error::BadAuth));
}

#[test]
fn decrypt_rejects_short_input() {
    assert_eq!(s().decrypt(&[]), Err(Error::BadFormat));
    assert_eq!(s().decrypt(&[0u8; 10]), Err(Error::BadFormat));
}

#[test]
fn nonce_is_random_so_two_encryptions_differ() {
    let rng = SystemRandom::new();
    let psk = [0u8; 32];
    let a = s().encrypt(&psk, 0, 0, SUITE, b"", &rng).unwrap();
    let b = s().encrypt(&psk, 0, 0, SUITE, b"", &rng).unwrap();
    assert_ne!(a, b);
}

#[test]
fn authenticated_early_data_context_requires_same_mode_and_transport_params() {
    let rng = SystemRandom::new();
    let context = Context::new(Mode::Quic, Some(u32::MAX), b"server tp v1");
    let psk = ResumptionPsk::new([3; 32]);
    let ticket = s()
        .encrypt_claims(
            Claims {
                psk: &psk,
                age_add: 5,
                issued_at_ms: 7,
                suite: SUITE,
                alpn: b"h3",
                context,
            },
            &rng,
        )
        .unwrap();
    let decrypted = s().decrypt(&ticket).unwrap();

    assert_eq!(decrypted.context, context);
    assert_eq!(
        decrypted
            .context
            .early_data_for(Mode::Quic, b"server tp v1"),
        Some(u32::MAX)
    );
    assert_eq!(
        decrypted
            .context
            .early_data_for(Mode::Quic, b"server tp v2"),
        None
    );
    assert_eq!(
        decrypted.context.early_data_for(Mode::Tls, b"server tp v1"),
        None
    );
}

#[test]
fn authenticated_early_data_context_requires_same_replay_domain() {
    let rng = SystemRandom::new();
    let context =
        Context::new_with_replay_domain(Mode::Tls, Some(16_384), b"server context", [41; 16]);
    let psk = ResumptionPsk::new([4; 32]);
    let ticket = s()
        .encrypt_claims(
            Claims {
                psk: &psk,
                age_add: 5,
                issued_at_ms: 7,
                suite: SUITE,
                alpn: b"h2",
                context,
            },
            &rng,
        )
        .unwrap();
    let decrypted = s().decrypt(&ticket).unwrap();

    assert_eq!(decrypted.context.replay_domain(), Some([41; 16]));
    assert_eq!(
        decrypted
            .context
            .early_data_for_replay_domain(Mode::Tls, b"server context", &[41; 16],),
        Some(16_384),
    );
    assert_eq!(
        decrypted
            .context
            .early_data_for_replay_domain(Mode::Tls, b"server context", &[42; 16],),
        None,
    );
    assert_eq!(
        decrypted
            .context
            .early_data_for(Mode::Tls, b"server context"),
        None,
        "domain-bound server tickets cannot be checked through the standalone domain",
    );
}

#[test]
fn malformed_mode_specific_allowance_is_not_issued() {
    let rng = SystemRandom::new();
    let psk = ResumptionPsk::new([0; 32]);
    for context in [
        Context::new(Mode::Tls, Some(u32::MAX), &[]),
        Context::new(Mode::Quic, Some(16_384), &[]),
    ] {
        assert_eq!(
            s().encrypt_claims(
                Claims {
                    psk: &psk,
                    age_add: 0,
                    issued_at_ms: 0,
                    suite: SUITE,
                    alpn: b"",
                    context,
                },
                &rng,
            ),
            Err(Error::BadFormat)
        );
    }
}
