use ring::rand::SystemRandom;
use shin::ticket::{TicketError, TicketSecret};

const SECRET: [u8; 32] = [0x42u8; 32];

fn s() -> TicketSecret {
    TicketSecret::new(SECRET)
}

#[test]
fn encrypt_then_decrypt_recovers_psk_age_add_and_issued_at() {
    let rng = SystemRandom::new();
    let psk = [0xABu8; 32];
    let age_add = 0x1234_5678u32;
    let issued_at = 1_700_000_000_000u64;
    let ticket = s()
        .encrypt(&psk, age_add, issued_at, 0x1301, b"", &rng)
        .unwrap();
    let dt = s().decrypt(&ticket).unwrap();
    assert_eq!(dt.psk, psk);
    assert_eq!(dt.age_add, age_add);
    assert_eq!(dt.issued_at_ms, issued_at);
    assert_eq!(dt.suite, 0x1301);
    assert_eq!(dt.alpn, b"");
}

#[test]
fn encrypt_then_decrypt_round_trips_alpn() {
    let rng = SystemRandom::new();
    let psk = [0xCDu8; 32];
    let ticket = s().encrypt(&psk, 7, 42, 0x1301, b"h2", &rng).unwrap();
    let dt = s().decrypt(&ticket).unwrap();
    assert_eq!(dt.psk, psk);
    assert_eq!(dt.alpn, b"h2");

    let ticket2 = s().encrypt(&psk, 7, 42, 0x1301, b"http/1.1", &rng).unwrap();
    let dt2 = s().decrypt(&ticket2).unwrap();
    assert_eq!(dt2.alpn, b"http/1.1");
}

#[test]
fn encrypt_rejects_overlong_alpn() {
    let rng = SystemRandom::new();
    let too_long = [0u8; 256];
    assert_eq!(
        s().encrypt(&[0u8; 32], 0, 0, 0x1301, &too_long, &rng),
        Err(TicketError::BadFormat)
    );
}

#[test]
fn decrypt_rejects_tampered_tail() {
    let rng = SystemRandom::new();
    let psk = [0u8; 32];
    let mut ticket = s().encrypt(&psk, 0, 0, 0x1301, b"", &rng).unwrap();
    let n = ticket.len();
    ticket[n - 1] ^= 0xFF;
    assert_eq!(s().decrypt(&ticket), Err(TicketError::BadAuth));
}

#[test]
fn decrypt_rejects_wrong_secret() {
    let rng = SystemRandom::new();
    let other = TicketSecret::new([0x00u8; 32]);
    let ticket = s().encrypt(&[7u8; 32], 9, 0, 0x1301, b"", &rng).unwrap();
    assert_eq!(other.decrypt(&ticket), Err(TicketError::BadAuth));
}

#[test]
fn decrypt_rejects_short_input() {
    assert_eq!(s().decrypt(&[]), Err(TicketError::BadFormat));
    assert_eq!(s().decrypt(&[0u8; 10]), Err(TicketError::BadFormat));
}

#[test]
fn nonce_is_random_so_two_encryptions_differ() {
    let rng = SystemRandom::new();
    let psk = [0u8; 32];
    let a = s().encrypt(&psk, 0, 0, 0x1301, b"", &rng).unwrap();
    let b = s().encrypt(&psk, 0, 0, 0x1301, b"", &rng).unwrap();
    assert_ne!(a, b);
}
