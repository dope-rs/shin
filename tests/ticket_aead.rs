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
    let ticket = s().encrypt(&psk, age_add, issued_at, &rng).unwrap();
    let (got_psk, got_age, got_issued) = s().decrypt(&ticket).unwrap();
    assert_eq!(got_psk, psk);
    assert_eq!(got_age, age_add);
    assert_eq!(got_issued, issued_at);
}

#[test]
fn decrypt_rejects_tampered_tail() {
    let rng = SystemRandom::new();
    let psk = [0u8; 32];
    let mut ticket = s().encrypt(&psk, 0, 0, &rng).unwrap();
    let n = ticket.len();
    ticket[n - 1] ^= 0xFF;
    assert_eq!(s().decrypt(&ticket), Err(TicketError::BadAuth));
}

#[test]
fn decrypt_rejects_wrong_secret() {
    let rng = SystemRandom::new();
    let other = TicketSecret::new([0x00u8; 32]);
    let ticket = s().encrypt(&[7u8; 32], 9, 0, &rng).unwrap();
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
    let a = s().encrypt(&psk, 0, 0, &rng).unwrap();
    let b = s().encrypt(&psk, 0, 0, &rng).unwrap();
    assert_ne!(a, b);
}
