use core::hint::black_box;
use core::mem::size_of;

use ring::rand::SystemRandom;
use shin::client::{Client, Hybrid};
use shin::crypto::kx::{EphemeralKey, HybridWorkspace, KexGroup};
use shin::crypto::ticket;
use shin::wire::handshake::MAX_SIZE;
use shin::wire::handshake::workspace::Scratch;

mod raw;

#[test]
fn default_workspaces_reserve_one_record_not_the_handshake_limit() {
    type TestClock = fn() -> u64;

    let mut client = None;
    let client_profile = raw::measured_with_bytes(|| {
        client = Some(Scratch::for_client());
    });
    let mut server = None;
    let server_profile = raw::measured_with_bytes(|| {
        server = Some(Scratch::for_server());
    });
    let client = client.unwrap();
    let server = server.unwrap();

    assert_eq!(client.capacities(), (MAX_SIZE, MAX_SIZE, 0));
    assert_eq!(server.capacities(), (MAX_SIZE, MAX_SIZE, MAX_SIZE));
    assert_eq!(client_profile, (2, 32 * 1024));
    assert_eq!(server_profile, (2, 32 * 1024));
    assert_eq!(size_of::<Scratch>(), 120);
    assert_eq!(size_of::<Client<TestClock>>(), 4_032);
}

#[test]
fn classical_ephemeral_state_is_small_and_allocation_free() {
    assert_eq!(size_of::<EphemeralKey>(), 144);

    let rng = SystemRandom::new();
    let allocations = raw::measured(|| {
        let key = EphemeralKey::generate(KexGroup::X25519, &rng).unwrap();
        assert_eq!(key.client_share().len(), 32);
        black_box(key);
    });
    assert_eq!(allocations, 0);
}

#[test]
fn compatibility_hybrid_ephemeral_state_pays_one_explicit_allocation() {
    let rng = SystemRandom::new();
    let allocations = raw::measured(|| {
        let key = EphemeralKey::generate(KexGroup::X25519Mlkem768, &rng).unwrap();
        assert_eq!(key.client_share().len(), 1_216);
        black_box(key);
    });
    assert_eq!(allocations, 1);
}

#[test]
fn hybrid_workspace_is_inline_and_charged_only_to_opt_in_clients() {
    type TestClock = fn() -> u64;

    let allocations = raw::measured(|| {
        black_box(HybridWorkspace::new());
    });
    assert_eq!(allocations, 0);

    assert_eq!(size_of::<HybridWorkspace>(), 3_272);
    assert_eq!(size_of::<Hybrid<'static, TestClock>>(), 4_040);
}

#[test]
fn ticket_key_schedule_is_allocated_once_and_reused() {
    assert!(size_of::<ticket::Secret>() <= 2 * size_of::<usize>());

    let mut secret = None;
    let allocations = raw::measured(|| {
        secret = Some(ticket::Secret::new([0x42; 32]));
    });
    assert_eq!(allocations, 1);
    let secret = secret.unwrap();
    assert_eq!(
        raw::measured(|| {
            black_box(secret.clone());
        }),
        0
    );

    let rng = SystemRandom::new();
    let mut encrypted = None;
    let allocations = raw::measured(|| {
        encrypted = Some(
            secret
                .encrypt(&[0x24; 32], 7, 11, 0x1301, b"h3", &rng)
                .unwrap(),
        );
    });
    assert_eq!(allocations, 0);
    let encrypted = encrypted.unwrap();

    let allocations = raw::measured(|| {
        black_box(secret.decrypt(&encrypted).unwrap());
    });
    assert_eq!(allocations, 0);
}
