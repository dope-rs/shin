#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::crypto::ticket::Keys;

// Ticket decryption runs on attacker-supplied PSK identities before any
// authentication, so it must reject arbitrary bytes without panicking. Both the
// single-key and two-generation paths are exercised.
fuzz_target!(|data: &[u8]| {
    let single = Keys::single([0x11u8; 32]).expect("fixed ticket key");
    let _ = single.decrypt(data);

    let rotated =
        Keys::with_previous([0x22u8; 32], Some([0x33u8; 32])).expect("fixed ticket keys");
    let _ = rotated.decrypt(data);
});
