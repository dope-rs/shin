#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::ticket::TicketKeys;

// Ticket decryption runs on attacker-supplied PSK identities before any
// authentication, so it must reject arbitrary bytes without panicking. Both the
// single-key and two-generation paths are exercised.
fuzz_target!(|data: &[u8]| {
    let single = TicketKeys::single([0x11u8; 32]);
    let _ = single.decrypt(data);

    let rotated = TicketKeys::with_previous([0x22u8; 32], Some([0x33u8; 32]));
    let _ = rotated.decrypt(data);
});
