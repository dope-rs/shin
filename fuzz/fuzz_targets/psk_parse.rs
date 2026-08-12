#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::wire::psk::{KxModesRef, OfferedPsks, SelectedIdentity};

// PSK wire parsers must not panic on adversarial bytes.
fuzz_target!(|data: &[u8]| {
    let _ = OfferedPsks::decode(data);
    let _ = KxModesRef::decode(data);
    let _ = SelectedIdentity::decode(data);
});
