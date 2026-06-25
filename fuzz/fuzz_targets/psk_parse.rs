#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::psk::{KxModes, Offer, SelectedIdentity};

// PSK wire parsers must not panic on adversarial bytes.
fuzz_target!(|data: &[u8]| {
    let _ = Offer::decode(data);
    let _ = KxModes::decode(data);
    let _ = SelectedIdentity::decode(data);
});
