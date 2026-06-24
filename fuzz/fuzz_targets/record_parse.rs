#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::record::{Opener, PlaintextRecord};

fuzz_target!(|data: &[u8]| {
    let _ = PlaintextRecord::parse(data);
    let mut buf = data.to_vec();
    let mut opener = Opener::from_secret(&[0x11u8; 32]);
    let _ = opener.open(&mut buf);
});
