#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::wire::record::{Opener, Plaintext};

fuzz_target!(|data: &[u8]| {
    let _ = Plaintext::parse(data);
    let mut buf = data.to_vec();
    let mut opener = Opener::from_secret(&[0x11u8; 32]).expect("fixed key must be valid");
    let _ = opener.open(&mut buf);
});
