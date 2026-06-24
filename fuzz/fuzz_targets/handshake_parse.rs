#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::codec::Reader;
use shin::handshake::Handshake;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    while !r.is_empty() {
        if Handshake::decode(&mut r).is_err() {
            break;
        }
    }
});
