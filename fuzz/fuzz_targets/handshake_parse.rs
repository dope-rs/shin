#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::wire::codec::Reader;
use shin::wire::handshake::frame::Frame;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    while !r.is_empty() {
        if Frame::decode(&mut r).is_err() {
            break;
        }
    }
});
