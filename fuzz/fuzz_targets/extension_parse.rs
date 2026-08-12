#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::wire::codec::Reader;
use shin::wire::extension::Extensions;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let _ = Extensions::decode(&mut r);
});
