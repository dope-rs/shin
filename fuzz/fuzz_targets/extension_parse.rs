#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::codec::Reader;
use shin::extension::Extension;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let _ = Extension::decode_list(&mut r);
});
