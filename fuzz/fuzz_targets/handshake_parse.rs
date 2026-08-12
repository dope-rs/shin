#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::wire::codec::Reader;
use shin::wire::handshake::frame::MessageRef;

fuzz_target!(|data: &[u8]| {
    let mut borrowed_reader = Reader::new(data);
    let mut offset = 0usize;
    while !borrowed_reader.is_empty() {
        let before = borrowed_reader.remaining().len();
        match MessageRef::decode_from(&mut borrowed_reader) {
            Ok(borrowed) => {
                let consumed = before - borrowed_reader.remaining().len();
                let owned = borrowed.into_owned();

                let mut encoded = Vec::new();
                owned.encode(&mut encoded).unwrap();
                assert_eq!(
                    encoded,
                    data[offset..offset + consumed],
                    "accepted message did not round-trip losslessly",
                );
                assert_eq!(
                    MessageRef::decode(&encoded).unwrap().into_owned(),
                    owned,
                );
                offset += consumed;
            }
            Err(_) => break,
        }
    }
});
