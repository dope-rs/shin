#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::wire::codec::Reader;
use shin::wire::handshake::frame::{Borrowed, Frame};

fuzz_target!(|data: &[u8]| {
    let mut borrowed_reader = Reader::new(data);
    let mut owned_reader = Reader::new(data);
    let mut offset = 0usize;
    while !borrowed_reader.is_empty() {
        let before = borrowed_reader.remaining().len();
        let borrowed = Borrowed::decode(&mut borrowed_reader);
        let owned = Frame::decode(&mut owned_reader);
        assert_eq!(
            borrowed_reader.remaining().len(),
            owned_reader.remaining().len(),
            "borrowed and owned decoders consumed different prefixes",
        );

        match (borrowed, owned) {
            (Ok(borrowed), Ok(owned)) => {
                let consumed = before - borrowed_reader.remaining().len();
                let borrowed = borrowed.into_owned();
                assert_eq!(borrowed, owned, "borrowed-to-owned conversion drifted");

                let mut encoded = Vec::new();
                owned.encode(&mut encoded).unwrap();
                assert_eq!(
                    encoded,
                    data[offset..offset + consumed],
                    "accepted message did not round-trip losslessly",
                );
                assert_eq!(
                    Borrowed::decode_exact(&encoded).unwrap().into_owned(),
                    owned,
                );
                offset += consumed;
            }
            (Err(borrowed), Err(owned)) => {
                assert_eq!(borrowed, owned, "borrowed and owned acceptance drifted");
                break;
            }
            _ => panic!("borrowed and owned acceptance drifted"),
        }
    }
});
