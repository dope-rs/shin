
```
use shin::record::{AEAD_TAG_LEN, ContentType, HEADER_LEN, Sealer};
let mut sealer = Sealer::from_secret(&[0u8; 32]).unwrap();
let mut wire = [0u8; 64];
let n = sealer
    .seal_into_slice(ContentType::ApplicationData, b"hi", &mut wire)
    .unwrap();
assert_eq!(n, HEADER_LEN + b"hi".len() + 1 + AEAD_TAG_LEN);
```
