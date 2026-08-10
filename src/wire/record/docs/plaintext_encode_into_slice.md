
```
use shin::wire::record::{ContentType, HEADER_LEN, Plaintext};
let mut wire = [0u8; 32];
let n = Plaintext::encode_into_slice(ContentType::Alert, &[1, 2], &mut wire).unwrap();
assert_eq!(n, HEADER_LEN + 2);
```
