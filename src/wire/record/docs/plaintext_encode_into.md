
```
use shin::wire::record::{ContentType, HEADER_LEN, Plaintext};
let mut wire = Vec::new();
Plaintext::encode_into(ContentType::Alert, &[1, 2], &mut wire).unwrap();
assert_eq!(wire.len(), HEADER_LEN + 2);
```
