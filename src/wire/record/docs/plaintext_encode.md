
```
use shin::wire::record::{ContentType, HEADER_LEN, Plaintext};
let wire = Plaintext::encode(ContentType::Alert, &[1, 2]).unwrap();
assert_eq!(wire.len(), HEADER_LEN + 2);
```
