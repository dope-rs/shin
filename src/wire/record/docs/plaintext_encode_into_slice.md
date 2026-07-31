
```
use shin::wire::record::{ContentType, HEADER_LEN, PlaintextRecord};
let mut wire = [0u8; 32];
let n = PlaintextRecord::encode_into_slice(ContentType::Alert, &[1, 2], &mut wire).unwrap();
assert_eq!(n, HEADER_LEN + 2);
```
