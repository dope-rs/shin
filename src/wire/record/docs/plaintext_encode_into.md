
```
use shin::wire::record::{ContentType, HEADER_LEN, PlaintextRecord};
let mut wire = Vec::new();
PlaintextRecord::encode_into(ContentType::Alert, &[1, 2], &mut wire).unwrap();
assert_eq!(wire.len(), HEADER_LEN + 2);
```
