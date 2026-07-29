
```
use shin::record::{ContentType, HEADER_LEN, PlaintextRecord};
let wire = PlaintextRecord::encode(ContentType::Alert, &[1, 2]).unwrap();
assert_eq!(wire.len(), HEADER_LEN + 2);
```
