
```
use shin::record::{ContentType, Sealer};
let mut sealer = Sealer::from_secret(&[0u8; 32]).unwrap();
let mut staged = Vec::new();
sealer.seal_into(ContentType::ApplicationData, b"a", &mut staged).unwrap();
sealer.seal_into(ContentType::ApplicationData, b"b", &mut staged).unwrap();
```
