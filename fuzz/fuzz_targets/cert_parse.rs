#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::identity::cert::Cert;
use shin::identity::cert::ext::ExtensionIter;

fuzz_target!(|data: &[u8]| {
    let Ok(cert) = Cert::parse(data) else { return };
    let Some(exts) = cert.tbs.extensions_der else {
        return;
    };
    for ext in ExtensionIter::new(exts) {
        if ext.is_err() {
            break;
        }
    }
});
