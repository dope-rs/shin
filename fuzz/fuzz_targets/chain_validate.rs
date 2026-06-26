#![no_main]

use libfuzzer_sys::fuzz_target;
use shin::cert::Cert;
use shin::chain::{Chain, TrustAnchor};
use shin::time::UnixTime;

// Split the input into length-prefixed DER blobs, parse each as a certificate,
// and run full chain validation. Exercises the hand-written cert-value parser
// and the path builder against arbitrary bytes; must never panic.
fuzz_target!(|data: &[u8]| {
    let mut blobs: Vec<&[u8]> = Vec::new();
    let mut r = data;
    while r.len() >= 2 {
        let len = u16::from_be_bytes([r[0], r[1]]) as usize;
        r = &r[2..];
        let take = len.min(r.len());
        let (chunk, rest) = r.split_at(take);
        blobs.push(chunk);
        r = rest;
        if blobs.len() >= 12 {
            break;
        }
    }

    let certs: Vec<Cert<'_>> = blobs.iter().filter_map(|b| Cert::parse(b).ok()).collect();
    if certs.is_empty() {
        return;
    }
    let anchors: Vec<TrustAnchor<'_>> = certs.iter().map(TrustAnchor::from_cert).collect();
    let _ = Chain::validate(&certs, &anchors, UnixTime(1_700_000_000), b"example.com");
});
