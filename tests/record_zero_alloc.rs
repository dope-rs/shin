use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::Infallible;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

use shin::client::Client;
use shin::client::config::Config;
use shin::connection::{Epoch, Event, EventContext, EventSink};
use shin::wire::record::{CipherSuite, ContentType, Opener, Sealer};

mod common;
use common::CollectEvents;
use common::{Server, ServerConfig, find_send, has_done, random_signing_key};

const TEST_SECRET: [u8; 32] = [
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
];

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

struct KeyUpdateSink {
    sends: usize,
    updates: usize,
    suite: Option<CipherSuite>,
}

impl EventSink for KeyUpdateSink {
    type Error = Infallible;

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => {
                assert_eq!(epoch, Epoch::Application);
                assert_eq!(data, [24, 0, 0, 1, 0]);
                self.sends += 1;
                self.suite = context.cipher_suite();
            }
            Event::KeyUpdate { .. } => {
                self.updates += 1;
                self.suite = context.cipher_suite();
            }
            event => panic!("unexpected event: {event:?}"),
        }
        Ok(())
    }
}

#[test]
fn caller_owned_record_and_event_hot_paths_allocate_nothing() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET).unwrap();
    let warmup = sealer
        .seal(ContentType::ApplicationData, b"warm up crypto state")
        .unwrap();
    let measured = sealer
        .seal(ContentType::ApplicationData, b"caller-owned output")
        .unwrap();
    let mut opener = Opener::from_secret(&TEST_SECRET).unwrap();
    let mut parts_sealer = Sealer::from_secret(&TEST_SECRET).unwrap();
    let mut warmup_output = [MaybeUninit::uninit(); 128];
    let mut measured_output = [MaybeUninit::uninit(); 128];
    let mut sealed_output = [MaybeUninit::uninit(); 128];
    let parts = [&b"caller-"[..], &b"owned "[..], &b"input"[..]];

    opener
        .open_into_uninit(&warmup, &mut warmup_output)
        .unwrap()
        .unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    let opened = opener
        .open_into_uninit(&measured, &mut measured_output)
        .unwrap()
        .unwrap();
    let sealed = parts_sealer
        .seal_parts_into_uninit(
            ContentType::ApplicationData,
            b"caller-owned input".len(),
            parts,
            &mut sealed_output,
        )
        .unwrap();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(opened.body, b"caller-owned output");
    assert!(!sealed.is_empty());
    assert_eq!(allocations, 0);

    let server_key = random_signing_key();
    let server_pubkey = *server_key.pubkey().unwrap();
    let mut server = Server::new(
        ServerConfig {
            source: shin::server::config::CertSource::RawPublicKey {
                signing_key: server_key,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_keys: None,
            accept_early_data: false,
        },
        || 0,
    );
    let mut client = Client::new(
        Config {
            verifier: shin::client::config::Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        || 0,
    )
    .unwrap();
    let client_start = client.start().unwrap();
    let client_hello = find_send(&client_start, Epoch::Plaintext).unwrap();
    let server_start = server.read(Epoch::Plaintext, &client_hello).unwrap();
    let server_hello = find_send(&server_start, Epoch::Plaintext).unwrap();
    let server_flight = find_send(&server_start, Epoch::Handshake).unwrap();
    client.read(Epoch::Plaintext, &server_hello).unwrap();
    let client_finish = client.read(Epoch::Handshake, &server_flight).unwrap();
    let client_flight = find_send(&client_finish, Epoch::Handshake).unwrap();
    let server_finish = server.read(Epoch::Handshake, &client_flight).unwrap();
    assert!(has_done(&server_finish));

    let key_update = [24, 0, 0, 1, 0];
    let mut sink = KeyUpdateSink {
        sends: 0,
        updates: 0,
        suite: None,
    };
    ALLOCATIONS.store(0, Ordering::Relaxed);
    client.send_key_update_into(false, &mut sink).unwrap();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(sink.sends, 1);
    assert_eq!(sink.updates, 1);
    assert_eq!(sink.suite, Some(CipherSuite::Aes128GcmSha256));
    assert_eq!(allocations, 0);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    client
        .read_into(Epoch::Application, &key_update, &mut sink)
        .unwrap();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(sink.updates, 2);
    assert_eq!(sink.suite, Some(CipherSuite::Aes128GcmSha256));
    assert_eq!(allocations, 0);

    client
        .read_into(Epoch::Application, &key_update[..2], &mut sink)
        .unwrap();
    client
        .read_into(Epoch::Application, &key_update[2..], &mut sink)
        .unwrap();
    ALLOCATIONS.store(0, Ordering::Relaxed);
    client
        .read_into(Epoch::Application, &key_update[..3], &mut sink)
        .unwrap();
    client
        .read_into(Epoch::Application, &key_update[3..], &mut sink)
        .unwrap();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(sink.updates, 4);
    assert_eq!(allocations, 0);
}
