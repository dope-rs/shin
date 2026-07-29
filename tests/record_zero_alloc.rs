use std::alloc::{GlobalAlloc, Layout, System};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

use shin::record::{ContentType, Opener, Sealer};

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

#[test]
fn open_into_uninit_hot_path_allocates_nothing() {
    let mut sealer = Sealer::from_secret(&TEST_SECRET).unwrap();
    let warmup = sealer
        .seal(ContentType::ApplicationData, b"warm up crypto state")
        .unwrap();
    let measured = sealer
        .seal(ContentType::ApplicationData, b"caller-owned output")
        .unwrap();
    let mut opener = Opener::from_secret(&TEST_SECRET).unwrap();
    let mut warmup_output = [MaybeUninit::uninit(); 128];
    let mut measured_output = [MaybeUninit::uninit(); 128];

    opener
        .open_into_uninit(&warmup, &mut warmup_output)
        .unwrap()
        .unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    let opened = opener
        .open_into_uninit(&measured, &mut measured_output)
        .unwrap()
        .unwrap();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(opened.body, b"caller-owned output");
    assert_eq!(allocations, 0);
}
