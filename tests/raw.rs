#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static COUNT_THREAD_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static THREAD_ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn record_allocation(bytes: usize) {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    let _ = COUNT_THREAD_ALLOCATIONS.try_with(|active| {
        if active.get() {
            let _ = THREAD_ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
    });
    let _ = COUNT_THREAD_ALLOCATIONS.try_with(|active| {
        if active.get() {
            let _ = THREAD_ALLOCATED_BYTES
                .try_with(|allocated| allocated.set(allocated.get().saturating_add(bytes)));
        }
    });
}

pub(crate) fn measured(run: impl FnOnce()) -> usize {
    measured_with_bytes(run).0
}

pub(crate) fn measured_with_bytes(run: impl FnOnce()) -> (usize, usize) {
    THREAD_ALLOCATIONS.with(|count| count.set(0));
    THREAD_ALLOCATED_BYTES.with(|bytes| bytes.set(0));
    COUNT_THREAD_ALLOCATIONS.with(|active| active.set(true));
    run();
    COUNT_THREAD_ALLOCATIONS.with(|active| active.set(false));
    (
        THREAD_ALLOCATIONS.with(Cell::get),
        THREAD_ALLOCATED_BYTES.with(Cell::get),
    )
}

pub(crate) fn reset() {
    ALLOCATIONS.store(0, Ordering::Relaxed);
}

pub(crate) fn count() -> usize {
    ALLOCATIONS.load(Ordering::Relaxed)
}
