//! Thread-scoped heap watermark used only by cfg(test) allocation-capacity evidence.
//!
//! The allocator is process-global because Rust allows no narrower hook, but
//! accounting is thread-local and disabled by default so parallel unit tests do
//! not contaminate one another.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct ThreadPeakAlloc;

thread_local! {
    static ALLOC_ENABLED: Cell<bool> = const { Cell::new(false) };
    static ALLOC_CURRENT: Cell<i64> = const { Cell::new(0) };
    static ALLOC_PEAK: Cell<i64> = const { Cell::new(0) };
}

fn record_alloc(size: usize, positive: bool) {
    ALLOC_ENABLED.with(|enabled| {
        if !enabled.get() {
            return;
        }
        ALLOC_CURRENT.with(|current| {
            let delta = if positive {
                size as i64
            } else {
                -(size as i64)
            };
            let next = current.get() + delta;
            current.set(next);
            ALLOC_PEAK.with(|peak| peak.set(peak.get().max(next)));
        });
    });
}

unsafe impl GlobalAlloc for ThreadPeakAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record_alloc(layout.size(), true);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        record_alloc(layout.size(), false);
    }
}

#[global_allocator]
static TEST_ALLOCATOR: ThreadPeakAlloc = ThreadPeakAlloc;

pub(crate) fn start_measurement() {
    ALLOC_ENABLED.with(|enabled| enabled.set(false));
    ALLOC_CURRENT.with(|current| current.set(0));
    ALLOC_PEAK.with(|peak| peak.set(0));
    ALLOC_ENABLED.with(|enabled| enabled.set(true));
}

pub(crate) fn measurement() -> (i64, i64) {
    ALLOC_ENABLED.with(|enabled| enabled.set(false));
    (ALLOC_CURRENT.with(Cell::get), ALLOC_PEAK.with(Cell::get))
}
