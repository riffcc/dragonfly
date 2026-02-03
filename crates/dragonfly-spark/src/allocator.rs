//! Simple bump allocator for bare-metal networking
//!
//! Allocates from a static buffer. Never frees (suitable for short-lived programs).

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Size of the heap (64KB - smoltcp needs more but disk scan runs first)
const HEAP_SIZE: usize = 64 * 1024;

/// Simple bump allocator
struct BumpAllocator {
    heap: UnsafeCell<[u8; HEAP_SIZE]>,
    next: AtomicUsize,
}

unsafe impl Sync for BumpAllocator {}

impl BumpAllocator {
    const fn new() -> Self {
        BumpAllocator {
            heap: UnsafeCell::new([0; HEAP_SIZE]),
            next: AtomicUsize::new(0),
        }
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        loop {
            let current = self.next.load(Ordering::Relaxed);
            let heap_start = self.heap.get() as usize;

            // Align the current position
            let aligned = (heap_start + current + align - 1) & !(align - 1);
            let offset = aligned - heap_start;
            let new_next = offset + size;

            if new_next > HEAP_SIZE {
                return null_mut(); // Out of memory
            }

            // Try to claim this allocation
            if self.next.compare_exchange_weak(
                current,
                new_next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ).is_ok() {
                return aligned as *mut u8;
            }
            // Otherwise, retry
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator doesn't free - memory is reclaimed when program exits
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

/// Allocation error handler
#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    // Output to serial - simple inline to avoid any dependencies
    unsafe {
        // Output "ALLOC FAIL" directly to serial port 0x3F8
        let msg = b"!!! ALLOC FAIL size=";
        for &b in msg {
            while (core::ptr::read_volatile(0x3F8u16 as *const u8 as *const u8).wrapping_add(5) & 0x20) == 0 {}
            core::ptr::write_volatile(0x3F8 as *mut u8, b);
        }
        // Print size as hex
        let size = layout.size();
        for i in (0..8).rev() {
            let nibble = ((size >> (i * 4)) & 0xF) as u8;
            let c = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
            core::ptr::write_volatile(0x3F8 as *mut u8, c);
        }
        core::ptr::write_volatile(0x3F8 as *mut u8, b'\n');
    }

    loop {
        unsafe {
            core::arch::asm!("cli");
            core::arch::asm!("hlt");
        }
    }
}
