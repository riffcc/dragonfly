//! VirtIO Network driver for bare-metal networking
//!
//! Provides Ethernet frame transmission and reception using VirtIO-net.
//! Integrates with smoltcp for TCP/IP stack.

use crate::pci;
use crate::serial;
use core::cell::UnsafeCell;

/// VirtIO vendor ID
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// VirtIO network device ID (transitional)
const VIRTIO_NET_DEVICE_TRANSITIONAL: u16 = 0x1000;
/// VirtIO network device ID (modern, non-transitional)
const VIRTIO_NET_DEVICE_MODERN: u16 = 0x1041;

/// VirtIO device status bits
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

/// VirtIO-net queue indices
const VIRTIO_NET_QUEUE_RX: u16 = 0;
const VIRTIO_NET_QUEUE_TX: u16 = 1;

/// VirtIO-net feature bits
const VIRTIO_NET_F_MAC: u32 = 1 << 5;        // Device has MAC address
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;    // Device has status field
const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15; // Merge RX buffers

/// Virtqueue sizes - must match device's queue sizes
const RX_QUEUE_SIZE: usize = 1024;
const TX_QUEUE_SIZE: usize = 256;

/// Maximum Ethernet frame size (MTU 1500 + headers)
const MAX_FRAME_SIZE: usize = 1514;

/// Number of RX buffers to keep ready
const RX_BUFFER_COUNT: usize = 16;

/// VirtIO-net header (prepended to each packet)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    // Note: num_buffers field only present with VIRTIO_NET_F_MRG_RXBUF
}

/// Virtqueue descriptor
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Virtqueue used element
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

// RX Queue structures (1024 entries)
#[repr(C)]
struct RxVirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; RX_QUEUE_SIZE],
}

#[repr(C)]
struct RxVirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; RX_QUEUE_SIZE],
}

// RX: desc = 1024*16 = 16384, avail = 4 + 2048 = 2052, total = 18436
// Next page = 20480, padding = 2044
const RX_QUEUE_PADDING: usize = 2044;

#[repr(C, align(4096))]
struct RxVirtioQueue {
    desc: [VirtqDesc; RX_QUEUE_SIZE],
    avail: RxVirtqAvail,
    _padding: [u8; RX_QUEUE_PADDING],
    used: RxVirtqUsed,
}

// TX Queue structures (256 entries)
#[repr(C)]
struct TxVirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; TX_QUEUE_SIZE],
}

#[repr(C)]
struct TxVirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; TX_QUEUE_SIZE],
}

// TX: desc = 256*16 = 4096, avail = 4 + 512 = 516, total = 4612
// Next page = 8192, padding = 3580
const TX_QUEUE_PADDING: usize = 3580;

#[repr(C, align(4096))]
struct TxVirtioQueue {
    desc: [VirtqDesc; TX_QUEUE_SIZE],
    avail: TxVirtqAvail,
    _padding: [u8; TX_QUEUE_PADDING],
    used: TxVirtqUsed,
}

/// RX/TX packet buffer (header + frame data)
#[repr(C)]
#[derive(Clone, Copy)]
struct PacketBuffer {
    header: VirtioNetHeader,
    data: [u8; MAX_FRAME_SIZE],
}

/// Sync wrapper for static data
struct SyncUnsafeCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    const fn new(value: T) -> Self {
        SyncUnsafeCell(UnsafeCell::new(value))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// Static storage for virtqueues
static RX_QUEUE: SyncUnsafeCell<RxVirtioQueue> = SyncUnsafeCell::new(RxVirtioQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; RX_QUEUE_SIZE],
    avail: RxVirtqAvail { flags: 0, idx: 0, ring: [0; RX_QUEUE_SIZE] },
    _padding: [0; RX_QUEUE_PADDING],
    used: RxVirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; RX_QUEUE_SIZE] },
});

static TX_QUEUE: SyncUnsafeCell<TxVirtioQueue> = SyncUnsafeCell::new(TxVirtioQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; TX_QUEUE_SIZE],
    avail: TxVirtqAvail { flags: 0, idx: 0, ring: [0; TX_QUEUE_SIZE] },
    _padding: [0; TX_QUEUE_PADDING],
    used: TxVirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; TX_QUEUE_SIZE] },
});

// RX buffers - pre-allocated for receiving packets
static RX_BUFFERS: SyncUnsafeCell<[PacketBuffer; RX_BUFFER_COUNT]> = SyncUnsafeCell::new(
    [PacketBuffer {
        header: VirtioNetHeader { flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0, csum_start: 0, csum_offset: 0 },
        data: [0; MAX_FRAME_SIZE],
    }; RX_BUFFER_COUNT]
);

// TX buffer - single buffer for sending
static TX_BUFFER: SyncUnsafeCell<PacketBuffer> = SyncUnsafeCell::new(PacketBuffer {
    header: VirtioNetHeader { flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0, csum_start: 0, csum_offset: 0 },
    data: [0; MAX_FRAME_SIZE],
});

/// VirtIO Network device
pub struct VirtioNet {
    io_base: u16,
    mac_address: [u8; 6],
    rx_last_used: u16,
    tx_next_desc: u16,
}

impl VirtioNet {
    /// Try to find and initialize a VirtIO-net device
    pub fn init() -> Option<Self> {
        serial::println("VirtIO-net: Scanning for controller...");
        serial::print("VirtIO-net: Looking for vendor=0x");
        serial::print_hex32(VIRTIO_VENDOR as u32);
        serial::print(" device=0x");
        serial::print_hex32(VIRTIO_NET_DEVICE_TRANSITIONAL as u32);
        serial::println("");

        // Find VirtIO-net device on PCI bus (try transitional first, then modern)
        let device = match pci::find_device(VIRTIO_VENDOR, VIRTIO_NET_DEVICE_TRANSITIONAL) {
            Some(d) => {
                serial::println("VirtIO-net: Found transitional device!");
                d
            }
            None => {
                serial::println("VirtIO-net: Transitional not found, trying modern...");
                serial::print("VirtIO-net: Looking for device=0x");
                serial::print_hex32(VIRTIO_NET_DEVICE_MODERN as u32);
                serial::println("");
                match pci::find_device(VIRTIO_VENDOR, VIRTIO_NET_DEVICE_MODERN) {
                    Some(d) => {
                        serial::println("VirtIO-net: Found modern device!");
                        d
                    }
                    None => {
                        serial::println("VirtIO-net: No device found!");
                        return None;
                    }
                }
            }
        };

        serial::print("VirtIO-net: Found at ");
        serial::print_dec(device.bus as u32);
        serial::print(":");
        serial::print_dec(device.slot as u32);
        serial::print(".");
        serial::print_dec(device.func as u32);
        serial::println("");

        // Enable bus mastering
        let cmd = pci::config_read_word(device.bus, device.slot, device.func, 0x04);
        pci::config_write_word(device.bus, device.slot, device.func, 0x04, cmd | 0x07);

        // Get I/O base address from BAR0
        let bar0 = pci::config_read_dword(device.bus, device.slot, device.func, 0x10);
        let io_base = (bar0 & 0xFFFC) as u16;

        serial::print("VirtIO-net: I/O base = 0x");
        serial::print_hex32(io_base as u32);
        serial::println("");

        if io_base == 0 {
            serial::println("VirtIO-net: ERROR - I/O base is 0!");
            return None;
        }

        serial::println("VirtIO-net: Resetting device...");
        // Reset device
        unsafe {
            outb(io_base + 18, 0); // Status = 0 (reset)
        }

        serial::println("VirtIO-net: Setting ACKNOWLEDGE...");
        // Set ACKNOWLEDGE status
        unsafe {
            outb(io_base + 18, VIRTIO_STATUS_ACKNOWLEDGE);
        }

        serial::println("VirtIO-net: Setting DRIVER...");
        // Set DRIVER status
        unsafe {
            outb(io_base + 18, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        }

        serial::println("VirtIO-net: Reading features...");
        // Read and negotiate features
        let features = unsafe { inl(io_base + 0) };
        serial::print("VirtIO-net: Features = 0x");
        serial::print_hex32(features);
        serial::println("");

        // We want: MAC address, and we DON'T want mergeable RX buffers (simpler)
        let wanted_features = VIRTIO_NET_F_MAC;
        unsafe {
            outl(io_base + 4, wanted_features);
        }

        // Set FEATURES_OK
        unsafe {
            let status = inb(io_base + 18);
            outb(io_base + 18, status | VIRTIO_STATUS_FEATURES_OK);
        }

        // Verify FEATURES_OK was accepted
        let status = unsafe { inb(io_base + 18) };
        if status & VIRTIO_STATUS_FEATURES_OK == 0 {
            serial::println("VirtIO-net: Features not accepted!");
            return None;
        }

        serial::println("VirtIO-net: Reading MAC address...");
        // Read MAC address from device config (offset 20 in legacy mode)
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = unsafe { inb(io_base + 20 + i as u16) };
        }
        serial::print("VirtIO-net: MAC = ");
        for i in 0..6 {
            serial::print_hex32(mac[i] as u32);
            if i < 5 { serial::print(":"); }
        }
        serial::println("");

        serial::println("VirtIO-net: Setting up RX queue...");
        // Initialize RX queue
        unsafe {
            outw(io_base + 14, VIRTIO_NET_QUEUE_RX);
            let queue_size = inw(io_base + 12);
            serial::print("VirtIO-net: RX queue size = ");
            serial::print_dec(queue_size as u32);
            serial::println("");

            let rx_queue = RX_QUEUE.get();
            serial::print("VirtIO-net: RX queue addr = 0x");
            serial::print_hex32(rx_queue as u32);
            serial::println("");
            let rx_pfn = (rx_queue as u32) >> 12;
            outl(io_base + 8, rx_pfn);
        }

        serial::println("VirtIO-net: Setting up TX queue...");
        // Initialize TX queue
        unsafe {
            outw(io_base + 14, VIRTIO_NET_QUEUE_TX);
            let queue_size = inw(io_base + 12);
            serial::print("VirtIO-net: TX queue size = ");
            serial::print_dec(queue_size as u32);
            serial::println("");

            let tx_queue = TX_QUEUE.get();
            serial::print("VirtIO-net: TX queue addr = 0x");
            serial::print_hex32(tx_queue as u32);
            serial::println("");
            let tx_pfn = (tx_queue as u32) >> 12;
            outl(io_base + 8, tx_pfn);
        }

        serial::println("VirtIO-net: Populating RX buffers...");
        // Populate RX queue with buffers (but don't notify yet)
        unsafe {
            let rx_queue = &mut *RX_QUEUE.get();
            let rx_buffers = &mut *RX_BUFFERS.get();

            for i in 0..RX_BUFFER_COUNT {
                let buf_addr = &rx_buffers[i] as *const _ as u64;
                rx_queue.desc[i] = VirtqDesc {
                    addr: buf_addr,
                    len: (core::mem::size_of::<VirtioNetHeader>() + MAX_FRAME_SIZE) as u32,
                    flags: VIRTQ_DESC_F_WRITE, // Device writes to this buffer
                    next: 0,
                };
                rx_queue.avail.ring[i] = i as u16;
            }
            rx_queue.avail.idx = RX_BUFFER_COUNT as u16;
        }

        // Set DRIVER_OK to finish initialization
        unsafe {
            let status = inb(io_base + 18);
            outb(io_base + 18, status | VIRTIO_STATUS_DRIVER_OK);
        }

        // NOW notify device about RX buffers (after DRIVER_OK)
        unsafe {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            outw(io_base + 16, VIRTIO_NET_QUEUE_RX);
        }

        // Debug: show RX queue state
        unsafe {
            let rx_queue = &*RX_QUEUE.get();
            serial::print("VirtIO-net: RX avail.idx=");
            serial::print_dec(rx_queue.avail.idx as u32);
            serial::print(" used.idx=");
            serial::print_dec(rx_queue.used.idx as u32);
            serial::println("");
        }

        serial::println("VirtIO-net: Initialized");

        Some(VirtioNet {
            io_base,
            mac_address: mac,
            rx_last_used: 0,
            tx_next_desc: 0,
        })
    }

    /// Get the MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Debug: print RX queue state
    pub fn debug_rx_state(&self) {
        unsafe {
            let rx_queue = &*RX_QUEUE.get();
            let avail = core::ptr::read_volatile(&rx_queue.avail.idx);
            let used = core::ptr::read_volatile(&rx_queue.used.idx);
            serial::print("RX: avail=");
            serial::print_dec(avail as u32);
            serial::print(" used=");
            serial::print_dec(used as u32);
            serial::print(" last=");
            serial::print_dec(self.rx_last_used as u32);
            serial::println("");
        }
    }

    /// Send an Ethernet frame
    pub fn send(&mut self, frame: &[u8]) -> bool {
        if frame.len() > MAX_FRAME_SIZE {
            serial::println("VirtIO-net: Frame too large");
            return false;
        }

        unsafe {
            let tx_queue = &mut *TX_QUEUE.get();
            let tx_buffer = &mut *TX_BUFFER.get();


            // Set up header (all zeros for simple send)
            tx_buffer.header = VirtioNetHeader::default();

            // Copy frame data
            tx_buffer.data[..frame.len()].copy_from_slice(frame);

            // Set up descriptor
            let desc_idx = self.tx_next_desc as usize;
            let buf_addr = tx_buffer as *const _ as u64;
            let total_len = (core::mem::size_of::<VirtioNetHeader>() + frame.len()) as u32;


            tx_queue.desc[desc_idx] = VirtqDesc {
                addr: buf_addr,
                len: total_len,
                flags: 0, // Device reads from this buffer
                next: 0,
            };

            // Add to available ring
            let avail_idx = tx_queue.avail.idx;
            tx_queue.avail.ring[avail_idx as usize % TX_QUEUE_SIZE] = desc_idx as u16;

            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Update available index
            tx_queue.avail.idx = avail_idx.wrapping_add(1);

            // Memory barrier before notify
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Notify device (write queue index to Queue Notify port)
            outw(self.io_base + 16, VIRTIO_NET_QUEUE_TX);

            self.tx_next_desc = (self.tx_next_desc + 1) % TX_QUEUE_SIZE as u16;

            // Wait for completion (simple polling)
            let expected_used = avail_idx.wrapping_add(1);
            for _ in 0..1000000u32 {
                core::hint::spin_loop();
                if core::ptr::read_volatile(&tx_queue.used.idx) == expected_used {
                    return true;
                }
            }
        }

        unsafe {
            let tx_queue = &*TX_QUEUE.get();
            serial::print("TX timeout: avail=");
            serial::print_dec(tx_queue.avail.idx as u32);
            serial::print(" used=");
            serial::print_dec(core::ptr::read_volatile(&tx_queue.used.idx) as u32);
            serial::println("");
        }
        false
    }

    /// Try to receive an Ethernet frame
    /// Returns the number of bytes received, or 0 if no packet available
    pub fn recv(&mut self, buffer: &mut [u8]) -> usize {
        unsafe {
            let rx_queue = &mut *RX_QUEUE.get();
            let rx_buffers = &*RX_BUFFERS.get();

            // Check if there's a new packet
            let used_idx = core::ptr::read_volatile(&rx_queue.used.idx);
            if used_idx == self.rx_last_used {
                return 0; // No new packets
            }


            // Get the used element
            let used_elem = rx_queue.used.ring[self.rx_last_used as usize % RX_QUEUE_SIZE];
            let desc_idx = used_elem.id as usize;
            let total_len = used_elem.len as usize;

            // Skip the virtio header
            let header_size = core::mem::size_of::<VirtioNetHeader>();
            if total_len <= header_size {
                self.rx_last_used = self.rx_last_used.wrapping_add(1);
                return 0;
            }

            let frame_len = total_len - header_size;
            let copy_len = frame_len.min(buffer.len());

            // Copy frame data (skip header)
            buffer[..copy_len].copy_from_slice(&rx_buffers[desc_idx % RX_BUFFER_COUNT].data[..copy_len]);

            // Re-add buffer to available ring
            let avail_idx = rx_queue.avail.idx;
            rx_queue.avail.ring[avail_idx as usize % RX_QUEUE_SIZE] = desc_idx as u16;
            rx_queue.avail.idx = avail_idx.wrapping_add(1);

            // Notify device (write queue index to Queue Notify port)
            outw(self.io_base + 16, VIRTIO_NET_QUEUE_RX);

            self.rx_last_used = self.rx_last_used.wrapping_add(1);

            copy_len
        }
    }
}

// I/O port functions
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    core::arch::asm!(
        "in ax, dx",
        out("ax") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

unsafe fn outw(port: u16, value: u16) {
    core::arch::asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") value,
        options(nomem, nostack, preserves_flags)
    );
}

unsafe fn outl(port: u16, value: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") value,
        options(nomem, nostack, preserves_flags)
    );
}
