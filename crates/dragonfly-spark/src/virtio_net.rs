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
const VIRTIO_NET_DEVICE: u16 = 0x1000;

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

/// Virtqueue size
const QUEUE_SIZE: u16 = 256;

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

/// Virtqueue available ring
#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
}

/// Virtqueue used element
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// Virtqueue used ring
#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE as usize],
}

// Padding for queue alignment
const QUEUE_PADDING: usize = 8192 - 4096 - (4 + 256 * 2);

/// Page-aligned virtqueue
#[repr(C, align(4096))]
struct VirtioQueue {
    desc: [VirtqDesc; QUEUE_SIZE as usize],
    avail: VirtqAvail,
    _padding: [u8; QUEUE_PADDING],
    used: VirtqUsed,
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
static RX_QUEUE: SyncUnsafeCell<VirtioQueue> = SyncUnsafeCell::new(VirtioQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE as usize],
    avail: VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE as usize] },
    _padding: [0; QUEUE_PADDING],
    used: VirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE as usize] },
});

static TX_QUEUE: SyncUnsafeCell<VirtioQueue> = SyncUnsafeCell::new(VirtioQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE as usize],
    avail: VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE as usize] },
    _padding: [0; QUEUE_PADDING],
    used: VirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE as usize] },
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

        // Find VirtIO-net device on PCI bus
        let device = pci::find_device(VIRTIO_VENDOR, VIRTIO_NET_DEVICE)?;

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

        // Reset device
        unsafe {
            outb(io_base + 18, 0); // Status = 0 (reset)
        }

        // Set ACKNOWLEDGE status
        unsafe {
            outb(io_base + 18, VIRTIO_STATUS_ACKNOWLEDGE);
        }

        // Set DRIVER status
        unsafe {
            outb(io_base + 18, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        }

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

        // Initialize RX queue
        unsafe {
            outw(io_base + 14, VIRTIO_NET_QUEUE_RX);
            let queue_size = inw(io_base + 12);
            serial::print("VirtIO-net: RX queue size = ");
            serial::print_dec(queue_size as u32);
            serial::println("");

            let rx_queue = RX_QUEUE.get();
            let rx_pfn = (rx_queue as u32) >> 12;
            outl(io_base + 8, rx_pfn);
        }

        // Initialize TX queue
        unsafe {
            outw(io_base + 14, VIRTIO_NET_QUEUE_TX);
            let queue_size = inw(io_base + 12);
            serial::print("VirtIO-net: TX queue size = ");
            serial::print_dec(queue_size as u32);
            serial::println("");

            let tx_queue = TX_QUEUE.get();
            let tx_pfn = (tx_queue as u32) >> 12;
            outl(io_base + 8, tx_pfn);
        }

        // Populate RX queue with buffers
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

            // Notify device about RX buffers
            outw(io_base + 14, VIRTIO_NET_QUEUE_RX);
            outw(io_base + 16, 0);
        }

        // Set DRIVER_OK to finish initialization
        unsafe {
            let status = inb(io_base + 18);
            outb(io_base + 18, status | VIRTIO_STATUS_DRIVER_OK);
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
            tx_queue.desc[desc_idx] = VirtqDesc {
                addr: tx_buffer as *const _ as u64,
                len: (core::mem::size_of::<VirtioNetHeader>() + frame.len()) as u32,
                flags: 0, // Device reads from this buffer
                next: 0,
            };

            // Add to available ring
            let avail_idx = tx_queue.avail.idx;
            tx_queue.avail.ring[avail_idx as usize % QUEUE_SIZE as usize] = desc_idx as u16;

            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Update available index
            tx_queue.avail.idx = avail_idx.wrapping_add(1);

            // Notify device
            outw(self.io_base + 14, VIRTIO_NET_QUEUE_TX);
            outw(self.io_base + 16, 0);

            self.tx_next_desc = (self.tx_next_desc + 1) % QUEUE_SIZE;
        }

        // Wait for completion (simple polling)
        for _ in 0..100000 {
            unsafe {
                let tx_queue = &*TX_QUEUE.get();
                if tx_queue.used.idx != tx_queue.avail.idx.wrapping_sub(1) {
                    return true;
                }
            }
        }

        serial::println("VirtIO-net: TX timeout");
        false
    }

    /// Try to receive an Ethernet frame
    /// Returns the number of bytes received, or 0 if no packet available
    pub fn recv(&mut self, buffer: &mut [u8]) -> usize {
        unsafe {
            let rx_queue = &mut *RX_QUEUE.get();
            let rx_buffers = &*RX_BUFFERS.get();

            // Check if there's a new packet
            if rx_queue.used.idx == self.rx_last_used {
                return 0; // No new packets
            }

            // Get the used element
            let used_elem = rx_queue.used.ring[self.rx_last_used as usize % QUEUE_SIZE as usize];
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
            rx_queue.avail.ring[avail_idx as usize % QUEUE_SIZE as usize] = desc_idx as u16;
            rx_queue.avail.idx = avail_idx.wrapping_add(1);

            // Notify device
            outw(self.io_base + 14, VIRTIO_NET_QUEUE_RX);
            outw(self.io_base + 16, 0);

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
