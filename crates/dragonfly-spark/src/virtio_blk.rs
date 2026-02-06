//! VirtIO Block driver for disk detection
//!
//! Supports VirtIO Block devices (virtio-blk), the default disk type in many
//! QEMU/Proxmox configurations. Much simpler than VirtIO SCSI - direct sector
//! reads without the SCSI command layer.

use crate::bios::{inb, outb, outw};
use crate::pci::{self, PciDevice};
use crate::serial;
use core::cell::UnsafeCell;

#[inline]
unsafe fn outl(port: u16, value: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
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

/// VirtIO vendor ID
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// VirtIO Block device IDs
const VIRTIO_BLK_DEVICE_LEGACY: u16 = 0x1001;  // Transitional (legacy)
const VIRTIO_BLK_DEVICE_MODERN: u16 = 0x1042;  // Modern (1.0+)

/// VirtIO device status bits
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

/// Legacy VirtIO I/O offsets
const VIRTIO_IO_DEVICE_FEATURES: u16 = 0;
const VIRTIO_IO_DRIVER_FEATURES: u16 = 4;
const VIRTIO_IO_QUEUE_ADDRESS: u16 = 8;
const VIRTIO_IO_QUEUE_SIZE: u16 = 12;
const VIRTIO_IO_QUEUE_SELECT: u16 = 14;
const VIRTIO_IO_QUEUE_NOTIFY: u16 = 16;
const VIRTIO_IO_DEVICE_STATUS: u16 = 18;
const VIRTIO_IO_ISR_STATUS: u16 = 19;
/// Device-specific config starts at offset 20 for legacy (no MSI-X)
const VIRTIO_IO_CONFIG: u16 = 20;

/// VirtIO Block request types
const VIRTIO_BLK_T_IN: u32 = 0;   // Read

/// VirtIO Block status values
const VIRTIO_BLK_S_OK: u8 = 0;

/// Virtqueue size - 128 is typical for virtio-blk
const QUEUE_SIZE: u16 = 128;

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

// Padding for queue alignment (page boundary between avail and used rings)
// For 128 entries: desc=2048, avail=4+256=260, total=2308, pad to 4096
const QUEUE_PADDING: usize = 4096 - (QUEUE_SIZE as usize * 16) - (4 + QUEUE_SIZE as usize * 2);

#[repr(C, align(4096))]
struct VirtioBlkQueue {
    desc: [VirtqDesc; QUEUE_SIZE as usize],
    avail: VirtqAvail,
    _padding: [u8; QUEUE_PADDING],
    used: VirtqUsed,
}

/// VirtIO Block request header
#[repr(C)]
struct VirtioBlkReqHeader {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

/// DMA-aligned buffer for data transfers
#[repr(C, align(4096))]
struct BlkDmaBuffer {
    data: [u8; 512],
    _padding: [u8; 3584],
}

/// Status byte buffer (device-writable, separate for descriptor chain)
#[repr(C, align(64))]
struct BlkStatusBuffer {
    status: u8,
    _padding: [u8; 63],
}

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

// Static allocations for the virtqueue and DMA buffers
static BLK_QUEUE: SyncUnsafeCell<VirtioBlkQueue> = SyncUnsafeCell::new(VirtioBlkQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE as usize],
    avail: VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE as usize] },
    _padding: [0; QUEUE_PADDING],
    used: VirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE as usize] },
});

static BLK_REQ_HEADER: SyncUnsafeCell<VirtioBlkReqHeader> = SyncUnsafeCell::new(VirtioBlkReqHeader {
    req_type: 0,
    reserved: 0,
    sector: 0,
});

static BLK_DMA: SyncUnsafeCell<BlkDmaBuffer> = SyncUnsafeCell::new(BlkDmaBuffer {
    data: [0; 512],
    _padding: [0; 3584],
});

static BLK_STATUS: SyncUnsafeCell<BlkStatusBuffer> = SyncUnsafeCell::new(BlkStatusBuffer {
    status: 0xFF,
    _padding: [0; 63],
});

/// VirtIO Block controller
pub struct VirtioBlk {
    io_base: u16,
    last_used_idx: u16,
    pub capacity_sectors: u64,
}

impl VirtioBlk {
    /// Initialize VirtIO Block from PCI device
    pub fn new(device: &PciDevice) -> Option<Self> {
        pci::enable_bus_master(device);

        let bar0 = pci::pci_read_bar(device, 0);
        if bar0 & 1 == 0 {
            serial::println("VirtIO-blk: BAR0 is not I/O space");
            return None;
        }
        let io_base = (bar0 & 0xFFFC) as u16;

        serial::print("VirtIO-blk: I/O base = 0x");
        serial::print_hex32(io_base as u32);
        serial::println("");

        let mut ctrl = VirtioBlk {
            io_base,
            last_used_idx: 0,
            capacity_sectors: 0,
        };

        // Reset device
        ctrl.write_status(0);
        for _ in 0..10000 { unsafe { core::arch::asm!("nop"); } }

        // Acknowledge + Driver
        ctrl.write_status(VIRTIO_STATUS_ACKNOWLEDGE);
        ctrl.write_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

        // Read features (we don't need any special features for basic reads)
        let features = unsafe { inl(io_base + VIRTIO_IO_DEVICE_FEATURES) };
        serial::print("VirtIO-blk: Features = 0x");
        serial::print_hex32(features);
        serial::println("");

        // Accept no features
        unsafe { outl(io_base + VIRTIO_IO_DRIVER_FEATURES, 0); }

        // Features OK
        ctrl.write_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

        let status = ctrl.read_status();
        if status & VIRTIO_STATUS_FEATURES_OK == 0 {
            serial::println("VirtIO-blk: Device rejected features!");
            return None;
        }

        // Read device config: capacity is at offset 0 in device-specific config (8 bytes)
        unsafe {
            let cap_lo = inl(io_base + VIRTIO_IO_CONFIG) as u64;
            let cap_hi = inl(io_base + VIRTIO_IO_CONFIG + 4) as u64;
            ctrl.capacity_sectors = cap_lo | (cap_hi << 32);
        }
        serial::print("VirtIO-blk: Capacity = ");
        serial::print_dec(ctrl.capacity_sectors as u32);
        serial::println(" sectors");

        // Set up queue 0 (requestq - the only queue for virtio-blk)
        unsafe {
            outw(io_base + VIRTIO_IO_QUEUE_SELECT, 0);
            let queue_size = inl(io_base + VIRTIO_IO_QUEUE_SIZE as u16) as u16;
            serial::print("VirtIO-blk: Queue size = ");
            serial::print_dec(queue_size as u32);
            serial::println("");

            if queue_size == 0 {
                serial::println("VirtIO-blk: Queue size is 0!");
                return None;
            }

            // Set queue address (page frame number)
            let queue_ptr = BLK_QUEUE.get();
            let queue_pfn = (queue_ptr as u32) >> 12;
            outl(io_base + VIRTIO_IO_QUEUE_ADDRESS, queue_pfn);
        }

        // Driver OK
        ctrl.write_status(
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
            VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK
        );

        serial::println("VirtIO-blk: Initialized");
        Some(ctrl)
    }

    fn read_status(&self) -> u8 {
        unsafe { inb(self.io_base + VIRTIO_IO_DEVICE_STATUS) }
    }

    fn write_status(&self, status: u8) {
        unsafe { outb(self.io_base + VIRTIO_IO_DEVICE_STATUS, status); }
    }

    /// Read a 512-byte sector from the block device
    pub fn read_sector(&mut self, lba: u32, buffer: &mut [u8; 512]) -> bool {
        unsafe {
            let queue = &mut *BLK_QUEUE.get();
            let req = &mut *BLK_REQ_HEADER.get();
            let dma = &mut *BLK_DMA.get();
            let status_buf = &mut *BLK_STATUS.get();

            // Set up request header
            core::ptr::write_volatile(&mut req.req_type, VIRTIO_BLK_T_IN);
            core::ptr::write_volatile(&mut req.reserved, 0);
            core::ptr::write_volatile(&mut req.sector, lba as u64);

            // Clear DMA buffer and status
            for i in 0..512 {
                core::ptr::write_volatile(&mut dma.data[i], 0);
            }
            core::ptr::write_volatile(&mut status_buf.status, 0xFF);

            // Descriptor chain: header (out) -> data (in) -> status (in)
            // Desc 0: request header (device reads)
            let desc0 = &mut queue.desc[0] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).addr), req as *const _ as u64);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).len), 16); // sizeof VirtioBlkReqHeader
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).flags), VIRTQ_DESC_F_NEXT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).next), 1);

            // Desc 1: data buffer (device writes)
            let desc1 = &mut queue.desc[1] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).addr), dma.data.as_ptr() as u64);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).len), 512);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).flags), VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).next), 2);

            // Desc 2: status byte (device writes)
            let desc2 = &mut queue.desc[2] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).addr), &status_buf.status as *const _ as u64);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).len), 1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).flags), VIRTQ_DESC_F_WRITE);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).next), 0);

            // Add to available ring
            let avail_idx = core::ptr::read_volatile(&queue.avail.idx);
            let ring_slot = (avail_idx % QUEUE_SIZE) as usize;
            core::ptr::write_volatile(&mut queue.avail.ring[ring_slot], 0); // head descriptor

            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(&mut queue.avail.idx, avail_idx.wrapping_add(1));
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Flush caches before notify
            core::arch::asm!("wbinvd", options(nostack, preserves_flags));

            // Notify device (queue 0)
            outw(self.io_base + VIRTIO_IO_QUEUE_NOTIFY, 0);

            // Wait for completion
            let start_used_idx = self.last_used_idx;
            for _ in 0..1_000_000u32 {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

                let current_used = core::ptr::read_volatile(&queue.used.idx);
                if current_used != start_used_idx {
                    self.last_used_idx = current_used;

                    // Invalidate cache to see device's writes
                    core::arch::asm!("wbinvd", options(nostack, preserves_flags));
                    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

                    // Check status
                    let st = core::ptr::read_volatile(&status_buf.status);
                    if st != VIRTIO_BLK_S_OK {
                        serial::print("VirtIO-blk: Read failed, status=");
                        serial::print_dec(st as u32);
                        serial::println("");
                        return false;
                    }

                    // Copy data out
                    buffer.copy_from_slice(&dma.data);
                    return true;
                }

                core::arch::asm!("pause", options(nostack, preserves_flags));
            }

            serial::println("VirtIO-blk: Read timed out");
            false
        }
    }
}

/// Find a VirtIO Block device on PCI bus
fn find_virtio_blk() -> Option<PciDevice> {
    // Try legacy transitional device first, then modern
    if let Some(dev) = pci::find_device(VIRTIO_VENDOR, VIRTIO_BLK_DEVICE_LEGACY) {
        serial::println("VirtIO-blk: Found legacy device");
        return Some(dev);
    }
    if let Some(dev) = pci::find_device(VIRTIO_VENDOR, VIRTIO_BLK_DEVICE_MODERN) {
        serial::println("VirtIO-blk: Found modern device");
        return Some(dev);
    }
    None
}

/// Initialize VirtIO Block driver. Returns controller if a disk is found.
pub fn init() -> Option<VirtioBlk> {
    serial::println("VirtIO-blk: Scanning for controller...");

    let device = find_virtio_blk()?;
    let ctrl = VirtioBlk::new(&device)?;

    if ctrl.capacity_sectors == 0 {
        serial::println("VirtIO-blk: Disk has 0 capacity");
        return None;
    }

    Some(ctrl)
}
