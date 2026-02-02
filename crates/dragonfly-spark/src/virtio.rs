//! VirtIO SCSI driver for disk detection
//!
//! Supports VirtIO SCSI controllers (common in VMs like Proxmox/QEMU)

use crate::pci::{self, PciDevice};
use crate::serial;
use core::ptr::{read_volatile, write_volatile};

/// VirtIO vendor ID
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// VirtIO SCSI device ID (transitional)
const VIRTIO_SCSI_DEVICE: u16 = 0x1004;

/// VirtIO PCI capability types
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// VirtIO device status bits
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

/// VirtIO SCSI queue indices
const VIRTIO_SCSI_QUEUE_CTRL: u16 = 0;
const VIRTIO_SCSI_QUEUE_EVENT: u16 = 1;
const VIRTIO_SCSI_QUEUE_REQUEST: u16 = 2;

/// Virtqueue size (must match device's queue size - typically 256 for VirtIO SCSI)
const QUEUE_SIZE: u16 = 256;

/// SCSI commands
const SCSI_CMD_TEST_UNIT_READY: u8 = 0x00;
const SCSI_CMD_READ_CAPACITY_10: u8 = 0x25;
const SCSI_CMD_READ_10: u8 = 0x28;

/// VirtIO SCSI request header - must be packed to match device expectation
/// Note: cdb_size from device config is 32 bytes
#[repr(C, packed)]
struct VirtioScsiReqHeader {
    lun: [u8; 8],
    tag: u64,
    task_attr: u8,
    prio: u8,
    crn: u8,
    cdb: [u8; 32], // SCSI CDB - must match device's cdb_size (32 bytes)
}

/// VirtIO SCSI response - must be packed to match device expectation
#[repr(C, packed)]
struct VirtioScsiResp {
    sense_len: u32,
    resid: u32,
    status_qualifier: u16,
    status: u8,
    response: u8,
    sense: [u8; 96],
}

/// Virtqueue descriptor - must be exactly 16 bytes, no padding
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

/// Virtqueue used element - exactly 8 bytes
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

/// Static buffers for virtqueue - MUST be page-aligned for legacy VirtIO!
use core::cell::UnsafeCell;

/// Legacy VirtIO queue layout (must be page-aligned):
/// - Descriptor table: 16 bytes * queue_size (at offset 0)
/// - Available ring: 6 + 2*queue_size bytes (immediately after)
/// - Padding to next page boundary
/// - Used ring: 6 + 8*queue_size bytes (at next page boundary)
///
/// For 256 entries:
/// - Desc: 256 * 16 = 4096 bytes
/// - Avail: 4 + 512 = 516 bytes
/// - Total before padding: 4612, pad to 8192
/// - Used: 4 + 2048 = 2052 bytes
/// Total: ~11KB but must start page-aligned

// Padding size constant for 256-entry queue (8192 - 4096 - 516 = 3580)
const QUEUE_PADDING: usize = 8192 - 4096 - (4 + 256 * 2);

#[repr(C, align(4096))]
struct VirtioQueue {
    // Descriptor table (at offset 0) - 4096 bytes for 256 entries
    desc: [VirtqDesc; QUEUE_SIZE as usize],
    // Available ring (immediately after descriptors) - 518 bytes
    avail: VirtqAvail,
    // Padding to align used ring to next page boundary (8192 from start)
    // desc=4096, avail=516 (4 + 256*2), need padding to reach 8192
    // 8192 - 4096 - 516 = 3580 bytes padding
    _padding: [u8; QUEUE_PADDING],
    // Used ring (at offset 8192 from start)
    used: VirtqUsed,
}

/// Number of queues for VirtIO SCSI
const NUM_QUEUES: usize = 3;

// Extra buffers for request/response (don't need to be in the queue)
// Must use repr(C) to ensure predictable memory layout for DMA
#[repr(C)]
struct VirtioReqBuffers {
    req_header: VirtioScsiReqHeader,
    resp: VirtioScsiResp,
    data_buffer: [u8; 512],
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

// Page-aligned queue structures - one for each VirtIO SCSI queue
static VIRTIO_QUEUE_CTRL: SyncUnsafeCell<VirtioQueue> = SyncUnsafeCell::new(VirtioQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE as usize],
    avail: VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE as usize] },
    _padding: [0; QUEUE_PADDING],
    used: VirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE as usize] },
});

static VIRTIO_QUEUE_EVENT: SyncUnsafeCell<VirtioQueue> = SyncUnsafeCell::new(VirtioQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE as usize],
    avail: VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE as usize] },
    _padding: [0; QUEUE_PADDING],
    used: VirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE as usize] },
});

static VIRTIO_QUEUE_REQ: SyncUnsafeCell<VirtioQueue> = SyncUnsafeCell::new(VirtioQueue {
    desc: [VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 }; QUEUE_SIZE as usize],
    avail: VirtqAvail { flags: 0, idx: 0, ring: [0; QUEUE_SIZE as usize] },
    _padding: [0; QUEUE_PADDING],
    used: VirtqUsed { flags: 0, idx: 0, ring: [VirtqUsedElem { id: 0, len: 0 }; QUEUE_SIZE as usize] },
});

// Request/response buffers (separate, don't need alignment)
static VIRTIO_REQ: SyncUnsafeCell<VirtioReqBuffers> = SyncUnsafeCell::new(VirtioReqBuffers {
    req_header: VirtioScsiReqHeader {
        lun: [0; 8],
        tag: 0,
        task_attr: 0,
        prio: 0,
        crn: 0,
        cdb: [0; 32],
    },
    resp: VirtioScsiResp {
        sense_len: 0,
        resid: 0,
        status_qualifier: 0,
        status: 0,
        response: 0,
        sense: [0; 96],
    },
    data_buffer: [0; 512],
});

/// VirtIO SCSI device configuration (from device config space)
#[repr(C, packed)]
struct VirtioScsiConfig {
    num_queues: u32,
    seg_max: u32,
    max_sectors: u32,
    cmd_per_lun: u32,
    event_info_size: u32,
    sense_size: u32,
    cdb_size: u32,
    max_channel: u16,
    max_target: u16,
    max_lun: u32,
}

/// VirtIO SCSI controller
pub struct VirtioScsi {
    /// Base address for legacy I/O (BAR0)
    io_base: u16,
    /// Last seen used index
    last_used_idx: u16,
    /// Device configuration
    max_target: u16,
    sense_size: u32,
    cdb_size: u32,
}

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

/// Saved BIOS queue addresses (PFNs) - restore these before chainloading
static mut BIOS_QUEUE_PFNS: [u32; 3] = [0; 3];
static mut BIOS_IO_BASE: u16 = 0;

impl VirtioScsi {
    /// Initialize VirtIO SCSI from PCI device
    pub fn new(device: &PciDevice) -> Option<Self> {
        // Enable bus mastering for DMA
        pci::enable_bus_master(device);

        // Get BAR0 (I/O port base for legacy VirtIO)
        let bar0 = pci::pci_read_bar(device, 0);
        if bar0 & 1 == 0 {
            serial::println("VirtIO: BAR0 is not I/O space");
            return None;
        }
        let io_base = (bar0 & 0xFFFC) as u16;

        serial::print("VirtIO SCSI: I/O base = 0x");
        serial::print_hex32(io_base as u32);
        serial::println("");

        // SAVE BIOS's queue addresses BEFORE we reset the device!
        unsafe {
            BIOS_IO_BASE = io_base;
            serial::println("VirtIO: Saving BIOS queue addresses...");
            for q in 0..3u16 {
                outw(io_base + VIRTIO_IO_QUEUE_SELECT, q);
                let pfn = inl(io_base + VIRTIO_IO_QUEUE_ADDRESS);
                BIOS_QUEUE_PFNS[q as usize] = pfn;
                serial::print("  BIOS Queue ");
                serial::print_dec(q as u32);
                serial::print(" PFN = 0x");
                serial::print_hex32(pfn);
                serial::println("");
            }
        }

        let mut ctrl = VirtioScsi {
            io_base,
            last_used_idx: 0,
            max_target: 0,
            sense_size: 0,
            cdb_size: 0,
        };

        // Reset device
        serial::println("VirtIO: Resetting device...");
        ctrl.write_status(0);

        // Small delay after reset
        for _ in 0..10000 { unsafe { core::arch::asm!("nop"); } }

        // Acknowledge device
        ctrl.write_status(VIRTIO_STATUS_ACKNOWLEDGE);
        serial::print("VirtIO: Status after ACK = 0x");
        serial::print_hex32(ctrl.read_status() as u32);
        serial::println("");

        // We're a driver
        ctrl.write_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        serial::print("VirtIO: Status after DRIVER = 0x");
        serial::print_hex32(ctrl.read_status() as u32);
        serial::println("");

        // Read features
        let features = ctrl.read_features();
        serial::print("VirtIO SCSI: Features = 0x");
        serial::print_hex32(features);
        serial::println("");

        // Accept no features (basic operation)
        ctrl.write_features(0);

        // Features OK
        ctrl.write_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

        // Verify FEATURES_OK stuck
        let status = ctrl.read_status();
        serial::print("VirtIO: Status after FEATURES_OK = 0x");
        serial::print_hex32(status as u32);
        serial::println("");

        if status & VIRTIO_STATUS_FEATURES_OK == 0 {
            serial::println("VirtIO: Device rejected features!");
            return None;
        }

        // Read device-specific configuration
        unsafe {
            let num_queues = inl(ctrl.io_base + VIRTIO_IO_CONFIG);
            let seg_max = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 4);
            let max_sectors = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 8);
            let cmd_per_lun = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 12);
            let event_info_size = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 16);
            let sense_size = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 20);
            let cdb_size = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 24);
            let max_channel_target = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 28);
            let max_lun = inl(ctrl.io_base + VIRTIO_IO_CONFIG + 32);

            let max_channel = (max_channel_target & 0xFFFF) as u16;
            let max_target = ((max_channel_target >> 16) & 0xFFFF) as u16;

            serial::println("VirtIO SCSI Config:");
            serial::print("  num_queues=");
            serial::print_dec(num_queues);
            serial::print(" seg_max=");
            serial::print_dec(seg_max);
            serial::print(" max_sectors=");
            serial::print_dec(max_sectors);
            serial::println("");
            serial::print("  sense_size=");
            serial::print_dec(sense_size);
            serial::print(" cdb_size=");
            serial::print_dec(cdb_size);
            serial::println("");
            serial::print("  max_channel=");
            serial::print_dec(max_channel as u32);
            serial::print(" max_target=");
            serial::print_dec(max_target as u32);
            serial::print(" max_lun=");
            serial::print_dec(max_lun);
            serial::println("");

            ctrl.max_target = max_target;
            ctrl.sense_size = sense_size;
            ctrl.cdb_size = cdb_size;
        }

        // Initialize ALL queues - control, event, and request
        // VirtIO SCSI requires all queues to be set up before DRIVER_OK
        serial::println("VirtIO: Initializing all queues...");

        if !ctrl.init_queue(VIRTIO_SCSI_QUEUE_CTRL) {
            serial::println("VirtIO SCSI: Failed to init control queue");
            return None;
        }

        if !ctrl.init_queue(VIRTIO_SCSI_QUEUE_EVENT) {
            serial::println("VirtIO SCSI: Failed to init event queue");
            return None;
        }

        if !ctrl.init_queue(VIRTIO_SCSI_QUEUE_REQUEST) {
            serial::println("VirtIO SCSI: Failed to init request queue");
            return None;
        }

        // Driver OK - device is live after this
        ctrl.write_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

        let final_status = ctrl.read_status();
        serial::print("VirtIO: Final status = 0x");
        serial::print_hex32(final_status as u32);
        serial::println("");

        // Small delay to let device fully initialize after DRIVER_OK
        for _ in 0..100000 { unsafe { core::arch::asm!("nop"); } }

        // Read back queue address to verify it was set
        unsafe {
            outw(ctrl.io_base + VIRTIO_IO_QUEUE_SELECT, VIRTIO_SCSI_QUEUE_REQUEST);
            let queue_addr_readback = inl(ctrl.io_base + VIRTIO_IO_QUEUE_ADDRESS);
            serial::print("VirtIO: Queue 2 PFN readback = 0x");
            serial::print_hex32(queue_addr_readback);
            serial::println("");
        }

        serial::println("VirtIO SCSI: Initialized");
        Some(ctrl)
    }

    fn read_features(&self) -> u32 {
        unsafe { inl(self.io_base + VIRTIO_IO_DEVICE_FEATURES) }
    }

    fn write_features(&self, features: u32) {
        unsafe { outl(self.io_base + VIRTIO_IO_DRIVER_FEATURES, features) }
    }

    fn read_status(&self) -> u8 {
        unsafe { inb(self.io_base + VIRTIO_IO_DEVICE_STATUS) }
    }

    fn write_status(&self, status: u8) {
        unsafe { outb(self.io_base + VIRTIO_IO_DEVICE_STATUS, status) }
    }

    fn init_queue(&mut self, queue_idx: u16) -> bool {
        unsafe {
            // Select queue
            outw(self.io_base + VIRTIO_IO_QUEUE_SELECT, queue_idx);

            // Read queue size
            let queue_size = inw(self.io_base + VIRTIO_IO_QUEUE_SIZE);
            serial::print("VirtIO: Queue ");
            serial::print_dec(queue_idx as u32);
            serial::print(" size = ");
            serial::print_dec(queue_size as u32);
            serial::println("");

            if queue_size == 0 {
                serial::println("VirtIO: Queue size 0, skipping");
                return true; // Queue doesn't exist, that's OK
            }

            // Get the appropriate queue structure for this queue index
            let queue = match queue_idx {
                VIRTIO_SCSI_QUEUE_CTRL => &mut *VIRTIO_QUEUE_CTRL.get(),
                VIRTIO_SCSI_QUEUE_EVENT => &mut *VIRTIO_QUEUE_EVENT.get(),
                VIRTIO_SCSI_QUEUE_REQUEST => &mut *VIRTIO_QUEUE_REQ.get(),
                _ => return false,
            };

            let queue_addr = queue.desc.as_ptr() as u32;

            serial::print("VirtIO: Queue ");
            serial::print_dec(queue_idx as u32);
            serial::print(" desc addr = 0x");
            serial::print_hex32(queue_addr);
            serial::println("");

            // Queue address is in 4096-byte pages
            let queue_pfn = queue_addr / 4096;
            serial::print("VirtIO: Queue ");
            serial::print_dec(queue_idx as u32);
            serial::print(" PFN = 0x");
            serial::print_hex32(queue_pfn);
            serial::println("");

            // Initialize the available ring
            queue.avail.flags = 0;
            queue.avail.idx = 0;

            // Initialize the used ring
            queue.used.flags = 0;
            queue.used.idx = 0;

            outl(self.io_base + VIRTIO_IO_QUEUE_ADDRESS, queue_pfn);

            true
        }
    }

    /// Test if a SCSI target exists
    pub fn test_unit_ready(&mut self, target: u8, lun: u8) -> bool {
        unsafe {
            let queue = &mut *VIRTIO_QUEUE_REQ.get();
            let req = &mut *VIRTIO_REQ.get();

            // Set up request header - simple single-level LUN addressing
            req.req_header.lun[0] = 1; // Single level LUN
            req.req_header.lun[1] = target;
            req.req_header.lun[2] = 0x40 | ((lun as u16 >> 8) as u8);
            req.req_header.lun[3] = lun;
            req.req_header.tag = 1;
            req.req_header.task_attr = 0;
            req.req_header.prio = 0;
            req.req_header.crn = 0;

            // SCSI TEST UNIT READY command
            req.req_header.cdb = [0; 32];
            req.req_header.cdb[0] = SCSI_CMD_TEST_UNIT_READY;

            // Clear response
            req.resp = core::mem::zeroed();

            // Set up descriptor chain using volatile writes to packed struct
            // Desc 0: request header (device reads)
            let req_addr = &req.req_header as *const _ as u64;
            let desc0 = &mut queue.desc[0] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).addr), req_addr);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).len), core::mem::size_of::<VirtioScsiReqHeader>() as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).flags), VIRTQ_DESC_F_NEXT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).next), 1);

            // Desc 1: response (device writes)
            let resp_addr = &req.resp as *const _ as u64;
            let desc1 = &mut queue.desc[1] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).addr), resp_addr);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).len), core::mem::size_of::<VirtioScsiResp>() as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).flags), VIRTQ_DESC_F_WRITE);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).next), 0);

            serial::print("VirtIO: desc[0] addr=0x");
            serial::print_hex32(req_addr as u32);
            serial::print(" len=");
            serial::print_dec(core::mem::size_of::<VirtioScsiReqHeader>() as u32);
            serial::print(" flags=0x");
            serial::print_hex32(VIRTQ_DESC_F_NEXT as u32);
            serial::println("");
            serial::print("VirtIO: desc[1] addr=0x");
            serial::print_hex32(resp_addr as u32);
            serial::print(" len=");
            serial::print_dec(core::mem::size_of::<VirtioScsiResp>() as u32);
            serial::print(" flags=0x");
            serial::print_hex32(VIRTQ_DESC_F_WRITE as u32);
            serial::println("");

            // Dump request header bytes
            let hdr_bytes = &req.req_header as *const _ as *const u8;
            serial::print("VirtIO: req_hdr bytes: ");
            for i in 0..16 {
                serial::print_hex32(core::ptr::read_volatile(hdr_bytes.add(i)) as u32);
                serial::print(" ");
            }
            serial::println("");

            // Add to available ring using volatile writes
            let avail_idx = core::ptr::read_volatile(&queue.avail.idx);
            let ring_slot = (avail_idx % QUEUE_SIZE) as usize;
            core::ptr::write_volatile(&mut queue.avail.ring[ring_slot], 0);

            serial::print("VirtIO: avail.idx before = ");
            serial::print_dec(avail_idx as u32);
            serial::print(", used.idx = ");
            serial::print_dec(core::ptr::read_volatile(&queue.used.idx) as u32);
            serial::println("");

            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            core::ptr::write_volatile(&mut queue.avail.idx, avail_idx.wrapping_add(1));

            // Memory barrier before notify
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Flush CPU caches to ensure device sees our writes
            core::arch::asm!("wbinvd", options(nostack, preserves_flags));

            // Notify device
            serial::println("VirtIO: Notifying device...");
            outw(self.io_base + VIRTIO_IO_QUEUE_NOTIFY, VIRTIO_SCSI_QUEUE_REQUEST);

            // Read ISR to check if device responded
            let isr = inb(self.io_base + VIRTIO_IO_ISR_STATUS);
            serial::print("VirtIO: ISR after notify = 0x");
            serial::print_hex32(isr as u32);
            serial::println("");

            // Wait for completion
            let start_used_idx = self.last_used_idx;
            for i in 0..1000000u32 {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

                let current_used = core::ptr::read_volatile(&queue.used.idx);
                if current_used != start_used_idx {
                    self.last_used_idx = current_used;
                    let status = req.resp.status;
                    let response = req.resp.response;
                    serial::print("VirtIO SCSI: TUR response=");
                    serial::print_dec(response as u32);
                    serial::print(" status=");
                    serial::print_dec(status as u32);
                    serial::println("");
                    // response=0 means device exists (status=2 CHECK CONDITION is OK, just means sense data available)
                    // response=3 means TARGET_FAILURE (no device)
                    return response == 0;
                }

                // Check ISR periodically
                if i == 100000 || i == 500000 {
                    let isr = inb(self.io_base + VIRTIO_IO_ISR_STATUS);
                    let used = core::ptr::read_volatile(&queue.used.idx);
                    serial::print("VirtIO: Wait check - ISR=0x");
                    serial::print_hex32(isr as u32);
                    serial::print(" used.idx=");
                    serial::print_dec(used as u32);
                    serial::println("");
                }
            }

            serial::println("VirtIO SCSI: TUR timeout");
            false
        }
    }

    /// Read a sector from disk
    pub fn read_sector(&mut self, target: u8, lun: u8, lba: u32, buffer: &mut [u8; 512]) -> bool {
        unsafe {
            let queue = &mut *VIRTIO_QUEUE_REQ.get();
            let req = &mut *VIRTIO_REQ.get();

            // Set up request header - simple single-level LUN addressing
            req.req_header.lun[0] = 1;
            req.req_header.lun[1] = target;
            req.req_header.lun[2] = 0x40 | ((lun as u16 >> 8) as u8);
            req.req_header.lun[3] = lun;
            req.req_header.tag = 2;
            req.req_header.task_attr = 0;
            req.req_header.prio = 0;
            req.req_header.crn = 0;

            // SCSI READ(10) command
            req.req_header.cdb = [0; 32];
            req.req_header.cdb[0] = SCSI_CMD_READ_10;
            req.req_header.cdb[2] = (lba >> 24) as u8;
            req.req_header.cdb[3] = (lba >> 16) as u8;
            req.req_header.cdb[4] = (lba >> 8) as u8;
            req.req_header.cdb[5] = lba as u8;
            req.req_header.cdb[7] = 0; // Transfer length (MSB)
            req.req_header.cdb[8] = 1; // Transfer length = 1 sector

            // Clear response and data buffer using volatile writes
            core::ptr::write_volatile(&mut req.resp, core::mem::zeroed());
            for i in 0..512 {
                core::ptr::write_volatile(&mut req.data_buffer[i], 0);
            }

            // Debug: verify buffer is cleared
            serial::print("After clear, bytes 10-12: ");
            serial::print_hex32(core::ptr::read_volatile(&req.data_buffer[10]) as u32);
            serial::print(" ");
            serial::print_hex32(core::ptr::read_volatile(&req.data_buffer[11]) as u32);
            serial::print(" ");
            serial::print_hex32(core::ptr::read_volatile(&req.data_buffer[12]) as u32);
            serial::println("");

            // Set up descriptor chain (3 descriptors for read) using volatile writes
            // Desc 0: request header (device reads - OUT)
            let req_addr = &req.req_header as *const _ as u64;
            let desc0 = &mut queue.desc[0] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).addr), req_addr);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).len), core::mem::size_of::<VirtioScsiReqHeader>() as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).flags), VIRTQ_DESC_F_NEXT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc0).next), 1);

            // Desc 1: response (device writes - IN)
            let resp_addr = &req.resp as *const _ as u64;
            let desc1 = &mut queue.desc[1] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).addr), resp_addr);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).len), core::mem::size_of::<VirtioScsiResp>() as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).flags), VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc1).next), 2);

            // Desc 2: data buffer (device writes - IN)
            let data_addr = req.data_buffer.as_ptr() as u64;
            let desc2 = &mut queue.desc[2] as *mut VirtqDesc;
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).addr), data_addr);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).len), 512);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).flags), VIRTQ_DESC_F_WRITE);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc2).next), 0);

            // Debug: print data buffer address
            serial::print("VirtIO: data_buffer addr=0x");
            serial::print_hex32(data_addr as u32);
            serial::println("");

            // Add to available ring using volatile writes
            let avail_idx = core::ptr::read_volatile(&queue.avail.idx);
            let ring_slot = (avail_idx % QUEUE_SIZE) as usize;
            core::ptr::write_volatile(&mut queue.avail.ring[ring_slot], 0);

            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            core::ptr::write_volatile(&mut queue.avail.idx, avail_idx.wrapping_add(1));

            // Flush caches before notify
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::arch::asm!("wbinvd", options(nostack, preserves_flags));

            // Notify device
            outw(self.io_base + VIRTIO_IO_QUEUE_NOTIFY, VIRTIO_SCSI_QUEUE_REQUEST);

            // Wait for completion
            let start_used_idx = self.last_used_idx;
            for _ in 0..1000000 {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

                let current_used = core::ptr::read_volatile(&queue.used.idx);
                if current_used != start_used_idx {
                    self.last_used_idx = current_used;

                    // Invalidate cache to see device's writes
                    core::arch::asm!("wbinvd", options(nostack, preserves_flags));
                    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

                    let status = core::ptr::read_volatile(core::ptr::addr_of!(req.resp.status));
                    let response = core::ptr::read_volatile(core::ptr::addr_of!(req.resp.response));
                    let resid = core::ptr::read_volatile(core::ptr::addr_of!(req.resp.resid));

                    serial::print("VirtIO SCSI: READ response=");
                    serial::print_dec(response as u32);
                    serial::print(" status=");
                    serial::print_dec(status as u32);
                    serial::print(" resid=");
                    serial::print_dec(resid);
                    serial::println("");

                    // Debug: print first 16 bytes directly from data_buffer
                    serial::print("data_buffer raw: ");
                    for i in 0..16 {
                        serial::print_hex32(core::ptr::read_volatile(&req.data_buffer[i]) as u32);
                        serial::print(" ");
                    }
                    serial::println("");

                    if response == 0 && status == 0 {
                        // Copy data using volatile reads
                        for i in 0..512 {
                            buffer[i] = core::ptr::read_volatile(&req.data_buffer[i]);
                        }
                        return true;
                    }

                    return false;
                }
            }

            serial::println("VirtIO SCSI: READ timeout");
            false
        }
    }
}

// I/O port operations
#[inline]
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

#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
unsafe fn outw(port: u16, value: u16) {
    core::arch::asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") value,
        options(nomem, nostack, preserves_flags)
    );
}

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

/// Find VirtIO SCSI controller
pub fn find_virtio_scsi() -> Option<PciDevice> {
    pci::find_device(VIRTIO_VENDOR, VIRTIO_SCSI_DEVICE)
}

/// Initialize and scan VirtIO SCSI
pub fn init() -> Option<(VirtioScsi, u8, u8)> {
    serial::println("VirtIO SCSI: Scanning for controller...");

    let device = find_virtio_scsi()?;
    serial::print("VirtIO SCSI: Found at ");
    serial::print_dec(device.bus as u32);
    serial::print(":");
    serial::print_dec(device.slot as u32);
    serial::print(".");
    serial::print_dec(device.func as u32);
    serial::println("");

    let mut ctrl = VirtioScsi::new(&device)?;

    // Scan for SCSI targets (typically target 0, lun 0)
    for target in 0..8u8 {
        serial::print("VirtIO SCSI: Probing target ");
        serial::print_dec(target as u32);
        serial::println("");

        if ctrl.test_unit_ready(target, 0) {
            serial::print("VirtIO SCSI: Found disk at target ");
            serial::print_dec(target as u32);
            serial::println("");
            return Some((ctrl, target, 0));
        }
    }

    serial::println("VirtIO SCSI: No disks found");
    None
}

/// Restore BIOS VirtIO state for INT 13h compatibility
/// This restores the queue addresses that BIOS set up originally
pub fn reset_all() {
    serial::println("VirtIO: Restoring BIOS state...");

    unsafe {
        if BIOS_IO_BASE == 0 {
            serial::println("VirtIO: No saved BIOS state");
            return;
        }

        let io_base = BIOS_IO_BASE;

        // Reset device first
        outb(io_base + VIRTIO_IO_DEVICE_STATUS, 0);
        for _ in 0..10000 { core::arch::asm!("nop"); }

        // Re-init device the way BIOS expects
        outb(io_base + VIRTIO_IO_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        outb(io_base + VIRTIO_IO_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

        // Accept same features BIOS would (none for basic)
        outl(io_base + VIRTIO_IO_DRIVER_FEATURES, 0);
        outb(io_base + VIRTIO_IO_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

        // Restore BIOS queue addresses
        serial::println("VirtIO: Restoring BIOS queue PFNs...");
        for q in 0..3u16 {
            outw(io_base + VIRTIO_IO_QUEUE_SELECT, q);
            outl(io_base + VIRTIO_IO_QUEUE_ADDRESS, BIOS_QUEUE_PFNS[q as usize]);
            serial::print("  Queue ");
            serial::print_dec(q as u32);
            serial::print(" PFN = 0x");
            serial::print_hex32(BIOS_QUEUE_PFNS[q as usize]);
            serial::println("");
        }

        // Set DRIVER_OK
        outb(io_base + VIRTIO_IO_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

        serial::println("VirtIO: BIOS state restored");
    }
}
