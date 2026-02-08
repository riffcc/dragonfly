//! VMware PVSCSI (Paravirtual SCSI) driver
//!
//! Implements the PVSCSI ring-buffer protocol for disk access on VMware VMs.
//! Reference: Linux kernel drivers/scsi/vmw_pvscsi.{c,h}

use crate::pci;
use crate::serial;
use core::ptr::{self, addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

// --- PCI identification ---
const PVSCSI_VENDOR_ID: u16 = 0x15AD; // VMware
const PVSCSI_DEVICE_ID: u16 = 0x07C0; // PVSCSI

// --- MMIO register offsets ---
const PVSCSI_REG_COMMAND: usize = 0x0000;
const PVSCSI_REG_COMMAND_DATA: usize = 0x0004;
const PVSCSI_REG_COMMAND_STATUS: usize = 0x0008;
const PVSCSI_REG_INTR_STATUS: usize = 0x100C;
const PVSCSI_REG_INTR_MASK: usize = 0x2010;
const PVSCSI_REG_KICK_NON_RW_IO: usize = 0x3014;
const PVSCSI_REG_KICK_RW_IO: usize = 0x4018;

// --- Commands ---
const PVSCSI_CMD_ADAPTER_RESET: u32 = 1;
const PVSCSI_CMD_SETUP_RINGS: u32 = 3;

// --- Request flags ---
const PVSCSI_FLAG_CMD_DIR_NONE: u32 = 1 << 2;
const PVSCSI_FLAG_CMD_DIR_TOHOST: u32 = 1 << 3;

// --- SCSI opcodes ---
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;

// --- Ring entry sizes ---
const REQ_DESC_SIZE: usize = 128;
const CMP_DESC_SIZE: usize = 32;
const REQS_PER_PAGE: usize = 4096 / REQ_DESC_SIZE; // 32
const CMPS_PER_PAGE: usize = 4096 / CMP_DESC_SIZE; // 128

// --- Static ring buffers (page-aligned) ---
// We use 1 page each: 32 request slots, 128 completion slots.
#[repr(C, align(4096))]
struct Page([u8; 4096]);

static mut RINGS_STATE: Page = Page([0u8; 4096]);
static mut REQ_RING: Page = Page([0u8; 4096]);
static mut CMP_RING: Page = Page([0u8; 4096]);
static mut SENSE_BUF: [u8; 256] = [0u8; 256];
static mut DATA_BUF: Page = Page([0u8; 4096]);

/// RingsState layout (subset — we only need the indices)
/// Offset 0x00: reqProdIdx  (u32)
/// Offset 0x04: reqConsIdx  (u32)
/// Offset 0x08: reqNumEntriesLog2 (u32)
/// Offset 0x0C: cmpProdIdx  (u32)
/// Offset 0x10: cmpConsIdx  (u32)
/// Offset 0x14: cmpNumEntriesLog2 (u32)

/// PVSCSI controller state
pub struct PvScsi {
    mmio_base: usize,
    req_prod_idx: u32,
    cmp_cons_idx: u32,
    context_counter: u64,
}

impl PvScsi {
    /// Read a sector (512 bytes) from the given target/lun at the given LBA.
    pub fn read_sector(&mut self, target: u8, lun: u8, lba: u32, buffer: &mut [u8; 512]) -> bool {
        // Issue SCSI READ(10) for 1 sector
        let cdb = [
            SCSI_READ_10,
            0x00,
            (lba >> 24) as u8,
            (lba >> 16) as u8,
            (lba >> 8) as u8,
            lba as u8,
            0x00,
            0x00, // count MSB
            0x01, // count LSB = 1 sector
            0x00,
            0, 0, 0, 0, 0, 0,
        ];

        let ok = self.submit_scsi_cmd(target, lun, &cdb, 10, PVSCSI_FLAG_CMD_DIR_TOHOST, 512);
        if ok {
            unsafe {
                let src = addr_of!(DATA_BUF) as *const u8;
                ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), 512);
            }
        }
        ok
    }

    /// Send SCSI INQUIRY to check if a target exists and is a disk.
    /// Returns true if target is a direct-access block device (type 0x00).
    fn inquiry(&mut self, target: u8, lun: u8) -> bool {
        let cdb = [
            SCSI_INQUIRY,
            0x00, 0x00, 0x00,
            0x24, // allocation length = 36
            0x00,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        if !self.submit_scsi_cmd(target, lun, &cdb, 6, PVSCSI_FLAG_CMD_DIR_TOHOST, 36) {
            return false;
        }

        // Byte 0, bits 4:0 = peripheral device type. 0x00 = direct access (disk).
        let device_type = unsafe { read_volatile(addr_of!(DATA_BUF) as *const u8) & 0x1F };
        device_type == 0x00
    }

    /// Send SCSI TEST UNIT READY.
    fn test_unit_ready(&mut self, target: u8, lun: u8) -> bool {
        let cdb = [
            SCSI_TEST_UNIT_READY,
            0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        self.submit_scsi_cmd(target, lun, &cdb, 6, PVSCSI_FLAG_CMD_DIR_NONE, 0)
    }

    /// Get disk capacity in sectors via READ CAPACITY (10).
    /// Returns (total_sectors, block_size) or None.
    fn read_capacity(&mut self, target: u8, lun: u8) -> Option<(u64, u32)> {
        let cdb = [
            SCSI_READ_CAPACITY_10,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        if !self.submit_scsi_cmd(target, lun, &cdb, 10, PVSCSI_FLAG_CMD_DIR_TOHOST, 8) {
            return None;
        }

        let mut data = [0u8; 8];
        unsafe {
            let src = addr_of!(DATA_BUF) as *const u8;
            ptr::copy_nonoverlapping(src, data.as_mut_ptr(), 8);
        }
        let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if block_size == 0 {
            return None;
        }

        Some(((last_lba as u64) + 1, block_size))
    }

    /// Submit a SCSI command and poll for completion.
    fn submit_scsi_cmd(
        &mut self,
        target: u8,
        lun: u8,
        cdb: &[u8; 16],
        cdb_len: u8,
        flags: u32,
        data_len: u64,
    ) -> bool {
        let req_num_entries_log2 = unsafe {
            let p = (addr_of!(RINGS_STATE) as *const u8).add(0x08) as *const u32;
            read_volatile(p)
        };
        let req_mask = (1u32 << req_num_entries_log2) - 1;
        let slot = self.req_prod_idx & req_mask;

        // Zero the request descriptor
        let req_base = unsafe { (addr_of_mut!(REQ_RING) as *mut u8).add(slot as usize * REQ_DESC_SIZE) };
        unsafe {
            ptr::write_bytes(req_base, 0, REQ_DESC_SIZE);
        }

        // Fill request descriptor
        self.context_counter += 1;
        let ctx = self.context_counter;

        unsafe {
            let p = req_base;
            // context (u64 @ offset 0)
            write_volatile(p.add(0) as *mut u64, ctx);
            // dataAddr (u64 @ offset 8)
            let data_phys = addr_of!(DATA_BUF) as u64;
            write_volatile(p.add(8) as *mut u64, data_phys);
            // dataLen (u64 @ offset 16)
            write_volatile(p.add(16) as *mut u64, data_len);
            // senseAddr (u64 @ offset 24)
            let sense_phys = addr_of!(SENSE_BUF) as u64;
            write_volatile(p.add(24) as *mut u64, sense_phys);
            // senseLen (u32 @ offset 32)
            write_volatile(p.add(32) as *mut u32, 256);
            // flags (u32 @ offset 36)
            write_volatile(p.add(36) as *mut u32, flags);
            // cdb (16 bytes @ offset 40)
            for i in 0..16 {
                write_volatile(p.add(40 + i), cdb[i]);
            }
            // cdbLen (u8 @ offset 56)
            write_volatile(p.add(56), cdb_len);
            // lun[0..8] @ offset 57: SAM-2 format
            write_volatile(p.add(57), 0u8); // address method
            write_volatile(p.add(58), lun);
            // target (u8 @ offset 67)
            write_volatile(p.add(67), target);
            // bus (u8 @ offset 66)
            write_volatile(p.add(66), 0u8);
        }

        // Memory barrier before publishing
        compiler_fence(Ordering::SeqCst);

        // Increment reqProdIdx
        self.req_prod_idx += 1;
        unsafe {
            let rings_req_prod = (addr_of_mut!(RINGS_STATE) as *mut u8).add(0x00) as *mut u32;
            write_volatile(rings_req_prod, self.req_prod_idx);
        }
        compiler_fence(Ordering::SeqCst);

        // Kick the device
        let kick_reg = if flags & PVSCSI_FLAG_CMD_DIR_NONE != 0 {
            PVSCSI_REG_KICK_NON_RW_IO
        } else {
            PVSCSI_REG_KICK_RW_IO
        };
        mmio_write32(self.mmio_base, kick_reg, 0);

        // Poll for completion
        let cmp_num_entries_log2 = unsafe {
            let p = (addr_of!(RINGS_STATE) as *const u8).add(0x14) as *const u32;
            read_volatile(p)
        };
        let cmp_mask = (1u32 << cmp_num_entries_log2) - 1;

        for _ in 0..1_000_000u32 {
            compiler_fence(Ordering::SeqCst);
            let cmp_prod = unsafe {
                let p = (addr_of!(RINGS_STATE) as *const u8).add(0x0C) as *const u32;
                read_volatile(p)
            };

            if cmp_prod != self.cmp_cons_idx {
                // Read completion
                let cmp_slot = self.cmp_cons_idx & cmp_mask;
                let cmp_base = unsafe {
                    (addr_of!(CMP_RING) as *const u8).add(cmp_slot as usize * CMP_DESC_SIZE)
                };

                let cmp_context = unsafe { read_volatile(cmp_base.add(0) as *const u64) };
                let host_status = unsafe { read_volatile(cmp_base.add(0x14) as *const u16) };
                let scsi_status = unsafe { read_volatile(cmp_base.add(0x16) as *const u16) };

                // Advance consumer
                self.cmp_cons_idx += 1;
                unsafe {
                    let p = (addr_of_mut!(RINGS_STATE) as *mut u8).add(0x10) as *mut u32;
                    write_volatile(p, self.cmp_cons_idx);
                }

                if cmp_context != ctx {
                    serial::println("PVSCSI: completion context mismatch");
                    return false;
                }

                if host_status != 0x00 {
                    serial::print("PVSCSI: host_status=0x");
                    serial::print_hex32(host_status as u32);
                    serial::println("");
                    return false;
                }

                if scsi_status != 0x00 {
                    // 0x02 = CHECK CONDITION, etc.
                    return false;
                }

                return true;
            }

            // Brief spin — volatile read is enough on x86
            for _ in 0..100u32 {
                core::hint::spin_loop();
            }
        }

        serial::println("PVSCSI: completion timeout");
        false
    }
}

// --- MMIO helpers ---

fn mmio_write32(base: usize, offset: usize, value: u32) {
    unsafe {
        write_volatile((base + offset) as *mut u32, value);
    }
}

fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe {
        read_volatile((base + offset) as *const u32)
    }
}

/// Initialize PVSCSI controller. Returns (controller, target, lun) of first disk found.
pub fn init() -> Option<(PvScsi, u8, u8)> {
    serial::println("PVSCSI: Scanning for controller...");

    let pci_dev = pci::find_device(PVSCSI_VENDOR_ID, PVSCSI_DEVICE_ID)?;

    serial::print("PVSCSI: Found at ");
    serial::print_dec(pci_dev.bus as u32);
    serial::print(":");
    serial::print_dec(pci_dev.slot as u32);
    serial::print(".");
    serial::print_dec(pci_dev.func as u32);
    serial::println("");

    // Read BAR0 (MMIO)
    let bar0_raw = pci::pci_read_bar(&pci_dev, 0);
    let mmio_base = (bar0_raw & 0xFFFFFFF0) as usize;

    serial::print("PVSCSI: MMIO base = 0x");
    serial::print_hex32(mmio_base as u32);
    serial::println("");

    if mmio_base == 0 {
        serial::println("PVSCSI: BAR0 is zero, cannot init");
        return None;
    }

    // Enable bus mastering (required for DMA)
    pci::enable_bus_master(&pci_dev);

    // Step 1: Adapter reset
    mmio_write32(mmio_base, PVSCSI_REG_COMMAND, PVSCSI_CMD_ADAPTER_RESET);

    // Brief delay for reset
    for _ in 0..10_000u32 {
        core::hint::spin_loop();
    }

    // Step 2: Zero ring buffers
    unsafe {
        ptr::write_bytes(addr_of_mut!(RINGS_STATE) as *mut u8, 0, 4096);
        ptr::write_bytes(addr_of_mut!(REQ_RING) as *mut u8, 0, 4096);
        ptr::write_bytes(addr_of_mut!(CMP_RING) as *mut u8, 0, 4096);
    }

    // Step 3: Build SetupRings command descriptor
    // Layout (as u32 words):
    //   [0]     reqRingNumPages (u32)
    //   [1]     cmpRingNumPages (u32)
    //   [2..3]  ringsStatePPN   (u64)
    //   [4..67] reqRingPPNs     (32 x u64)
    //   [68..131] cmpRingPPNs   (32 x u64)
    // Total: 132 u32 words

    let rings_state_ppn = unsafe { addr_of!(RINGS_STATE) as u64 } >> 12;
    let req_ring_ppn = unsafe { addr_of!(REQ_RING) as u64 } >> 12;
    let cmp_ring_ppn = unsafe { addr_of!(CMP_RING) as u64 } >> 12;

    let mut cmd_data = [0u32; 132];
    cmd_data[0] = 1; // reqRingNumPages
    cmd_data[1] = 1; // cmpRingNumPages
    cmd_data[2] = rings_state_ppn as u32;        // low
    cmd_data[3] = (rings_state_ppn >> 32) as u32; // high
    cmd_data[4] = req_ring_ppn as u32;
    cmd_data[5] = (req_ring_ppn >> 32) as u32;
    cmd_data[68] = cmp_ring_ppn as u32;
    cmd_data[69] = (cmp_ring_ppn >> 32) as u32;

    // Issue SETUP_RINGS command
    mmio_write32(mmio_base, PVSCSI_REG_COMMAND, PVSCSI_CMD_SETUP_RINGS);
    for word in cmd_data.iter() {
        mmio_write32(mmio_base, PVSCSI_REG_COMMAND_DATA, *word);
    }

    let status = mmio_read32(mmio_base, PVSCSI_REG_COMMAND_STATUS);
    if status != 0 {
        serial::print("PVSCSI: SETUP_RINGS failed, status=");
        serial::print_dec(status);
        serial::println("");
        return None;
    }

    serial::println("PVSCSI: Rings configured");

    // Mask interrupts (we use polling)
    mmio_write32(mmio_base, PVSCSI_REG_INTR_MASK, 0);

    let mut ctrl = PvScsi {
        mmio_base,
        req_prod_idx: 0,
        cmp_cons_idx: 0,
        context_counter: 0,
    };

    // Step 4: Scan for disk targets (0..15)
    for target in 0..16u8 {
        if !ctrl.inquiry(target, 0) {
            continue;
        }

        serial::print("PVSCSI: Disk found at target ");
        serial::print_dec(target as u32);
        serial::println("");

        if !ctrl.test_unit_ready(target, 0) {
            serial::println("PVSCSI: Device not ready");
            continue;
        }

        if let Some((sectors, block_size)) = ctrl.read_capacity(target, 0) {
            let size_mb = (sectors * block_size as u64) / (1024 * 1024);
            serial::print("PVSCSI: Capacity ");
            serial::print_dec(size_mb as u32);
            serial::print(" MB (");
            serial::print_dec(sectors as u32);
            serial::print(" sectors x ");
            serial::print_dec(block_size);
            serial::print("b)");
            serial::println("");
        }

        return Some((ctrl, target, 0));
    }

    serial::println("PVSCSI: No disks found");
    None
}
