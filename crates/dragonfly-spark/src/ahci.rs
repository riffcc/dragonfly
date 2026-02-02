//! AHCI (SATA) driver for disk detection
//!
//! Supports detecting drives and reading sectors via AHCI

use crate::pci::{self, PciDevice};
use crate::serial;
use core::ptr::{read_volatile, write_volatile};

/// AHCI HBA memory registers (at ABAR)
#[repr(C)]
struct HbaMemory {
    cap: u32,        // Host Capabilities
    ghc: u32,        // Global Host Control
    is: u32,         // Interrupt Status
    pi: u32,         // Ports Implemented
    vs: u32,         // Version
    ccc_ctl: u32,    // Command Completion Coalescing Control
    ccc_ports: u32,  // Command Completion Coalescing Ports
    em_loc: u32,     // Enclosure Management Location
    em_ctl: u32,     // Enclosure Management Control
    cap2: u32,       // Extended Capabilities
    bohc: u32,       // BIOS/OS Handoff Control
    _reserved: [u8; 0xA0 - 0x2C],
    vendor: [u8; 0x100 - 0xA0],
    ports: [HbaPort; 32],
}

/// AHCI Port registers
#[repr(C)]
struct HbaPort {
    clb: u32,        // Command List Base Address (low)
    clbu: u32,       // Command List Base Address (high)
    fb: u32,         // FIS Base Address (low)
    fbu: u32,        // FIS Base Address (high)
    is: u32,         // Interrupt Status
    ie: u32,         // Interrupt Enable
    cmd: u32,        // Command and Status
    _reserved0: u32,
    tfd: u32,        // Task File Data
    sig: u32,        // Signature
    ssts: u32,       // SATA Status
    sctl: u32,       // SATA Control
    serr: u32,       // SATA Error
    sact: u32,       // SATA Active
    ci: u32,         // Command Issue
    sntf: u32,       // SATA Notification
    fbs: u32,        // FIS-based Switching Control
    _reserved1: [u32; 11],
    vendor: [u32; 4],
}

/// Port signatures
const SATA_SIG_ATA: u32 = 0x00000101;   // SATA drive
const SATA_SIG_ATAPI: u32 = 0xEB140101; // SATAPI drive
const SATA_SIG_SEMB: u32 = 0xC33C0101;  // Enclosure management bridge
const SATA_SIG_PM: u32 = 0x96690101;    // Port multiplier

/// Device detection status
const HBA_PORT_DET_PRESENT: u32 = 0x3;

/// Interface power management
const HBA_PORT_IPM_ACTIVE: u32 = 0x1;

/// Command header (one per command slot)
#[repr(C)]
struct HbaCmdHeader {
    // DW0
    cfl_a_w_p_r_c: u8, // Command FIS length (bits 0-4), ATAPI (5), Write (6), Prefetchable (7)
    pmp_c_b_r: u8,     // Port Multiplier Port (0-3), reserved (4), Clear busy (6), BIST (5), Reset (7)
    prdtl: u16,        // Physical Region Descriptor Table Length
    // DW1
    prdbc: u32,        // PRD Byte Count
    // DW2-3
    ctba: u32,         // Command Table Base Address (low)
    ctbau: u32,        // Command Table Base Address (high)
    // DW4-7
    _reserved: [u32; 4],
}

/// Physical Region Descriptor Table entry
#[repr(C)]
struct HbaPrdtEntry {
    dba: u32,          // Data Base Address (low)
    dbau: u32,         // Data Base Address (high)
    _reserved: u32,
    dbc_i: u32,        // Data Byte Count (bits 0-21), Interrupt on completion (bit 31)
}

/// Command Table
#[repr(C)]
struct HbaCmdTable {
    cfis: [u8; 64],    // Command FIS
    acmd: [u8; 16],    // ATAPI Command
    _reserved: [u8; 48],
    prdt: [HbaPrdtEntry; 8], // Up to 8 PRDTs (enough for 32KB)
}

/// FIS types
const FIS_TYPE_REG_H2D: u8 = 0x27; // Register FIS - Host to Device

/// ATA commands
const ATA_CMD_READ_DMA_EX: u8 = 0x25;
const ATA_CMD_IDENTIFY: u8 = 0xEC;

/// AHCI controller state
pub struct AhciController {
    abar: u32,
    ports_implemented: u32,
}

/// Detected AHCI drive
pub struct AhciDrive {
    pub port: u8,
    pub is_atapi: bool,
}

// Static memory for AHCI structures (must be aligned and below 4GB)
// We use a static buffer in low memory
// Using a wrapper to make UnsafeCell Sync (safe in single-threaded bare-metal)
use core::cell::UnsafeCell;

struct AhciBuffers {
    cmd_list: [[u8; 1024]; 32],
    fis_area: [[u8; 256]; 32],
    cmd_table: [[u8; 256]; 32],
    data_buffer: [u8; 512],
}

// Wrapper that implements Sync for single-threaded bare-metal use
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

static AHCI_BUFFERS: SyncUnsafeCell<AhciBuffers> = SyncUnsafeCell::new(AhciBuffers {
    cmd_list: [[0; 1024]; 32],
    fis_area: [[0; 256]; 32],
    cmd_table: [[0; 256]; 32],
    data_buffer: [0; 512],
});

impl AhciController {
    /// Initialize AHCI controller
    pub fn new(device: &PciDevice) -> Option<Self> {
        let abar = device.bar5;
        if abar == 0 {
            serial::println("AHCI: BAR5 is zero!");
            return None;
        }

        serial::print("AHCI: ABAR = 0x");
        serial::print_hex32(abar);
        serial::println("");

        let ctrl = AhciController {
            abar,
            ports_implemented: 0,
        };

        // Read ports implemented
        let pi = ctrl.read_reg(0x0C); // PI register
        serial::print("AHCI: Ports implemented = 0x");
        serial::print_hex32(pi);
        serial::println("");

        Some(AhciController {
            abar,
            ports_implemented: pi,
        })
    }

    /// Read a register from HBA memory
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { read_volatile((self.abar + offset) as *const u32) }
    }

    /// Write a register to HBA memory
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe { write_volatile((self.abar + offset) as *mut u32, value) }
    }

    /// Read a port register
    fn read_port_reg(&self, port: u8, offset: u32) -> u32 {
        let port_base = 0x100 + (port as u32 * 0x80);
        self.read_reg(port_base + offset)
    }

    /// Write a port register
    fn write_port_reg(&self, port: u8, offset: u32, value: u32) {
        let port_base = 0x100 + (port as u32 * 0x80);
        self.write_reg(port_base + offset, value)
    }

    /// Scan for connected drives
    pub fn scan_ports(&self) -> Option<AhciDrive> {
        for port in 0..32u8 {
            if self.ports_implemented & (1 << port) == 0 {
                continue;
            }

            serial::print("AHCI: Checking port ");
            serial::print_dec(port as u32);

            // Read SATA status
            let ssts = self.read_port_reg(port, 0x28); // PxSSTS
            let det = ssts & 0x0F;
            let ipm = (ssts >> 8) & 0x0F;

            serial::print(" SSTS=0x");
            serial::print_hex32(ssts);

            if det != HBA_PORT_DET_PRESENT {
                serial::println(" - no device");
                continue;
            }

            if ipm != HBA_PORT_IPM_ACTIVE {
                serial::println(" - not active");
                continue;
            }

            // Read signature
            let sig = self.read_port_reg(port, 0x24); // PxSIG
            serial::print(" SIG=0x");
            serial::print_hex32(sig);

            let is_atapi = match sig {
                SATA_SIG_ATA => {
                    serial::println(" - SATA drive");
                    false
                }
                SATA_SIG_ATAPI => {
                    serial::println(" - SATAPI drive");
                    true
                }
                _ => {
                    serial::println(" - unknown");
                    continue;
                }
            };

            return Some(AhciDrive { port, is_atapi });
        }

        None
    }

    /// Initialize a port for use
    pub fn init_port(&self, port: u8) -> bool {
        serial::print("AHCI: Initializing port ");
        serial::print_dec(port as u32);
        serial::println("");

        // Stop command engine
        self.stop_cmd(port);

        // Set up command list and FIS area
        unsafe {
            let buffers = &mut *AHCI_BUFFERS.get();
            let clb = buffers.cmd_list[port as usize].as_ptr() as u32;
            let fb = buffers.fis_area[port as usize].as_ptr() as u32;

            serial::print("  CLB = 0x");
            serial::print_hex32(clb);
            serial::print(", FB = 0x");
            serial::print_hex32(fb);
            serial::println("");

            self.write_port_reg(port, 0x00, clb);  // PxCLB
            self.write_port_reg(port, 0x04, 0);    // PxCLBU
            self.write_port_reg(port, 0x08, fb);   // PxFB
            self.write_port_reg(port, 0x0C, 0);    // PxFBU
        }

        // Clear error register
        self.write_port_reg(port, 0x30, 0xFFFFFFFF); // PxSERR

        // Start command engine
        self.start_cmd(port);

        true
    }

    /// Stop command engine
    fn stop_cmd(&self, port: u8) {
        let mut cmd = self.read_port_reg(port, 0x18); // PxCMD

        // Clear ST (bit 0)
        cmd &= !(1 << 0);
        self.write_port_reg(port, 0x18, cmd);

        // Wait for CR (bit 15) to clear
        for _ in 0..1000000 {
            let cmd = self.read_port_reg(port, 0x18);
            if cmd & (1 << 15) == 0 {
                break;
            }
        }

        // Clear FRE (bit 4)
        cmd = self.read_port_reg(port, 0x18);
        cmd &= !(1 << 4);
        self.write_port_reg(port, 0x18, cmd);

        // Wait for FR (bit 14) to clear
        for _ in 0..1000000 {
            let cmd = self.read_port_reg(port, 0x18);
            if cmd & (1 << 14) == 0 {
                break;
            }
        }
    }

    /// Start command engine
    fn start_cmd(&self, port: u8) {
        // Wait until CR is cleared
        for _ in 0..1000000 {
            let cmd = self.read_port_reg(port, 0x18);
            if cmd & (1 << 15) == 0 {
                break;
            }
        }

        // Set FRE and ST
        let mut cmd = self.read_port_reg(port, 0x18);
        cmd |= (1 << 4) | (1 << 0); // FRE | ST
        self.write_port_reg(port, 0x18, cmd);
    }

    /// Read a sector from disk
    pub fn read_sector(&self, port: u8, lba: u64, buffer: &mut [u8; 512]) -> bool {
        unsafe {
            let buffers = &mut *AHCI_BUFFERS.get();

            // Set up command header
            let cmd_header = buffers.cmd_list[port as usize].as_mut_ptr() as *mut HbaCmdHeader;

            // Command FIS length = 5 DWORDS, not ATAPI, not write
            (*cmd_header).cfl_a_w_p_r_c = 5;
            (*cmd_header).pmp_c_b_r = 0;
            (*cmd_header).prdtl = 1;

            let ctba = buffers.cmd_table[port as usize].as_ptr() as u32;
            (*cmd_header).ctba = ctba;
            (*cmd_header).ctbau = 0;

            // Set up command table
            let cmd_table = buffers.cmd_table[port as usize].as_mut_ptr() as *mut HbaCmdTable;

            // Clear command table
            core::ptr::write_bytes(cmd_table, 0, 1);

            // Set up PRDT
            let data_ptr = buffers.data_buffer.as_ptr() as u32;
            (*cmd_table).prdt[0].dba = data_ptr;
            (*cmd_table).prdt[0].dbau = 0;
            (*cmd_table).prdt[0].dbc_i = 511; // 512 bytes - 1

            // Set up command FIS (Register H2D)
            let cfis = &mut (*cmd_table).cfis;
            cfis[0] = FIS_TYPE_REG_H2D;
            cfis[1] = 0x80; // Command bit set
            cfis[2] = ATA_CMD_READ_DMA_EX;
            cfis[3] = 0; // Features

            // LBA
            cfis[4] = lba as u8;
            cfis[5] = (lba >> 8) as u8;
            cfis[6] = (lba >> 16) as u8;
            cfis[7] = 0x40; // LBA mode

            cfis[8] = (lba >> 24) as u8;
            cfis[9] = (lba >> 32) as u8;
            cfis[10] = (lba >> 40) as u8;
            cfis[11] = 0; // Features (high)

            // Sector count = 1
            cfis[12] = 1;
            cfis[13] = 0;

            // Clear interrupt status
            self.write_port_reg(port, 0x10, 0xFFFFFFFF); // PxIS

            // Issue command (slot 0)
            self.write_port_reg(port, 0x38, 1); // PxCI

            // Wait for completion
            for _ in 0..10000000 {
                let ci = self.read_port_reg(port, 0x38);
                if ci == 0 {
                    // Command completed
                    buffer.copy_from_slice(&buffers.data_buffer);
                    return true;
                }

                // Check for error
                let is = self.read_port_reg(port, 0x10);
                if is & (1 << 30) != 0 {
                    serial::println("AHCI: Task file error");
                    return false;
                }
            }

            serial::println("AHCI: Command timeout");
            false
        }
    }
}

/// Find and initialize AHCI controller
pub fn init() -> Option<(AhciController, AhciDrive)> {
    serial::println("AHCI: Scanning for controller...");

    let device = pci::find_ahci_controller()?;
    serial::print("AHCI: Found controller at ");
    serial::print_dec(device.bus as u32);
    serial::print(":");
    serial::print_dec(device.slot as u32);
    serial::print(".");
    serial::print_dec(device.func as u32);
    serial::println("");

    let controller = AhciController::new(&device)?;
    let drive = controller.scan_ports()?;

    if !controller.init_port(drive.port) {
        serial::println("AHCI: Failed to initialize port");
        return None;
    }

    Some((controller, drive))
}
