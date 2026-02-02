//! Disk scanning and OS detection
//!
//! Supports ATA PIO (legacy IDE), AHCI (SATA), and VirtIO SCSI

use crate::bios::{inb, outb, insw, io_wait};
use crate::serial;
use crate::ahci;
use crate::virtio;

/// ATA Primary bus I/O ports
const ATA_PRIMARY_DATA: u16 = 0x1F0;
const ATA_PRIMARY_ERROR: u16 = 0x1F1;
const ATA_PRIMARY_SECTOR_COUNT: u16 = 0x1F2;
const ATA_PRIMARY_LBA_LO: u16 = 0x1F3;
const ATA_PRIMARY_LBA_MID: u16 = 0x1F4;
const ATA_PRIMARY_LBA_HI: u16 = 0x1F5;
const ATA_PRIMARY_DRIVE: u16 = 0x1F6;
const ATA_PRIMARY_STATUS: u16 = 0x1F7;
const ATA_PRIMARY_COMMAND: u16 = 0x1F7;

/// ATA status bits
const ATA_STATUS_BSY: u8 = 0x80;
const ATA_STATUS_DRQ: u8 = 0x08;
const ATA_STATUS_ERR: u8 = 0x01;

/// ATA commands
const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_IDENTIFY: u8 = 0xEC;

/// MBR signature
const MBR_SIGNATURE: u16 = 0xAA55;

/// Disk interface type
#[derive(Clone, Copy, Debug)]
pub enum DiskType {
    /// ATA PIO (legacy IDE)
    AtaPio,
    /// AHCI (SATA)
    Ahci { port: u8 },
    /// VirtIO SCSI (VMs)
    VirtioScsi { target: u8, lun: u8 },
    /// BIOS INT 13h (direct, preserves BIOS state)
    BiosDirect { drive: u8 },
}

/// Detected OS information
pub struct OsInfo {
    pub name: &'static str,
    pub disk_type: DiskType,
    pub partition: u8,
    pub bootable: bool,
    /// Cached MBR from detection (for chainloading without re-reading)
    pub mbr: [u8; 512],
}


/// Partition table entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PartitionEntry {
    status: u8,           // 0x80 = bootable
    chs_start: [u8; 3],
    partition_type: u8,
    chs_end: [u8; 3],
    lba_start: u32,
    sector_count: u32,
}

/// Scan for bootable operating systems
pub fn scan_for_os() -> Option<OsInfo> {
    serial::println("scan_for_os() starting");

    // Try ATA PIO first (legacy IDE)
    if let Some(os) = scan_ata_pio() {
        return Some(os);
    }

    // Try AHCI (SATA)
    if let Some(os) = scan_ahci() {
        return Some(os);
    }

    // Try VirtIO SCSI (VMs)
    if let Some(os) = scan_virtio_scsi() {
        return Some(os);
    }

    serial::println("No bootable drives found");
    None
}

/// Scan using VirtIO SCSI (common in VMs)
fn scan_virtio_scsi() -> Option<OsInfo> {
    serial::println("Trying VirtIO SCSI...");

    let (mut controller, target, lun) = virtio::init()?;

    serial::print("VirtIO SCSI: Reading MBR from target ");
    serial::print_dec(target as u32);
    serial::println("");

    // Read MBR
    let mut mbr = [0u8; 512];
    if !controller.read_sector(target, lun, 0, &mut mbr) {
        serial::println("VirtIO SCSI: MBR read failed");
        return None;
    }
    serial::println("VirtIO SCSI: MBR read OK");

    parse_mbr(&mbr, DiskType::VirtioScsi { target, lun })
}

/// Scan using ATA PIO mode (legacy IDE)
fn scan_ata_pio() -> Option<OsInfo> {
    serial::println("Trying ATA PIO...");

    // Check if drive exists
    if !drive_exists(0) {
        serial::println("ATA PIO: No drive found");
        return None;
    }
    serial::println("ATA PIO: Drive found");

    // Read MBR
    let mut mbr = [0u8; 512];
    if !read_sector_ata(0, 0, &mut mbr) {
        serial::println("ATA PIO: MBR read failed");
        return None;
    }

    parse_mbr(&mbr, DiskType::AtaPio)
}

/// Scan using AHCI (SATA)
fn scan_ahci() -> Option<OsInfo> {
    serial::println("Trying AHCI...");

    let (controller, drive) = ahci::init()?;

    if drive.is_atapi {
        serial::println("AHCI: Found ATAPI (CD/DVD), skipping");
        return None;
    }

    serial::print("AHCI: Reading MBR from port ");
    serial::print_dec(drive.port as u32);
    serial::println("");

    // Read MBR
    let mut mbr = [0u8; 512];
    if !controller.read_sector(drive.port, 0, &mut mbr) {
        serial::println("AHCI: MBR read failed");
        return None;
    }
    serial::println("AHCI: MBR read OK");

    parse_mbr(&mbr, DiskType::Ahci { port: drive.port })
}

/// Parse MBR and find bootable OS
fn parse_mbr(mbr: &[u8; 512], disk_type: DiskType) -> Option<OsInfo> {
    // Debug: print first 16 bytes of MBR
    serial::print("MBR first 16 bytes: ");
    for i in 0..16 {
        serial::print_hex32(mbr[i] as u32);
        serial::print(" ");
    }
    serial::println("");

    // Debug: print last 16 bytes of MBR (including signature)
    serial::print("MBR last 16 bytes: ");
    for i in 496..512 {
        serial::print_hex32(mbr[i] as u32);
        serial::print(" ");
    }
    serial::println("");

    // Check MBR signature
    let signature = u16::from_le_bytes([mbr[510], mbr[511]]);
    if signature != MBR_SIGNATURE {
        serial::print("Invalid MBR signature: 0x");
        serial::print_hex32(signature as u32);
        serial::println("");
        return None;
    }
    serial::println("MBR signature valid");

    // Parse partition table (starts at offset 446)
    for i in 0..4 {
        let offset = 446 + i * 16;
        let entry = unsafe {
            core::ptr::read_unaligned(mbr.as_ptr().add(offset) as *const PartitionEntry)
        };

        if entry.partition_type == 0 {
            continue; // Empty partition
        }

        let bootable = entry.status == 0x80;
        let type_name = partition_type_name(entry.partition_type);

        serial::print("  Partition ");
        serial::print_dec(i as u32 + 1);
        serial::print(": ");
        serial::print(type_name);
        if bootable {
            serial::print(" [BOOTABLE]");
        }
        serial::println("");

        // If we find a bootable Linux/Windows partition, return it
        if bootable && is_bootable_type(entry.partition_type) {
            return Some(OsInfo {
                name: type_name,
                disk_type,
                partition: i as u8 + 1,
                bootable: true,
                mbr: *mbr,  // Cache MBR for chainloading
            });
        }
    }

    // Check for GPT (partition type 0xEE in first entry)
    let first_entry = unsafe {
        core::ptr::read_unaligned(mbr.as_ptr().add(446) as *const PartitionEntry)
    };
    if first_entry.partition_type == 0xEE {
        serial::println("GPT detected");
        return Some(OsInfo {
            name: "GPT System",
            disk_type,
            partition: 1,
            bootable: true,
            mbr: *mbr,  // Cache MBR for chainloading
        });
    }

    None
}

/// Check if ATA drive exists
fn drive_exists(drive: u8) -> bool {
    serial::println("drive_exists() called");
    unsafe {
        // Select drive
        serial::println("Selecting drive...");
        outb(ATA_PRIMARY_DRIVE, 0xA0 | (drive << 4));
        io_wait();

        // Send IDENTIFY command
        serial::println("Sending IDENTIFY command...");
        outb(ATA_PRIMARY_COMMAND, ATA_CMD_IDENTIFY);
        io_wait();

        // Check status
        serial::println("Checking status...");
        let status = inb(ATA_PRIMARY_STATUS);
        if status == 0 {
            serial::println("Status=0, no drive");
            return false; // Drive doesn't exist
        }

        // Wait for BSY to clear
        serial::println("Waiting for BSY...");
        for _ in 0..100000 {
            let status = inb(ATA_PRIMARY_STATUS);
            if status & ATA_STATUS_BSY == 0 {
                break;
            }
        }

        // Check for error (would indicate ATAPI or no drive)
        let status = inb(ATA_PRIMARY_STATUS);
        if status & ATA_STATUS_ERR != 0 {
            serial::println("Drive error");
            return false;
        }

        serial::println("Drive exists!");
        true
    }
}

/// Read a sector from disk using ATA PIO
fn read_sector_ata(drive: u8, lba: u32, buffer: &mut [u8; 512]) -> bool {
    unsafe {
        // Wait for drive ready
        wait_ready();

        // Select drive and set up LBA
        outb(ATA_PRIMARY_DRIVE, 0xE0 | (drive << 4) | ((lba >> 24) & 0x0F) as u8);
        outb(ATA_PRIMARY_ERROR, 0); // Features = 0
        outb(ATA_PRIMARY_SECTOR_COUNT, 1); // Read 1 sector
        outb(ATA_PRIMARY_LBA_LO, lba as u8);
        outb(ATA_PRIMARY_LBA_MID, (lba >> 8) as u8);
        outb(ATA_PRIMARY_LBA_HI, (lba >> 16) as u8);

        // Send read command
        outb(ATA_PRIMARY_COMMAND, ATA_CMD_READ_SECTORS);

        // Wait for data ready
        if !wait_drq() {
            return false;
        }

        // Read data (256 words = 512 bytes)
        let buffer_words = core::slice::from_raw_parts_mut(
            buffer.as_mut_ptr() as *mut u16,
            256
        );
        insw(ATA_PRIMARY_DATA, buffer_words);

        true
    }
}

/// Wait for drive to be ready
fn wait_ready() {
    unsafe {
        for _ in 0..100000 {
            let status = inb(ATA_PRIMARY_STATUS);
            if status & ATA_STATUS_BSY == 0 {
                return;
            }
        }
    }
}

/// Wait for data request
fn wait_drq() -> bool {
    unsafe {
        for _ in 0..100000 {
            let status = inb(ATA_PRIMARY_STATUS);
            if status & ATA_STATUS_ERR != 0 {
                return false;
            }
            if status & ATA_STATUS_DRQ != 0 {
                return true;
            }
        }
        false
    }
}

/// Get partition type name
fn partition_type_name(ptype: u8) -> &'static str {
    match ptype {
        0x00 => "Empty",
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x05 | 0x0F => "Extended",
        0x07 => "NTFS/HPFS",
        0x0B | 0x0C => "FAT32",
        0x11 => "Hidden FAT12",
        0x14 | 0x16 | 0x1E => "Hidden FAT16",
        0x17 => "Hidden NTFS",
        0x1B | 0x1C => "Hidden FAT32",
        0x82 => "Linux Swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xA5 => "FreeBSD",
        0xA6 => "OpenBSD",
        0xAF => "macOS HFS+",
        0xEE => "GPT Protective",
        0xEF => "EFI System",
        0xFD => "Linux RAID",
        _ => "Unknown",
    }
}

/// Check if partition type is typically bootable
fn is_bootable_type(ptype: u8) -> bool {
    matches!(ptype,
        0x07 |  // NTFS (Windows)
        0x0B | 0x0C |  // FAT32
        0x83 |  // Linux
        0xEE |  // GPT
        0xEF    // EFI System
    )
}
