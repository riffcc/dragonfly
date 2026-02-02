//! Disk scanning and OS detection
//!
//! Supports ATA PIO (legacy IDE), AHCI (SATA), and VirtIO SCSI
//! Can read GPT partition tables and ext4 filesystems to detect OS

use crate::bios::{inb, outb, insw, io_wait};
use crate::serial;
use crate::ahci;
use crate::virtio;

/// GPT header signature "EFI PART"
const GPT_SIGNATURE: u64 = 0x5452415020494645;

/// Linux filesystem partition type GUID (little-endian bytes)
/// 0FC63DAF-8483-4772-8E79-3D69D8477DE4
const LINUX_FS_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4
];

/// EFI System Partition GUID
/// C12A7328-F81F-11D2-BA4B-00A0C93EC93B
const EFI_SYSTEM_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B
];

/// ext4 superblock magic number
const EXT4_MAGIC: u16 = 0xEF53;

/// FAT32 boot sector signature
const FAT32_SIGNATURE: u16 = 0xAA55;

/// FAT32 Boot Sector / BPB (BIOS Parameter Block)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Fat32BootSector {
    jmp_boot: [u8; 3],
    oem_name: [u8; 8],
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    root_entry_count: u16,  // 0 for FAT32
    total_sectors_16: u16,  // 0 for FAT32
    media_type: u8,
    fat_size_16: u16,       // 0 for FAT32
    sectors_per_track: u16,
    num_heads: u16,
    hidden_sectors: u32,
    total_sectors_32: u32,
    // FAT32-specific fields
    fat_size_32: u32,
    ext_flags: u16,
    fs_version: u16,
    root_cluster: u32,
    fs_info: u16,
    backup_boot_sector: u16,
    reserved: [u8; 12],
    drive_number: u8,
    reserved1: u8,
    boot_sig: u8,
    volume_id: u32,
    volume_label: [u8; 11],
    fs_type: [u8; 8],
}

/// FAT32 Directory Entry (32 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Fat32DirEntry {
    name: [u8; 11],         // 8.3 format
    attr: u8,
    nt_reserved: u8,
    create_time_tenth: u8,
    create_time: u16,
    create_date: u16,
    access_date: u16,
    cluster_hi: u16,
    modify_time: u16,
    modify_date: u16,
    cluster_lo: u16,
    file_size: u32,
}

/// FAT32 Long File Name entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Fat32LfnEntry {
    order: u8,
    name1: [u16; 5],
    attr: u8,
    lfn_type: u8,
    checksum: u8,
    name2: [u16; 6],
    cluster: u16,
    name3: [u16; 2],
}

const FAT_ATTR_DIRECTORY: u8 = 0x10;
const FAT_ATTR_LFN: u8 = 0x0F;

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
    /// Detected OS name from filesystem (heap-allocated string simulation)
    pub os_name_buf: [u8; 64],
    pub os_name_len: usize,
}

impl OsInfo {
    /// Get the display name - either detected OS or fallback partition type
    pub fn display_name(&self) -> &str {
        if self.os_name_len > 0 {
            // Safety: we only store valid UTF-8 from os-release
            unsafe { core::str::from_utf8_unchecked(&self.os_name_buf[..self.os_name_len]) }
        } else {
            self.name
        }
    }
}

/// GPT Header (at LBA 1)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GptHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    reserved: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: [u8; 16],
    partition_entry_lba: u64,
    num_partition_entries: u32,
    partition_entry_size: u32,
    partition_array_crc32: u32,
}

/// GPT Partition Entry (128 bytes each)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GptPartitionEntry {
    type_guid: [u8; 16],
    partition_guid: [u8; 16],
    starting_lba: u64,
    ending_lba: u64,
    attributes: u64,
    name: [u16; 36], // UTF-16LE partition name
}

/// ext4 Superblock (partial - we only need a few fields)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ext4Superblock {
    s_inodes_count: u32,
    s_blocks_count_lo: u32,
    s_r_blocks_count_lo: u32,
    s_free_blocks_count_lo: u32,
    s_free_inodes_count: u32,
    s_first_data_block: u32,
    s_log_block_size: u32,
    s_log_cluster_size: u32,
    s_blocks_per_group: u32,
    s_clusters_per_group: u32,
    s_inodes_per_group: u32,
    s_mtime: u32,
    s_wtime: u32,
    s_mnt_count: u16,
    s_max_mnt_count: u16,
    s_magic: u16,
    s_state: u16,
    s_errors: u16,
    s_minor_rev_level: u16,
    s_lastcheck: u32,
    s_checkinterval: u32,
    s_creator_os: u32,
    s_rev_level: u32,
    s_def_resuid: u16,
    s_def_resgid: u16,
    // ext4 specific fields
    s_first_ino: u32,
    s_inode_size: u16,
    s_block_group_nr: u16,
    s_feature_compat: u32,
    s_feature_incompat: u32,
    s_feature_ro_compat: u32,
    s_uuid: [u8; 16],
    s_volume_name: [u8; 16], // Volume label
}

/// ext4 inode structure (partial)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ext4Inode {
    i_mode: u16,
    i_uid: u16,
    i_size_lo: u32,
    i_atime: u32,
    i_ctime: u32,
    i_mtime: u32,
    i_dtime: u32,
    i_gid: u16,
    i_links_count: u16,
    i_blocks_lo: u32,
    i_flags: u32,
    i_osd1: u32,
    i_block: [u32; 15], // Block pointers
    i_generation: u32,
    i_file_acl_lo: u32,
    i_size_high: u32,
}

/// ext4 directory entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ext4DirEntry {
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
    // name follows (variable length)
}

/// ext4 extent header (at start of i_block when using extents)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ext4ExtentHeader {
    eh_magic: u16,      // 0xF30A
    eh_entries: u16,
    eh_max: u16,
    eh_depth: u16,
    eh_generation: u32,
}

/// ext4 extent (leaf node)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ext4Extent {
    ee_block: u32,      // First file block covered
    ee_len: u16,        // Number of blocks
    ee_start_hi: u16,   // High 16 bits of physical block
    ee_start_lo: u32,   // Low 32 bits of physical block
}

/// ext4 extent index (internal node)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ext4ExtentIdx {
    ei_block: u32,      // Covers file blocks from this
    ei_leaf_lo: u32,    // Block number of next level
    ei_leaf_hi: u16,    // High 16 bits of block
    ei_unused: u16,
}

const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const EXT4_EXTENTS_FL: u32 = 0x00080000;


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

    // Check for GPT - if so, do full OS detection
    let first_entry = unsafe {
        core::ptr::read_unaligned(mbr.as_ptr().add(446) as *const PartitionEntry)
    };
    if first_entry.partition_type == 0xEE {
        serial::println("GPT detected - performing OS detection");
        return detect_os_from_gpt(&mut controller, target, lun, &mbr);
    }

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
                mbr: *mbr,
                os_name_buf: [0; 64],
                os_name_len: 0,
            });
        }
    }

    // Check for GPT (partition type 0xEE in first entry)
    let first_entry = unsafe {
        core::ptr::read_unaligned(mbr.as_ptr().add(446) as *const PartitionEntry)
    };
    if first_entry.partition_type == 0xEE {
        serial::println("GPT protective MBR detected");
        return Some(OsInfo {
            name: "GPT System",
            disk_type,
            partition: 1,
            bootable: true,
            mbr: *mbr,
            os_name_buf: [0; 64],
            os_name_len: 0,
        });
    }

    None
}

/// Parse GPT and detect OS from filesystem
/// This is called after we have a working disk reader
fn detect_os_from_gpt(controller: &mut virtio::VirtioScsi, target: u8, lun: u8, mbr: &[u8; 512]) -> Option<OsInfo> {
    serial::println("Parsing GPT for OS detection...");

    // Read GPT header at LBA 1
    let mut gpt_sector = [0u8; 512];
    if !controller.read_sector(target, lun, 1, &mut gpt_sector) {
        serial::println("Failed to read GPT header - returning GPT System fallback");
        // Don't fail completely - we know it's GPT from the protective MBR
        return Some(OsInfo {
            name: "GPT System",
            disk_type: DiskType::VirtioScsi { target, lun },
            partition: 1,
            bootable: true,
            mbr: *mbr,
            os_name_buf: [0; 64],
            os_name_len: 0,
        });
    }

    let gpt_header = unsafe {
        core::ptr::read_unaligned(gpt_sector.as_ptr() as *const GptHeader)
    };

    // Verify GPT signature
    serial::print("GPT signature: 0x");
    serial::print_hex32((gpt_header.signature >> 32) as u32);
    serial::print_hex32(gpt_header.signature as u32);
    serial::println("");

    if gpt_header.signature != GPT_SIGNATURE {
        serial::println("Invalid GPT signature - returning GPT System fallback");
        return Some(OsInfo {
            name: "GPT System",
            disk_type: DiskType::VirtioScsi { target, lun },
            partition: 1,
            bootable: true,
            mbr: *mbr,
            os_name_buf: [0; 64],
            os_name_len: 0,
        });
    }
    serial::println("GPT signature valid");

    let num_entries = gpt_header.num_partition_entries.min(128) as usize;
    let entry_size = gpt_header.partition_entry_size as usize;
    let entries_per_sector = 512 / entry_size;

    serial::print("GPT: ");
    serial::print_dec(num_entries as u32);
    serial::print(" partition entries, ");
    serial::print_dec(entry_size as u32);
    serial::println(" bytes each");

    // Scan partition entries - look for both EFI System and Linux partitions
    // Ubuntu cloud images: partition 1 = Linux root, partition 15 = ESP
    let mut esp_partition_lba: u64 = 0;
    let mut linux_partition_lba: u64 = 0;
    let mut linux_partition_num: u8 = 0;

    // Cache the last read sector to avoid re-reading
    let mut cached_sector_idx: i32 = -1;
    let mut cached_sector = [0u8; 512];

    // Only scan first 20 entries (enough for Ubuntu's layout, avoids timeout)
    let scan_limit = num_entries.min(20);
    serial::print("Scanning first ");
    serial::print_dec(scan_limit as u32);
    serial::println(" partition entries...");

    for entry_idx in 0..scan_limit {
        let sector_idx = entry_idx / entries_per_sector;
        let offset_in_sector = (entry_idx % entries_per_sector) * entry_size;

        // Read sector if not cached
        if sector_idx as i32 != cached_sector_idx {
            let entry_lba = gpt_header.partition_entry_lba + sector_idx as u64;
            if !controller.read_sector(target, lun, entry_lba as u32, &mut cached_sector) {
                serial::print("Failed to read GPT entry sector ");
                serial::print_dec(sector_idx as u32);
                serial::println("");
                continue;
            }
            cached_sector_idx = sector_idx as i32;
        }

        let entry = unsafe {
            core::ptr::read_unaligned(cached_sector.as_ptr().add(offset_in_sector) as *const GptPartitionEntry)
        };

        // Skip empty entries
        if entry.type_guid == [0u8; 16] {
            continue;
        }

        // Debug: show partition type GUID for non-empty entries
        serial::print("Entry ");
        serial::print_dec(entry_idx as u32);
        serial::print(" GUID: ");
        for i in 0..4 {
            serial::print_hex32(entry.type_guid[i] as u32);
        }
        serial::println("...");

        // Check for EFI System Partition
        if entry.type_guid == EFI_SYSTEM_GUID && esp_partition_lba == 0 {
            serial::print("  -> EFI System Partition at LBA ");
            serial::print_dec(entry.starting_lba as u32);
            serial::println("");
            esp_partition_lba = entry.starting_lba;
        }

        // Check for Linux filesystem partition
        if entry.type_guid == LINUX_FS_GUID && linux_partition_lba == 0 {
            serial::print("  -> Linux partition at LBA ");
            serial::print_dec(entry.starting_lba as u32);
            serial::println("");
            linux_partition_lba = entry.starting_lba;
            linux_partition_num = entry_idx as u8 + 1;
        }

        // Stop early if we found both
        if esp_partition_lba != 0 && linux_partition_lba != 0 {
            serial::println("Found both ESP and Linux partitions");
            break;
        }
    }

    // Try to detect OS from bootloader config (FAT32 ESP) first
    // This works for GRUB, systemd-boot, etc.
    let (mut os_name_buf, mut os_name_len) = ([0u8; 64], 0usize);

    // Try FAT32 ESP first (GRUB/systemd-boot config)
    if esp_partition_lba != 0 {
        serial::println("Trying ESP (FAT32) for OS detection...");
        if let Some((buf, len)) = detect_os_from_esp(controller, target, lun, esp_partition_lba) {
            os_name_buf = buf;
            os_name_len = len;
        }
    }

    // Fall back to ext4 /etc/os-release or volume label
    if os_name_len == 0 && linux_partition_lba != 0 {
        serial::println("Falling back to ext4 for OS detection...");
        let (buf, len) = detect_os_from_ext4(controller, target, lun, linux_partition_lba);
        os_name_buf = buf;
        os_name_len = len;
    }

    if linux_partition_lba == 0 && esp_partition_lba == 0 {
        serial::println("No Linux or EFI partition found in GPT");
        return Some(OsInfo {
            name: "GPT System",
            disk_type: DiskType::VirtioScsi { target, lun },
            partition: 1,
            bootable: true,
            mbr: *mbr,
            os_name_buf: [0; 64],
            os_name_len: 0,
        });
    }

    Some(OsInfo {
        name: "Linux",
        disk_type: DiskType::VirtioScsi { target, lun },
        partition: if linux_partition_num > 0 { linux_partition_num } else { 1 },
        bootable: true,
        mbr: *mbr,
        os_name_buf,
        os_name_len,
    })
}

/// Detect OS from EFI System Partition by reading GRUB config
fn detect_os_from_esp(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64
) -> Option<([u8; 64], usize)> {
    serial::println("Reading FAT32 ESP for GRUB config...");

    // Read FAT32 boot sector
    let mut boot_sector = [0u8; 512];
    if !controller.read_sector(target, lun, partition_lba as u32, &mut boot_sector) {
        serial::println("Failed to read FAT32 boot sector");
        return None;
    }

    // Verify FAT32 signature
    let signature = u16::from_le_bytes([boot_sector[510], boot_sector[511]]);
    if signature != FAT32_SIGNATURE {
        serial::println("Invalid FAT32 signature");
        return None;
    }

    let bpb = unsafe {
        core::ptr::read_unaligned(boot_sector.as_ptr() as *const Fat32BootSector)
    };

    // Verify it's FAT32 (fat_size_16 == 0 means FAT32)
    if bpb.fat_size_16 != 0 {
        serial::println("Not FAT32 (FAT16 detected)");
        return None;
    }

    let bytes_per_sector = bpb.bytes_per_sector as u32;
    let sectors_per_cluster = bpb.sectors_per_cluster as u32;
    let reserved_sectors = bpb.reserved_sectors as u32;
    let fat_size = bpb.fat_size_32;
    let num_fats = bpb.num_fats as u32;
    let root_cluster = bpb.root_cluster;

    serial::print("FAT32: ");
    serial::print_dec(bytes_per_sector);
    serial::print(" bytes/sector, ");
    serial::print_dec(sectors_per_cluster);
    serial::print(" sectors/cluster, root cluster ");
    serial::print_dec(root_cluster);
    serial::println("");

    // Calculate data region start
    let fat_start_lba = partition_lba + reserved_sectors as u64;
    let data_start_lba = fat_start_lba + (num_fats as u64 * fat_size as u64);

    // Create FAT32 context for navigation
    let fat32 = Fat32Context {
        partition_lba,
        fat_start_lba,
        data_start_lba,
        sectors_per_cluster,
        bytes_per_sector,
    };

    // Try common GRUB paths on ESP
    // Path 1: /EFI/ubuntu/grub.cfg (Ubuntu)
    // Path 2: /EFI/debian/grub.cfg (Debian)
    // Path 3: /EFI/fedora/grub.cfg (Fedora)
    // Path 4: /boot/grub/grub.cfg (legacy)

    let paths: &[&[&[u8]]] = &[
        &[b"EFI", b"UBUNTU", b"GRUB.CFG"],
        &[b"EFI", b"DEBIAN", b"GRUB.CFG"],
        &[b"EFI", b"FEDORA", b"GRUB.CFG"],
        &[b"EFI", b"BOOT", b"GRUB.CFG"],
        &[b"BOOT", b"GRUB", b"GRUB.CFG"],
    ];

    let mut found_loader_stub = false;
    let mut distro_hint: Option<&[u8]> = None;

    for path in paths {
        serial::print("Trying path: /");
        for (i, component) in path.iter().enumerate() {
            if i > 0 { serial::print("/"); }
            for &c in *component {
                serial::print_char(c);
            }
        }
        serial::println("");

        if let Some(contents) = read_fat32_file(controller, target, lun, &fat32, root_cluster, path) {
            serial::println("Found GRUB config!");

            match parse_grub_config(&contents) {
                GrubParseResult::MenuEntry(buf, len) => {
                    return Some((buf, len));
                }
                GrubParseResult::LoaderStub => {
                    found_loader_stub = true;
                    // Remember which distro directory we found it in
                    if path.len() >= 2 {
                        distro_hint = Some(path[1]); // e.g., "UBUNTU", "DEBIAN"
                    }
                }
                GrubParseResult::NotFound => {}
            }
        }
    }

    if found_loader_stub {
        serial::println("ESP has loader stub - will read /boot/grub/grub.cfg from ext4");
        // Return the distro hint so caller knows to try ext4
        if let Some(distro) = distro_hint {
            serial::print("Distro hint from ESP: ");
            for &c in distro {
                serial::print_char(c);
            }
            serial::println("");
        }
    }

    serial::println("No menuentry found on ESP");
    None
}

/// FAT32 filesystem context
struct Fat32Context {
    partition_lba: u64,
    fat_start_lba: u64,
    data_start_lba: u64,
    sectors_per_cluster: u32,
    bytes_per_sector: u32,
}

/// Read a file from FAT32 filesystem
fn read_fat32_file(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    fat32: &Fat32Context,
    root_cluster: u32,
    path: &[&[u8]]
) -> Option<[u8; 512]> {
    let mut current_cluster = root_cluster;

    // Navigate through path components
    for (i, component) in path.iter().enumerate() {
        let is_last = i == path.len() - 1;

        // Find component in current directory
        let entry = find_fat32_entry(controller, target, lun, fat32, current_cluster, component)?;

        if is_last {
            // This is the file - read first sector of its data
            let file_cluster = ((entry.cluster_hi as u32) << 16) | (entry.cluster_lo as u32);
            let file_lba = cluster_to_lba(fat32, file_cluster);

            let mut contents = [0u8; 512];
            if !controller.read_sector(target, lun, file_lba as u32, &mut contents) {
                return None;
            }
            return Some(contents);
        } else {
            // This is a directory - descend into it
            if entry.attr & FAT_ATTR_DIRECTORY == 0 {
                return None; // Not a directory
            }
            current_cluster = ((entry.cluster_hi as u32) << 16) | (entry.cluster_lo as u32);
        }
    }

    None
}

/// Find a directory entry by name (8.3 format, case-insensitive)
/// Follows FAT cluster chain to search entire directory
fn find_fat32_entry(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    fat32: &Fat32Context,
    start_cluster: u32,
    name: &[u8]
) -> Option<Fat32DirEntry> {
    let entries_per_sector = fat32.bytes_per_sector / 32;
    let mut current_cluster = start_cluster;
    let mut chain_depth = 0;

    // Follow cluster chain (limit to 64 clusters to avoid infinite loops)
    while current_cluster >= 2 && current_cluster < 0x0FFFFFF8 && chain_depth < 64 {
        let cluster_lba = cluster_to_lba(fat32, current_cluster);

        // Read all sectors in this cluster
        for sector_offset in 0..fat32.sectors_per_cluster {
            let mut sector = [0u8; 512];
            if !controller.read_sector(target, lun, (cluster_lba + sector_offset as u64) as u32, &mut sector) {
                serial::print("FAT32: Failed to read dir sector at cluster ");
                serial::print_dec(current_cluster);
                serial::println("");
                // Try next cluster instead of failing completely
                break;
            }

            for entry_idx in 0..entries_per_sector {
                let offset = (entry_idx * 32) as usize;
                let entry = unsafe {
                    core::ptr::read_unaligned(sector.as_ptr().add(offset) as *const Fat32DirEntry)
                };

                // End of directory
                if entry.name[0] == 0x00 {
                    return None;
                }

                // Deleted entry or LFN entry
                if entry.name[0] == 0xE5 || entry.attr == FAT_ATTR_LFN {
                    continue;
                }

                // Compare name (8.3 format, case-insensitive)
                if fat32_name_match(&entry.name, name) {
                    serial::print("FAT32: Found '");
                    for &c in name {
                        serial::print_char(c);
                    }
                    serial::print("' in cluster ");
                    serial::print_dec(current_cluster);
                    serial::println("");
                    return Some(entry);
                }
            }
        }

        // Get next cluster from FAT
        current_cluster = get_next_cluster(controller, target, lun, fat32, current_cluster)?;
        chain_depth += 1;
    }

    None
}

/// Read FAT entry to get next cluster in chain
fn get_next_cluster(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    fat32: &Fat32Context,
    cluster: u32
) -> Option<u32> {
    // Each FAT32 entry is 4 bytes
    // Calculate which sector of the FAT contains this entry
    let fat_offset = cluster * 4;
    let fat_sector = fat32.fat_start_lba + (fat_offset / fat32.bytes_per_sector) as u64;
    let offset_in_sector = (fat_offset % fat32.bytes_per_sector) as usize;

    let mut sector = [0u8; 512];
    if !controller.read_sector(target, lun, fat_sector as u32, &mut sector) {
        return None;
    }

    // Read 4-byte FAT entry (little-endian)
    let next = u32::from_le_bytes([
        sector[offset_in_sector],
        sector[offset_in_sector + 1],
        sector[offset_in_sector + 2],
        sector[offset_in_sector + 3],
    ]) & 0x0FFFFFFF; // FAT32 uses only 28 bits

    Some(next)
}

/// Convert cluster number to LBA
fn cluster_to_lba(fat32: &Fat32Context, cluster: u32) -> u64 {
    fat32.data_start_lba + ((cluster - 2) as u64 * fat32.sectors_per_cluster as u64)
}

/// Match FAT32 8.3 name against search name (case-insensitive)
fn fat32_name_match(entry_name: &[u8; 11], search: &[u8]) -> bool {
    // Build 8.3 name from search (e.g., "GRUB.CFG" -> "GRUB    CFG")
    let mut name83 = [b' '; 11];
    let mut pos = 0;
    let mut in_ext = false;

    for &c in search {
        if c == b'.' {
            in_ext = true;
            pos = 8;
        } else {
            let uc = if c >= b'a' && c <= b'z' { c - 32 } else { c };
            if !in_ext && pos < 8 {
                name83[pos] = uc;
                pos += 1;
            } else if in_ext && pos < 11 {
                name83[pos] = uc;
                pos += 1;
            }
        }
    }

    // Compare (entry name is already uppercase and space-padded)
    for i in 0..11 {
        let entry_c = entry_name[i];
        let search_c = name83[i];
        // Case-insensitive compare
        let entry_uc = if entry_c >= b'a' && entry_c <= b'z' { entry_c - 32 } else { entry_c };
        if entry_uc != search_c {
            return false;
        }
    }

    true
}

/// Result of parsing GRUB config
enum GrubParseResult {
    /// Found menuentry with OS name
    MenuEntry([u8; 64], usize),
    /// Found loader stub (configfile directive) - need to read from root partition
    LoaderStub,
    /// Nothing useful found
    NotFound,
}

/// Parse GRUB config - either menuentry or detect loader stub
fn parse_grub_config(contents: &[u8; 512]) -> GrubParseResult {
    // Look for: menuentry 'Ubuntu' or menuentry "Ubuntu"
    let pattern1 = b"menuentry '";
    let pattern2 = b"menuentry \"";

    for pattern in [pattern1, pattern2] {
        for i in 0..contents.len().saturating_sub(pattern.len()) {
            if &contents[i..i + pattern.len()] == pattern {
                let start = i + pattern.len();
                let quote = if pattern == pattern1 { b'\'' } else { b'"' };

                // Find closing quote
                let mut end = start;
                while end < contents.len() && contents[end] != quote && contents[end] != 0 {
                    end += 1;
                }

                let name_len = (end - start).min(64);
                let mut name_buf = [0u8; 64];
                name_buf[..name_len].copy_from_slice(&contents[start..start + name_len]);

                serial::print("Found menuentry: ");
                for j in 0..name_len {
                    serial::print_char(name_buf[j]);
                }
                serial::println("");

                return GrubParseResult::MenuEntry(name_buf, name_len);
            }
        }
    }

    // Check if this is a loader stub (contains "configfile" or "search.fs_uuid")
    let stub_patterns = [b"configfile" as &[u8], b"search.fs_uuid"];
    for pattern in stub_patterns {
        for i in 0..contents.len().saturating_sub(pattern.len()) {
            if &contents[i..i + pattern.len()] == pattern {
                serial::println("Detected GRUB loader stub - need to read /boot/grub/grub.cfg");
                return GrubParseResult::LoaderStub;
            }
        }
    }

    GrubParseResult::NotFound
}

/// Detect OS from ext4 filesystem by reading /etc/os-release
fn detect_os_from_ext4(controller: &mut virtio::VirtioScsi, target: u8, lun: u8, partition_lba: u64) -> ([u8; 64], usize) {
    serial::println("Reading ext4 filesystem for OS detection...");

    // ext4 superblock is at offset 1024 (byte 1024-2047 of the partition)
    // For 512-byte sectors, that's sector 2 of the partition
    let superblock_lba = partition_lba + 2;

    let mut sb_sector = [0u8; 512];
    if !controller.read_sector(target, lun, superblock_lba as u32, &mut sb_sector) {
        serial::println("Failed to read ext4 superblock");
        return ([0; 64], 0);
    }

    let superblock = unsafe {
        core::ptr::read_unaligned(sb_sector.as_ptr() as *const Ext4Superblock)
    };

    // Verify ext4 magic
    if superblock.s_magic != EXT4_MAGIC {
        serial::print("Not ext4 (magic=0x");
        serial::print_hex32(superblock.s_magic as u32);
        serial::println(")");
        return ([0; 64], 0);
    }
    serial::println("ext4 filesystem confirmed");

    // Calculate block size
    let block_size = 1024u32 << superblock.s_log_block_size;
    serial::print("Block size: ");
    serial::print_dec(block_size);
    serial::println(" bytes");

    // Try to read /etc/os-release
    // First, find the root inode (inode 2)
    // Then navigate to /etc/os-release

    if let Some((buf, len)) = read_os_release(controller, target, lun, partition_lba, &superblock) {
        return (buf, len);
    }

    // Fallback: check volume label
    let mut name_buf = [0u8; 64];
    let mut name_len = 0usize;

    for (i, &c) in superblock.s_volume_name.iter().enumerate() {
        if c == 0 {
            break;
        }
        if i < 64 {
            name_buf[i] = c;
            name_len = i + 1;
        }
    }

    if name_len > 0 {
        serial::print("Volume label: ");
        for i in 0..name_len {
            serial::print_char(name_buf[i]);
        }
        serial::println("");
    }

    (name_buf, name_len)
}

/// Try to read OS info from ext4 - first /boot/grub/grub.cfg, then /etc/os-release
fn read_os_release(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64,
    superblock: &Ext4Superblock
) -> Option<([u8; 64], usize)> {
    let block_size = 1024u32 << superblock.s_log_block_size;
    let inode_size = superblock.s_inode_size as u32;

    // Read root inode (inode 2)
    // Inode table location is in the block group descriptor
    // Block group descriptor table starts at block 1 (or 2 for 1024-byte blocks)
    let bgdt_block = if block_size == 1024 { 2 } else { 1 };
    let bgdt_lba = partition_lba + (bgdt_block as u64 * block_size as u64 / 512);

    let mut bgdt_sector = [0u8; 512];
    if !controller.read_sector(target, lun, bgdt_lba as u32, &mut bgdt_sector) {
        serial::println("Failed to read block group descriptor");
        return None;
    }

    // Block group descriptor is 32 bytes (or 64 for 64-bit features)
    // We need inode table location (offset 8, 4 bytes)
    let inode_table_block = u32::from_le_bytes([bgdt_sector[8], bgdt_sector[9], bgdt_sector[10], bgdt_sector[11]]);

    serial::print("Inode table at block ");
    serial::print_dec(inode_table_block);
    serial::println("");

    // Root inode is inode 2 (index 1 in 0-based)
    let root_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, 2)?;

    // Debug: show root inode info
    serial::print("Root inode: mode=0x");
    serial::print_hex32(root_inode.i_mode as u32);
    serial::print(" flags=0x");
    serial::print_hex32(root_inode.i_flags);
    serial::print(" blocks=");
    serial::print_dec(root_inode.i_blocks_lo);
    serial::println("");

    // Copy i_block to avoid packed struct alignment issues
    let mut root_i_block_bytes = [0u8; 60];
    unsafe {
        let inode_ptr = &root_inode as *const Ext4Inode as *const u8;
        // i_block is at offset 40 (0x28) in the inode struct
        core::ptr::copy_nonoverlapping(
            inode_ptr.add(40),
            root_i_block_bytes.as_mut_ptr(),
            60
        );
    }
    serial::print("Root i_block[0..4]: ");
    for i in 0..4 {
        let val = u32::from_le_bytes([
            root_i_block_bytes[i*4], root_i_block_bytes[i*4+1],
            root_i_block_bytes[i*4+2], root_i_block_bytes[i*4+3]
        ]);
        serial::print_hex32(val);
        serial::print(" ");
    }
    serial::println("");

    // Try /boot/grub/grub.cfg first (for GRUB menuentry)
    serial::println("Trying /boot/grub/grub.cfg...");
    if let Some(result) = read_grub_cfg_from_ext4(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, &root_inode) {
        return Some(result);
    }

    // Fall back to /etc/os-release
    serial::println("Trying /etc/os-release...");
    read_etc_os_release(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, &root_inode)
}

/// Read /boot/grub/grub.cfg from ext4
fn read_grub_cfg_from_ext4(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    root_inode: &Ext4Inode
) -> Option<([u8; 64], usize)> {
    // Find /boot directory
    let boot_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, root_inode, b"boot")?;
    serial::print("Found /boot at inode ");
    serial::print_dec(boot_inode_num);
    serial::println("");

    let boot_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, boot_inode_num)?;

    // Find /boot/grub directory
    let grub_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, &boot_inode, b"grub")?;
    serial::print("Found /boot/grub at inode ");
    serial::print_dec(grub_inode_num);
    serial::println("");

    let grub_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, grub_inode_num)?;

    // Find grub.cfg
    let cfg_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, &grub_inode, b"grub.cfg")?;
    serial::print("Found /boot/grub/grub.cfg at inode ");
    serial::print_dec(cfg_inode_num);
    serial::println("");

    let cfg_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, cfg_inode_num)?;

    // Read file contents
    let contents = read_file_contents(controller, target, lun, partition_lba, block_size, &cfg_inode)?;

    // Parse menuentry from grub.cfg
    match parse_grub_config(&contents) {
        GrubParseResult::MenuEntry(buf, len) => Some((buf, len)),
        _ => None,
    }
}

/// Read /etc/os-release from ext4
fn read_etc_os_release(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    root_inode: &Ext4Inode
) -> Option<([u8; 64], usize)> {
    // Find /etc directory in root
    let etc_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, root_inode, b"etc")?;

    serial::print("Found /etc at inode ");
    serial::print_dec(etc_inode_num);
    serial::println("");

    // Read /etc inode
    let etc_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, etc_inode_num)?;

    // Find os-release in /etc
    let os_release_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, &etc_inode, b"os-release")?;

    serial::print("Found /etc/os-release at inode ");
    serial::print_dec(os_release_inode_num);
    serial::println("");

    // Read os-release inode
    let os_release_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, os_release_inode_num)?;

    // Check if it's a symlink - if so, follow to /usr/lib/os-release
    if (os_release_inode.i_mode & 0xF000) == 0xA000 {
        serial::println("os-release is symlink, trying /usr/lib/os-release");
        return read_usr_lib_os_release(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, root_inode);
    }

    // Read file contents
    let contents = read_file_contents(controller, target, lun, partition_lba, block_size, &os_release_inode)?;

    // Parse PRETTY_NAME from os-release
    parse_pretty_name(&contents)
}

/// Read /usr/lib/os-release from ext4 (symlink target)
fn read_usr_lib_os_release(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    root_inode: &Ext4Inode
) -> Option<([u8; 64], usize)> {
    // Find /usr directory
    let usr_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, root_inode, b"usr")?;
    serial::print("Found /usr at inode ");
    serial::print_dec(usr_inode_num);
    serial::println("");

    let usr_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, usr_inode_num)?;

    // Find /usr/lib directory
    let lib_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, &usr_inode, b"lib")?;
    serial::print("Found /usr/lib at inode ");
    serial::print_dec(lib_inode_num);
    serial::println("");

    let lib_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, lib_inode_num)?;

    // Find os-release in /usr/lib
    let os_release_inode_num = find_dir_entry(controller, target, lun, partition_lba, block_size, &lib_inode, b"os-release")?;
    serial::print("Found /usr/lib/os-release at inode ");
    serial::print_dec(os_release_inode_num);
    serial::println("");

    let os_release_inode = read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, os_release_inode_num)?;

    // Read file contents
    let contents = read_file_contents(controller, target, lun, partition_lba, block_size, &os_release_inode)?;

    // Parse PRETTY_NAME from os-release
    parse_pretty_name(&contents)
}

/// Read an inode from the filesystem
fn read_inode(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    inode_num: u32
) -> Option<Ext4Inode> {
    // Inode numbers are 1-based
    let inode_index = inode_num - 1;
    let inode_offset = inode_index * inode_size;
    let inode_block = inode_table_block + (inode_offset / block_size);
    let offset_in_block = inode_offset % block_size;

    let inode_lba = partition_lba + (inode_block as u64 * block_size as u64 / 512);
    let sector_offset = offset_in_block / 512;
    let offset_in_sector = offset_in_block % 512;

    serial::print("read_inode(");
    serial::print_dec(inode_num);
    serial::print("): table_blk=");
    serial::print_dec(inode_table_block);
    serial::print(" inode_blk=");
    serial::print_dec(inode_block);
    serial::print(" LBA=");
    serial::print_dec((inode_lba + sector_offset as u64) as u32);
    serial::println("");

    let mut sector = [0u8; 512];
    if !controller.read_sector(target, lun, (inode_lba + sector_offset as u64) as u32, &mut sector) {
        serial::println("  -> read_inode FAILED");
        return None;
    }

    let inode = unsafe {
        core::ptr::read_unaligned(sector.as_ptr().add(offset_in_sector as usize) as *const Ext4Inode)
    };

    Some(inode)
}

/// Get the first data block from an inode (handles both extents and direct blocks)
fn get_first_data_block(dir_inode: &Ext4Inode) -> Option<u64> {
    // Copy i_block to avoid packed struct alignment issues
    let mut i_block_bytes = [0u8; 60];
    unsafe {
        let inode_ptr = dir_inode as *const Ext4Inode as *const u8;
        // i_block is at offset 40 (0x28) in the inode struct
        core::ptr::copy_nonoverlapping(
            inode_ptr.add(40),
            i_block_bytes.as_mut_ptr(),
            60
        );
    }

    let mode = dir_inode.i_mode;
    let flags = dir_inode.i_flags;
    let size = dir_inode.i_size_lo;

    serial::print("  inode mode=0x");
    serial::print_hex32(mode as u32);
    serial::print(" flags=0x");
    serial::print_hex32(flags);
    serial::print(" size=");
    serial::print_dec(size);
    serial::println("");

    // Check if this is a symlink (mode & 0xF000 == 0xA000)
    if (mode & 0xF000) == 0xA000 {
        serial::println("  -> This is a SYMLINK");
        // For small symlinks, target is stored inline in i_block
        serial::print("  Symlink target: ");
        for i in 0..size.min(60) as usize {
            if i_block_bytes[i] == 0 { break; }
            serial::print_char(i_block_bytes[i]);
        }
        serial::println("");
        return None; // Can't follow symlinks yet
    }

    // Check if extents are used (i_flags & EXT4_EXTENTS_FL)
    if flags & EXT4_EXTENTS_FL != 0 {
        // Parse extent header from i_block

        let eh = unsafe {
            core::ptr::read_unaligned(i_block_bytes.as_ptr() as *const Ext4ExtentHeader)
        };

        serial::print("Extent header: magic=0x");
        serial::print_hex32(eh.eh_magic as u32);
        serial::print(" entries=");
        serial::print_dec(eh.eh_entries as u32);
        serial::print(" depth=");
        serial::print_dec(eh.eh_depth as u32);
        serial::println("");

        if eh.eh_magic != EXT4_EXTENT_MAGIC {
            serial::println("Bad extent magic!");
            return None;
        }

        if eh.eh_entries == 0 {
            serial::println("No extent entries!");
            return None;
        }

        if eh.eh_depth == 0 {
            // Leaf node - extent directly follows header
            let extent = unsafe {
                core::ptr::read_unaligned(i_block_bytes.as_ptr().add(12) as *const Ext4Extent)
            };
            let block = ((extent.ee_start_hi as u64) << 32) | (extent.ee_start_lo as u64);
            serial::print("Extent: block=");
            serial::print_dec(block as u32);
            serial::print(" len=");
            serial::print_dec(extent.ee_len as u32);
            serial::println("");
            return Some(block);
        } else {
            // Internal node - need to follow index
            serial::println("Extent tree depth > 0 not supported yet");
            return None;
        }
    } else {
        // Direct block pointers - read from i_block_bytes
        let block_num = u32::from_le_bytes([i_block_bytes[0], i_block_bytes[1], i_block_bytes[2], i_block_bytes[3]]);
        serial::print("Direct block: ");
        serial::print_dec(block_num);
        serial::println("");
        if block_num == 0 {
            return None;
        }
        return Some(block_num as u64);
    }
}

/// Find a directory entry by name
fn find_dir_entry(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    dir_inode: &Ext4Inode,
    name: &[u8]
) -> Option<u32> {
    // Get the first data block (handling extents)
    let block_num = get_first_data_block(dir_inode)?;

    let block_lba = partition_lba + (block_num * block_size as u64 / 512);
    serial::print("Reading dir block at LBA ");
    serial::print_dec(block_lba as u32);
    serial::println("");

    // Read directory block (may span multiple sectors)
    let sectors_per_block = block_size / 512;
    let mut block_data = [0u8; 4096]; // Max 4K block

    for i in 0..sectors_per_block.min(8) {
        let mut sector = [0u8; 512];
        if !controller.read_sector(target, lun, (block_lba + i as u64) as u32, &mut sector) {
            return None;
        }
        block_data[i as usize * 512..(i as usize + 1) * 512].copy_from_slice(&sector);
    }

    // Debug: show first 32 bytes of directory block
    serial::print("Dir block first 32 bytes: ");
    for i in 0..32 {
        serial::print_hex32(block_data[i] as u32);
        serial::print(" ");
    }
    serial::println("");

    // Parse directory entries
    let mut offset = 0usize;
    while offset < block_size as usize {
        let entry = unsafe {
            core::ptr::read_unaligned(block_data.as_ptr().add(offset) as *const Ext4DirEntry)
        };

        if entry.inode == 0 || entry.rec_len == 0 {
            break;
        }

        let entry_name = &block_data[offset + 8..offset + 8 + entry.name_len as usize];

        // Debug: show entry
        serial::print("  Entry: inode=");
        serial::print_dec(entry.inode);
        serial::print(" name=");
        for &b in entry_name {
            serial::print_char(b);
        }
        serial::println("");

        if entry_name == name {
            return Some(entry.inode);
        }

        offset += entry.rec_len as usize;
    }

    None
}

/// Read file contents (first block only, up to 512 bytes)
fn read_file_contents(
    controller: &mut virtio::VirtioScsi,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode: &Ext4Inode
) -> Option<[u8; 512]> {
    // Get the first data block (handling extents)
    let block_num = get_first_data_block(inode)?;

    let block_lba = partition_lba + (block_num * block_size as u64 / 512);

    let mut sector = [0u8; 512];
    if !controller.read_sector(target, lun, block_lba as u32, &mut sector) {
        return None;
    }

    Some(sector)
}

/// Parse PRETTY_NAME from os-release contents
fn parse_pretty_name(contents: &[u8; 512]) -> Option<([u8; 64], usize)> {
    // Look for PRETTY_NAME="..."
    let pattern = b"PRETTY_NAME=\"";

    let mut start = None;
    for i in 0..contents.len() - pattern.len() {
        if &contents[i..i + pattern.len()] == pattern {
            start = Some(i + pattern.len());
            break;
        }
    }

    let start = start?;

    // Find closing quote
    let mut end = start;
    while end < contents.len() && contents[end] != b'"' && contents[end] != 0 {
        end += 1;
    }

    let name_len = (end - start).min(64);
    let mut name_buf = [0u8; 64];
    name_buf[..name_len].copy_from_slice(&contents[start..start + name_len]);

    serial::print("Detected OS: ");
    for i in 0..name_len {
        serial::print_char(name_buf[i]);
    }
    serial::println("");

    Some((name_buf, name_len))
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
