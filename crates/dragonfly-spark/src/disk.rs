//! Disk scanning and OS detection
//!
//! Supports ATA PIO (legacy IDE), AHCI (SATA), VirtIO SCSI, and VirtIO Block
//! Can read GPT partition tables and ext4 filesystems to detect OS

use crate::bios::{inb, outb, insw, io_wait};
use crate::serial;
use crate::ahci;
use crate::pvscsi;
use crate::virtio;
use crate::virtio_blk;

/// GPT header signature "EFI PART"
const GPT_SIGNATURE: u64 = 0x5452415020494645;

/// Linux filesystem partition type GUID (generic)
/// 0FC63DAF-8483-4772-8E79-3D69D8477DE4
const LINUX_FS_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4
];

/// Linux root (x86-64) partition type GUID — used by Debian 13+ discoverable partitions
/// 4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
const LINUX_ROOT_X86_64_GUID: [u8; 16] = [
    0xE3, 0xBC, 0x68, 0x4F, 0xCD, 0xE8, 0xB1, 0x4D,
    0x96, 0xE7, 0xFB, 0xCA, 0xF9, 0x84, 0xB7, 0x09
];

/// Linux root (x86) partition type GUID
/// 44479540-F297-41B2-9AF7-D131D5F0458A
const LINUX_ROOT_X86_GUID: [u8; 16] = [
    0x40, 0x95, 0x47, 0x44, 0x97, 0xF2, 0xB2, 0x41,
    0x9A, 0xF7, 0xD1, 0x31, 0xD5, 0xF0, 0x45, 0x8A
];

/// Linux root (ARM64/AArch64) partition type GUID
/// B921B045-1DF0-41C3-AF44-4C6F280D3FAE
const LINUX_ROOT_ARM64_GUID: [u8; 16] = [
    0x45, 0xB0, 0x21, 0xB9, 0xF0, 0x1D, 0xC3, 0x41,
    0xAF, 0x44, 0x4C, 0x6F, 0x28, 0x0D, 0x3F, 0xAE
];

/// EFI System Partition GUID
/// C12A7328-F81F-11D2-BA4B-00A0C93EC93B
const EFI_SYSTEM_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B
];

/// Check if a GUID is any Linux partition type (generic FS, root x86/x86-64/arm64)
fn is_linux_partition_guid(guid: &[u8; 16]) -> bool {
    *guid == LINUX_FS_GUID
        || *guid == LINUX_ROOT_X86_64_GUID
        || *guid == LINUX_ROOT_X86_GUID
        || *guid == LINUX_ROOT_ARM64_GUID
}

/// ext4 superblock magic number
const EXT4_MAGIC: u16 = 0xEF53;

/// ext4 feature flag: 64-bit mode (descriptor size > 32 bytes)
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;

/// Cached ext4 filesystem context for correct multi-block-group inode lookup.
/// Populated once in detect_os_from_ext4, used by read_inode.
struct Ext4FsContext {
    partition_lba: u64,
    block_size: u32,
    inode_size: u32,
    inodes_per_group: u32,
    desc_size: u32,   // 32 or 64 bytes per BGDT entry
    valid: bool,
}

static mut EXT4_CTX: Ext4FsContext = Ext4FsContext {
    partition_lba: 0,
    block_size: 0,
    inode_size: 0,
    inodes_per_group: 0,
    desc_size: 32,
    valid: false,
};

/// Static buffer for OS name (avoid stack allocation issues in 64-bit mode)
static mut OS_NAME_BUF: [u8; 64] = [0u8; 64];
static mut OS_NAME_LEN: usize = 0;

/// Static buffer for detected hostname from /etc/hostname or /etc/hosts
static mut HOSTNAME_BUF: [u8; 256] = [0u8; 256];
static mut HOSTNAME_LEN: usize = 0;

/// Get detected hostname (for checkin reporting)
pub fn detected_hostname() -> Option<&'static str> {
    unsafe {
        if HOSTNAME_LEN > 0 {
            core::str::from_utf8(&HOSTNAME_BUF[..HOSTNAME_LEN]).ok()
        } else {
            None
        }
    }
}

/// Detected disk information for reporting (independent of OS detection)
pub struct DetectedDisk {
    pub disk_type: DiskType,
    pub size_bytes: u64,
    pub model: [u8; 40],
    pub model_len: usize,
}

const MAX_DETECTED_DISKS: usize = 8;
static mut DETECTED_DISKS: [DetectedDisk; MAX_DETECTED_DISKS] = {
    const EMPTY: DetectedDisk = DetectedDisk {
        disk_type: DiskType::AtaPio,
        size_bytes: 0,
        model: [0u8; 40],
        model_len: 0,
    };
    [EMPTY; MAX_DETECTED_DISKS]
};
static mut DETECTED_DISK_COUNT: usize = 0;

/// Get detected disks (for checkin reporting)
pub fn detected_disks() -> &'static [DetectedDisk] {
    unsafe { &DETECTED_DISKS[..DETECTED_DISK_COUNT] }
}

/// Record a detected disk
fn record_disk(disk_type: DiskType, size_bytes: u64, model: &[u8], model_len: usize) {
    unsafe {
        if DETECTED_DISK_COUNT >= MAX_DETECTED_DISKS {
            return;
        }
        let d = &mut DETECTED_DISKS[DETECTED_DISK_COUNT];
        d.disk_type = disk_type;
        d.size_bytes = size_bytes;
        let copy_len = model_len.min(40);
        d.model[..copy_len].copy_from_slice(&model[..copy_len]);
        d.model_len = copy_len;
        DETECTED_DISK_COUNT += 1;

        serial::print("Disk detected: ");
        serial::print_dec((size_bytes / (1024 * 1024 * 1024)) as u32);
        serial::print(" GiB");
        if copy_len > 0 {
            serial::print(" model=");
            if let Ok(s) = core::str::from_utf8(&model[..copy_len]) {
                serial::print(s.trim());
            }
        }
        serial::println("");
    }
}

/// Static storage for OsInfo to avoid ~600 byte struct returns in 64-bit mode
static mut OS_INFO: OsInfo = OsInfo {
    name: "",
    disk_type: DiskType::AtaPio,
    partition: 0,
    bootable: false,
    mbr: [0u8; 512],
    os_name_buf: [0u8; 64],
    os_name_len: 0,
};
static mut OS_INFO_VALID: bool = false;

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
    /// VirtIO Block (VMs)
    VirtioBlk,
    /// VMware PVSCSI (paravirtual SCSI)
    PvScsi { target: u8, lun: u8 },
    /// BIOS INT 13h (direct, preserves BIOS state)
    BiosDirect { drive: u8 },
}

/// Unified disk reader - wraps different controller types so GPT/ext4 code
/// doesn't need to be duplicated per controller type.
pub enum DiskReader {
    VirtioScsi { ctrl: virtio::VirtioScsi, target: u8, lun: u8 },
    VirtioBlk { ctrl: virtio_blk::VirtioBlk },
    AtaPio { drive: u8 },
    Ahci { ctrl: ahci::AhciController, port: u8 },
    PvScsi { ctrl: pvscsi::PvScsi, target: u8, lun: u8 },
}

impl DiskReader {
    fn read_sector(&mut self, lba: u32, buffer: &mut [u8; 512]) -> bool {
        match self {
            DiskReader::VirtioScsi { ctrl, target, lun } => ctrl.read_sector(*target, *lun, lba, buffer),
            DiskReader::VirtioBlk { ctrl } => ctrl.read_sector(lba, buffer),
            DiskReader::AtaPio { drive } => read_sector_ata(*drive, lba, buffer),
            DiskReader::Ahci { ctrl, port } => ctrl.read_sector(*port, lba as u64, buffer),
            DiskReader::PvScsi { ctrl, target, lun } => ctrl.read_sector(*target, *lun, lba, buffer),
        }
    }

    fn disk_type(&self) -> DiskType {
        match self {
            DiskReader::VirtioScsi { target, lun, .. } => DiskType::VirtioScsi { target: *target, lun: *lun },
            DiskReader::VirtioBlk { .. } => DiskType::VirtioBlk,
            DiskReader::AtaPio { .. } => DiskType::AtaPio,
            DiskReader::Ahci { port, .. } => DiskType::Ahci { port: *port },
            DiskReader::PvScsi { target, lun, .. } => DiskType::PvScsi { target: *target, lun: *lun },
        }
    }
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
/// Returns a reference to static storage to avoid ~600 byte struct returns
pub fn scan_for_os() -> Option<&'static OsInfo> {
    serial::println("scan_for_os() starting");

    // Try ATA PIO first (legacy IDE)
    if scan_ata_pio_into_static() {
        serial::println("DBG: scan_for_os returning ATA PIO result");
        return unsafe { Some(&*core::ptr::addr_of!(OS_INFO)) };
    }

    // Try AHCI (SATA)
    if scan_ahci_into_static() {
        serial::println("DBG: scan_for_os returning AHCI result");
        return unsafe { Some(&*core::ptr::addr_of!(OS_INFO)) };
    }

    // Try VMware PVSCSI (paravirtual SCSI)
    if scan_pvscsi_into_static() {
        serial::println("DBG: scan_for_os returning PVSCSI result");
        return unsafe { Some(&*core::ptr::addr_of!(OS_INFO)) };
    }

    // Try VirtIO SCSI (VMs)
    if scan_virtio_scsi_into_static() {
        serial::println("DBG: scan_for_os returning VirtIO SCSI result");
        return unsafe { Some(&*core::ptr::addr_of!(OS_INFO)) };
    }

    // Try VirtIO Block (VMs - common in Proxmox)
    if scan_virtio_blk_into_static() {
        serial::println("DBG: scan_for_os returning VirtIO Block result");
        return unsafe { Some(&*core::ptr::addr_of!(OS_INFO)) };
    }

    serial::println("No bootable drives found");
    None
}

/// Scan VirtIO SCSI and write directly to static storage (avoids struct return)
fn scan_virtio_scsi_into_static() -> bool {
    serial::println("Trying VirtIO SCSI...");

    let init_result = virtio::init();
    if init_result.is_none() {
        return false;
    }
    let (controller, target, lun) = init_result.unwrap();

    // Record disk for checkin reporting (size will be updated from GPT if available)
    record_disk(DiskType::VirtioScsi { target, lun }, 0, b"VirtIO SCSI Disk", 16);

    let mut reader = DiskReader::VirtioScsi { ctrl: controller, target, lun };

    serial::print("VirtIO SCSI: Reading MBR from target ");
    serial::print_dec(target as u32);
    serial::println("");

    // Read MBR directly into static storage
    unsafe {
        if !reader.read_sector(0, &mut (*core::ptr::addr_of_mut!(OS_INFO)).mbr) {
            serial::println("VirtIO SCSI: MBR read failed");
            return false;
        }
    }
    serial::println("VirtIO SCSI: MBR read OK");

    analyze_mbr_into_static(&mut reader)
}

/// Scan VirtIO Block and write directly to static storage (avoids struct return)
fn scan_virtio_blk_into_static() -> bool {
    serial::println("Trying VirtIO Block...");

    let init_result = virtio_blk::init();
    if init_result.is_none() {
        return false;
    }
    let controller = init_result.unwrap();

    // Record disk for checkin reporting
    let size_bytes = controller.capacity_sectors * 512;
    record_disk(DiskType::VirtioBlk, size_bytes, b"VirtIO Block Device", 19);

    let mut reader = DiskReader::VirtioBlk { ctrl: controller };

    serial::println("VirtIO Block: Reading MBR");

    // Read MBR directly into static storage
    unsafe {
        if !reader.read_sector(0, &mut (*core::ptr::addr_of_mut!(OS_INFO)).mbr) {
            serial::println("VirtIO Block: MBR read failed");
            return false;
        }
    }
    serial::println("VirtIO Block: MBR read OK");

    analyze_mbr_into_static(&mut reader)
}

/// Scan ATA PIO and write directly to static storage
fn scan_ata_pio_into_static() -> bool {
    serial::println("Trying ATA PIO...");

    // Check if drive exists (also records disk info from IDENTIFY)
    if !drive_exists(0) {
        serial::println("ATA PIO: No drive found");
        return false;
    }
    serial::println("ATA PIO: Drive found");

    let mut reader = DiskReader::AtaPio { drive: 0 };

    // Read MBR directly into static storage
    unsafe {
        if !reader.read_sector(0, &mut (*core::ptr::addr_of_mut!(OS_INFO)).mbr) {
            serial::println("ATA PIO: MBR read failed");
            return false;
        }
    }

    analyze_mbr_into_static(&mut reader)
}

/// Scan VMware PVSCSI and write directly to static storage
fn scan_pvscsi_into_static() -> bool {
    serial::println("Trying PVSCSI...");

    let init_result = pvscsi::init();
    if init_result.is_none() {
        return false;
    }
    let (controller, target, lun) = init_result.unwrap();

    // Record disk for checkin reporting
    record_disk(DiskType::PvScsi { target, lun }, 0, b"VMware PVSCSI Disk", 18);

    let mut reader = DiskReader::PvScsi { ctrl: controller, target, lun };

    serial::print("PVSCSI: Reading MBR from target ");
    serial::print_dec(target as u32);
    serial::println("");

    // Read MBR directly into static storage
    unsafe {
        if !reader.read_sector(0, &mut (*core::ptr::addr_of_mut!(OS_INFO)).mbr) {
            serial::println("PVSCSI: MBR read failed");
            return false;
        }
    }
    serial::println("PVSCSI: MBR read OK");

    analyze_mbr_into_static(&mut reader)
}

/// Scan AHCI and write directly to static storage
fn scan_ahci_into_static() -> bool {
    serial::println("Trying AHCI...");

    let init_result = ahci::init();
    if init_result.is_none() {
        return false;
    }
    let (controller, drive) = init_result.unwrap();

    if drive.is_atapi {
        serial::println("AHCI: Found ATAPI (CD/DVD), skipping");
        return false;
    }

    // Record disk for checkin reporting
    record_disk(DiskType::Ahci { port: drive.port }, 0, b"AHCI/SATA Disk", 14);

    let port = drive.port;
    let mut reader = DiskReader::Ahci { ctrl: controller, port };

    serial::print("AHCI: Reading MBR from port ");
    serial::print_dec(port as u32);
    serial::println("");

    // Read MBR directly into static storage
    unsafe {
        if !reader.read_sector(0, &mut (*core::ptr::addr_of_mut!(OS_INFO)).mbr) {
            serial::println("AHCI: MBR read failed");
            return false;
        }
    }
    serial::println("AHCI: MBR read OK");

    analyze_mbr_into_static(&mut reader)
}

/// Common MBR analysis: check boot signature, detect GPT, route to OS detection.
/// Called after MBR has been read into OS_INFO.mbr.
/// Returns true if a disk with valid MBR/GPT was found (even without OS).
fn analyze_mbr_into_static(reader: &mut DiskReader) -> bool {
    // Check MBR boot signature (0xAA55) - required for BOTH MBR and GPT disks
    let has_boot_sig = unsafe {
        let mbr = &(*core::ptr::addr_of!(OS_INFO)).mbr;
        let sig = u16::from_le_bytes([mbr[510], mbr[511]]);
        if sig != MBR_SIGNATURE {
            serial::print("No MBR boot signature (0x");
            serial::print_hex32(sig as u32);
            serial::println(") - blank or unformatted disk");
        }
        sig == MBR_SIGNATURE
    };

    if !has_boot_sig {
        // Disk exists but no valid MBR - report as unformatted
        unsafe {
            let os_info = &mut *core::ptr::addr_of_mut!(OS_INFO);
            os_info.name = "No OS";
            os_info.disk_type = reader.disk_type();
            os_info.partition = 0;
            os_info.bootable = false;
            os_info.os_name_buf = [0; 64];
            os_info.os_name_len = 0;
        }
        return true; // Disk detected, just no OS
    }

    // Check for GPT protective MBR
    let first_entry = unsafe {
        let mbr_ptr = core::ptr::addr_of!(OS_INFO).cast::<u8>().add(core::mem::offset_of!(OsInfo, mbr));
        core::ptr::read_unaligned(mbr_ptr.add(446) as *const PartitionEntry)
    };
    if first_entry.partition_type == 0xEE {
        serial::println("GPT detected - performing OS detection");
        return detect_os_from_gpt_into_static(reader, 0, 0);
    }

    // Legacy MBR
    parse_mbr_into_static(reader.disk_type())
}

/// Parse MBR and write to static storage
fn parse_mbr_into_static(disk_type: DiskType) -> bool {
    unsafe {
        let mbr = &(*core::ptr::addr_of!(OS_INFO)).mbr;

        // Verify MBR signature
        let signature = u16::from_le_bytes([mbr[510], mbr[511]]);
        if signature != MBR_SIGNATURE {
            serial::print("Invalid MBR signature: 0x");
            serial::print_hex32(signature as u32);
            serial::println("");
            return false;
        }

        // Find bootable partition
        for i in 0..4 {
            let offset = 446 + (i * 16);
            let entry = core::ptr::read_unaligned(mbr.as_ptr().add(offset) as *const PartitionEntry);

            if entry.status == 0x80 && entry.partition_type != 0 {
                serial::print("Found bootable partition ");
                serial::print_dec(i as u32 + 1);
                serial::print(" type 0x");
                serial::print_hex32(entry.partition_type as u32);
                serial::println("");

                let os_info = &mut *core::ptr::addr_of_mut!(OS_INFO);
                os_info.name = match entry.partition_type {
                    0x07 => "Windows/NTFS",
                    0x0B | 0x0C => "Windows/FAT32",
                    0x83 => "Linux",
                    0xEE => "GPT Protective",
                    _ => "Unknown OS",
                };
                os_info.disk_type = disk_type;
                os_info.partition = i as u8 + 1;
                os_info.bootable = true;
                // mbr is already in place
                os_info.os_name_buf = [0; 64];
                os_info.os_name_len = 0;
                return true;
            }
        }

        // No bootable partition, but valid MBR
        let os_info = &mut *core::ptr::addr_of_mut!(OS_INFO);
        os_info.name = "Unknown";
        os_info.disk_type = disk_type;
        os_info.partition = 0;
        os_info.bootable = false;
        os_info.os_name_buf = [0; 64];
        os_info.os_name_len = 0;
        true
    }
}

/// Detect OS from GPT and write directly to static storage
fn detect_os_from_gpt_into_static(controller: &mut DiskReader, _target: u8, _lun: u8) -> bool {
    serial::println("Parsing GPT for OS detection...");
    let disk_type = controller.disk_type();

    // Read GPT header at LBA 1
    let mut gpt_sector = [0u8; 512];
    if !controller.read_sector(1, &mut gpt_sector) {
        serial::println("Failed to read GPT header - returning GPT System fallback");
        unsafe {
            let os_info = &mut *core::ptr::addr_of_mut!(OS_INFO);
            os_info.name = "GPT System";
            os_info.disk_type = disk_type;
            os_info.partition = 1;
            os_info.bootable = true;
            // mbr already in place from caller
            os_info.os_name_buf = [0; 64];
            os_info.os_name_len = 0;
        }
        return true;
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
        unsafe {
            let os_info = &mut *core::ptr::addr_of_mut!(OS_INFO);
            os_info.name = "GPT System";
            os_info.disk_type = disk_type;
            os_info.partition = 1;
            os_info.bootable = true;
            os_info.os_name_buf = [0; 64];
            os_info.os_name_len = 0;
        }
        return true;
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
    // Collect multiple Linux partitions (Debian may have separate /boot + root)
    let mut esp_partition_lba: u64 = 0;
    const MAX_LINUX_PARTS: usize = 4;
    let mut linux_parts: [(u64, u8); MAX_LINUX_PARTS] = [(0, 0); MAX_LINUX_PARTS]; // (lba, partition_num)
    let mut linux_part_count: usize = 0;

    // Cache the last read sector
    let mut cached_sector_idx: i32 = -1;
    let mut cached_sector = [0u8; 512];

    let scan_limit = num_entries.min(20);
    serial::print("Scanning first ");
    serial::print_dec(scan_limit as u32);
    serial::println(" partition entries...");

    for entry_idx in 0..scan_limit {
        let sector_idx = entry_idx / entries_per_sector;
        let offset_in_sector = (entry_idx % entries_per_sector) * entry_size;

        if sector_idx as i32 != cached_sector_idx {
            let entry_lba = gpt_header.partition_entry_lba + sector_idx as u64;
            if !controller.read_sector(entry_lba as u32, &mut cached_sector) {
                continue;
            }
            cached_sector_idx = sector_idx as i32;
        }

        let entry = unsafe {
            core::ptr::read_unaligned(cached_sector.as_ptr().add(offset_in_sector) as *const GptPartitionEntry)
        };

        if entry.type_guid == [0u8; 16] {
            continue;
        }

        serial::print("Entry ");
        serial::print_dec(entry_idx as u32);
        serial::print(" GUID: ");
        for i in 0..4 {
            serial::print_hex32(entry.type_guid[i] as u32);
        }
        serial::println("...");

        if entry.type_guid == EFI_SYSTEM_GUID && esp_partition_lba == 0 {
            serial::print("  -> EFI System Partition at LBA ");
            serial::print_dec(entry.starting_lba as u32);
            serial::println("");
            esp_partition_lba = entry.starting_lba;
        }

        if is_linux_partition_guid(&entry.type_guid) && linux_part_count < MAX_LINUX_PARTS {
            serial::print("  -> Linux partition ");
            serial::print_dec(linux_part_count as u32);
            serial::print(" at LBA ");
            serial::print_dec(entry.starting_lba as u32);
            serial::println("");
            linux_parts[linux_part_count] = (entry.starting_lba, entry_idx as u8 + 1);
            linux_part_count += 1;
        }

        if esp_partition_lba != 0 && linux_part_count >= 2 {
            serial::println("Found ESP and multiple Linux partitions");
            break;
        }
    }

    serial::print("Found ");
    serial::print_dec(linux_part_count as u32);
    serial::println(" Linux partition(s)");

    // Zero OS_NAME_BUF for reuse
    unsafe {
        for i in 0..64 {
            core::ptr::write_volatile(&mut OS_NAME_BUF[i], 0);
        }
        OS_NAME_LEN = 0;
    }

    // Try FAT32 ESP first
    if esp_partition_lba != 0 {
        serial::println("Trying ESP (FAT32) for OS detection...");
        if let Some((buf, len)) = detect_os_from_esp(controller, _target, _lun, esp_partition_lba) {
            unsafe {
                OS_NAME_BUF = buf;
                OS_NAME_LEN = len;
            }
        }
    }

    // Fall back to ext4 — try each Linux partition until we detect an OS name
    // This handles Debian's separate /boot + root layout (first Linux partition
    // is /boot which has no /etc/os-release, second is root which does)
    if unsafe { OS_NAME_LEN } == 0 {
        for i in 0..linux_part_count {
            let (part_lba, _part_num) = linux_parts[i];
            serial::print("Trying ext4 on Linux partition ");
            serial::print_dec(i as u32);
            serial::print(" at LBA ");
            serial::print_dec(part_lba as u32);
            serial::println("...");
            if detect_os_from_ext4(controller, _target, _lun, part_lba) {
                serial::println("OS detected from ext4!");
                break;
            }
        }
    }

    // Use the last partition with a Linux GUID for the partition number (usually root)
    let linux_partition_lba = if linux_part_count > 0 { linux_parts[0].0 } else { 0 };
    let linux_partition_num = if linux_part_count > 0 { linux_parts[linux_part_count - 1].1 } else { 0 };

    serial::println("DBG: writing final OsInfo to static");
    serial::print("DBG: OS_NAME_LEN=");
    serial::print_dec(unsafe { OS_NAME_LEN } as u32);
    serial::println("");

    // Write to static OS_INFO
    unsafe {
        let os_info = &mut *core::ptr::addr_of_mut!(OS_INFO);
        if linux_partition_lba == 0 && esp_partition_lba == 0 {
            os_info.name = "GPT System";
            os_info.partition = 1;
        } else {
            os_info.name = "Linux";
            os_info.partition = if linux_partition_num > 0 { linux_partition_num } else { 1 };
        }
        os_info.disk_type = disk_type;
        os_info.bootable = true;
        // mbr already in place
        // Copy os_name_buf byte by byte to avoid alignment issues
        serial::println("DBG: copying os_name_buf byte by byte");
        for i in 0..64 {
            core::ptr::write_volatile(
                &mut os_info.os_name_buf[i] as *mut u8,
                core::ptr::read_volatile(&OS_NAME_BUF[i] as *const u8)
            );
        }
        serial::println("DBG: os_name_buf copied");
        os_info.os_name_len = OS_NAME_LEN;
    }
    serial::println("DBG: OsInfo written to static successfully");
    true
}

/// Scan using VirtIO SCSI (common in VMs)
fn scan_virtio_scsi() -> Option<OsInfo> {
    serial::println("Trying VirtIO SCSI...");

    let (controller, target, lun) = virtio::init()?;
    let mut reader = DiskReader::VirtioScsi { ctrl: controller, target, lun };

    serial::print("VirtIO SCSI: Reading MBR from target ");
    serial::print_dec(target as u32);
    serial::println("");

    // Read MBR
    let mut mbr = [0u8; 512];
    if !reader.read_sector(0, &mut mbr) {
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
        return detect_os_from_gpt(&mut reader, target, lun, &mbr);
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
fn detect_os_from_gpt(controller: &mut DiskReader, _target: u8, _lun: u8, mbr: &[u8; 512]) -> Option<OsInfo> {
    serial::println("Parsing GPT for OS detection...");
    let disk_type = controller.disk_type();

    // Read GPT header at LBA 1
    let mut gpt_sector = [0u8; 512];
    if !controller.read_sector(1, &mut gpt_sector) {
        serial::println("Failed to read GPT header - returning GPT System fallback");
        // Don't fail completely - we know it's GPT from the protective MBR
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
            disk_type,
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
            if !controller.read_sector(entry_lba as u32, &mut cached_sector) {
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
        if is_linux_partition_guid(&entry.type_guid) && linux_partition_lba == 0 {
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

    serial::println("DBG: after partition loop");

    // Use static buffers to avoid stack allocation issues in 64-bit mode
    serial::println("DBG: zeroing static byte by byte");
    unsafe {
        for i in 0..64 {
            core::ptr::write_volatile(&mut OS_NAME_BUF[i], 0);
        }
        OS_NAME_LEN = 0;
    }
    serial::println("DBG: static initialized");

    // Try FAT32 ESP first (GRUB/systemd-boot config)
    if esp_partition_lba != 0 {
        serial::println("Trying ESP (FAT32) for OS detection...");
        if let Some((buf, len)) = detect_os_from_esp(controller, _target, _lun, esp_partition_lba) {
            unsafe {
                OS_NAME_BUF = buf;
                OS_NAME_LEN = len;
            }
        }
    }

    // Fall back to ext4 /etc/os-release or volume label
    if unsafe { OS_NAME_LEN } == 0 && linux_partition_lba != 0 {
        serial::println("Falling back to ext4 for OS detection...");
        // detect_os_from_ext4 writes directly to OS_NAME_BUF and OS_NAME_LEN
        detect_os_from_ext4(controller, _target, _lun, linux_partition_lba);
    }

    serial::println("DBG: about to return OsInfo");
    serial::print("DBG: OS_NAME_LEN=");
    serial::print_dec(unsafe { OS_NAME_LEN } as u32);
    serial::println("");

    if linux_partition_lba == 0 && esp_partition_lba == 0 {
        serial::println("No Linux or EFI partition found in GPT");
        serial::println("DBG: returning GPT System");
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

    serial::println("DBG: returning Linux OsInfo");
    unsafe {
        Some(OsInfo {
            name: "Linux",
            disk_type,
            partition: if linux_partition_num > 0 { linux_partition_num } else { 1 },
            bootable: true,
            mbr: *mbr,
            os_name_buf: OS_NAME_BUF,
            os_name_len: OS_NAME_LEN,
        })
    }
}

/// Detect OS from EFI System Partition by reading GRUB config
fn detect_os_from_esp(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64
) -> Option<([u8; 64], usize)> {
    // Debug: print stack pointer
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp); }
    serial::print("DBG: RSP = 0x");
    serial::print_hex32((rsp >> 32) as u32);
    serial::print_hex32(rsp as u32);
    serial::println("");

    serial::println("Reading FAT32 ESP for GRUB config...");

    // Read FAT32 boot sector
    let mut boot_sector = [0u8; 512];
    if !controller.read_sector(partition_lba as u32, &mut boot_sector) {
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

        serial::println("DBG: about to call read_fat32_file");
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
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    fat32: &Fat32Context,
    root_cluster: u32,
    path: &[&[u8]]
) -> Option<[u8; 512]> {
    serial::println("DBG: entered read_fat32_file");
    let mut current_cluster = root_cluster;

    // Navigate through path components
    for (i, component) in path.iter().enumerate() {
        let is_last = i == path.len() - 1;

        // Find component in current directory
        let entry = find_fat32_entry(controller, target, lun, fat32, current_cluster, component)?;

        // Read packed struct fields safely using read_unaligned
        let entry_ptr = &entry as *const Fat32DirEntry as *const u8;
        let attr = unsafe { core::ptr::read_unaligned(entry_ptr.wrapping_add(11)) };
        let cluster_hi = unsafe {
            u16::from_le_bytes([
                core::ptr::read_unaligned(entry_ptr.wrapping_add(20)),
                core::ptr::read_unaligned(entry_ptr.wrapping_add(21)),
            ])
        };
        let cluster_lo = unsafe {
            u16::from_le_bytes([
                core::ptr::read_unaligned(entry_ptr.wrapping_add(26)),
                core::ptr::read_unaligned(entry_ptr.wrapping_add(27)),
            ])
        };

        if is_last {
            // This is the file - read first sector of its data
            let file_cluster = ((cluster_hi as u32) << 16) | (cluster_lo as u32);
            let file_lba = cluster_to_lba(fat32, file_cluster);

            let mut contents = [0u8; 512];
            if !controller.read_sector(file_lba as u32, &mut contents) {
                return None;
            }
            return Some(contents);
        } else {
            // This is a directory - descend into it
            if attr & FAT_ATTR_DIRECTORY == 0 {
                return None; // Not a directory
            }
            current_cluster = ((cluster_hi as u32) << 16) | (cluster_lo as u32);
        }
    }

    None
}

/// Find a directory entry by name (8.3 format, case-insensitive)
/// Follows FAT cluster chain to search entire directory
fn find_fat32_entry(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    fat32: &Fat32Context,
    start_cluster: u32,
    name: &[u8]
) -> Option<Fat32DirEntry> {
    // Debug RSP
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp); }
    serial::print("find_fat32_entry RSP=0x");
    serial::print_hex32(rsp as u32);
    serial::println("");

    let entries_per_sector = fat32.bytes_per_sector / 32;
    let mut current_cluster = start_cluster;
    let mut chain_depth = 0;

    // Follow cluster chain (limit to 64 clusters to avoid infinite loops)
    while current_cluster >= 2 && current_cluster < 0x0FFFFFF8 && chain_depth < 64 {
        let cluster_lba = cluster_to_lba(fat32, current_cluster);

        // Read all sectors in this cluster
        for sector_offset in 0..fat32.sectors_per_cluster {
            let mut sector = [0u8; 512];
            if !controller.read_sector((cluster_lba + sector_offset as u64) as u32, &mut sector) {
                serial::print("FAT32: Failed to read dir sector at cluster ");
                serial::print_dec(current_cluster);
                serial::println("");
                // Try next cluster instead of failing completely
                break;
            }

            for entry_idx in 0..entries_per_sector {
                let offset = (entry_idx * 32) as usize;

                // Read entry bytes directly to avoid packed struct alignment issues
                let entry_ptr = sector.as_ptr().wrapping_add(offset);

                // Read first byte (name[0]) - check for end or deleted
                let first_byte = unsafe { core::ptr::read_unaligned(entry_ptr) };

                // End of directory
                if first_byte == 0x00 {
                    return None;
                }

                // Read attr byte (offset 11 in the entry)
                let attr_byte = unsafe { core::ptr::read_unaligned(entry_ptr.wrapping_add(11)) };

                // Deleted entry or LFN entry
                if first_byte == 0xE5 || attr_byte == FAT_ATTR_LFN {
                    continue;
                }

                // Copy name to aligned buffer for comparison
                let mut entry_name = [0u8; 11];
                for i in 0..11 {
                    entry_name[i] = unsafe { core::ptr::read_unaligned(entry_ptr.wrapping_add(i)) };
                }

                // Compare name (8.3 format, case-insensitive)
                if fat32_name_match(&entry_name, name) {
                    serial::print("FAT32: Found '");
                    for &c in name {
                        serial::print_char(c);
                    }
                    serial::print("' in cluster ");
                    serial::print_dec(current_cluster);
                    serial::println("");

                    // Read the full entry with read_unaligned
                    let entry = unsafe {
                        core::ptr::read_unaligned(entry_ptr as *const Fat32DirEntry)
                    };
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
    controller: &mut DiskReader,
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
    if !controller.read_sector(fat_sector as u32, &mut sector) {
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
/// Detect OS from ext4. Writes to OS_NAME_BUF and OS_NAME_LEN globals. Returns true on success.
fn detect_os_from_ext4(controller: &mut DiskReader, target: u8, lun: u8, partition_lba: u64) -> bool {
    serial::println("Reading ext4 filesystem for OS detection...");

    // Reset ext4 context from any previous scan
    unsafe { EXT4_CTX.valid = false; }

    // ext4 superblock is at offset 1024 (byte 1024-2047 of the partition)
    // For 512-byte sectors, that's sector 2 of the partition
    let superblock_lba = partition_lba + 2;

    let mut sb_sector = [0u8; 512];
    if !controller.read_sector(superblock_lba as u32, &mut sb_sector) {
        serial::println("Failed to read ext4 superblock");
        return false;
    }

    let superblock = unsafe {
        core::ptr::read_unaligned(sb_sector.as_ptr() as *const Ext4Superblock)
    };

    // Verify ext4 magic
    if superblock.s_magic != EXT4_MAGIC {
        serial::print("Not ext4 (magic=0x");
        serial::print_hex32(superblock.s_magic as u32);
        serial::println(")");
        return false;
    }
    serial::println("ext4 filesystem confirmed");

    // Calculate block size
    let block_size = 1024u32 << superblock.s_log_block_size;
    serial::print("Block size: ");
    serial::print_dec(block_size);
    serial::println(" bytes");

    // Populate ext4 filesystem context for correct multi-block-group inode lookup
    let inode_size = superblock.s_inode_size as u32;
    let inodes_per_group = superblock.s_inodes_per_group;

    // Determine block group descriptor size: 32 bytes (standard) or 64 bytes (64-bit feature)
    let desc_size = if superblock.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT != 0 {
        // s_desc_size is at superblock offset 254 (within our 512-byte read)
        let ds = u16::from_le_bytes([sb_sector[254], sb_sector[255]]) as u32;
        if ds >= 32 { ds } else { 32 }
    } else {
        32
    };

    unsafe {
        EXT4_CTX.partition_lba = partition_lba;
        EXT4_CTX.block_size = block_size;
        EXT4_CTX.inode_size = inode_size;
        EXT4_CTX.inodes_per_group = inodes_per_group;
        EXT4_CTX.desc_size = desc_size;
        EXT4_CTX.valid = true;
    }

    serial::print("ext4: inodes_per_group=");
    serial::print_dec(inodes_per_group);
    serial::print(" inode_size=");
    serial::print_dec(inode_size);
    serial::print(" desc_size=");
    serial::print_dec(desc_size);
    serial::println("");

    // Try to read /etc/os-release
    // First, find the root inode (inode 2)
    // Then navigate to /etc/os-release

    if read_os_release(controller, target, lun, partition_lba, &superblock) {
        // OS info is now in OS_NAME_BUF and OS_NAME_LEN globals
        serial::println("DBG: detect_os_from_ext4 success");
        // Also try to detect hostname while we have the ext4 context
        try_read_hostname(controller, target, lun, partition_lba, &superblock);
        return true;
    }

    // Even if OS detection failed, try hostname detection (might find /etc/hostname
    // on a partition that doesn't have /etc/os-release or /boot/grub/grub.cfg)
    try_read_hostname(controller, target, lun, partition_lba, &superblock);

    // Fallback: check volume label - write directly to globals
    unsafe {
        OS_NAME_LEN = 0;
        for i in 0..64 {
            OS_NAME_BUF[i] = 0;
        }
    }

    for (i, &c) in superblock.s_volume_name.iter().enumerate() {
        if c == 0 {
            break;
        }
        if i < 64 {
            unsafe {
                OS_NAME_BUF[i] = c;
                OS_NAME_LEN = i + 1;
            }
        }
    }

    let name_len = unsafe { OS_NAME_LEN };
    if name_len > 0 {
        serial::print("Volume label: ");
        for i in 0..name_len {
            unsafe { serial::print_char(OS_NAME_BUF[i]); }
        }
        serial::println("");
        return true;
    }

    false
}

/// Try to read OS info from ext4 - first /boot/grub/grub.cfg, then /etc/os-release
/// Writes directly to OS_NAME_BUF and OS_NAME_LEN globals. Returns true on success.
fn read_os_release(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    superblock: &Ext4Superblock
) -> bool {
    let block_size = 1024u32 << superblock.s_log_block_size;
    let inode_size = superblock.s_inode_size as u32;

    // Read root inode (inode 2)
    // Inode table location is in the block group descriptor
    // Block group descriptor table starts at block 1 (or 2 for 1024-byte blocks)
    let bgdt_block = if block_size == 1024 { 2 } else { 1 };
    let bgdt_lba = partition_lba + (bgdt_block as u64 * block_size as u64 / 512);

    let mut bgdt_sector = [0u8; 512];
    if !controller.read_sector(bgdt_lba as u32, &mut bgdt_sector) {
        serial::println("Failed to read block group descriptor");
        return false;
    }

    // Block group descriptor is 32 bytes (or 64 for 64-bit features)
    // We need inode table location (offset 8, 4 bytes)
    let inode_table_block = u32::from_le_bytes([bgdt_sector[8], bgdt_sector[9], bgdt_sector[10], bgdt_sector[11]]);

    serial::print("Inode table at block ");
    serial::print_dec(inode_table_block);
    serial::println("");

    // Root inode is inode 2 (index 1 in 0-based)
    let root_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, 2) {
        Some(i) => i,
        None => return false,
    };

    // Debug: show root inode info - use read_unaligned for packed struct
    let inode_ptr = &root_inode as *const Ext4Inode as *const u8;
    let i_mode = unsafe {
        u16::from_le_bytes([
            core::ptr::read_unaligned(inode_ptr),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(1)),
        ])
    };
    let i_flags = unsafe {
        u32::from_le_bytes([
            core::ptr::read_unaligned(inode_ptr.wrapping_add(32)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(33)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(34)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(35)),
        ])
    };
    let i_blocks_lo = unsafe {
        u32::from_le_bytes([
            core::ptr::read_unaligned(inode_ptr.wrapping_add(28)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(29)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(30)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(31)),
        ])
    };

    serial::print("Root inode: mode=0x");
    serial::print_hex32(i_mode as u32);
    serial::print(" flags=0x");
    serial::print_hex32(i_flags);
    serial::print(" blocks=");
    serial::print_dec(i_blocks_lo);
    serial::println("");

    serial::print("DBG: inode_ptr=0x");
    serial::print_hex32(inode_ptr as u32);
    serial::println("");

    // Use static buffer to avoid stack allocation issues
    static mut ROOT_I_BLOCK: [u8; 60] = [0u8; 60];

    serial::println("DBG: about to copy i_block");

    // Copy i_block to avoid packed struct alignment issues
    // i_block is at offset 40 (0x28) in the inode struct
    for i in 0..60 {
        unsafe {
            ROOT_I_BLOCK[i] = core::ptr::read_unaligned(inode_ptr.wrapping_add(40 + i));
        }
    }

    serial::println("DBG: copied i_block");

    // Use static buffer directly - avoid stack copy
    serial::print("Root i_block[0..4]: ");
    for i in 0..4 {
        let val = unsafe {
            u32::from_le_bytes([
                ROOT_I_BLOCK[i*4], ROOT_I_BLOCK[i*4+1],
                ROOT_I_BLOCK[i*4+2], ROOT_I_BLOCK[i*4+3]
            ])
        };
        serial::print_hex32(val);
        serial::print(" ");
    }
    serial::println("");

    // Try /boot/grub/grub.cfg first (for GRUB menuentry)
    serial::println("Trying /boot/grub/grub.cfg...");
    if let Some((buf, len)) = read_grub_cfg_from_ext4(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, &root_inode) {
        // Copy grub result to globals
        unsafe {
            OS_NAME_LEN = len;
            for i in 0..len.min(64) {
                OS_NAME_BUF[i] = buf[i];
            }
        }
        return true;
    }

    // Fall back to /etc/os-release
    serial::println("Trying /etc/os-release...");
    serial::println("DBG: about to call read_etc_os_release");
    let success = read_etc_os_release(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, &root_inode);
    serial::print("DBG: read_etc_os_release returned ");
    if success { serial::println("true"); } else { serial::println("false"); }

    serial::println("DBG: returning from read_os_release");
    success
}

/// Read /boot/grub/grub.cfg from ext4
fn read_grub_cfg_from_ext4(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    root_inode: &Ext4Inode
) -> Option<([u8; 64], usize)> {
    serial::println("DBG: entered read_grub_cfg_from_ext4");
    // Find /boot directory
    serial::println("DBG: calling find_dir_entry for 'boot'");
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
    match parse_grub_config(contents) {
        GrubParseResult::MenuEntry(buf, len) => Some((buf, len)),
        _ => None,
    }
}

/// Read /etc/os-release from ext4. Returns true if OS was detected.
fn read_etc_os_release(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    root_inode: &Ext4Inode
) -> bool {
    // Find /etc directory in root
    let etc_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, root_inode, b"etc") {
        Some(n) => n,
        None => return false,
    };

    serial::print("Found /etc at inode ");
    serial::print_dec(etc_inode_num);
    serial::println("");

    // Read /etc inode
    let etc_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, etc_inode_num) {
        Some(i) => i,
        None => return false,
    };

    // Find os-release in /etc
    let os_release_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, &etc_inode, b"os-release") {
        Some(n) => n,
        None => return false,
    };

    serial::print("Found /etc/os-release at inode ");
    serial::print_dec(os_release_inode_num);
    serial::println("");

    // Read os-release inode
    let os_release_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, os_release_inode_num) {
        Some(i) => i,
        None => return false,
    };

    // Check if it's a symlink - if so, follow to /usr/lib/os-release
    let os_release_inode_ptr = &os_release_inode as *const Ext4Inode as *const u8;
    let os_release_mode = unsafe {
        u16::from_le_bytes([
            core::ptr::read_unaligned(os_release_inode_ptr),
            core::ptr::read_unaligned(os_release_inode_ptr.wrapping_add(1)),
        ])
    };
    if (os_release_mode & 0xF000) == 0xA000 {
        serial::println("os-release is symlink, trying /usr/lib/os-release");
        return read_usr_lib_os_release(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, root_inode);
    }

    // Read file contents
    let contents = match read_file_contents(controller, target, lun, partition_lba, block_size, &os_release_inode) {
        Some(c) => c,
        None => return false,
    };

    // Parse PRETTY_NAME from os-release (writes to global OS_NAME_BUF/LEN)
    parse_pretty_name(contents)
}

/// Read /usr/lib/os-release from ext4 (symlink target). Returns true if OS was detected.
fn read_usr_lib_os_release(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    root_inode: &Ext4Inode
) -> bool {
    // Find /usr directory
    let usr_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, root_inode, b"usr") {
        Some(n) => n,
        None => return false,
    };
    serial::print("Found /usr at inode ");
    serial::print_dec(usr_inode_num);
    serial::println("");

    let usr_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, usr_inode_num) {
        Some(i) => i,
        None => return false,
    };

    // Find /usr/lib directory
    let lib_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, &usr_inode, b"lib") {
        Some(n) => n,
        None => return false,
    };
    serial::print("Found /usr/lib at inode ");
    serial::print_dec(lib_inode_num);
    serial::println("");

    let lib_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, lib_inode_num) {
        Some(i) => i,
        None => return false,
    };

    // Find os-release in /usr/lib
    let os_release_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, &lib_inode, b"os-release") {
        Some(n) => n,
        None => return false,
    };
    serial::print("Found /usr/lib/os-release at inode ");
    serial::print_dec(os_release_inode_num);
    serial::println("");

    let os_release_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, os_release_inode_num) {
        Some(i) => i,
        None => return false,
    };

    // Read file contents
    let contents = match read_file_contents(controller, target, lun, partition_lba, block_size, &os_release_inode) {
        Some(c) => c,
        None => return false,
    };

    // Parse PRETTY_NAME from os-release (writes to global OS_NAME_BUF/LEN)
    parse_pretty_name(contents)
}

/// Try to read hostname from ext4 filesystem.
/// Reads /etc/hostname first, falls back to /etc/hosts.
/// Writes to HOSTNAME_BUF/HOSTNAME_LEN globals.
fn try_read_hostname(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    superblock: &Ext4Superblock,
) {
    // Skip if we already have a hostname from a previous partition
    if unsafe { HOSTNAME_LEN } > 0 {
        return;
    }

    serial::println("Trying hostname detection...");

    let block_size = 1024u32 << superblock.s_log_block_size;
    let inode_size = superblock.s_inode_size as u32;

    // Read BG0 descriptor to get inode table location
    let bgdt_block = if block_size == 1024 { 2 } else { 1 };
    let bgdt_lba = partition_lba + (bgdt_block as u64 * block_size as u64 / 512);

    let mut bgdt_sector = [0u8; 512];
    if !controller.read_sector(bgdt_lba as u32, &mut bgdt_sector) {
        return;
    }

    let inode_table_block = u32::from_le_bytes([bgdt_sector[8], bgdt_sector[9], bgdt_sector[10], bgdt_sector[11]]);

    // Read root inode (inode 2)
    let root_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, 2) {
        Some(i) => i,
        None => return,
    };

    // Find /etc directory
    let etc_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, &root_inode, b"etc") {
        Some(n) => n,
        None => return,
    };

    let etc_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, etc_inode_num) {
        Some(i) => i,
        None => return,
    };

    // Try /etc/hostname first
    if try_read_etc_hostname(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, &etc_inode) {
        return;
    }

    // Fallback: try /etc/hosts
    try_read_etc_hosts(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, &etc_inode);
}

/// Read /etc/hostname and parse the hostname from it
fn try_read_etc_hostname(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    etc_inode: &Ext4Inode,
) -> bool {
    let hostname_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, etc_inode, b"hostname") {
        Some(n) => n,
        None => return false,
    };

    serial::print("Found /etc/hostname at inode ");
    serial::print_dec(hostname_inode_num);
    serial::println("");

    let hostname_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, hostname_inode_num) {
        Some(i) => i,
        None => return false,
    };

    let contents = match read_file_contents(controller, target, lun, partition_lba, block_size, &hostname_inode) {
        Some(c) => c,
        None => return false,
    };

    // /etc/hostname is just the hostname with an optional trailing newline
    parse_hostname_file(contents)
}

/// Parse hostname from /etc/hostname contents (single line, trim whitespace)
fn parse_hostname_file(contents: &[u8; 512]) -> bool {
    // Skip leading whitespace
    let mut start = 0;
    while start < 512 && (contents[start] == b' ' || contents[start] == b'\t' || contents[start] == b'\n' || contents[start] == b'\r') {
        start += 1;
    }

    // Find end (first newline, null, or whitespace after hostname)
    let mut end = start;
    while end < 512 && contents[end] != 0 && contents[end] != b'\n' && contents[end] != b'\r' {
        end += 1;
    }

    // Trim trailing whitespace
    while end > start && (contents[end - 1] == b' ' || contents[end - 1] == b'\t') {
        end -= 1;
    }

    let len = end - start;
    if len == 0 || len > 255 {
        return false;
    }

    // Skip "localhost" — not a useful hostname
    if len == 9 && contents[start] == b'l' && &contents[start..end] == b"localhost" {
        return false;
    }

    unsafe {
        for i in 0..len {
            HOSTNAME_BUF[i] = contents[start + i];
        }
        HOSTNAME_LEN = len;
    }

    serial::print("Detected hostname: ");
    if let Ok(s) = core::str::from_utf8(&contents[start..end]) {
        serial::println(s);
    }

    true
}

/// Read /etc/hosts and extract hostname from 127.0.1.1 line
fn try_read_etc_hosts(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    etc_inode: &Ext4Inode,
) -> bool {
    let hosts_inode_num = match find_dir_entry(controller, target, lun, partition_lba, block_size, etc_inode, b"hosts") {
        Some(n) => n,
        None => return false,
    };

    serial::print("Found /etc/hosts at inode ");
    serial::print_dec(hosts_inode_num);
    serial::println("");

    let hosts_inode = match read_inode(controller, target, lun, partition_lba, block_size, inode_table_block, inode_size, hosts_inode_num) {
        Some(i) => i,
        None => return false,
    };

    let contents = match read_file_contents(controller, target, lun, partition_lba, block_size, &hosts_inode) {
        Some(c) => c,
        None => return false,
    };

    parse_hostname_from_hosts(contents)
}

/// Parse hostname from /etc/hosts — look for 127.0.1.1 line
fn parse_hostname_from_hosts(contents: &[u8; 512]) -> bool {
    let pattern = b"127.0.1.1";

    let mut i = 0;
    while i + 9 <= 512 {
        // Match pattern at start of line
        if (i == 0 || contents[i - 1] == b'\n') && &contents[i..i + 9] == pattern {
            // Skip whitespace/tabs after the IP
            let mut pos = i + 9;
            while pos < 512 && (contents[pos] == b' ' || contents[pos] == b'\t') {
                pos += 1;
            }

            // Read hostname (until whitespace, newline, or null)
            let name_start = pos;
            while pos < 512 && contents[pos] != 0 && contents[pos] != b' ' && contents[pos] != b'\t' && contents[pos] != b'\n' && contents[pos] != b'\r' {
                pos += 1;
            }

            let len = pos - name_start;
            if len > 0 && len <= 255 {
                // Skip "localhost"
                if len == 9 && &contents[name_start..pos] == b"localhost" {
                    i = pos;
                    continue;
                }

                unsafe {
                    for k in 0..len {
                        HOSTNAME_BUF[k] = contents[name_start + k];
                    }
                    HOSTNAME_LEN = len;
                }

                serial::print("Detected hostname from /etc/hosts: ");
                if let Ok(s) = core::str::from_utf8(&contents[name_start..pos]) {
                    serial::println(s);
                }

                return true;
            }
        }
        i += 1;
    }

    false
}

/// Read an inode from the filesystem
fn read_inode(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode_table_block: u32,
    inode_size: u32,
    inode_num: u32
) -> Option<Ext4Inode> {
    // Use EXT4_CTX for correct multi-block-group lookup when available
    let (actual_inode_table_block, local_inode_index) = unsafe {
        if EXT4_CTX.valid && EXT4_CTX.inodes_per_group > 0 {
            let inodes_per_group = EXT4_CTX.inodes_per_group;
            let block_group = (inode_num - 1) / inodes_per_group;
            let local_idx = (inode_num - 1) % inodes_per_group;

            if block_group == 0 {
                // Block group 0 — use the passed inode_table_block (fast path)
                (inode_table_block, local_idx)
            } else {
                // Different block group — read its BGDT entry to get inode table location
                let desc_size = EXT4_CTX.desc_size;
                let bgdt_block = if block_size == 1024 { 2u64 } else { 1u64 };
                let bgdt_byte_offset = block_group as u64 * desc_size as u64;
                let bgdt_lba = partition_lba + (bgdt_block * block_size as u64 / 512) + (bgdt_byte_offset / 512);
                let sector_off = (bgdt_byte_offset % 512) as usize;

                serial::print("read_inode: BG ");
                serial::print_dec(block_group);
                serial::print(" desc at LBA ");
                serial::print_dec(bgdt_lba as u32);
                serial::println("");

                let mut bgdt_sector = [0u8; 512];
                if !controller.read_sector(bgdt_lba as u32, &mut bgdt_sector) {
                    serial::println("  -> BGDT read FAILED");
                    return None;
                }

                // inode table block is at offset 8 within the BGDT entry
                let it_block = u32::from_le_bytes([
                    bgdt_sector[sector_off + 8],
                    bgdt_sector[sector_off + 9],
                    bgdt_sector[sector_off + 10],
                    bgdt_sector[sector_off + 11],
                ]);

                serial::print("  BG ");
                serial::print_dec(block_group);
                serial::print(" inode_table_block=");
                serial::print_dec(it_block);
                serial::println("");

                (it_block, local_idx)
            }
        } else {
            // No EXT4_CTX — legacy fallback (all inodes from BG0)
            (inode_table_block, inode_num - 1)
        }
    };

    let inode_offset = local_inode_index * inode_size;
    let inode_block = actual_inode_table_block + (inode_offset / block_size);
    let offset_in_block = inode_offset % block_size;

    let inode_lba = partition_lba + (inode_block as u64 * block_size as u64 / 512);
    let sector_offset = offset_in_block / 512;
    let offset_in_sector = offset_in_block % 512;

    serial::print("read_inode(");
    serial::print_dec(inode_num);
    serial::print("): table_blk=");
    serial::print_dec(actual_inode_table_block);
    serial::print(" inode_blk=");
    serial::print_dec(inode_block);
    serial::print(" LBA=");
    serial::print_dec((inode_lba + sector_offset as u64) as u32);
    serial::println("");

    let mut sector = [0u8; 512];
    if !controller.read_sector((inode_lba + sector_offset as u64) as u32, &mut sector) {
        serial::println("  -> read_inode FAILED");
        return None;
    }

    let inode = unsafe {
        core::ptr::read_unaligned(sector.as_ptr().add(offset_in_sector as usize) as *const Ext4Inode)
    };

    Some(inode)
}

// Static buffer for i_block data in get_first_data_block
static mut IBLOCK_BYTES: [u8; 60] = [0u8; 60];

/// A contiguous range of physical data blocks from an extent
#[derive(Clone, Copy)]
struct DataExtent {
    start_block: u64,
    num_blocks: u16,
}

/// Maximum number of extents we track for a single inode
const MAX_EXTENTS: usize = 32;

/// Static storage for inode extent lists (avoids heap allocation)
static mut INODE_EXTENTS: [DataExtent; MAX_EXTENTS] = [DataExtent { start_block: 0, num_blocks: 0 }; MAX_EXTENTS];
static mut INODE_EXTENT_COUNT: usize = 0;

/// Buffer for reading extent tree leaf blocks (depth > 0)
static mut EXTENT_LEAF_BUF: [u8; 4096] = [0u8; 4096];

/// Static buffer for i_block data in get_inode_extents (separate from get_first_data_block)
static mut EXTENT_IBLOCK_BYTES: [u8; 60] = [0u8; 60];

/// Get the first data block from an inode (handles both extents and direct blocks)
fn get_first_data_block(dir_inode: &Ext4Inode) -> Option<u64> {
    serial::println("DBG: entered get_first_data_block");

    let inode_ptr = dir_inode as *const Ext4Inode as *const u8;
    serial::print("DBG: inode_ptr=0x");
    serial::print_hex32(inode_ptr as u32);
    serial::println("");

    // Copy i_block byte by byte to avoid alignment issues
    // i_block is at offset 40 (0x28) in the inode struct
    let i_block_bytes = unsafe { &mut *core::ptr::addr_of_mut!(IBLOCK_BYTES) };
    for i in 0..60 {
        i_block_bytes[i] = unsafe { core::ptr::read_unaligned(inode_ptr.wrapping_add(40 + i)) };
    }
    serial::println("DBG: copied i_block_bytes");

    // Read packed struct fields safely
    let mode = unsafe {
        u16::from_le_bytes([
            core::ptr::read_unaligned(inode_ptr),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(1)),
        ])
    };
    let flags = unsafe {
        u32::from_le_bytes([
            core::ptr::read_unaligned(inode_ptr.wrapping_add(32)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(33)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(34)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(35)),
        ])
    };
    let size = unsafe {
        u32::from_le_bytes([
            core::ptr::read_unaligned(inode_ptr.wrapping_add(4)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(5)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(6)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(7)),
        ])
    };

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
        // Parse extent header from i_block - read fields directly to avoid packed struct issues
        // Ext4ExtentHeader layout: magic(2) entries(2) max(2) depth(2) generation(4) = 12 bytes
        let eh_magic = u16::from_le_bytes([i_block_bytes[0], i_block_bytes[1]]);
        let eh_entries = u16::from_le_bytes([i_block_bytes[2], i_block_bytes[3]]);
        let eh_depth = u16::from_le_bytes([i_block_bytes[6], i_block_bytes[7]]);

        serial::print("Extent header: magic=0x");
        serial::print_hex32(eh_magic as u32);
        serial::print(" entries=");
        serial::print_dec(eh_entries as u32);
        serial::print(" depth=");
        serial::print_dec(eh_depth as u32);
        serial::println("");

        if eh_magic != EXT4_EXTENT_MAGIC {
            serial::println("Bad extent magic!");
            return None;
        }

        if eh_entries == 0 {
            serial::println("No extent entries!");
            return None;
        }

        if eh_depth == 0 {
            // Leaf node - extent directly follows header at offset 12
            // Ext4Extent layout: ee_block(4) ee_len(2) ee_start_hi(2) ee_start_lo(4) = 12 bytes
            let ee_len = u16::from_le_bytes([i_block_bytes[16], i_block_bytes[17]]);
            let ee_start_hi = u16::from_le_bytes([i_block_bytes[18], i_block_bytes[19]]);
            let ee_start_lo = u32::from_le_bytes([
                i_block_bytes[20], i_block_bytes[21], i_block_bytes[22], i_block_bytes[23]
            ]);

            let block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);
            serial::print("Extent: block=");
            serial::print_dec(block as u32);
            serial::print(" len=");
            serial::print_dec(ee_len as u32);
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

// Static buffer for directory block reads - avoid 4KB stack allocation
static mut DIR_BLOCK_DATA: [u8; 4096] = [0u8; 4096];

/// Populate INODE_EXTENTS with all data extents for an inode.
/// Handles extent trees of depth 0 (inline) and depth 1+ (index nodes on disk).
/// Returns the number of extents found.
fn get_inode_extents(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode: &Ext4Inode,
) -> usize {
    unsafe { INODE_EXTENT_COUNT = 0; }

    let inode_ptr = inode as *const Ext4Inode as *const u8;

    // Copy i_block (60 bytes at offset 40) to static buffer
    let i_block = unsafe { &mut *core::ptr::addr_of_mut!(EXTENT_IBLOCK_BYTES) };
    for i in 0..60 {
        i_block[i] = unsafe { core::ptr::read_unaligned(inode_ptr.wrapping_add(40 + i)) };
    }

    let flags = unsafe {
        u32::from_le_bytes([
            core::ptr::read_unaligned(inode_ptr.wrapping_add(32)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(33)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(34)),
            core::ptr::read_unaligned(inode_ptr.wrapping_add(35)),
        ])
    };

    if flags & EXT4_EXTENTS_FL == 0 {
        // Direct block pointers (legacy, no extents)
        let block_num = u32::from_le_bytes([i_block[0], i_block[1], i_block[2], i_block[3]]);
        if block_num != 0 {
            unsafe {
                INODE_EXTENTS[0] = DataExtent { start_block: block_num as u64, num_blocks: 1 };
                INODE_EXTENT_COUNT = 1;
            }
        }
        return unsafe { INODE_EXTENT_COUNT };
    }

    // Parse extent header
    let eh_magic = u16::from_le_bytes([i_block[0], i_block[1]]);
    let eh_entries = u16::from_le_bytes([i_block[2], i_block[3]]);
    let eh_depth = u16::from_le_bytes([i_block[6], i_block[7]]);

    if eh_magic != EXT4_EXTENT_MAGIC || eh_entries == 0 {
        return 0;
    }

    if eh_depth == 0 {
        // Leaf: extents are inline after the 12-byte header (max 4 fit in 60 bytes)
        let count = (eh_entries as usize).min(MAX_EXTENTS).min(4);
        for i in 0..count {
            let off = 12 + i * 12;
            if off + 12 > 60 { break; }
            let ee_len = u16::from_le_bytes([i_block[off + 4], i_block[off + 5]]);
            let ee_start_hi = u16::from_le_bytes([i_block[off + 6], i_block[off + 7]]);
            let ee_start_lo = u32::from_le_bytes([
                i_block[off + 8], i_block[off + 9], i_block[off + 10], i_block[off + 11]
            ]);
            let start = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);
            let len = ee_len & 0x7FFF; // mask off uninitialized flag
            unsafe {
                INODE_EXTENTS[i] = DataExtent { start_block: start, num_blocks: len };
            }
        }
        unsafe { INODE_EXTENT_COUNT = count; }
    } else {
        // Depth > 0: index nodes in i_block point to leaf blocks on disk
        let num_indices = (eh_entries as usize).min(4);
        let sectors_per_block = block_size / 512;

        for idx_i in 0..num_indices {
            let off = 12 + idx_i * 12;
            if off + 12 > 60 { break; }
            // Index entry: ei_block(4) ei_leaf_lo(4) ei_leaf_hi(2) ei_unused(2)
            let ei_leaf_lo = u32::from_le_bytes([
                i_block[off + 4], i_block[off + 5], i_block[off + 6], i_block[off + 7]
            ]);
            let ei_leaf_hi = u16::from_le_bytes([i_block[off + 8], i_block[off + 9]]);
            let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);

            // Read the leaf block from disk
            let leaf_lba = partition_lba + (leaf_block * block_size as u64 / 512);
            let leaf_buf = unsafe { &mut *core::ptr::addr_of_mut!(EXTENT_LEAF_BUF) };

            let mut read_ok = true;
            for s in 0..sectors_per_block.min(8) {
                let mut sector = [0u8; 512];
                if !controller.read_sector((leaf_lba + s as u64) as u32, &mut sector) {
                    read_ok = false;
                    break;
                }
                leaf_buf[s as usize * 512..(s as usize + 1) * 512].copy_from_slice(&sector);
            }
            if !read_ok { continue; }

            // Parse leaf block extent header
            let leaf_magic = u16::from_le_bytes([leaf_buf[0], leaf_buf[1]]);
            let leaf_entries = u16::from_le_bytes([leaf_buf[2], leaf_buf[3]]);
            let leaf_depth = u16::from_le_bytes([leaf_buf[6], leaf_buf[7]]);

            if leaf_magic != EXT4_EXTENT_MAGIC || leaf_depth != 0 {
                continue; // not a valid leaf, or deeper tree (very rare)
            }

            for j in 0..leaf_entries as usize {
                let ext_count = unsafe { INODE_EXTENT_COUNT };
                if ext_count >= MAX_EXTENTS { break; }

                let eoff = 12 + j * 12;
                if eoff + 12 > block_size as usize { break; }
                let ee_len = u16::from_le_bytes([leaf_buf[eoff + 4], leaf_buf[eoff + 5]]);
                let ee_start_hi = u16::from_le_bytes([leaf_buf[eoff + 6], leaf_buf[eoff + 7]]);
                let ee_start_lo = u32::from_le_bytes([
                    leaf_buf[eoff + 8], leaf_buf[eoff + 9], leaf_buf[eoff + 10], leaf_buf[eoff + 11]
                ]);
                let start = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);
                let len = ee_len & 0x7FFF;
                unsafe {
                    INODE_EXTENTS[ext_count] = DataExtent { start_block: start, num_blocks: len };
                    INODE_EXTENT_COUNT = ext_count + 1;
                }
            }
        }
    }

    unsafe { INODE_EXTENT_COUNT }
}

/// Find a directory entry by name, scanning ALL blocks in the directory.
/// Handles multi-block directories and extent trees of any reasonable depth.
fn find_dir_entry(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    dir_inode: &Ext4Inode,
    name: &[u8]
) -> Option<u32> {
    // Get all data extents for this directory inode
    let extent_count = get_inode_extents(controller, target, lun, partition_lba, block_size, dir_inode);
    if extent_count == 0 {
        return None;
    }

    let sectors_per_block = block_size / 512;
    let block_data = unsafe { &mut *core::ptr::addr_of_mut!(DIR_BLOCK_DATA) };

    // Iterate ALL blocks across ALL extents
    for ext_i in 0..extent_count {
        let extent = unsafe { INODE_EXTENTS[ext_i] };

        for blk_offset in 0..extent.num_blocks {
            let phys_block = extent.start_block + blk_offset as u64;
            let block_lba = partition_lba + (phys_block * block_size as u64 / 512);

            // Read full directory block
            let mut read_ok = true;
            for s in 0..sectors_per_block.min(8) {
                let mut sector = [0u8; 512];
                if !controller.read_sector((block_lba + s as u64) as u32, &mut sector) {
                    read_ok = false;
                    break;
                }
                block_data[s as usize * 512..(s as usize + 1) * 512].copy_from_slice(&sector);
            }
            if !read_ok { continue; }

            // Parse directory entries in this block
            // Ext4DirEntry: inode(4) rec_len(2) name_len(1) file_type(1) name(variable)
            let mut offset = 0usize;
            while offset + 8 <= block_size as usize {
                let entry_inode = u32::from_le_bytes([
                    block_data[offset], block_data[offset + 1],
                    block_data[offset + 2], block_data[offset + 3]
                ]);
                let entry_rec_len = u16::from_le_bytes([
                    block_data[offset + 4], block_data[offset + 5]
                ]);
                let entry_name_len = block_data[offset + 6];

                if entry_rec_len == 0 { break; }
                if entry_inode == 0 {
                    offset += entry_rec_len as usize;
                    continue;
                }

                let name_end = offset + 8 + entry_name_len as usize;
                if name_end > block_size as usize { break; }

                let entry_name = &block_data[offset + 8..name_end];

                if entry_name == name {
                    return Some(entry_inode);
                }

                offset += entry_rec_len as usize;
            }
        }
    }

    None
}

// Static buffer for file contents - avoid 512-byte stack return
static mut FILE_CONTENTS: [u8; 512] = [0u8; 512];

/// Read file contents (first block only, up to 512 bytes)
/// Returns a reference to a static buffer
fn read_file_contents(
    controller: &mut DiskReader,
    target: u8,
    lun: u8,
    partition_lba: u64,
    block_size: u32,
    inode: &Ext4Inode
) -> Option<&'static [u8; 512]> {
    serial::println("DBG: read_file_contents");

    // Get the first data block (handling extents)
    let block_num = get_first_data_block(inode)?;
    serial::println("DBG: got block_num for file");

    let block_lba = partition_lba + (block_num * block_size as u64 / 512);

    let contents = unsafe { &mut *core::ptr::addr_of_mut!(FILE_CONTENTS) };
    if !controller.read_sector(block_lba as u32, contents) {
        return None;
    }

    serial::println("DBG: read file sector OK");
    Some(unsafe { &*core::ptr::addr_of!(FILE_CONTENTS) })
}

/// Parse PRETTY_NAME from os-release contents.
/// Writes directly to global OS_NAME_BUF and OS_NAME_LEN to avoid stack returns.
/// Returns true on success.
fn parse_pretty_name(contents: &[u8; 512]) -> bool {
    serial::println("DBG: parse_pretty_name");

    // Look for PRETTY_NAME="..."
    let pattern = b"PRETTY_NAME=\"";

    let mut start_idx = 0usize;
    let mut found = false;

    for i in 0..(512 - 13) {
        let mut matches = true;
        for j in 0..13 {
            if contents[i + j] != pattern[j] {
                matches = false;
                break;
            }
        }
        if matches {
            start_idx = i + 13;
            found = true;
            break;
        }
    }

    if !found {
        serial::println("DBG: PRETTY_NAME not found");
        return false;
    }

    // Find closing quote
    let mut end_idx = start_idx;
    while end_idx < 512 && contents[end_idx] != b'"' && contents[end_idx] != 0 {
        end_idx += 1;
    }

    let name_len = (end_idx - start_idx).min(64);

    // Write directly to global statics (avoids returning arrays on stack)
    unsafe {
        OS_NAME_LEN = name_len;
        for i in 0..64 {
            OS_NAME_BUF[i] = 0;
        }
        for i in 0..name_len {
            OS_NAME_BUF[i] = contents[start_idx + i];
        }
    }

    serial::print("Detected OS: ");
    for i in 0..name_len {
        unsafe { serial::print_char(OS_NAME_BUF[i]); }
    }
    serial::println("");

    serial::println("DBG: parse_pretty_name done");
    true
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

        // Read the IDENTIFY data (256 words = 512 bytes) that's waiting
        // We must read it to clear the buffer, and we extract size + model
        if status & ATA_STATUS_DRQ != 0 {
            let mut identify = [0u16; 256];
            insw(ATA_PRIMARY_DATA, &mut identify);

            // Words 27-46: Model number (40 ASCII chars, byte-swapped)
            let mut model = [0u8; 40];
            for i in 0..20 {
                let word = identify[27 + i];
                model[i * 2] = (word >> 8) as u8;
                model[i * 2 + 1] = (word & 0xFF) as u8;
            }
            // Trim trailing spaces
            let mut model_len = 40;
            while model_len > 0 && (model[model_len - 1] == b' ' || model[model_len - 1] == 0) {
                model_len -= 1;
            }

            // Words 60-61: Total sectors (28-bit LBA)
            let sectors_28 = (identify[61] as u64) << 16 | identify[60] as u64;
            // Words 100-103: Total sectors (48-bit LBA, if supported)
            let sectors_48 = (identify[103] as u64) << 48
                | (identify[102] as u64) << 32
                | (identify[101] as u64) << 16
                | identify[100] as u64;
            let total_sectors = if sectors_48 > 0 { sectors_48 } else { sectors_28 };
            let size_bytes = total_sectors * 512;

            record_disk(DiskType::AtaPio, size_bytes, &model, model_len);
        }

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
