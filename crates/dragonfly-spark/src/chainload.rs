//! Chainloading bootloaders
//!
//! To chainload GRUB/MBR, we need to:
//! 1. Load the MBR (first 512 bytes) to 0x7C00
//! 2. Switch from long mode (64-bit) to real mode (16-bit)
//! 3. Jump to 0x0000:0x7C00 with proper register setup
//!
//! The real mode transition from 64-bit long mode is complex:
//! - We're in 64-bit long mode (from our boot.s)
//! - Need to disable paging and exit long mode (clear LME in EFER)
//! - Transition to 32-bit protected mode
//! - Then to 16-bit protected mode
//! - Then disable protection and enter real mode
//! - All while keeping code executing properly

use crate::disk::{OsInfo, DiskType};
use crate::vga;
use crate::bios;
use crate::serial;

/// Buffer for MBR at the standard boot location
const BOOT_SECTOR_ADDR: u32 = 0x7C00;

/// Location where we'll place our real mode transition trampoline
const TRAMPOLINE_ADDR: u32 = 0x1000;

/// Chainload GRUB/MBR from the detected OS
pub fn boot_grub(os: &OsInfo) -> ! {
    vga::println("");
    vga::print("Chainloading boot sector...");
    vga::println("");

    // Use the cached MBR from disk detection
    // IMPORTANT: We don't re-read the disk here because that would
    // reinitialize VirtIO and break the BIOS's INT 13h setup!
    serial::println("Chainload: Using cached MBR from detection");
    let mbr = &os.mbr;

    // Determine boot drive number for BIOS
    let boot_drive: u8 = match os.disk_type {
        DiskType::AtaPio => {
            serial::println("Chainload: ATA disk -> drive 0x80");
            0x80
        }
        DiskType::Ahci { port } => {
            serial::print("Chainload: AHCI port ");
            serial::print_dec(port as u32);
            serial::println(" -> drive 0x80");
            0x80
        }
        DiskType::VirtioScsi { target, .. } => {
            serial::print("Chainload: VirtIO SCSI target ");
            serial::print_dec(target as u32);
            serial::println(" -> drive 0x80");
            0x80
        }
        DiskType::VirtioBlk => {
            serial::println("Chainload: VirtIO Block -> drive 0x80");
            0x80
        }
        DiskType::PvScsi { target, .. } => {
            serial::print("Chainload: PVSCSI target ");
            serial::print_dec(target as u32);
            serial::println(" -> drive 0x80");
            0x80
        }
        DiskType::BiosDirect { drive } => {
            serial::print("Chainload: BIOS direct drive 0x");
            serial::print_hex32(drive as u32);
            serial::println("");
            drive
        }
    };

    // Verify MBR signature
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        vga::print_error("Invalid MBR signature!");
        serial::print("MBR bytes 510-511: ");
        serial::print_hex32(mbr[510] as u32);
        serial::print(" ");
        serial::print_hex32(mbr[511] as u32);
        serial::println("");
        crate::halt();
    }

    vga::print_success("MBR loaded successfully");
    vga::println("");

    // Debug: print first bytes of MBR to serial
    serial::print("Chainload: MBR first 8 bytes: ");
    for i in 0..8 {
        serial::print_hex32(mbr[i] as u32);
        serial::print(" ");
    }
    serial::println("");
    serial::print("Chainload: MBR sig: ");
    serial::print_hex32(mbr[510] as u32);
    serial::print(" ");
    serial::print_hex32(mbr[511] as u32);
    serial::println("");

    vga::println("Switching to real mode and jumping to bootloader...");
    vga::println("");

    // Copy MBR to 0x7C00
    unsafe {
        core::ptr::copy_nonoverlapping(
            mbr.as_ptr(),
            BOOT_SECTOR_ADDR as *mut u8,
            512
        );
    }

    // Switch to real mode and jump to MBR
    // DL register should contain the boot drive number
    switch_to_real_mode_and_jump(boot_drive);
}

/// Boot into imaging environment
pub fn boot_imaging() -> ! {
    vga::println("");
    vga::println("Rebooting into imaging environment...");
    vga::println("(iPXE will chain to Alpine/Mage)");
    vga::println("");

    // Set a flag that iPXE can check, then reboot
    // The flag could be in a specific memory location or we could
    // just rely on iPXE's logic to check with the server

    // For now, just reboot - iPXE should handle the rest
    bios::reboot();
}

/// Load MBR from disk using VirtIO SCSI
/// NOTE: This reinitializes VirtIO which breaks BIOS INT 13h!
/// For chainloading, use the cached MBR from detection instead.
fn load_mbr_virtio(_target: u8, _lun: u8, _buffer: &mut [u8; 512]) -> bool {
    // DON'T reinitialize VirtIO SCSI here!
    // That would break the BIOS's INT 13h setup for the disk.
    // The MBR should be passed from disk detection instead.
    serial::println("Chainload: ERROR - should use cached MBR, not re-read!");
    false
}

/// Load MBR from disk using ATA PIO
fn load_mbr_ata(drive: u8, buffer: &mut [u8; 512]) -> bool {
    use crate::bios::{inb, outb, insw, io_wait};

    const ATA_PRIMARY_DATA: u16 = 0x1F0;
    const ATA_PRIMARY_ERROR: u16 = 0x1F1;
    const ATA_PRIMARY_SECTOR_COUNT: u16 = 0x1F2;
    const ATA_PRIMARY_LBA_LO: u16 = 0x1F3;
    const ATA_PRIMARY_LBA_MID: u16 = 0x1F4;
    const ATA_PRIMARY_LBA_HI: u16 = 0x1F5;
    const ATA_PRIMARY_DRIVE: u16 = 0x1F6;
    const ATA_PRIMARY_STATUS: u16 = 0x1F7;
    const ATA_PRIMARY_COMMAND: u16 = 0x1F7;

    const ATA_STATUS_BSY: u8 = 0x80;
    const ATA_STATUS_DRQ: u8 = 0x08;
    const ATA_STATUS_ERR: u8 = 0x01;
    const ATA_CMD_READ_SECTORS: u8 = 0x20;

    unsafe {
        // Wait for drive ready
        for _ in 0..100000 {
            if inb(ATA_PRIMARY_STATUS) & ATA_STATUS_BSY == 0 {
                break;
            }
        }

        // Select drive and LBA 0
        outb(ATA_PRIMARY_DRIVE, 0xE0 | ((drive & 1) << 4));
        io_wait();
        outb(ATA_PRIMARY_ERROR, 0);
        outb(ATA_PRIMARY_SECTOR_COUNT, 1);
        outb(ATA_PRIMARY_LBA_LO, 0);
        outb(ATA_PRIMARY_LBA_MID, 0);
        outb(ATA_PRIMARY_LBA_HI, 0);

        // Send read command
        outb(ATA_PRIMARY_COMMAND, ATA_CMD_READ_SECTORS);

        // Wait for data
        for _ in 0..100000 {
            let status = inb(ATA_PRIMARY_STATUS);
            if status & ATA_STATUS_ERR != 0 {
                return false;
            }
            if status & ATA_STATUS_DRQ != 0 {
                break;
            }
        }

        // Read 512 bytes
        let buffer_words = core::slice::from_raw_parts_mut(
            buffer.as_mut_ptr() as *mut u16,
            256
        );
        insw(ATA_PRIMARY_DATA, buffer_words);

        true
    }
}

/// 16-bit real mode trampoline code
/// This code will be copied to TRAMPOLINE_ADDR and executed
/// It runs in 16-bit protected mode, then switches to real mode
///
/// The machine code here is hand-assembled 16-bit x86:
/// - Disable protected mode
/// - Far jump to real mode
/// - Set up segments
/// - Output debug char to serial
/// - Jump to 0x7C00
static TRAMPOLINE_CODE: [u8; 52] = [
    // At this point we're in 16-bit protected mode with CS=0x18 (16-bit code)
    // DS/ES/SS = 0x20 (16-bit data)

    // mov eax, cr0
    0x0F, 0x20, 0xC0,
    // and al, 0xFE  (clear PE bit)
    0x24, 0xFE,
    // mov cr0, eax
    0x0F, 0x22, 0xC0,

    // Far jump to flush prefetch and enter real mode
    // jmp 0x0000:0x100D (TRAMPOLINE_ADDR + 13 = where real mode code starts)
    // Bytes 0-12 are protected mode code, real mode starts at byte 13
    0xEA, 0x0D, 0x10, 0x00, 0x00,

    // ===== NOW IN REAL MODE at offset 13 (0x0D) =====
    // Set up real mode segments
    // xor ax, ax
    0x31, 0xC0,
    // mov ds, ax
    0x8E, 0xD8,
    // mov es, ax
    0x8E, 0xC0,
    // mov fs, ax
    0x8E, 0xE0,
    // mov gs, ax
    0x8E, 0xE8,
    // mov ss, ax
    0x8E, 0xD0,

    // Set up stack at 0x7C00 (just below boot sector)
    // mov sp, 0x7C00
    0xBC, 0x00, 0x7C,

    // Output 'R' to serial port (COM1 = 0x3F8) to prove we reached real mode
    // mov dx, 0x3F8
    0xBA, 0xF8, 0x03,
    // mov al, 'R'
    0xB0, 0x52,
    // out dx, al
    0xEE,
    // Output '!' to show we're about to jump
    // mov al, '!'
    0xB0, 0x21,
    // out dx, al
    0xEE,
    // Output newline
    // mov al, '\n'
    0xB0, 0x0A,
    // out dx, al
    0xEE,

    // DL already has boot drive from earlier setup
    // Jump to MBR at 0x0000:0x7C00
    // jmp 0x0000:0x7C00
    0xEA, 0x00, 0x7C, 0x00, 0x00,

    // Padding to reach 64 bytes
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

/// GDT for real mode transition
/// Entry 0: Null descriptor
/// Entry 1: 32-bit code segment (selector 0x08)
/// Entry 2: 32-bit data segment (selector 0x10)
/// Entry 3: 16-bit code segment (selector 0x18) - base at TRAMPOLINE_ADDR
/// Entry 4: 16-bit data segment (selector 0x20)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

impl GdtEntry {
    const fn null() -> Self {
        Self { limit_low: 0, base_low: 0, base_middle: 0, access: 0, granularity: 0, base_high: 0 }
    }

    const fn code64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,      // Present, Ring 0, Code, Executable, Readable
            granularity: 0xAF, // 4KB granularity, 64-bit (L=1, D=0)
            base_high: 0
        }
    }

    const fn data64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,      // Present, Ring 0, Data, Writable
            granularity: 0xCF, // 4KB granularity, 32/64-bit data
            base_high: 0
        }
    }

    const fn code32() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,      // Present, Ring 0, Code, Executable, Readable
            granularity: 0xCF, // 4KB granularity, 32-bit
            base_high: 0
        }
    }

    const fn data32() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,      // Present, Ring 0, Data, Writable
            granularity: 0xCF, // 4KB granularity, 32-bit
            base_high: 0
        }
    }

    const fn code16(base: u32) -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: (base & 0xFFFF) as u16,
            base_middle: ((base >> 16) & 0xFF) as u8,
            access: 0x9A,      // Present, Ring 0, Code, Executable, Readable
            granularity: 0x0F, // Byte granularity, 16-bit
            base_high: ((base >> 24) & 0xFF) as u8
        }
    }

    const fn data16() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,      // Present, Ring 0, Data, Writable
            granularity: 0x0F, // Byte granularity, 16-bit
            base_high: 0
        }
    }
}

/// GDT pointer structure for 64-bit mode
#[repr(C, packed)]
struct GdtPtr64 {
    limit: u16,
    base: u64,
}

/// GDT pointer structure for 32-bit mode (stored in low memory)
#[repr(C, packed)]
struct GdtPtr32 {
    limit: u16,
    base: u32,
}

/// 32-bit trampoline address - must be in low memory (below 1MB)
const TRAMPOLINE_32BIT_ADDR: u32 = 0x0B00;

/// 32-bit trampoline code
/// This code runs after we exit long mode and enter 32-bit protected mode.
/// It then transitions to 16-bit protected mode and finally to real mode.
///
/// Layout at TRAMPOLINE_32BIT_ADDR (0x0B00):
/// - 32-bit protected mode code starts here
/// - Transitions to 16-bit protected mode
/// - Then to real mode
/// - Finally jumps to 0x7C00
static TRAMPOLINE_32BIT_CODE: [u8; 64] = [
    // === 32-bit protected mode code ===
    // At entry: DS/ES/SS = 0x20 (32-bit data), CS = 0x18 (32-bit code)
    // DL contains boot drive number

    // Load 16-bit data segments
    // mov ax, 0x28  (16-bit data selector)
    0x66, 0xB8, 0x28, 0x00,
    // mov ds, ax
    0x8E, 0xD8,
    // mov es, ax
    0x8E, 0xC0,
    // mov ss, ax
    0x8E, 0xD0,
    // mov fs, ax
    0x8E, 0xE0,
    // mov gs, ax
    0x8E, 0xE8,

    // Far jump to 16-bit protected mode code (at offset 32 in this trampoline)
    // jmp 0x30:0x0B20  (selector 0x30 = 16-bit code, offset = 0x0B00 + 32)
    0xEA, 0x20, 0x0B, 0x00, 0x00, 0x30, 0x00,

    // Padding to offset 32 (0x20)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90,

    // === 16-bit protected mode code (at offset 32 = 0x20) ===
    // Now in 16-bit protected mode

    // Clear PE bit in CR0 to enter real mode
    // mov eax, cr0
    0x0F, 0x20, 0xC0,
    // and al, 0xFE  (clear PE bit)
    0x24, 0xFE,
    // mov cr0, eax
    0x0F, 0x22, 0xC0,

    // Far jump to flush prefetch and enter real mode
    // jmp 0x0000:0x0B30 (real mode: segment 0, offset 0x0B00 + 48)
    0xEA, 0x30, 0x0B, 0x00, 0x00,

    // === Real mode code (at offset 48 = 0x30) ===
    // xor ax, ax
    0x31, 0xC0,
    // mov ds, ax
    0x8E, 0xD8,
    // mov es, ax
    0x8E, 0xC0,
    // mov ss, ax
    0x8E, 0xD0,
    // mov sp, 0x7C00
    0xBC, 0x00, 0x7C,

    // DL already has boot drive
    // jmp 0x0000:0x7C00
    0xEA, 0x00, 0x7C, 0x00, 0x00,

    // Padding to reach 64 bytes
    0x90, 0x90, 0x90,
];

/// Switch from 64-bit long mode to 16-bit real mode and jump to 0x7C00
///
/// Strategy:
/// 1. Copy 16-bit trampoline code to low memory (0x1000)
/// 2. Copy 32-bit trampoline code to low memory (0x0B00)
/// 3. Set up GDT with 64-bit, 32-bit, and 16-bit segments at known address
/// 4. Disable paging (must be done before exiting long mode)
/// 5. Clear LME bit in EFER MSR to exit long mode
/// 6. Load GDT with 32-bit segments
/// 7. Far jump to 32-bit protected mode trampoline
/// 8. 32-bit trampoline transitions to 16-bit, then real mode
/// 9. Real mode code jumps to 0x7C00
fn switch_to_real_mode_and_jump(boot_drive: u8) -> ! {
    // Copy 16-bit trampoline to low memory (used by 16-bit protected mode)
    unsafe {
        core::ptr::copy_nonoverlapping(
            TRAMPOLINE_CODE.as_ptr(),
            TRAMPOLINE_ADDR as *mut u8,
            TRAMPOLINE_CODE.len()
        );
    }

    // Copy 32-bit trampoline to low memory
    unsafe {
        core::ptr::copy_nonoverlapping(
            TRAMPOLINE_32BIT_CODE.as_ptr(),
            TRAMPOLINE_32BIT_ADDR as *mut u8,
            TRAMPOLINE_32BIT_CODE.len()
        );
    }

    // Build GDT in low memory
    // Layout:
    // 0x00: Null
    // 0x08: 64-bit code (current)
    // 0x10: 64-bit data (current)
    // 0x18: 32-bit code
    // 0x20: 32-bit data
    // 0x28: 16-bit data (base 0)
    // 0x30: 16-bit code (base 0)
    const GDT_ADDR: u32 = 0x0800;

    let gdt: [GdtEntry; 7] = [
        GdtEntry::null(),           // 0x00
        GdtEntry::code64(),         // 0x08
        GdtEntry::data64(),         // 0x10
        GdtEntry::code32(),         // 0x18
        GdtEntry::data32(),         // 0x20
        GdtEntry::data16(),         // 0x28
        GdtEntry::code16(0),        // 0x30 (base 0 for real mode transition)
    ];

    // GDT pointer for 32-bit mode (placed right after GDT)
    const GDT_PTR_ADDR: u32 = 0x07E0;

    unsafe {
        // Copy GDT to known location
        core::ptr::copy_nonoverlapping(
            gdt.as_ptr() as *const u8,
            GDT_ADDR as *mut u8,
            core::mem::size_of_val(&gdt)
        );

        // Set up 32-bit GDT pointer at known address
        let gdt_ptr32 = GdtPtr32 {
            limit: (core::mem::size_of_val(&gdt) - 1) as u16,
            base: GDT_ADDR,
        };
        core::ptr::copy_nonoverlapping(
            &gdt_ptr32 as *const GdtPtr32 as *const u8,
            GDT_PTR_ADDR as *mut u8,
            core::mem::size_of::<GdtPtr32>()
        );

        // Set up real mode IDT pointer (IVT at 0x0000, limit 0x3FF)
        const IDT_PTR_ADDR: u32 = 0x07D8;
        #[repr(C, packed)]
        struct IdtPtr32 {
            limit: u16,
            base: u32,
        }
        let idt_ptr = IdtPtr32 {
            limit: 0x03FF,
            base: 0x0000,
        };
        core::ptr::copy_nonoverlapping(
            &idt_ptr as *const IdtPtr32 as *const u8,
            IDT_PTR_ADDR as *mut u8,
            core::mem::size_of::<IdtPtr32>()
        );

        // Debug output
        serial::println("Chainload: About to switch from 64-bit to real mode");
        serial::print("Chainload: 32-bit trampoline at 0x");
        serial::print_hex32(TRAMPOLINE_32BIT_ADDR);
        serial::print(", GDT at 0x");
        serial::print_hex32(GDT_ADDR);
        serial::print(", boot drive = 0x");
        serial::print_hex32(boot_drive as u32);
        serial::println("");
        serial::println("Chainload: Exiting long mode NOW...");

        // Store boot drive in low memory where trampoline can access it
        // We'll load it into DL in the trampoline
        let drive_addr: *mut u8 = 0x0600 as *mut u8;
        *drive_addr = boot_drive;

        // Execute the long mode exit and transition to 32-bit
        // This is the critical sequence:
        // 1. Disable interrupts
        // 2. Load boot drive into DL
        // 3. Disable paging (clear PG bit in CR0)
        // 4. Clear LME bit in EFER MSR
        // 5. Load 32-bit GDT
        // 6. Load real mode IDT
        // 7. Load 32-bit data segments
        // 8. Far jump to 32-bit code segment
        core::arch::asm!(
            // Disable interrupts
            "cli",

            // Load boot drive into DL (survives mode transitions)
            "mov dl, [{drive_addr}]",

            // Disable paging: clear PG bit (bit 31) in CR0
            // Must use rax in 64-bit mode
            "mov rax, cr0",
            "and eax, 0x7FFFFFFF",
            "mov cr0, rax",

            // Clear LME bit in EFER MSR to exit long mode
            // EFER MSR is at 0xC0000080, LME is bit 8
            "mov ecx, 0xC0000080",
            "rdmsr",
            "and eax, 0xFFFFFEFF",  // Clear bit 8 (LME)
            "wrmsr",

            // Now we're in compatibility mode (32-bit in a 64-bit world)
            // Load 32-bit GDT
            "lgdt [0x07E0]",

            // Load real mode IDT
            "lidt [0x07D8]",

            // Load 32-bit data segment into all data segment registers
            // Selector 0x20 is our 32-bit data segment
            "mov ax, 0x20",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",

            // Set up stack in low memory
            "mov esp, 0x7000",

            // Far jump to 32-bit protected mode code
            // Use push/retfq to do a far return which acts as far jump
            // Push 32-bit code segment selector (0x18)
            "push 0x18",
            // Push 32-bit trampoline address
            "push {tramp32}",
            // Far return (pops RIP and CS)
            "retfq",

            drive_addr = in(reg) 0x0600u64,
            tramp32 = in(reg) TRAMPOLINE_32BIT_ADDR as u64,
            options(noreturn)
        );
    }
}
