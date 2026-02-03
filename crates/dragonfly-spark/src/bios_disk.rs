//! BIOS INT 13h disk access via real mode
//!
//! This module provides disk access using BIOS INT 13h by temporarily
//! switching from protected/long mode to real mode. This preserves BIOS state
//! and works with any disk the BIOS can access (including VirtIO).
//!
//! In 64-bit mode, we must first transition to 32-bit compatibility mode,
//! then to 16-bit protected mode, then to real mode.

use crate::serial;
#[cfg(not(target_arch = "x86_64"))]
use crate::vga;
#[cfg(target_arch = "x86_64")]
use crate::vga;

/// Buffer location for real mode code (must be < 1MB)
const REALMODE_CODE_ADDR: u32 = 0x1000;

/// Buffer location for disk data (must be < 1MB)
const DISK_BUFFER_ADDR: u32 = 0x2000;

/// GDT location for mode switching
const GDT_ADDR: u32 = 0x0800;

/// Result flag location
const RESULT_ADDR: u32 = 0x0600;

/// Location to store detected OS type
const OS_TYPE_ADDR: u32 = 0x0604;

/// Location to store saved ESP/RSP for return
const SAVED_SP_ADDR: u32 = 0x0608;

/// Return trampoline address (protected mode stub)
const RETURN_TRAMPOLINE_ADDR: u32 = 0x0A00;

/// Continuation address - where to jump after returning to protected mode
const CONTINUATION_ADDR: u32 = 0x060C;

/// MBR buffer location (separate from DISK_BUFFER for detection)
const MBR_BUFFER_ADDR: u32 = 0x3000;

/// 32-bit code trampoline for 64-bit mode (transition point)
#[cfg(target_arch = "x86_64")]
const TRAMPOLINE_32BIT_ADDR: u32 = 0x0B00;

/// Detected OS types
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum DetectedOs {
    Unknown = 0,
    Linux = 1,
    Windows = 2,
    GptSystem = 3,
    NoOs = 4,
    ReadError = 5,
}

/// GDT entry structure
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

    const fn code16() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,      // Present, ring 0, code, readable
            granularity: 0x0F, // 16-bit, byte granularity, limit 0xFFFFF
            base_high: 0
        }
    }

    const fn data16() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,      // Present, ring 0, data, writable
            granularity: 0x0F, // 16-bit, byte granularity
            base_high: 0
        }
    }

    const fn code32() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,      // Present, ring 0, code, readable
            granularity: 0xCF, // 32-bit, 4K granularity, limit 0xFFFFF
            base_high: 0
        }
    }

    const fn data32() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,      // Present, ring 0, data, writable
            granularity: 0xCF, // 32-bit, 4K granularity
            base_high: 0
        }
    }

    #[cfg(target_arch = "x86_64")]
    const fn code64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,      // Present, ring 0, code, readable
            granularity: 0xAF, // 64-bit, 4K granularity
            base_high: 0
        }
    }

    #[cfg(target_arch = "x86_64")]
    const fn data64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,      // Present, ring 0, data, writable
            granularity: 0xCF, // 64-bit compatible data segment
            base_high: 0
        }
    }
}

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct GdtPtr64 {
    limit: u16,
    base: u64,
}

// ============================================================================
// 64-bit implementations
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub fn detect_os_via_bios(drive: u8) -> (DetectedOs, [u8; 512]) {
    serial::println("BIOS: Detecting OS via INT 13h (64-bit mode)...");
    serial::println("BIOS: 64-bit -> 32-bit -> 16-bit -> real mode transition");

    unsafe {
        // Initialize result locations
        *(OS_TYPE_ADDR as *mut u8) = DetectedOs::Unknown as u8;
        *(SAVED_SP_ADDR as *mut u64) = 0;

        // Clear MBR buffer
        core::ptr::write_bytes(MBR_BUFFER_ADDR as *mut u8, 0, 512);

        // Build the GDT with all segment types for full transition
        // 0x00: null
        // 0x08: 16-bit code
        // 0x10: 16-bit data
        // 0x18: 32-bit code
        // 0x20: 32-bit data
        // 0x28: 64-bit code
        // 0x30: 64-bit data
        let gdt: [GdtEntry; 7] = [
            GdtEntry::null(),    // 0x00
            GdtEntry::code16(),  // 0x08
            GdtEntry::data16(),  // 0x10
            GdtEntry::code32(),  // 0x18
            GdtEntry::data32(),  // 0x20
            GdtEntry::code64(),  // 0x28
            GdtEntry::data64(),  // 0x30
        ];

        core::ptr::copy_nonoverlapping(
            gdt.as_ptr() as *const u8,
            GDT_ADDR as *mut u8,
            core::mem::size_of_val(&gdt)
        );

        // GDT pointer for 32-bit mode (used after leaving long mode)
        let gdt_ptr32 = GdtPtr {
            limit: (core::mem::size_of_val(&gdt) - 1) as u16,
            base: GDT_ADDR,
        };
        core::ptr::copy_nonoverlapping(
            &gdt_ptr32 as *const GdtPtr as *const u8,
            0x07E0 as *mut u8,
            6
        );

        // Real mode IDT pointer
        let idt_ptr = GdtPtr {
            limit: 0x03FF,
            base: 0x0000,
        };
        core::ptr::copy_nonoverlapping(
            &idt_ptr as *const GdtPtr as *const u8,
            0x07F0 as *mut u8,
            6
        );

        // Build the detection code (real mode) - same as 32-bit version
        build_detect_code(drive);

        // Build the return trampoline (switches back to protected mode)
        build_return_trampoline();

        // Build 32-bit trampoline that goes to 16-bit then real mode
        build_32bit_trampoline();

        // Build trampoline from 16-bit protected to real mode
        let to_real_trampoline: u32 = 0x0900;
        let tramp = to_real_trampoline as *mut u8;
        let mut i = 0;

        // mov eax, cr0
        *tramp.add(i) = 0x0F; i += 1;
        *tramp.add(i) = 0x20; i += 1;
        *tramp.add(i) = 0xC0; i += 1;
        // and al, 0xFE (clear PE)
        *tramp.add(i) = 0x24; i += 1;
        *tramp.add(i) = 0xFE; i += 1;
        // mov cr0, eax
        *tramp.add(i) = 0x0F; i += 1;
        *tramp.add(i) = 0x22; i += 1;
        *tramp.add(i) = 0xC0; i += 1;
        // Far jump to real mode code
        *tramp.add(i) = 0xEA; i += 1;
        *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
        *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
        *tramp.add(i) = 0x00; i += 1;
        *tramp.add(i) = 0x00; i += 1;

        serial::println("BIOS: Switching to real mode for detection (from long mode)...");

        // The 64-bit to real mode transition:
        // 1. Disable paging (exits long mode, enters 32-bit compatibility mode)
        // 2. Clear LME bit in EFER MSR
        // 3. Load 32-bit GDT
        // 4. Jump to 32-bit code segment
        // 5. From 32-bit, jump to 16-bit segment
        // 6. Clear PE bit, enter real mode

        // Store continuation address for return
        *(CONTINUATION_ADDR as *mut u32) = 0; // Will be set by return path

        // We need to execute 32-bit code to complete the transition
        // The inline asm will disable long mode and jump to our 32-bit trampoline

        core::arch::asm!(
            // Save RSP to known location
            "mov [{saved_sp}], rsp",

            // Disable interrupts
            "cli",

            // We need to exit long mode:
            // 1. Load 32-bit GDT (already at 0x07E0)
            // 2. Disable paging
            // 3. Clear LME in EFER
            // 4. Far jump to 32-bit code

            // Load identity-mapped CR3 if needed (we should already have one from boot)

            // Disable paging - this exits long mode compatibility mode
            "mov rax, cr0",
            "and eax, 0x7FFFFFFF",  // Clear PG bit (bit 31)
            "mov cr0, rax",

            // Clear LME bit in EFER MSR
            "mov ecx, 0xC0000080",  // EFER MSR
            "rdmsr",
            "and eax, 0xFFFFFEFF",  // Clear LME (bit 8)
            "wrmsr",

            // Now we're in 32-bit protected mode
            // Load 32-bit GDT
            "lgdt [0x07E0]",

            // Load 32-bit data segments
            "mov ax, 0x20",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            "mov esp, 0x7000",

            // Far jump to 32-bit code segment
            // This requires building the jump target on stack
            "push 0x18",              // 32-bit code segment selector
            "push {tramp32}",         // 32-bit trampoline address
            "retfq",                  // Far return (acts as far jump)

            saved_sp = in(reg) SAVED_SP_ADDR as u64,
            tramp32 = in(reg) TRAMPOLINE_32BIT_ADDR as u64,
            options(noreturn)
        );
    }
}

/// Build 32-bit trampoline code that continues transition to real mode
#[cfg(target_arch = "x86_64")]
unsafe fn build_32bit_trampoline() {
    let code = TRAMPOLINE_32BIT_ADDR as *mut u8;
    let mut i = 0;

    // Output 'T' to serial to show we reached 32-bit trampoline
    *code.add(i) = 0xBA; i += 1;  // mov dx, 0x3F8
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xB0; i += 1;  // mov al, 'T'
    *code.add(i) = 0x54; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Load 16-bit GDT (same GDT, different interpretation)
    // lgdt [0x07E0] - already loaded, but reload for safety
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x15; i += 1;  // lgdt [imm32]
    *code.add(i) = 0xE0; i += 1;
    *code.add(i) = 0x07; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // Load real mode IDT
    // lidt [0x07F0]
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x1D; i += 1;  // lidt [imm32]
    *code.add(i) = 0xF0; i += 1;
    *code.add(i) = 0x07; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // Load 16-bit data segments (selector 0x10)
    *code.add(i) = 0x66; i += 1;  // operand size prefix
    *code.add(i) = 0xB8; i += 1;  // mov ax, 0x10
    *code.add(i) = 0x10; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ds, ax
    *code.add(i) = 0xD8; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov es, ax
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov fs, ax
    *code.add(i) = 0xE0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov gs, ax
    *code.add(i) = 0xE8; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ss, ax
    *code.add(i) = 0xD0; i += 1;

    // mov esp, 0x7000
    *code.add(i) = 0xBC; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x70; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // Far jump to 16-bit code segment (selector 0x08), then to real mode trampoline
    // jmp 0x08:0x0900
    *code.add(i) = 0xEA; i += 1;
    *code.add(i) = 0x00; i += 1;  // offset low
    *code.add(i) = 0x09; i += 1;  // offset high (0x0900)
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x08; i += 1;  // selector low
    *code.add(i) = 0x00; i += 1;  // selector high

    serial::print("BIOS: 32-bit trampoline size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

#[cfg(target_arch = "x86_64")]
pub fn read_sector(drive: u8, lba: u32, buffer: &mut [u8; 512]) -> bool {
    serial::println("BIOS: read_sector not fully implemented for 64-bit yet");
    serial::println("BIOS: Use VirtIO-SCSI instead for disk access");
    false
}

#[cfg(target_arch = "x86_64")]
pub fn read_and_chainload(drive: u8) -> ! {
    serial::println("BIOS: Direct boot via INT 13h (64-bit mode)");
    vga::println("");
    vga::println("Booting from disk via BIOS (64-bit transition)...");

    unsafe {
        execute_realmode_boot_64(drive);
    }
}

#[cfg(target_arch = "x86_64")]
pub fn chainload_mbr(mbr: &[u8; 512], drive: u8) -> ! {
    serial::println("Chainloading with cached MBR (64-bit mode)");
    vga::println("");
    vga::println("Booting from cached MBR...");

    unsafe {
        // Copy MBR to 0x7C00
        core::ptr::copy_nonoverlapping(
            mbr.as_ptr(),
            0x7C00 as *mut u8,
            512
        );
        serial::println("MBR copied to 0x7C00");

        execute_realmode_jump_64(drive);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn execute_realmode_boot_64(drive: u8) -> ! {
    serial::println("BIOS: 64-bit -> real mode transition for boot...");

    // Build GDT with all segment types
    let gdt: [GdtEntry; 7] = [
        GdtEntry::null(),    // 0x00
        GdtEntry::code16(),  // 0x08
        GdtEntry::data16(),  // 0x10
        GdtEntry::code32(),  // 0x18
        GdtEntry::data32(),  // 0x20
        GdtEntry::code64(),  // 0x28
        GdtEntry::data64(),  // 0x30
    ];

    core::ptr::copy_nonoverlapping(
        gdt.as_ptr() as *const u8,
        GDT_ADDR as *mut u8,
        core::mem::size_of_val(&gdt)
    );

    let gdt_ptr32 = GdtPtr {
        limit: (core::mem::size_of_val(&gdt) - 1) as u16,
        base: GDT_ADDR,
    };
    core::ptr::copy_nonoverlapping(
        &gdt_ptr32 as *const GdtPtr as *const u8,
        0x07E0 as *mut u8,
        6
    );

    let idt_ptr = GdtPtr {
        limit: 0x03FF,
        base: 0x0000,
    };
    core::ptr::copy_nonoverlapping(
        &idt_ptr as *const GdtPtr as *const u8,
        0x07F0 as *mut u8,
        6
    );

    // Build boot code
    build_boot_code(drive);

    // Build 32-bit trampoline for boot
    build_32bit_boot_trampoline();

    // Build 16-bit to real mode trampoline
    let to_real_trampoline: u32 = 0x0900;
    let tramp = to_real_trampoline as *mut u8;
    let mut i = 0;

    *tramp.add(i) = 0x0F; i += 1;  // mov eax, cr0
    *tramp.add(i) = 0x20; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0x24; i += 1;  // and al, 0xFE
    *tramp.add(i) = 0xFE; i += 1;
    *tramp.add(i) = 0x0F; i += 1;  // mov cr0, eax
    *tramp.add(i) = 0x22; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0xEA; i += 1;  // far jmp
    *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
    *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0x00; i += 1;

    serial::println("BIOS: Executing 64-bit exit sequence...");

    core::arch::asm!(
        "cli",

        // Disable paging - exits long mode
        "mov rax, cr0",
        "and eax, 0x7FFFFFFF",
        "mov cr0, rax",

        // Clear LME in EFER
        "mov ecx, 0xC0000080",
        "rdmsr",
        "and eax, 0xFFFFFEFF",
        "wrmsr",

        // Load 32-bit GDT
        "lgdt [0x07E0]",

        // Load 32-bit data segments
        "mov ax, 0x20",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",
        "mov esp, 0x7000",

        // Far jump to 32-bit code
        "push 0x18",
        "push {tramp32}",
        "retfq",

        tramp32 = in(reg) TRAMPOLINE_32BIT_ADDR as u64,
        options(noreturn)
    );
}

#[cfg(target_arch = "x86_64")]
unsafe fn build_32bit_boot_trampoline() {
    let code = TRAMPOLINE_32BIT_ADDR as *mut u8;
    let mut i = 0;

    // Load IDT
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x1D; i += 1;
    *code.add(i) = 0xE8; i += 1;
    *code.add(i) = 0x07; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // Load 16-bit segments
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xB8; i += 1;
    *code.add(i) = 0x10; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD8; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xE0; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xE8; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD0; i += 1;

    *code.add(i) = 0xBC; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x70; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // Far jump to 16-bit
    *code.add(i) = 0xEA; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x09; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x08; i += 1;
    *code.add(i) = 0x00; i += 1;
}

#[cfg(target_arch = "x86_64")]
unsafe fn execute_realmode_jump_64(drive: u8) -> ! {
    serial::println("BIOS: 64-bit -> real mode jump to MBR...");

    let gdt: [GdtEntry; 7] = [
        GdtEntry::null(),
        GdtEntry::code16(),
        GdtEntry::data16(),
        GdtEntry::code32(),
        GdtEntry::data32(),
        GdtEntry::code64(),
        GdtEntry::data64(),
    ];

    core::ptr::copy_nonoverlapping(
        gdt.as_ptr() as *const u8,
        GDT_ADDR as *mut u8,
        core::mem::size_of_val(&gdt)
    );

    // In 64-bit mode, GDTR is 10 bytes (2-byte limit + 8-byte base)
    let gdt_ptr64 = GdtPtr64 {
        limit: (core::mem::size_of_val(&gdt) - 1) as u16,
        base: GDT_ADDR as u64,
    };
    core::ptr::copy_nonoverlapping(
        &gdt_ptr64 as *const GdtPtr64 as *const u8,
        0x07E0 as *mut u8,
        10
    );

    // IDT pointer for real mode (will be loaded from 32-bit code, so 6 bytes)
    let idt_ptr = GdtPtr {
        limit: 0x03FF,
        base: 0x0000,
    };
    core::ptr::copy_nonoverlapping(
        &idt_ptr as *const GdtPtr as *const u8,
        0x07F0 as *mut u8,  // Moved to avoid overlap with 10-byte GDT ptr
        6
    );

    build_jump_code(drive);
    // Note: build_32bit_compat_trampoline() is called later and handles the 32-bit code

    let to_real_trampoline: u32 = 0x0900;
    let tramp = to_real_trampoline as *mut u8;
    let mut i = 0;

    // Debug: Output 'E' - reached 16-bit protected mode
    *tramp.add(i) = 0xBA; i += 1;  // mov dx, 0x3F8
    *tramp.add(i) = 0xF8; i += 1;
    *tramp.add(i) = 0x03; i += 1;
    *tramp.add(i) = 0xB0; i += 1;  // mov al, 'E'
    *tramp.add(i) = 0x45; i += 1;
    *tramp.add(i) = 0xEE; i += 1;  // out dx, al

    *tramp.add(i) = 0x0F; i += 1;  // mov eax, cr0
    *tramp.add(i) = 0x20; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0x24; i += 1;
    *tramp.add(i) = 0xFE; i += 1;
    *tramp.add(i) = 0x0F; i += 1;
    *tramp.add(i) = 0x22; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0xEA; i += 1;
    *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
    *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0x00; i += 1;

    // Build the 32-bit trampoline that will disable paging and go to 16-bit
    // This MUST be built BEFORE we jump to it
    build_32bit_compat_trampoline();

    serial::println("DBG: About to enter inline asm");
    serial::print("DBG: tramp32 addr = 0x");
    serial::print_hex32(TRAMPOLINE_32BIT_ADDR);
    serial::println("");

    // Verify code at trampoline address
    let first_byte = unsafe { *(TRAMPOLINE_32BIT_ADDR as *const u8) };
    serial::print("DBG: first byte at trampoline = 0x");
    serial::print_hex32(first_byte as u32);
    serial::println("");

    // Strategy: Stay in long mode, far jump to compatibility mode (32-bit code segment)
    // The 32-bit trampoline at 0x0B00 will then safely disable paging and LME
    // This avoids mixing 64-bit instruction encoding with 32-bit execution

    // Intel says: to exit long mode, first switch to compatibility mode,
    // THEN disable paging, THEN clear LME.
    // We use an indirect far jump through memory to enter compatibility mode.

    // Set up 6-byte far pointer at 0x0650 for JMP m16:32
    // Format: [4-byte offset][2-byte selector]
    let far_ptr = 0x0650 as *mut u8;
    *far_ptr.add(0) = (TRAMPOLINE_32BIT_ADDR & 0xFF) as u8;        // 0x00
    *far_ptr.add(1) = ((TRAMPOLINE_32BIT_ADDR >> 8) & 0xFF) as u8; // 0x0B
    *far_ptr.add(2) = 0;  // high bytes of offset
    *far_ptr.add(3) = 0;
    *far_ptr.add(4) = 0x18;  // 32-bit code segment selector
    *far_ptr.add(5) = 0x00;

    core::arch::asm!(
        "cli",

        // Debug: output '1' via serial
        "mov dx, 0x3F8",
        "mov al, 0x31",
        "out dx, al",

        // Load GDT (still in long mode with paging)
        "lgdt [0x07E0]",

        // Debug: output '2'
        "mov al, 0x32",
        "out dx, al",

        // Set up stack
        "mov rsp, 0x7000",

        // Debug: output '3'
        "mov al, 0x33",
        "out dx, al",

        // Debug: output '4' before far jump
        "mov dx, 0x3F8",
        "mov al, 0x34",
        "out dx, al",

        // Far jump to compatibility mode (32-bit code segment)
        // Using indirect far jump through memory at 0x0650
        // The far pointer is 10 bytes: 8-byte offset + 2-byte selector
        "mov rax, 0x0650",
        "jmp fword ptr [rax]",

        options(noreturn)
    );
}

/// Build 32-bit trampoline that disables paging, clears LME, and enters real mode
/// This code runs in compatibility mode (32-bit code within long mode, paging still enabled)
#[cfg(target_arch = "x86_64")]
unsafe fn build_32bit_compat_trampoline() {
    let code = TRAMPOLINE_32BIT_ADDR as *mut u8;
    let mut i = 0;

    // === Compatibility mode (32-bit) code ===
    // We arrive here via far jump from 64-bit mode
    // Paging is still enabled, LME is still set

    // Debug: output 'T' for 32-bit trampoline reached
    *code.add(i) = 0xBA; i += 1;  // mov edx, 0x3F8
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xB0; i += 1;  // mov al, 'T'
    *code.add(i) = 0x54; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Disable paging (CR0.PG = 0) - this exits long mode
    // mov eax, cr0
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x20; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // and eax, 0x7FFFFFFF
    *code.add(i) = 0x25; i += 1;
    *code.add(i) = 0xFF; i += 1;
    *code.add(i) = 0xFF; i += 1;
    *code.add(i) = 0xFF; i += 1;
    *code.add(i) = 0x7F; i += 1;
    // mov cr0, eax
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x22; i += 1;
    *code.add(i) = 0xC0; i += 1;

    // Debug: output 'P' for paging disabled
    *code.add(i) = 0xB0; i += 1;  // mov al, 'P'
    *code.add(i) = 0x50; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Clear LME in EFER MSR
    // mov ecx, 0xC0000080
    *code.add(i) = 0xB9; i += 1;
    *code.add(i) = 0x80; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // rdmsr
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x32; i += 1;
    // and eax, 0xFFFFFEFF (clear bit 8)
    *code.add(i) = 0x25; i += 1;
    *code.add(i) = 0xFF; i += 1;
    *code.add(i) = 0xFE; i += 1;
    *code.add(i) = 0xFF; i += 1;
    *code.add(i) = 0xFF; i += 1;
    // wrmsr
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x30; i += 1;

    // Debug: output 'L' for LME cleared
    // Note: rdmsr clobbers EDX, so we need to reload it
    *code.add(i) = 0xBA; i += 1;  // mov edx, 0x3F8
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xB0; i += 1;  // mov al, 'L'
    *code.add(i) = 0x4C; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Now we're in real 32-bit protected mode (not long mode)
    // IMPORTANT: Must load valid 32-bit data segments BEFORE accessing memory!
    // DS may still have 64-bit selector from long mode.

    // Debug: output 'I' - about to load 32-bit data segments
    *code.add(i) = 0xB0; i += 1;  // mov al, 'I'
    *code.add(i) = 0x49; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Load 32-bit data segment (selector 0x20) first so we can access memory
    // In 32-bit mode, no operand size prefix needed
    *code.add(i) = 0xB8; i += 1;  // mov eax, 0x20
    *code.add(i) = 0x20; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ds, ax
    *code.add(i) = 0xD8; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov es, ax
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ss, ax
    *code.add(i) = 0xD0; i += 1;

    // Debug: output 'S' - segments loaded
    *code.add(i) = 0xB0; i += 1;  // mov al, 'S'
    *code.add(i) = 0x53; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Set stack (need SS loaded first)
    *code.add(i) = 0xBC; i += 1;  // mov esp, 0x7000
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x70; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // Debug: output 'D' - about to load IDT
    *code.add(i) = 0xB0; i += 1;  // mov al, 'D'
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Load real-mode IDT (now safe to access memory)
    // lidt [0x07F0]
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x1D; i += 1;
    *code.add(i) = 0xF0; i += 1;
    *code.add(i) = 0x07; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // Debug: output 'K' - IDT loaded, about to switch to 16-bit
    *code.add(i) = 0xB0; i += 1;  // mov al, 'K'
    *code.add(i) = 0x4B; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Now load 16-bit data segments for transition to 16-bit protected mode
    *code.add(i) = 0xB8; i += 1;  // mov eax, 0x10
    *code.add(i) = 0x10; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ds, ax
    *code.add(i) = 0xD8; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov es, ax
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov fs, ax
    *code.add(i) = 0xE0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov gs, ax
    *code.add(i) = 0xE8; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ss, ax
    *code.add(i) = 0xD0; i += 1;

    // Debug: output 'F' for about to far jump to 16-bit
    *code.add(i) = 0xB0; i += 1;  // mov al, 'F'
    *code.add(i) = 0x46; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Far jump to 16-bit code at 0x0900
    // jmp 0x08:0x0900
    *code.add(i) = 0xEA; i += 1;
    *code.add(i) = 0x00; i += 1;  // offset low
    *code.add(i) = 0x09; i += 1;  // offset high = 0x0900
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x08; i += 1;  // 16-bit code segment
    *code.add(i) = 0x00; i += 1;

    serial::print("32-bit compat trampoline size: ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

// ============================================================================
// Shared code builders (used by both 32-bit and 64-bit)
// ============================================================================

/// Build the real mode detection code
unsafe fn build_detect_code(drive: u8) {
    let code = REALMODE_CODE_ADDR as *mut u8;
    let mut i = 0;

    // Set up segments
    *code.add(i) = 0x31; i += 1;  // xor ax, ax
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ds, ax
    *code.add(i) = 0xD8; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov es, ax
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ss, ax
    *code.add(i) = 0xD0; i += 1;
    *code.add(i) = 0xBC; i += 1;  // mov sp, 0x7C00
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;

    // Output 'D' for detect
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0xEE; i += 1;

    // Set up DAP at 0x0500 to read MBR
    let dap_addr: u16 = 0x0500;

    *code.add(i) = 0xBE; i += 1;  // mov si, dap_addr
    *code.add(i) = (dap_addr & 0xFF) as u8; i += 1;
    *code.add(i) = ((dap_addr >> 8) & 0xFF) as u8; i += 1;

    // Build DAP inline
    *code.add(i) = 0xC6; i += 1;  // mov byte [si+0], 0x10
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0x10; i += 1;
    *code.add(i) = 0xC6; i += 1;  // mov byte [si+1], 0x00
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xC7; i += 1;  // mov word [si+2], 0x0001
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x02; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xC7; i += 1;  // mov word [si+4], MBR_BUFFER_ADDR low
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = (MBR_BUFFER_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((MBR_BUFFER_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 0xC7; i += 1;  // mov word [si+6], 0x0000
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    // LBA = 0
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x08; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x0C; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    *code.add(i) = 0xB2; i += 1;  // mov dl, drive
    *code.add(i) = drive; i += 1;
    *code.add(i) = 0xB4; i += 1;  // mov ah, 0x42
    *code.add(i) = 0x42; i += 1;

    *code.add(i) = 0xCD; i += 1;  // int 0x13
    *code.add(i) = 0x13; i += 1;

    // Check carry flag
    *code.add(i) = 0x72; i += 1;  // jc read_error
    let jc_offset_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Output 'R' for read OK
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x52; i += 1;
    *code.add(i) = 0xEE; i += 1;

    // Check MBR signature
    *code.add(i) = 0xBB; i += 1;  // mov bx, MBR_BUFFER_ADDR
    *code.add(i) = (MBR_BUFFER_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((MBR_BUFFER_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 0x81; i += 1;  // cmp word [bx+510], 0xAA55
    *code.add(i) = 0xBF; i += 1;
    *code.add(i) = 0xFE; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x55; i += 1;
    *code.add(i) = 0xAA; i += 1;
    *code.add(i) = 0x75; i += 1;  // jne no_os
    let jne_offset_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Check partition type
    *code.add(i) = 0x8A; i += 1;  // mov al, [bx+450]
    *code.add(i) = 0x87; i += 1;
    *code.add(i) = 0xC2; i += 1;
    *code.add(i) = 0x01; i += 1;

    // Check for GPT
    *code.add(i) = 0x3C; i += 1;  // cmp al, 0xEE
    *code.add(i) = 0xEE; i += 1;
    *code.add(i) = 0x74; i += 1;  // je gpt_found
    let je_gpt_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Check for Linux
    *code.add(i) = 0x3C; i += 1;  // cmp al, 0x83
    *code.add(i) = 0x83; i += 1;
    *code.add(i) = 0x74; i += 1;  // je linux_found
    let je_linux_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Check for NTFS
    *code.add(i) = 0x3C; i += 1;  // cmp al, 0x07
    *code.add(i) = 0x07; i += 1;
    *code.add(i) = 0x74; i += 1;  // je windows_found
    let je_windows_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Default: Linux
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 1; i += 1;
    *code.add(i) = 0xEB; i += 1;  // jmp return_to_pm
    let jmp_return_pos = i;
    *code.add(i) = 0x00; i += 1;

    // gpt_found:
    let gpt_found = i;
    *code.add(je_gpt_pos) = (gpt_found - je_gpt_pos - 1) as u8;
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 3; i += 1;
    *code.add(i) = 0xEB; i += 1;
    let jmp_return_pos2 = i;
    *code.add(i) = 0x00; i += 1;

    // linux_found:
    let linux_found = i;
    *code.add(je_linux_pos) = (linux_found - je_linux_pos - 1) as u8;
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 1; i += 1;
    *code.add(i) = 0xEB; i += 1;
    let jmp_return_pos3 = i;
    *code.add(i) = 0x00; i += 1;

    // windows_found:
    let windows_found = i;
    *code.add(je_windows_pos) = (windows_found - je_windows_pos - 1) as u8;
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 2; i += 1;
    *code.add(i) = 0xEB; i += 1;
    let jmp_return_pos4 = i;
    *code.add(i) = 0x00; i += 1;

    // no_os:
    let no_os = i;
    *code.add(jne_offset_pos) = (no_os - jne_offset_pos - 1) as u8;
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 4; i += 1;
    *code.add(i) = 0xEB; i += 1;
    let jmp_return_pos5 = i;
    *code.add(i) = 0x00; i += 1;

    // read_error:
    let read_error = i;
    *code.add(jc_offset_pos) = (read_error - jc_offset_pos - 1) as u8;
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 5; i += 1;

    // return_to_pm:
    let return_to_pm = i;
    *code.add(jmp_return_pos) = (return_to_pm - jmp_return_pos - 1) as u8;
    *code.add(jmp_return_pos2) = (return_to_pm - jmp_return_pos2 - 1) as u8;
    *code.add(jmp_return_pos3) = (return_to_pm - jmp_return_pos3 - 1) as u8;
    *code.add(jmp_return_pos4) = (return_to_pm - jmp_return_pos4 - 1) as u8;
    *code.add(jmp_return_pos5) = (return_to_pm - jmp_return_pos5 - 1) as u8;

    // Output 'P'
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x50; i += 1;
    *code.add(i) = 0xEE; i += 1;

    // For chainload, just halt here
    *code.add(i) = 0xFA; i += 1;  // cli
    *code.add(i) = 0xF4; i += 1;  // hlt
    *code.add(i) = 0xEB; i += 1;  // jmp $
    *code.add(i) = 0xFD; i += 1;

    serial::print("BIOS: Detect code size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

/// Build the return trampoline (32-bit protected mode code)
unsafe fn build_return_trampoline() {
    // For chainload, we don't return - just halt after detection
    serial::println("BIOS: Return trampoline built (no-op for chainload)");
}

/// Build simple real mode code that jumps to MBR at 0x7C00
unsafe fn build_jump_code(drive: u8) {
    let code = REALMODE_CODE_ADDR as *mut u8;
    let mut i = 0;

    // Set up segments
    *code.add(i) = 0x31; i += 1;  // xor ax, ax
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ds, ax
    *code.add(i) = 0xD8; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov es, ax
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;  // mov ss, ax
    *code.add(i) = 0xD0; i += 1;
    *code.add(i) = 0xBC; i += 1;  // mov sp, 0x7C00
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;

    // Reset video mode
    *code.add(i) = 0xB8; i += 1;  // mov ax, 0x0003
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xCD; i += 1;  // int 0x10
    *code.add(i) = 0x10; i += 1;

    // Output 'J'
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x4A; i += 1;
    *code.add(i) = 0xEE; i += 1;

    // Set boot drive
    *code.add(i) = 0xB2; i += 1;  // mov dl, drive
    *code.add(i) = drive; i += 1;

    // Jump to MBR
    *code.add(i) = 0xEA; i += 1;  // far jmp 0x0000:0x7C00
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    serial::print("Jump code size: ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

/// Build real mode code that reads MBR and chainloads
unsafe fn build_boot_code(drive: u8) {
    let code = REALMODE_CODE_ADDR as *mut u8;
    let mut i = 0;

    // Set up segments
    *code.add(i) = 0x31; i += 1;
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD8; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xC0; i += 1;
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD0; i += 1;
    *code.add(i) = 0xBC; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;

    // Output 'B'
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x42; i += 1;
    *code.add(i) = 0xEE; i += 1;

    // Set up DAP at 0x0500
    let dap_addr: u16 = 0x0500;

    *code.add(i) = 0xBE; i += 1;
    *code.add(i) = (dap_addr & 0xFF) as u8; i += 1;
    *code.add(i) = ((dap_addr >> 8) & 0xFF) as u8; i += 1;

    // Build DAP
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0x10; i += 1;
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x02; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x08; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x0C; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    *code.add(i) = 0xB2; i += 1;
    *code.add(i) = drive; i += 1;
    *code.add(i) = 0xB4; i += 1;
    *code.add(i) = 0x42; i += 1;

    *code.add(i) = 0xCD; i += 1;
    *code.add(i) = 0x13; i += 1;

    // Check result
    *code.add(i) = 0x50; i += 1;  // push ax
    *code.add(i) = 0x72; i += 1;  // jc error
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0xB0; i += 1;  // mov al, 'O'
    *code.add(i) = 0x4F; i += 1;
    *code.add(i) = 0xEB; i += 1;  // jmp output
    *code.add(i) = 0x02; i += 1;
    *code.add(i) = 0xB0; i += 1;  // mov al, 'E'
    *code.add(i) = 0x45; i += 1;
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xEE; i += 1;
    *code.add(i) = 0x58; i += 1;  // pop ax

    // If error, halt
    *code.add(i) = 0x73; i += 1;  // jnc ok
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0xFA; i += 1;
    *code.add(i) = 0xF4; i += 1;
    *code.add(i) = 0xEB; i += 1;
    *code.add(i) = 0xFD; i += 1;

    // Output '!'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x21; i += 1;
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xEE; i += 1;

    // Jump to MBR
    *code.add(i) = 0xEA; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    serial::print("BIOS: Boot code size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

// ============================================================================
// 32-bit implementations (original code)
// ============================================================================

#[cfg(not(target_arch = "x86_64"))]
pub fn detect_os_via_bios(drive: u8) -> (DetectedOs, [u8; 512]) {
    serial::println("BIOS: Detecting OS via INT 13h...");

    unsafe {
        *(OS_TYPE_ADDR as *mut u8) = DetectedOs::Unknown as u8;
        *(SAVED_SP_ADDR as *mut u32) = 0;

        core::ptr::write_bytes(MBR_BUFFER_ADDR as *mut u8, 0, 512);

        let gdt: [GdtEntry; 5] = [
            GdtEntry::null(),
            GdtEntry::code16(),
            GdtEntry::data16(),
            GdtEntry::code32(),
            GdtEntry::data32(),
        ];

        core::ptr::copy_nonoverlapping(
            gdt.as_ptr() as *const u8,
            GDT_ADDR as *mut u8,
            core::mem::size_of_val(&gdt)
        );

        let gdt_ptr = GdtPtr {
            limit: (core::mem::size_of_val(&gdt) - 1) as u16,
            base: GDT_ADDR,
        };

        let idt_ptr = GdtPtr {
            limit: 0x03FF,
            base: 0x0000,
        };

        build_detect_code(drive);
        build_return_trampoline();

        let to_real_trampoline: u32 = 0x0900;
        let tramp = to_real_trampoline as *mut u8;
        let mut i = 0;

        *tramp.add(i) = 0x0F; i += 1;
        *tramp.add(i) = 0x20; i += 1;
        *tramp.add(i) = 0xC0; i += 1;
        *tramp.add(i) = 0x24; i += 1;
        *tramp.add(i) = 0xFE; i += 1;
        *tramp.add(i) = 0x0F; i += 1;
        *tramp.add(i) = 0x22; i += 1;
        *tramp.add(i) = 0xC0; i += 1;
        *tramp.add(i) = 0xEA; i += 1;
        *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
        *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
        *tramp.add(i) = 0x00; i += 1;
        *tramp.add(i) = 0x00; i += 1;

        serial::println("BIOS: Switching to real mode for detection...");

        core::arch::asm!(
            "mov [{saved_esp}], esp",
            "lea eax, [2f]",
            "mov [{cont_addr}], eax",
            "cli",
            "mov eax, cr0",
            "and eax, 0x7FFFFFFF",
            "mov cr0, eax",
            "lgdt [{gdt_ptr}]",
            "lidt [{idt_ptr}]",
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            "mov esp, 0x7000",
            "push 0x08",
            "push {tramp}",
            "retf",
            "2:",
            "mov ax, 0x20",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            "mov esp, [{saved_esp}]",
            saved_esp = in(reg) SAVED_SP_ADDR,
            cont_addr = in(reg) CONTINUATION_ADDR,
            gdt_ptr = in(reg) &gdt_ptr,
            idt_ptr = in(reg) &idt_ptr,
            tramp = in(reg) to_real_trampoline,
            out("eax") _,
        );

        let os_type_byte = *(OS_TYPE_ADDR as *const u8);
        let os_type = match os_type_byte {
            1 => DetectedOs::Linux,
            2 => DetectedOs::Windows,
            3 => DetectedOs::GptSystem,
            4 => DetectedOs::NoOs,
            5 => DetectedOs::ReadError,
            _ => DetectedOs::Unknown,
        };

        let mut mbr = [0u8; 512];
        core::ptr::copy_nonoverlapping(
            MBR_BUFFER_ADDR as *const u8,
            mbr.as_mut_ptr(),
            512
        );

        serial::print("BIOS: Detection complete, OS type = ");
        serial::print_dec(os_type_byte as u32);
        serial::println("");

        (os_type, mbr)
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn read_sector(drive: u8, lba: u32, buffer: &mut [u8; 512]) -> bool {
    serial::println("BIOS: Reading sector via INT 13h");
    // Implementation for 32-bit is same as before
    false // Stub for now - use VirtIO-SCSI
}

#[cfg(not(target_arch = "x86_64"))]
pub fn read_and_chainload(drive: u8) -> ! {
    serial::println("BIOS: Direct boot via INT 13h");
    vga::println("");
    vga::println("Booting from disk via BIOS...");

    unsafe {
        execute_realmode_boot_32(drive);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn chainload_mbr(mbr: &[u8; 512], drive: u8) -> ! {
    serial::println("Chainloading with cached MBR (no BIOS read needed)");
    vga::println("");
    vga::println("Booting from cached MBR...");

    unsafe {
        core::ptr::copy_nonoverlapping(
            mbr.as_ptr(),
            0x7C00 as *mut u8,
            512
        );
        serial::println("MBR copied to 0x7C00");
        execute_realmode_jump_32(drive);
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn execute_realmode_boot_32(drive: u8) -> ! {
    serial::println("BIOS: Switching to real mode for direct boot...");

    let gdt: [GdtEntry; 3] = [
        GdtEntry::null(),
        GdtEntry::code16(),
        GdtEntry::data16(),
    ];

    core::ptr::copy_nonoverlapping(
        gdt.as_ptr() as *const u8,
        GDT_ADDR as *mut u8,
        core::mem::size_of_val(&gdt)
    );

    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of_val(&gdt) - 1) as u16,
        base: GDT_ADDR,
    };

    let idt_ptr = GdtPtr {
        limit: 0x03FF,
        base: 0x0000,
    };

    build_boot_code(drive);

    let trampoline_addr: u32 = 0x0900;
    let tramp = trampoline_addr as *mut u8;
    let mut i = 0;

    *tramp.add(i) = 0x0F; i += 1;
    *tramp.add(i) = 0x20; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0x24; i += 1;
    *tramp.add(i) = 0xFE; i += 1;
    *tramp.add(i) = 0x0F; i += 1;
    *tramp.add(i) = 0x22; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0xEA; i += 1;
    *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
    *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0x00; i += 1;

    core::arch::asm!(
        "cli",
        "mov eax, cr0",
        "and eax, 0x7FFFFFFF",
        "mov cr0, eax",
        "lgdt [{gdt_ptr}]",
        "lidt [{idt_ptr}]",
        "mov ax, 0x10",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",
        "mov esp, 0x7000",
        "push 0x08",
        "push {tramp}",
        "retf",
        gdt_ptr = in(reg) &gdt_ptr,
        idt_ptr = in(reg) &idt_ptr,
        tramp = in(reg) trampoline_addr,
        options(noreturn)
    );
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn execute_realmode_jump_32(drive: u8) -> ! {
    serial::println("Switching to real mode (simple jump)...");

    let gdt: [GdtEntry; 3] = [
        GdtEntry::null(),
        GdtEntry::code16(),
        GdtEntry::data16(),
    ];

    core::ptr::copy_nonoverlapping(
        gdt.as_ptr() as *const u8,
        GDT_ADDR as *mut u8,
        core::mem::size_of_val(&gdt)
    );

    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of_val(&gdt) - 1) as u16,
        base: GDT_ADDR,
    };

    let idt_ptr = GdtPtr {
        limit: 0x03FF,
        base: 0x0000,
    };

    build_jump_code(drive);

    let trampoline_addr: u32 = 0x0900;
    let tramp = trampoline_addr as *mut u8;
    let mut i = 0;

    *tramp.add(i) = 0x0F; i += 1;
    *tramp.add(i) = 0x20; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0x24; i += 1;
    *tramp.add(i) = 0xFE; i += 1;
    *tramp.add(i) = 0x0F; i += 1;
    *tramp.add(i) = 0x22; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0xEA; i += 1;
    *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
    *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0x00; i += 1;

    core::arch::asm!(
        "cli",
        "mov eax, cr0",
        "and eax, 0x7FFFFFFF",
        "mov cr0, eax",
        "lgdt [{gdt_ptr}]",
        "lidt [{idt_ptr}]",
        "mov ax, 0x10",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",
        "mov esp, 0x7000",
        "push 0x08",
        "push {tramp}",
        "retf",
        gdt_ptr = in(reg) &gdt_ptr,
        idt_ptr = in(reg) &idt_ptr,
        tramp = in(reg) trampoline_addr,
        options(noreturn)
    );
}
