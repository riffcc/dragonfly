//! VBE (VESA BIOS Extensions) mode switching via real mode
//!
//! This module sets up VBE graphics mode by dropping to real mode and calling
//! INT 10h VBE functions. This allows Spark to have graphics even when the
//! bootloader (iPXE) doesn't provide framebuffer info.
//!
//! The approach mirrors bios_disk.rs: 64-bit → 32-bit → 16-bit → real mode → back.

use crate::serial;
use crate::framebuffer::Framebuffer;

/// VBE info structure location (must be < 1MB, 512 bytes needed)
const VBE_INFO_ADDR: u32 = 0x4000;

/// VBE mode info structure location (256 bytes needed)
const VBE_MODE_INFO_ADDR: u32 = 0x4200;

/// Real mode code location
const VBE_CODE_ADDR: u32 = 0x5000;

/// Result storage location
const VBE_RESULT_ADDR: u32 = 0x4400;

/// GDT location for mode switching (shared with bios_disk)
const GDT_ADDR: u32 = 0x0800;

/// 32-bit trampoline address
const TRAMPOLINE_32BIT_ADDR: u32 = 0x5800;

/// 16-bit to real mode trampoline
const TO_REAL_TRAMPOLINE_ADDR: u32 = 0x5900;

/// Saved stack pointer
const SAVED_SP_ADDR: u32 = 0x5A00;

/// VBE mode we want: 1024x768x32 with linear framebuffer
/// Mode 0x118 = 1024x768 (depth varies), 0x4000 = LFB flag
/// For 32bpp, some BIOSes use 0x118, others use different modes
/// We'll try standard VESA modes
const VBE_MODE_1024x768: u16 = 0x118;  // Standard 1024x768
const VBE_LFB_FLAG: u16 = 0x4000;      // Request linear framebuffer

/// GDT entry structure (same as bios_disk)
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
            access: 0x9A,
            granularity: 0x0F,
            base_high: 0
        }
    }

    const fn data16() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,
            granularity: 0x0F,
            base_high: 0
        }
    }

    const fn code32() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,
            granularity: 0xCF,
            base_high: 0
        }
    }

    const fn data32() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,
            granularity: 0xCF,
            base_high: 0
        }
    }

    const fn code64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x9A,
            granularity: 0xAF,
            base_high: 0
        }
    }

    const fn data64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_middle: 0,
            access: 0x92,
            granularity: 0xCF,
            base_high: 0
        }
    }
}

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u32,
}

/// VBE mode info structure (partial - we only need some fields)
#[repr(C, packed)]
struct VbeModeInfo {
    attributes: u16,          // 0
    window_a: u8,             // 2
    window_b: u8,             // 3
    granularity: u16,         // 4
    window_size: u16,         // 6
    segment_a: u16,           // 8
    segment_b: u16,           // 10
    win_func_ptr: u32,        // 12
    pitch: u16,               // 16 - bytes per scan line
    width: u16,               // 18 - horizontal resolution
    height: u16,              // 20 - vertical resolution
    w_char: u8,               // 22
    y_char: u8,               // 23
    planes: u8,               // 24
    bpp: u8,                  // 25 - bits per pixel
    banks: u8,                // 26
    memory_model: u8,         // 27
    bank_size: u8,            // 28
    image_pages: u8,          // 29
    reserved0: u8,            // 30
    red_mask: u8,             // 31
    red_position: u8,         // 32
    green_mask: u8,           // 33
    green_position: u8,       // 34
    blue_mask: u8,            // 35
    blue_position: u8,        // 36
    rsv_mask: u8,             // 37
    rsv_position: u8,         // 38
    direct_color_attributes: u8, // 39
    framebuffer: u32,         // 40 - physical address of LFB
    offscreen_mem: u32,       // 44
    offscreen_size: u16,      // 48
}

/// Try to set VBE graphics mode
/// Returns Some(Framebuffer) on success, None on failure
pub fn set_graphics_mode() -> Option<Framebuffer> {
    serial::println("VBE: Attempting to set graphics mode via BIOS...");

    unsafe {
        // Clear result area
        *(VBE_RESULT_ADDR as *mut u32) = 0;
        core::ptr::write_bytes(VBE_MODE_INFO_ADDR as *mut u8, 0, 256);

        // Build GDT
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

        // GDT pointer for 64-bit mode (10 bytes: 2-byte limit + 8-byte base)
        // We'll store it at 0x07D8 to leave room for 10 bytes
        let gdt_ptr_addr = 0x07D8 as *mut u8;
        let limit = (core::mem::size_of_val(&gdt) - 1) as u16;
        // Write limit (2 bytes)
        gdt_ptr_addr.add(0).write((limit & 0xFF) as u8);
        gdt_ptr_addr.add(1).write(((limit >> 8) & 0xFF) as u8);
        // Write base (8 bytes, but our GDT is in low memory so upper 4 are zero)
        gdt_ptr_addr.add(2).write((GDT_ADDR & 0xFF) as u8);
        gdt_ptr_addr.add(3).write(((GDT_ADDR >> 8) & 0xFF) as u8);
        gdt_ptr_addr.add(4).write(((GDT_ADDR >> 16) & 0xFF) as u8);
        gdt_ptr_addr.add(5).write(((GDT_ADDR >> 24) & 0xFF) as u8);
        gdt_ptr_addr.add(6).write(0);  // Upper 32 bits = 0
        gdt_ptr_addr.add(7).write(0);
        gdt_ptr_addr.add(8).write(0);
        gdt_ptr_addr.add(9).write(0);

        // Also set up 32-bit GDT pointer at 0x07E0 for use after transition
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

        // Build the VBE code (runs in real mode)
        build_vbe_code();

        // Build 32-bit trampoline
        build_32bit_trampoline();

        // Build 16-bit to real mode trampoline
        build_16bit_to_real_trampoline();

        serial::println("VBE: Switching to real mode...");

        // Execute the transition to real mode
        // This is non-returning - we use a continuation callback mechanism
        execute_vbe_transition();

        // Check result
        let result = *(VBE_RESULT_ADDR as *const u32);

        if result != 0x004F {
            serial::print("VBE: Set mode failed, result=0x");
            serial::print_hex32(result);
            serial::println("");
            return None;
        }

        // Read mode info from where real mode code stored it
        let mode_info = &*(VBE_MODE_INFO_ADDR as *const VbeModeInfo);

        serial::print("VBE: Mode set! ");
        serial::print_dec(mode_info.width as u32);
        serial::print("x");
        serial::print_dec(mode_info.height as u32);
        serial::print("x");
        serial::print_dec(mode_info.bpp as u32);
        serial::print(" @ 0x");
        serial::print_hex32(mode_info.framebuffer);
        serial::print(" pitch=");
        serial::print_dec(mode_info.pitch as u32);
        serial::println("");

        Some(Framebuffer {
            addr: mode_info.framebuffer,
            pitch: mode_info.pitch as u32,
            width: mode_info.width as u32,
            height: mode_info.height as u32,
            bpp: mode_info.bpp,
        })
    }
}

/// Build real mode code that sets VBE mode
unsafe fn build_vbe_code() {
    let code = VBE_CODE_ADDR as *mut u8;
    let mut i = 0;

    // Real mode code - sets VBE mode and gets mode info
    // We're now in real mode with CS:IP = 0000:5000

    // Set up segments
    // xor ax, ax
    code.add(i).write(0x31); i += 1;
    code.add(i).write(0xC0); i += 1;
    // mov ds, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xD8); i += 1;
    // mov es, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xC0); i += 1;
    // mov ss, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xD0); i += 1;
    // mov sp, 0x7000
    code.add(i).write(0xBC); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x70); i += 1;

    // Output 'V' to serial for debugging
    // mov dx, 0x3F8
    code.add(i).write(0xBA); i += 1;
    code.add(i).write(0xF8); i += 1;
    code.add(i).write(0x03); i += 1;
    // mov al, 'V'
    code.add(i).write(0xB0); i += 1;
    code.add(i).write(0x56); i += 1;
    // out dx, al
    code.add(i).write(0xEE); i += 1;

    // First, get VBE mode info for our target mode
    // mov ax, 0x4F01  (VBE Get Mode Info)
    code.add(i).write(0xB8); i += 1;
    code.add(i).write(0x01); i += 1;
    code.add(i).write(0x4F); i += 1;
    // mov cx, mode (0x118 for 1024x768)
    code.add(i).write(0xB9); i += 1;
    code.add(i).write((VBE_MODE_1024x768 & 0xFF) as u8); i += 1;
    code.add(i).write(((VBE_MODE_1024x768 >> 8) & 0xFF) as u8); i += 1;
    // mov di, VBE_MODE_INFO_ADDR (ES:DI points to buffer)
    code.add(i).write(0xBF); i += 1;
    code.add(i).write((VBE_MODE_INFO_ADDR & 0xFF) as u8); i += 1;
    code.add(i).write(((VBE_MODE_INFO_ADDR >> 8) & 0xFF) as u8); i += 1;
    // int 0x10
    code.add(i).write(0xCD); i += 1;
    code.add(i).write(0x10); i += 1;

    // Output 'E' for mode info done
    code.add(i).write(0xBA); i += 1;
    code.add(i).write(0xF8); i += 1;
    code.add(i).write(0x03); i += 1;
    code.add(i).write(0xB0); i += 1;
    code.add(i).write(0x45); i += 1;  // 'E'
    code.add(i).write(0xEE); i += 1;

    // Now set the mode with LFB
    // mov ax, 0x4F02  (VBE Set Mode)
    code.add(i).write(0xB8); i += 1;
    code.add(i).write(0x02); i += 1;
    code.add(i).write(0x4F); i += 1;
    // mov bx, mode | LFB_FLAG (0x4118)
    let mode_with_lfb = VBE_MODE_1024x768 | VBE_LFB_FLAG;
    code.add(i).write(0xBB); i += 1;
    code.add(i).write((mode_with_lfb & 0xFF) as u8); i += 1;
    code.add(i).write(((mode_with_lfb >> 8) & 0xFF) as u8); i += 1;
    // int 0x10
    code.add(i).write(0xCD); i += 1;
    code.add(i).write(0x10); i += 1;

    // Store result (AX) to VBE_RESULT_ADDR
    // mov [VBE_RESULT_ADDR], ax
    code.add(i).write(0xA3); i += 1;
    code.add(i).write((VBE_RESULT_ADDR & 0xFF) as u8); i += 1;
    code.add(i).write(((VBE_RESULT_ADDR >> 8) & 0xFF) as u8); i += 1;

    // Output 'S' for set mode done
    code.add(i).write(0xBA); i += 1;
    code.add(i).write(0xF8); i += 1;
    code.add(i).write(0x03); i += 1;
    code.add(i).write(0xB0); i += 1;
    code.add(i).write(0x53); i += 1;  // 'S'
    code.add(i).write(0xEE); i += 1;

    // Return to protected mode
    // cli
    code.add(i).write(0xFA); i += 1;
    // lgdt [0x07E0]
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x01); i += 1;
    code.add(i).write(0x16); i += 1;
    code.add(i).write(0xE0); i += 1;
    code.add(i).write(0x07); i += 1;

    // mov eax, cr0
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x20); i += 1;
    code.add(i).write(0xC0); i += 1;
    // or al, 1 (set PE)
    code.add(i).write(0x0C); i += 1;
    code.add(i).write(0x01); i += 1;
    // mov cr0, eax
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x22); i += 1;
    code.add(i).write(0xC0); i += 1;

    // Far jump to 32-bit protected mode (to return trampoline)
    // jmp 0x18:return_addr (we'll use a known return point)
    code.add(i).write(0x66); i += 1;  // operand size prefix
    code.add(i).write(0xEA); i += 1;  // far jmp
    // Return address - we'll jump to a 32-bit return stub
    let return_addr: u32 = 0x5A10;  // Return stub address
    code.add(i).write((return_addr & 0xFF) as u8); i += 1;
    code.add(i).write(((return_addr >> 8) & 0xFF) as u8); i += 1;
    code.add(i).write(((return_addr >> 16) & 0xFF) as u8); i += 1;
    code.add(i).write(((return_addr >> 24) & 0xFF) as u8); i += 1;
    code.add(i).write(0x18); i += 1;  // 32-bit code segment
    code.add(i).write(0x00); i += 1;

    serial::print("VBE: Real mode code size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");

    // Now build the 32-bit return stub that goes back to 64-bit
    build_return_stub();
}

/// Build the 32-bit return stub that transitions back to 64-bit long mode
unsafe fn build_return_stub() {
    let code = 0x5A10 as *mut u8;
    let mut i = 0;

    // We're now in 32-bit protected mode
    // Need to: set up segments, enable PAE, enable LME, enable paging, far jump to 64-bit

    // Load 32-bit data segments
    // mov ax, 0x20
    code.add(i).write(0x66); i += 1;
    code.add(i).write(0xB8); i += 1;
    code.add(i).write(0x20); i += 1;
    code.add(i).write(0x00); i += 1;
    // mov ds, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xD8); i += 1;
    // mov es, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xC0); i += 1;
    // mov ss, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xD0); i += 1;
    // mov fs, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xE0); i += 1;
    // mov gs, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xE8); i += 1;

    // Output 'R' to serial
    code.add(i).write(0xBA); i += 1;
    code.add(i).write(0xF8); i += 1;
    code.add(i).write(0x03); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0xB0); i += 1;
    code.add(i).write(0x52); i += 1;  // 'R'
    code.add(i).write(0xEE); i += 1;

    // We need to re-enable long mode. The page tables should still be in memory
    // from the original boot setup. We need to:
    // 1. Load CR3 with our page table address
    // 2. Enable PAE in CR4
    // 3. Set LME in EFER
    // 4. Enable paging in CR0
    // 5. Far jump to 64-bit code

    // The original page tables are at p4_table which is in the BSS section
    // For simplicity, we'll use a fixed address - boot.s puts p4_table at a known location
    // Actually we stored the CR3 value, let's use that
    // For now, use identity mapping setup - p4_table is defined in boot.s
    // We'll reference the external symbol

    // Actually, let's use a simpler approach: store CR3 before transitioning
    // and restore it here. But that requires setup. For now, let's use a
    // continuation approach where we mark completion and spin, then the
    // original 64-bit code checks for completion.

    // Mark completion at SAVED_SP_ADDR with a magic value
    // mov dword [0x5A00], 0xDEADBEEF
    code.add(i).write(0xC7); i += 1;
    code.add(i).write(0x05); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x5A); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0xEF); i += 1;
    code.add(i).write(0xBE); i += 1;
    code.add(i).write(0xAD); i += 1;
    code.add(i).write(0xDE); i += 1;

    // Halt - we can't easily return to 64-bit, so we'll spin
    // The 64-bit code will check the completion flag
    // Actually this is problematic. Let's implement proper return.

    // For proper return to long mode, we need the original page tables.
    // Let's store CR3 before the transition.
    // We'll store it at 0x5A04

    // Load stored CR3
    // mov eax, [0x5A04]
    code.add(i).write(0xA1); i += 1;
    code.add(i).write(0x04); i += 1;
    code.add(i).write(0x5A); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    // mov cr3, eax
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x22); i += 1;
    code.add(i).write(0xD8); i += 1;

    // Enable PAE (bit 5 of CR4)
    // mov eax, cr4
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x20); i += 1;
    code.add(i).write(0xE0); i += 1;
    // or eax, 0x20
    code.add(i).write(0x0D); i += 1;
    code.add(i).write(0x20); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    // mov cr4, eax
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x22); i += 1;
    code.add(i).write(0xE0); i += 1;

    // Set LME bit in EFER MSR (bit 8)
    // mov ecx, 0xC0000080
    code.add(i).write(0xB9); i += 1;
    code.add(i).write(0x80); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0xC0); i += 1;
    // rdmsr
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x32); i += 1;
    // or eax, 0x100
    code.add(i).write(0x0D); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x01); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    // wrmsr
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x30); i += 1;

    // Enable paging (bit 31 of CR0)
    // mov eax, cr0
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x20); i += 1;
    code.add(i).write(0xC0); i += 1;
    // or eax, 0x80000000
    code.add(i).write(0x0D); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x80); i += 1;
    // mov cr0, eax
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x22); i += 1;
    code.add(i).write(0xC0); i += 1;

    // Load 64-bit GDT pointer (we need to set this up)
    // For now, use the same GDT with 64-bit selector
    // lgdt [0x07E0] - already has our GDT
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x01); i += 1;
    code.add(i).write(0x15); i += 1;
    code.add(i).write(0xE0); i += 1;
    code.add(i).write(0x07); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;

    // Far jump to 64-bit code segment (selector 0x28)
    // We'll jump to a 64-bit trampoline that restores RSP and returns
    // jmp 0x28:vbe_return_64
    let return_64_addr: u32 = 0x5B00;
    code.add(i).write(0xEA); i += 1;
    code.add(i).write((return_64_addr & 0xFF) as u8); i += 1;
    code.add(i).write(((return_64_addr >> 8) & 0xFF) as u8); i += 1;
    code.add(i).write(((return_64_addr >> 16) & 0xFF) as u8); i += 1;
    code.add(i).write(((return_64_addr >> 24) & 0xFF) as u8); i += 1;
    code.add(i).write(0x28); i += 1;  // 64-bit code segment
    code.add(i).write(0x00); i += 1;

    serial::print("VBE: Return stub size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");

    // Build 64-bit return trampoline
    build_64bit_return();
}

/// Build 64-bit return trampoline
unsafe fn build_64bit_return() {
    let code = 0x5B00 as *mut u8;
    let mut i = 0;

    // We're now in 64-bit long mode
    // Restore segments and stack, then return

    // Clear data segments (use 64-bit data selector 0x30 or just 0)
    // xor ax, ax
    code.add(i).write(0x66); i += 1;
    code.add(i).write(0x31); i += 1;
    code.add(i).write(0xC0); i += 1;
    // mov ds, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xD8); i += 1;
    // mov es, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xC0); i += 1;
    // mov fs, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xE0); i += 1;
    // mov gs, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xE8); i += 1;
    // mov ss, ax
    code.add(i).write(0x8E); i += 1;
    code.add(i).write(0xD0); i += 1;

    // Restore RSP from saved location (0x5A08)
    // mov rsp, [0x5A08]
    code.add(i).write(0x48); i += 1;  // REX.W
    code.add(i).write(0x8B); i += 1;
    code.add(i).write(0x24); i += 1;
    code.add(i).write(0x25); i += 1;
    code.add(i).write(0x08); i += 1;
    code.add(i).write(0x5A); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;

    // Mark completion
    // mov dword [0x5A00], 0xDEADBEEF
    code.add(i).write(0xC7); i += 1;
    code.add(i).write(0x04); i += 1;
    code.add(i).write(0x25); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x5A); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0xEF); i += 1;
    code.add(i).write(0xBE); i += 1;
    code.add(i).write(0xAD); i += 1;
    code.add(i).write(0xDE); i += 1;

    // Return to caller
    // ret
    code.add(i).write(0xC3); i += 1;

    serial::print("VBE: 64-bit return size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

/// Build 32-bit trampoline code
unsafe fn build_32bit_trampoline() {
    let code = TRAMPOLINE_32BIT_ADDR as *mut u8;
    let mut i = 0;

    // Output 'T' to serial
    code.add(i).write(0xBA); i += 1;  // mov dx, 0x3F8
    code.add(i).write(0xF8); i += 1;
    code.add(i).write(0x03); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0xB0); i += 1;  // mov al, 'T'
    code.add(i).write(0x54); i += 1;
    code.add(i).write(0xEE); i += 1;  // out dx, al

    // Load GDT
    code.add(i).write(0x0F); i += 1;  // lgdt [0x07E0]
    code.add(i).write(0x01); i += 1;
    code.add(i).write(0x15); i += 1;
    code.add(i).write(0xE0); i += 1;
    code.add(i).write(0x07); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;

    // Load real mode IDT
    code.add(i).write(0x0F); i += 1;  // lidt [0x07F0]
    code.add(i).write(0x01); i += 1;
    code.add(i).write(0x1D); i += 1;
    code.add(i).write(0xF0); i += 1;
    code.add(i).write(0x07); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;

    // Load 16-bit data segments (selector 0x10)
    code.add(i).write(0x66); i += 1;  // mov ax, 0x10
    code.add(i).write(0xB8); i += 1;
    code.add(i).write(0x10); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x8E); i += 1;  // mov ds, ax
    code.add(i).write(0xD8); i += 1;
    code.add(i).write(0x8E); i += 1;  // mov es, ax
    code.add(i).write(0xC0); i += 1;
    code.add(i).write(0x8E); i += 1;  // mov fs, ax
    code.add(i).write(0xE0); i += 1;
    code.add(i).write(0x8E); i += 1;  // mov gs, ax
    code.add(i).write(0xE8); i += 1;
    code.add(i).write(0x8E); i += 1;  // mov ss, ax
    code.add(i).write(0xD0); i += 1;

    // Set stack
    code.add(i).write(0xBC); i += 1;  // mov esp, 0x7000
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x70); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;

    // Far jump to 16-bit code
    code.add(i).write(0xEA); i += 1;  // jmp 0x08:TO_REAL_TRAMPOLINE_ADDR
    code.add(i).write((TO_REAL_TRAMPOLINE_ADDR & 0xFF) as u8); i += 1;
    code.add(i).write(((TO_REAL_TRAMPOLINE_ADDR >> 8) & 0xFF) as u8); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x08); i += 1;  // 16-bit code segment
    code.add(i).write(0x00); i += 1;
}

/// Build 16-bit to real mode trampoline
unsafe fn build_16bit_to_real_trampoline() {
    let code = TO_REAL_TRAMPOLINE_ADDR as *mut u8;
    let mut i = 0;

    // Clear PE bit in CR0 to enter real mode
    // mov eax, cr0
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x20); i += 1;
    code.add(i).write(0xC0); i += 1;
    // and al, 0xFE
    code.add(i).write(0x24); i += 1;
    code.add(i).write(0xFE); i += 1;
    // mov cr0, eax
    code.add(i).write(0x0F); i += 1;
    code.add(i).write(0x22); i += 1;
    code.add(i).write(0xC0); i += 1;

    // Far jump to real mode code
    // jmp 0x0000:VBE_CODE_ADDR
    code.add(i).write(0xEA); i += 1;
    code.add(i).write((VBE_CODE_ADDR & 0xFF) as u8); i += 1;
    code.add(i).write(((VBE_CODE_ADDR >> 8) & 0xFF) as u8); i += 1;
    code.add(i).write(0x00); i += 1;
    code.add(i).write(0x00); i += 1;
}

/// Execute the VBE transition
unsafe fn execute_vbe_transition() {
    // Save CR3 for return path
    let cr3: u64;
    core::arch::asm!("mov {}, cr3", out(reg) cr3);
    *(0x5A04 as *mut u32) = cr3 as u32;

    // Save RSP for return path
    let rsp: u64;
    core::arch::asm!("mov {}, rsp", out(reg) rsp);
    *(0x5A08 as *mut u64) = rsp;

    // Clear completion flag
    *(SAVED_SP_ADDR as *mut u32) = 0;

    serial::println("VBE: Executing 64-bit exit sequence...");

    // Build a small 32-bit stub that will clear LME after the far jump
    // This stub goes at 0x5C00 and is executed after we disable paging
    // The stub: clears LME, then jumps to main 32-bit trampoline
    let stub32 = 0x5C00 as *mut u8;
    let mut i = 0;

    // Output 'X' to serial to show we reached 32-bit stub
    stub32.add(i).write(0xBA); i += 1;  // mov dx, 0x3F8
    stub32.add(i).write(0xF8); i += 1;
    stub32.add(i).write(0x03); i += 1;
    stub32.add(i).write(0x00); i += 1;
    stub32.add(i).write(0xB0); i += 1;  // mov al, 'X'
    stub32.add(i).write(0x58); i += 1;
    stub32.add(i).write(0xEE); i += 1;  // out dx, al

    // Clear LME bit in EFER MSR (now safe since we're in 32-bit mode)
    // mov ecx, 0xC0000080
    stub32.add(i).write(0xB9); i += 1;
    stub32.add(i).write(0x80); i += 1;
    stub32.add(i).write(0x00); i += 1;
    stub32.add(i).write(0x00); i += 1;
    stub32.add(i).write(0xC0); i += 1;
    // rdmsr
    stub32.add(i).write(0x0F); i += 1;
    stub32.add(i).write(0x32); i += 1;
    // and eax, ~0x100 (clear LME bit 8)
    stub32.add(i).write(0x25); i += 1;
    stub32.add(i).write(0xFF); i += 1;
    stub32.add(i).write(0xFE); i += 1;
    stub32.add(i).write(0xFF); i += 1;
    stub32.add(i).write(0xFF); i += 1;
    // wrmsr
    stub32.add(i).write(0x0F); i += 1;
    stub32.add(i).write(0x30); i += 1;

    // Jump to main 32-bit trampoline
    // jmp TRAMPOLINE_32BIT_ADDR
    stub32.add(i).write(0xE9); i += 1;  // jmp rel32
    let offset = (TRAMPOLINE_32BIT_ADDR as i32) - (0x5C00 + i as i32 + 4);
    stub32.add(i).write((offset & 0xFF) as u8); i += 1;
    stub32.add(i).write(((offset >> 8) & 0xFF) as u8); i += 1;
    stub32.add(i).write(((offset >> 16) & 0xFF) as u8); i += 1;
    stub32.add(i).write(((offset >> 24) & 0xFF) as u8); i += 1;

    serial::print("VBE: 32-bit stub size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");

    // Use the exact same approach as bios_disk.rs which works
    // Add serial markers to diagnose where crash occurs
    core::arch::asm!(
        // Disable interrupts
        "cli",

        // Marker '1' - start of transition
        "mov dx, 0x3F8",
        "mov al, '1'",
        "out dx, al",

        // Step 1: Disable paging (clear PG bit)
        "mov rax, cr0",
        "and eax, 0x7FFFFFFF",  // Clear PG bit (bit 31)
        "mov cr0, rax",

        // Marker '2' - paging disabled
        "mov dx, 0x3F8",
        "mov al, '2'",
        "out dx, al",

        // Step 2: Clear LME bit in EFER MSR
        "mov ecx, 0xC0000080",  // EFER MSR
        "rdmsr",
        "and eax, 0xFFFFFEFF",  // Clear LME (bit 8)
        "wrmsr",

        // Marker '3' - LME cleared
        "mov dx, 0x3F8",
        "mov al, '3'",
        "out dx, al",

        // Step 3: Load 32-bit GDT (using 6-byte pointer at 0x07E0)
        "lgdt [0x07E0]",

        // Marker '4' - GDT loaded
        "mov dx, 0x3F8",
        "mov al, '4'",
        "out dx, al",

        // Step 4: Load 32-bit data segments
        "mov ax, 0x20",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",
        "mov esp, 0x7000",

        // Marker '5' - segments loaded
        "mov dx, 0x3F8",
        "mov al, '5'",
        "out dx, al",

        // Step 5: Far jump to 32-bit code segment
        "push 0x18",              // 32-bit code segment selector
        "push {tramp32}",         // 32-bit stub address

        // Marker '6' - about to retfq
        "mov dx, 0x3F8",
        "mov al, '6'",
        "out dx, al",

        "retfq",                  // Far return completes the transition

        tramp32 = in(reg) 0x5C00u64,
        options(noreturn)
    );
}

/// Initialize framebuffer via VBE
/// Call this if multiboot didn't provide framebuffer info
pub fn init_framebuffer() -> bool {
    if let Some(fb) = set_graphics_mode() {
        // Store in global framebuffer state
        *crate::framebuffer::FB.lock() = Some(fb);
        true
    } else {
        false
    }
}
