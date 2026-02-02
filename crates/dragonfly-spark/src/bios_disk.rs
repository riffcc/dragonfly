//! BIOS INT 13h disk access via real mode
//!
//! This module provides disk access using BIOS INT 13h by temporarily
//! switching from protected mode to real mode. This preserves BIOS state
//! and works with any disk the BIOS can access (including VirtIO).

use crate::serial;
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

/// Location to store saved ESP for return
const SAVED_ESP_ADDR: u32 = 0x0608;

/// Return trampoline address (protected mode stub)
const RETURN_TRAMPOLINE_ADDR: u32 = 0x0A00;

/// Continuation address - where to jump after returning to protected mode
const CONTINUATION_ADDR: u32 = 0x060C;

/// MBR buffer location (separate from DISK_BUFFER for detection)
const MBR_BUFFER_ADDR: u32 = 0x3000;

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

/// Detect OS on disk via BIOS INT 13h
/// Returns the detected OS type without corrupting BIOS state
pub fn detect_os_via_bios(drive: u8) -> (DetectedOs, [u8; 512]) {
    serial::println("BIOS: Detecting OS via INT 13h...");

    unsafe {
        // Initialize result locations
        *(OS_TYPE_ADDR as *mut u8) = DetectedOs::Unknown as u8;
        *(SAVED_ESP_ADDR as *mut u32) = 0;

        // Clear MBR buffer
        core::ptr::write_bytes(MBR_BUFFER_ADDR as *mut u8, 0, 512);

        // Build the GDT with both 16-bit and 32-bit segments
        let gdt: [GdtEntry; 5] = [
            GdtEntry::null(),    // 0x00: null
            GdtEntry::code16(),  // 0x08: 16-bit code
            GdtEntry::data16(),  // 0x10: 16-bit data
            GdtEntry::code32(),  // 0x18: 32-bit code
            GdtEntry::data32(),  // 0x20: 32-bit data
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

        // Build real mode IDT pointer
        let idt_ptr = GdtPtr {
            limit: 0x03FF,
            base: 0x0000,
        };

        // Build the detection code (real mode)
        build_detect_code(drive);

        // Build the return trampoline (switches back to protected mode)
        build_return_trampoline();

        // Build trampoline to switch to real mode
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

        serial::println("BIOS: Switching to real mode for detection...");

        // Save current ESP and do the mode switch
        let mut result_esp: u32;
        core::arch::asm!(
            // Save ESP to known location
            "mov [{saved_esp}], esp",

            // Store address of return label at CONTINUATION_ADDR
            "lea eax, [2f]",
            "mov [{cont_addr}], eax",

            "cli",

            // Disable paging
            "mov eax, cr0",
            "and eax, 0x7FFFFFFF",
            "mov cr0, eax",

            // Load 16-bit GDT
            "lgdt [{gdt_ptr}]",
            // Load real mode IDT (IVT)
            "lidt [{idt_ptr}]",

            // Load 16-bit data segments
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            "mov esp, 0x7000",

            // Far jump to 16-bit code segment, then to real mode
            "push 0x08",
            "push {tramp}",
            "retf",

            // === RETURN POINT ===
            // The return trampoline jumps here after re-enabling protected mode
            "2:",

            // Restore 32-bit data segments
            "mov ax, 0x20",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",

            // Restore ESP
            "mov esp, [{saved_esp}]",

            saved_esp = in(reg) SAVED_ESP_ADDR,
            cont_addr = in(reg) CONTINUATION_ADDR,
            gdt_ptr = in(reg) &gdt_ptr,
            idt_ptr = in(reg) &idt_ptr,
            tramp = in(reg) to_real_trampoline,
            out("eax") _,
        );

        // Read results from low memory
        let os_type_byte = *(OS_TYPE_ADDR as *const u8);
        let os_type = match os_type_byte {
            1 => DetectedOs::Linux,
            2 => DetectedOs::Windows,
            3 => DetectedOs::GptSystem,
            4 => DetectedOs::NoOs,
            5 => DetectedOs::ReadError,
            _ => DetectedOs::Unknown,
        };

        // Copy MBR from buffer
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

/// Build the real mode detection code
unsafe fn build_detect_code(drive: u8) {
    let code = REALMODE_CODE_ADDR as *mut u8;
    let mut i = 0;

    // Set up segments
    // xor ax, ax
    *code.add(i) = 0x31; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // mov ds, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD8; i += 1;
    // mov es, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // mov ss, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD0; i += 1;
    // mov sp, 0x7C00
    *code.add(i) = 0xBC; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;

    // Output 'D' for detect
    *code.add(i) = 0xBA; i += 1;  // mov dx, 0x3F8
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;  // mov al, 'D'
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Set up DAP at 0x0500 to read MBR to MBR_BUFFER_ADDR
    let dap_addr: u16 = 0x0500;

    // mov si, dap_addr
    *code.add(i) = 0xBE; i += 1;
    *code.add(i) = (dap_addr & 0xFF) as u8; i += 1;
    *code.add(i) = ((dap_addr >> 8) & 0xFF) as u8; i += 1;

    // Build DAP inline
    // mov byte [si+0], 0x10
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0x10; i += 1;
    // mov byte [si+1], 0x00
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov word [si+2], 0x0001 (1 sector)
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x02; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov word [si+4], MBR_BUFFER_ADDR low
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = (MBR_BUFFER_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((MBR_BUFFER_ADDR >> 8) & 0xFF) as u8; i += 1;
    // mov word [si+6], 0x0000 (segment 0)
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    // LBA = 0 (dword at si+8 and si+12)
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

    // mov dl, drive
    *code.add(i) = 0xB2; i += 1;
    *code.add(i) = drive; i += 1;
    // mov ah, 0x42
    *code.add(i) = 0xB4; i += 1;
    *code.add(i) = 0x42; i += 1;

    // int 0x13
    *code.add(i) = 0xCD; i += 1;
    *code.add(i) = 0x13; i += 1;

    // Check carry flag for error
    // jc read_error
    *code.add(i) = 0x72; i += 1;
    let jc_offset_pos = i;
    *code.add(i) = 0x00; i += 1;  // Will patch

    // Output 'R' for read OK
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x52; i += 1;  // 'R'
    *code.add(i) = 0xEE; i += 1;

    // Check MBR signature at MBR_BUFFER_ADDR+510
    // mov bx, MBR_BUFFER_ADDR
    *code.add(i) = 0xBB; i += 1;
    *code.add(i) = (MBR_BUFFER_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((MBR_BUFFER_ADDR >> 8) & 0xFF) as u8; i += 1;
    // cmp word [bx+510], 0xAA55
    *code.add(i) = 0x81; i += 1;
    *code.add(i) = 0xBF; i += 1;
    *code.add(i) = 0xFE; i += 1;  // offset 510
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x55; i += 1;
    *code.add(i) = 0xAA; i += 1;
    // jne no_os
    *code.add(i) = 0x75; i += 1;
    let jne_offset_pos = i;
    *code.add(i) = 0x00; i += 1;  // Will patch

    // Check partition type at MBR_BUFFER_ADDR+450 (first partition type)
    // mov al, [bx+450]
    *code.add(i) = 0x8A; i += 1;
    *code.add(i) = 0x87; i += 1;
    *code.add(i) = 0xC2; i += 1;  // offset 450 (446 + 4)
    *code.add(i) = 0x01; i += 1;

    // Check for GPT (0xEE)
    // cmp al, 0xEE
    *code.add(i) = 0x3C; i += 1;
    *code.add(i) = 0xEE; i += 1;
    // je gpt_found
    *code.add(i) = 0x74; i += 1;
    let je_gpt_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Check for Linux (0x83)
    // cmp al, 0x83
    *code.add(i) = 0x3C; i += 1;
    *code.add(i) = 0x83; i += 1;
    // je linux_found
    *code.add(i) = 0x74; i += 1;
    let je_linux_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Check for NTFS (0x07)
    // cmp al, 0x07
    *code.add(i) = 0x3C; i += 1;
    *code.add(i) = 0x07; i += 1;
    // je windows_found
    *code.add(i) = 0x74; i += 1;
    let je_windows_pos = i;
    *code.add(i) = 0x00; i += 1;

    // Default: unknown but valid MBR
    // mov byte [OS_TYPE_ADDR], 1 (Linux as default for bootable)
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 1; i += 1;
    // jmp return_to_pm
    *code.add(i) = 0xEB; i += 1;
    let jmp_return_pos = i;
    *code.add(i) = 0x00; i += 1;

    // gpt_found:
    let gpt_found = i;
    *code.add(je_gpt_pos) = (gpt_found - je_gpt_pos - 1) as u8;
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = (OS_TYPE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((OS_TYPE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = 3; i += 1;  // GptSystem
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
    *code.add(i) = 1; i += 1;  // Linux
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
    *code.add(i) = 2; i += 1;  // Windows
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
    *code.add(i) = 4; i += 1;  // NoOs
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
    *code.add(i) = 5; i += 1;  // ReadError
    // Fall through to return

    // return_to_pm: Switch back to protected mode
    let return_to_pm = i;
    *code.add(jmp_return_pos) = (return_to_pm - jmp_return_pos - 1) as u8;
    *code.add(jmp_return_pos2) = (return_to_pm - jmp_return_pos2 - 1) as u8;
    *code.add(jmp_return_pos3) = (return_to_pm - jmp_return_pos3 - 1) as u8;
    *code.add(jmp_return_pos4) = (return_to_pm - jmp_return_pos4 - 1) as u8;
    *code.add(jmp_return_pos5) = (return_to_pm - jmp_return_pos5 - 1) as u8;

    // Output 'P' for returning to protected mode
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x50; i += 1;  // 'P'
    *code.add(i) = 0xEE; i += 1;

    // cli
    *code.add(i) = 0xFA; i += 1;

    // lgdt [GDT_ADDR] - need to build GDT pointer in memory
    // We'll use a fixed location for the GDTR
    // mov word [0x07F0], gdt_limit
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = 0xF0; i += 1;
    *code.add(i) = 0x07; i += 1;
    *code.add(i) = 0x27; i += 1;  // limit = 39 (5 entries * 8 - 1)
    *code.add(i) = 0x00; i += 1;
    // mov dword [0x07F2], GDT_ADDR
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = 0xF2; i += 1;
    *code.add(i) = 0x07; i += 1;
    *code.add(i) = (GDT_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((GDT_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = ((GDT_ADDR >> 16) & 0xFF) as u8; i += 1;
    *code.add(i) = ((GDT_ADDR >> 24) & 0xFF) as u8; i += 1;

    // lgdt [0x07F0]
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x16; i += 1;
    *code.add(i) = 0xF0; i += 1;
    *code.add(i) = 0x07; i += 1;

    // Enable protected mode
    // mov eax, cr0
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x20; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // or al, 1
    *code.add(i) = 0x0C; i += 1;
    *code.add(i) = 0x01; i += 1;
    // mov cr0, eax
    *code.add(i) = 0x0F; i += 1;
    *code.add(i) = 0x22; i += 1;
    *code.add(i) = 0xC0; i += 1;

    // Far jump to 32-bit code segment (selector 0x18)
    // jmp 0x18:RETURN_TRAMPOLINE_ADDR
    *code.add(i) = 0x66; i += 1;  // operand size prefix
    *code.add(i) = 0xEA; i += 1;
    *code.add(i) = (RETURN_TRAMPOLINE_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((RETURN_TRAMPOLINE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = ((RETURN_TRAMPOLINE_ADDR >> 16) & 0xFF) as u8; i += 1;
    *code.add(i) = ((RETURN_TRAMPOLINE_ADDR >> 24) & 0xFF) as u8; i += 1;
    *code.add(i) = 0x18; i += 1;
    *code.add(i) = 0x00; i += 1;

    serial::print("BIOS: Detect code size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

/// Build the return trampoline (32-bit protected mode code)
unsafe fn build_return_trampoline() {
    let code = RETURN_TRAMPOLINE_ADDR as *mut u8;
    let mut i = 0;

    // Output 'T' for trampoline
    // mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov al, 'T'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x54; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;

    // Load 32-bit data segments
    // mov ax, 0x20
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xB8; i += 1;
    *code.add(i) = 0x20; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov ds, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD8; i += 1;
    // mov es, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // mov fs, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xE0; i += 1;
    // mov gs, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xE8; i += 1;
    // mov ss, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD0; i += 1;

    // Restore ESP from SAVED_ESP_ADDR
    // mov esp, [SAVED_ESP_ADDR]
    *code.add(i) = 0x8B; i += 1;
    *code.add(i) = 0x25; i += 1;
    *code.add(i) = (SAVED_ESP_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((SAVED_ESP_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = ((SAVED_ESP_ADDR >> 16) & 0xFF) as u8; i += 1;
    *code.add(i) = ((SAVED_ESP_ADDR >> 24) & 0xFF) as u8; i += 1;

    // Output '!' for success
    // mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov al, '!'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x21; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;

    // Jump to continuation address stored at CONTINUATION_ADDR
    // jmp [CONTINUATION_ADDR]
    *code.add(i) = 0xFF; i += 1;
    *code.add(i) = 0x25; i += 1;
    *code.add(i) = (CONTINUATION_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((CONTINUATION_ADDR >> 8) & 0xFF) as u8; i += 1;
    *code.add(i) = ((CONTINUATION_ADDR >> 16) & 0xFF) as u8; i += 1;
    *code.add(i) = ((CONTINUATION_ADDR >> 24) & 0xFF) as u8; i += 1;

    serial::print("BIOS: Return trampoline size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

/// Read a sector using BIOS INT 13h
/// Returns true if successful, data is copied to buffer
pub fn read_sector(drive: u8, lba: u32, buffer: &mut [u8; 512]) -> bool {
    serial::println("BIOS: Reading sector via INT 13h");
    serial::print("BIOS: Drive=0x");
    serial::print_hex32(drive as u32);
    serial::print(" LBA=");
    serial::print_dec(lba);
    serial::println("");

    // Build the real mode code that will:
    // 1. Set up segments
    // 2. Call INT 13h (extended read)
    // 3. Store result
    // 4. Return to protected mode (or halt for now)

    // For LBA access, we use INT 13h AH=42h (Extended Read)
    // This requires a Disk Address Packet (DAP) structure

    // DAP structure (16 bytes):
    // Offset 0: Size of DAP (1 byte) = 0x10
    // Offset 1: Reserved (1 byte) = 0x00
    // Offset 2: Number of sectors (2 bytes) = 0x0001
    // Offset 4: Buffer offset (2 bytes)
    // Offset 6: Buffer segment (2 bytes)
    // Offset 8: LBA (8 bytes)

    let dap_addr: u32 = 0x0500;  // Put DAP at 0x500

    unsafe {
        // Build the DAP
        let dap = dap_addr as *mut u8;
        *dap.add(0) = 0x10;  // Size
        *dap.add(1) = 0x00;  // Reserved
        *dap.add(2) = 0x01;  // Sectors low
        *dap.add(3) = 0x00;  // Sectors high
        *dap.add(4) = (DISK_BUFFER_ADDR & 0xFF) as u8;  // Buffer offset low
        *dap.add(5) = ((DISK_BUFFER_ADDR >> 8) & 0xFF) as u8;  // Buffer offset high
        *dap.add(6) = 0x00;  // Buffer segment low (segment 0)
        *dap.add(7) = 0x00;  // Buffer segment high
        // LBA (64-bit, little endian)
        *dap.add(8) = (lba & 0xFF) as u8;
        *dap.add(9) = ((lba >> 8) & 0xFF) as u8;
        *dap.add(10) = ((lba >> 16) & 0xFF) as u8;
        *dap.add(11) = ((lba >> 24) & 0xFF) as u8;
        *dap.add(12) = 0x00;
        *dap.add(13) = 0x00;
        *dap.add(14) = 0x00;
        *dap.add(15) = 0x00;

        // Clear result flag
        *(RESULT_ADDR as *mut u8) = 0xFF;  // 0xFF = not done yet

        // Build the real mode code
        build_int13_code(drive, dap_addr);

        // Execute the real mode code
        execute_realmode();

        // Check result
        let result = *(RESULT_ADDR as *mut u8);
        serial::print("BIOS: INT 13h result = 0x");
        serial::print_hex32(result as u32);
        serial::println("");

        if result == 0 {
            // Success! Copy data from buffer
            core::ptr::copy_nonoverlapping(
                DISK_BUFFER_ADDR as *const u8,
                buffer.as_mut_ptr(),
                512
            );

            // Debug: print first few bytes
            serial::print("BIOS: Data first 8 bytes: ");
            for i in 0..8 {
                serial::print_hex32(buffer[i] as u32);
                serial::print(" ");
            }
            serial::println("");

            return true;
        }
    }

    false
}

/// Build the real mode INT 13h code at REALMODE_CODE_ADDR
unsafe fn build_int13_code(drive: u8, dap_addr: u32) {
    let code = REALMODE_CODE_ADDR as *mut u8;
    let mut i = 0;

    // This code runs in 16-bit real mode
    // It will:
    // 1. Set up segments (DS = 0 for DAP access)
    // 2. Load SI with DAP address
    // 3. Load DL with drive number
    // 4. Call INT 13h AH=42h
    // 5. Store result (AH) to RESULT_ADDR
    // 6. Far jump back to protected mode trampoline

    // xor ax, ax
    *code.add(i) = 0x31; i += 1;
    *code.add(i) = 0xC0; i += 1;

    // mov ds, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD8; i += 1;

    // mov es, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xC0; i += 1;

    // mov ss, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD0; i += 1;

    // mov sp, 0x7C00 (set up stack)
    *code.add(i) = 0xBC; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;

    // Output 'B' to serial to show we're in BIOS code
    // mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    // mov al, 'B'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x42; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;

    // mov si, dap_addr (DAP address)
    *code.add(i) = 0xBE; i += 1;
    *code.add(i) = (dap_addr & 0xFF) as u8; i += 1;
    *code.add(i) = ((dap_addr >> 8) & 0xFF) as u8; i += 1;

    // mov dl, drive
    *code.add(i) = 0xB2; i += 1;
    *code.add(i) = drive; i += 1;

    // mov ah, 0x42 (extended read)
    *code.add(i) = 0xB4; i += 1;
    *code.add(i) = 0x42; i += 1;

    // int 0x13
    *code.add(i) = 0xCD; i += 1;
    *code.add(i) = 0x13; i += 1;

    // jc error (jump if carry set = error)
    *code.add(i) = 0x72; i += 1;
    *code.add(i) = 0x04; i += 1;  // Jump 4 bytes forward

    // Success: mov al, 0
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x00; i += 1;
    // jmp store
    *code.add(i) = 0xEB; i += 1;
    *code.add(i) = 0x02; i += 1;  // Jump 2 bytes forward

    // Error: mov al, ah (error code is in AH)
    *code.add(i) = 0x88; i += 1;
    *code.add(i) = 0xE0; i += 1;

    // Store result: mov [RESULT_ADDR], al
    *code.add(i) = 0xA2; i += 1;
    *code.add(i) = (RESULT_ADDR & 0xFF) as u8; i += 1;
    *code.add(i) = ((RESULT_ADDR >> 8) & 0xFF) as u8; i += 1;

    // Output result to serial
    // mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    // add al, '0' (convert to ASCII digit for simple results)
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0x30; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;
    // mov al, '\n'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x0A; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;

    // Now we need to return to protected mode
    // This is tricky - we'll use a simple approach:
    // Jump to a return trampoline that switches back

    // For now, just halt after the INT 13h
    // We'll implement proper return later
    // cli
    *code.add(i) = 0xFA; i += 1;
    // hlt
    *code.add(i) = 0xF4; i += 1;
    // jmp $ (infinite loop)
    *code.add(i) = 0xEB; i += 1;
    *code.add(i) = 0xFD; i += 1;
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
}

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u32,
}

/// Read MBR and immediately chainload - all in real mode
/// This is the simplest approach that preserves BIOS state
pub fn read_and_chainload(drive: u8) -> ! {
    serial::println("BIOS: Direct boot via INT 13h");
    vga::println("");
    vga::println("Booting from disk via BIOS...");

    unsafe {
        execute_realmode_boot(drive);
    }
}

/// Chainload using pre-loaded MBR (from VirtIO detection)
/// No BIOS INT 13h needed - MBR is already in memory
pub fn chainload_mbr(mbr: &[u8; 512], drive: u8) -> ! {
    serial::println("Chainloading with cached MBR (no BIOS read needed)");
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

        // Verify copy
        let check = *(0x7C00 as *const u8);
        serial::print("First byte at 0x7C00: 0x");
        serial::print_hex32(check as u32);
        serial::println("");

        // Use the working mode switch code, just build simpler boot code
        execute_realmode_jump_simple(drive);
    }
}

/// Simple real mode jump - reuses working mode switch, just jumps to 0x7C00
unsafe fn execute_realmode_jump_simple(drive: u8) -> ! {
    serial::println("Switching to real mode (simple jump)...");

    // Build GDT with 16-bit segments - same as working code
    let gdt: [GdtEntry; 3] = [
        GdtEntry::null(),
        GdtEntry::code16(),  // Selector 0x08
        GdtEntry::data16(),  // Selector 0x10
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

    // Build boot code that just sets up segments and jumps to 0x7C00
    // (MBR is already there)
    build_jump_code(drive);

    // Build trampoline - same as working code, with debug
    let trampoline_addr: u32 = 0x0900;
    let tramp = trampoline_addr as *mut u8;
    let mut i = 0;

    // Output 'T' to show trampoline reached
    *tramp.add(i) = 0xBA; i += 1;  // mov dx, 0x3F8
    *tramp.add(i) = 0xF8; i += 1;
    *tramp.add(i) = 0x03; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0xB0; i += 1;  // mov al, 'T'
    *tramp.add(i) = 0x54; i += 1;
    *tramp.add(i) = 0xEE; i += 1;  // out dx, al

    *tramp.add(i) = 0x0F; i += 1;  // mov eax, cr0
    *tramp.add(i) = 0x20; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0x24; i += 1;  // and al, 0xFE
    *tramp.add(i) = 0xFE; i += 1;
    *tramp.add(i) = 0x0F; i += 1;  // mov cr0, eax
    *tramp.add(i) = 0x22; i += 1;
    *tramp.add(i) = 0xC0; i += 1;

    // Output 'R' to show real mode reached
    *tramp.add(i) = 0xBA; i += 1;  // mov dx, 0x3F8
    *tramp.add(i) = 0xF8; i += 1;
    *tramp.add(i) = 0x03; i += 1;
    *tramp.add(i) = 0xB0; i += 1;  // mov al, 'R'
    *tramp.add(i) = 0x52; i += 1;
    *tramp.add(i) = 0xEE; i += 1;  // out dx, al

    *tramp.add(i) = 0xEA; i += 1;  // far jmp
    *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
    *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0x00; i += 1;

    serial::print("Trampoline at 0x");
    serial::print_hex32(trampoline_addr);
    serial::print(", code at 0x");
    serial::print_hex32(REALMODE_CODE_ADDR);
    serial::println("");
    serial::println("Executing mode switch...");

    // Same working asm block with debug output
    core::arch::asm!(
        "cli",
        "mov dx, 0x3F8",
        "mov al, 0x32",  // '2'
        "out dx, al",
        "mov eax, cr0",
        "and eax, 0x7FFFFFFF",
        "mov cr0, eax",
        "mov dx, 0x3F8",
        "mov al, 0x33",  // '3'
        "out dx, al",
        "lgdt [{gdt_ptr}]",
        "lidt [{idt_ptr}]",
        "mov dx, 0x3F8",
        "mov al, 0x34",  // '4'
        "out dx, al",
        "mov ax, 0x10",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",
        "mov esp, 0x7000",
        "mov dx, 0x3F8",
        "mov al, 0x35",  // '5'
        "out dx, al",
        "push 0x08",
        "push {tramp}",
        // Output '6' right before retf
        "mov dx, 0x3F8",
        "mov al, 0x36",
        "out dx, al",
        "retf",
        gdt_ptr = in(reg) &gdt_ptr,
        idt_ptr = in(reg) &idt_ptr,
        tramp = in(reg) trampoline_addr,
        options(noreturn)
    );
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

    // Reset video to VGA text mode (mode 3) before chainload
    // This fixes black screen when chainloading from graphical framebuffer mode
    // INT 10h, AH=00h (set mode), AL=03h (80x25 16-color text)
    *code.add(i) = 0xB8; i += 1;  // mov ax, 0x0003
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0xCD; i += 1;  // int 0x10
    *code.add(i) = 0x10; i += 1;

    // Output 'V' to serial (video mode set)
    *code.add(i) = 0xBA; i += 1;  // mov dx, 0x3F8
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    *code.add(i) = 0xB0; i += 1;  // mov al, 'V'
    *code.add(i) = 0x56; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Output 'J' to serial (jumping to MBR)
    *code.add(i) = 0xB0; i += 1;  // mov al, 'J'
    *code.add(i) = 0x4A; i += 1;
    *code.add(i) = 0xEE; i += 1;  // out dx, al

    // Set boot drive in DL
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

/// Switch to real mode and jump to MBR at 0x7C00
unsafe fn execute_realmode_jump(drive: u8) -> ! {
    serial::println("Switching to real mode for MBR jump...");

    // Build GDT with 16-bit segments
    let gdt: [GdtEntry; 3] = [
        GdtEntry::null(),
        GdtEntry::code16(),  // Selector 0x08
        GdtEntry::data16(),  // Selector 0x10
    ];

    // Copy GDT to known location
    core::ptr::copy_nonoverlapping(
        gdt.as_ptr() as *const u8,
        GDT_ADDR as *mut u8,
        core::mem::size_of_val(&gdt)
    );

    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of_val(&gdt) - 1) as u16,
        base: GDT_ADDR,
    };

    // Real mode IDT (IVT at 0x0000)
    let idt_ptr = GdtPtr {
        limit: 0x03FF,
        base: 0x0000,
    };

    // Build simple trampoline that just sets up real mode and jumps to 0x7C00
    let trampoline_addr: u32 = 0x0900;
    let tramp = trampoline_addr as *mut u8;
    let mut i = 0;

    // Disable protected mode: mov eax, cr0; and al, 0xFE; mov cr0, eax
    *tramp.add(i) = 0x0F; i += 1;  // mov eax, cr0
    *tramp.add(i) = 0x20; i += 1;
    *tramp.add(i) = 0xC0; i += 1;
    *tramp.add(i) = 0x24; i += 1;  // and al, 0xFE
    *tramp.add(i) = 0xFE; i += 1;
    *tramp.add(i) = 0x0F; i += 1;  // mov cr0, eax
    *tramp.add(i) = 0x22; i += 1;
    *tramp.add(i) = 0xC0; i += 1;

    // Far jump to real mode code at 0x1000
    *tramp.add(i) = 0xEA; i += 1;
    *tramp.add(i) = 0x00; i += 1;  // offset low
    *tramp.add(i) = 0x10; i += 1;  // offset high (0x1000)
    *tramp.add(i) = 0x00; i += 1;  // segment low
    *tramp.add(i) = 0x00; i += 1;  // segment high

    // Build real mode code at 0x1000 that sets up segments and jumps to 0x7C00
    let code = REALMODE_CODE_ADDR as *mut u8;
    let mut j = 0;

    // xor ax, ax; mov ds, ax; mov es, ax; mov ss, ax; mov sp, 0x7C00
    *code.add(j) = 0x31; j += 1;  // xor ax, ax
    *code.add(j) = 0xC0; j += 1;
    *code.add(j) = 0x8E; j += 1;  // mov ds, ax
    *code.add(j) = 0xD8; j += 1;
    *code.add(j) = 0x8E; j += 1;  // mov es, ax
    *code.add(j) = 0xC0; j += 1;
    *code.add(j) = 0x8E; j += 1;  // mov ss, ax
    *code.add(j) = 0xD0; j += 1;
    *code.add(j) = 0xBC; j += 1;  // mov sp, 0x7C00
    *code.add(j) = 0x00; j += 1;
    *code.add(j) = 0x7C; j += 1;

    // Output 'J' to serial (jump)
    *code.add(j) = 0xBA; j += 1;  // mov dx, 0x3F8
    *code.add(j) = 0xF8; j += 1;
    *code.add(j) = 0x03; j += 1;
    *code.add(j) = 0xB0; j += 1;  // mov al, 'J'
    *code.add(j) = 0x4A; j += 1;
    *code.add(j) = 0xEE; j += 1;  // out dx, al

    // mov dl, drive (boot drive for MBR)
    *code.add(j) = 0xB2; j += 1;
    *code.add(j) = drive; j += 1;

    // Far jump to 0x0000:0x7C00
    *code.add(j) = 0xEA; j += 1;
    *code.add(j) = 0x00; j += 1;  // offset low
    *code.add(j) = 0x7C; j += 1;  // offset high
    *code.add(j) = 0x00; j += 1;  // segment low
    *code.add(j) = 0x00; j += 1;  // segment high

    serial::println("Executing transition to real mode...");

    // Do the mode switch
    core::arch::asm!(
        "cli",
        "mov eax, cr0",
        "and eax, 0x7FFFFFFF",  // Disable paging
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

/// Execute real mode code that reads MBR and chainloads
unsafe fn execute_realmode_boot(drive: u8) -> ! {
    serial::println("BIOS: Switching to real mode for direct boot...");

    // Build GDT with 16-bit segments
    let gdt: [GdtEntry; 3] = [
        GdtEntry::null(),
        GdtEntry::code16(),  // Selector 0x08
        GdtEntry::data16(),  // Selector 0x10
    ];

    // Copy GDT to known location
    core::ptr::copy_nonoverlapping(
        gdt.as_ptr() as *const u8,
        GDT_ADDR as *mut u8,
        core::mem::size_of_val(&gdt)
    );

    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of_val(&gdt) - 1) as u16,
        base: GDT_ADDR,
    };

    // Real mode IDT (IVT at 0x0000)
    #[repr(C, packed)]
    struct IdtPtr {
        limit: u16,
        base: u32,
    }
    let idt_ptr = IdtPtr {
        limit: 0x03FF,
        base: 0x0000,
    };

    // Build real mode boot code at REALMODE_CODE_ADDR
    // This code:
    // 1. Sets up segments
    // 2. Reads MBR using INT 13h to 0x7C00
    // 3. Jumps to 0x7C00
    build_boot_code(drive);

    // Build trampoline to switch to real mode
    let trampoline_addr: u32 = 0x0900;
    let tramp = trampoline_addr as *mut u8;
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

    // Far jump to real mode boot code
    *tramp.add(i) = 0xEA; i += 1;
    *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
    *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0x00; i += 1;

    serial::println("BIOS: Executing real mode boot code...");
    serial::print("BIOS: Trampoline at 0x");
    serial::print_hex32(trampoline_addr);
    serial::print(", code at 0x");
    serial::print_hex32(REALMODE_CODE_ADDR);
    serial::println("");

    serial::println("BIOS: About to enter asm block...");

    // Output '1' to serial right before asm (32-bit mode)
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x31",  // '1'
            "out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    serial::println("BIOS: After '1' output, entering transition...");

    // Execute the transition
    core::arch::asm!(
        "cli",

        // Output '2' - about to disable paging
        "mov dx, 0x3F8",
        "mov al, 0x32",
        "out dx, al",

        "mov eax, cr0",
        "and eax, 0x7FFFFFFF",
        "mov cr0, eax",

        // Output '3' - paging disabled, loading GDT
        "mov dx, 0x3F8",
        "mov al, 0x33",
        "out dx, al",

        "lgdt [{gdt_ptr}]",
        "lidt [{idt_ptr}]",

        // Output '4' - GDT loaded, loading segments
        "mov dx, 0x3F8",
        "mov al, 0x34",
        "out dx, al",

        "mov ax, 0x10",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",
        "mov esp, 0x7000",

        // Output '5' - about to far jump
        "mov dx, 0x3F8",
        "mov al, 0x35",
        "out dx, al",

        "push 0x08",
        "push {tramp}",
        "retf",
        gdt_ptr = in(reg) &gdt_ptr,
        idt_ptr = in(reg) &idt_ptr,
        tramp = in(reg) trampoline_addr,
        options(noreturn)
    );
}

/// Build real mode code that reads MBR and chainloads
unsafe fn build_boot_code(drive: u8) {
    let code = REALMODE_CODE_ADDR as *mut u8;
    let mut i = 0;

    // Real mode boot code

    // Set up segments
    // xor ax, ax
    *code.add(i) = 0x31; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // mov ds, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD8; i += 1;
    // mov es, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xC0; i += 1;
    // mov ss, ax
    *code.add(i) = 0x8E; i += 1;
    *code.add(i) = 0xD0; i += 1;
    // mov sp, 0x7C00
    *code.add(i) = 0xBC; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;

    // Output 'B' to serial
    // mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    // mov al, 'B'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x42; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;

    // Set up DAP (Disk Address Packet) at 0x0500
    // We'll read sector 0 (MBR) to 0x7C00
    let dap_addr: u16 = 0x0500;

    // mov si, dap_addr
    *code.add(i) = 0xBE; i += 1;
    *code.add(i) = (dap_addr & 0xFF) as u8; i += 1;
    *code.add(i) = ((dap_addr >> 8) & 0xFF) as u8; i += 1;

    // Build DAP in memory
    // mov byte [si+0], 0x10  ; Size
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0x10; i += 1;
    // mov byte [si+1], 0x00  ; Reserved
    *code.add(i) = 0xC6; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov word [si+2], 0x0001  ; Sectors
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x02; i += 1;
    *code.add(i) = 0x01; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov word [si+4], 0x7C00  ; Buffer offset
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x04; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;
    // mov word [si+6], 0x0000  ; Buffer segment
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x06; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov dword [si+8], 0x00000000  ; LBA low
    *code.add(i) = 0x66; i += 1;  // operand size prefix for 32-bit
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x08; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    // mov dword [si+12], 0x00000000  ; LBA high
    *code.add(i) = 0x66; i += 1;
    *code.add(i) = 0xC7; i += 1;
    *code.add(i) = 0x44; i += 1;
    *code.add(i) = 0x0C; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    // mov dl, drive
    *code.add(i) = 0xB2; i += 1;
    *code.add(i) = drive; i += 1;

    // mov ah, 0x42 (extended read)
    *code.add(i) = 0xB4; i += 1;
    *code.add(i) = 0x42; i += 1;

    // Output 'I' before INT 13h
    // mov al, 'I'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x49; i += 1;
    // push dx
    *code.add(i) = 0x52; i += 1;
    // mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;
    // pop dx
    *code.add(i) = 0x5A; i += 1;

    // Restore AH=0x42 (it got clobbered)
    *code.add(i) = 0xB4; i += 1;
    *code.add(i) = 0x42; i += 1;

    // int 0x13
    *code.add(i) = 0xCD; i += 1;
    *code.add(i) = 0x13; i += 1;

    // Output result - 'O' for OK, 'E' for error
    // push ax
    *code.add(i) = 0x50; i += 1;
    // jc error
    *code.add(i) = 0x72; i += 1;
    *code.add(i) = 0x04; i += 1;  // jump 4 bytes
    // mov al, 'O'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x4F; i += 1;
    // jmp output
    *code.add(i) = 0xEB; i += 1;
    *code.add(i) = 0x02; i += 1;  // jump 2 bytes
    // error: mov al, 'E'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x45; i += 1;
    // output: mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;
    // pop ax
    *code.add(i) = 0x58; i += 1;

    // If error, halt
    // jnc ok
    *code.add(i) = 0x73; i += 1;
    *code.add(i) = 0x04; i += 1;  // jump 4 bytes
    // cli; hlt; jmp $
    *code.add(i) = 0xFA; i += 1;
    *code.add(i) = 0xF4; i += 1;
    *code.add(i) = 0xEB; i += 1;
    *code.add(i) = 0xFD; i += 1;

    // ok: Output '!' before jump
    // mov al, '!'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x21; i += 1;
    // mov dx, 0x3F8
    *code.add(i) = 0xBA; i += 1;
    *code.add(i) = 0xF8; i += 1;
    *code.add(i) = 0x03; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;
    // mov al, '\n'
    *code.add(i) = 0xB0; i += 1;
    *code.add(i) = 0x0A; i += 1;
    // out dx, al
    *code.add(i) = 0xEE; i += 1;

    // Jump to MBR at 0x0000:0x7C00
    // DL already has drive number
    *code.add(i) = 0xEA; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x7C; i += 1;
    *code.add(i) = 0x00; i += 1;
    *code.add(i) = 0x00; i += 1;

    serial::print("BIOS: Boot code size = ");
    serial::print_dec(i as u32);
    serial::println(" bytes");
}

/// Execute the real mode code
unsafe fn execute_realmode() {
    serial::println("BIOS: Switching to real mode for INT 13h...");

    // Build GDT with 16-bit segments
    let gdt: [GdtEntry; 3] = [
        GdtEntry::null(),
        GdtEntry::code16(),  // Selector 0x08
        GdtEntry::data16(),  // Selector 0x10
    ];

    // Copy GDT to known location
    core::ptr::copy_nonoverlapping(
        gdt.as_ptr() as *const u8,
        GDT_ADDR as *mut u8,
        core::mem::size_of_val(&gdt)
    );

    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of_val(&gdt) - 1) as u16,
        base: GDT_ADDR,
    };

    // Real mode IDT (IVT at 0x0000)
    #[repr(C, packed)]
    struct IdtPtr {
        limit: u16,
        base: u32,
    }
    let idt_ptr = IdtPtr {
        limit: 0x03FF,
        base: 0x0000,
    };

    // Build trampoline to switch to real mode and jump to our INT 13h code
    let trampoline_addr: u32 = 0x0900;
    let tramp = trampoline_addr as *mut u8;
    let mut i = 0;

    // 16-bit protected mode code that disables PE and jumps to real mode

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

    // Far jump to real mode (flushes prefetch)
    // jmp 0x0000:REALMODE_CODE_ADDR
    *tramp.add(i) = 0xEA; i += 1;
    *tramp.add(i) = (REALMODE_CODE_ADDR & 0xFF) as u8; i += 1;
    *tramp.add(i) = ((REALMODE_CODE_ADDR >> 8) & 0xFF) as u8; i += 1;
    *tramp.add(i) = 0x00; i += 1;
    *tramp.add(i) = 0x00; i += 1;

    // Execute the transition
    core::arch::asm!(
        "cli",

        // Disable paging if enabled
        "mov eax, cr0",
        "and eax, 0x7FFFFFFF",
        "mov cr0, eax",

        // Load our GDT
        "lgdt [{gdt_ptr}]",

        // Load real mode IDT
        "lidt [{idt_ptr}]",

        // Load 16-bit data segments
        "mov ax, 0x10",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",

        // Set up stack
        "mov esp, 0x7000",

        // Far jump to 16-bit protected mode trampoline
        // The trampoline will disable PE and jump to real mode code
        "push 0x08",      // 16-bit code segment
        "push {tramp}",   // Trampoline address
        "retf",

        gdt_ptr = in(reg) &gdt_ptr,
        idt_ptr = in(reg) &idt_ptr,
        tramp = in(reg) trampoline_addr,
        options(noreturn)
    );
}
