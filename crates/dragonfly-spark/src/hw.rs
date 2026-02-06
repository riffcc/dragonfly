//! Hardware detection via CPUID
//!
//! Provides CPU brand string, core count, and memory info from CPUID and multiboot2 memory map.
//!
//! Note: LLVM reserves rbx internally, so all CPUID calls must save/restore rbx
//! manually and move the result to another register (rdi used here).

/// Get CPU brand string from CPUID extended leaves 0x80000002-0x80000004
/// Returns the brand string bytes and the length
pub fn cpu_brand() -> ([u8; 48], usize) {
    let mut brand = [0u8; 48];

    // Check if extended CPUID is supported
    let max_ext: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0x80000000u32 => max_ext,
            out("ecx") _,
            out("edx") _,
            options(preserves_flags)
        );
    }

    if max_ext < 0x80000004 {
        let msg = b"Unknown CPU";
        brand[..msg.len()].copy_from_slice(msg);
        return (brand, msg.len());
    }

    // Read brand string from leaves 0x80000002, 0x80000003, 0x80000004
    for i in 0..3u32 {
        let leaf = 0x80000002 + i;
        let (eax, ebx_val, ecx, edx): (u32, u32, u32, u32);
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "mov edi, ebx",
                "pop rbx",
                inout("eax") leaf => eax,
                out("edi") ebx_val,
                out("ecx") ecx,
                out("edx") edx,
                options(preserves_flags)
            );
        }
        let offset = (i * 16) as usize;
        brand[offset..offset + 4].copy_from_slice(&eax.to_le_bytes());
        brand[offset + 4..offset + 8].copy_from_slice(&ebx_val.to_le_bytes());
        brand[offset + 8..offset + 12].copy_from_slice(&ecx.to_le_bytes());
        brand[offset + 12..offset + 16].copy_from_slice(&edx.to_le_bytes());
    }

    // Find actual string length (trim trailing null/space)
    let mut len = 48;
    while len > 0 && (brand[len - 1] == 0 || brand[len - 1] == b' ') {
        len -= 1;
    }

    // Trim leading spaces
    let mut start = 0;
    while start < len && brand[start] == b' ' {
        start += 1;
    }

    if start > 0 {
        brand.copy_within(start..len, 0);
        len -= start;
    }

    (brand, len)
}

/// Detect CPU vendor from CPUID leaf 0x00
/// Returns 1 for Intel, 2 for AMD, 0 for unknown
fn cpu_vendor() -> u8 {
    let (ebx_val, ecx, edx): (u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov edi, ebx",
            "pop rbx",
            inout("eax") 0u32 => _,
            out("edi") ebx_val,
            out("ecx") ecx,
            out("edx") edx,
            options(preserves_flags)
        );
    }
    // "GenuineIntel" = EBX=0x756E6547 EDX=0x49656E69 ECX=0x6C65746E
    if ebx_val == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E {
        return 1;
    }
    // "AuthenticAMD" = EBX=0x68747541 EDX=0x69746E65 ECX=0x444D4163
    if ebx_val == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163 {
        return 2;
    }
    0
}

/// Get logical processor (thread) count from CPUID leaf 0x01
pub fn cpu_threads() -> u32 {
    let ebx_val: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov edi, ebx",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("edi") ebx_val,
            out("ecx") _,
            out("edx") _,
            options(preserves_flags)
        );
    }
    // Bits 23:16 of EBX = maximum number of addressable IDs for logical processors
    let count = (ebx_val >> 16) & 0xFF;
    if count == 0 { 1 } else { count }
}

/// Get physical core count from CPUID
///
/// Intel: CPUID leaf 0x04 (ECX=0), EAX[31:26] + 1 = cores per package
/// AMD: CPUID leaf 0x80000008, ECX[7:0] + 1 = physical cores
/// Unknown: falls back to logical thread count
pub fn cpu_cores() -> u32 {
    let vendor = cpu_vendor();

    if vendor == 1 {
        // Intel: CPUID leaf 0x04 (deterministic cache parameters)
        let eax_val: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 4u32 => eax_val,
                inout("ecx") 0u32 => _,
                out("edx") _,
                options(preserves_flags)
            );
        }
        // EAX[31:26] = max cores per package - 1
        let cores = ((eax_val >> 26) & 0x3F) + 1;
        if cores == 0 { 1 } else { cores }
    } else if vendor == 2 {
        // AMD: CPUID leaf 0x80000008
        let ecx_val: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0x80000008u32 => _,
                out("edi") _,
                out("ecx") ecx_val,
                out("edx") _,
                options(preserves_flags)
            );
        }
        // ECX[7:0] = number of physical cores - 1
        let cores = (ecx_val & 0xFF) + 1;
        if cores == 0 { 1 } else { cores }
    } else {
        // Unknown vendor: fall back to logical thread count
        cpu_threads()
    }
}

/// Total memory detected at boot (bytes), set once by init_memory()
static mut TOTAL_MEMORY_BYTES: u64 = 0;

/// Initialize memory detection from multiboot info. Call once at boot.
///
/// # Safety
/// `multiboot_info` must point to a valid multiboot info structure.
pub unsafe fn init_memory(multiboot_info: u32, is_multiboot2: bool) {
    let bytes = if is_multiboot2 {
        total_memory_mb_mb2(multiboot_info) as u64 * 1024 * 1024
    } else {
        total_memory_bytes_mb1(multiboot_info)
    };
    unsafe { TOTAL_MEMORY_BYTES = bytes; }
}

/// Get total detected memory in bytes (0 if not yet detected)
pub fn total_memory_bytes() -> u64 {
    unsafe { TOTAL_MEMORY_BYTES }
}

/// Parse Multiboot1 memory info and return total usable memory in bytes
///
/// Multiboot1 info structure:
///   offset 0: flags
///   offset 4: mem_lower (KB below 1MB, if flags bit 0)
///   offset 8: mem_upper (KB above 1MB, if flags bit 0)
///
/// # Safety
/// `multiboot_info` must point to a valid multiboot1 information structure.
unsafe fn total_memory_bytes_mb1(multiboot_info: u32) -> u64 {
    let info_ptr = multiboot_info as *const u32;
    let flags = unsafe { *info_ptr };

    // Bit 0 of flags indicates mem_lower/mem_upper are valid
    if flags & 1 == 0 {
        return 0;
    }

    let mem_lower_kb = unsafe { *info_ptr.add(1) } as u64; // KB below 1MB
    let mem_upper_kb = unsafe { *info_ptr.add(2) } as u64; // KB above 1MB

    (mem_lower_kb + mem_upper_kb) * 1024
}

/// Multiboot2 tag types for memory map
const MULTIBOOT2_TAG_TYPE_END: u32 = 0;
const MULTIBOOT2_TAG_TYPE_MMAP: u32 = 6;

/// Parse multiboot2 memory map and return total usable memory in MB
///
/// # Safety
/// `multiboot_info` must point to a valid multiboot2 information structure.
pub unsafe fn total_memory_mb_mb2(multiboot_info: u32) -> u32 {
    let info_ptr = multiboot_info as *const u8;
    // Multiboot2 info header: total_size (u32) + reserved (u32)
    let total_size = *(info_ptr as *const u32);
    let mut offset = 8u32; // Skip header

    let mut total_bytes: u64 = 0;

    while offset < total_size {
        let tag_ptr = info_ptr.add(offset as usize);
        let tag_type = *(tag_ptr as *const u32);
        let tag_size = *(tag_ptr.add(4) as *const u32);

        if tag_type == MULTIBOOT2_TAG_TYPE_END {
            break;
        }

        if tag_type == MULTIBOOT2_TAG_TYPE_MMAP {
            // Memory map tag:
            //   type (u32) + size (u32) + entry_size (u32) + entry_version (u32)
            //   followed by entries
            let entry_size = *(tag_ptr.add(8) as *const u32);
            let entries_start = 16u32; // After tag header + entry_size + entry_version
            let mut entry_offset = entries_start;

            while entry_offset + entry_size <= tag_size {
                let entry = tag_ptr.add(entry_offset as usize);
                let base = *(entry as *const u64);
                let length = *(entry.add(8) as *const u64);
                let mem_type = *(entry.add(16) as *const u32);

                // Type 1 = available RAM
                if mem_type == 1 {
                    let _ = base; // We just sum all usable regions
                    total_bytes += length;
                }

                entry_offset += entry_size;
            }
        }

        // Tags are 8-byte aligned
        offset += (tag_size + 7) & !7;
    }

    (total_bytes / (1024 * 1024)) as u32
}
