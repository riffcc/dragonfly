//! BIOS and low-level I/O
//!
//! For protected mode, we use direct port I/O instead of BIOS calls where possible.
//! This avoids the complexity of switching to real mode.

/// Read a byte from an I/O port
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Write a byte to an I/O port
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read a word from an I/O port
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Write a word to an I/O port
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read multiple words from an I/O port (for PIO disk reads)
#[inline]
pub unsafe fn insw(port: u16, buffer: &mut [u16]) {
    unsafe {
        core::arch::asm!(
            "cld",           // Clear direction flag (increment mode)
            "rep insw",
            in("dx") port,
            in("ecx") buffer.len(),
            in("edi") buffer.as_mut_ptr(),
            options(nostack)
        );
    }
}

/// Small delay using I/O port
#[inline]
pub fn io_wait() {
    unsafe {
        outb(0x80, 0); // Port 0x80 is used for POST codes, writing to it causes a small delay
    }
}

/// Reboot the system using keyboard controller
pub fn reboot() -> ! {
    unsafe {
        // Try keyboard controller reset
        let mut good = false;
        for _ in 0..100 {
            if inb(0x64) & 0x02 == 0 {
                good = true;
                break;
            }
            io_wait();
        }
        if good {
            outb(0x64, 0xFE); // Pulse CPU reset line
        }

        // If that didn't work, triple fault
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &0u64,
            options(noreturn)
        );
    }
}

/// Read keyboard scancode (non-blocking)
pub fn read_scancode() -> Option<u8> {
    unsafe {
        // Check if data is available
        if inb(0x64) & 0x01 != 0 {
            Some(inb(0x60))
        } else {
            None
        }
    }
}

/// Wait for and read keyboard scancode (blocking)
pub fn wait_scancode() -> u8 {
    loop {
        if let Some(scancode) = read_scancode() {
            return scancode;
        }
    }
}

/// Scancode to ASCII (simplified - just handles basic keys)
pub fn scancode_to_ascii(scancode: u8) -> Option<char> {
    // Only handle key press (not release)
    if scancode & 0x80 != 0 {
        return None;
    }

    match scancode {
        0x02 => Some('1'),
        0x03 => Some('2'),
        0x04 => Some('3'),
        0x05 => Some('4'),
        0x06 => Some('5'),
        0x07 => Some('6'),
        0x08 => Some('7'),
        0x09 => Some('8'),
        0x0A => Some('9'),
        0x0B => Some('0'),
        0x1C => Some('\n'), // Enter
        0x39 => Some(' '),  // Space
        _ => None,
    }
}
