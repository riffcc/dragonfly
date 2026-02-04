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

/// Escape scancode
pub const SCANCODE_ESC: u8 = 0x01;
/// Backspace scancode
pub const SCANCODE_BACKSPACE: u8 = 0x0E;

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

/// Extended scancode to ASCII - includes letters, punctuation for URL entry
pub fn scancode_to_ascii_full(scancode: u8) -> Option<char> {
    // Only handle key press (not release)
    if scancode & 0x80 != 0 {
        return None;
    }

    match scancode {
        // Numbers
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
        // Letters (lowercase)
        0x10 => Some('q'),
        0x11 => Some('w'),
        0x12 => Some('e'),
        0x13 => Some('r'),
        0x14 => Some('t'),
        0x15 => Some('y'),
        0x16 => Some('u'),
        0x17 => Some('i'),
        0x18 => Some('o'),
        0x19 => Some('p'),
        0x1E => Some('a'),
        0x1F => Some('s'),
        0x20 => Some('d'),
        0x21 => Some('f'),
        0x22 => Some('g'),
        0x23 => Some('h'),
        0x24 => Some('j'),
        0x25 => Some('k'),
        0x26 => Some('l'),
        0x2C => Some('z'),
        0x2D => Some('x'),
        0x2E => Some('c'),
        0x2F => Some('v'),
        0x30 => Some('b'),
        0x31 => Some('n'),
        0x32 => Some('m'),
        // Punctuation for URLs
        0x0C => Some('-'),  // minus
        0x0D => Some('='),
        0x27 => Some(';'),
        0x28 => Some('\''),
        0x33 => Some(','),
        0x34 => Some('.'),  // period
        0x35 => Some('/'),  // forward slash
        0x1A => Some('['),
        0x1B => Some(']'),
        // Special
        0x1C => Some('\n'), // Enter
        0x39 => Some(' '),  // Space
        // Shift+; = colon (for http://) - handled via separate shift-aware path
        _ => None,
    }
}

/// Check if shift key is held (read keyboard status byte)
pub fn is_shift_held() -> bool {
    // Read keyboard flags from BIOS data area at 0x0417
    // Bit 0 = right shift, bit 1 = left shift
    unsafe {
        let flags = *(0x0417 as *const u8);
        (flags & 0x03) != 0
    }
}

/// Get ASCII with shift awareness for URL entry
pub fn scancode_to_url_char(scancode: u8) -> Option<char> {
    // Only handle key press (not release)
    if scancode & 0x80 != 0 {
        return None;
    }

    let shifted = is_shift_held();

    if shifted {
        // Shifted characters needed for URLs
        match scancode {
            0x27 => return Some(':'),  // Shift+; = colon
            0x35 => return Some('?'),  // Shift+/ = question mark
            0x0D => return Some('+'),  // Shift+= = plus
            0x1A => return Some('{'),
            0x1B => return Some('}'),
            0x33 => return Some('<'),
            0x34 => return Some('>'),
            0x0C => return Some('_'),  // Shift+- = underscore
            _ => {}
        }
    }

    scancode_to_ascii_full(scancode)
}
