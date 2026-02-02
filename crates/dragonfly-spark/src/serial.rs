//! Serial port output (COM1)
//!
//! Outputs to COM1 (0x3F8) for debugging in QEMU and other environments

use crate::bios::{inb, outb};

const COM1: u16 = 0x3F8;

/// Initialize serial port
pub fn init() {
    unsafe {
        // Disable interrupts
        outb(COM1 + 1, 0x00);
        // Enable DLAB (set baud rate divisor)
        outb(COM1 + 3, 0x80);
        // Set divisor to 1 (115200 baud)
        outb(COM1 + 0, 0x01);
        outb(COM1 + 1, 0x00);
        // 8 bits, no parity, one stop bit
        outb(COM1 + 3, 0x03);
        // Enable FIFO, clear them, with 14-byte threshold
        outb(COM1 + 2, 0xC7);
        // IRQs enabled, RTS/DSR set
        outb(COM1 + 4, 0x0B);
    }
}

/// Check if transmit buffer is empty
fn is_transmit_empty() -> bool {
    unsafe { inb(COM1 + 5) & 0x20 != 0 }
}

/// Write a byte to serial
pub fn write_byte(byte: u8) {
    // Wait for transmit buffer to be empty
    while !is_transmit_empty() {}
    unsafe {
        outb(COM1, byte);
    }
}

/// Write a string to serial
pub fn print(s: &str) {
    for byte in s.bytes() {
        if byte == b'\n' {
            write_byte(b'\r');
        }
        write_byte(byte);
    }
}

/// Write a string with newline
pub fn println(s: &str) {
    print(s);
    write_byte(b'\r');
    write_byte(b'\n');
}

/// Print a decimal number
pub fn print_dec(mut val: u32) {
    if val == 0 {
        write_byte(b'0');
        return;
    }

    let mut buf = [0u8; 10];
    let mut i = 0;

    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        write_byte(buf[i]);
    }
}

/// Print a hex u32
pub fn print_hex32(val: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for i in (0..8).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        write_byte(HEX[nibble]);
    }
}

/// Print a single character
pub fn print_char(c: u8) {
    write_byte(c);
}
