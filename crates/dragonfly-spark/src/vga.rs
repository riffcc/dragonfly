//! VGA text mode output
//!
//! Direct manipulation of VGA text buffer at 0xB8000
//! Standard 80x25 text mode with 16 colors

use spin::Mutex;

/// VGA buffer address
const VGA_BUFFER: *mut u8 = 0xB8000 as *mut u8;

/// Screen dimensions
const WIDTH: usize = 80;
const HEIGHT: usize = 25;

/// Color codes
#[repr(u8)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

/// Color attribute byte
const fn color_code(fg: Color, bg: Color) -> u8 {
    (bg as u8) << 4 | (fg as u8)
}

/// Global writer state
static WRITER: Mutex<Writer> = Mutex::new(Writer {
    col: 0,
    row: 0,
    color: color_code(Color::LightGray, Color::Black),
});

/// Writer state
struct Writer {
    col: usize,
    row: usize,
    color: u8,
}

impl Writer {
    fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => {
                self.newline();
            }
            byte => {
                if self.col >= WIDTH {
                    self.newline();
                }

                let offset = (self.row * WIDTH + self.col) * 2;
                unsafe {
                    *VGA_BUFFER.add(offset) = byte;
                    *VGA_BUFFER.add(offset + 1) = self.color;
                }
                self.col += 1;
            }
        }
    }

    fn newline(&mut self) {
        self.row += 1;
        self.col = 0;

        if self.row >= HEIGHT {
            self.scroll();
        }
    }

    fn scroll(&mut self) {
        // Move all lines up by one
        unsafe {
            core::ptr::copy(
                VGA_BUFFER.add(WIDTH * 2),
                VGA_BUFFER,
                WIDTH * (HEIGHT - 1) * 2,
            );
        }

        // Clear the last line
        let last_row_offset = (HEIGHT - 1) * WIDTH * 2;
        for col in 0..WIDTH {
            unsafe {
                *VGA_BUFFER.add(last_row_offset + col * 2) = b' ';
                *VGA_BUFFER.add(last_row_offset + col * 2 + 1) = self.color;
            }
        }

        self.row = HEIGHT - 1;
    }

    fn clear(&mut self) {
        use crate::serial;
        serial::print("VGA: clear loop start, buffer=0x");
        serial::print_hex32(VGA_BUFFER as u32);
        serial::println("");

        // Try writing first byte
        serial::println("VGA: Writing first byte...");
        unsafe {
            core::ptr::write_volatile(VGA_BUFFER, b' ');
        }
        serial::println("VGA: First byte written!");

        for i in 0..(WIDTH * HEIGHT) {
            unsafe {
                core::ptr::write_volatile(VGA_BUFFER.add(i * 2), b' ');
                core::ptr::write_volatile(VGA_BUFFER.add(i * 2 + 1), self.color);
            }
        }
        serial::println("VGA: clear loop done");
        self.row = 0;
        self.col = 0;
    }

    fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = color_code(fg, bg);
    }
}

/// Initialize VGA - switch to text mode if needed
pub fn init() {
    // Switch to VGA text mode (mode 3: 80x25, 16 colors)
    // This is needed when we're in graphical framebuffer mode
    unsafe {
        set_text_mode();
    }

    let mut writer = WRITER.lock();
    writer.set_color(Color::LightCyan, Color::Black);
}

/// Switch VGA to text mode 3 (80x25)
unsafe fn set_text_mode() {
    use crate::serial;
    serial::println("VGA: set_text_mode() starting...");

    // VGA register ports
    const MISC_OUTPUT_WRITE: u16 = 0x3C2;
    const SEQ_INDEX: u16 = 0x3C4;
    const SEQ_DATA: u16 = 0x3C5;
    const GC_INDEX: u16 = 0x3CE;
    const GC_DATA: u16 = 0x3CF;
    const CRTC_INDEX: u16 = 0x3D4;
    const CRTC_DATA: u16 = 0x3D5;
    const ATTR_INDEX: u16 = 0x3C0;
    const ATTR_DATA_WRITE: u16 = 0x3C0;
    const INPUT_STATUS_1: u16 = 0x3DA;

    // Helper to write to port
    fn outb(port: u16, value: u8) {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    fn inb(port: u16) -> u8 {
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

    serial::println("VGA: Writing MISC output...");
    // Miscellaneous Output Register - set for 80-column text mode
    // Bit 0: I/O address select (1 = 0x3Dx, 0 = 0x3Bx)
    // Bit 1: RAM enable
    // Bits 2-3: Clock select (0 = 25MHz for text mode)
    // Bit 5: Page bit for odd/even (0 for text)
    // Bits 6-7: Horizontal sync polarity
    outb(MISC_OUTPUT_WRITE, 0x67);

    serial::println("VGA: Writing SEQ regs...");
    // Sequencer registers for text mode
    let seq_regs: [(u8, u8); 5] = [
        (0x00, 0x03), // Reset register
        (0x01, 0x00), // Clocking mode (8 dots/char)
        (0x02, 0x03), // Map mask (planes 0 and 1 for text)
        (0x03, 0x00), // Character map select
        (0x04, 0x02), // Memory mode (odd/even addressing)
    ];

    for (index, value) in seq_regs.iter() {
        outb(SEQ_INDEX, *index);
        outb(SEQ_DATA, *value);
    }

    serial::println("VGA: Unlocking CRTC...");
    // Unlock CRTC registers (write directly without read-modify-write)
    outb(CRTC_INDEX, 0x03);
    serial::println("VGA: CRTC index 0x03 set");
    outb(CRTC_DATA, 0x80); // Just set the unlock bit
    serial::println("VGA: CRTC 0x03 written");
    outb(CRTC_INDEX, 0x11);
    serial::println("VGA: CRTC index 0x11 set");
    outb(CRTC_DATA, 0x0E); // Clear protection bit (standard value for mode 3)
    serial::println("VGA: CRTC 0x11 written");

    serial::println("VGA: Writing CRTC regs...");
    // CRTC registers for 80x25 text mode - write directly without array
    outb(CRTC_INDEX, 0x00); outb(CRTC_DATA, 0x5F); serial::print("0");
    outb(CRTC_INDEX, 0x01); outb(CRTC_DATA, 0x4F); serial::print("1");
    outb(CRTC_INDEX, 0x02); outb(CRTC_DATA, 0x50); serial::print("2");
    outb(CRTC_INDEX, 0x03); outb(CRTC_DATA, 0x82); serial::print("3");
    outb(CRTC_INDEX, 0x04); outb(CRTC_DATA, 0x55); serial::print("4");
    outb(CRTC_INDEX, 0x05); outb(CRTC_DATA, 0x81); serial::print("5");
    outb(CRTC_INDEX, 0x06); outb(CRTC_DATA, 0xBF); serial::print("6");
    outb(CRTC_INDEX, 0x07); outb(CRTC_DATA, 0x1F); serial::print("7");
    outb(CRTC_INDEX, 0x08); outb(CRTC_DATA, 0x00); serial::print("8");
    outb(CRTC_INDEX, 0x09); outb(CRTC_DATA, 0x4F); serial::print("9");
    outb(CRTC_INDEX, 0x0A); outb(CRTC_DATA, 0x0D); serial::print("A");
    outb(CRTC_INDEX, 0x0B); outb(CRTC_DATA, 0x0E); serial::print("B");
    outb(CRTC_INDEX, 0x0C); outb(CRTC_DATA, 0x00); serial::print("C");
    outb(CRTC_INDEX, 0x0D); outb(CRTC_DATA, 0x00); serial::print("D");
    outb(CRTC_INDEX, 0x0E); outb(CRTC_DATA, 0x00); serial::print("E");
    outb(CRTC_INDEX, 0x0F); outb(CRTC_DATA, 0x00); serial::print("F");
    outb(CRTC_INDEX, 0x10); outb(CRTC_DATA, 0x9C); serial::print("G");
    outb(CRTC_INDEX, 0x11); outb(CRTC_DATA, 0x0E); serial::print("H");
    outb(CRTC_INDEX, 0x12); outb(CRTC_DATA, 0x8F); serial::print("I");
    outb(CRTC_INDEX, 0x13); outb(CRTC_DATA, 0x28); serial::print("J");
    outb(CRTC_INDEX, 0x14); outb(CRTC_DATA, 0x1F); serial::print("K");
    outb(CRTC_INDEX, 0x15); outb(CRTC_DATA, 0x96); serial::print("L");
    outb(CRTC_INDEX, 0x16); outb(CRTC_DATA, 0xB9); serial::print("M");
    outb(CRTC_INDEX, 0x17); outb(CRTC_DATA, 0xA3); serial::print("N");
    outb(CRTC_INDEX, 0x18); outb(CRTC_DATA, 0xFF); serial::println("O");

    serial::println("VGA: Writing GC regs...");
    // Graphics controller registers for text mode - write directly
    outb(GC_INDEX, 0x00); outb(GC_DATA, 0x00); serial::print("0");
    outb(GC_INDEX, 0x01); outb(GC_DATA, 0x00); serial::print("1");
    outb(GC_INDEX, 0x02); outb(GC_DATA, 0x00); serial::print("2");
    outb(GC_INDEX, 0x03); outb(GC_DATA, 0x00); serial::print("3");
    outb(GC_INDEX, 0x04); outb(GC_DATA, 0x00); serial::print("4");
    outb(GC_INDEX, 0x05); outb(GC_DATA, 0x10); serial::print("5");
    outb(GC_INDEX, 0x06); outb(GC_DATA, 0x0E); serial::print("6");
    outb(GC_INDEX, 0x07); outb(GC_DATA, 0x00); serial::print("7");
    outb(GC_INDEX, 0x08); outb(GC_DATA, 0xFF); serial::println("8");

    serial::println("VGA: Writing ATTR regs...");
    // Reset attribute controller flip-flop by reading status register
    let _ = inb(INPUT_STATUS_1);
    serial::print("R");

    // Attribute controller registers - write directly
    // Palette 0-7
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x00); outb(ATTR_DATA_WRITE, 0x00); serial::print("0");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x01); outb(ATTR_DATA_WRITE, 0x01); serial::print("1");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x02); outb(ATTR_DATA_WRITE, 0x02); serial::print("2");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x03); outb(ATTR_DATA_WRITE, 0x03); serial::print("3");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x04); outb(ATTR_DATA_WRITE, 0x04); serial::print("4");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x05); outb(ATTR_DATA_WRITE, 0x05); serial::print("5");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x06); outb(ATTR_DATA_WRITE, 0x06); serial::print("6");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x07); outb(ATTR_DATA_WRITE, 0x07); serial::print("7");
    // Palette 8-15
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x08); outb(ATTR_DATA_WRITE, 0x38); serial::print("8");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x09); outb(ATTR_DATA_WRITE, 0x39); serial::print("9");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x0A); outb(ATTR_DATA_WRITE, 0x3A); serial::print("A");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x0B); outb(ATTR_DATA_WRITE, 0x3B); serial::print("B");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x0C); outb(ATTR_DATA_WRITE, 0x3C); serial::print("C");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x0D); outb(ATTR_DATA_WRITE, 0x3D); serial::print("D");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x0E); outb(ATTR_DATA_WRITE, 0x3E); serial::print("E");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x0F); outb(ATTR_DATA_WRITE, 0x3F); serial::print("F");
    // Mode registers
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x10); outb(ATTR_DATA_WRITE, 0x0C); serial::print("G");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x11); outb(ATTR_DATA_WRITE, 0x00); serial::print("H");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x12); outb(ATTR_DATA_WRITE, 0x0F); serial::print("I");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x13); outb(ATTR_DATA_WRITE, 0x08); serial::print("J");
    let _ = inb(INPUT_STATUS_1); outb(ATTR_INDEX, 0x14); outb(ATTR_DATA_WRITE, 0x00); serial::println("K");

    serial::println("VGA: Enabling video output...");
    // Enable video output
    let _ = inb(INPUT_STATUS_1);
    outb(ATTR_INDEX, 0x20);
    serial::println("VGA: Text mode set complete!");
}

/// Clear the screen
pub fn clear() {
    use crate::serial;
    serial::println("VGA: clear() called");
    serial::print("VGA: buffer addr = 0x");
    serial::print_hex32(VGA_BUFFER as u32);
    serial::println("");

    serial::println("VGA: About to write first byte...");
    // Write directly to VGA buffer without lock
    unsafe {
        core::ptr::write_volatile(VGA_BUFFER, b'X');
    }
    serial::println("VGA: First byte written");

    serial::println("VGA: Starting clear loop...");
    unsafe {
        for i in 0..(WIDTH * HEIGHT) {
            core::ptr::write_volatile(VGA_BUFFER.add(i * 2), b' ');
            core::ptr::write_volatile(VGA_BUFFER.add(i * 2 + 1), 0x0B); // Light cyan on black
        }
    }
    serial::println("VGA: Loop done");

    // Skip cursor reset for now - causes lock issues
    // TODO: Fix spin lock handling

    serial::println("VGA: clear() done");
}

/// Print a string
pub fn print(s: &str) {
    let mut writer = WRITER.lock();
    for byte in s.bytes() {
        writer.write_byte(byte);
    }
}

/// Print a string with newline
pub fn println(s: &str) {
    let mut writer = WRITER.lock();
    for byte in s.bytes() {
        writer.write_byte(byte);
    }
    writer.write_byte(b'\n');
}

/// Print a hex byte
pub fn print_hex8(val: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut writer = WRITER.lock();
    writer.write_byte(HEX[(val >> 4) as usize]);
    writer.write_byte(HEX[(val & 0xF) as usize]);
}

/// Print a hex u16
pub fn print_hex16(val: u16) {
    print_hex8((val >> 8) as u8);
    print_hex8(val as u8);
}

/// Print a hex u32
pub fn print_hex32(val: u32) {
    print_hex16((val >> 16) as u16);
    print_hex16(val as u16);
}

/// Print a decimal number
pub fn print_dec(mut val: u32) {
    if val == 0 {
        print("0");
        return;
    }

    let mut buf = [0u8; 10];
    let mut i = 0;

    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }

    let mut writer = WRITER.lock();
    while i > 0 {
        i -= 1;
        writer.write_byte(buf[i]);
    }
}

/// Print an error message (red text)
pub fn print_error(s: &str) {
    let mut writer = WRITER.lock();
    let old_color = writer.color;
    writer.set_color(Color::LightRed, Color::Black);
    for byte in s.bytes() {
        writer.write_byte(byte);
    }
    writer.write_byte(b'\n');
    writer.color = old_color;
}

/// Print a success message (green text)
pub fn print_success(s: &str) {
    let mut writer = WRITER.lock();
    let old_color = writer.color;
    writer.set_color(Color::LightGreen, Color::Black);
    for byte in s.bytes() {
        writer.write_byte(byte);
    }
    writer.write_byte(b'\n');
    writer.color = old_color;
}

/// Print a warning message (yellow text)
pub fn print_warning(s: &str) {
    let mut writer = WRITER.lock();
    let old_color = writer.color;
    writer.set_color(Color::Yellow, Color::Black);
    for byte in s.bytes() {
        writer.write_byte(byte);
    }
    writer.write_byte(b'\n');
    writer.color = old_color;
}
