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
        for i in 0..(WIDTH * HEIGHT) {
            unsafe {
                *VGA_BUFFER.add(i * 2) = b' ';
                *VGA_BUFFER.add(i * 2 + 1) = self.color;
            }
        }
        self.row = 0;
        self.col = 0;
    }

    fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = color_code(fg, bg);
    }
}

/// Initialize VGA
pub fn init() {
    let mut writer = WRITER.lock();
    writer.set_color(Color::LightCyan, Color::Black);
}

/// Clear the screen
pub fn clear() {
    WRITER.lock().clear();
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
