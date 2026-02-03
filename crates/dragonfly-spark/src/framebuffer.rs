//! Framebuffer graphics - supports any resolution
//!
//! Parses multiboot1 and multiboot2 info to find framebuffer and provides drawing primitives.
//! Resolution is determined at runtime from what the bootloader provides.
//!
//! Multiboot 1 (iPXE) framebuffer info structure (when flags bit 12 is set):
//!   - framebuffer_addr at offset 88 (u64)
//!   - framebuffer_pitch at offset 96 (u32)
//!   - framebuffer_width at offset 100 (u32)
//!   - framebuffer_height at offset 104 (u32)
//!   - framebuffer_bpp at offset 108 (u8)
//!   - framebuffer_type at offset 109 (u8) - 0=indexed, 1=RGB, 2=EGA text

use spin::Mutex;

/// Dragonfly color palette (matching the web UI)
pub mod colors {
    /// Background color #0A0B10
    pub const BG_DARK: u32 = 0x0A0B10;
    /// Card/panel background
    pub const BG_PANEL: u32 = 0x12131A;
    /// Border color
    pub const BORDER: u32 = 0x222222;
    /// Primary text (white)
    pub const TEXT_PRIMARY: u32 = 0xF3F4F6;
    /// Secondary text (gray)
    pub const TEXT_SECONDARY: u32 = 0x9CA3AF;
    /// Purple accent (indigo-400)
    pub const ACCENT_PURPLE: u32 = 0x818CF8;
    /// Purple highlight (purple-500)
    pub const ACCENT_PURPLE_BRIGHT: u32 = 0xA855F7;
    /// Green success
    pub const SUCCESS: u32 = 0x22C55E;
    /// Yellow warning
    pub const WARNING: u32 = 0xEAB308;
    /// Red error
    pub const ERROR: u32 = 0xEF4444;
    /// Cyan accent
    pub const ACCENT_CYAN: u32 = 0x06B6D4;
}

/// Global framebuffer state
pub static FB: Mutex<Option<Framebuffer>> = Mutex::new(None);

/// Framebuffer info
#[derive(Clone, Copy)]
pub struct Framebuffer {
    pub addr: u32,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
}

/// Multiboot2 tag types
const MULTIBOOT2_TAG_TYPE_END: u32 = 0;
const MULTIBOOT2_TAG_TYPE_FRAMEBUFFER: u32 = 8;

/// Multiboot1 flags bit for framebuffer info
const MULTIBOOT1_FLAG_FRAMEBUFFER: u32 = 1 << 12;

/// Multiboot1 framebuffer types
const _MULTIBOOT1_FB_TYPE_INDEXED: u8 = 0;
const MULTIBOOT1_FB_TYPE_RGB: u8 = 1;
const _MULTIBOOT1_FB_TYPE_EGA_TEXT: u8 = 2;

/// Fixed low-memory addresses from boot.s
const VBE_MODE_INFO_ADDR: u32 = 0x2000;
const VBE_STATUS_ADDR: u32 = 0x2100;

/// VBE mode info structure layout (standard VESA)
/// Offsets into vbe_mode_info buffer
const VBE_PITCH_OFFSET: usize = 16;      // u16 bytes per scan line
const VBE_WIDTH_OFFSET: usize = 18;      // u16 width
const VBE_HEIGHT_OFFSET: usize = 20;     // u16 height
const VBE_BPP_OFFSET: usize = 25;        // u8 bits per pixel
const VBE_FRAMEBUFFER_OFFSET: usize = 40; // u32 physical address of LFB

/// Initialize framebuffer from VBE info set by boot.s
pub fn init_from_boot_vbe() {
    unsafe {
        let status = *(VBE_STATUS_ADDR as *const u32);

        crate::serial::print("VBE status from boot.s: 0x");
        crate::serial::print_hex32(status);
        crate::serial::println("");

        // Check if VBE set mode succeeded (AX = 0x004F means success)
        if status != 0x004F {
            crate::serial::println("VBE: Mode set failed in boot.s");
            return;
        }

        // Read VBE mode info from low memory
        let info = VBE_MODE_INFO_ADDR as *const u8;

        let pitch = u16::from_le_bytes([
            *info.add(VBE_PITCH_OFFSET),
            *info.add(VBE_PITCH_OFFSET + 1),
        ]) as u32;

        let width = u16::from_le_bytes([
            *info.add(VBE_WIDTH_OFFSET),
            *info.add(VBE_WIDTH_OFFSET + 1),
        ]) as u32;

        let height = u16::from_le_bytes([
            *info.add(VBE_HEIGHT_OFFSET),
            *info.add(VBE_HEIGHT_OFFSET + 1),
        ]) as u32;

        let bpp = *info.add(VBE_BPP_OFFSET);

        let fb_addr = u32::from_le_bytes([
            *info.add(VBE_FRAMEBUFFER_OFFSET),
            *info.add(VBE_FRAMEBUFFER_OFFSET + 1),
            *info.add(VBE_FRAMEBUFFER_OFFSET + 2),
            *info.add(VBE_FRAMEBUFFER_OFFSET + 3),
        ]);

        crate::serial::print("VBE: ");
        crate::serial::print_dec(width);
        crate::serial::print("x");
        crate::serial::print_dec(height);
        crate::serial::print("x");
        crate::serial::print_dec(bpp as u32);
        crate::serial::print(" @ 0x");
        crate::serial::print_hex32(fb_addr);
        crate::serial::print(" pitch=");
        crate::serial::print_dec(pitch);
        crate::serial::println("");

        // Sanity check
        if width == 0 || height == 0 || bpp == 0 || fb_addr == 0 {
            crate::serial::println("VBE: Invalid mode info");
            return;
        }

        *FB.lock() = Some(Framebuffer {
            addr: fb_addr,
            pitch,
            width,
            height,
            bpp,
        });

        crate::serial::println("VBE: Framebuffer initialized from boot.s!");
    }
}

/// Initialize framebuffer from multiboot1 info (iPXE boot)
pub fn init_mb1(multiboot_info: u32) {
    let fb = parse_multiboot1_framebuffer(multiboot_info);

    if let Some(fb_info) = fb {
        crate::serial::print("MB1 Framebuffer found: ");
        crate::serial::print_dec(fb_info.width);
        crate::serial::print("x");
        crate::serial::print_dec(fb_info.height);
        crate::serial::print("x");
        crate::serial::print_dec(fb_info.bpp as u32);
        crate::serial::print(" @ 0x");
        crate::serial::print_hex32(fb_info.addr);
        crate::serial::println("");

        *FB.lock() = Some(fb_info);
    } else {
        crate::serial::println("WARNING: No MB1 framebuffer found, falling back to VGA text mode");
    }
}

/// Parse multiboot1 info structure to find framebuffer
fn parse_multiboot1_framebuffer(info_addr: u32) -> Option<Framebuffer> {
    unsafe {
        // Multiboot1 info structure offsets:
        // 0:  flags (u32)
        // 88: framebuffer_addr (u64)
        // 96: framebuffer_pitch (u32)
        // 100: framebuffer_width (u32)
        // 104: framebuffer_height (u32)
        // 108: framebuffer_bpp (u8)
        // 109: framebuffer_type (u8)

        let flags = *(info_addr as *const u32);

        // Check if framebuffer info is available (bit 12)
        if (flags & MULTIBOOT1_FLAG_FRAMEBUFFER) == 0 {
            crate::serial::print("MB1: flags=0x");
            crate::serial::print_hex32(flags);
            crate::serial::println(" - no framebuffer bit set");
            return None;
        }

        let fb_addr_lo = *((info_addr + 88) as *const u32);
        let _fb_addr_hi = *((info_addr + 92) as *const u32);
        let fb_pitch = *((info_addr + 96) as *const u32);
        let fb_width = *((info_addr + 100) as *const u32);
        let fb_height = *((info_addr + 104) as *const u32);
        let fb_bpp = *((info_addr + 108) as *const u8);
        let fb_type = *((info_addr + 109) as *const u8);

        crate::serial::print("MB1: framebuffer type=");
        crate::serial::print_dec(fb_type as u32);
        crate::serial::println("");

        // Only support RGB framebuffer (type 1)
        if fb_type != MULTIBOOT1_FB_TYPE_RGB {
            crate::serial::println("MB1: framebuffer is not RGB type, cannot use");
            return None;
        }

        // Sanity check dimensions
        if fb_width == 0 || fb_height == 0 || fb_bpp == 0 {
            crate::serial::println("MB1: invalid framebuffer dimensions");
            return None;
        }

        Some(Framebuffer {
            addr: fb_addr_lo,
            pitch: fb_pitch,
            width: fb_width,
            height: fb_height,
            bpp: fb_bpp,
        })
    }
}

/// Initialize framebuffer from multiboot2 info
pub fn init(multiboot_info: u32) {
    let fb = parse_multiboot2_framebuffer(multiboot_info);

    if let Some(fb_info) = fb {
        crate::serial::print("Framebuffer found: ");
        crate::serial::print_dec(fb_info.width);
        crate::serial::print("x");
        crate::serial::print_dec(fb_info.height);
        crate::serial::print("x");
        crate::serial::print_dec(fb_info.bpp as u32);
        crate::serial::print(" @ 0x");
        crate::serial::print_hex32(fb_info.addr);
        crate::serial::println("");

        *FB.lock() = Some(fb_info);
    } else {
        crate::serial::println("WARNING: No framebuffer found, falling back to VGA text mode");
    }
}

/// Check if framebuffer is available
pub fn is_available() -> bool {
    FB.lock().is_some()
}

/// Get screen dimensions (width, height)
pub fn dimensions() -> Option<(u32, u32)> {
    FB.lock().map(|fb| (fb.width, fb.height))
}

/// Get framebuffer info
pub fn info() -> Option<Framebuffer> {
    *FB.lock()
}

/// Parse multiboot2 info structure to find framebuffer tag
fn parse_multiboot2_framebuffer(info_addr: u32) -> Option<Framebuffer> {
    unsafe {
        // Multiboot2 info structure:
        // u32 total_size
        // u32 reserved
        // tags...

        let total_size = *(info_addr as *const u32);
        let mut tag_addr = info_addr + 8; // Skip size and reserved
        let end_addr = info_addr + total_size;

        while tag_addr < end_addr {
            // Each tag:
            // u32 type
            // u32 size
            // ... data
            let tag_type = *(tag_addr as *const u32);
            let tag_size = *((tag_addr + 4) as *const u32);

            if tag_type == MULTIBOOT2_TAG_TYPE_END {
                break;
            }

            if tag_type == MULTIBOOT2_TAG_TYPE_FRAMEBUFFER {
                // Framebuffer tag structure:
                // u32 type
                // u32 size
                // u64 framebuffer_addr
                // u32 framebuffer_pitch
                // u32 framebuffer_width
                // u32 framebuffer_height
                // u8  framebuffer_bpp
                // u8  framebuffer_type (1 = RGB)
                // u8  reserved

                let fb_addr_lo = *((tag_addr + 8) as *const u32);
                let _fb_addr_hi = *((tag_addr + 12) as *const u32);
                let fb_pitch = *((tag_addr + 16) as *const u32);
                let fb_width = *((tag_addr + 20) as *const u32);
                let fb_height = *((tag_addr + 24) as *const u32);
                let fb_bpp = *((tag_addr + 28) as *const u8);

                return Some(Framebuffer {
                    addr: fb_addr_lo,
                    pitch: fb_pitch,
                    width: fb_width,
                    height: fb_height,
                    bpp: fb_bpp,
                });
            }

            // Move to next tag (8-byte aligned)
            tag_addr += (tag_size + 7) & !7;
        }

        None
    }
}

/// Clear screen with a color (handles 24bpp and 32bpp)
pub fn clear(color: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        unsafe {
            if fb_info.bpp == 24 {
                // 24bpp: 3 bytes per pixel
                let fb_ptr = fb_info.addr as *mut u8;
                let b = color as u8;
                let g = (color >> 8) as u8;
                let r = (color >> 16) as u8;
                let total_bytes = (fb_info.pitch * fb_info.height) as usize;
                let mut i = 0;
                while i < total_bytes {
                    *fb_ptr.add(i) = b;
                    *fb_ptr.add(i + 1) = g;
                    *fb_ptr.add(i + 2) = r;
                    i += 3;
                }
            } else {
                // 32bpp: 4 bytes per pixel
                let fb_ptr = fb_info.addr as *mut u32;
                let pixels = (fb_info.pitch / 4) * fb_info.height;
                for i in 0..pixels {
                    *fb_ptr.add(i as usize) = color;
                }
            }
        }
    }
}

/// Draw a single pixel (handles 24bpp and 32bpp)
pub fn put_pixel(x: u32, y: u32, color: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        if x < fb_info.width && y < fb_info.height {
            unsafe {
                let fb_ptr = fb_info.addr as *mut u8;
                if fb_info.bpp == 24 {
                    // 24bpp: 3 bytes per pixel (BGR order)
                    let byte_offset = (y * fb_info.pitch + x * 3) as usize;
                    *fb_ptr.add(byte_offset) = color as u8;           // B
                    *fb_ptr.add(byte_offset + 1) = (color >> 8) as u8;  // G
                    *fb_ptr.add(byte_offset + 2) = (color >> 16) as u8; // R
                } else {
                    // 32bpp: 4 bytes per pixel
                    let offset = y * fb_info.pitch / 4 + x;
                    let fb_ptr32 = fb_info.addr as *mut u32;
                    *fb_ptr32.add(offset as usize) = color;
                }
            }
        }
    }
}

/// Draw a filled rectangle (handles 24bpp and 32bpp)
pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        unsafe {
            let b = color as u8;
            let g = (color >> 8) as u8;
            let r = (color >> 16) as u8;

            for row in 0..h {
                if y + row >= fb_info.height {
                    break;
                }
                for col in 0..w {
                    if x + col >= fb_info.width {
                        break;
                    }
                    if fb_info.bpp == 24 {
                        // 24bpp: 3 bytes per pixel (BGR order)
                        let fb_ptr = fb_info.addr as *mut u8;
                        let byte_offset = ((y + row) * fb_info.pitch + (x + col) * 3) as usize;
                        *fb_ptr.add(byte_offset) = b;
                        *fb_ptr.add(byte_offset + 1) = g;
                        *fb_ptr.add(byte_offset + 2) = r;
                    } else {
                        // 32bpp: 4 bytes per pixel
                        let fb_ptr = fb_info.addr as *mut u32;
                        let pitch = fb_info.pitch / 4;
                        let offset = (y + row) * pitch + (x + col);
                        *fb_ptr.add(offset as usize) = color;
                    }
                }
            }
        }
    }
}

/// Draw a rectangle outline
pub fn draw_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    // Top and bottom
    fill_rect(x, y, w, 1, color);
    fill_rect(x, y + h - 1, w, 1, color);
    // Left and right
    fill_rect(x, y, 1, h, color);
    fill_rect(x + w - 1, y, 1, h, color);
}

/// Draw a rounded rectangle (simplified - just corners)
pub fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, radius: u32, color: u32) {
    if radius == 0 {
        draw_rect(x, y, w, h, color);
        return;
    }

    let r = radius.min(w / 2).min(h / 2);

    // Top edge (minus corners)
    fill_rect(x + r, y, w - 2 * r, 1, color);
    // Bottom edge
    fill_rect(x + r, y + h - 1, w - 2 * r, 1, color);
    // Left edge
    fill_rect(x, y + r, 1, h - 2 * r, color);
    // Right edge
    fill_rect(x + w - 1, y + r, 1, h - 2 * r, color);

    // Simplified corner pixels
    for i in 0..r {
        // Top-left
        put_pixel(x + r - i - 1, y + r - i - 1, color);
        // Top-right
        put_pixel(x + w - r + i, y + r - i - 1, color);
        // Bottom-left
        put_pixel(x + r - i - 1, y + h - r + i, color);
        // Bottom-right
        put_pixel(x + w - r + i, y + h - r + i, color);
    }
}

/// Fill a rounded rectangle
pub fn fill_rounded_rect(x: u32, y: u32, w: u32, h: u32, radius: u32, color: u32) {
    if radius == 0 {
        fill_rect(x, y, w, h, color);
        return;
    }

    let r = radius.min(w / 2).min(h / 2);

    // Main body (without corners)
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, r, h - 2 * r, color);
    fill_rect(x + w - r, y + r, r, h - 2 * r, color);

    // Corners (simple quarter circles approximation)
    for cy in 0..r {
        for cx in 0..r {
            let dx = r - cx - 1;
            let dy = r - cy - 1;
            if dx * dx + dy * dy <= r * r {
                // Top-left
                put_pixel(x + cx, y + cy, color);
                // Top-right
                put_pixel(x + w - 1 - cx, y + cy, color);
                // Bottom-left
                put_pixel(x + cx, y + h - 1 - cy, color);
                // Bottom-right
                put_pixel(x + w - 1 - cx, y + h - 1 - cy, color);
            }
        }
    }
}

/// Draw a horizontal gradient (handles 24bpp and 32bpp)
pub fn fill_gradient_h(x: u32, y: u32, w: u32, h: u32, color1: u32, color2: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        unsafe {
            let r1 = ((color1 >> 16) & 0xFF) as i32;
            let g1 = ((color1 >> 8) & 0xFF) as i32;
            let b1 = (color1 & 0xFF) as i32;

            let r2 = ((color2 >> 16) & 0xFF) as i32;
            let g2 = ((color2 >> 8) & 0xFF) as i32;
            let b2 = (color2 & 0xFF) as i32;

            for col in 0..w {
                if x + col >= fb_info.width {
                    break;
                }

                let t = col as i32;
                let w_i = w as i32;

                let r = (r1 + (r2 - r1) * t / w_i) as u32;
                let g = (g1 + (g2 - g1) * t / w_i) as u32;
                let b = (b1 + (b2 - b1) * t / w_i) as u32;
                let color = (r << 16) | (g << 8) | b;

                for row in 0..h {
                    if y + row >= fb_info.height {
                        break;
                    }
                    if fb_info.bpp == 24 {
                        // 24bpp: 3 bytes per pixel (BGR order)
                        let fb_ptr = fb_info.addr as *mut u8;
                        let byte_offset = ((y + row) * fb_info.pitch + (x + col) * 3) as usize;
                        *fb_ptr.add(byte_offset) = b as u8;
                        *fb_ptr.add(byte_offset + 1) = g as u8;
                        *fb_ptr.add(byte_offset + 2) = r as u8;
                    } else {
                        // 32bpp
                        let fb_ptr = fb_info.addr as *mut u32;
                        let pitch = fb_info.pitch / 4;
                        let offset = (y + row) * pitch + (x + col);
                        *fb_ptr.add(offset as usize) = color;
                    }
                }
            }
        }
    }
}
