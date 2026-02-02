//! Framebuffer graphics - supports any resolution
//!
//! Parses multiboot2 info to find framebuffer and provides drawing primitives.
//! Resolution is determined at runtime from what the bootloader provides.

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
static FB: Mutex<Option<Framebuffer>> = Mutex::new(None);

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

/// Clear screen with a color
pub fn clear(color: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        unsafe {
            let fb_ptr = fb_info.addr as *mut u32;
            let pixels = (fb_info.pitch / 4) * fb_info.height;
            for i in 0..pixels {
                *fb_ptr.add(i as usize) = color;
            }
        }
    }
}

/// Draw a single pixel
pub fn put_pixel(x: u32, y: u32, color: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        if x < fb_info.width && y < fb_info.height {
            unsafe {
                let offset = y * fb_info.pitch / 4 + x;
                let fb_ptr = fb_info.addr as *mut u32;
                *fb_ptr.add(offset as usize) = color;
            }
        }
    }
}

/// Draw a filled rectangle
pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        unsafe {
            let fb_ptr = fb_info.addr as *mut u32;
            let pitch = fb_info.pitch / 4;

            for row in 0..h {
                if y + row >= fb_info.height {
                    break;
                }
                for col in 0..w {
                    if x + col >= fb_info.width {
                        break;
                    }
                    let offset = (y + row) * pitch + (x + col);
                    *fb_ptr.add(offset as usize) = color;
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

/// Draw a horizontal gradient
pub fn fill_gradient_h(x: u32, y: u32, w: u32, h: u32, color1: u32, color2: u32) {
    let fb = FB.lock();
    if let Some(ref fb_info) = *fb {
        unsafe {
            let fb_ptr = fb_info.addr as *mut u32;
            let pitch = fb_info.pitch / 4;

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
                    let offset = (y + row) * pitch + (x + col);
                    *fb_ptr.add(offset as usize) = color;
                }
            }
        }
    }
}
