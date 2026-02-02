//! Dragonfly-style graphical UI
//!
//! Renders the boot menu with the Dragonfly visual style

use crate::disk::OsInfo;
use crate::font;
use crate::framebuffer::{self, colors};
use crate::bios;

/// Menu choices
pub enum Choice {
    BootLocal,
    Reinstall,
    Shell,
}

/// Boot timeout in seconds
const BOOT_TIMEOUT: u32 = 10;

/// Draw the Dragonfly splash screen and boot menu
pub fn draw_boot_screen(os: Option<&OsInfo>) -> Choice {
    let (width, height) = framebuffer::dimensions().unwrap_or((800, 600));

    // Clear to dark background
    framebuffer::clear(colors::BG_DARK);

    // Draw header area with gradient
    let header_h = draw_header(width);

    // Draw main content panel - sized based on remaining space
    let panel_w = 700.min(width - 100);
    let panel_y = header_h + 20;
    let panel_h = (height - panel_y - 60).min(400);
    let panel_x = (width - panel_w) / 2;

    // Panel background with border
    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::ACCENT_PURPLE);

    // Panel title - larger
    let title = match os {
        Some(_) => "Boot Menu",
        None => "No OS Detected",
    };
    let title_width = title.len() as u32 * 16; // 2x scale
    let title_x = (width - title_width) / 2;
    font::draw_string_large(title_x, panel_y + 25, title, colors::TEXT_PRIMARY);

    // Detected OS info
    if let Some(os_info) = os {
        let y = panel_y + 80;
        font::draw_string_centered(y, "Detected Operating System:", colors::TEXT_SECONDARY, width);
        // OS name in larger text - use detected name if available
        let os_name = os_info.display_name();
        let os_width = os_name.len() as u32 * 16;
        font::draw_string_large((width - os_width) / 2, y + 30, os_name, colors::ACCENT_PURPLE_BRIGHT);
    }

    // Menu options - bigger spacing
    let menu_y = panel_y + 160;
    let options = if os.is_some() {
        &[
            ("1", "Boot Local OS", "(default)"),
            ("2", "Reinstall / Imaging", ""),
            ("3", "Debug Shell", ""),
        ][..]
    } else {
        &[
            ("1", "Enter Imaging Mode", "(default)"),
            ("2", "Reboot", ""),
            ("3", "Debug Shell", ""),
        ][..]
    };

    for (i, (key, label, hint)) in options.iter().enumerate() {
        let y = menu_y + (i as u32 * 55); // More vertical space
        let option_x = panel_x + 80;

        // Key badge - bigger
        let badge_x = option_x;
        let badge_y = y;
        framebuffer::fill_rounded_rect(badge_x, badge_y, 40, 36, 6, colors::ACCENT_PURPLE);
        // Center the key in badge
        font::draw_string_large(badge_x + 12, badge_y + 10, key, colors::TEXT_PRIMARY);

        // Label - larger
        font::draw_string_large(badge_x + 60, badge_y + 10, label, colors::TEXT_PRIMARY);

        // Hint
        if !hint.is_empty() {
            let hint_x = badge_x + 60 + (label.len() as u32 + 1) * 16; // 2x char width
            font::draw_string_large(hint_x, badge_y + 10, hint, colors::TEXT_SECONDARY);
        }
    }

    // Countdown timer - in panel
    let timer_y = panel_y + panel_h - 70;
    draw_countdown(width, timer_y, BOOT_TIMEOUT);

    // Wait for input with timeout
    wait_for_choice(width, timer_y, os.is_some())
}

/// Draw the header with logo
fn draw_header(width: u32) -> u32 {
    // Calculate scale based on screen width
    // "Dragonfly" is 9 chars, at 8px per char = 72px at 1x
    // We want it to take ~50% of screen width max
    let logo_text = "Dragonfly";
    let base_width = logo_text.len() as u32 * 8; // 72px at scale 1
    let target_width = width / 2;
    let scale = (target_width / base_width).max(2).min(6); // Scale 2-6x

    let logo_pixel_width = base_width * scale;
    let logo_pixel_height = 16 * scale;
    let header_h = logo_pixel_height + 35; // Logo + padding + tagline

    // Header background gradient
    framebuffer::fill_gradient_h(0, 0, width, header_h, colors::BG_DARK, colors::BG_PANEL);

    // Top accent line
    framebuffer::fill_gradient_h(0, 0, width, 3, colors::ACCENT_PURPLE, colors::ACCENT_CYAN);

    // Logo - centered, scaled bitmap font
    let logo_x = (width - logo_pixel_width) / 2;
    let logo_y = 10;
    draw_string_scaled(logo_x, logo_y, logo_text, colors::ACCENT_PURPLE_BRIGHT, scale);

    // Tagline - positioned to the right of the 'g' tail
    // 'g' is the 4th char (index 3), ends at position 4
    let g_end_x = logo_x + (4 * 8 * scale) - (3 * scale); // account for f->l kerning
    let tagline_x = g_end_x + (2 * scale) + 8; // centered between g and y tails
    let tagline_y = logo_y + logo_pixel_height - 13; // align with descender area
    font::draw_string(tagline_x, tagline_y, "metal, managed", colors::TEXT_SECONDARY);

    header_h
}

/// Draw a string at arbitrary scale with kerning adjustments
fn draw_string_scaled(x: u32, y: u32, s: &str, color: u32, scale: u32) {
    let mut cx = x;
    let mut prev = '\0';
    for c in s.chars() {
        // Kerning: pull 'l' and 'y' closer to 'f' (the gap was before 'l')
        let kern: i32 = match (prev, c) {
            ('f', 'l') => -3, // Pull 'l' closer to 'f'
            _ => 0,
        };
        cx = (cx as i32 + kern * scale as i32) as u32;

        font::draw_char_scaled(cx, y, c, color, scale);
        cx += 8 * scale;
        prev = c;
    }
}

/// Draw countdown timer - larger text
fn draw_countdown(width: u32, y: u32, seconds: u32) {
    // Using large text (2x)
    let msg_width = 26 * 16; // "Auto-boot in XX seconds..." in 2x scale
    let x = (width - msg_width) / 2;

    font::draw_string_large(x, y, "Auto-boot in ", colors::TEXT_SECONDARY);
    // Leave space for number
    let num_x = x + 13 * 16;
    draw_number_large(num_x, y, seconds, colors::ACCENT_CYAN);
    font::draw_string_large(num_x + 3 * 16, y, " seconds...", colors::TEXT_SECONDARY);
}

/// Draw a number at 2x scale
fn draw_number_large(x: u32, y: u32, n: u32, color: u32) {
    let s = if n >= 10 {
        let d1 = (n / 10) as u8 + b'0';
        let d2 = (n % 10) as u8 + b'0';
        [d1 as char, d2 as char]
    } else {
        [' ', (n as u8 + b'0') as char]
    };
    font::draw_char_scaled(x, y, s[0], color, 2);
    font::draw_char_scaled(x + 16, y, s[1], color, 2);
}


/// Wait for user input with visual countdown
fn wait_for_choice(width: u32, timer_y: u32, has_os: bool) -> Choice {
    let iterations_per_second = 100000000u32; // Very high for fast QEMU
    let mut remaining = BOOT_TIMEOUT;

    for i in 0..(BOOT_TIMEOUT * iterations_per_second) {
        // Check for keypress
        if let Some(scancode) = bios::read_scancode() {
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                return match c {
                    '1' => {
                        if has_os {
                            Choice::BootLocal
                        } else {
                            Choice::Reinstall
                        }
                    }
                    '2' => {
                        if has_os {
                            Choice::Reinstall
                        } else {
                            // Reboot requested
                            bios::reboot();
                        }
                    }
                    '3' => Choice::Shell,
                    _ => continue,
                };
            }
        }

        // Update countdown display every second
        if i % iterations_per_second == 0 && i > 0 {
            remaining = BOOT_TIMEOUT - (i / iterations_per_second);
            // Redraw countdown - using 2x scale positions
            let msg_width = 26 * 16;
            let num_x = (width - msg_width) / 2 + 13 * 16;
            // Clear and redraw number (2x scale = 32 pixel height)
            framebuffer::fill_rect(num_x, timer_y, 3 * 16, 32, colors::BG_PANEL);
            draw_number_large(num_x, timer_y, remaining, colors::ACCENT_CYAN);
        }
    }

    // Timeout - default action
    if has_os {
        Choice::BootLocal
    } else {
        Choice::Reinstall
    }
}
