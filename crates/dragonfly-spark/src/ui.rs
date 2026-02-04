//! Dragonfly-style graphical UI
//!
//! Renders the boot menu with the Dragonfly visual style.
//! Two-level menu: Main → Advanced submenu.

use crate::disk::OsInfo;
use crate::font;
use crate::framebuffer::{self, colors};
use crate::bios;
use smoltcp::wire::Ipv4Address;

/// Menu choices - all possible actions from the menu system
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Choice {
    /// Boot the local OS (chainload MBR)
    BootLocal,
    /// Install a new OS (select template, request reimage)
    InstallOs,
    /// Run memory test (memtest86+ via server boot-mode tag)
    MemoryTest,
    /// Boot rescue environment (Mage/Alpine via server boot-mode tag)
    Rescue,
    /// Boot from ISO (server-hosted, iPXE sanboot via boot-mode tag)
    BootIso,
    /// Remove this machine from Dragonfly
    RemoveFromDragonfly,
    /// Reboot
    Reboot,
}

/// Which menu screen is currently displayed
#[derive(Debug, Clone, Copy, PartialEq)]
enum MenuScreen {
    Main,
    Advanced,
}

/// A menu item to render
struct MenuItem {
    key: &'static str,
    label: &'static str,
    hint: &'static str,
    visible: bool,
}

/// Boot timeout in seconds
const BOOT_TIMEOUT: u32 = 10;

/// Cached panel coordinates for update_countdown
static mut PANEL_Y: u32 = 0;
static mut PANEL_H: u32 = 0;

/// Draw the boot screen without starting countdown (for external countdown control)
pub fn draw_boot_screen_static(os: Option<&OsInfo>, width: u32, height: u32) {
    framebuffer::clear(colors::BG_DARK);
    let header_h = draw_header(width);

    let panel_w = 700.min(width - 100);
    let panel_y = header_h + 20;
    let panel_h = (height - panel_y - 60).min(400);
    let panel_x = (width - panel_w) / 2;

    unsafe {
        PANEL_Y = panel_y;
        PANEL_H = panel_h;
    }

    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::ACCENT_PURPLE);

    let title = match os {
        Some(_) => "Dragonfly Spark",
        None => "No OS Detected",
    };
    let title_width = title.len() as u32 * 16;
    let title_x = (width - title_width) / 2;
    font::draw_string_large(title_x, panel_y + 35, title, colors::TEXT_PRIMARY);

    if let Some(os_info) = os {
        let y = panel_y + 80;
        font::draw_string_centered(y, "Detected Operating System:", colors::TEXT_SECONDARY, width);
        let os_name = os_info.display_name();
        let os_width = os_name.len() as u32 * 16;
        font::draw_string_large((width - os_width) / 2, y + 30, os_name, colors::ACCENT_PURPLE_BRIGHT);
    }

    let hint_y = panel_y + 160;
    font::draw_string_centered(hint_y, "Press SPACE for boot menu", colors::TEXT_SECONDARY, width);

    let timer_y = panel_y + panel_h - 70;
    draw_countdown(width, timer_y, 2);
}

/// Update the countdown display (call from external countdown loop)
pub fn update_countdown(width: u32, seconds: u32) {
    let timer_y = unsafe { PANEL_Y + PANEL_H - 70 };
    let msg_width = 26 * 16;
    let num_x = (width - msg_width) / 2 + 13 * 16;
    framebuffer::fill_rect(num_x, timer_y, 3 * 16, 32, colors::BG_PANEL);
    draw_number_large(num_x, timer_y, seconds, colors::ACCENT_CYAN);
}

/// Show the interactive boot menu with network stack for async IP display
///
/// Renders a two-level menu system: Main → Advanced submenu.
/// Returns the user's choice.
pub fn draw_boot_screen_with_net(
    os: Option<&OsInfo>,
    net_stack: &mut Option<crate::net::NetworkStack<'static>>,
) -> Choice {
    let (width, height) = framebuffer::dimensions().unwrap_or((800, 600));
    let has_os = os.is_some();
    let has_net = net_stack.is_some();

    let mut screen = MenuScreen::Main;

    loop {
        let choice = match screen {
            MenuScreen::Main => draw_main_menu(os, width, height, has_net, net_stack),
            MenuScreen::Advanced => draw_advanced_menu(width, height, net_stack),
        };

        match choice {
            MenuChoice::Selected(c) => return c,
            MenuChoice::EnterAdvanced => screen = MenuScreen::Advanced,
            MenuChoice::Back => screen = MenuScreen::Main,
            MenuChoice::Timeout => {
                return if has_os { Choice::BootLocal } else { Choice::Reboot };
            }
        }
    }
}

/// Internal result from a menu screen
enum MenuChoice {
    Selected(Choice),
    EnterAdvanced,
    Back,
    Timeout,
}

/// Draw and handle the main menu
fn draw_main_menu(os: Option<&OsInfo>, width: u32, height: u32, _has_net: bool, net_stack: &mut Option<crate::net::NetworkStack<'static>>) -> MenuChoice {
    framebuffer::clear(colors::BG_DARK);
    let header_h = draw_header(width);

    let panel_w = 700.min(width - 100);
    let panel_y = header_h + 20;
    let panel_h = (height - panel_y - 60).min(400);
    let panel_x = (width - panel_w) / 2;

    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::ACCENT_PURPLE);

    // Title
    let title = if os.is_some() { "Boot Menu" } else { "No OS Detected" };
    let title_width = title.len() as u32 * 16;
    font::draw_string_large((width - title_width) / 2, panel_y + 35, title, colors::TEXT_PRIMARY);

    // OS info
    if let Some(os_info) = os {
        let y = panel_y + 80;
        font::draw_string_centered(y, "Detected Operating System:", colors::TEXT_SECONDARY, width);
        let os_name = os_info.display_name();
        let os_width = os_name.len() as u32 * 16;
        font::draw_string_large((width - os_width) / 2, y + 30, os_name, colors::ACCENT_PURPLE_BRIGHT);
    }

    // Build menu items — 3 items only
    let has_os = os.is_some();
    let items: [MenuItem; 3] = [
        MenuItem {
            key: "1",
            label: if has_os { "Boot Local OS" } else { "Reboot" },
            hint: "(default)",
            visible: true,
        },
        MenuItem { key: "2", label: "Advanced", hint: "", visible: true },
        MenuItem { key: "3", label: "Boot from ISO", hint: "", visible: true },
    ];

    let menu_y = panel_y + 160;
    draw_menu_items(&items, panel_x, menu_y);

    // Countdown
    let timer_y = panel_y + panel_h - 70;
    draw_countdown(width, timer_y, BOOT_TIMEOUT);

    // Input loop with countdown and network polling
    let mut last_count = read_pit_count();
    let mut elapsed_ticks: u64 = 0;
    let mut last_displayed_second = BOOT_TIMEOUT;
    let mut ip_displayed = net_stack.as_ref().map_or(false, |s| s.has_ip());

    // Draw IP footer if already known
    if let Some(stack) = net_stack.as_ref() {
        if let Some(ip) = stack.get_ip() {
            draw_ip_footer(width, height, ip);
        }
    }

    loop {
        // Check for keypress
        if let Some(scancode) = bios::read_scancode() {
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                match c {
                    '1' => return if has_os {
                        MenuChoice::Selected(Choice::BootLocal)
                    } else {
                        MenuChoice::Selected(Choice::Reboot)
                    },
                    '2' => return MenuChoice::EnterAdvanced,
                    '3' => return MenuChoice::Selected(Choice::BootIso),
                    _ => {}
                }
            }
        }

        // Poll network — display IP as soon as DHCP completes
        if !ip_displayed {
            if let Some(stack) = net_stack.as_mut() {
                stack.poll();
                if let Some(ip) = stack.get_ip() {
                    stack.freeze_dhcp();
                    draw_ip_footer(width, height, ip);
                    ip_displayed = true;
                }
            }
        }

        // PIT countdown
        let count = read_pit_count();
        if count <= last_count {
            elapsed_ticks += (last_count - count) as u64;
        } else {
            elapsed_ticks += (last_count as u64) + (65536 - count as u64);
        }
        last_count = count;

        let elapsed_seconds = (elapsed_ticks / PIT_FREQUENCY) as u32;
        if elapsed_seconds >= BOOT_TIMEOUT {
            return MenuChoice::Timeout;
        }

        let remaining = BOOT_TIMEOUT - elapsed_seconds;
        if remaining != last_displayed_second {
            last_displayed_second = remaining;
            let msg_width = 26 * 16;
            let num_x = (width - msg_width) / 2 + 13 * 16;
            framebuffer::fill_rect(num_x, timer_y, 3 * 16, 32, colors::BG_PANEL);
            draw_number_large(num_x, timer_y, remaining, colors::ACCENT_CYAN);
        }
    }
}

/// Draw and handle the advanced submenu
fn draw_advanced_menu(width: u32, height: u32, net_stack: &mut Option<crate::net::NetworkStack<'static>>) -> MenuChoice {
    framebuffer::clear(colors::BG_DARK);
    let header_h = draw_header(width);

    let panel_w = 700.min(width - 100);
    let panel_y = header_h + 20;
    let panel_h = (height - panel_y - 60).min(400);
    let panel_x = (width - panel_w) / 2;

    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::ACCENT_PURPLE);

    // Title
    let title = "Advanced";
    let title_width = title.len() as u32 * 16;
    font::draw_string_large((width - title_width) / 2, panel_y + 35, title, colors::TEXT_PRIMARY);

    // Build menu items
    let items: [MenuItem; 4] = [
        MenuItem { key: "1", label: "Install OS", hint: "", visible: true },
        MenuItem { key: "2", label: "Memory Test", hint: "", visible: true },
        MenuItem { key: "3", label: "Boot Rescue Environment", hint: "(Alpine)", visible: true },
        MenuItem { key: "4", label: "Remove from Dragonfly", hint: "", visible: true },
    ];

    let menu_y = panel_y + 80;
    draw_menu_items(&items, panel_x, menu_y);

    // ESC hint at bottom
    let esc_y = panel_y + panel_h - 50;
    font::draw_string_centered(esc_y, "[ESC] Back to main menu", colors::TEXT_SECONDARY, width);

    // Track whether IP is already displayed
    let mut ip_displayed = net_stack.as_ref().map_or(false, |s| s.has_ip());

    // Draw IP footer if already known
    if let Some(stack) = net_stack.as_ref() {
        if let Some(ip) = stack.get_ip() {
            draw_ip_footer(width, height, ip);
        }
    }

    // Wait for input (no countdown on advanced menu), poll network
    loop {
        if let Some(scancode) = bios::read_scancode() {
            // Check ESC first
            if scancode == bios::SCANCODE_ESC {
                return MenuChoice::Back;
            }

            if let Some(c) = bios::scancode_to_ascii(scancode) {
                match c {
                    '1' => return MenuChoice::Selected(Choice::InstallOs),
                    '2' => return MenuChoice::Selected(Choice::MemoryTest),
                    '3' => return MenuChoice::Selected(Choice::Rescue),
                    '4' => return MenuChoice::Selected(Choice::RemoveFromDragonfly),
                    _ => {}
                }
            }
        }

        // Poll network — display IP as soon as DHCP completes
        if !ip_displayed {
            if let Some(stack) = net_stack.as_mut() {
                stack.poll();
                if let Some(ip) = stack.get_ip() {
                    stack.freeze_dhcp();
                    draw_ip_footer(width, height, ip);
                    ip_displayed = true;
                }
            }
        }
    }
}

/// Draw a list of menu items with badges
fn draw_menu_items(items: &[MenuItem], panel_x: u32, start_y: u32) {
    let mut visible_idx = 0u32;
    for item in items {
        if !item.visible {
            continue;
        }
        let y = start_y + (visible_idx * 55);
        let option_x = panel_x + 80;

        // Key badge
        let badge_x = option_x;
        let badge_y = y;
        framebuffer::fill_rounded_rect(badge_x, badge_y, 40, 36, 6, colors::ACCENT_PURPLE);
        font::draw_string_large(badge_x + 12, badge_y + 3, item.key, colors::TEXT_PRIMARY);

        // Label — vertically aligned with badge text
        font::draw_string_large(badge_x + 60, badge_y + 3, item.label, colors::TEXT_PRIMARY);

        // Hint
        if !item.hint.is_empty() {
            let hint_x = badge_x + 60 + (item.label.len() as u32 + 1) * 16;
            font::draw_string_large(hint_x, badge_y + 3, item.hint, colors::TEXT_SECONDARY);
        }

        visible_idx += 1;
    }
}

/// PIT (Programmable Interval Timer) frequency: 1,193,182 Hz
/// This is a hardware constant — the PIT crystal oscillator runs at this rate
/// regardless of CPU speed, making it reliable for real-time measurement.
const PIT_FREQUENCY: u64 = 1_193_182;

/// Read the PIT channel 0 counter value.
///
/// The PIT counts down from 65535 to 0, then wraps. By tracking the counter
/// value over time, we can measure elapsed real time without needing interrupts.
fn read_pit_count() -> u16 {
    unsafe {
        // Latch counter 0: write 0x00 to command register (port 0x43)
        // This freezes the current count so we can read it atomically
        bios::outb(0x43, 0x00);
        // Read low byte then high byte from channel 0 data port (0x40)
        let lo = bios::inb(0x40);
        let hi = bios::inb(0x40);
        (hi as u16) << 8 | lo as u16
    }
}

/// Wait for menu input with optional PIT-based countdown timer.
///
/// Uses the x86 PIT hardware timer for accurate real-time countdown,
/// independent of CPU speed.
fn wait_for_menu_input<F>(
    width: u32,
    timer_y: u32,
    handler: &F,
    has_countdown: bool,
) -> MenuChoice
where
    F: Fn(u8) -> Option<MenuChoice>,
{
    if !has_countdown {
        // No timeout - just wait for input
        loop {
            if let Some(scancode) = bios::read_scancode() {
                if let Some(result) = handler(scancode) {
                    return result;
                }
            }
        }
    }

    // PIT-based countdown: track elapsed ticks by reading the hardware counter
    let mut last_count = read_pit_count();
    let mut elapsed_ticks: u64 = 0;
    let mut last_displayed_second = BOOT_TIMEOUT;

    loop {
        // Check for keypress
        if let Some(scancode) = bios::read_scancode() {
            if let Some(result) = handler(scancode) {
                return result;
            }
        }

        // Read PIT counter and accumulate elapsed ticks
        let count = read_pit_count();
        if count <= last_count {
            // Normal countdown: counter decreased
            elapsed_ticks += (last_count - count) as u64;
        } else {
            // Counter wrapped around (0 → 65535)
            elapsed_ticks += (last_count as u64) + (65536 - count as u64);
        }
        last_count = count;

        let elapsed_seconds = (elapsed_ticks / PIT_FREQUENCY) as u32;

        // Timeout reached
        if elapsed_seconds >= BOOT_TIMEOUT {
            return MenuChoice::Timeout;
        }

        // Update countdown display when second changes
        let remaining = BOOT_TIMEOUT - elapsed_seconds;
        if remaining != last_displayed_second {
            last_displayed_second = remaining;
            let msg_width = 26 * 16;
            let num_x = (width - msg_width) / 2 + 13 * 16;
            framebuffer::fill_rect(num_x, timer_y, 3 * 16, 32, colors::BG_PANEL);
            draw_number_large(num_x, timer_y, remaining, colors::ACCENT_CYAN);
        }
    }
}

/// Draw a confirmation dialog. Returns true if user confirms.
pub fn draw_confirmation(width: u32, height: u32, title: &str, message: &str) -> bool {
    framebuffer::clear(colors::BG_DARK);
    let header_h = draw_header(width);

    let panel_w = 600.min(width - 100);
    let panel_y = header_h + 60;
    let panel_h = 200;
    let panel_x = (width - panel_w) / 2;

    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::WARNING);

    // Title
    let title_width = title.len() as u32 * 16;
    font::draw_string_large((width - title_width) / 2, panel_y + 30, title, colors::WARNING);

    // Message
    font::draw_string_centered(panel_y + 70, message, colors::TEXT_PRIMARY, width);

    // Options
    font::draw_string_centered(panel_y + 120, "[Y] Confirm    [N/ESC] Cancel", colors::TEXT_SECONDARY, width);

    loop {
        if let Some(scancode) = bios::read_scancode() {
            if scancode == bios::SCANCODE_ESC {
                return false;
            }
            if let Some(c) = bios::scancode_to_ascii_full(scancode) {
                match c {
                    'y' => return true,
                    'n' => return false,
                    _ => {}
                }
            }
        }
    }
}

/// Draw a status message screen (used for "working..." states)
pub fn draw_status(width: u32, height: u32, title: &str, message: &str, color: u32) {
    framebuffer::clear(colors::BG_DARK);
    let header_h = draw_header(width);

    let panel_w = 600.min(width - 100);
    let panel_y = header_h + 60;
    let panel_h = 150;
    let panel_x = (width - panel_w) / 2;

    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, color);

    let title_width = title.len() as u32 * 16;
    font::draw_string_large((width - title_width) / 2, panel_y + 35, title, color);
    font::draw_string_centered(panel_y + 80, message, colors::TEXT_PRIMARY, width);
}

/// Draw a result screen and wait for any key
pub fn draw_result_and_wait(width: u32, height: u32, title: &str, message: &str, success: bool) {
    let color = if success { colors::SUCCESS } else { colors::ERROR };
    draw_status(width, height, title, message, color);

    let y = height / 2 + 80;
    font::draw_string_centered(y, "Press any key to continue...", colors::TEXT_SECONDARY, width);

    // Wait for key press (ignore releases)
    loop {
        if let Some(scancode) = bios::read_scancode() {
            if scancode & 0x80 == 0 {
                return;
            }
        }
    }
}

/// Draw a template selection screen
/// Returns the selected template index (0-based), or None if cancelled
pub fn draw_template_list(
    width: u32,
    height: u32,
    names: &[[u8; 64]],
    name_lens: &[usize],
    count: usize,
) -> Option<usize> {
    framebuffer::clear(colors::BG_DARK);
    let header_h = draw_header(width);

    let panel_w = 700.min(width - 100);
    let panel_y = header_h + 20;
    let max_items = 8.min(count);
    let panel_h = (max_items as u32 * 50 + 120).min(height - panel_y - 60);
    let panel_x = (width - panel_w) / 2;

    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::ACCENT_PURPLE);

    // Title
    let title = "Select OS Template";
    let title_width = title.len() as u32 * 16;
    font::draw_string_large((width - title_width) / 2, panel_y + 30, title, colors::TEXT_PRIMARY);

    // List templates
    let list_y = panel_y + 70;
    for i in 0..max_items {
        let y = list_y + (i as u32 * 50);
        let option_x = panel_x + 80;

        // Number badge
        let key_char = (b'1' + i as u8) as char;
        let mut key_str = [0u8; 1];
        key_str[0] = key_char as u8;

        let badge_x = option_x;
        framebuffer::fill_rounded_rect(badge_x, y, 40, 36, 6, colors::ACCENT_PURPLE);
        if let Ok(s) = core::str::from_utf8(&key_str) {
            font::draw_string_large(badge_x + 12, y + 3, s, colors::TEXT_PRIMARY);
        }

        // Template name
        if let Ok(name) = core::str::from_utf8(&names[i][..name_lens[i]]) {
            font::draw_string_large(badge_x + 60, y + 3, name, colors::TEXT_PRIMARY);
        }
    }

    // ESC hint
    let esc_y = panel_y + panel_h - 40;
    font::draw_string_centered(esc_y, "[ESC] Cancel", colors::TEXT_SECONDARY, width);

    // Wait for selection
    loop {
        if let Some(scancode) = bios::read_scancode() {
            if scancode == bios::SCANCODE_ESC {
                return None;
            }
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                let idx = (c as u8).wrapping_sub(b'1') as usize;
                if idx < max_items {
                    return Some(idx);
                }
            }
        }
    }
}

/// Draw an ISO image selection screen
/// Returns the selected ISO index (0-based), or None if cancelled
pub fn draw_iso_list(
    width: u32,
    height: u32,
    names: &[[u8; 64]],
    name_lens: &[usize],
    count: usize,
) -> Option<usize> {
    framebuffer::clear(colors::BG_DARK);
    let header_h = draw_header(width);

    let panel_w = 700.min(width - 100);
    let panel_y = header_h + 20;
    let max_items = 8.min(count);
    let panel_h = (max_items as u32 * 50 + 120).min(height - panel_y - 60);
    let panel_x = (width - panel_w) / 2;

    framebuffer::fill_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::BG_PANEL);
    framebuffer::draw_rounded_rect(panel_x, panel_y, panel_w, panel_h, 12, colors::ACCENT_PURPLE);

    // Title
    let title = "Boot from ISO";
    let title_width = title.len() as u32 * 16;
    font::draw_string_large((width - title_width) / 2, panel_y + 30, title, colors::TEXT_PRIMARY);

    // List ISOs
    let list_y = panel_y + 70;
    for i in 0..max_items {
        let y = list_y + (i as u32 * 50);
        let option_x = panel_x + 80;

        // Number badge
        let key_char = (b'1' + i as u8) as char;
        let mut key_str = [0u8; 1];
        key_str[0] = key_char as u8;

        let badge_x = option_x;
        framebuffer::fill_rounded_rect(badge_x, y, 40, 36, 6, colors::ACCENT_PURPLE);
        if let Ok(s) = core::str::from_utf8(&key_str) {
            font::draw_string_large(badge_x + 12, y + 3, s, colors::TEXT_PRIMARY);
        }

        // ISO filename
        if let Ok(name) = core::str::from_utf8(&names[i][..name_lens[i]]) {
            font::draw_string_large(badge_x + 60, y + 3, name, colors::TEXT_PRIMARY);
        }
    }

    // ESC hint
    let esc_y = panel_y + panel_h - 40;
    font::draw_string_centered(esc_y, "[ESC] Cancel", colors::TEXT_SECONDARY, width);

    // Wait for selection
    loop {
        if let Some(scancode) = bios::read_scancode() {
            if scancode == bios::SCANCODE_ESC {
                return None;
            }
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                let idx = (c as u8).wrapping_sub(b'1') as usize;
                if idx < max_items {
                    return Some(idx);
                }
            }
        }
    }
}

// === Rendering helpers (unchanged from original) ===

/// Draw the header with logo
fn draw_header(width: u32) -> u32 {
    let logo_text = "Dragonfly";
    let base_width = logo_text.len() as u32 * 8;
    let target_width = width / 2;
    let scale = (target_width / base_width).max(2).min(6);

    let logo_pixel_width = base_width * scale;
    let logo_pixel_height = 16 * scale;
    let header_h = logo_pixel_height + 35;

    framebuffer::fill_gradient_h(0, 0, width, header_h, colors::BG_DARK, colors::BG_PANEL);
    framebuffer::fill_gradient_h(0, 0, width, 3, colors::ACCENT_PURPLE, colors::ACCENT_CYAN);

    let logo_x = (width - logo_pixel_width) / 2;
    let logo_y = 10;
    draw_string_scaled(logo_x, logo_y, logo_text, colors::ACCENT_PURPLE_BRIGHT, scale);

    let g_end_x = logo_x + (4 * 8 * scale) - (3 * scale);
    let tagline_x = g_end_x + (2 * scale) + 8;
    let tagline_y = logo_y + logo_pixel_height - 13;
    font::draw_string(tagline_x, tagline_y, "metal, managed", colors::TEXT_SECONDARY);

    header_h
}

/// Draw a string at arbitrary scale with kerning adjustments
fn draw_string_scaled(x: u32, y: u32, s: &str, color: u32, scale: u32) {
    let mut cx = x;
    let mut prev = '\0';
    for c in s.chars() {
        let kern: i32 = match (prev, c) {
            ('f', 'l') => -3,
            _ => 0,
        };
        cx = (cx as i32 + kern * scale as i32) as u32;
        font::draw_char_scaled(cx, y, c, color, scale);
        cx += 8 * scale;
        prev = c;
    }
}

/// Draw countdown timer
fn draw_countdown(width: u32, y: u32, seconds: u32) {
    let msg_width = 26 * 16;
    let x = (width - msg_width) / 2;
    font::draw_string_large(x, y, "Auto-boot in ", colors::TEXT_SECONDARY);
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

/// Draw IP address in footer area
pub fn draw_ip_footer(width: u32, height: u32, ip: Ipv4Address) {
    let y = height - 45;
    let mut ip_buf = [0u8; 20];
    let mut pos = 0;

    ip_buf[pos] = b'I'; pos += 1;
    ip_buf[pos] = b'P'; pos += 1;
    ip_buf[pos] = b':'; pos += 1;
    ip_buf[pos] = b' '; pos += 1;

    for (i, &octet) in ip.0.iter().enumerate() {
        if i > 0 { ip_buf[pos] = b'.'; pos += 1; }
        if octet >= 100 { ip_buf[pos] = b'0' + (octet / 100); pos += 1; }
        if octet >= 10 { ip_buf[pos] = b'0' + ((octet / 10) % 10); pos += 1; }
        ip_buf[pos] = b'0' + (octet % 10); pos += 1;
    }

    if let Ok(ip_str) = core::str::from_utf8(&ip_buf[..pos]) {
        let text_width = pos as u32 * 16;
        let x = (width - text_width) / 2;
        font::draw_string_large(x, y, ip_str, 0xFFFFFF);
    }
}
