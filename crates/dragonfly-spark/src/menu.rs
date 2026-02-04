//! Simple text-based boot menu with keyboard input (VGA fallback)

use crate::disk::OsInfo;
use crate::bios;
use crate::vga;
use crate::ui::Choice;

/// Show the boot menu and wait for user input.
/// No countdown — user already pressed spacebar to get here.
pub fn show_boot_menu(os: &OsInfo) -> Choice {
    loop {
        vga::println("========================================");
        vga::println("         Dragonfly Boot Menu            ");
        vga::println("========================================");
        vga::println("");
        vga::print("  Detected: ");
        vga::println(os.display_name());
        vga::println("");
        vga::println("  [1] Boot local OS (default)");
        vga::println("  [2] Advanced");
        vga::println("  [3] Boot from ISO");
        vga::println("");

        let choice = wait_for_key();

        match choice {
            Some('1') => {
                vga::print_success("  Selected: Boot local OS");
                return Choice::BootLocal;
            }
            Some('2') => {
                if let Some(c) = show_advanced_menu() {
                    return c;
                }
                // ESC pressed — loop back to main menu
            }
            Some('3') => {
                vga::print_warning("  Selected: Boot from ISO");
                return Choice::BootIso;
            }
            _ => {}
        }
    }
}

/// Show advanced options submenu. Returns None if user pressed ESC (go back).
fn show_advanced_menu() -> Option<Choice> {
    vga::println("");
    vga::println("  === Advanced ===");
    vga::println("");
    vga::println("  [1] Install OS");
    vga::println("  [2] Memory Test");
    vga::println("  [3] Boot Rescue Environment (Alpine)");
    vga::println("  [4] Remove from Dragonfly");
    vga::println("  [ESC] Back");
    vga::println("");

    loop {
        if let Some(scancode) = bios::read_scancode() {
            if scancode == bios::SCANCODE_ESC {
                return None;
            }
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                return Some(match c {
                    '1' => {
                        vga::print_warning("  Selected: Install OS");
                        Choice::InstallOs
                    }
                    '2' => {
                        vga::print_warning("  Selected: Memory Test");
                        Choice::MemoryTest
                    }
                    '3' => {
                        vga::print_warning("  Selected: Rescue Environment");
                        Choice::Rescue
                    }
                    '4' => {
                        vga::print_warning("  Selected: Remove from Dragonfly");
                        Choice::RemoveFromDragonfly
                    }
                    _ => continue,
                });
            }
        }
    }
}

/// Simple menu for when no OS is detected.
/// No countdown — user already pressed spacebar to get here.
pub fn show_no_os_menu() -> Choice {
    loop {
        vga::println("========================================");
        vga::println("         Dragonfly Boot Menu            ");
        vga::println("========================================");
        vga::println("");
        vga::print_warning("  No bootable OS detected!");
        vga::println("");
        vga::println("  [1] Reboot");
        vga::println("  [2] Advanced");
        vga::println("  [3] Boot from ISO");
        vga::println("");

        let choice = wait_for_key();

        match choice {
            Some('1') => {
                vga::println("  Rebooting...");
                return Choice::Reboot;
            }
            Some('2') => {
                if let Some(c) = show_advanced_menu() {
                    return c;
                }
                // ESC pressed — loop back to main menu
            }
            Some('3') => {
                vga::print_warning("  Selected: Boot from ISO");
                return Choice::BootIso;
            }
            _ => {}
        }
    }
}

/// Wait for any key press, returns the ASCII character
fn wait_for_key() -> Option<char> {
    loop {
        if let Some(scancode) = bios::read_scancode() {
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                return Some(c);
            }
        }
    }
}
