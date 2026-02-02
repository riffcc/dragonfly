//! Simple text-based boot menu with keyboard input

use crate::disk::OsInfo;
use crate::bios;
use crate::vga;

/// Menu choices
pub enum Choice {
    BootLocal,
    Reinstall,
    Shell,
}

/// Timeout in approximate seconds (rough timing)
const BOOT_TIMEOUT: u32 = 5;

/// Show the boot menu and wait for user input
pub fn show_boot_menu(os: &OsInfo) -> Choice {
    vga::println("========================================");
    vga::println("         Dragonfly Boot Menu            ");
    vga::println("========================================");
    vga::println("");
    vga::print("  Detected: ");
    vga::println(os.name);
    vga::println("");
    vga::println("  [1] Boot local OS (default)");
    vga::println("  [2] Reinstall / Imaging");
    vga::println("  [3] Debug shell");
    vga::println("");
    vga::print("  Auto-boot in ");
    vga::print_dec(BOOT_TIMEOUT);
    vga::println(" seconds... Press a key to select.");
    vga::println("");

    // Wait for keypress with timeout
    let choice = wait_for_choice(BOOT_TIMEOUT);

    match choice {
        Some('1') | None => {
            vga::print_success("  Selected: Boot local OS");
            Choice::BootLocal
        }
        Some('2') => {
            vga::print_warning("  Selected: Reinstall / Imaging");
            Choice::Reinstall
        }
        Some('3') => {
            vga::print_warning("  Selected: Debug shell");
            Choice::Shell
        }
        Some(_) => {
            vga::println("  Invalid choice, defaulting to boot local");
            Choice::BootLocal
        }
    }
}

/// Wait for user choice with timeout
/// Returns None if timeout reached (auto-boot)
fn wait_for_choice(timeout_seconds: u32) -> Option<char> {
    // Rough timing: ~100000 iterations per second on most systems
    let iterations_per_second = 100000u32;
    let total_iterations = timeout_seconds * iterations_per_second;

    for i in 0..total_iterations {
        // Check for keypress
        if let Some(scancode) = bios::read_scancode() {
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                return Some(c);
            }
        }

        // Update countdown display every "second"
        if i % iterations_per_second == 0 && i > 0 {
            let remaining = timeout_seconds - (i / iterations_per_second);
            vga::print("\r  Auto-boot in ");
            vga::print_dec(remaining);
            vga::print(" seconds...  ");
        }
    }

    None // Timeout - auto-boot
}

/// Simple menu for when no OS is detected
pub fn show_no_os_menu() -> Choice {
    vga::println("========================================");
    vga::println("         Dragonfly Boot Menu            ");
    vga::println("========================================");
    vga::println("");
    vga::print_warning("  No bootable OS detected!");
    vga::println("");
    vga::println("  [1] Enter imaging mode (default)");
    vga::println("  [2] Reboot");
    vga::println("  [3] Debug shell");
    vga::println("");
    vga::print("  Auto-imaging in ");
    vga::print_dec(BOOT_TIMEOUT);
    vga::println(" seconds...");
    vga::println("");

    let choice = wait_for_choice(BOOT_TIMEOUT);

    match choice {
        Some('1') | None => {
            vga::print_success("  Entering imaging mode...");
            Choice::Reinstall
        }
        Some('2') => {
            vga::println("  Rebooting...");
            bios::reboot();
        }
        Some('3') => {
            Choice::Shell
        }
        Some(_) => {
            Choice::Reinstall
        }
    }
}
