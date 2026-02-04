//! Simple text-based boot menu with keyboard input (VGA fallback)

use crate::disk::OsInfo;
use crate::bios;
use crate::vga;
use crate::ui::Choice;

/// Timeout in approximate seconds (rough timing via PIT)
const BOOT_TIMEOUT: u32 = 10;

/// Show the boot menu and wait for user input
pub fn show_boot_menu(os: &OsInfo) -> Choice {
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
    vga::print("  Auto-boot in ");
    vga::print_dec(BOOT_TIMEOUT);
    vga::println(" seconds... Press a key to select.");
    vga::println("");

    let choice = wait_for_choice(BOOT_TIMEOUT);

    match choice {
        Some('1') | None => {
            vga::print_success("  Selected: Boot local OS");
            Choice::BootLocal
        }
        Some('2') => {
            // Show advanced submenu
            show_advanced_menu()
        }
        Some('3') => {
            vga::print_warning("  Selected: Boot from ISO");
            Choice::BootIso
        }
        Some(_) => {
            vga::println("  Invalid choice, defaulting to boot local");
            Choice::BootLocal
        }
    }
}

/// Show advanced options submenu
fn show_advanced_menu() -> Choice {
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
                // Go back - but in text mode we just reboot
                vga::println("  Rebooting...");
                bios::reboot();
            }
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                return match c {
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
                };
            }
        }
    }
}

/// Simple menu for when no OS is detected
pub fn show_no_os_menu() -> Choice {
    vga::println("========================================");
    vga::println("         Dragonfly Boot Menu            ");
    vga::println("========================================");
    vga::println("");
    vga::print_warning("  No bootable OS detected!");
    vga::println("");
    vga::println("  [1] Reboot (default)");
    vga::println("  [2] Advanced");
    vga::println("  [3] Boot from ISO");
    vga::println("");
    vga::print("  Auto-reboot in ");
    vga::print_dec(BOOT_TIMEOUT);
    vga::println(" seconds...");
    vga::println("");

    let choice = wait_for_choice(BOOT_TIMEOUT);

    match choice {
        Some('1') | None => {
            vga::println("  Rebooting...");
            Choice::Reboot
        }
        Some('2') => {
            show_advanced_menu()
        }
        Some('3') => {
            vga::print_warning("  Selected: Boot from ISO");
            Choice::BootIso
        }
        Some(_) => {
            Choice::Reboot
        }
    }
}

/// PIT frequency: 1,193,182 Hz (hardware constant)
const PIT_FREQUENCY: u64 = 1_193_182;

/// Read PIT channel 0 counter value
fn read_pit_count() -> u16 {
    unsafe {
        bios::outb(0x43, 0x00);
        let lo = bios::inb(0x40);
        let hi = bios::inb(0x40);
        (hi as u16) << 8 | lo as u16
    }
}

/// Wait for user choice with PIT-based timeout
fn wait_for_choice(timeout_seconds: u32) -> Option<char> {
    let mut last_count = read_pit_count();
    let mut elapsed_ticks: u64 = 0;
    let mut last_displayed_second = timeout_seconds;

    loop {
        if let Some(scancode) = bios::read_scancode() {
            if let Some(c) = bios::scancode_to_ascii(scancode) {
                return Some(c);
            }
        }

        // Read PIT counter and accumulate elapsed ticks
        let count = read_pit_count();
        if count <= last_count {
            elapsed_ticks += (last_count - count) as u64;
        } else {
            elapsed_ticks += (last_count as u64) + (65536 - count as u64);
        }
        last_count = count;

        let elapsed_seconds = (elapsed_ticks / PIT_FREQUENCY) as u32;

        if elapsed_seconds >= timeout_seconds {
            return None;
        }

        let remaining = timeout_seconds - elapsed_seconds;
        if remaining != last_displayed_second {
            last_displayed_second = remaining;
            vga::print("\r  Auto-boot in ");
            vga::print_dec(remaining);
            vga::print(" seconds...  ");
        }
    }
}
