//! Dragonfly Spark - Tiny multiboot binary for OS detection and GRUB chainloading
//!
//! This is a minimal bare-metal binary that:
//! 1. Gets loaded by iPXE via multiboot
//! 2. Detects existing bootable OS on disk
//! 3. Chainloads GRUB directly (no kexec, no display issues)
//! 4. Falls back to chaining Alpine/Mage if imaging is needed

#![no_std]
#![no_main]

use core::panic::PanicInfo;

mod ahci;
mod bios;
mod bios_disk;
mod block_logo;
mod chainload;
mod disk;
mod font;
mod framebuffer;
mod memory;
mod menu;
mod pci;
mod serial;
mod ui;
mod vector_font;
mod vga;
mod virtio;

/// Multiboot2 header magic that bootloader passes to us
const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36d76289;

/// Entry point - called by boot.s after multiboot handoff
#[unsafe(no_mangle)]
pub extern "C" fn _start(multiboot_magic: u32, multiboot_info: u32) -> ! {
    // Initialize serial first for debugging
    serial::init();
    serial::println("Dragonfly Spark v0.1.0 - Serial debug enabled");

    // Verify multiboot magic before anything else
    if multiboot_magic != MULTIBOOT2_BOOTLOADER_MAGIC {
        serial::print("ERROR: Bad magic: 0x");
        serial::print_hex32(multiboot_magic);
        serial::println("");
        // Fall back to VGA for error display
        vga::init();
        vga::clear();
        vga::print_error("Not loaded via Multiboot2!");
        halt();
    }

    serial::println("Multiboot2 verified OK");

    // Try to initialize framebuffer from multiboot info
    framebuffer::init(multiboot_info);

    if framebuffer::is_available() {
        // Graphical mode!
        if let Some((w, h)) = framebuffer::dimensions() {
            serial::print("Using graphical mode: ");
            serial::print_dec(w);
            serial::print("x");
            serial::print_dec(h);
            serial::println("");
        }
        main_logic_graphical();
    } else {
        // Fall back to VGA text mode
        serial::println("No framebuffer, using VGA text mode");
        vga::init();
        vga::clear();
        main_logic_text();
    }
}

/// Main logic with graphical UI
fn main_logic_graphical() -> ! {
    serial::println("Entering graphical main_logic()");

    // Detect OS via VirtIO - we cache the MBR for chainloading
    serial::println("Scanning for OS...");
    let detected_os = disk::scan_for_os();
    serial::println("OS scan complete");

    // Show graphical boot menu
    let choice = ui::draw_boot_screen(detected_os.as_ref());

    match choice {
        ui::Choice::BootLocal => {
            serial::println("User chose: Boot local OS");
            // Reset VirtIO to try to restore BIOS compatibility
            virtio::reset_all();
            // Use cached MBR from VirtIO detection
            if let Some(ref os) = detected_os {
                bios_disk::chainload_mbr(&os.mbr, 0x80);
            } else {
                serial::println("ERROR: No OS detected, cannot boot");
                halt_silent();
            }
        }
        ui::Choice::Reinstall => {
            serial::println("User chose: Reinstall/Imaging");
            chainload::boot_imaging();
        }
        ui::Choice::Shell => {
            serial::println("User chose: Debug shell");
            // For now, just halt with a message
            if let Some((w, _h)) = framebuffer::dimensions() {
                font::draw_string_centered(400, "Debug shell not implemented yet", framebuffer::colors::WARNING, w);
                font::draw_string_centered(420, "System halted.", framebuffer::colors::ERROR, w);
            }
            halt_silent();
        }
    }
}

/// Main logic with VGA text mode (fallback)
fn main_logic_text() -> ! {
    serial::println("Entering text main_logic()");

    // Splash screen
    vga::println("");
    vga::println("  ____                              __ _");
    vga::println(" |  _ \\ _ __ __ _  __ _  ___  _ __ / _| |_   _");
    vga::println(" | | | | '__/ _` |/ _` |/ _ \\| '_ \\ |_| | | | |");
    vga::println(" | |_| | | | (_| | (_| | (_) | | | |  _| | |_| |");
    vga::println(" |____/|_|  \\__,_|\\__, |\\___/|_| |_|_| |_|\\__, |");
    vga::println("    SPARK         |___/                   |___/");
    vga::println("");
    vga::println("  Bare Metal Boot Manager v0.1.0");
    vga::println("");
    vga::println("  ================================================");
    vga::println("");

    vga::print_success("Multiboot2 verified");
    vga::println("");
    vga::println("Scanning for bootable operating systems...");
    vga::println("");

    // Scan for OS
    let detected_os = disk::scan_for_os();
    serial::println("OS scan complete");

    match detected_os {
        Some(os_info) => {
            vga::print("Found: ");
            vga::println(os_info.name);
            vga::println("");

            // Show text menu
            match menu::show_boot_menu(&os_info) {
                menu::Choice::BootLocal => {
                    vga::println("Chainloading bootloader...");
                    chainload::boot_grub(&os_info);
                }
                menu::Choice::Reinstall => {
                    vga::println("Rebooting into imaging environment...");
                    chainload::boot_imaging();
                }
                menu::Choice::Shell => {
                    vga::println("Debug shell not implemented");
                    halt();
                }
            }
        }
        None => {
            vga::println("");
            vga::print_warning("No existing OS detected");
            vga::println("");
            vga::println("In production: would reboot into imaging environment");
            vga::println("For testing: halting here so you can see the screen");
            halt();
        }
    }
}

/// Halt the CPU
pub fn halt() -> ! {
    vga::println("");
    vga::print_error("System halted.");
    halt_silent()
}

/// Halt without message (for graphical mode)
pub fn halt_silent() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli");
            core::arch::asm!("hlt");
        }
    }
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::println("!!! PANIC !!!");
    if let Some(location) = info.location() {
        serial::print("At: ");
        serial::println(location.file());
    }

    // Try to show on screen
    if framebuffer::is_available() {
        if let Some((w, _)) = framebuffer::dimensions() {
            font::draw_string_centered(300, "=== PANIC ===", framebuffer::colors::ERROR, w);
            if let Some(loc) = info.location() {
                font::draw_string_centered(320, loc.file(), framebuffer::colors::TEXT_PRIMARY, w);
            }
        }
    } else {
        vga::println("");
        vga::print_error("=== PANIC ===");
        if let Some(location) = info.location() {
            vga::print("At: ");
            vga::println(location.file());
        }
    }

    halt_silent()
}
