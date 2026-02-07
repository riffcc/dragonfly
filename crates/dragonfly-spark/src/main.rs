//! Dragonfly Spark - Tiny multiboot binary for OS detection and GRUB chainloading
//!
//! This is a minimal bare-metal binary that:
//! 1. Gets loaded by iPXE via multiboot
//! 2. Detects existing bootable OS on disk
//! 3. Chainloads GRUB directly (no kexec, no display issues)
//! 4. Falls back to chaining Alpine/Mage if imaging is needed

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::panic::PanicInfo;

use net::NetDevice;

mod ahci;
mod allocator;
mod bios;
mod bios_disk;
mod block_logo;
mod chainload;
mod cmdline;
mod disk;
mod e1000e;
mod font;
mod framebuffer;
mod http;
mod hw;
mod memory;
mod menu;
mod net;
mod pci;
mod serial;
mod ui;
mod vector_font;
mod vbe;
mod vga;
mod virtio;
mod virtio_blk;
mod virtio_net;

/// Multiboot1 magic that bootloader passes to us (iPXE)
const MULTIBOOT1_BOOTLOADER_MAGIC: u32 = 0x2BADB002;

/// Multiboot2 magic that bootloader passes to us (GRUB2)
const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36d76289;

/// Entry point - called by boot.s after multiboot handoff
#[unsafe(no_mangle)]
pub extern "C" fn _start(multiboot_magic: u32, multiboot_info: u32) -> ! {
    // Initialize serial first for debugging
    serial::init();
    serial::println("Dragonfly Spark v0.2.2 - Serial debug enabled");

    // Detect multiboot version and handle accordingly
    let is_multiboot2 = match multiboot_magic {
        MULTIBOOT1_BOOTLOADER_MAGIC => {
            serial::println("Booted via Multiboot1 (iPXE)");
            false
        }
        MULTIBOOT2_BOOTLOADER_MAGIC => {
            serial::println("Booted via Multiboot2 (GRUB2)");
            true
        }
        _ => {
            serial::print("ERROR: Bad magic: 0x");
            serial::print_hex32(multiboot_magic);
            serial::println("");
            // Fall back to VGA for error display
            vga::init();
            vga::clear();
            vga::print_error("Not loaded via Multiboot!");
            halt();
        }
    };

    // Detect total memory from multiboot info (must happen before allocator init)
    unsafe { hw::init_memory(multiboot_info, is_multiboot2); }
    let mem_mb = (hw::total_memory_bytes() / (1024 * 1024)) as u32;
    serial::print("Memory: ");
    serial::print_dec(mem_mb);
    serial::println(" MB");

    // Detect CPU topology
    let cores = hw::cpu_cores();
    let threads = hw::cpu_threads();
    serial::print("CPU: ");
    serial::print_dec(cores);
    serial::print(" cores, ");
    serial::print_dec(threads);
    serial::println(" threads");

    // Scan for GPUs via PCI
    pci::scan_gpus();

    // Parse command line and framebuffer based on multiboot version
    if is_multiboot2 {
        // Parse command line parameters (server=IP:PORT) - MB2 format
        cmdline::init(multiboot_info);

        // Try to initialize framebuffer from multiboot info - MB2 format
        framebuffer::init(multiboot_info);
    } else {
        // MB1 boot (iPXE) - VBE was set up in boot.s before entering long mode
        serial::println("MB1: Checking VBE mode set by boot.s...");
        framebuffer::init_from_boot_vbe();

        // Fallback: try MB1 framebuffer info (unlikely to have it)
        if !framebuffer::is_available() {
            serial::println("MB1: No VBE from boot.s, trying MB1 info...");
            framebuffer::init_mb1(multiboot_info);
        }

        // Parse MB1 cmdline for server= parameter
        cmdline::init_mb1(multiboot_info);
    }

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
///
/// Boot flow:
/// 1. Detect OS on disk
/// 2. Initialize network, get DHCP
/// 3. Show boot screen with countdown
/// 4. During countdown: poll for spacebar AND check in with server
/// 5. If spacebar pressed: show menu, let user choose
/// 6. If server responds: execute action (LocalBoot, Execute, Wait, Reboot)
/// 7. If timeout/unreachable: auto-boot local OS (or imaging if none)
///
/// Design goal: Fast, unobtrusive. Server being down never blocks boot.
fn main_logic_graphical() -> ! {
    serial::println("Entering graphical main_logic()");

    // Detect OS via VirtIO - we cache the MBR for chainloading
    serial::println("Scanning for OS...");
    let detected_os = disk::scan_for_os();
    serial::println("OS scan complete");

    // Initialize network stack for DHCP and server check-in
    let mut net_stack = init_network_stack();

    // Draw initial boot screen
    let (width, height) = framebuffer::dimensions().unwrap_or((800, 600));
    ui::draw_boot_screen_static(detected_os, width, height);

    // Boot flow with server check-in and spacebar interrupt
    let (action, net_stack) = boot_flow_with_checkin(detected_os, net_stack, width, height);

    // Execute the decided action
    execute_boot_action(action, detected_os, net_stack);
}

/// Result of the boot flow decision
#[derive(Debug, Clone, Copy, PartialEq)]
enum BootAction {
    /// Boot the local OS (chainload MBR)
    BootLocal,
    /// Enter imaging mode (reboot to get Mage)
    Imaging,
    /// Show the full menu (user pressed spacebar)
    ShowMenu,
    /// Reboot the machine
    Reboot,
    /// Memory test (server boot-mode tag → iPXE boots memtest86+)
    MemoryTest,
    /// Install OS (show template list, request install, reboot to Mage)
    InstallOs,
    /// Boot rescue environment (server boot-mode tag → Mage discovery)
    Rescue,
    /// Boot from ISO (server-hosted, boot-mode tag → iPXE sanboot)
    BootIso,
    /// Remove from Dragonfly
    RemoveFromDragonfly,
}

/// Fallback server port (used only if cmdline and DHCP both fail)
const DEFAULT_SERVER_PORT: u16 = 3000;

/// Resolve the Dragonfly server address.
///
/// Priority:
/// 1. Command line parameter (`server=http://IP:PORT` from iPXE script)
/// 2. DHCP boot server (siaddr) with default port
/// 3. DHCP gateway with default port
/// 4. Hardcoded fallback (10.7.1.1:8080)
fn resolve_server(stack: &net::NetworkStack) -> (smoltcp::wire::Ipv4Address, u16) {
    let params = cmdline::params();
    if params.has_server {
        (smoltcp::wire::Ipv4Address(params.server_ip), params.server_port)
    } else {
        let ip = stack.boot_server.unwrap_or_else(|| {
            stack.gateway.unwrap_or(smoltcp::wire::Ipv4Address([10, 7, 1, 1]))
        });
        (ip, DEFAULT_SERVER_PORT)
    }
}

/// Ensure the network stack has an IP address (wait for DHCP if needed).
/// Freezes DHCP once the IP is obtained.
/// Returns false if no IP after timeout (5 seconds).
fn ensure_ip(stack: &mut net::NetworkStack) -> bool {
    if stack.has_ip() {
        stack.freeze_dhcp();
        return true;
    }
    serial::println("NET: Waiting for DHCP...");
    let start = net::now().total_millis();
    while (net::now().total_millis() - start) < 5000 {
        stack.poll();
        if stack.has_ip() {
            stack.freeze_dhcp();
            return true;
        }
    }
    serial::println("NET: DHCP timeout - no IP address");
    false
}

/// Boot timeout (seconds)
/// Must be long enough for DHCP + server check-in on slow networks.
/// User can press spacebar to enter menu immediately.
const BOOT_TIMEOUT_SECS: u32 = 8;

/// Perform boot flow with server check-in and spacebar interrupt
/// Returns the decided action and the network stack (for reuse in menu)
fn boot_flow_with_checkin(
    detected_os: Option<&disk::OsInfo>,
    mut net_stack: Option<net::NetworkStack<'static>>,
    width: u32,
    height: u32,
) -> (BootAction, Option<net::NetworkStack<'static>>) {
    let mut ip_displayed = false;
    let mut checkin_done = false;

    // Get MAC address from network stack (if available)
    let mac = net_stack.as_ref().map(|s| s.device.mac_address());

    serial::println("Boot flow: Starting - press SPACE for menu");

    // Use wall-clock time for timeout (1 second max wait for DHCP + checkin)
    let start_time = net::now().total_millis();
    let timeout_ms = (BOOT_TIMEOUT_SECS as i64) * 1000;

    let mut decided_action: Option<BootAction> = None;

    loop {
        let elapsed = net::now().total_millis() - start_time;

        // Check for spacebar (scancode 0x39)
        // Don't break - let the loop continue so checkin still happens.
        // The machine must always register with the server.
        if let Some(scancode) = bios::read_scancode() {
            if scancode == 0x39 && decided_action != Some(BootAction::ShowMenu) {
                serial::println("Boot flow: Spacebar pressed - will show menu after checkin");
                decided_action = Some(BootAction::ShowMenu);
            }
        }

        // Poll network
        if let Some(stack) = net_stack.as_mut() {
            stack.poll();

            // Display IP once we have it, and freeze DHCP
            if !ip_displayed && stack.has_ip() {
                if let Some(ip) = stack.get_ip() {
                    ui::draw_ip_footer(width, height, ip);
                    ip_displayed = true;
                    serial::println("Boot flow: Got IP");

                    // Freeze DHCP as soon as we have an IP. DHCP's ARP activity
                    // triggers smoltcp's global neighbor cache rate limiter, which
                    // blocks TCP from resolving the server's MAC address.
                    // A boot manager doesn't need lease renewal.
                    stack.freeze_dhcp();
                }
            }

            // Attempt server check-in once we have IP
            if !checkin_done && stack.has_ip() {
                if let Some(mac_addr) = mac.as_ref() {
                    checkin_done = true;

                    let (server_ip, server_port) = resolve_server(stack);

                    serial::print("Boot flow: Checking in with ");
                    serial::print_dec(server_ip.0[0] as u32);
                    serial::print(".");
                    serial::print_dec(server_ip.0[1] as u32);
                    serial::print(".");
                    serial::print_dec(server_ip.0[2] as u32);
                    serial::print(".");
                    serial::print_dec(server_ip.0[3] as u32);
                    serial::print(":");
                    serial::print_dec(server_port as u32);
                    serial::println("");

                    // Perform check-in (has its own fast timeouts)
                    if let Some(response) = http::checkin(
                        stack,
                        server_ip,
                        server_port,
                        mac_addr,
                        detected_os,
                    ) {
                        serial::println("Boot flow: Server responded");
                        // Only use server's action if user hasn't pressed spacebar.
                        // User's explicit menu request takes priority.
                        if decided_action.is_none() {
                            decided_action = Some(match response.action {
                                http::AgentAction::LocalBoot => {
                                    serial::println("  -> LocalBoot");
                                    BootAction::BootLocal
                                }
                                http::AgentAction::Execute => {
                                    serial::println("  -> Execute (imaging)");
                                    BootAction::Imaging
                                }
                                http::AgentAction::Reboot => {
                                    serial::println("  -> Reboot");
                                    BootAction::Reboot
                                }
                                http::AgentAction::Wait => {
                                    serial::println("  -> Wait (show menu)");
                                    BootAction::ShowMenu
                                }
                            });
                        } else {
                            serial::println("  -> User override (spacebar), ignoring server action");
                        }
                        break;
                    } else {
                        // Server unreachable - proceed with whatever we have
                        serial::println("Boot flow: Server unreachable");
                        break;
                    }
                }
            }
        }

        // Timeout - proceed to default action
        if elapsed >= timeout_ms {
            serial::println("Boot flow: Timeout, proceeding to autoboot");
            break;
        }
    }

    // Determine action (server response, spacebar, or default autoboot)
    let action = decided_action.unwrap_or_else(|| {
        serial::println("Boot flow: Autoboot");
        if detected_os.is_some() {
            BootAction::BootLocal
        } else {
            BootAction::Imaging
        }
    });
    (action, net_stack)
}

/// Execute the decided boot action
fn execute_boot_action(
    action: BootAction,
    detected_os: Option<&disk::OsInfo>,
    mut net_stack: Option<net::NetworkStack<'static>>,
) -> ! {
    let (width, height) = framebuffer::dimensions().unwrap_or((800, 600));

    match action {
        BootAction::BootLocal => {
            serial::println("Executing: Boot local OS");
            virtio::reset_all();
            if let Some(os) = detected_os {
                bios_disk::chainload_mbr(&os.mbr, 0x80);
            } else {
                serial::println("ERROR: No OS detected, cannot boot");
                halt_silent();
            }
        }
        BootAction::Imaging => {
            serial::println("Executing: Imaging mode (boot Mage)");
            chainload::boot_imaging();
        }
        BootAction::MemoryTest => {
            serial::println("Executing: Memory test via server boot-mode tag");
            handle_boot_mode_request(detected_os, &mut net_stack, width, height, b"memtest", 7, None);
        }
        BootAction::Rescue => {
            serial::println("Executing: Rescue environment via server boot-mode tag");
            handle_boot_mode_request(detected_os, &mut net_stack, width, height, b"rescue", 6, None);
        }
        BootAction::ShowMenu => {
            serial::println("Executing: Show menu");
            let choice = ui::draw_boot_screen_with_net(detected_os, &mut net_stack);
            dispatch_menu_choice(choice, detected_os, &mut net_stack, width, height);
        }
        BootAction::InstallOs => {
            serial::println("Executing: Install OS");
            handle_install_os(detected_os, &mut net_stack, width, height);
        }
        BootAction::BootIso => {
            serial::println("Executing: Boot ISO");
            handle_boot_iso(detected_os, &mut net_stack, width, height);
        }
        BootAction::RemoveFromDragonfly => {
            serial::println("Executing: Remove from Dragonfly");
            handle_remove_from_dragonfly(detected_os, &mut net_stack, width, height);
        }
        BootAction::Reboot => {
            serial::println("Executing: Reboot");
            bios::reboot();
        }
    }
}

/// Dispatch a menu choice to the appropriate action
fn dispatch_menu_choice(
    choice: ui::Choice,
    detected_os: Option<&disk::OsInfo>,
    net_stack: &mut Option<net::NetworkStack<'static>>,
    width: u32,
    height: u32,
) -> ! {
    match choice {
        ui::Choice::BootLocal => {
            virtio::reset_all();
            if let Some(os) = detected_os {
                bios_disk::chainload_mbr(&os.mbr, 0x80);
            } else {
                serial::println("ERROR: No OS detected");
                halt_silent();
            }
        }
        ui::Choice::InstallOs => {
            handle_install_os(detected_os, net_stack, width, height);
        }
        ui::Choice::MemoryTest => {
            handle_boot_mode_request(detected_os, net_stack, width, height, b"memtest", 7, None);
        }
        ui::Choice::Rescue => {
            handle_boot_mode_request(detected_os, net_stack, width, height, b"rescue", 6, None);
        }
        ui::Choice::BootIso => {
            handle_boot_iso(detected_os, net_stack, width, height);
        }
        ui::Choice::RemoveFromDragonfly => {
            handle_remove_from_dragonfly(detected_os, net_stack, width, height);
        }
        ui::Choice::Reboot => {
            bios::reboot();
        }
    }
}

/// Handle "Install OS" flow: fetch templates, show list, request install, reboot
fn handle_install_os(
    detected_os: Option<&disk::OsInfo>,
    net_stack: &mut Option<net::NetworkStack<'static>>,
    width: u32,
    height: u32,
) -> ! {
    ui::draw_status(width, height, "Install OS", "Fetching available templates...", framebuffer::colors::ACCENT_PURPLE);

    let stack = match net_stack.as_mut() {
        Some(s) => s,
        None => {
            ui::draw_result_and_wait(width, height, "Error", "No network available", false);
            bios::reboot();
        }
    };

    if !ensure_ip(stack) {
        ui::draw_result_and_wait(width, height, "Error", "No IP address (DHCP failed)", false);
        bios::reboot();
    }

    let (server_ip, server_port) = resolve_server(stack);

    // Fetch template list
    let templates = http::get_templates(stack, server_ip, server_port);

    match templates {
        Some(list) if list.count > 0 => {
            // Build arrays for the UI
            let mut names = [[0u8; 64]; 16];
            let mut name_lens = [0usize; 16];
            for i in 0..list.count {
                names[i] = list.entries[i].display_name;
                name_lens[i] = list.entries[i].display_name_len;
            }

            if let Some(idx) = ui::draw_template_list(width, height, &names, &name_lens, list.count) {
                // User selected a template - get the machine_id from a quick checkin
                let mac = stack.device.mac_address();
                ui::draw_status(width, height, "Install OS", "Requesting installation...", framebuffer::colors::ACCENT_PURPLE);

                // Do a quick check-in to get our machine_id
                if let Some(response) = http::checkin(stack, server_ip, server_port, &mac, detected_os) {
                    let success = http::request_install(
                        stack,
                        server_ip,
                        server_port,
                        &response.machine_id,
                        response.machine_id_len,
                        &mac,
                        &list.entries[idx].name,
                        list.entries[idx].name_len,
                    );

                    if success {
                        ui::draw_status(width, height, "Install OS", "Rebooting into imaging...", framebuffer::colors::SUCCESS);
                        // Brief display then reboot into Mage
                        let brief_start = net::now().total_millis();
                        while (net::now().total_millis() - brief_start) < 1000 {}
                        chainload::boot_imaging();
                    } else {
                        ui::draw_result_and_wait(width, height, "Error", "Server rejected install request", false);
                        bios::reboot();
                    }
                } else {
                    ui::draw_result_and_wait(width, height, "Error", "Could not reach server for check-in", false);
                    bios::reboot();
                }
            } else {
                // User cancelled - reboot to go back to menu
                bios::reboot();
            }
        }
        _ => {
            ui::draw_result_and_wait(width, height, "No Templates", "No OS templates available on server", false);
            bios::reboot();
        }
    }
}

/// Handle "Boot from ISO" flow: fetch ISO list from server, show selection, request boot mode
fn handle_boot_iso(
    detected_os: Option<&disk::OsInfo>,
    net_stack: &mut Option<net::NetworkStack<'static>>,
    width: u32,
    height: u32,
) -> ! {
    ui::draw_status(width, height, "Boot from ISO", "Fetching available ISOs...", framebuffer::colors::ACCENT_PURPLE);

    let stack = match net_stack.as_mut() {
        Some(s) => s,
        None => {
            ui::draw_result_and_wait(width, height, "Error", "No network available", false);
            bios::reboot();
        }
    };

    if !ensure_ip(stack) {
        ui::draw_result_and_wait(width, height, "Error", "No IP address (DHCP failed)", false);
        bios::reboot();
    }

    let (server_ip, server_port) = resolve_server(stack);

    // Fetch ISO list from server
    let isos = http::get_isos(stack, server_ip, server_port);

    match isos {
        Some(list) if list.count > 0 => {
            // Build arrays for the UI
            let mut names = [[0u8; 64]; 16];
            let mut name_lens = [0usize; 16];
            for i in 0..list.count {
                names[i] = list.entries[i].name;
                name_lens[i] = list.entries[i].name_len;
            }

            if let Some(idx) = ui::draw_iso_list(width, height, &names, &name_lens, list.count) {
                // User selected an ISO — request boot mode from server
                let mac = stack.device.mac_address();
                ui::draw_status(width, height, "Boot from ISO", "Requesting ISO boot...", framebuffer::colors::ACCENT_PURPLE);

                if let Some(response) = http::checkin(stack, server_ip, server_port, &mac, detected_os) {
                    let success = http::request_boot_mode(
                        stack,
                        server_ip,
                        server_port,
                        &response.machine_id,
                        response.machine_id_len,
                        &mac,
                        b"iso",
                        3,
                        Some((&list.entries[idx].name, list.entries[idx].name_len)),
                    );

                    if success {
                        ui::draw_status(width, height, "Boot from ISO", "Rebooting for iPXE sanboot...", framebuffer::colors::SUCCESS);
                        let brief_start = net::now().total_millis();
                        while (net::now().total_millis() - brief_start) < 1000 {}
                        bios::reboot();
                    } else {
                        ui::draw_result_and_wait(width, height, "Error", "Server rejected ISO boot request", false);
                        bios::reboot();
                    }
                } else {
                    ui::draw_result_and_wait(width, height, "Error", "Could not reach server for check-in", false);
                    bios::reboot();
                }
            } else {
                // User cancelled - reboot to go back to menu
                bios::reboot();
            }
        }
        _ => {
            ui::draw_result_and_wait(width, height, "No ISOs", "No ISO images available on server", false);
            bios::reboot();
        }
    }
}

/// Handle a generic boot-mode request (memtest, rescue, etc.)
///
/// Checks in with server, sends boot-mode request, and reboots.
/// The server sets a one-shot tag; iPXE fetches the appropriate boot script on next boot.
fn handle_boot_mode_request(
    detected_os: Option<&disk::OsInfo>,
    net_stack: &mut Option<net::NetworkStack<'static>>,
    width: u32,
    height: u32,
    mode: &[u8],
    mode_len: usize,
    iso_name: Option<(&[u8], usize)>,
) -> ! {
    let mode_str = core::str::from_utf8(&mode[..mode_len]).unwrap_or("unknown");
    ui::draw_status(width, height, mode_str, "Contacting server...", framebuffer::colors::ACCENT_PURPLE);

    let stack = match net_stack.as_mut() {
        Some(s) => s,
        None => {
            ui::draw_result_and_wait(width, height, "Error", "No network available", false);
            bios::reboot();
        }
    };

    if !ensure_ip(stack) {
        ui::draw_result_and_wait(width, height, "Error", "No IP address (DHCP timeout)", false);
        bios::reboot();
    }

    let (server_ip, server_port) = resolve_server(stack);

    let mac = stack.device.mac_address();
    if let Some(response) = http::checkin(stack, server_ip, server_port, &mac, detected_os) {
        let success = http::request_boot_mode(
            stack,
            server_ip,
            server_port,
            &response.machine_id,
            response.machine_id_len,
            &mac,
            mode,
            mode_len,
            iso_name,
        );

        if success {
            ui::draw_status(width, height, mode_str, "Rebooting...", framebuffer::colors::SUCCESS);
            let brief_start = net::now().total_millis();
            while (net::now().total_millis() - brief_start) < 1000 {}
            bios::reboot();
        } else {
            ui::draw_result_and_wait(width, height, "Error", "Server rejected boot mode request", false);
            bios::reboot();
        }
    } else {
        ui::draw_result_and_wait(width, height, "Error", "Could not reach server", false);
        bios::reboot();
    }
}

/// Handle "Remove from Dragonfly" flow
fn handle_remove_from_dragonfly(
    detected_os: Option<&disk::OsInfo>,
    net_stack: &mut Option<net::NetworkStack<'static>>,
    width: u32,
    height: u32,
) -> ! {
    // Confirmation dialog
    if !ui::draw_confirmation(
        width,
        height,
        "Remove from Dragonfly",
        "This machine will be unregistered from the server.",
    ) {
        // User cancelled
        bios::reboot();
    }

    let stack = match net_stack.as_mut() {
        Some(s) => s,
        None => {
            ui::draw_result_and_wait(width, height, "Error", "No network available", false);
            bios::reboot();
        }
    };

    if !ensure_ip(stack) {
        ui::draw_result_and_wait(width, height, "Error", "No IP address (DHCP timeout)", false);
        bios::reboot();
    }

    let (server_ip, server_port) = resolve_server(stack);

    ui::draw_status(width, height, "Removing", "Contacting server...", framebuffer::colors::WARNING);

    let mac = stack.device.mac_address();
    if let Some(response) = http::checkin(stack, server_ip, server_port, &mac, detected_os) {
        let success = http::remove_machine(
            stack,
            server_ip,
            server_port,
            &response.machine_id,
            response.machine_id_len,
            &mac,
        );

        if success {
            ui::draw_result_and_wait(width, height, "Removed", "Machine unregistered from Dragonfly", true);
        } else {
            ui::draw_result_and_wait(width, height, "Error", "Server rejected removal request", false);
        }
    } else {
        ui::draw_result_and_wait(width, height, "Error", "Could not reach server", false);
    }

    bios::reboot();
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

    vga::print_success("Multiboot verified");
    vga::println("");
    vga::println("Scanning for bootable operating systems...");
    vga::println("");

    // Scan for OS
    let detected_os = disk::scan_for_os();
    serial::println("OS scan complete");

    match detected_os {
        Some(os_info) => {
            vga::print("Found: ");
            vga::println(os_info.display_name());
            vga::println("");

            // Show text menu
            let choice = menu::show_boot_menu(&os_info);
            match choice {
                ui::Choice::BootLocal => {
                    vga::println("Chainloading bootloader...");
                    chainload::boot_grub(&os_info);
                }
                ui::Choice::Reboot => bios::reboot(),
                ui::Choice::InstallOs => {
                    vga::println("Rebooting into imaging environment...");
                    chainload::boot_imaging();
                }
                ui::Choice::MemoryTest | ui::Choice::Rescue | ui::Choice::BootIso | ui::Choice::RemoveFromDragonfly => {
                    vga::println("This feature requires graphical mode.");
                    halt();
                }
            }
        }
        None => {
            let choice = menu::show_no_os_menu();
            match choice {
                ui::Choice::BootLocal | ui::Choice::Reboot => bios::reboot(),
                _ => {
                    vga::println("Rebooting into imaging environment...");
                    chainload::boot_imaging();
                }
            }
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

// Import stack_bottom from boot.s so we can check stack usage
unsafe extern "C" {
    static stack_bottom: u8;
    static stack_top: u8;
}

/// Print current stack usage
fn print_stack_usage(label: &str) {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp); }
    let stack_top_addr = unsafe { &stack_top as *const u8 as u64 };
    let stack_bottom_addr = unsafe { &stack_bottom as *const u8 as u64 };
    let used = stack_top_addr.saturating_sub(rsp);
    let total = stack_top_addr.saturating_sub(stack_bottom_addr);

    serial::print("STACK[");
    serial::print(label);
    serial::print("]: RSP=0x");
    serial::print_hex32((rsp >> 32) as u32);
    serial::print_hex32(rsp as u32);
    serial::print(" used=");
    serial::print_dec((used / 1024) as u32);
    serial::print("KB/");
    serial::print_dec((total / 1024) as u32);
    serial::println("KB");
}

/// Socket storage for network stack (must be static to outlive function)
static mut SOCKET_STORAGE: [smoltcp::iface::SocketStorage<'static>; 4] = [
    smoltcp::iface::SocketStorage::EMPTY,
    smoltcp::iface::SocketStorage::EMPTY,
    smoltcp::iface::SocketStorage::EMPTY,
    smoltcp::iface::SocketStorage::EMPTY,
];

/// Initialize network stack (non-blocking) - DHCP will be polled during UI countdown
///
/// Tries e1000e (real hardware) first, then falls back to VirtIO-net (VMs).
fn init_network_stack() -> Option<net::NetworkStack<'static>> {
    // Try e1000e first (real hardware Intel NICs)
    let device = if let Some(e1000e) = e1000e::E1000e::init() {
        serial::print("MAC: ");
        let mac = e1000e.mac_address();
        for i in 0..6 {
            if i > 0 { serial::print(":"); }
            serial::print_hex32(mac[i] as u32);
        }
        serial::println("");
        NetDevice::new_e1000e(e1000e)
    } else if let Some(virtio_net) = virtio_net::VirtioNet::init() {
        serial::print("MAC: ");
        let mac = virtio_net.mac_address();
        for i in 0..6 {
            if i > 0 { serial::print(":"); }
            serial::print_hex32(mac[i] as u32);
        }
        serial::println("");
        NetDevice::new_virtio(virtio_net)
    } else {
        serial::println("NET: No network device found (tried e1000e, VirtIO-net)");
        return None;
    };

    // Disable interrupts (no IDT)
    unsafe { core::arch::asm!("cli"); }

    // Initialize network stack with DHCP (uses static socket storage)
    // SAFETY: This is only called once at boot, no concurrent access
    #[allow(static_mut_refs)]
    let stack = unsafe { net::NetworkStack::new(device, &mut SOCKET_STORAGE) };

    serial::println("Network stack initialized, DHCP will run during countdown");
    stack
}

/// Test network functionality - initialize VirtIO-net, get DHCP, register with server
fn test_network() {
    serial::println("=== Dragonfly Spark Network ===");

    // Get server from command line (optional)
    let params = cmdline::params();

    vga::println("Initializing network...");

    // Initialize NIC — try e1000e first, then VirtIO-net
    let device = if let Some(e1000e) = e1000e::E1000e::init() {
        let mac = e1000e.mac_address();
        serial::print("MAC: ");
        for i in 0..6 {
            if i > 0 { serial::print(":"); }
            serial::print_hex32(mac[i] as u32);
        }
        serial::println("");
        NetDevice::new_e1000e(e1000e)
    } else if let Some(virtio_net) = virtio_net::VirtioNet::init() {
        let mac = virtio_net.mac_address();
        serial::print("MAC: ");
        for i in 0..6 {
            if i > 0 { serial::print(":"); }
            serial::print_hex32(mac[i] as u32);
        }
        serial::println("");
        NetDevice::new_virtio(virtio_net)
    } else {
        serial::println("ERROR: No network device found");
        vga::print_error("No network device found (tried e1000e, VirtIO-net)");
        return;
    };

    let mac = device.mac_address();

    // Disable interrupts (no IDT)
    unsafe { core::arch::asm!("cli"); }

    // Create socket storage
    let mut socket_storage: [smoltcp::iface::SocketStorage<'_>; 4] = Default::default();

    // Initialize network stack with DHCP
    let mut stack = match net::NetworkStack::new(device, &mut socket_storage) {
        Some(s) => s,
        None => {
            serial::println("ERROR: Failed to initialize network stack");
            vga::print_error("Failed to initialize network stack");
            return;
        }
    };

    vga::println("DHCP: Requesting IP address...");
    serial::println("DHCP: Polling for 10 seconds...");

    // Poll for DHCP - poll for 10 seconds (10000ms)
    let start_time = net::now().total_millis();
    let timeout_ms = 10000; // 10 seconds
    let mut last_print = 0u32;

    loop {
        stack.poll();

        let elapsed = (net::now().total_millis() - start_time) as u32;

        if stack.has_ip() {
            if let Some(ip) = stack.get_ip() {
                vga::print("Got IP: ");
                let mut ip_str = [0u8; 16];
                let len = net::format_ip(&ip, &mut ip_str);
                if let Ok(s) = core::str::from_utf8(&ip_str[..len]) {
                    vga::println(s);
                }
            }
            vga::print_success("Network ready!");
            break;
        }

        // Print progress every second
        if elapsed / 1000 > last_print {
            last_print = elapsed / 1000;
            serial::print("DHCP: ");
            serial::print_dec(last_print);
            serial::println("s...");
            vga::print(".");
        }

        if elapsed > timeout_ms {
            vga::println("");
            vga::print_warning("DHCP timeout - no IP received");
            serial::println("DHCP: Timeout after 10s");
            return;
        }
    }

    // Register with Dragonfly server if specified
    if !params.has_server {
        vga::println("");
        vga::println("No server specified - skipping registration");
        serial::println("No server= param, skipping registration");
        return;
    }

    vga::println("");
    vga::println("Registering with Dragonfly server...");

    // Create TCP socket buffers
    let mut tcp_rx_buffer = [0u8; 2048];
    let mut tcp_tx_buffer = [0u8; 2048];

    let tcp_handle = stack.create_tcp_socket(&mut tcp_rx_buffer, &mut tcp_tx_buffer);

    // Connect to server (IP from command line)
    let server_ip = smoltcp::wire::Ipv4Address(params.server_ip);
    let endpoint = smoltcp::wire::IpEndpoint::new(server_ip.into(), params.server_port);

    if !stack.tcp_connect(tcp_handle, endpoint) {
        vga::print_error("Failed to initiate connection");
        return;
    }

    // Wait for connection to establish
    let mut connected = false;
    for _ in 0..100000 {
        stack.poll();
        if stack.tcp_is_connected(tcp_handle) {
            connected = true;
            serial::println("TCP: Connected!");
            break;
        }
    }

    if !connected {
        vga::print_warning("Connection timeout");
        serial::println("TCP: Connection timeout");
        return;
    }

    vga::print("Connected to server!");

    // Build JSON registration payload
    let mut json_buf = [0u8; 512];
    let json_len = build_register_json(&mac, stack.get_ip().unwrap(), &mut json_buf);

    // Build HTTP POST request
    let mut http_buf = [0u8; 1024];
    let http_len = build_http_post(&json_buf[..json_len], &params.server_ip, &mut http_buf);

    serial::println("Sending registration request...");

    // Send HTTP request
    let mut sent = 0;
    while sent < http_len {
        stack.poll();
        if stack.tcp_can_send(tcp_handle) {
            let n = stack.tcp_send(tcp_handle, &http_buf[sent..http_len]);
            sent += n;
        }
    }

    serial::print("Sent ");
    serial::print_dec(sent as u32);
    serial::println(" bytes");

    // Wait for response
    let mut response_buf = [0u8; 1024];
    let mut response_len = 0;

    for _ in 0..100000 {
        stack.poll();
        if stack.tcp_can_recv(tcp_handle) {
            let n = stack.tcp_recv(tcp_handle, &mut response_buf[response_len..]);
            response_len += n;
            if n == 0 || response_len > 100 {
                break; // Got response or connection closed
            }
        }
    }

    if response_len > 0 {
        serial::print("Response: ");
        serial::print_dec(response_len as u32);
        serial::println(" bytes");

        // Check for HTTP 200/201 in response
        if response_buf.starts_with(b"HTTP/1.1 200") || response_buf.starts_with(b"HTTP/1.1 201") {
            vga::print_success("Registered with server!");
            serial::println("Registration successful!");
        } else {
            vga::print_warning("Server returned error");
            // Print first line of response
            if let Some(end) = response_buf[..response_len].iter().position(|&c| c == b'\n') {
                if let Ok(line) = core::str::from_utf8(&response_buf[..end]) {
                    serial::println(line);
                }
            }
        }
    } else {
        vga::print_warning("No response from server");
    }

    // Close connection
    stack.tcp_close(tcp_handle);

    // Keep polling to allow graceful close
    for _ in 0..10000 {
        stack.poll();
    }
}

/// Build JSON registration payload
fn build_register_json(mac: &[u8; 6], ip: smoltcp::wire::Ipv4Address, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    // Start JSON object
    buf[pos..pos+14].copy_from_slice(b"{\"mac_address\"");
    pos += 14;
    buf[pos..pos+2].copy_from_slice(b":\"");
    pos += 2;

    // Format MAC address
    pos += net::format_mac(mac, &mut buf[pos..]);

    buf[pos..pos+16].copy_from_slice(b"\",\"ip_address\":\"");
    pos += 16;

    // Format IP address
    pos += net::format_ip(&ip, &mut buf[pos..]);

    buf[pos..pos+2].copy_from_slice(b"\"}");
    pos += 2;

    pos
}

/// Build HTTP POST request
fn build_http_post(body: &[u8], server_ip: &[u8; 4], buf: &mut [u8]) -> usize {
    let mut pos = 0;

    // Request line
    buf[pos..pos+37].copy_from_slice(b"POST /api/v1/machines HTTP/1.1\r\nHost");
    pos += 37;
    buf[pos..pos+2].copy_from_slice(b": ");
    pos += 2;

    // Host header (server IP from params)
    let ip = smoltcp::wire::Ipv4Address(*server_ip);
    pos += net::format_ip(&ip, &mut buf[pos..]);

    buf[pos..pos+2].copy_from_slice(b"\r\n");
    pos += 2;

    // Content-Type header
    buf[pos..pos+32].copy_from_slice(b"Content-Type: application/json\r\n");
    pos += 32;

    // Content-Length header
    buf[pos..pos+16].copy_from_slice(b"Content-Length: ");
    pos += 16;

    // Write body length as decimal
    let body_len = body.len();
    if body_len >= 100 {
        buf[pos] = b'0' + (body_len / 100) as u8;
        pos += 1;
    }
    if body_len >= 10 {
        buf[pos] = b'0' + ((body_len / 10) % 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (body_len % 10) as u8;
    pos += 1;

    // Connection close and end headers
    buf[pos..pos+23].copy_from_slice(b"\r\nConnection: close\r\n\r\n");
    pos += 23;

    // Copy body
    buf[pos..pos+body.len()].copy_from_slice(body);
    pos += body.len();

    pos
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
