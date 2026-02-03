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
use virtio_net::VirtioNet;

mod ahci;
mod allocator;
mod bios;
mod bios_disk;
mod block_logo;
mod chainload;
mod cmdline;
mod disk;
mod font;
mod framebuffer;
mod http;
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
    serial::println("Dragonfly Spark v0.1.0 - Serial debug enabled");

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

        // MB1: cmdline parsing not implemented yet
        // Server address will come from DHCP siaddr instead
        serial::println("MB1: Using DHCP for server discovery");
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
    let action = boot_flow_with_checkin(detected_os, &mut net_stack, width, height);

    // Execute the decided action
    execute_boot_action(action, detected_os);
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
}

/// Default server port for check-in
const DEFAULT_SERVER_PORT: u16 = 8080;

/// Boot timeout (seconds)
/// Just long enough for DHCP + server check-in. User can hold spacebar to enter menu.
const BOOT_TIMEOUT_SECS: u32 = 2;

/// Perform boot flow with server check-in and spacebar interrupt
fn boot_flow_with_checkin(
    detected_os: Option<&disk::OsInfo>,
    net_stack: &mut Option<net::NetworkStack<'static>>,
    width: u32,
    height: u32,
) -> BootAction {
    let mut ip_displayed = false;
    let mut checkin_done = false;

    // Get MAC address from network stack (if available)
    let mac = net_stack.as_ref().map(|s| s.device.mac_address());

    serial::println("Boot flow: Starting - press SPACE for menu");

    // Use wall-clock time for timeout (1 second max wait for DHCP + checkin)
    let start_time = net::now().total_millis();
    let timeout_ms = (BOOT_TIMEOUT_SECS as i64) * 1000;

    loop {
        let elapsed = net::now().total_millis() - start_time;

        // Check for spacebar (scancode 0x39)
        if let Some(scancode) = bios::read_scancode() {
            if scancode == 0x39 {
                serial::println("Boot flow: Spacebar pressed - showing menu");
                return BootAction::ShowMenu;
            }
        }

        // Poll network
        if let Some(stack) = net_stack.as_mut() {
            stack.poll();

            // Display IP once we have it
            if !ip_displayed && stack.has_ip() {
                if let Some(ip) = stack.get_ip() {
                    ui::draw_ip_footer(width, height, ip);
                    ip_displayed = true;
                    serial::println("Boot flow: Got IP");
                }
            }

            // Attempt server check-in once we have IP
            if !checkin_done && stack.has_ip() {
                if let Some(mac_addr) = mac.as_ref() {
                    checkin_done = true;

                    // Get server IP from DHCP boot server (siaddr) or fallback
                    let server_ip = stack.boot_server.unwrap_or_else(|| {
                        stack.gateway.unwrap_or(smoltcp::wire::Ipv4Address([10, 7, 1, 1]))
                    });

                    serial::print("Boot flow: Checking in with ");
                    serial::print_dec(server_ip.0[0] as u32);
                    serial::print(".");
                    serial::print_dec(server_ip.0[1] as u32);
                    serial::print(".");
                    serial::print_dec(server_ip.0[2] as u32);
                    serial::print(".");
                    serial::print_dec(server_ip.0[3] as u32);
                    serial::println("");

                    // Perform check-in (has its own fast timeouts)
                    if let Some(response) = http::checkin(
                        stack,
                        server_ip,
                        DEFAULT_SERVER_PORT,
                        mac_addr,
                        detected_os,
                    ) {
                        serial::println("Boot flow: Server responded");
                        // Execute server's directive
                        return match response.action {
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
                        };
                    } else {
                        // Server unreachable - proceed to autoboot
                        serial::println("Boot flow: Server unreachable, proceeding to autoboot");
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

    // Default: boot local OS if detected, otherwise imaging
    serial::println("Boot flow: Autoboot");
    if detected_os.is_some() {
        BootAction::BootLocal
    } else {
        BootAction::Imaging
    }
}

/// Execute the decided boot action
fn execute_boot_action(action: BootAction, detected_os: Option<&disk::OsInfo>) -> ! {
    match action {
        BootAction::BootLocal => {
            serial::println("Executing: Boot local OS");
            // Reset VirtIO to restore BIOS compatibility
            virtio::reset_all();
            if let Some(os) = detected_os {
                bios_disk::chainload_mbr(&os.mbr, 0x80);
            } else {
                serial::println("ERROR: No OS detected, cannot boot");
                halt_silent();
            }
        }
        BootAction::Imaging => {
            serial::println("Executing: Imaging mode");
            chainload::boot_imaging();
        }
        BootAction::ShowMenu => {
            serial::println("Executing: Show menu");
            // Reinitialize network for menu use
            let net_stack = init_network_stack();
            let choice = ui::draw_boot_screen_with_net(detected_os, net_stack);
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
                ui::Choice::Reinstall => chainload::boot_imaging(),
                ui::Choice::Shell => {
                    vga::init();
                    vga::clear();
                    vga::println("=== Dragonfly Spark Network Test ===");
                    test_network();
                    vga::println("Test complete. System halted.");
                    halt_silent();
                }
            }
        }
        BootAction::Reboot => {
            serial::println("Executing: Reboot");
            bios::reboot();
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
                    vga::println("");
                    test_network();
                    vga::println("");
                    vga::println("Test complete.");
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
fn init_network_stack() -> Option<net::NetworkStack<'static>> {
    // Initialize VirtIO-net
    let virtio_net = VirtioNet::init()?;

    serial::print("MAC: ");
    let mac = virtio_net.mac_address();
    for i in 0..6 {
        if i > 0 { serial::print(":"); }
        serial::print_hex32(mac[i] as u32);
    }
    serial::println("");

    // Disable interrupts (no IDT)
    unsafe { core::arch::asm!("cli"); }

    // Wrap in NetDevice
    let device = NetDevice::new(virtio_net);

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

    // Initialize VirtIO-net
    let virtio_net = match VirtioNet::init() {
        Some(dev) => dev,
        None => {
            serial::println("ERROR: No VirtIO-net device found");
            vga::print_error("No VirtIO-net device found");
            return;
        }
    };

    let mac = virtio_net.mac_address();
    serial::print("MAC: ");
    for i in 0..6 {
        if i > 0 { serial::print(":"); }
        serial::print_hex32(mac[i] as u32);
    }
    serial::println("");

    // Disable interrupts (no IDT)
    unsafe { core::arch::asm!("cli"); }

    // Wrap in NetDevice
    let device = NetDevice::new(virtio_net);

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
