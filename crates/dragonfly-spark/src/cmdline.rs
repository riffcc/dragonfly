//! Multiboot2 command line parsing
//!
//! Parses boot parameters passed from iPXE/GRUB

use crate::serial;

/// Multiboot2 command line tag type
const MULTIBOOT2_TAG_TYPE_CMDLINE: u32 = 1;
const MULTIBOOT2_TAG_TYPE_END: u32 = 0;

/// Parsed boot parameters
#[derive(Clone, Copy)]
pub struct BootParams {
    /// Dragonfly server IP address
    pub server_ip: [u8; 4],
    /// Dragonfly server port
    pub server_port: u16,
    /// Whether server was specified
    pub has_server: bool,
}

impl Default for BootParams {
    fn default() -> Self {
        BootParams {
            server_ip: [0, 0, 0, 0],
            server_port: 3000, // Default port
            has_server: false,
        }
    }
}

/// Global boot parameters
static mut BOOT_PARAMS: BootParams = BootParams {
    server_ip: [0, 0, 0, 0],
    server_port: 3000,
    has_server: false,
};

/// Parse multiboot2 info to extract command line
pub fn init(multiboot_info: u32) {
    let cmdline = parse_multiboot2_cmdline(multiboot_info);
    if let Some(cmd) = cmdline {
        serial::print("Boot cmdline: ");
        serial::println(cmd);
        parse_params(cmd);
    } else {
        serial::println("No boot command line found");
    }
}

/// Get parsed boot parameters
pub fn params() -> BootParams {
    unsafe { BOOT_PARAMS }
}

/// Parse multiboot2 info structure to find command line tag
fn parse_multiboot2_cmdline(info_addr: u32) -> Option<&'static str> {
    unsafe {
        let total_size = *(info_addr as *const u32);
        let mut tag_addr = info_addr + 8; // Skip size and reserved
        let end_addr = info_addr + total_size;

        while tag_addr < end_addr {
            let tag_type = *(tag_addr as *const u32);
            let tag_size = *((tag_addr + 4) as *const u32);

            if tag_type == MULTIBOOT2_TAG_TYPE_END {
                break;
            }

            if tag_type == MULTIBOOT2_TAG_TYPE_CMDLINE {
                // Command line tag: type, size, then null-terminated string
                let str_ptr = (tag_addr + 8) as *const u8;
                let str_len = tag_size.saturating_sub(9) as usize; // -8 for header, -1 for null

                // Find actual string length (up to null terminator)
                let mut actual_len = 0;
                while actual_len < str_len {
                    if *str_ptr.add(actual_len) == 0 {
                        break;
                    }
                    actual_len += 1;
                }

                let slice = core::slice::from_raw_parts(str_ptr, actual_len);
                return core::str::from_utf8(slice).ok();
            }

            // Move to next tag (8-byte aligned)
            tag_addr += (tag_size + 7) & !7;
        }

        None
    }
}

/// Parse command line parameters
/// Format: server=IP:PORT or server=IP (uses default port 3000)
fn parse_params(cmdline: &str) {
    // Look for "server=" parameter
    if let Some(start) = cmdline.find("server=") {
        let value_start = start + 7; // len("server=")
        let value_end = cmdline[value_start..]
            .find(|c: char| c.is_whitespace())
            .map(|i| value_start + i)
            .unwrap_or(cmdline.len());

        let value = &cmdline[value_start..value_end];

        // Parse IP:PORT or just IP
        let (ip_str, port_str) = if let Some(colon) = value.rfind(':') {
            (&value[..colon], Some(&value[colon + 1..]))
        } else {
            (value, None)
        };

        // Parse IP address
        if let Some(ip) = parse_ipv4(ip_str) {
            unsafe {
                BOOT_PARAMS.server_ip = ip;
                BOOT_PARAMS.has_server = true;

                serial::print("Parsed server IP: ");
                serial::print_dec(ip[0] as u32);
                serial::print(".");
                serial::print_dec(ip[1] as u32);
                serial::print(".");
                serial::print_dec(ip[2] as u32);
                serial::print(".");
                serial::print_dec(ip[3] as u32);
            }

            // Parse port if present
            if let Some(port_s) = port_str {
                if let Some(port) = parse_u16(port_s) {
                    unsafe {
                        BOOT_PARAMS.server_port = port;
                    }
                    serial::print(":");
                    serial::print_dec(port as u32);
                }
            }
            serial::println("");
        }
    }
}

/// Parse IPv4 address from string (e.g., "10.7.1.10")
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut current: u16 = 0;
    let mut has_digit = false;

    for c in s.chars() {
        if c == '.' {
            if !has_digit || octet_idx >= 3 {
                return None;
            }
            if current > 255 {
                return None;
            }
            octets[octet_idx] = current as u8;
            octet_idx += 1;
            current = 0;
            has_digit = false;
        } else if c.is_ascii_digit() {
            current = current * 10 + (c as u16 - '0' as u16);
            has_digit = true;
        } else {
            return None;
        }
    }

    // Last octet
    if !has_digit || octet_idx != 3 || current > 255 {
        return None;
    }
    octets[3] = current as u8;

    Some(octets)
}

/// Parse u16 from string
fn parse_u16(s: &str) -> Option<u16> {
    let mut result: u32 = 0;
    let mut has_digit = false;

    for c in s.chars() {
        if c.is_ascii_digit() {
            result = result * 10 + (c as u32 - '0' as u32);
            has_digit = true;
            if result > 65535 {
                return None;
            }
        } else {
            break;
        }
    }

    if has_digit {
        Some(result as u16)
    } else {
        None
    }
}
