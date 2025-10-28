use color_eyre::eyre::{Result, eyre};
use std::net::Ipv4Addr;
use std::process::Command;
use network_interface::{NetworkInterface, NetworkInterfaceConfig, Addr};

/// Get the network interface configuration with IP and netmask
fn get_network_config() -> Result<(Ipv4Addr, Ipv4Addr)> {
    let interfaces = NetworkInterface::show()
        .map_err(|e| eyre!("Failed to get network interfaces: {}", e))?;

    for interface in interfaces {
        // Skip loopback interfaces
        if interface.name.starts_with("lo") {
            continue;
        }

        // Look for IPv4 addresses
        for addr in interface.addr {
            if let Addr::V4(v4_addr) = addr {
                let ip = v4_addr.ip;

                // Skip loopback addresses
                if ip.is_loopback() {
                    continue;
                }

                // Get netmask or default to /24
                let netmask = v4_addr.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0));

                return Ok((ip, netmask));
            }
        }
    }

    Err(eyre!("No suitable network interface found"))
}

/// Calculate the network range to scan based on IP and netmask
fn calculate_scan_range(ip: Ipv4Addr, netmask: Ipv4Addr) -> (Ipv4Addr, Ipv4Addr) {
    let ip_bits = u32::from(ip);
    let mask_bits = u32::from(netmask);

    // Count the prefix length
    let prefix_len = mask_bits.count_ones();

    // If subnet is /24 or larger (smaller number = bigger network), use just the /24
    // If subnet is more restrictive (e.g., /25, /26), use the actual subnet
    let scan_mask = if prefix_len <= 24 {
        // Use /24
        0xFFFFFF00u32
    } else {
        // Use the actual netmask
        mask_bits
    };

    let scan_network = ip_bits & scan_mask;
    let scan_broadcast = scan_network | !scan_mask;

    // Start from network + 1, end at broadcast - 1
    let start = Ipv4Addr::from(scan_network + 1);
    let end = Ipv4Addr::from(scan_broadcast - 1);

    (start, end)
}

/// Check if an IP is available (doesn't respond to ping)
fn is_ip_available(ip: Ipv4Addr) -> bool {
    // Use ping with 1 packet and 1 second timeout
    let output = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("1")
        .arg(ip.to_string())
        .output();

    match output {
        Ok(result) => !result.status.success(), // If ping fails, IP is available
        Err(_) => true, // If we can't ping, assume it's available
    }
}

/// Detects the first available IP address in the current network range
pub fn detect_first_available_ip() -> Result<Ipv4Addr> {
    let (ip, netmask) = get_network_config()?;
    let (start, end) = calculate_scan_range(ip, netmask);

    // Convert to u32 for iteration
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    // Scan the range for available IPs
    for ip_u32 in start_u32..=end_u32 {
        let candidate = Ipv4Addr::from(ip_u32);

        // Skip our own IP
        if candidate == ip {
            continue;
        }

        if is_ip_available(candidate) {
            return Ok(candidate);
        }
    }

    Err(eyre!("No available IPs found in range {} - {}", start, end))
}

/// Validates an IPv4 address string
pub fn validate_ipv4(ip_str: &str) -> Result<Ipv4Addr> {
    // Trim and parse the IP address
    let trimmed = ip_str.trim();

    // Check if the trimmed string is different from original (has spaces)
    if trimmed != ip_str {
        return Err(eyre!("IP address should not contain leading or trailing spaces"));
    }

    // Parse the IP address
    let ip: Ipv4Addr = trimmed.parse()
        .map_err(|_| eyre!("Invalid IPv4 address format: {}", ip_str))?;

    Ok(ip)
}

/// Processes user input for IP selection
/// Returns the IP to use based on input
pub fn process_ip_input(input: &str, default_ip: Ipv4Addr) -> Result<Ipv4Addr> {
    let trimmed = input.trim();

    // Empty input or just Enter means accept default
    if trimmed.is_empty() {
        return Ok(default_ip);
    }

    // Otherwise, validate the input as an IPv4 address
    validate_ipv4(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_scan_range_slash_24() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let netmask = Ipv4Addr::new(255, 255, 255, 0); // /24

        let (start, end) = calculate_scan_range(ip, netmask);

        assert_eq!(start, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(end, Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_calculate_scan_range_slash_16_uses_slash_24() {
        let ip = Ipv4Addr::new(10, 7, 50, 100);
        let netmask = Ipv4Addr::new(255, 255, 0, 0); // /16

        let (start, end) = calculate_scan_range(ip, netmask);

        // Should only scan the /24 we're in
        assert_eq!(start, Ipv4Addr::new(10, 7, 50, 1));
        assert_eq!(end, Ipv4Addr::new(10, 7, 50, 254));
    }

    #[test]
    fn test_calculate_scan_range_slash_25() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let netmask = Ipv4Addr::new(255, 255, 255, 128); // /25

        let (start, end) = calculate_scan_range(ip, netmask);

        // Should only scan the /25 subnet (192.168.1.0 - 192.168.1.127)
        assert_eq!(start, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(end, Ipv4Addr::new(192, 168, 1, 126));
    }

    #[test]
    fn test_calculate_scan_range_slash_26() {
        let ip = Ipv4Addr::new(192, 168, 1, 200);
        let netmask = Ipv4Addr::new(255, 255, 255, 192); // /26

        let (start, end) = calculate_scan_range(ip, netmask);

        // Should only scan the /26 subnet (192.168.1.192 - 192.168.1.255)
        assert_eq!(start, Ipv4Addr::new(192, 168, 1, 193));
        assert_eq!(end, Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_detect_first_available_ip_returns_valid_ipv4() {
        let result = detect_first_available_ip();
        assert!(result.is_ok(), "Should detect an available IP");

        let ip = result.unwrap();
        assert!(ip.octets()[0] > 0, "IP should not start with 0");
    }

    #[test]
    fn test_validate_ipv4_valid_addresses() {
        let test_cases = vec![
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "10.7.1.130",
        ];

        for ip_str in test_cases {
            let result = validate_ipv4(ip_str);
            assert!(result.is_ok(), "Should validate {} as valid IPv4", ip_str);
        }
    }

    #[test]
    fn test_validate_ipv4_invalid_addresses() {
        let test_cases = vec![
            "256.256.256.256", // Out of range
            "192.168.1",        // Incomplete
            "192.168.1.1.1",    // Too many octets
            "abc.def.ghi.jkl",  // Non-numeric
            "",                 // Empty
            "192.168.-1.1",     // Negative
        ];

        for ip_str in test_cases {
            let result = validate_ipv4(ip_str);
            assert!(result.is_err(), "Should reject {} as invalid IPv4", ip_str);
        }
    }

    #[test]
    fn test_validate_ipv4_edge_cases() {
        // Test boundary values
        assert!(validate_ipv4("0.0.0.0").is_ok(), "0.0.0.0 should be valid");
        assert!(validate_ipv4("255.255.255.255").is_ok(), "255.255.255.255 should be valid");

        // Test with spaces
        assert!(validate_ipv4(" 192.168.1.1").is_err(), "Should reject leading space");
        assert!(validate_ipv4("192.168.1.1 ").is_err(), "Should reject trailing space");
    }

    #[test]
    fn test_detect_ip_returns_in_valid_range() {
        let result = detect_first_available_ip();

        if let Ok(ip) = result {
            let octets = ip.octets();

            // Check if it's in a private network range
            let is_private =
                (octets[0] == 10) ||
                (octets[0] == 172 && (16..=31).contains(&octets[1])) ||
                (octets[0] == 192 && octets[1] == 168);

            assert!(is_private, "Detected IP should be in a private range");
        }
    }

    #[test]
    fn test_process_ip_input_accepts_default_on_enter() {
        let default_ip = Ipv4Addr::new(10, 7, 1, 130);

        // Test empty input (Enter key)
        let result = process_ip_input("", default_ip);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), default_ip);

        // Test whitespace only
        let result = process_ip_input("   ", default_ip);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), default_ip);
    }

    #[test]
    fn test_process_ip_input_accepts_valid_custom_ip() {
        let default_ip = Ipv4Addr::new(10, 7, 1, 130);
        let custom_ip_str = "192.168.1.100";

        let result = process_ip_input(custom_ip_str, default_ip);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_process_ip_input_rejects_invalid_custom_ip() {
        let default_ip = Ipv4Addr::new(10, 7, 1, 130);

        let invalid_ips = vec![
            "256.256.256.256",
            "not.an.ip.address",
            "192.168.1",
        ];

        for invalid_ip in invalid_ips {
            let result = process_ip_input(invalid_ip, default_ip);
            assert!(result.is_err(), "Should reject invalid IP: {}", invalid_ip);
        }
    }
}
