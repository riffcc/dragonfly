use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::store::v1::Store;
use dragonfly_common::Network;

/// Detect the server's own network configuration and create a Default network entity
/// if one with `is_native = true` doesn't already exist.
pub async fn init_default_network(store: Arc<dyn Store>) -> Result<()> {
    // Check if a native network already exists
    let networks = store.list_networks().await?;
    for net in &networks {
        if net.is_native {
            // Clean up stale auto-generated descriptions from earlier versions
            if net
                .description
                .as_deref()
                .map_or(false, |d| d.starts_with("Management network on "))
            {
                let mut updated = net.clone();
                updated.description = None;
                updated.updated_at = chrono::Utc::now();
                store.put_network(&updated).await?;
                info!(
                    "Cleared stale description from native network '{}'",
                    net.name
                );
            }
            debug!("Native network already exists, skipping auto-detection");
            return Ok(());
        }
    }

    info!("No native network found, detecting server network configuration...");

    let iface_info = detect_primary_interface()?;
    let gateway = detect_default_gateway();
    let mut dns_servers = detect_dns_servers();
    // Filter out loopback stubs (systemd-resolved) and fall back to public DNS
    dns_servers.retain(|s| !s.starts_with("127."));
    if dns_servers.is_empty() {
        info!("No usable DNS servers detected, defaulting to 1.1.1.1 and 8.8.8.8");
        dns_servers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
    }

    let subnet = format!(
        "{}/{}",
        network_address(&iface_info.address, iface_info.prefix_len),
        iface_info.prefix_len
    );

    let mut network = Network::new("Default".to_string(), subnet.clone());
    network.is_native = true;
    network.dhcp_enabled = true;
    network.gateway = gateway.clone();
    network.dns_servers = dns_servers.clone();
    network.domain = Some("home.arpa".to_string());
    network.description = None;

    store.put_network(&network).await?;

    info!(
        "Created default network: subnet={}, gateway={}, dns=[{}], iface={}",
        subnet,
        gateway.as_deref().unwrap_or("none"),
        dns_servers.join(", "),
        iface_info.interface,
    );

    Ok(())
}

struct InterfaceInfo {
    interface: String,
    address: String,
    prefix_len: u8,
}

/// Find the primary network interface by looking at the default route,
/// then read its IPv4 address and prefix length.
fn detect_primary_interface() -> Result<InterfaceInfo> {
    // Get default route to find the outgoing interface
    // `ip -j route show default` returns JSON like:
    // [{"dst":"default","gateway":"10.7.1.1","dev":"eno1","protocol":"dhcp",...}]
    let route_output = Command::new("ip")
        .args(["-j", "route", "show", "default"])
        .output()?;

    if !route_output.status.success() {
        anyhow::bail!("Failed to run 'ip -j route show default'");
    }

    let route_json: serde_json::Value = serde_json::from_slice(&route_output.stdout)?;
    let routes = route_json
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No default routes found"))?;

    let first_route = routes
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty default route list"))?;

    let iface = first_route["dev"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No 'dev' in default route"))?;

    debug!("Primary interface from default route: {}", iface);

    // Get address info for this interface
    // `ip -j addr show dev eno1` returns JSON with address details
    let addr_output = Command::new("ip")
        .args(["-j", "-4", "addr", "show", "dev", iface])
        .output()?;

    if !addr_output.status.success() {
        anyhow::bail!("Failed to run 'ip -j -4 addr show dev {}'", iface);
    }

    let addr_json: serde_json::Value = serde_json::from_slice(&addr_output.stdout)?;
    let interfaces = addr_json
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No address info for {}", iface))?;

    let first_iface = interfaces
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty address list for {}", iface))?;

    let addr_info = first_iface["addr_info"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow::anyhow!("No addr_info for {}", iface))?;

    let address = addr_info["local"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No 'local' address for {}", iface))?;

    let prefix_len = addr_info["prefixlen"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("No 'prefixlen' for {}", iface))? as u8;

    Ok(InterfaceInfo {
        interface: iface.to_string(),
        address: address.to_string(),
        prefix_len,
    })
}

/// Read default gateway from the default route.
fn detect_default_gateway() -> Option<String> {
    let output = Command::new("ip")
        .args(["-j", "route", "show", "default"])
        .output()
        .ok()?;

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let gateway = json.as_array()?.first()?["gateway"].as_str()?.to_string();

    Some(gateway)
}

/// Parse DNS servers from /etc/resolv.conf.
fn detect_dns_servers() -> Vec<String> {
    let content = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(c) => c,
        Err(e) => {
            warn!("Could not read /etc/resolv.conf: {}", e);
            return Vec::new();
        }
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                Some(line.strip_prefix("nameserver ")?.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Return all local IPv4 interfaces as (name, ip, prefix_len) tuples.
///
/// Uses `ip -j -4 addr show` to enumerate every non-loopback interface
/// that has at least one IPv4 address.
pub fn enumerate_local_interfaces() -> Vec<(String, Ipv4Addr, u8)> {
    let output = match Command::new("ip")
        .args(["-j", "-4", "addr", "show"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to run 'ip -j -4 addr show': {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to parse 'ip addr' JSON output: {}", e);
            return Vec::new();
        }
    };

    let mut result = Vec::new();

    if let Some(ifaces) = json.as_array() {
        for iface in ifaces {
            let name = match iface["ifname"].as_str() {
                Some(n) => n,
                None => continue,
            };

            // Skip loopback
            if name == "lo" {
                continue;
            }

            if let Some(addr_info) = iface["addr_info"].as_array() {
                for addr in addr_info {
                    let ip_str = match addr["local"].as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    let prefix_len = match addr["prefixlen"].as_u64() {
                        Some(p) => p as u8,
                        None => continue,
                    };
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        result.push((name.to_string(), ip, prefix_len));
                    }
                }
            }
        }
    }

    result
}

/// Given a subnet CIDR (e.g. "10.2.0.0/24"), find the local interface
/// whose IPv4 address falls within that subnet.
///
/// Returns `(interface_name, server_ip)` for the first matching interface,
/// or `None` if no local interface is on that subnet.
pub fn find_interface_for_subnet(subnet_cidr: &str) -> Option<(String, Ipv4Addr)> {
    // Parse the CIDR
    let (net_str, prefix_str) = subnet_cidr.split_once('/')?;
    let prefix_len: u8 = prefix_str.parse().ok()?;
    let subnet_ip: Ipv4Addr = net_str.parse().ok()?;
    let subnet_u32 = u32::from(subnet_ip);
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let subnet_network = subnet_u32 & mask;

    for (iface, ip, _prefix) in enumerate_local_interfaces() {
        // The interface "owns" the subnet if masking its IP with the subnet mask
        // gives the subnet's network address.
        let ip_in_subnet = (u32::from(ip) & mask) == subnet_network;

        if ip_in_subnet {
            debug!(
                iface = %iface,
                ip = %ip,
                subnet = %subnet_cidr,
                "Interface matches subnet"
            );
            return Some((iface, ip));
        }
    }

    None
}

/// Compute the network address from an IP and prefix length.
/// e.g. "10.7.1.37" with prefix 24 → "10.7.1.0"
fn network_address(ip: &str, prefix_len: u8) -> String {
    let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();

    if octets.len() != 4 || prefix_len > 32 {
        return ip.to_string();
    }

    let ip_u32 = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    let net = ip_u32 & mask;
    let bytes = net.to_be_bytes();

    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Check whether a given IP is in a CIDR subnet.
/// Used in unit tests to verify the subnet-matching logic.
#[cfg(test)]
fn ip_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let (net_str, prefix_str) = match cidr.split_once('/') {
        Some(p) => p,
        None => return false,
    };
    let prefix_len: u8 = match prefix_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let subnet_ip: Ipv4Addr = match net_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    (u32::from(ip) & mask) == (u32::from(subnet_ip) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_cidr_basic() {
        let ip: Ipv4Addr = "10.2.0.1".parse().unwrap();
        assert!(ip_in_cidr(ip, "10.2.0.0/24"));
        assert!(!ip_in_cidr(ip, "10.1.21.0/24"));
    }

    #[test]
    fn test_ip_in_cidr_host_on_different_subnet() {
        let ip: Ipv4Addr = "10.1.21.28".parse().unwrap();
        assert!(ip_in_cidr(ip, "10.1.0.0/16"));
        assert!(!ip_in_cidr(ip, "10.2.0.0/24"));
    }

    #[test]
    fn test_ip_in_cidr_slash_32() {
        let ip: Ipv4Addr = "192.168.1.5".parse().unwrap();
        assert!(ip_in_cidr(ip, "192.168.1.5/32"));
        assert!(!ip_in_cidr(ip, "192.168.1.6/32"));
    }

    #[test]
    fn test_ip_in_cidr_slash_0() {
        // /0 matches everything
        let ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        assert!(ip_in_cidr(ip, "0.0.0.0/0"));
    }

    #[test]
    fn test_ip_in_cidr_invalid() {
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        assert!(!ip_in_cidr(ip, "notacidr"));
        assert!(!ip_in_cidr(ip, "10.0.0.0")); // No prefix
    }

    #[test]
    fn test_find_interface_for_subnet_no_match() {
        // Using a subnet that definitely does not exist on this host
        // (unicast-reserved documentation range)
        let result = find_interface_for_subnet("192.0.2.0/24");
        assert!(
            result.is_none(),
            "192.0.2.0/24 is documentation-only and should never match"
        );
    }

    #[test]
    fn test_enumerate_local_interfaces_returns_vec() {
        // Smoke test: the function should not panic and should return a Vec.
        // We cannot assert contents (differs by host), but we can verify the
        // loopback is excluded and all entries have valid IPs.
        let ifaces = enumerate_local_interfaces();
        for (name, ip, prefix) in &ifaces {
            assert!(!name.is_empty(), "Interface name should not be empty");
            assert_ne!(name, "lo", "Loopback should be excluded");
            // Prefix length must be 0–32
            assert!(*prefix <= 32, "Prefix length must be ≤ 32, got {}", prefix);
            // IP must be valid (already guaranteed by parse::<Ipv4Addr>())
            let _ = ip;
        }
    }
}
