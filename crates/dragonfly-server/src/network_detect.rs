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
