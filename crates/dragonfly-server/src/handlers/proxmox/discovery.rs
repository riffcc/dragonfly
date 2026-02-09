use axum::{Json, http::StatusCode, response::IntoResponse};
use proxmox_client::{Client as ProxmoxApiClient, HttpApiClient};
use std::net::Ipv4Addr;
use tracing::{debug, error, info, warn};

use crate::AppState;
use crate::store::conversions::machine_from_register_request;
use dragonfly_common::models::{ErrorResponse, RegisterRequest};

use super::client::connect_to_proxmox;
use super::errors::{ProxmoxHandlerError, ProxmoxResult};
use super::types::DiscoveredProxmox;

/// Associative identity lookup: find an existing machine that matches ANY identity
/// anchor from the new machine.
pub(super) fn find_existing_machine<'a>(
    existing_machines: &'a [dragonfly_common::Machine],
    new_machine: &dragonfly_common::Machine,
) -> Option<&'a dragonfly_common::Machine> {
    use dragonfly_common::MachineSource;

    // Priority 1: Match by Proxmox source tuple (strongest anchor)
    match &new_machine.metadata.source {
        MachineSource::Proxmox {
            cluster,
            node,
            vmid,
        } => {
            if let Some(m) = existing_machines.iter().find(|m| {
                matches!(&m.metadata.source, MachineSource::Proxmox { cluster: c, node: n, vmid: v }
                    if c == cluster && n == node && v == vmid)
            }) {
                return Some(m);
            }
        }
        MachineSource::ProxmoxLxc {
            cluster,
            node,
            ctid,
        } => {
            if let Some(m) = existing_machines.iter().find(|m| {
                matches!(&m.metadata.source, MachineSource::ProxmoxLxc { cluster: c, node: n, ctid: ct }
                    if c == cluster && n == node && ct == ctid)
            }) {
                return Some(m);
            }
        }
        MachineSource::ProxmoxNode { cluster, node } => {
            if let Some(m) = existing_machines.iter().find(|m| {
                matches!(&m.metadata.source, MachineSource::ProxmoxNode { cluster: c, node: n }
                    if c == cluster && n == node)
            }) {
                return Some(m);
            }
        }
        _ => {}
    }

    // Priority 2: Match by ANY MAC address
    for new_mac in &new_machine.identity.all_macs {
        if new_mac.is_empty() || new_mac == "unknown" {
            continue;
        }
        for existing in existing_machines.iter() {
            if existing.identity.all_macs.iter().any(|m| m == new_mac) {
                return Some(existing);
            }
        }
    }

    None
}

/// Merge a newly-discovered machine into an existing one using LWW CRDT semantics.
///
/// Mutates `new_machine` to be the merged result, keeping `existing.id` and
/// applying `Machine::merge_lww` so that user-configured fields, identity
/// fields (smbios_uuid, machine_id, fs_uuid), netboot config, labels, etc.
/// are never erased by a discovery source that doesn't carry them.
pub(super) fn merge_into_existing(
    existing: &dragonfly_common::Machine,
    new_machine: &mut dragonfly_common::Machine,
) {
    // Start from the existing machine, merge incoming data on top
    let mut merged = existing.clone();
    merged.merge_lww(new_machine);

    // Replace new_machine with the merged result
    *new_machine = merged;
}

/// Helper function to extract MAC address from Proxmox network configuration.
fn extract_mac_from_net_config(net_config: &str) -> Option<String> {
    for part in net_config.split(',') {
        if part.contains('=') {
            let mut parts = part.splitn(2, '=');
            _ = parts.next();
            if let Some(mac) = parts.next() {
                if mac.len() == 17 && mac.bytes().filter(|&b| b == b':').count() == 5 {
                    return Some(mac.to_lowercase());
                }
            }
        }
    }

    None
}

/// Helper to find the first valid, non-loopback, non-link-local IPv4 address in a single interface.
fn find_valid_ipv4_in_interface(iface: &serde_json::Value, vmid: u32) -> Option<String> {
    let interface_name = iface
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");
    if let Some(ip_addresses) = iface.get("ip-addresses").and_then(|ips| ips.as_array()) {
        info!(
            "Checking {} IP addresses on interface '{}' for VM {}",
            ip_addresses.len(),
            interface_name,
            vmid
        );

        for ip_obj in ip_addresses {
            info!(
                "IP address entry for VM {} on interface {}: {}",
                vmid,
                interface_name,
                serde_json::to_string_pretty(&ip_obj)
                    .unwrap_or_else(|_| "Failed to format".to_string())
            );

            let ip_type = ip_obj.get("ip-address-type").and_then(|t| t.as_str());
            let ip = ip_obj.get("ip-address").and_then(|a| a.as_str());

            info!("Found IP address type: {:?}, address: {:?}", ip_type, ip);

            if let (Some("ipv4"), Some(addr)) = (ip_type, ip) {
                if addr.starts_with("169.254.") {
                    info!("Skipping link-local address {} for VM {}", addr, vmid);
                    continue;
                }

                if addr.starts_with("127.") {
                    info!("Skipping loopback address {} for VM {}", addr, vmid);
                    continue;
                }

                return Some(addr.to_string());
            }
        }
    }
    None
}

fn calculate_network_address(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    Ipv4Addr::from(ip_u32 & mask)
}

fn generate_ip_in_subnet(network_addr: Ipv4Addr, host_num: u32) -> Ipv4Addr {
    let network_u32 = u32::from(network_addr);
    Ipv4Addr::from(network_u32 + host_num)
}

/// Run Proxmox discovery and return the connect response.
pub async fn connect_proxmox_discover(
    state: &crate::AppState,
    host: &str,
    import_guests: bool,
    tokens_reused: bool,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut import_result = None;
    info!(
        "Starting Proxmox discovery (import_guests={}, tokens_reused={})...",
        import_guests, tokens_reused
    );
    match connect_to_proxmox(state, "sync").await {
        Ok(client) => {
            let cluster_name = host.to_string();
            match discover_and_register_proxmox_vms(&client, &cluster_name, state, import_guests)
                .await
            {
                Ok((nodes, guests, failed, _)) => {
                    info!(
                        "Proxmox discovery complete: {} nodes, {} guests, {} failed",
                        nodes, guests, failed
                    );
                    import_result = Some(serde_json::json!({
                        "imported_nodes": nodes,
                        "imported_guests": guests,
                        "failed": failed,
                    }));
                }
                Err(e) => {
                    warn!("Proxmox discovery failed: {:?}", e);
                    import_result = Some(serde_json::json!({
                        "error": format!("Discovery failed: {:?}", e),
                    }));
                }
            }
        }
        Err(e) => {
            warn!("Could not connect for Proxmox discovery: {}", e);
            import_result = Some(serde_json::json!({
                "error": format!("Could not connect for discovery: {}", e),
            }));
        }
    }

    let message = if tokens_reused {
        "Reconnected to Proxmox using existing API tokens"
    } else {
        "Successfully connected to Proxmox and created API tokens"
    };

    let mut response = serde_json::json!({
        "success": true,
        "message": message,
        "tokens_created": !tokens_reused,
        "tokens_reused": tokens_reused,
        "tokens_saved": true
    });
    if let Some(ir) = import_result {
        response
            .as_object_mut()
            .unwrap()
            .insert("import_result".to_string(), ir);
    }
    (StatusCode::OK, Json(response))
}

/// Discover and register all Proxmox VMs, LXCs, and host nodes.
pub(super) async fn discover_and_register_proxmox_vms(
    client: &ProxmoxApiClient,
    cluster_name: &str,
    state: &AppState,
    import_guests: bool,
) -> ProxmoxResult<(usize, usize, usize, Vec<DiscoveredProxmox>)> {
    info!(
        "Discovering Proxmox cluster '{}' (import_guests={})",
        cluster_name, import_guests
    );

    let nodes_response = client.get("/api2/json/nodes").await.map_err(|e| {
        error!("Failed to fetch nodes list: {}", e);
        ProxmoxHandlerError::ApiError(e)
    })?;

    let nodes_value: serde_json::Value =
        serde_json::from_slice(&nodes_response.body).map_err(|e| {
            error!("Failed to parse nodes response: {}", e);
            ProxmoxHandlerError::InternalError(anyhow::anyhow!("Failed to parse nodes JSON: {}", e))
        })?;

    let nodes_data = nodes_value
        .get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| {
            error!("Invalid nodes response format");
            ProxmoxHandlerError::InternalError(anyhow::anyhow!("Invalid nodes response format"))
        })?;

    info!("Found {} nodes in Proxmox cluster", nodes_data.len());

    let existing_machines = state.store.list_machines().await.unwrap_or_default();
    info!(
        "Loaded {} existing machines for dedup",
        existing_machines.len()
    );

    // Query /cluster/status for real corosync cluster name, node IPs, and online status
    let mut node_ip_map = std::collections::HashMap::<String, String>::new();
    let mut node_online_map = std::collections::HashMap::<String, bool>::new();
    let mut real_cluster_name: Option<String> = None;
    if let Ok(cluster_status_resp) = client.get("/api2/json/cluster/status").await {
        if let Ok(cluster_val) =
            serde_json::from_slice::<serde_json::Value>(&cluster_status_resp.body)
        {
            if let Some(entries) = cluster_val.get("data").and_then(|d| d.as_array()) {
                for entry in entries {
                    match entry.get("type").and_then(|t| t.as_str()) {
                        Some("cluster") => {
                            if let Some(name) = entry.get("name").and_then(|n| n.as_str()) {
                                info!("Discovered Proxmox cluster name: '{}'", name);
                                real_cluster_name = Some(name.to_string());
                            }
                        }
                        Some("node") => {
                            if let (Some(name), Some(ip)) = (
                                entry.get("name").and_then(|n| n.as_str()),
                                entry.get("ip").and_then(|i| i.as_str()),
                            ) {
                                let online = entry.get("online").and_then(|o| o.as_u64()).unwrap_or(0) == 1;
                                info!("Cluster status: node '{}' has IP {}, online={}", name, ip, online);
                                node_ip_map.insert(name.to_string(), ip.to_string());
                                node_online_map.insert(name.to_string(), online);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    // Use the real corosync cluster name if discovered, otherwise fall back to host
    let cluster_name = real_cluster_name.as_deref().unwrap_or(cluster_name);

    let mut registered_nodes = 0;
    let mut registered_guests = 0;
    let mut failed_registrations = 0;
    let mut discovered_machines = Vec::new();

    for node in nodes_data {
        let node_name = node.get("node").and_then(|n| n.as_str()).ok_or_else(|| {
            error!("Node missing 'node' field");
            ProxmoxHandlerError::InternalError(anyhow::anyhow!("Node missing 'node' field"))
        })?;

        let host_ip = node_ip_map
            .get(node_name)
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        // Check if node is online — use cluster/status map first, fall back to nodes list
        let node_status_str = node.get("status").and_then(|s| s.as_str()).unwrap_or("online");
        let node_is_online = node_online_map.get(node_name).copied().unwrap_or(node_status_str == "online");

        if !node_is_online {
            info!("Node '{}' is OFFLINE (out of quorum), registering with Offline state", node_name);

            // Try to update an existing machine rather than creating a new one
            let existing_machines = state.store.list_machines().await.unwrap_or_default();
            if let Some(existing) = existing_machines.iter().find(|m| {
                matches!(m.metadata.source, dragonfly_common::machine::MachineSource::ProxmoxNode { .. })
                    && m.config.hostname.as_deref() == Some(node_name)
            }) {
                let mut updated = existing.clone();
                updated.status.state = dragonfly_common::MachineState::Offline;
                if let Err(e) = state.store.put_machine(&updated).await {
                    warn!("Failed to mark offline node '{}': {}", node_name, e);
                } else {
                    info!("Marked existing node '{}' as Offline", node_name);
                }
            } else {
                warn!("Offline node '{}' has no prior registration — skipping (no NICs available)", node_name);
            }
            continue;
        }

        let node_status_path = format!("/api2/json/nodes/{}/status", node_name);
        let mut host_hostname = node_name.to_string();
        let mut host_cpu_model = None;
        let mut host_cpu_cores = None;
        let mut host_cpu_threads = None;
        let mut host_ram_bytes = None;

        if let Ok(resp) = client.get(&node_status_path).await {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                if let Some(data) = val.get("data") {
                    let _ = data.get("pveversion");
                    if let Some(cpuinfo) = data.get("cpuinfo") {
                        host_cpu_model = cpuinfo
                            .get("model")
                            .and_then(|m| m.as_str())
                            .map(String::from);
                        host_cpu_cores = cpuinfo
                            .get("cores")
                            .and_then(|c| c.as_u64())
                            .map(|c| c as u32);
                        host_cpu_threads = cpuinfo
                            .get("cpus")
                            .and_then(|c| c.as_u64())
                            .map(|c| c as u32);
                    }
                    if let Some(meminfo) = data.get("memory") {
                        host_ram_bytes = meminfo.get("total").and_then(|t| t.as_u64());
                    }
                }
            }
        }

        let node_net_path = format!("/api2/json/nodes/{}/network", node_name);
        let mut physical_nics: Vec<dragonfly_common::NetworkInterface> = Vec::new();
        let mut node_iface_methods: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        if let Ok(resp) = client.get(&node_net_path).await {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                if let Some(ifaces) = val.get("data").and_then(|d| d.as_array()) {
                    let all_names: Vec<&str> = ifaces
                        .iter()
                        .filter_map(|i| i.get("iface").and_then(|n| n.as_str()))
                        .collect();
                    info!(
                        "Node '{}': Proxmox API returned {} interfaces: {:?}",
                        node_name,
                        ifaces.len(),
                        all_names
                    );

                    for iface in ifaces {
                        let name = iface.get("iface").and_then(|n| n.as_str()).unwrap_or("");
                        let itype = iface.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        let active = iface.get("active").and_then(|a| a.as_u64()).unwrap_or(0) == 1;

                        let hwaddr_direct =
                            iface.get("hwaddr").and_then(|h| h.as_str()).unwrap_or("");
                        let hwaddr = if hwaddr_direct.len() == 17 && hwaddr_direct.contains(':') {
                            hwaddr_direct.to_string()
                        } else {
                            iface
                                .get("altnames")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| {
                                    arr.iter().find_map(|a| {
                                        let s = a.as_str()?;
                                        if s.starts_with("enx") && s.len() == 15 {
                                            let hex = &s[3..];
                                            Some(format!(
                                                "{}:{}:{}:{}:{}:{}",
                                                &hex[0..2],
                                                &hex[2..4],
                                                &hex[4..6],
                                                &hex[6..8],
                                                &hex[8..10],
                                                &hex[10..12]
                                            ))
                                        } else {
                                            None
                                        }
                                    })
                                })
                                .unwrap_or_default()
                        };

                        let is_virtual = name.starts_with("tap")
                            || name.starts_with("veth")
                            || name.starts_with("fwbr")
                            || name.starts_with("fwpr")
                            || name.starts_with("fwln")
                            || name.starts_with("docker")
                            || name.starts_with("br-")
                            || name.starts_with("virbr")
                            || name == "lo";
                        if is_virtual {
                            continue;
                        }

                        if hwaddr.is_empty() && itype == "eth" {
                            debug!(
                                "Node '{}': skipping eth '{}' — no MAC from hwaddr or altnames",
                                node_name, name
                            );
                            continue;
                        }

                        let members: Vec<String> = iface
                            .get("bridge_ports")
                            .or_else(|| iface.get("slaves"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.split_whitespace().map(String::from).collect())
                            .unwrap_or_default();
                        let ip_address = iface
                            .get("cidr")
                            .and_then(|v| v.as_str())
                            .or_else(|| iface.get("address").and_then(|v| v.as_str()))
                            .map(String::from);
                        let bond_mode = iface
                            .get("bond_mode")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        let mtu = iface.get("mtu").and_then(|v| {
                            v.as_str()
                                .and_then(|s| s.parse().ok())
                                .or_else(|| v.as_u64().map(|n| n as u32))
                        });

                        if let Some(method) = iface.get("method").and_then(|m| m.as_str()) {
                            node_iface_methods.insert(name.to_string(), method.to_string());
                        }

                        info!(
                            "Node '{}': found NIC {} (type={}, hwaddr={}, active={}, ip={:?}, members={:?})",
                            node_name, name, itype, hwaddr, active, ip_address, members
                        );

                        physical_nics.push(dragonfly_common::NetworkInterface {
                            name: name.to_string(),
                            mac: hwaddr.to_lowercase(),
                            speed_mbps: None,
                            interface_type: match itype {
                                "eth" => dragonfly_common::InterfaceType::Ether,
                                "bond" => dragonfly_common::InterfaceType::Bond,
                                "bridge" => dragonfly_common::InterfaceType::Bridge,
                                _ => dragonfly_common::InterfaceType::Unknown,
                            },
                            members,
                            ip_address,
                            active: Some(active),
                            bond_mode,
                            mtu,
                        });
                    }
                }
            }
        } else {
            warn!(
                "Node '{}': failed to fetch /nodes/{}/network — no NICs collected",
                node_name, node_name
            );
        }

        let collected_names: Vec<&str> = physical_nics.iter().map(|n| n.name.as_str()).collect();
        info!(
            "Node '{}': collected {} NICs after filtering: {:?}",
            node_name,
            physical_nics.len(),
            collected_names
        );

        // GPUs
        let mut host_gpus: Vec<dragonfly_common::GpuInfo> = Vec::new();
        let pci_path = format!("/api2/json/nodes/{}/hardware/pci", node_name);
        if let Ok(pci_resp) = client.get(&pci_path).await {
            if let Ok(pci_val) = serde_json::from_slice::<serde_json::Value>(&pci_resp.body) {
                if let Some(pci_devices) = pci_val.get("data").and_then(|d| d.as_array()) {
                    for dev in pci_devices {
                        let class = dev.get("class").and_then(|c| c.as_str()).unwrap_or("");
                        if class.starts_with("0x03") {
                            let name = dev
                                .get("device_name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("Unknown GPU")
                                .to_string();
                            let vendor = dev
                                .get("vendor_name")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            info!(
                                "Node '{}': found GPU: {} ({})",
                                node_name,
                                name,
                                vendor.as_deref().unwrap_or("unknown")
                            );
                            host_gpus.push(dragonfly_common::GpuInfo {
                                name,
                                vendor,
                                vram_bytes: None,
                            });
                        }
                    }
                }
            }
        }

        // Disks
        let mut host_disks: Vec<dragonfly_common::Disk> = Vec::new();
        let disks_path = format!("/api2/json/nodes/{}/disks/list", node_name);
        if let Ok(disks_resp) = client.get(&disks_path).await {
            if let Ok(disks_val) = serde_json::from_slice::<serde_json::Value>(&disks_resp.body) {
                if let Some(disks_data) = disks_val.get("data").and_then(|d| d.as_array()) {
                    for disk in disks_data {
                        let devpath = disk
                            .get("devpath")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_string();
                        let size = disk.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                        let model = disk.get("model").and_then(|m| m.as_str()).map(String::from);
                        let serial = disk
                            .get("serial")
                            .and_then(|s| s.as_str())
                            .map(String::from);
                        let disk_type = disk.get("type").and_then(|t| t.as_str()).map(String::from);
                        let wearout = disk
                            .get("wearout")
                            .and_then(|w| w.as_u64())
                            .map(|w| w as u32);
                        let health = disk
                            .get("health")
                            .and_then(|h| h.as_str())
                            .map(String::from);
                        if !devpath.is_empty() && size > 0 {
                            info!(
                                "Node '{}': found disk {} ({}, {:.0}GB, wear={}%, health={})",
                                node_name,
                                devpath,
                                disk_type.as_deref().unwrap_or("?"),
                                size as f64 / 1e9,
                                wearout.map(|w| w.to_string()).unwrap_or("N/A".to_string()),
                                health.as_deref().unwrap_or("?")
                            );
                            host_disks.push(dragonfly_common::Disk {
                                device: devpath,
                                size_bytes: size,
                                model,
                                serial,
                                disk_type,
                                wearout,
                                health,
                            });
                        }
                    }
                }
            }
        }

        if physical_nics.is_empty() {
            warn!(
                "No physical NICs found for node '{}', skipping registration",
                node_name
            );
        } else {
            info!(
                "Node '{}': {} physical NICs, IP={}, CPU={:?}, RAM={:?}",
                node_name,
                physical_nics.len(),
                host_ip,
                host_cpu_model,
                host_ram_bytes
            );

            let all_macs: Vec<String> = physical_nics
                .iter()
                .map(|n| n.mac.clone())
                .filter(|m| !m.is_empty() && m.contains(':'))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            if all_macs.is_empty() {
                warn!(
                    "Node '{}': found {} interfaces but none have a valid MAC, skipping registration",
                    node_name,
                    physical_nics.len()
                );
                continue;
            }
            let primary_mac = all_macs[0].clone();
            let identity = dragonfly_common::MachineIdentity::new(
                primary_mac.clone(),
                all_macs,
                None,
                None,
                None,
            );

            let now = chrono::Utc::now();
            let mut machine = dragonfly_common::Machine {
                id: dragonfly_common::new_machine_id(),
                identity,
                status: dragonfly_common::MachineStatus {
                    state: dragonfly_common::MachineState::ExistingOs {
                        os_name: "Proxmox VE".to_string(),
                    },
                    last_seen: Some(now),
                    current_ip: Some(host_ip.clone()),
                    current_workflow: None,
                    last_workflow_result: None,
                    uptime_seconds: None,
                },
                hardware: dragonfly_common::HardwareInfo {
                    cpu_model: host_cpu_model,
                    cpu_cores: host_cpu_cores,
                    cpu_threads: host_cpu_threads,
                    memory_bytes: host_ram_bytes,
                    disks: host_disks,
                    gpus: host_gpus,
                    network_interfaces: physical_nics,
                    is_virtual: false,
                    virt_platform: None,
                },
                config: {
                    let mut cfg = dragonfly_common::MachineConfig::with_mac(&primary_mac);
                    cfg.hostname = Some(host_hostname.clone());

                    if let Some(method) = node_iface_methods
                        .get("vmbr0")
                        .or_else(|| node_iface_methods.values().find(|m| *m == "static"))
                    {
                        match method.as_str() {
                            "static" => {
                                if node_iface_methods.values().any(|m| m == "static") {
                                    cfg.network_mode = dragonfly_common::NetworkMode::StaticIpv4;
                                }
                            }
                            _ => {}
                        }
                    }

                    let dns_path = format!("/api2/json/nodes/{}/dns", node_name);
                    if let Ok(dns_resp) = client.get(&dns_path).await {
                        if let Ok(dns_val) =
                            serde_json::from_slice::<serde_json::Value>(&dns_resp.body)
                        {
                            if let Some(data) = dns_val.get("data") {
                                let mut nameservers = Vec::new();
                                for key in &["dns1", "dns2", "dns3"] {
                                    if let Some(ns) = data.get(key).and_then(|v| v.as_str()) {
                                        if !ns.is_empty() {
                                            nameservers.push(ns.to_string());
                                        }
                                    }
                                }
                                if !nameservers.is_empty() {
                                    info!(
                                        "Node '{}': DNS nameservers: {:?}",
                                        node_name, nameservers
                                    );
                                    cfg.nameservers = nameservers;
                                }
                                if let Some(search) = data.get("search").and_then(|v| v.as_str()) {
                                    if !search.is_empty() {
                                        cfg.domain = Some(search.to_string());
                                    }
                                }
                            }
                        }
                    }

                    cfg
                },
                metadata: dragonfly_common::MachineMetadata {
                    created_at: now,
                    updated_at: now,
                    labels: std::collections::HashMap::new(),
                    source: dragonfly_common::MachineSource::ProxmoxNode {
                        cluster: cluster_name.to_string(),
                        node: node_name.to_string(),
                    },
                },
            };

            if let Some(existing) = find_existing_machine(&existing_machines, &machine) {
                info!(
                    "Found existing machine {} for node '{}', updating",
                    existing.id, node_name
                );
                merge_into_existing(existing, &mut machine);
            }

            let machine_id = machine.id;
            match state.store.put_machine(&machine).await {
                Ok(()) => {
                    info!(
                        "Registered Proxmox host node '{}' as machine {} ({} NICs)",
                        node_name,
                        machine_id,
                        machine.hardware.network_interfaces.len()
                    );
                    registered_nodes += 1;

                    if let Err(e) = crate::dns_sync::sync_machine_dns(
                        &state.store,
                        &machine,
                        dragonfly_common::dns::DnsRecordSource::ProxmoxSync,
                    )
                    .await
                    {
                        warn!("DNS sync failed for node '{}': {}", node_name, e);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to register Proxmox host node '{}': {}",
                        node_name, e
                    );
                    failed_registrations += 1;
                }
            }
        }

        // --- Fetch and Register VMs for this node (only if import_guests) ---
        if !import_guests {
            info!("Skipping VM/LXC import for node '{}' (import_guests=false)", node_name);
            continue;
        }
        info!("Processing VMs for node: {}", node_name);

        let vms_path = format!("/api2/json/nodes/{}/qemu", node_name);
        let vms_response = match client.get(&vms_path).await {
            Ok(response) => response,
            Err(e) => {
                error!("Failed to fetch VMs for node {}: {}", node_name, e);
                continue;
            }
        };

        let vms_value: serde_json::Value = match serde_json::from_slice(&vms_response.body) {
            Ok(value) => value,
            Err(e) => {
                error!("Failed to parse VMs response for node {}: {}", node_name, e);
                continue;
            }
        };

        let vms_data = match vms_value.get("data").and_then(|d| d.as_array()) {
            Some(data) => data,
            None => {
                error!("Invalid VMs response format for node {}", node_name);
                continue;
            }
        };

        info!("Found {} VMs on node {}", vms_data.len(), node_name);

        for vm in vms_data {
            let vmid = match vm
                .get("vmid")
                .and_then(|id| id.as_u64())
                .map(|id| id as u32)
            {
                Some(id) => id,
                None => {
                    error!("VM missing vmid");
                    continue;
                }
            };

            let name = vm.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");

            let status = vm
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");

            info!("OS name: {}", name);
            let mut vm_os = "Unknown OS".to_string();
            if name.to_lowercase().contains("ubuntu") {
                vm_os = "Ubuntu 22.04".to_string();
            } else if name.to_lowercase().contains("debian") {
                vm_os = "Debian 12".to_string();
            } else if name.to_lowercase().contains("centos") {
                vm_os = "CentOS 7".to_string();
            } else if name.to_lowercase().contains("windows") {
                vm_os = "Windows Server".to_string();
            }

            let vm_details_path = format!(
                "/api2/json/nodes/{}/qemu/{}/status/current",
                node_name, vmid
            );
            let mut vm_mem_bytes = 0;
            let mut vm_cpu_cores = 0;

            if let Ok(vm_details_response) = client.get(&vm_details_path).await {
                if let Ok(vm_details_value) =
                    serde_json::from_slice::<serde_json::Value>(&vm_details_response.body)
                {
                    if let Some(vm_details_data) = vm_details_value.get("data") {
                        if let Some(mem) = vm_details_data.get("maxmem").and_then(|m| m.as_u64()) {
                            vm_mem_bytes = mem;
                        }
                        if let Some(cpu) = vm_details_data.get("cpus").and_then(|c| c.as_u64()) {
                            vm_cpu_cores = cpu as u32;
                        }
                    }
                }
            }

            let vm_config_path = format!("/api2/json/nodes/{}/qemu/{}/config", node_name, vmid);
            let vm_config_response = match client.get(&vm_config_path).await {
                Ok(response) => response,
                Err(e) => {
                    error!("Failed to fetch VM config for VM {}: {}", vmid, e);
                    continue;
                }
            };

            let vm_config: serde_json::Value =
                match serde_json::from_slice(&vm_config_response.body) {
                    Ok(value) => value,
                    Err(e) => {
                        error!("Failed to parse VM config response for VM {}: {}", vmid, e);
                        continue;
                    }
                };

            let mut mac_addresses = Vec::new();
            let config_data = match vm_config.get("data") {
                Some(data) => data,
                None => {
                    error!("Invalid VM config response format for VM {}", vmid);
                    continue;
                }
            };

            let mut agent_enabled = false;
            if let Some(agent) = config_data.get("agent").and_then(|a| a.as_str()) {
                agent_enabled = agent.contains("enabled=1") || agent.contains("enabled=true");
                info!(
                    "QEMU Guest Agent status for VM {}: {}",
                    vmid,
                    if agent_enabled { "Enabled" } else { "Disabled" }
                );
            }

            if let Some(os_type) = config_data.get("ostype").and_then(|o| o.as_str()) {
                match os_type {
                    "l26" => vm_os = "Unknown".to_string(),
                    "win10" | "win11" => vm_os = "windows-10".to_string(),
                    "win8" | "win7" => vm_os = "windows-7".to_string(),
                    "other" => {}
                    _ => vm_os = "unknown".to_string(),
                }
                info!("VM {} has OS type {} (from Proxmox config)", vmid, vm_os);
            }

            for i in 0..8 {
                let net_key = format!("net{}", i);
                if let Some(net_config) = config_data.get(&net_key).and_then(|n| n.as_str()) {
                    if let Some(mac) = extract_mac_from_net_config(net_config) {
                        mac_addresses.push(mac);
                    }
                }
            }

            if mac_addresses.is_empty() {
                error!("No MAC addresses found for VM {}", vmid);
                continue;
            }

            let mac_address = mac_addresses[0].clone().to_lowercase();

            let mut ip_address = "Unknown".to_string();

            if agent_enabled {
                let agent_ping_path =
                    format!("/api2/json/nodes/{}/qemu/{}/agent/ping", node_name, vmid);
                let agent_running = match client.get(&agent_ping_path).await {
                    Ok(ping_response) => {
                        if let Ok(ping_value) =
                            serde_json::from_slice::<serde_json::Value>(&ping_response.body)
                        {
                            ping_value.get("data").is_some()
                                && !ping_value
                                    .get("data")
                                    .and_then(|d| d.get("error"))
                                    .is_some()
                        } else {
                            false
                        }
                    }
                    Err(_) => false,
                };

                if agent_running {
                    info!(
                        "QEMU Guest Agent is running for VM {}, attempting to retrieve network interfaces",
                        vmid
                    );

                    // Get OS information
                    let agent_os_path = format!(
                        "/api2/json/nodes/{}/qemu/{}/agent/get-osinfo",
                        node_name, vmid
                    );
                    let os_detected = match client.get(&agent_os_path).await {
                        Ok(os_response) => {
                            match serde_json::from_slice::<serde_json::Value>(&os_response.body) {
                                Ok(os_value) => {
                                    info!(
                                        "OS info response for VM {}: {}",
                                        vmid,
                                        serde_json::to_string_pretty(&os_value)
                                            .unwrap_or_else(|_| "Failed to format".to_string())
                                    );

                                    if let Some(result) =
                                        os_value.get("data").and_then(|d| d.get("result"))
                                    {
                                        info!(
                                            "Raw OS info for VM {}: {}",
                                            vmid,
                                            serde_json::to_string(result).unwrap_or_default()
                                        );

                                        let os_name = result
                                            .get("id")
                                            .and_then(|id| id.as_str())
                                            .unwrap_or("Unknown");
                                        let os_version = result
                                            .get("version")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        let os_pretty_name =
                                            result.get("pretty-name").and_then(|pn| pn.as_str());

                                        let detected_os = if let Some(pretty) = os_pretty_name {
                                            pretty.to_string()
                                        } else if !os_version.is_empty() {
                                            format!("{} {}", os_name, os_version)
                                        } else {
                                            os_name.to_string()
                                        };

                                        let os_name_lower = os_name.to_lowercase();

                                        vm_os = if os_name_lower.contains("ubuntu")
                                            || detected_os.to_lowercase().contains("ubuntu")
                                        {
                                            if os_version.contains(".") {
                                                let version_parts: Vec<&str> =
                                                    os_version.split('.').collect();
                                                if version_parts.len() >= 2 {
                                                    format!(
                                                        "ubuntu-{}{}",
                                                        version_parts[0], version_parts[1]
                                                    )
                                                } else {
                                                    format!(
                                                        "ubuntu-{}",
                                                        os_version.replace(".", "")
                                                    )
                                                }
                                            } else if detected_os.contains("22.04") {
                                                "ubuntu-2204".to_string()
                                            } else if detected_os.contains("24.04") {
                                                "ubuntu-2404".to_string()
                                            } else {
                                                "ubuntu".to_string()
                                            }
                                        } else if os_name_lower.contains("debian")
                                            || detected_os.to_lowercase().contains("debian")
                                        {
                                            if detected_os.contains("12")
                                                || detected_os.contains("bookworm")
                                            {
                                                "debian-12".to_string()
                                            } else if let Some(version) = os_version
                                                .split(' ')
                                                .next()
                                                .and_then(|v| v.parse::<u32>().ok())
                                            {
                                                format!("debian-{}", version)
                                            } else {
                                                "debian".to_string()
                                            }
                                        } else {
                                            detected_os.clone()
                                        };

                                        info!(
                                            "Guest Agent detected OS for VM {}: {} (standardized as: {})",
                                            vmid, detected_os, vm_os
                                        );
                                        true
                                    } else {
                                        info!(
                                            "No OS information in Guest Agent response for VM {}",
                                            vmid
                                        );
                                        false
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to parse Guest Agent OS info response for VM {}: {}",
                                        vmid, e
                                    );
                                    false
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to get OS info from Guest Agent for VM {}: {}",
                                vmid, e
                            );
                            false
                        }
                    };

                    if !os_detected {
                        info!("Using fallback OS detection for VM {}: {}", vmid, vm_os);
                    }

                    // Get network interfaces
                    let agent_path = format!(
                        "/api2/json/nodes/{}/qemu/{}/agent/network-get-interfaces",
                        node_name, vmid
                    );

                    match client.get(&agent_path).await {
                        Ok(agent_response) => {
                            match serde_json::from_slice::<serde_json::Value>(&agent_response.body)
                            {
                                Ok(agent_value) => {
                                    info!(
                                        "Full Guest Agent response for VM {}: {}",
                                        vmid,
                                        serde_json::to_string_pretty(&agent_value)
                                            .unwrap_or_else(|_| "Failed to format".to_string())
                                    );

                                    if let Some(result) =
                                        agent_value.get("data").and_then(|d| d.get("result"))
                                    {
                                        if let Some(interfaces) = result.as_array() {
                                            info!(
                                                "Found {} network interfaces for VM {}",
                                                interfaces.len(),
                                                vmid
                                            );

                                            let mut preferred_ip: Option<String> = None;
                                            let mut fallback_ip: Option<String> = None;

                                            for iface in interfaces {
                                                if let Some(iface_name) =
                                                    iface.get("name").and_then(|n| n.as_str())
                                                {
                                                    if iface_name.starts_with("lo") {
                                                        continue;
                                                    }

                                                    let is_preferred = iface_name.starts_with("eth")
                                                        || iface_name.starts_with("ens")
                                                        || iface_name.starts_with("eno");
                                                    if !is_preferred {
                                                        continue;
                                                    }

                                                    info!(
                                                        "Processing preferred interface '{}' for VM {}",
                                                        iface_name, vmid
                                                    );

                                                    if let Some(ip_addr) =
                                                        find_valid_ipv4_in_interface(iface, vmid)
                                                    {
                                                        preferred_ip = Some(ip_addr);
                                                        break;
                                                    }
                                                }
                                            }

                                            if preferred_ip.is_none() {
                                                info!(
                                                    "No IP found on preferred interfaces for VM {}. Checking others.",
                                                    vmid
                                                );
                                                for iface in interfaces {
                                                    if let Some(iface_name) =
                                                        iface.get("name").and_then(|n| n.as_str())
                                                    {
                                                        if iface_name.starts_with("lo")
                                                            || iface_name.starts_with("eth")
                                                            || iface_name.starts_with("ens")
                                                            || iface_name.starts_with("eno")
                                                        {
                                                            continue;
                                                        }
                                                        if iface_name.starts_with("tailscale")
                                                            || iface_name.starts_with("docker")
                                                            || iface_name.starts_with("veth")
                                                            || iface_name.starts_with("virbr")
                                                            || iface_name.starts_with("br-")
                                                        {
                                                            continue;
                                                        }

                                                        info!(
                                                            "Processing fallback interface '{}' for VM {}",
                                                            iface_name, vmid
                                                        );

                                                        if let Some(ip_addr) =
                                                            find_valid_ipv4_in_interface(
                                                                iface, vmid,
                                                            )
                                                        {
                                                            fallback_ip = Some(ip_addr);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }

                                            if let Some(preferred) = preferred_ip {
                                                ip_address = preferred;
                                                info!(
                                                    "Selected preferred IPv4 address {} for VM {} via Guest Agent",
                                                    ip_address, vmid
                                                );
                                            } else if let Some(fallback) = fallback_ip {
                                                ip_address = fallback;
                                                info!(
                                                    "Selected fallback IPv4 address {} for VM {} via Guest Agent",
                                                    ip_address, vmid
                                                );
                                            } else {
                                                info!(
                                                    "No suitable IPv4 address found for VM {} via Guest Agent",
                                                    vmid
                                                );
                                            }
                                        } else {
                                            info!(
                                                "No network interfaces array found in Guest Agent response for VM {}",
                                                vmid
                                            );
                                        }
                                    } else {
                                        info!(
                                            "No 'result' field in Guest Agent response for VM {}",
                                            vmid
                                        );
                                    }
                                }
                                Err(e) => warn!(
                                    "Failed to parse Guest Agent response for VM {}: {}",
                                    vmid, e
                                ),
                            }
                        }
                        Err(e) => warn!(
                            "Failed to get network interfaces from QEMU Guest Agent for VM {}: {}",
                            vmid, e
                        ),
                    }
                }
            } else {
                info!(
                    "QEMU Guest Agent not enabled for VM {}. IP will be set to Unknown.",
                    vmid
                );
            }

            discovered_machines.push(DiscoveredProxmox {
                host: format!("{}-{}", node_name, vmid),
                port: 0,
                hostname: Some(name.to_string()),
                mac_address: Some(mac_address.clone()),
                machine_type: "proxmox-vm".to_string(),
                vmid: Some(vmid),
                parent_host: Some(node_name.to_string()),
            });

            info!(
                "Processing VM {} (ID: {}, Status: {}, OS: {}, IP: {})",
                name, vmid, status, vm_os, ip_address
            );

            let register_request = RegisterRequest {
                mac_address,
                ip_address,
                hostname: Some(name.to_string()),
                disks: Vec::new(),
                nameservers: Vec::new(),
                cpu_model: Some("Proxmox Virtual CPU".to_string()),
                cpu_cores: Some(vm_cpu_cores),
                total_ram_bytes: Some(vm_mem_bytes),
                proxmox_vmid: Some(vmid),
                proxmox_node: Some(node_name.to_string()),
                proxmox_cluster: Some(cluster_name.to_string()),
                proxmox_type: Some("vm".to_string()),
            };

            let mut machine = machine_from_register_request(&register_request);

            if let Some(tags_str) = config_data.get("tags").and_then(|t| t.as_str()) {
                machine.config.tags = tags_str
                    .split(';')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                if !machine.config.tags.is_empty() {
                    info!(
                        "Imported {} tags for VM {}: {:?}",
                        machine.config.tags.len(),
                        vmid,
                        machine.config.tags
                    );
                }
            }

            use dragonfly_common::MachineState;
            machine.status.state = match status {
                "running" => MachineState::ExistingOs {
                    os_name: "Unknown".to_string(),
                },
                "stopped" => MachineState::Offline,
                _ => MachineState::ExistingOs {
                    os_name: "Unknown".to_string(),
                },
            };

            if let Some(existing) = find_existing_machine(&existing_machines, &machine) {
                info!(
                    "Found existing machine {} for VM {} ({}), updating",
                    existing.id, vmid, name
                );
                merge_into_existing(existing, &mut machine);
            }

            let machine_id = machine.id;
            match state.store.put_machine(&machine).await {
                Ok(()) => {
                    info!(
                        "Successfully registered Proxmox VM {} as machine {}",
                        vmid, machine_id
                    );
                    registered_guests += 1;

                    if let Err(e) = crate::dns_sync::sync_machine_dns(
                        &state.store,
                        &machine,
                        dragonfly_common::dns::DnsRecordSource::ProxmoxSync,
                    )
                    .await
                    {
                        warn!("DNS sync failed for VM {}: {}", vmid, e);
                    }
                }
                Err(e) => {
                    error!("Failed to register Proxmox VM {}: {}", vmid, e);
                    failed_registrations += 1;
                }
            }
        }

        // --- LXC containers ---
        info!("Processing LXC containers for node: {}", node_name);

        let lxc_path = format!("/api2/json/nodes/{}/lxc", node_name);
        let lxc_response = match client.get(&lxc_path).await {
            Ok(response) => Some(response),
            Err(e) => {
                warn!(
                    "Failed to fetch LXC containers for node {}: {}",
                    node_name, e
                );
                None
            }
        };

        if let Some(lxc_resp) = lxc_response {
            let lxc_value: serde_json::Value = match serde_json::from_slice(&lxc_resp.body) {
                Ok(value) => value,
                Err(e) => {
                    warn!("Failed to parse LXC response for node {}: {}", node_name, e);
                    serde_json::Value::Null
                }
            };

            if let Some(lxc_data) = lxc_value.get("data").and_then(|d| d.as_array()) {
                info!(
                    "Found {} LXC containers on node {}",
                    lxc_data.len(),
                    node_name
                );

                for ct in lxc_data {
                    let ctid = match ct
                        .get("vmid")
                        .and_then(|id| id.as_u64())
                        .map(|id| id as u32)
                    {
                        Some(id) => id,
                        None => {
                            continue;
                        }
                    };

                    let ct_name = ct.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                    let ct_status = ct
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");

                    let ct_config_path =
                        format!("/api2/json/nodes/{}/lxc/{}/config", node_name, ctid);
                    let ct_config = match client.get(&ct_config_path).await {
                        Ok(resp) => serde_json::from_slice::<serde_json::Value>(&resp.body).ok(),
                        Err(e) => {
                            warn!("Failed to fetch LXC {} config: {}", ctid, e);
                            None
                        }
                    };

                    let mut ct_mac = None;
                    let mut ct_mem_bytes: u64 = 0;
                    let mut ct_cpu_cores: u32 = 0;

                    if let Some(config_val) = &ct_config {
                        if let Some(config_data) = config_val.get("data") {
                            for i in 0..8 {
                                let net_key = format!("net{}", i);
                                if let Some(net_cfg) =
                                    config_data.get(&net_key).and_then(|n| n.as_str())
                                {
                                    for part in net_cfg.split(',') {
                                        if let Some(mac) = part.strip_prefix("hwaddr=") {
                                            if mac.len() == 17 && mac.contains(':') {
                                                ct_mac = Some(mac.to_lowercase());
                                                break;
                                            }
                                        }
                                    }
                                    if ct_mac.is_some() {
                                        break;
                                    }
                                }
                            }

                            if let Some(mem_mb) = config_data.get("memory").and_then(|m| m.as_u64())
                            {
                                ct_mem_bytes = mem_mb * 1024 * 1024;
                            }

                            if let Some(cores) = config_data.get("cores").and_then(|c| c.as_u64()) {
                                ct_cpu_cores = cores as u32;
                            }
                        }
                    }

                    let mac_address = match ct_mac {
                        Some(mac) => mac,
                        None => {
                            warn!("No MAC found for LXC container {}, skipping", ctid);
                            continue;
                        }
                    };

                    let mut ct_ip = "Unknown".to_string();
                    if ct_status == "running" {
                        let ct_ifaces_path =
                            format!("/api2/json/nodes/{}/lxc/{}/interfaces", node_name, ctid);
                        if let Ok(ifaces_resp) = client.get(&ct_ifaces_path).await {
                            if let Ok(ifaces_val) =
                                serde_json::from_slice::<serde_json::Value>(&ifaces_resp.body)
                            {
                                if let Some(ifaces) =
                                    ifaces_val.get("data").and_then(|d| d.as_array())
                                {
                                    for iface in ifaces {
                                        let iface_name = iface
                                            .get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("");
                                        if iface_name == "lo" {
                                            continue;
                                        }
                                        if let Some(inet) =
                                            iface.get("inet").and_then(|i| i.as_str())
                                        {
                                            if let Some(ip) = inet.split('/').next() {
                                                if !ip.starts_with("127.") {
                                                    ct_ip = ip.to_string();
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    discovered_machines.push(DiscoveredProxmox {
                        host: format!("{}-lxc-{}", node_name, ctid),
                        port: 0,
                        hostname: Some(ct_name.to_string()),
                        mac_address: Some(mac_address.clone()),
                        machine_type: "proxmox-lxc".to_string(),
                        vmid: Some(ctid),
                        parent_host: Some(node_name.to_string()),
                    });

                    info!(
                        "Processing LXC container {} (ID: {}, Status: {}, IP: {})",
                        ct_name, ctid, ct_status, ct_ip
                    );

                    let register_request = RegisterRequest {
                        mac_address,
                        ip_address: ct_ip,
                        hostname: Some(ct_name.to_string()),
                        disks: Vec::new(),
                        nameservers: Vec::new(),
                        cpu_model: Some("Proxmox LXC Container".to_string()),
                        cpu_cores: Some(ct_cpu_cores),
                        total_ram_bytes: Some(ct_mem_bytes),
                        proxmox_vmid: Some(ctid),
                        proxmox_node: Some(node_name.to_string()),
                        proxmox_cluster: Some(cluster_name.to_string()),
                        proxmox_type: Some("lxc".to_string()),
                    };

                    let mut machine = machine_from_register_request(&register_request);

                    if let Some(config_val) = &ct_config {
                        if let Some(config_data) = config_val.get("data") {
                            if let Some(tags_str) = config_data.get("tags").and_then(|t| t.as_str())
                            {
                                machine.config.tags = tags_str
                                    .split(';')
                                    .map(|t| t.trim().to_string())
                                    .filter(|t| !t.is_empty())
                                    .collect();
                                if !machine.config.tags.is_empty() {
                                    info!(
                                        "Imported {} tags for LXC {}: {:?}",
                                        machine.config.tags.len(),
                                        ctid,
                                        machine.config.tags
                                    );
                                }
                            }
                        }
                    }

                    use dragonfly_common::MachineState;
                    machine.status.state = match ct_status {
                        "running" => MachineState::ExistingOs {
                            os_name: "Unknown".to_string(),
                        },
                        "stopped" => MachineState::Offline,
                        _ => MachineState::ExistingOs {
                            os_name: "Unknown".to_string(),
                        },
                    };

                    if let Some(existing) = find_existing_machine(&existing_machines, &machine) {
                        info!(
                            "Found existing machine {} for LXC {} ({}), updating",
                            existing.id, ctid, ct_name
                        );
                        merge_into_existing(existing, &mut machine);
                    }

                    let machine_id = machine.id;
                    match state.store.put_machine(&machine).await {
                        Ok(()) => {
                            info!(
                                "Successfully registered Proxmox LXC {} as machine {}",
                                ctid, machine_id
                            );
                            registered_guests += 1;

                            if let Err(e) = crate::dns_sync::sync_machine_dns(
                                &state.store,
                                &machine,
                                dragonfly_common::dns::DnsRecordSource::ProxmoxSync,
                            )
                            .await
                            {
                                warn!("DNS sync failed for LXC {}: {}", ctid, e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to register Proxmox LXC {}: {}", ctid, e);
                            failed_registrations += 1;
                        }
                    }
                }
            }
        }
    }

    info!(
        "Proxmox discovery complete: {} nodes, {} guests registered, {} failed",
        registered_nodes, registered_guests, failed_registrations
    );

    Ok((
        registered_nodes,
        registered_guests,
        failed_registrations,
        discovered_machines,
    ))
}

/// Network discovery handler — scans for Proxmox hosts on the local network.
pub async fn discover_proxmox_handler() -> impl IntoResponse {
    const PROXMOX_PORT: u16 = 8006;
    info!("Starting Proxmox discovery scan on port {}", PROXMOX_PORT);

    let scan_result = tokio::task::spawn_blocking(move || {
        let interfaces = netdev::get_interfaces();
        let mut all_addresses = Vec::new();
        let bad_prefixes = ["docker", "virbr", "veth", "cni", "flannel", "br-", "vnet"];
        let bad_names = [
            "cni0", "docker0", "podman0", "podman1", "virbr0", "k3s0", "k3s1",
        ];
        let preferred_prefixes = ["eth", "en", "wl", "bond", "br0"];

        for interface in interfaces {
            let if_name = &interface.name;
            if interface.is_loopback() {
                continue;
            }
            let has_bad_prefix = bad_prefixes
                .iter()
                .any(|prefix| if_name.starts_with(prefix));
            let is_bad_name = bad_names.iter().any(|name| if_name == name);
            if has_bad_prefix || is_bad_name {
                continue;
            }
            let is_preferred = preferred_prefixes
                .iter()
                .any(|prefix| if_name.starts_with(prefix));
            if !is_preferred && interface.ipv4.is_empty() {
                continue;
            }

            let mut scan_targets = Vec::new();
            for ip_config in &interface.ipv4 {
                let ip_addr = ip_config.addr;
                let prefix_len = ip_config.prefix_len;
                let host_count = if prefix_len >= 30 {
                    4u32
                } else if prefix_len >= 24 {
                    1u32 << (32 - prefix_len)
                } else {
                    256u32
                };
                let network_addr = calculate_network_address(ip_addr, prefix_len);
                for i in 1..(host_count - 1) {
                    let host_ip = generate_ip_in_subnet(network_addr, i);
                    let host = netscan::host::Host::new(host_ip.into(), String::new())
                        .with_ports(vec![PROXMOX_PORT]);
                    scan_targets.push(host);
                }
            }
            if scan_targets.is_empty() {
                continue;
            }

            let scan_setting = netscan::scan::setting::PortScanSetting::default()
                .set_if_index(interface.index)
                .set_scan_type(netscan::scan::setting::PortScanType::TcpConnectScan)
                .set_targets(scan_targets)
                .set_timeout(std::time::Duration::from_secs(5))
                .set_wait_time(std::time::Duration::from_millis(500));
            let scanner = netscan::scan::scanner::PortScanner::new(scan_setting);
            let scan_result = scanner.scan();
            for host in scan_result.hosts {
                if host
                    .get_open_ports()
                    .iter()
                    .any(|p| p.number == PROXMOX_PORT)
                {
                    all_addresses.push(std::net::SocketAddr::new(host.ip_addr, PROXMOX_PORT));
                }
            }
        }
        Ok::<Vec<std::net::SocketAddr>, String>(all_addresses)
    })
    .await;

    match scan_result {
        Ok(Ok(addresses)) => {
            info!("Proxmox scan found {} potential machines", addresses.len());
            let machines: Vec<DiscoveredProxmox> = addresses
                .into_iter()
                .map(|socket_addr| {
                    let ip = socket_addr.ip();
                    let host = ip.to_string();
                    let hostname =
                        match tokio::task::block_in_place(|| dns_lookup::lookup_addr(&ip).ok()) {
                            Some(name) if name != host => Some(name),
                            _ => None,
                        };
                    DiscoveredProxmox {
                        host,
                        port: PROXMOX_PORT,
                        hostname,
                        mac_address: None,
                        machine_type: "host".to_string(),
                        vmid: None,
                        parent_host: None,
                    }
                })
                .collect();
            info!(
                "Completed Proxmox discovery with {} machines",
                machines.len()
            );
            (
                StatusCode::OK,
                Json(super::types::ProxmoxDiscoverResponse { machines }),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            error!("Proxmox discovery scan failed: {}", e);
            let error_message = format!("Network scan failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Scan Error".to_string(),
                    message: error_message,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Proxmox discovery task failed: {}", e);
            let error_message = format!("Scanner task failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Task Error".to_string(),
                    message: error_message,
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_common::{Machine, MachineIdentity, MachineSource};

    fn make_vm(mac: &str, cluster: &str, node: &str, vmid: u32) -> Machine {
        let identity = MachineIdentity::from_mac(mac);
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::Proxmox {
            cluster: cluster.to_string(),
            node: node.to_string(),
            vmid,
        };
        m
    }

    fn make_lxc(mac: &str, cluster: &str, node: &str, ctid: u32) -> Machine {
        let identity = MachineIdentity::from_mac(mac);
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::ProxmoxLxc {
            cluster: cluster.to_string(),
            node: node.to_string(),
            ctid,
        };
        m
    }

    fn make_node(mac: &str, cluster: &str, node: &str) -> Machine {
        let identity = MachineIdentity::from_mac(mac);
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::ProxmoxNode {
            cluster: cluster.to_string(),
            node: node.to_string(),
        };
        m
    }

    fn make_multi_nic_node(macs: &[&str], cluster: &str, node: &str) -> Machine {
        let all_macs: Vec<String> = macs.iter().map(|m| m.to_string()).collect();
        let identity = MachineIdentity::new(all_macs[0].clone(), all_macs, None, None, None);
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::ProxmoxNode {
            cluster: cluster.to_string(),
            node: node.to_string(),
        };
        m
    }

    #[test]
    fn test_dedup_matches_node_by_any_nic_mac() {
        let existing = vec![make_multi_nic_node(
            &[
                "aa:bb:cc:00:00:01",
                "aa:bb:cc:00:00:02",
                "aa:bb:cc:00:00:03",
                "aa:bb:cc:00:00:04",
            ],
            "cluster1",
            "bee",
        )];

        let new = make_node("aa:bb:cc:00:00:03", "cluster1", "bee");
        let found = find_existing_machine(&existing, &new);
        assert!(
            found.is_some(),
            "Should match when ANY MAC in all_macs overlaps"
        );
    }

    #[test]
    fn test_dedup_matches_pxe_boot_agent_to_node_by_mac() {
        let existing = vec![make_multi_nic_node(
            &["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"],
            "cluster1",
            "bee",
        )];

        let identity = MachineIdentity::from_mac("aa:bb:cc:00:00:02");
        let agent_machine = Machine::new(identity);
        let found = find_existing_machine(&existing, &agent_machine);
        assert!(
            found.is_some(),
            "PXE boot on any NIC should find the existing node"
        );
    }

    #[test]
    fn test_dedup_matches_vm_by_source() {
        let existing = vec![make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, existing[0].id);
    }

    #[test]
    fn test_dedup_matches_vm_even_with_different_mac() {
        let existing = vec![make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("ff:ff:ff:ff:ff:ff", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        assert!(
            found.is_some(),
            "Should match by Proxmox source even when MAC differs"
        );
        assert_eq!(found.unwrap().id, existing[0].id);
    }

    #[test]
    fn test_dedup_no_match_different_vmid() {
        let existing = vec![make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("aa:bb:cc:dd:ee:02", "cluster1", "node1", 200);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_none(), "Different VMID = different machine");
    }

    #[test]
    fn test_dedup_matches_lxc_by_source() {
        let existing = vec![make_lxc("aa:bb:cc:dd:ee:01", "cluster1", "node1", 300)];
        let new = make_lxc("aa:bb:cc:dd:ee:01", "cluster1", "node1", 300);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some());
    }

    #[test]
    fn test_dedup_matches_node_by_source() {
        let existing = vec![make_node("aa:bb:cc:dd:ee:01", "cluster1", "bee")];
        let new = make_node("ff:ff:ff:ff:ff:ff", "cluster1", "bee");
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some(), "Should match node by cluster+node_name");
    }

    #[test]
    fn test_dedup_falls_back_to_mac() {
        let identity = MachineIdentity::from_mac("aa:bb:cc:dd:ee:01");
        let agent_machine = Machine::new(identity);
        let existing = vec![agent_machine];

        let new = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        assert!(
            found.is_some(),
            "Should fall back to MAC match when source doesn't match"
        );
    }

    #[test]
    fn test_dedup_vm_does_not_match_lxc_same_id() {
        let existing = vec![make_lxc("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("aa:bb:cc:dd:ee:02", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        assert!(
            found.is_none(),
            "VM and LXC with same numeric ID are different machines"
        );
    }

    #[test]
    fn test_merge_preserves_user_fields() {
        let mut existing = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        existing.config.memorable_name = "my-cool-server".to_string();
        existing.config.os_choice = Some("debian-12".to_string());
        existing.config.tags = vec!["production".to_string(), "web".to_string()];

        let mut new = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        new.config.tags = vec!["proxmox-imported".to_string()];
        new.hardware.cpu_cores = Some(8);

        merge_into_existing(&existing, &mut new);

        assert_eq!(new.id, existing.id, "UUID must be preserved");
        assert_eq!(
            new.config.memorable_name, "my-cool-server",
            "User-set name must be preserved"
        );
        assert_eq!(
            new.config.os_choice,
            Some("debian-12".to_string()),
            "User-set OS must be preserved"
        );
        assert!(
            new.config.tags.contains(&"production".to_string()),
            "Existing tags must be kept"
        );
        assert!(
            new.config.tags.contains(&"web".to_string()),
            "Existing tags must be kept"
        );
        assert!(
            new.config.tags.contains(&"proxmox-imported".to_string()),
            "New tags must be added"
        );
        assert_eq!(
            new.hardware.cpu_cores,
            Some(8),
            "Fresh hardware data must be used"
        );
    }

    #[test]
    fn test_merge_never_erases_identity_fields() {
        // Simulate: agent checked in with full identity, then Proxmox discovery
        // runs with only a MAC (no smbios_uuid, machine_id, fs_uuid)
        let mut existing = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        existing.identity.smbios_uuid = Some("abcd-1234-ef56-7890".to_string());
        existing.identity.machine_id = Some("deadbeef12345678".to_string());
        existing.identity.fs_uuid = Some("aaaa-bbbb-cccc-dddd".to_string());

        // Discovery builds a new machine with None for these fields
        let mut incoming = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        assert!(incoming.identity.smbios_uuid.is_none());
        assert!(incoming.identity.machine_id.is_none());
        assert!(incoming.identity.fs_uuid.is_none());

        merge_into_existing(&existing, &mut incoming);

        assert_eq!(incoming.id, existing.id);
        assert_eq!(
            incoming.identity.smbios_uuid,
            Some("abcd-1234-ef56-7890".to_string()),
            "smbios_uuid must survive discovery merge"
        );
        assert_eq!(
            incoming.identity.machine_id,
            Some("deadbeef12345678".to_string()),
            "machine_id must survive discovery merge"
        );
        assert_eq!(
            incoming.identity.fs_uuid,
            Some("aaaa-bbbb-cccc-dddd".to_string()),
            "fs_uuid must survive discovery merge"
        );
    }

    #[test]
    fn test_merge_never_erases_netboot_config() {
        use dragonfly_common::machine::{DhcpReservation, NetbootConfig};

        let mut existing = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        existing.config.netboot = NetbootConfig {
            allow_pxe: false,        // user disabled PXE
            allow_workflow: false,    // user disabled workflow
            dhcp_ip: Some(DhcpReservation {
                address: "10.0.0.42".to_string(),
                gateway: Some("10.0.0.1".to_string()),
                netmask: Some("255.255.255.0".to_string()),
            }),
        };

        // Proxmox discovery doesn't know about netboot
        let mut incoming = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        assert!(incoming.config.netboot.allow_pxe);
        assert!(incoming.config.netboot.dhcp_ip.is_none());

        merge_into_existing(&existing, &mut incoming);

        assert!(!incoming.config.netboot.allow_pxe, "PXE setting must survive");
        assert!(!incoming.config.netboot.allow_workflow, "Workflow setting must survive");
        assert_eq!(
            incoming.config.netboot.dhcp_ip.as_ref().unwrap().address,
            "10.0.0.42",
            "DHCP reservation must survive"
        );
    }

    #[test]
    fn test_merge_preserves_labels() {
        let mut existing = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        existing.metadata.labels.insert("role".to_string(), "database".to_string());
        existing.metadata.labels.insert("env".to_string(), "prod".to_string());

        let mut incoming = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        incoming.metadata.labels.insert("imported".to_string(), "true".to_string());

        merge_into_existing(&existing, &mut incoming);

        assert_eq!(incoming.metadata.labels.get("role").unwrap(), "database");
        assert_eq!(incoming.metadata.labels.get("env").unwrap(), "prod");
        assert_eq!(incoming.metadata.labels.get("imported").unwrap(), "true");
    }

    #[test]
    fn test_merge_unions_macs() {
        // Existing machine from agent has two MACs
        let identity = MachineIdentity::new(
            "aa:bb:cc:dd:ee:01".to_string(),
            vec!["aa:bb:cc:dd:ee:01".to_string(), "aa:bb:cc:dd:ee:02".to_string()],
            None, None, None,
        );
        let mut existing = Machine::new(identity);
        existing.metadata.source = MachineSource::Agent;

        // Proxmox sees it with a third MAC (e.g., bond member)
        let mut incoming = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        incoming.identity.all_macs.push("aa:bb:cc:dd:ee:03".to_string());

        merge_into_existing(&existing, &mut incoming);

        assert!(incoming.identity.all_macs.contains(&"aa:bb:cc:dd:ee:01".to_string()));
        assert!(incoming.identity.all_macs.contains(&"aa:bb:cc:dd:ee:02".to_string()));
        assert!(incoming.identity.all_macs.contains(&"aa:bb:cc:dd:ee:03".to_string()));
    }

    #[test]
    fn test_merge_upgrades_source_agent_to_proxmox() {
        let mut existing = Machine::new(MachineIdentity::from_mac("aa:bb:cc:dd:ee:01"));
        assert_eq!(existing.metadata.source, MachineSource::Agent);

        let mut incoming = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);

        merge_into_existing(&existing, &mut incoming);

        assert!(
            matches!(incoming.metadata.source, MachineSource::Proxmox { .. }),
            "Source should be upgraded from Agent to Proxmox"
        );
    }

    #[test]
    fn test_merge_does_not_downgrade_source() {
        let mut existing = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);

        let mut incoming = Machine::new(MachineIdentity::from_mac("aa:bb:cc:dd:ee:01"));
        // incoming has Agent source (e.g., from provisioning check-in)

        merge_into_existing(&existing, &mut incoming);

        assert!(
            matches!(incoming.metadata.source, MachineSource::Proxmox { .. }),
            "Source should NOT be downgraded from Proxmox to Agent"
        );
    }

    #[test]
    fn test_merge_ip_unknown_does_not_overwrite() {
        let mut existing = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        existing.status.current_ip = Some("10.0.0.50".to_string());

        let mut incoming = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        incoming.status.current_ip = Some("Unknown".to_string());

        merge_into_existing(&existing, &mut incoming);

        assert_eq!(
            incoming.status.current_ip,
            Some("10.0.0.50".to_string()),
            "'Unknown' IP must not overwrite a real IP"
        );
    }
}
