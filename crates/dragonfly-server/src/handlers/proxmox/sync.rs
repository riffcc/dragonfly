use proxmox_client::{Client as ProxmoxApiClient, HttpApiClient};
use serde_json::json;
use tracing::{debug, error, info, warn};

use super::client::connect_to_proxmox;
use super::settings::get_proxmox_settings_from_store;

/// Extract the first non-loopback IPv4 address from a QEMU agent network-get-interfaces response
fn extract_agent_ip(ip_val: &serde_json::Value) -> Option<String> {
    let result_array = ip_val
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())?;
    for iface_info in result_array {
        if let Some(ip_addrs) = iface_info.get("ip-addresses").and_then(|a| a.as_array()) {
            for addr_info in ip_addrs {
                if addr_info.get("ip-address-type").and_then(|t| t.as_str()) == Some("ipv4") {
                    if let Some(ip_str) = addr_info.get("ip-address").and_then(|i| i.as_str()) {
                        if !ip_str.starts_with("127.") {
                            return Some(ip_str.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Parse semicolon-separated Proxmox tags into a sorted Vec
fn parse_proxmox_tags(tags_str: Option<&str>) -> Vec<String> {
    let mut tags: Vec<String> = tags_str
        .map(|s| {
            s.split(';')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    tags.sort();
    tags
}

/// Merge two tag sets (union). Returns (merged, db_changed, api_changed).
fn merge_tags(db_tags: &[String], api_tags: &[String]) -> (Vec<String>, bool, bool) {
    let mut merged: Vec<String> = db_tags.to_vec();
    for tag in api_tags {
        if !merged.contains(tag) {
            merged.push(tag.clone());
        }
    }
    merged.sort();

    let mut sorted_db = db_tags.to_vec();
    sorted_db.sort();
    let mut sorted_api = api_tags.to_vec();
    sorted_api.sort();

    let db_changed = merged != sorted_db;
    let api_changed = merged != sorted_api;
    (merged, db_changed, api_changed)
}

/// Bidirectional Proxmox sync: status, IP, tags for VMs, LXCs, and physical hosts.
async fn sync_proxmox_machines(
    client: &ProxmoxApiClient,
    db_machines: &[&dragonfly_common::Machine],
    state: &crate::AppState,
) -> Result<(), anyhow::Error> {
    use dragonfly_common::{MachineSource, MachineState};

    info!("Starting Proxmox machine synchronization...");

    // ── Phase 1: Enumerate current Proxmox state ────────────────────────

    let nodes_response = client
        .get("/api2/json/nodes")
        .await
        .map_err(|e| anyhow::anyhow!("Sync: Failed to fetch nodes: {}", e))?;
    let nodes_value: serde_json::Value = serde_json::from_slice(&nodes_response.body)
        .map_err(|e| anyhow::anyhow!("Sync: Failed to parse nodes response: {}", e))?;
    let nodes_data = nodes_value
        .get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| anyhow::anyhow!("Sync: Invalid nodes response format"))?;

    let mut existing_node_names = std::collections::HashSet::new();
    // VM details: vmid → (node, status, agent_running, tags, uptime_secs)
    let mut vm_details: std::collections::HashMap<
        u32,
        (String, String, bool, Vec<String>, Option<u64>),
    > = std::collections::HashMap::new();
    // LXC details: ctid → (node, status, tags, uptime_secs)
    let mut lxc_details: std::collections::HashMap<
        u32,
        (String, String, Vec<String>, Option<u64>),
    > = std::collections::HashMap::new();
    // Node uptime: node_name → uptime_secs
    let mut node_uptimes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    // Node online status: node_name → is_online
    let mut node_online: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    // Track which nodes we successfully enumerated VMs/LXCs for.
    // Only prune machines from nodes where we got a confirmed successful API response.
    let mut nodes_with_successful_vm_enum: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut nodes_with_successful_lxc_enum: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for node in nodes_data {
        let node_name = node
            .get("node")
            .and_then(|n| n.as_str())
            .ok_or_else(|| anyhow::anyhow!("Sync: Node missing 'node' field"))?;
        existing_node_names.insert(node_name.to_string());
        let is_online = node.get("status").and_then(|s| s.as_str()).unwrap_or("online") == "online";
        node_online.insert(node_name.to_string(), is_online);
        if let Some(uptime) = node.get("uptime").and_then(|u| u.as_u64()) {
            node_uptimes.insert(node_name.to_string(), uptime);
        }

        // ── VMs (qemu) ──────────────────────────────────────────────────
        let vms_path = format!("/api2/json/nodes/{}/qemu", node_name);
        match client.get(&vms_path).await {
            Ok(vms_resp) => {
                if vms_resp.status != 200 {
                    warn!(
                        "Sync: Node '{}' VM endpoint returned HTTP {} — skipping",
                        node_name, vms_resp.status
                    );
                } else {
                    match serde_json::from_slice::<serde_json::Value>(&vms_resp.body) {
                        Ok(vms_val) => {
                            if let Some(vms_data) = vms_val.get("data").and_then(|d| d.as_array()) {
                                nodes_with_successful_vm_enum.insert(node_name.to_string());
                                for vm in vms_data {
                                    let Some(vmid) = vm
                                        .get("vmid")
                                        .and_then(|id| id.as_u64())
                                        .map(|id| id as u32)
                                    else {
                                        continue;
                                    };
                                    let status = vm
                                        .get("status")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    let uptime = vm.get("uptime").and_then(|u| u.as_u64());

                                    // Fetch VM config for agent check + tags
                                    let cfg_path = format!(
                                        "/api2/json/nodes/{}/qemu/{}/config",
                                        node_name, vmid
                                    );
                                    let (agent_enabled, api_tags) =
                                        match client.get(&cfg_path).await {
                                            Ok(cfg_resp) => {
                                                match serde_json::from_slice::<serde_json::Value>(
                                                    &cfg_resp.body,
                                                ) {
                                                    Ok(cfg_val) => {
                                                        let agent = cfg_val
                                                            .get("data")
                                                            .and_then(|d| d.get("agent"))
                                                            .and_then(|a| a.as_str())
                                                            .map(|s| {
                                                                s.contains("enabled=1")
                                                                    || s.contains("enabled=true")
                                                            })
                                                            .unwrap_or(false);
                                                        let tags = parse_proxmox_tags(
                                                            cfg_val
                                                                .get("data")
                                                                .and_then(|d| d.get("tags"))
                                                                .and_then(|t| t.as_str()),
                                                        );
                                                        (agent, tags)
                                                    }
                                                    Err(_) => (false, Vec::new()),
                                                }
                                            }
                                            Err(_) => (false, Vec::new()),
                                        };

                                    let mut agent_running = false;
                                    if status == "running" && agent_enabled {
                                        let ping_path = format!(
                                            "/api2/json/nodes/{}/qemu/{}/agent/ping",
                                            node_name, vmid
                                        );
                                        agent_running = client
                                            .get(&ping_path)
                                            .await
                                            .ok()
                                            .and_then(|r| {
                                                serde_json::from_slice::<serde_json::Value>(&r.body)
                                                    .ok()
                                            })
                                            .map(|v| {
                                                v.get("data").is_some()
                                                    && v.get("data")
                                                        .and_then(|d| d.get("error"))
                                                        .is_none()
                                            })
                                            .unwrap_or(false);
                                    }

                                    vm_details.insert(
                                        vmid,
                                        (
                                            node_name.to_string(),
                                            status,
                                            agent_running,
                                            api_tags,
                                            uptime,
                                        ),
                                    );
                                }
                            } else {
                                warn!(
                                    "Sync: Node '{}' VM response missing 'data' array — skipping VM sync for this node",
                                    node_name
                                );
                            }
                        }
                        Err(e) => warn!(
                            "Sync: Failed to parse VM response for node '{}': {} — skipping VM sync for this node",
                            node_name, e
                        ),
                    }
                } // status == 200
            }
            Err(e) => warn!(
                "Sync: Failed to fetch VMs for node '{}': {} — skipping VM sync for this node",
                node_name, e
            ),
        }

        // ── LXC containers ──────────────────────────────────────────────
        let lxc_path = format!("/api2/json/nodes/{}/lxc", node_name);
        match client.get(&lxc_path).await {
            Ok(lxc_resp) => {
                if lxc_resp.status != 200 {
                    warn!(
                        "Sync: Node '{}' LXC endpoint returned HTTP {} — skipping",
                        node_name, lxc_resp.status
                    );
                } else {
                    match serde_json::from_slice::<serde_json::Value>(&lxc_resp.body) {
                        Ok(lxc_val) => {
                            if let Some(lxc_data) = lxc_val.get("data").and_then(|d| d.as_array()) {
                                nodes_with_successful_lxc_enum.insert(node_name.to_string());
                                for ct in lxc_data {
                                    let Some(ctid) = ct
                                        .get("vmid")
                                        .and_then(|id| id.as_u64())
                                        .map(|id| id as u32)
                                    else {
                                        continue;
                                    };
                                    let status = ct
                                        .get("status")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    let uptime = ct.get("uptime").and_then(|u| u.as_u64());

                                    // Fetch LXC config for tags
                                    let cfg_path = format!(
                                        "/api2/json/nodes/{}/lxc/{}/config",
                                        node_name, ctid
                                    );
                                    let api_tags = match client.get(&cfg_path).await {
                                        Ok(cfg_resp) => {
                                            serde_json::from_slice::<serde_json::Value>(
                                                &cfg_resp.body,
                                            )
                                            .ok()
                                            .map(|v| {
                                                parse_proxmox_tags(
                                                    v.get("data")
                                                        .and_then(|d| d.get("tags"))
                                                        .and_then(|t| t.as_str()),
                                                )
                                            })
                                            .unwrap_or_default()
                                        }
                                        Err(_) => Vec::new(),
                                    };

                                    lxc_details.insert(
                                        ctid,
                                        (node_name.to_string(), status, api_tags, uptime),
                                    );
                                }
                            } else {
                                warn!(
                                    "Sync: Node '{}' LXC response missing 'data' array — skipping LXC sync for this node",
                                    node_name
                                );
                            }
                        }
                        Err(e) => warn!(
                            "Sync: Failed to parse LXC response for node '{}': {} — skipping LXC sync for this node",
                            node_name, e
                        ),
                    }
                } // status == 200
            }
            Err(e) => warn!(
                "Sync: Failed to fetch LXCs for node '{}': {} — skipping LXC sync for this node",
                node_name, e
            ),
        }
    }

    info!(
        "Sync: Found {} nodes, {} VMs (from {}/{} nodes), {} LXCs (from {}/{} nodes)",
        existing_node_names.len(),
        vm_details.len(),
        nodes_with_successful_vm_enum.len(),
        existing_node_names.len(),
        lxc_details.len(),
        nodes_with_successful_lxc_enum.len(),
        existing_node_names.len()
    );

    // ── Phase 2: Compare with DB machines ───────────────────────────────

    let mut updated_count = 0u32;
    let mut tag_sync_count = 0u32;
    let mut pruned_count = 0u32;
    let mut machines_to_prune: Vec<uuid::Uuid> = Vec::new();

    for db_machine in db_machines {
        match &db_machine.metadata.source {
            // ── Physical hosts ───────────────────────────────────────
            MachineSource::ProxmoxNode { node, .. } => {
                // The /nodes endpoint succeeded (we parsed nodes_data above),
                // so if a node isn't listed, it's genuinely removed from the cluster.
                if !existing_node_names.contains(node) {
                    info!(
                        "Sync: Proxmox host '{}' (ID: {}) removed from cluster, deleting",
                        node, db_machine.id
                    );
                    machines_to_prune.push(db_machine.id);
                } else {
                    let mut machine = match state.store.get_machine(db_machine.id).await {
                        Ok(Some(m)) => m,
                        _ => continue,
                    };
                    let mut changed = false;
                    let is_online = node_online.get(node).copied().unwrap_or(true);

                    // Update online/offline state
                    if !is_online && !matches!(machine.status.state, MachineState::Offline) {
                        info!("Sync: Node '{}' is OFFLINE (out of quorum)", node);
                        machine.status.state = MachineState::Offline;
                        changed = true;
                    } else if is_online && matches!(machine.status.state, MachineState::Offline) {
                        info!("Sync: Node '{}' is back ONLINE", node);
                        machine.status.state = MachineState::ExistingOs {
                            os_name: "Proxmox VE".to_string(),
                        };
                        changed = true;
                    }

                    // Sync uptime for online hosts
                    if let Some(&uptime) = node_uptimes.get(node) {
                        if machine.status.uptime_seconds != Some(uptime) {
                            machine.status.uptime_seconds = Some(uptime);
                            changed = true;
                        }
                    }

                    if changed {
                        machine.status.last_seen = Some(chrono::Utc::now());
                        machine.metadata.updated_at = chrono::Utc::now();
                        if let Err(e) = state.store.put_machine(&machine).await {
                            error!("Sync: Failed to save node '{}': {}", node, e);
                        } else {
                            updated_count += 1;
                        }
                    }
                }
            }

            // ── QEMU VMs ────────────────────────────────────────────
            MachineSource::Proxmox { node, vmid, .. } => {
                if let Some((api_node, api_status, agent_running, api_tags, api_uptime)) =
                    vm_details.get(vmid)
                {
                    let mut machine = match state.store.get_machine(db_machine.id).await {
                        Ok(Some(m)) => m,
                        _ => continue,
                    };
                    let mut changed = false;

                    // Status sync
                    let new_state = match api_status.as_str() {
                        "running" => MachineState::Installed,
                        "stopped" => MachineState::Offline,
                        _ => MachineState::ExistingOs {
                            os_name: "Proxmox VM".to_string(),
                        },
                    };
                    if machine.status.state != new_state {
                        info!(
                            "Sync: VM {} status {:?} → {:?}",
                            vmid, machine.status.state, new_state
                        );
                        machine.status.state = new_state;
                        changed = true;
                    }

                    // Uptime sync
                    if machine.status.uptime_seconds != *api_uptime {
                        machine.status.uptime_seconds = *api_uptime;
                        changed = true;
                    }

                    // IP sync via QEMU agent
                    if *agent_running {
                        let ip_path = format!(
                            "/api2/json/nodes/{}/qemu/{}/agent/network-get-interfaces",
                            api_node, vmid
                        );
                        if let Ok(ip_resp) = client.get(&ip_path).await {
                            if let Ok(ip_val) =
                                serde_json::from_slice::<serde_json::Value>(&ip_resp.body)
                            {
                                if let Some(ip) = extract_agent_ip(&ip_val) {
                                    if machine.status.current_ip.as_deref() != Some(&ip) {
                                        info!("Sync: VM {} IP → {}", vmid, ip);
                                        machine.status.current_ip = Some(ip);
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }

                    // Bidirectional tag sync
                    let (merged, db_changed, api_changed) =
                        merge_tags(&machine.config.tags, api_tags);
                    if db_changed {
                        machine.config.tags = merged.clone();
                        changed = true;
                        tag_sync_count += 1;
                    }
                    if api_changed {
                        let tags_str = merged.join(";");
                        let path = format!("/api2/json/nodes/{}/qemu/{}/config", api_node, vmid);
                        if let Err(e) = client
                            .put(&path, &serde_json::json!({ "tags": tags_str }))
                            .await
                        {
                            warn!("Sync: Failed to push tags to Proxmox VM {}: {}", vmid, e);
                        } else {
                            tag_sync_count += 1;
                        }
                    }

                    if changed {
                        machine.metadata.updated_at = chrono::Utc::now();
                        if let Err(e) = state.store.put_machine(&machine).await {
                            error!("Sync: Failed to save VM {}: {}", vmid, e);
                        } else {
                            updated_count += 1;

                            if machine.status.current_ip.is_some() {
                                if let Err(e) = crate::dns_sync::sync_machine_dns(
                                    &state.store,
                                    &machine,
                                    dragonfly_common::dns::DnsRecordSource::ProxmoxSync,
                                )
                                .await
                                {
                                    warn!("Sync: DNS sync failed for VM {}: {}", vmid, e);
                                }
                            }
                        }
                    }
                } else if nodes_with_successful_vm_enum.contains(node) {
                    // We successfully enumerated VMs on this node and this VM wasn't there → deleted
                    info!(
                        "Sync: VM {} on node '{}' (ID: {}) deleted in Proxmox, removing",
                        vmid, node, db_machine.id
                    );
                    machines_to_prune.push(db_machine.id);
                } else {
                    // We couldn't enumerate VMs on this node — don't assume anything
                    debug!(
                        "Sync: VM {} on node '{}' — node VM enumeration failed, skipping",
                        vmid, node
                    );
                }
            }

            // ── LXC containers ──────────────────────────────────────
            MachineSource::ProxmoxLxc { node, ctid, .. } => {
                if let Some((api_node, api_status, api_tags, api_uptime)) = lxc_details.get(ctid) {
                    let mut machine = match state.store.get_machine(db_machine.id).await {
                        Ok(Some(m)) => m,
                        _ => continue,
                    };
                    let mut changed = false;

                    // Status sync
                    let new_state = match api_status.as_str() {
                        "running" => MachineState::Installed,
                        "stopped" => MachineState::Offline,
                        _ => MachineState::ExistingOs {
                            os_name: "Proxmox LXC".to_string(),
                        },
                    };
                    if machine.status.state != new_state {
                        info!(
                            "Sync: LXC {} status {:?} → {:?}",
                            ctid, machine.status.state, new_state
                        );
                        machine.status.state = new_state;
                        changed = true;
                    }

                    // Uptime sync
                    if machine.status.uptime_seconds != *api_uptime {
                        machine.status.uptime_seconds = *api_uptime;
                        changed = true;
                    }

                    // Bidirectional tag sync
                    let (merged, db_changed, api_changed) =
                        merge_tags(&machine.config.tags, api_tags);
                    if db_changed {
                        machine.config.tags = merged.clone();
                        changed = true;
                        tag_sync_count += 1;
                    }
                    if api_changed {
                        let tags_str = merged.join(";");
                        let path = format!("/api2/json/nodes/{}/lxc/{}/config", api_node, ctid);
                        if let Err(e) = client
                            .put(&path, &serde_json::json!({ "tags": tags_str }))
                            .await
                        {
                            warn!("Sync: Failed to push tags to Proxmox LXC {}: {}", ctid, e);
                        } else {
                            tag_sync_count += 1;
                        }
                    }

                    if changed {
                        machine.metadata.updated_at = chrono::Utc::now();
                        if let Err(e) = state.store.put_machine(&machine).await {
                            error!("Sync: Failed to save LXC {}: {}", ctid, e);
                        } else {
                            updated_count += 1;
                        }
                    }
                } else if nodes_with_successful_lxc_enum.contains(node) {
                    // We successfully enumerated LXCs on this node and this CT wasn't there → deleted
                    info!(
                        "Sync: LXC {} on node '{}' (ID: {}) deleted in Proxmox, removing",
                        ctid, node, db_machine.id
                    );
                    machines_to_prune.push(db_machine.id);
                } else {
                    debug!(
                        "Sync: LXC {} on node '{}' — node LXC enumeration failed, skipping",
                        ctid, node
                    );
                }
            }

            _ => {} // Not a Proxmox machine
        }
    }

    // ── Phase 3: Delete machines confirmed gone from Proxmox ─────────────
    // Safety invariant: NEVER prune to 0 through sync alone. If the API shows 0
    // VMs/LXCs on a node but the DB has machines there, the last deletions must
    // come through the live event stream. This protects against permission issues
    // where the token can't see VMs (200 OK with empty data:[]).
    if !machines_to_prune.is_empty() {
        // Count how many DB machines of each type exist per node
        let mut db_vm_per_node: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut db_lxc_per_node: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for m in db_machines {
            match &m.metadata.source {
                MachineSource::Proxmox { node, .. } => {
                    *db_vm_per_node.entry(node.clone()).or_default() += 1
                }
                MachineSource::ProxmoxLxc { node, .. } => {
                    *db_lxc_per_node.entry(node.clone()).or_default() += 1
                }
                _ => {}
            }
        }

        // Count how many would be pruned per node per type
        let mut prune_vm_per_node: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut prune_lxc_per_node: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for m in db_machines {
            if !machines_to_prune.contains(&m.id) {
                continue;
            }
            match &m.metadata.source {
                MachineSource::Proxmox { node, .. } => {
                    *prune_vm_per_node.entry(node.clone()).or_default() += 1
                }
                MachineSource::ProxmoxLxc { node, .. } => {
                    *prune_lxc_per_node.entry(node.clone()).or_default() += 1
                }
                _ => {}
            }
        }

        // Build blocked nodes — where pruning would go to 0
        let mut blocked_nodes_vm: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut blocked_nodes_lxc: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (node, prune_count) in &prune_vm_per_node {
            if let Some(&db_count) = db_vm_per_node.get(node) {
                if *prune_count >= db_count {
                    warn!(
                        "Sync: Refusing to prune all {} VMs on node '{}' — last deletions must come through event stream",
                        db_count, node
                    );
                    blocked_nodes_vm.insert(node.clone());
                }
            }
        }
        for (node, prune_count) in &prune_lxc_per_node {
            if let Some(&db_count) = db_lxc_per_node.get(node) {
                if *prune_count >= db_count {
                    warn!(
                        "Sync: Refusing to prune all {} LXCs on node '{}' — last deletions must come through event stream",
                        db_count, node
                    );
                    blocked_nodes_lxc.insert(node.clone());
                }
            }
        }

        // Filter out blocked prunes
        let safe_prunes: Vec<uuid::Uuid> = machines_to_prune
            .iter()
            .filter(|id| {
                let m = db_machines.iter().find(|m| m.id == **id);
                match m.map(|m| &m.metadata.source) {
                    Some(MachineSource::Proxmox { node, .. }) => !blocked_nodes_vm.contains(node),
                    Some(MachineSource::ProxmoxLxc { node, .. }) => {
                        !blocked_nodes_lxc.contains(node)
                    }
                    _ => true, // nodes are pruned by cluster membership, different rule
                }
            })
            .copied()
            .collect();

        if !safe_prunes.is_empty() {
            info!(
                "Sync: Deleting {} machines confirmed removed from Proxmox",
                safe_prunes.len()
            );
            for machine_id in &safe_prunes {
                match state.store.delete_machine(*machine_id).await {
                    Ok(true) => {
                        info!("Sync: Deleted machine {}", machine_id);
                        pruned_count += 1;
                    }
                    Ok(false) => warn!("Sync: Machine {} already deleted", machine_id),
                    Err(e) => error!("Sync: Failed to delete machine {}: {}", machine_id, e),
                }
            }
        }
    }

    info!(
        "Proxmox sync finished. Updated: {}, Tags synced: {}, Pruned: {}",
        updated_count, tag_sync_count, pruned_count
    );

    Ok(())
}

/// Starts the background Proxmox sync task.
pub async fn start_proxmox_sync_task(
    state: std::sync::Arc<crate::AppState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
) {
    use std::time::Duration;

    let state_clone = state.clone();

    tokio::spawn(async move {
        let poll_interval = Duration::from_secs(90); // Check every 90 seconds
        info!(
            "Starting Proxmox sync task with interval of {:?}",
            poll_interval
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {
                    info!("Running Proxmox machine sync check");

                    // Check if Proxmox is configured either in memory or database
                    let proxmox_configured = {
                        let settings = state_clone.settings.lock().await;
                        let in_memory_configured = settings.proxmox_host.is_some()
                            && settings.proxmox_username.is_some();

                        let tokens = state_clone.tokens.lock().await;
                        let has_sync_token = tokens.contains_key("proxmox_vm_sync_token");

                        drop(tokens);
                        drop(settings);

                        in_memory_configured || has_sync_token
                    };

                    if !proxmox_configured {
                        match get_proxmox_settings_from_store(state_clone.store.as_ref()).await {
                            Ok(Some(settings)) => {
                                if settings.vm_sync_token.is_none() {
                                    info!("Proxmox configured but sync token not available, skipping sync check");
                                    continue;
                                }
                            },
                            _ => {
                                info!("Proxmox not configured, skipping sync check");
                                continue;
                            }
                        }
                    }

                    // Get all machines from v1 Store and filter for Proxmox machines
                    use dragonfly_common::MachineSource;
                    let machines = match state_clone.store.list_machines().await {
                        Ok(m) => m,
                        Err(e) => {
                            error!("Failed to get machines for Proxmox sync: {}", e);
                            continue;
                        }
                    };

                    let proxmox_machines: Vec<&dragonfly_common::Machine> = machines.iter()
                        .filter(|m| matches!(m.metadata.source,
                            MachineSource::Proxmox { .. } |
                            MachineSource::ProxmoxLxc { .. } |
                            MachineSource::ProxmoxNode { .. }
                        ))
                        .collect();

                    if proxmox_machines.is_empty() {
                        info!("No Proxmox machines found, skipping sync check");
                        continue;
                    }

                    // Connect to Proxmox — try "sync" token first (has VM.Audit for visibility),
                    // fall back to "config" token (may lack VM.Audit)
                    let client = match connect_to_proxmox(&state_clone, "sync").await {
                        Ok(c) => c,
                        Err(_) => match connect_to_proxmox(&state_clone, "config").await {
                            Ok(c) => c,
                            Err(e) => {
                                error!("Failed to connect to Proxmox for sync check: {}", e);
                                continue;
                            }
                        }
                    };
                    if let Err(e) = sync_proxmox_machines(&client, &proxmox_machines, &state_clone).await {
                        error!("Error during Proxmox sync check: {}", e);
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("Shutdown signal received, stopping Proxmox sync task");
                    break;
                }
            }
        }
    });
}

/// Push local tags to Proxmox for a VM or LXC.
pub async fn sync_tags_to_proxmox(state: &crate::AppState, machine: &dragonfly_common::machine::Machine) {
    use dragonfly_common::MachineSource;

    let (api_type, node, id) = match &machine.metadata.source {
        MachineSource::Proxmox { node, vmid, .. } => ("qemu", node.clone(), *vmid),
        MachineSource::ProxmoxLxc { node, ctid, .. } => ("lxc", node.clone(), *ctid),
        _ => return, // Not a Proxmox guest, nothing to sync
    };

    let tags_str = machine.config.tags.join(";");
    let path = format!("/api2/json/nodes/{}/{}/{}/config", node, api_type, id);

    match connect_to_proxmox(state, "config").await {
        Ok(client) => {
            let body = json!({ "tags": tags_str });
            match client.put(&path, &body).await {
                Ok(resp) => {
                    if resp.status >= 200 && resp.status < 300 {
                        info!(
                            "Synced tags to Proxmox {} {}: {:?}",
                            api_type, id, machine.config.tags
                        );
                    } else {
                        warn!(
                            "Proxmox returned {} when syncing tags for {} {}",
                            resp.status, api_type, id
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to sync tags to Proxmox for {} {}: {}",
                        api_type, id, e
                    );
                }
            }
        }
        Err(e) => {
            warn!("Could not connect to Proxmox to sync tags: {}", e);
        }
    }
}
