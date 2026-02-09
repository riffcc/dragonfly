//! Automatic HA Cluster Deployment via Proxmox LXC
//!
//! Orchestrates the creation of rqlite cluster nodes as LXC containers
//! across all Proxmox hosts, installs rqlite inside each, forms a Raft
//! cluster, and migrates the Dragonfly server from SQLite to distributed
//! rqlite storage.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use dragonfly_common::machine::{Machine, MachineIdentity, MachineSource, MachineState};
use proxmox_client::{HttpApiClient, Client as ProxmoxApiClient};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::sync::atomic::Ordering;
use tracing::{info, warn, error};

use crate::AppState;
use crate::event_manager::EventManager;
use crate::ha;
use crate::handlers::proxmox::connect_to_proxmox;
use crate::store::v1::{RqliteStore, SqliteStore};

/// Jetpack OutputHandler that emits SSE events for provisioning lifecycle.
///
/// This runs inside Jetpack's sync code (spawn_blocking), so it uses
/// the broadcast sender directly (which is sync-safe).
struct ClusterOutputHandler {
    event_manager: EventManager,
}

impl jetpack::OutputHandler for ClusterOutputHandler {
    fn on_playbook_start(&self, _path: &str) {}
    fn on_playbook_end(&self, _path: &str, _success: bool) {}
    fn on_play_start(&self, _name: &str, _hosts: Vec<String>) {}
    fn on_play_end(&self, _name: &str) {}
    fn on_task_start(&self, _name: &str, _host_count: usize) {}
    fn on_task_host_result(&self, _host: &jetpack::inventory::hosts::Host, _task: &jetpack::tasks::request::TaskRequest, _response: &jetpack::tasks::response::TaskResponse) {}
    fn on_task_end(&self, _name: &str) {}
    fn on_handler_start(&self, _name: &str) {}
    fn on_handler_end(&self, _name: &str) {}
    fn on_recap(&self, _data: jetpack::output::RecapData) {}
    fn log(&self, _level: jetpack::output::LogLevel, _message: &str) {}

    fn on_provision_created(&self, host: &str) {
        let payload = serde_json::json!({
            "type": "cluster_provision",
            "host": host,
            "event": "created",
        });
        let _ = self.event_manager.send(format!("cluster:{}", payload));
    }

    fn on_provision_exists(&self, host: &str) {
        let payload = serde_json::json!({
            "type": "cluster_provision",
            "host": host,
            "event": "exists",
        });
        let _ = self.event_manager.send(format!("cluster:{}", payload));
    }

    fn on_provision_ssh_wait(&self, host: &str, ip: &str, timeout_secs: u64) {
        let payload = serde_json::json!({
            "type": "cluster_provision",
            "host": host,
            "event": "ssh_wait",
            "ip": ip,
            "timeout": timeout_secs,
        });
        let _ = self.event_manager.send(format!("cluster:{}", payload));
    }

    fn on_provision_ssh_ready(&self, host: &str, elapsed_secs: u64, attempts: u32) {
        let payload = serde_json::json!({
            "type": "cluster_provision",
            "host": host,
            "event": "ssh_ready",
            "elapsed": elapsed_secs,
            "attempts": attempts,
        });
        let _ = self.event_manager.send(format!("cluster:{}", payload));
    }

    fn on_provision_destroyed(&self, host: &str) {
        let payload = serde_json::json!({
            "type": "cluster_provision",
            "host": host,
            "event": "destroyed",
        });
        let _ = self.event_manager.send(format!("cluster:{}", payload));
    }
}

// =============================================================================
// SSH Management Key — auto-generated keypair for cluster node authentication
// =============================================================================

const MANAGEMENT_KEY_DIR: &str = "/var/lib/dragonfly/cluster-deploy";
const MANAGEMENT_KEY_PATH: &str = "/var/lib/dragonfly/cluster-deploy/management_key";

/// Ensure an SSH management keypair exists. Generates one if missing.
/// Returns (public_key_openssh, private_key_path).
///
/// Public wrapper for API access (key rotation, status check).
pub async fn ensure_management_key_public(state: &AppState) -> Result<(String, String)> {
    ensure_management_key(state).await
}

async fn ensure_management_key(state: &AppState) -> Result<(String, String)> {
    // Check if we already have a stored public key
    let existing_pub = state.store.get_setting("cluster_management_pubkey").await
        .ok().flatten().unwrap_or_default();
    let existing_priv_enc = state.store.get_setting("cluster_management_privkey").await
        .ok().flatten().unwrap_or_default();

    if !existing_pub.is_empty() && !existing_priv_enc.is_empty() {
        // Decrypt and write private key to disk
        let privkey_pem = crate::encryption::decrypt_string(&existing_priv_enc)
            .context("Failed to decrypt management key")?;
        write_key_file(MANAGEMENT_KEY_DIR, MANAGEMENT_KEY_PATH, &privkey_pem)?;
        return Ok((existing_pub, MANAGEMENT_KEY_PATH.to_string()));
    }

    // Generate new ed25519 keypair
    info!("Generating SSH management keypair for cluster authentication");
    let private_key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::OsRng,
        ssh_key::Algorithm::Ed25519,
    ).context("Failed to generate ed25519 keypair")?;

    // Serialize to OpenSSH format
    let privkey_pem = private_key.to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to serialize private key")?
        .to_string();
    let pubkey_openssh = private_key.public_key().to_openssh()
        .context("Failed to serialize public key")?;

    // Add comment to public key
    let pubkey_line = format!("{} dragonfly-management", pubkey_openssh);

    // Encrypt and store
    let encrypted_priv = crate::encryption::encrypt_string(&privkey_pem)
        .context("Failed to encrypt management key")?;
    state.store.put_setting("cluster_management_pubkey", &pubkey_line).await
        .context("Failed to store management public key")?;
    state.store.put_setting("cluster_management_privkey", &encrypted_priv).await
        .context("Failed to store management private key")?;

    // Write private key to disk for Jetpack
    write_key_file(MANAGEMENT_KEY_DIR, MANAGEMENT_KEY_PATH, &privkey_pem)?;

    info!("SSH management key generated and stored (encrypted at rest)");
    Ok((pubkey_line, MANAGEMENT_KEY_PATH.to_string()))
}

/// Write a private key to disk with correct permissions (0600).
fn write_key_file(dir: &str, path: &str, privkey_pem: &str) -> Result<()> {
    std::fs::create_dir_all(dir)
        .context("Failed to create key directory")?;
    std::fs::write(path, privkey_pem)
        .context("Failed to write key file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set key file permissions")?;
    }
    Ok(())
}

// =============================================================================
// SSH Machine Key — auto-generated keypair for provisioned machine authentication
// =============================================================================

const MACHINE_KEY_DIR: &str = "/var/lib/dragonfly";
const MACHINE_KEY_PATH: &str = "/var/lib/dragonfly/machine_key";

/// Ensure an SSH machine keypair exists. Generates one if missing.
/// Returns (public_key_openssh, private_key_path).
///
/// Public wrapper for API access (key rotation, status check).
pub async fn ensure_machine_key_public(state: &AppState) -> Result<(String, String)> {
    ensure_machine_key(state).await
}

pub async fn ensure_machine_key(state: &AppState) -> Result<(String, String)> {
    let existing_pub = state.store.get_setting("machine_management_pubkey").await
        .ok().flatten().unwrap_or_default();
    let existing_priv_enc = state.store.get_setting("machine_management_privkey").await
        .ok().flatten().unwrap_or_default();

    if !existing_pub.is_empty() && !existing_priv_enc.is_empty() {
        let privkey_pem = crate::encryption::decrypt_string(&existing_priv_enc)
            .context("Failed to decrypt machine key")?;
        write_key_file(MACHINE_KEY_DIR, MACHINE_KEY_PATH, &privkey_pem)?;
        return Ok((existing_pub, MACHINE_KEY_PATH.to_string()));
    }

    info!("Generating SSH machine keypair for provisioned machine authentication");
    let private_key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::OsRng,
        ssh_key::Algorithm::Ed25519,
    ).context("Failed to generate ed25519 keypair")?;

    let privkey_pem = private_key.to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to serialize private key")?
        .to_string();
    let pubkey_openssh = private_key.public_key().to_openssh()
        .context("Failed to serialize public key")?;
    let pubkey_line = format!("{} dragonfly-machine", pubkey_openssh);

    let encrypted_priv = crate::encryption::encrypt_string(&privkey_pem)
        .context("Failed to encrypt machine key")?;
    state.store.put_setting("machine_management_pubkey", &pubkey_line).await
        .context("Failed to store machine public key")?;
    state.store.put_setting("machine_management_privkey", &encrypted_priv).await
        .context("Failed to store machine private key")?;

    write_key_file(MACHINE_KEY_DIR, MACHINE_KEY_PATH, &privkey_pem)?;

    info!("SSH machine key generated and stored (encrypted at rest)");
    Ok((pubkey_line, MACHINE_KEY_PATH.to_string()))
}

/// An existing LXC container found by hostname scan.
#[derive(Debug, Clone)]
struct ExistingContainer {
    node: String,
    vmid: u32,
    ip: Option<Ipv4Addr>,
    status: String,
}

/// A planned cluster node (LXC to be deployed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedNode {
    pub idx: usize,
    pub hostname: String,
    pub proxmox_node: String,
    pub vmid: u32,
    pub ip: Ipv4Addr,
    pub role: String,
    pub state: String,
    /// Per-node storage for LXC rootfs (detected per Proxmox host)
    pub storage: String,
    /// Per-node template storage (vztmpl-capable)
    pub template_storage: String,
    /// Per-node OS template volid
    pub ostemplate: String,
    /// Generated root password for the LXC
    #[serde(skip_serializing)]
    pub password: String,
    /// Whether this container already exists on Proxmox (skip creation)
    #[serde(default)]
    pub existing: bool,
}

/// The complete cluster deployment plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPlan {
    pub nodes: Vec<PlannedNode>,
    pub network_subnet: String,
    pub network_gateway: String,
    pub network_prefix: u8,
}

/// SSE event helper — sends cluster deployment progress and persists phase in AppState.
/// Global events (idx == -1) update the global phase.
/// Per-node events (idx >= 0) update the per-node phase map.
fn emit_cluster_event(state: &AppState, idx: i32, phase: &str, msg: &str) {
    // Persist phase for reconnecting clients
    if idx < 0 {
        if let Ok(mut p) = state.cluster_phase.lock() {
            *p = phase.to_string();
        }
    } else {
        if let Ok(mut m) = state.cluster_node_phases.lock() {
            m.insert(idx as usize, phase.to_string());
        }
    }

    let payload = serde_json::json!({
        "type": "cluster",
        "idx": idx,
        "phase": phase,
        "msg": msg,
    });
    let _ = state.event_manager.send(format!("cluster:{}", payload));
}

/// Check if the user has requested deployment abort.
fn is_aborted(state: &AppState) -> bool {
    state.cluster_abort.load(Ordering::Relaxed)
}

/// Clean up LXCs created during an aborted or failed deployment.
///
/// Stops and deletes every successfully-created LXC, then clears the stored
/// cluster plan so the user is never left with orphaned state (Rule 425).
async fn cleanup_deployment(
    state: &AppState,
    plan: &ClusterPlan,
    created_indices: &std::collections::HashSet<usize>,
) {
    if created_indices.is_empty() {
        let _ = state.store.put_setting("cluster_plan", "").await;
        return;
    }

    let client = match connect_to_proxmox(state, "create").await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to Proxmox for cleanup: {}", e);
            let _ = state.store.put_setting("cluster_plan", "").await;
            return;
        }
    };

    for node in plan.nodes.iter().filter(|n| created_indices.contains(&n.idx)) {
        emit_cluster_event(state, node.idx as i32, "aborting", "Cleaning up...");

        // Stop
        let stop_path = format!(
            "/api2/json/nodes/{}/lxc/{}/status/stop",
            node.proxmox_node, node.vmid
        );
        if let Ok(resp) = client.post(&stop_path, &serde_json::json!({})).await {
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
            if let Some(upid) = body.get("data").and_then(|d| d.as_str()) {
                let _ = wait_for_proxmox_task(&client, &node.proxmox_node, upid).await;
            }
        }

        // Delete
        let del_path = format!(
            "/api2/json/nodes/{}/lxc/{}",
            node.proxmox_node, node.vmid
        );
        match client.delete(&del_path).await {
            Ok(resp) => {
                let body: serde_json::Value =
                    serde_json::from_slice(&resp.body).unwrap_or_default();
                if let Some(upid) = body.get("data").and_then(|d| d.as_str()) {
                    let _ = wait_for_proxmox_task(&client, &node.proxmox_node, upid).await;
                }
                info!("Cleaned up LXC {} on {}", node.vmid, node.proxmox_node);
            }
            Err(e) => warn!(
                "Failed to cleanup LXC {} on {}: {:?}",
                node.vmid, node.proxmox_node, e
            ),
        }
    }

    // Clear cluster plan — no orphaned state
    let _ = state.store.put_setting("cluster_plan", "").await;
    info!("Deployment cleanup complete, cluster plan cleared");
}

/// Public abort entry point — called from the API handler when the deploy task
/// may have already exited.  Reads the stored cluster plan and destroys any LXCs.
pub async fn abort_cluster(state: &AppState) -> Result<()> {
    // Signal the running deploy task (if still alive)
    state.cluster_abort.store(true, Ordering::Relaxed);
    // Force-clear the deploying flag — the background task may be stuck in planning
    state.cluster_deploying.store(false, Ordering::Relaxed);

    // Also do cleanup ourselves in case deploy_cluster already returned
    let plan_json = state
        .store
        .get_setting("cluster_plan")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read cluster plan: {}", e))?;

    match plan_json {
        Some(json) if !json.is_empty() => {
            match serde_json::from_str::<ClusterPlan>(&json) {
                Ok(plan) => {
                    // Treat ALL nodes as potentially created — cleanup is idempotent
                    let all_indices: std::collections::HashSet<usize> =
                        plan.nodes.iter().map(|n| n.idx).collect();
                    cleanup_deployment(state, &plan, &all_indices).await;
                }
                Err(e) => {
                    // Plan format changed or is corrupted — just clear it.
                    // Rule 425: Don't leave stale state even if we can't parse it.
                    warn!("Could not parse cluster plan (clearing stale data): {}", e);
                    let _ = state.store.put_setting("cluster_plan", "").await;
                }
            }

            emit_cluster_event(state, -1, "aborted", "Deployment aborted and cleaned up");
            Ok(())
        }
        _ => {
            // No plan — nothing to clean up
            emit_cluster_event(state, -1, "aborted", "No deployment to abort");
            Ok(())
        }
    }
}

/// Extract the node name from a MachineSource::ProxmoxNode variant.
fn proxmox_node_name(source: &dragonfly_common::machine::MachineSource) -> Option<&str> {
    match source {
        dragonfly_common::machine::MachineSource::ProxmoxNode { node, .. } => Some(node.as_str()),
        _ => None,
    }
}

/// Ensure Proxmox custom roles have the permissions needed for cluster operations.
/// This is idempotent — it updates existing roles and reassigns token ACLs.
/// The sync token's Sys.Modify privilege allows role management.
async fn ensure_proxmox_roles(client: &ProxmoxApiClient, state: &AppState) {
    let role_updates = [
        ("DragonflyCreate", "VM.Allocate,VM.Config.Options,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Config.Network,VM.Config.HWType,VM.PowerMgmt,VM.Console,Datastore.AllocateSpace,Datastore.Audit,SDN.Use,Sys.Audit"),
        ("DragonflySync", "VM.Audit,Sys.Audit,Sys.Modify,SDN.Audit,VM.Config.Options,Datastore.Audit"),
    ];

    for (role_name, privs) in &role_updates {
        let path = format!("/api2/json/access/roles/{}", role_name);
        let params = serde_json::json!({ "privs": privs });

        // Try PUT to update existing role
        match client.put(&path, &params).await {
            Ok(_) => {
                info!("Updated Proxmox role '{}' with required permissions", role_name);
            }
            Err(_) => {
                // Role might not exist yet — try POST to create it
                info!("Role '{}' does not exist, creating...", role_name);
                let create_params = serde_json::json!({
                    "roleid": role_name,
                    "privs": privs,
                });
                match client.post("/api2/json/access/roles", &create_params).await {
                    Ok(_) => info!("Created Proxmox role '{}'", role_name),
                    Err(e) => warn!("Could not create role '{}': {:?} — token may lack Sys.Modify on /access", role_name, e),
                }
            }
        }
    }

    // Reassign token ACLs to use our custom roles (in case they were created with built-in roles)
    let token_role_map = [
        ("create", "DragonflyCreate"),
        ("sync", "DragonflySync"),
    ];

    for (token_type, role_name) in &token_role_map {
        let token_key = format!("proxmox_vm_{}_token", token_type);
        let tokens = state.tokens.lock().await;
        let token = tokens.get(&token_key).cloned();
        drop(tokens);

        if let Some(token_str) = token {
            if let Some(equals_pos) = token_str.find('=') {
                let token_id = &token_str[..equals_pos]; // "user@realm!tokenname"
                let acl_params = serde_json::json!({
                    "path": "/",
                    "propagate": "1",
                    "roles": role_name,
                    "tokens": token_id,
                });
                match client.put("/api2/json/access/acl", &acl_params).await {
                    Ok(resp) => {
                        if resp.status == 200 {
                            info!("Reassigned {} token ACL to role '{}'", token_type, role_name);
                        } else {
                            warn!("Failed to reassign {} token ACL (status {})", token_type, resp.status);
                        }
                    }
                    Err(e) => warn!("Could not update {} token ACL: {:?}", token_type, e),
                }
            }
        }
    }
}

/// Pre-flight IP availability scan.
///
/// Checks ARP table first (instant, no traffic), then sends a single ICMP
/// ping to remaining IPs in parallel (1 second timeout). Returns the set
/// of IPs that are already occupied.
async fn scan_ips_occupied(ips: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    // Phase 1: Read ARP table — instant, no network traffic
    let mut arp_known: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
    if let Ok(arp_output) = tokio::process::Command::new("ip")
        .args(["neigh", "show"])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&arp_output.stdout);
        for line in stdout.lines() {
            // Format: "10.7.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            if let Some(ip_str) = line.split_whitespace().next() {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    // Only count entries that are REACHABLE, STALE, or DELAY (not FAILED/INCOMPLETE)
                    let upper = line.to_uppercase();
                    if upper.contains("REACHABLE") || upper.contains("STALE") || upper.contains("DELAY") {
                        arp_known.insert(ip);
                    }
                }
            }
        }
    }

    let mut occupied = Vec::new();
    let mut need_ping = Vec::new();

    for &ip in ips {
        if arp_known.contains(&ip) {
            info!("Pre-flight: {} is in ARP table (occupied)", ip);
            occupied.push(ip);
        } else {
            need_ping.push(ip);
        }
    }

    // Phase 2: Parallel ping with 1s timeout for IPs not in ARP
    if !need_ping.is_empty() {
        info!("Pre-flight: pinging {} IPs not found in ARP table", need_ping.len());
        let mut handles = Vec::new();
        for ip in need_ping {
            handles.push(tokio::spawn(async move {
                let result = tokio::process::Command::new("ping")
                    .args(["-c", "1", "-W", "1", &ip.to_string()])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await;
                match result {
                    Ok(status) if status.success() => Some(ip),
                    _ => None,
                }
            }));
        }
        for handle in handles {
            if let Ok(Some(ip)) = handle.await {
                info!("Pre-flight: {} responded to ping (occupied)", ip);
                occupied.push(ip);
            }
        }
    }

    occupied
}

/// Scan all Proxmox nodes for LXCs with hostnames matching `dragonfly\d+`.
/// Returns a map: hostname → ExistingContainer.
async fn scan_existing_containers(
    client: &ProxmoxApiClient,
    proxmox_node_names: &[&str],
) -> HashMap<String, ExistingContainer> {
    let mut found = HashMap::new();

    for &node in proxmox_node_names {
        let path = format!("/api2/json/nodes/{}/lxc", node);
        let resp = match client.get(&path).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to list LXCs on node '{}': {:?}", node, e);
                continue;
            }
        };

        let body: serde_json::Value = match serde_json::from_slice(&resp.body) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
            for entry in data {
                let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("");
                // Match dragonfly01, dragonfly02, etc.
                if !name.starts_with("dragonfly") {
                    continue;
                }
                let suffix = &name["dragonfly".len()..];
                if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let vmid = entry.get("vmid")
                    .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(0) as u32;

                let status = entry.get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Try to extract IP from the config
                let ip = extract_lxc_ip(client, node, vmid).await;

                info!("Found existing container '{}' on node '{}' (vmid={}, status={})",
                    name, node, vmid, status);

                found.insert(name.to_string(), ExistingContainer {
                    node: node.to_string(),
                    vmid,
                    ip,
                    status,
                });
            }
        }
    }

    found
}

/// Extract IP address from an LXC container's net0 config.
async fn extract_lxc_ip(
    client: &ProxmoxApiClient,
    node: &str,
    vmid: u32,
) -> Option<Ipv4Addr> {
    let path = format!("/api2/json/nodes/{}/lxc/{}/config", node, vmid);
    let resp = client.get(&path).await.ok()?;
    let body: serde_json::Value = serde_json::from_slice(&resp.body).ok()?;
    let data = body.get("data")?;

    // Parse net0..net7 for ip=X.X.X.X/Y
    for i in 0..8 {
        let net_key = format!("net{}", i);
        if let Some(net_cfg) = data.get(&net_key).and_then(|n| n.as_str()) {
            for part in net_cfg.split(',') {
                if let Some(ip_str) = part.strip_prefix("ip=") {
                    // Strip CIDR prefix if present
                    let ip_only = ip_str.split('/').next().unwrap_or(ip_str);
                    if let Ok(ip) = ip_only.parse::<Ipv4Addr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// Build a cluster plan from the current Proxmox hosts and network config.
///
/// Returns the plan and stores it in settings KV as `"cluster_plan"`.
pub async fn build_cluster_plan(state: &AppState) -> Result<ClusterPlan> {
    // 1. Get Proxmox nodes from machine store
    let machines = state.store.list_machines().await
        .map_err(|e| anyhow::anyhow!("Failed to list machines: {}", e))?;

    let proxmox_nodes: Vec<_> = machines.iter()
        .filter(|m| matches!(m.metadata.source, dragonfly_common::machine::MachineSource::ProxmoxNode { .. }))
        .filter(|m| !matches!(m.status.state, dragonfly_common::MachineState::Offline))
        .collect();

    if proxmox_nodes.is_empty() {
        bail!("No online Proxmox nodes found. All nodes may be offline, or no Proxmox cluster is connected.");
    }

    // 2. Get primary network for IP allocation
    let networks = state.store.list_networks().await
        .map_err(|e| anyhow::anyhow!("Failed to list networks: {}", e))?;

    let network = networks.first()
        .ok_or_else(|| anyhow::anyhow!("No networks configured. Create a network first."))?;

    let gateway = network.gateway.as_deref()
        .ok_or_else(|| anyhow::anyhow!("Network has no gateway configured"))?;

    // Parse subnet to get prefix length
    let prefix: u8 = if let Some(slash) = network.subnet.rfind('/') {
        network.subnet[slash + 1..].parse().unwrap_or(24)
    } else {
        24
    };

    // 3. Connect to Proxmox and ensure roles have correct permissions
    let client = connect_to_proxmox(state, "sync").await
        .context("Failed to connect to Proxmox with sync token")?;

    // Ensure roles have the permissions we need (upgrades existing installations)
    ensure_proxmox_roles(&client, state).await;

    // 4. Parse subnet for IP scanning
    let gateway_ip: Ipv4Addr = gateway.parse()
        .context("Failed to parse gateway IP")?;
    let gateway_octets = gateway_ip.octets();

    // 5. Scan for existing containers by hostname (fixes duplicate VM bug)
    let node_names: Vec<&str> = proxmox_nodes.iter()
        .filter_map(|m| proxmox_node_name(&m.metadata.source))
        .collect();
    let existing = scan_existing_containers(&client, &node_names).await;

    // Collect IPs already owned by our existing containers
    let our_ips: std::collections::HashSet<Ipv4Addr> = existing.values()
        .filter_map(|ec| ec.ip)
        .collect();

    // 5b. Scan subnet for occupied IPs, then find a contiguous free block
    let needed = proxmox_nodes.len();
    let new_needed = {
        let mut count = 0usize;
        for i in 0..needed {
            let hostname = format!("dragonfly{:02}", i + 1);
            if !existing.contains_key(&hostname) {
                count += 1;
            }
        }
        count
    };

    // Determine the scannable range from the subnet
    // For /24: .2 to .254 (skip .0 network and .255 broadcast, and gateway)
    let subnet_base = [gateway_octets[0], gateway_octets[1], gateway_octets[2], 0];
    let scan_start: u8 = 2; // skip .0 (network) and .1 (common gateway)
    let scan_end: u8 = 254; // skip .255 (broadcast)

    let allocated_ips: Vec<Ipv4Addr> = if new_needed > 0 {
        info!("Pre-flight: scanning subnet {}.{}.{}.0/{} for {} contiguous free IPs",
            subnet_base[0], subnet_base[1], subnet_base[2], prefix, new_needed);

        // Build full list of IPs to scan
        let scan_range: Vec<Ipv4Addr> = (scan_start..=scan_end)
            .map(|last| Ipv4Addr::new(subnet_base[0], subnet_base[1], subnet_base[2], last))
            .filter(|ip| ip != &gateway_ip) // skip the gateway
            .filter(|ip| !our_ips.contains(ip)) // skip our existing containers
            .collect();

        let occupied = scan_ips_occupied(&scan_range).await;
        let occupied_set: std::collections::HashSet<Ipv4Addr> = occupied.into_iter().collect();

        info!("Pre-flight: found {} occupied IPs in subnet (excluding {} owned containers)",
            occupied_set.len(), our_ips.len());

        // Find first contiguous block of `new_needed` free IPs
        // Walk .2 to .254, skipping gateway and occupied
        let mut block = Vec::new();
        for last in scan_start..=scan_end {
            let ip = Ipv4Addr::new(subnet_base[0], subnet_base[1], subnet_base[2], last);
            if ip == gateway_ip || our_ips.contains(&ip) || occupied_set.contains(&ip) {
                block.clear();
                continue;
            }
            block.push(ip);
            if block.len() == new_needed {
                break;
            }
        }

        if block.len() < new_needed {
            bail!(
                "Cannot find {} contiguous free IPs in subnet {}.{}.{}.0/{}. \
                 Found only {} contiguous free IPs. Free up addresses or use a larger subnet.",
                new_needed, subnet_base[0], subnet_base[1], subnet_base[2], prefix,
                block.len()
            );
        }

        info!("Pre-flight: allocated contiguous block {}-{} ({} IPs)",
            block.first().unwrap(), block.last().unwrap(), block.len());
        block
    } else {
        info!("Pre-flight: all containers already exist, no new IPs needed");
        Vec::new()
    };

    // Try to recover passwords from a previous plan
    let old_passwords: HashMap<String, String> = state.store
        .get_setting("cluster_plan").await
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str::<ClusterPlan>(&json).ok())
        .map(|old_plan| {
            old_plan.nodes.into_iter()
                .map(|n| (n.hostname, n.password))
                .collect()
        })
        .unwrap_or_default();

    // Count how many NEW VMIDs we need
    let mut new_vmid_count = 0u32;
    for (i, _) in proxmox_nodes.iter().enumerate() {
        let hostname = format!("dragonfly{:02}", i + 1);
        if !existing.contains_key(&hostname) {
            new_vmid_count += 1;
        }
    }

    // Only request VMIDs if we need new containers
    let base_vmid = if new_vmid_count > 0 {
        get_next_vmid(&client).await
            .context("Failed to get next VMID from Proxmox")?
    } else {
        0 // unused — all containers already exist
    };
    let mut vmid_counter = 0u32;
    let mut alloc_idx = 0usize;

    // 6. Build per-node plans with per-node storage detection
    let mut nodes = Vec::new();
    for (i, machine) in proxmox_nodes.iter().enumerate() {
        let node_name = proxmox_node_name(&machine.metadata.source)
            .unwrap_or("node");
        let hostname = format!("dragonfly{:02}", i + 1);

        // Detect storage, template storage, and OS template for THIS specific node
        let storage = detect_storage(&client, node_name).await
            .context(format!("Failed to detect rootdir storage on node '{}'", node_name))?;

        let tmpl_storage = detect_template_storage(&client, node_name).await
            .context(format!("Failed to detect template storage on node '{}'", node_name))?;

        let ostemplate = ensure_template(&client, node_name, &tmpl_storage).await
            .context(format!("Failed to ensure Debian template on node '{}'", node_name))?;

        // Reuse existing container data or allocate from scanned free block
        let (vmid, ip, is_existing) = if let Some(ec) = existing.get(&hostname) {
            let ip = ec.ip.unwrap_or_else(|| {
                // Fallback: take from allocated block if available
                if let Some(&alloc_ip) = allocated_ips.get(alloc_idx) {
                    alloc_idx += 1;
                    alloc_ip
                } else {
                    Ipv4Addr::new(gateway_octets[0], gateway_octets[1], gateway_octets[2], 200 + i as u8)
                }
            });
            info!("Reusing existing container '{}' on '{}' (vmid={}, ip={})",
                hostname, ec.node, ec.vmid, ip);
            (ec.vmid, ip, true)
        } else {
            let vmid = base_vmid + vmid_counter;
            vmid_counter += 1;
            let ip = allocated_ips[alloc_idx];
            alloc_idx += 1;
            (vmid, ip, false)
        };

        let role = if i < 3 { "core" } else { "replica" };

        // Reuse old password if available, otherwise generate new
        let password = old_passwords.get(&hostname).cloned().unwrap_or_else(|| {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            (0..24).map(|_| {
                let idx = rng.gen_range(0..62);
                if idx < 10 {
                    (b'0' + idx) as char
                } else if idx < 36 {
                    (b'a' + idx - 10) as char
                } else {
                    (b'A' + idx - 36) as char
                }
            }).collect()
        });

        info!("Planned node {} on '{}': storage={}, template={}, existing={}",
            hostname, node_name, storage, tmpl_storage, is_existing);

        nodes.push(PlannedNode {
            idx: i,
            hostname,
            proxmox_node: node_name.to_string(),
            vmid,
            ip,
            role: role.to_string(),
            state: "pending".to_string(),
            storage,
            template_storage: tmpl_storage,
            ostemplate,
            password,
            existing: is_existing,
        });
    }

    let plan = ClusterPlan {
        nodes,
        network_subnet: network.subnet.clone(),
        network_gateway: gateway.to_string(),
        network_prefix: prefix,
    };

    // Store plan in settings KV
    let plan_json = serde_json::to_string(&plan)?;
    state.store.put_setting("cluster_plan", &plan_json).await
        .map_err(|e| anyhow::anyhow!("Failed to store cluster plan: {}", e))?;

    Ok(plan)
}

/// Detect the best storage volume that supports `rootdir` content type on the given node.
///
/// Prefers local storage (local-lvm, local-zfs, lvmthin, zfspool, dir) over shared/distributed
/// storage (nfs, cifs, cephfs, moosefs, etc.) because LXC rootfs benefits from local I/O and
/// avoids nbd/fuse issues on distributed backends.
async fn detect_storage(
    client: &ProxmoxApiClient,
    node: &str,
) -> Result<String> {
    info!("Detecting storage on node '{}' ...", node);
    let path = format!("/api2/json/nodes/{}/storage", node);
    let resp = client.get(&path).await
        .map_err(|e| anyhow::anyhow!("Failed to query storage on node '{}': {:?}", node, e))?;

    let raw_body = String::from_utf8_lossy(&resp.body);
    info!("Raw storage response (status={}): {}", resp.status, &raw_body[..raw_body.len().min(2000)]);

    let body: serde_json::Value = serde_json::from_slice(&resp.body)
        .context("Failed to parse storage response")?;

    if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
        info!("Found {} storage entries on node '{}'", data.len(), node);

        // Collect all rootdir-capable, active, enabled storages with a preference score
        let mut candidates: Vec<(&str, u8)> = Vec::new();
        for entry in data {
            let content = entry.get("content").and_then(|c| c.as_str()).unwrap_or("");
            let storage_name = entry.get("storage").and_then(|s| s.as_str()).unwrap_or("");
            let storage_type = entry.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let active = entry.get("active").and_then(|a| a.as_i64()).unwrap_or(0);
            let enabled = entry.get("enabled").and_then(|e| e.as_i64()).unwrap_or(0);
            let shared = entry.get("shared").and_then(|s| s.as_i64()).unwrap_or(0);
            info!("  storage='{}' type='{}' content='{}' active={} enabled={} shared={}",
                storage_name, storage_type, content, active, enabled, shared);

            if !content.contains("rootdir") || storage_name.is_empty() || active != 1 || enabled != 1 {
                continue;
            }

            // Score: lower is better. Prefer local block storage over shared/distributed.
            let score = match storage_type {
                "lvmthin" => 1,  // Best: thin provisioning, local, fast
                "zfspool" => 2,  // Excellent: local ZFS
                "lvm"     => 3,  // Good: local LVM (thick)
                "dir"     => 4,  // OK: local directory
                "btrfs"   => 5,  // OK: local btrfs
                _         => {
                    if shared == 1 { 10 } else { 6 }  // Shared/distributed = last resort
                }
            };
            candidates.push((storage_name, score));
        }

        candidates.sort_by_key(|(_name, score)| *score);
        if let Some((best_name, _score)) = candidates.first() {
            info!("Detected storage '{}' with rootdir support on node {} (from {} candidates)",
                best_name, node, candidates.len());
            return Ok(best_name.to_string());
        }
    } else {
        warn!("No 'data' array in storage response for node '{}': {}", node, body);
    }

    bail!("No storage with rootdir support found on node '{}'", node);
}

/// Detect a storage volume that supports `vztmpl` content type (for LXC templates).
/// List all vztmpl-capable storages on a node (active + enabled).
async fn list_vztmpl_storages(
    client: &ProxmoxApiClient,
    node: &str,
) -> Result<Vec<(String, bool)>> {
    let path = format!("/api2/json/nodes/{}/storage", node);
    let resp = client.get(&path).await
        .map_err(|e| anyhow::anyhow!("Failed to query storage on node '{}': {:?}", node, e))?;

    let body: serde_json::Value = serde_json::from_slice(&resp.body)
        .context("Failed to parse storage response")?;

    let mut storages = Vec::new();
    if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
        for entry in data {
            let content = entry.get("content").and_then(|c| c.as_str()).unwrap_or("");
            let name = entry.get("storage").and_then(|s| s.as_str()).unwrap_or("");
            let active = entry.get("active").and_then(|a| a.as_i64()).unwrap_or(0);
            let enabled = entry.get("enabled").and_then(|e| e.as_i64()).unwrap_or(0);
            let shared = entry.get("shared").and_then(|s| s.as_i64()).unwrap_or(0);
            if content.contains("vztmpl") && !name.is_empty() && active == 1 && enabled == 1 {
                storages.push((name.to_string(), shared == 1));
            }
        }
    }

    // Prefer shared storages (e.g. moosefs) — they already have templates
    // downloaded once for the whole cluster.
    storages.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(storages)
}

async fn detect_template_storage(
    client: &ProxmoxApiClient,
    node: &str,
) -> Result<String> {
    let storages = list_vztmpl_storages(client, node).await?;
    if let Some((name, _)) = storages.first() {
        info!("Detected template storage '{}' (vztmpl) on node {}", name, node);
        Ok(name.clone())
    } else {
        bail!("No storage with vztmpl support found on node '{}'", node);
    }
}

/// Search ALL vztmpl-capable storages on a node for a Debian template.
/// Returns the volid of the best match (Debian 13 preferred, latest point release).
async fn detect_template(
    client: &ProxmoxApiClient,
    node: &str,
    _preferred_storage: &str,
) -> Result<String> {
    let storages = list_vztmpl_storages(client, node).await?;
    if storages.is_empty() {
        bail!("No vztmpl-capable storages on node '{}'", node);
    }

    // Search every vztmpl-capable storage, not just one
    for (storage_name, _shared) in &storages {
        let path = format!(
            "/api2/json/nodes/{}/storage/{}/content?content=vztmpl",
            node, storage_name
        );
        let resp = match client.get(&path).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to query templates on {}:{}: {:?}", node, storage_name, e);
                continue;
            }
        };

        let body: serde_json::Value = match serde_json::from_slice(&resp.body) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
            let mut best: Option<&str> = None;
            for entry in data {
                let volid = entry.get("volid").and_then(|v| v.as_str()).unwrap_or("");
                if volid.contains("debian-13-standard") {
                    if best.map_or(true, |b| !b.contains("debian-13") || volid > b) {
                        best = Some(volid);
                    }
                } else if volid.contains("debian-12-standard") && best.is_none() {
                    best = Some(volid);
                }
            }
            if let Some(template) = best {
                info!("Found Debian template on {}:{}: {}", node, storage_name, template);
                return Ok(template.to_string());
            }
        }
    }

    bail!("No Debian template found on any storage on node '{}'", node);
}

/// Ensure a Debian template exists on the node — download if missing.
///
/// Searches all vztmpl-capable storages first.  If not found anywhere,
/// downloads to the preferred shared storage (or first available).
async fn ensure_template(
    client: &ProxmoxApiClient,
    node: &str,
    storage: &str,
) -> Result<String> {
    // Search ALL storages on the node
    if let Ok(template) = detect_template(client, node, storage).await {
        return Ok(template);
    }

    // Not found anywhere — download to the given storage
    info!("Downloading Debian 13 template to {}:{} ...", node, storage);

    let path = format!("/api2/json/nodes/{}/aplinfo", node);
    let body = serde_json::json!({
        "template": "debian-13-standard_13.1-2_amd64.tar.zst",
        "storage": storage,
    });
    let resp = client.post(&path, &body).await
        .map_err(|e| anyhow::anyhow!("Failed to initiate template download: {:?}", e))?;

    let resp_body: serde_json::Value = serde_json::from_slice(&resp.body)
        .context("Failed to parse template download response")?;

    if let Some(upid) = resp_body.get("data").and_then(|d| d.as_str()) {
        wait_for_proxmox_task(client, node, upid).await?;
    }

    // Re-detect across all storages
    detect_template(client, node, storage).await
        .context("Template download completed but template not found")
}

/// Wait for a Proxmox task (UPID) to complete using long-poll.
async fn wait_for_proxmox_task(
    client: &ProxmoxApiClient,
    node: &str,
    upid: &str,
) -> Result<()> {
    let encoded_upid = urlencoding::encode(upid);
    let mut start = 0u64;

    loop {
        let path = format!(
            "/api2/json/nodes/{}/tasks/{}/log?start={}&limit=50",
            node, encoded_upid, start
        );
        let resp = client.get(&path).await
            .map_err(|e| anyhow::anyhow!("Task log query failed: {:?}", e))?;

        let body: serde_json::Value = serde_json::from_slice(&resp.body)
            .context("Failed to parse task log")?;

        // Update start for next poll
        if let Some(total) = body.get("total").and_then(|t| t.as_u64()) {
            start = total;
        }

        // Check task status
        let status_path = format!(
            "/api2/json/nodes/{}/tasks/{}/status",
            node, encoded_upid
        );
        let status_resp = client.get(&status_path).await
            .map_err(|e| anyhow::anyhow!("Task status query failed: {:?}", e))?;

        let status_body: serde_json::Value = serde_json::from_slice(&status_resp.body)
            .context("Failed to parse task status")?;

        if let Some(data) = status_body.get("data") {
            let task_status = data.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if task_status == "stopped" {
                let exit_status = data.get("exitstatus").and_then(|s| s.as_str()).unwrap_or("");
                if exit_status == "OK" {
                    return Ok(());
                } else {
                    bail!("Proxmox task failed with status: {}", exit_status);
                }
            }
        }
        // Loop continues — each iteration makes 2 network requests (~60ms total),
        // providing natural rate limiting without client-side sleep
    }
}

/// Get the next available VMID from Proxmox cluster.
async fn get_next_vmid(client: &ProxmoxApiClient) -> Result<u32> {
    let path = "/api2/json/cluster/nextid";
    let resp = client.get(path).await
        .map_err(|e| anyhow::anyhow!("Failed to get next VMID: {:?}", e))?;

    let body: serde_json::Value = serde_json::from_slice(&resp.body)
        .context("Failed to parse nextid response")?;

    body.get("data")
        .and_then(|d| {
            // Response can be either a number or a string
            d.as_u64().or_else(|| d.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)
        .ok_or_else(|| anyhow::anyhow!("Unexpected nextid response format"))
}

/// Build a Jetpack Inventory directly from a ClusterPlan and Proxmox credentials.
///
/// Each PlannedNode becomes a host in the `dragonfly_cluster` group.
/// Non-existing nodes get a `provision:` block for Jetpack's proxmox_lxc provisioner.
/// A special `proxmox-cluster` host holds the API credentials.
fn build_jetpack_inventory(
    plan: &ClusterPlan,
    proxmox_host: &str,
    proxmox_port: u16,
    token_id: &str,
    token_secret: &str,
    password: &str,
    management_pubkey: Option<&str>,
) -> Arc<RwLock<jetpack::Inventory>> {
    let mut inventory = jetpack::Inventory::new();

    // Create the cluster credential host (Jetpack provisioner reads API creds from here)
    let cluster_host_name = "proxmox-cluster".to_string();
    inventory.store_host(&"all".to_string(), &cluster_host_name);
    let mut cluster_vars = serde_yaml::Mapping::new();
    cluster_vars.insert(
        serde_yaml::Value::String("proxmox_api_host".into()),
        serde_yaml::Value::String(format!("{}:{}", proxmox_host, proxmox_port)),
    );
    cluster_vars.insert(
        serde_yaml::Value::String("proxmox_api_token_id".into()),
        serde_yaml::Value::String(token_id.to_string()),
    );
    cluster_vars.insert(
        serde_yaml::Value::String("proxmox_api_token_secret".into()),
        serde_yaml::Value::String(token_secret.to_string()),
    );
    inventory.store_host_variables(&cluster_host_name, cluster_vars);

    // Create the dragonfly_cluster group
    let group_name = "dragonfly_cluster".to_string();
    inventory.store_group(&group_name);

    // Add each planned node to the group
    for node in &plan.nodes {
        inventory.store_host(&group_name, &node.hostname);

        // Set host variables (SSH connection info)
        let mut host_vars = serde_yaml::Mapping::new();
        host_vars.insert(
            serde_yaml::Value::String("jet_ssh_hostname".into()),
            serde_yaml::Value::String(node.ip.to_string()),
        );

        inventory.store_host_variables(&node.hostname, host_vars);

        // For non-existing nodes, set up provisioning
        if !node.existing {
            let net_config = format!(
                "name=eth0,bridge=vmbr0,ip={}/{},gw={}",
                node.ip, plan.network_prefix, plan.network_gateway
            );

            let mut extra = HashMap::new();
            extra.insert("searchdomain".to_string(), "home.arpa".to_string());

            let provision = jetpack::ProvisionConfig {
                provision_type: "proxmox_lxc".to_string(),
                state: "present".to_string(),
                cluster: cluster_host_name.clone(),
                node: Some(node.proxmox_node.clone()),
                hostname: Some(node.hostname.clone()),
                vmid: Some(node.vmid.to_string()),
                memory: Some("1536".to_string()),
                cores: Some("1".to_string()),
                ostemplate: Some(node.ostemplate.clone()),
                storage: Some(node.storage.clone()),
                rootfs_size: Some("4G".to_string()),
                net0: Some(net_config),
                net1: None,
                net2: None,
                net3: None,
                password: Some(password.to_string()),
                authorized_keys: management_pubkey.map(|k| k.to_string()),
                ssh_user: Some("root".to_string()),
                unprivileged: Some("true".to_string()),
                start_on_create: Some("true".to_string()),
                features: Some("nesting=1".to_string()),
                tun: None,
                nameserver: Some(plan.network_gateway.clone()),
                wait_for_host: Some(true),
                wait_timeout: Some(120),
                wait_delay: None,
                wait_strategy: None,
                wait_max_delay: None,
                extra,
            };

            let host = inventory.get_host(&node.hostname);
            host.write().expect("host write").set_provision(provision);
        }
    }

    Arc::new(RwLock::new(inventory))
}

// Embedded playbooks — baked into the binary at compile time.
const PLAYBOOK_PROVISION: &str = include_str!("../../../playbooks/cluster/provision.yml");
const PLAYBOOK_CONFIGURE: &str = include_str!("../../../playbooks/cluster/configure.yml");

/// Run an inline Jetpack playbook (sync, for use in spawn_blocking).
fn run_jetpack_playbook(
    name: &str,
    yaml: &str,
    inventory: &Arc<RwLock<jetpack::Inventory>>,
    password: &str,
    private_key_file: Option<&str>,
    limit_hosts: Option<Vec<String>>,
    extra_vars: Option<serde_yaml::Value>,
    output_handler: Option<Arc<dyn jetpack::OutputHandler>>,
    async_mode: bool,
) -> std::result::Result<jetpack::PlaybookResult, jetpack::JetpackError> {
    let mut builder = jetpack::run_inline(name, yaml)
        .ssh()
        .user("root")
        .with_inventory(Arc::clone(inventory));

    // Prefer key-based auth; fall back to password
    if let Some(key_path) = private_key_file {
        builder = builder.private_key_file(key_path);
    } else {
        builder = builder.login_password(password);
    }

    if let Some(hosts) = limit_hosts {
        builder = builder.limit_hosts(hosts);
    }
    if let Some(vars) = extra_vars {
        builder = builder.extra_vars(vars);
    }
    if async_mode {
        builder = builder.async_mode();
    }

    if let Some(handler) = output_handler {
        builder.run_with_output(handler)
    } else {
        builder.run()
    }
}

/// The main cluster deployment orchestrator.
///
/// Spawned via `tokio::spawn` from the API handler. Progresses through phases:
/// A. Ensure Debian template on all target nodes
/// B. Provision LXCs via Jetpack (idempotent — skips existing)
/// C. Install rqlite via Jetpack
/// D. Cluster formation via Jetpack (leader, then joiners)
/// E. Migrate store and switch to HA mode
pub async fn deploy_cluster(state: AppState, mut plan: ClusterPlan) {
    info!("Starting cluster deployment with {} nodes ({} existing)",
        plan.nodes.len(), plan.nodes.iter().filter(|n| n.existing).count());

    // Mark deployment as in-progress; RAII guard clears it on all exit paths
    state.cluster_deploying.store(true, Ordering::Relaxed);
    struct DeployGuard(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DeployGuard {
        fn drop(&mut self) { self.0.store(false, Ordering::Relaxed); }
    }
    let _deploy_guard = DeployGuard(Arc::clone(&state.cluster_deploying));

    // Reset abort flag and phase tracking for this deployment
    state.cluster_abort.store(false, Ordering::Relaxed);
    if let Ok(mut p) = state.cluster_phase.lock() { p.clear(); }
    if let Ok(mut m) = state.cluster_node_phases.lock() { m.clear(); }

    // Rule 425: Persist the plan BEFORE creating anything.
    let plan_json = serde_json::to_string(&plan).unwrap_or_default();
    if let Err(e) = state.store.put_setting("cluster_plan", &plan_json).await {
        error!("Failed to persist cluster plan: {}", e);
        emit_cluster_event(&state, -1, "error", "Failed to save cluster plan");
        return;
    }

    // Track which LXCs were actually created (for cleanup on abort/failure)
    let mut created_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
    // Mark pre-existing containers as "created" for cleanup tracking
    for node in plan.nodes.iter().filter(|n| n.existing) {
        created_indices.insert(node.idx);
    }

    emit_cluster_event(&state, -1, "starting", "Deploying cluster...");

    // Phase A: Ensure Debian template on all unique nodes (only for non-existing)
    let needs_new_containers = plan.nodes.iter().any(|n| !n.existing);
    if needs_new_containers {
        emit_cluster_event(&state, -1, "template", "Ensuring Debian template...");
        let sync_client = match connect_to_proxmox(&state, "sync").await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to connect to Proxmox (sync): {}", e);
                emit_cluster_event(&state, -1, "error", &format!("Proxmox connection failed: {}", e));
                return;
            }
        };

        let mut seen_nodes = std::collections::HashSet::new();
        for node in plan.nodes.iter().filter(|n| !n.existing) {
            if !seen_nodes.insert(node.proxmox_node.clone()) {
                continue;
            }
            match ensure_template(&sync_client, &node.proxmox_node, &node.template_storage).await {
                Ok(_) => info!("Template ready on node {}", node.proxmox_node),
                Err(e) => {
                    error!("Failed to ensure template on {}: {}", node.proxmox_node, e);
                    emit_cluster_event(&state, -1, "error", &format!("Template failed on {}: {}", node.proxmox_node, e));
                    return;
                }
            }
        }
    }

    if is_aborted(&state) {
        emit_cluster_event(&state, -1, "aborted", "Deployment aborted — use Cleanup to remove containers, or Retry to continue");
        return;
    }

    // Extract Proxmox credentials for Jetpack inventory
    let (proxmox_host, proxmox_port) = {
        let settings = state.settings.lock().await;
        (
            settings.proxmox_host.clone().unwrap_or_default(),
            settings.proxmox_port.unwrap_or(8006),
        )
    };

    let (token_id, token_secret) = {
        let tokens = state.tokens.lock().await;
        let token_str = tokens.get("proxmox_vm_create_token").cloned().unwrap_or_default();
        if let Some(eq_pos) = token_str.find('=') {
            (token_str[..eq_pos].to_string(), token_str[eq_pos + 1..].to_string())
        } else {
            (token_str.clone(), String::new())
        }
    };

    // Use a single password for all cluster nodes (simplifies Jetpack's global login_password)
    let cluster_password = plan.nodes[0].password.clone();

    // Resolve cluster name for machine registration
    let create_client = match connect_to_proxmox(&state, "create").await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to Proxmox (create): {}", e);
            emit_cluster_event(&state, -1, "error", &format!("Proxmox connection failed: {}", e));
            return;
        }
    };

    let cluster_name = match create_client.get("/api2/json/cluster/status").await {
        Ok(resp) => {
            let val = serde_json::from_slice::<serde_json::Value>(&resp.body).ok();
            val.as_ref()
                .and_then(|v| v.get("data"))
                .and_then(|d| d.as_array())
                .and_then(|entries| {
                    entries.iter().find_map(|e| {
                        if e.get("type").and_then(|t| t.as_str()) == Some("cluster") {
                            e.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| proxmox_host.clone())
        }
        Err(_) => proxmox_host.clone(),
    };

    // Generate or load SSH management key for cluster authentication
    let (management_pubkey, management_key_path) = match ensure_management_key(&state).await {
        Ok(pair) => (Some(pair.0), Some(pair.1)),
        Err(e) => {
            warn!("Failed to set up management key, falling back to password auth: {}", e);
            (None, None)
        }
    };

    // Build Jetpack inventory from the plan
    let inventory = build_jetpack_inventory(
        &plan, &proxmox_host, proxmox_port, &token_id, &token_secret, &cluster_password,
        management_pubkey.as_deref(),
    );

    // Playbooks are embedded in the binary — no external files needed.

    // Output handler for Jetpack provisioning lifecycle events → SSE
    let output_handler: Arc<dyn jetpack::OutputHandler> = Arc::new(ClusterOutputHandler {
        event_manager: state.event_manager.as_ref().clone(),
    });

    // Phase B: Provision LXCs via Jetpack (idempotent — skips existing containers)
    emit_cluster_event(&state, -1, "creating", "Creating cluster nodes...");
    for node in plan.nodes.iter().filter(|n| !n.existing) {
        emit_cluster_event(&state, node.idx as i32, "creating",
            &format!("Creating LXC on {}...", node.proxmox_node));
    }
    for node in plan.nodes.iter().filter(|n| n.existing) {
        emit_cluster_event(&state, node.idx as i32, "creating", "Reusing existing container");
    }

    let inv_clone = Arc::clone(&inventory);
    let pw = cluster_password.clone();
    let oh = Arc::clone(&output_handler);
    let key_path = management_key_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        run_jetpack_playbook("provision.yml", PLAYBOOK_PROVISION, &inv_clone, &pw, key_path.as_deref(), None, None, Some(oh), true)
    }).await;

    match result {
        Ok(Ok(r)) if r.success => {
            info!("Jetpack provisioning complete ({} hosts processed)", r.hosts_processed);
            for node in &plan.nodes {
                created_indices.insert(node.idx);
            }
        }
        Ok(Ok(_)) => {
            error!("Jetpack provisioning reported failure");
            emit_cluster_event(&state, -1, "error", "Provisioning failed");
            cleanup_deployment(&state, &plan, &created_indices).await;
            return;
        }
        Ok(Err(e)) => {
            error!("Jetpack provisioning error: {}", e);
            emit_cluster_event(&state, -1, "error", &format!("Provisioning failed: {}", e));
            cleanup_deployment(&state, &plan, &created_indices).await;
            return;
        }
        Err(e) => {
            error!("Jetpack provisioning task panicked: {}", e);
            emit_cluster_event(&state, -1, "error", "Provisioning task panicked");
            cleanup_deployment(&state, &plan, &created_indices).await;
            return;
        }
    }

    // Clear provision blocks — containers exist now, subsequent playbooks must not re-provision
    {
        let inv = inventory.read().unwrap();
        for node in &plan.nodes {
            let host = inv.get_host(&node.hostname);
            host.write().unwrap().clear_provision();
        }
    }

    // Register all LXCs as Machine entries + DNS records
    for node in &plan.nodes {
        let mac = fetch_lxc_mac(&create_client, &node.proxmox_node, node.vmid).await;
        register_cluster_lxc(&state, node, &cluster_name, &node.proxmox_node, mac.as_deref()).await;
    }

    if is_aborted(&state) {
        emit_cluster_event(&state, -1, "aborted", "Deployment aborted — use Cleanup to remove containers, or Retry to continue");
        return;
    }

    // Phase C+D: Install, configure, and form cluster via async Jetpack
    //
    // Single playbook (configure.yml) runs all nodes in parallel:
    //   1. Install rqlite binary (independent per host)
    //   2. Write /etc/hosts for DNS discovery (independent per host)
    //   3. !wait_for_others barrier — all hosts must have /etc/hosts before starting
    //   4. Start rqlite with DNS discovery (all simultaneously)
    //   5. Wait for rqlite readiness
    //
    // Async mode means each host races through steps 1-2 as fast as it can,
    // then waits at the barrier for slower hosts to catch up.
    emit_cluster_event(&state, -1, "installing", "Installing and configuring rqlite (async)...");
    for node in &plan.nodes {
        emit_cluster_event(&state, node.idx as i32, "installing", "Installing rqlite...");
    }

    // Build extra vars for the unified playbook
    let hosts_entries: String = plan.nodes.iter()
        .map(|n| format!("{} rqlite.cluster", n.ip))
        .collect::<Vec<_>>()
        .join("\n");

    let configure_vars = serde_yaml::Value::Mapping({
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("cluster_hosts_entries".into()),
            serde_yaml::Value::String(hosts_entries),
        );
        m.insert(
            serde_yaml::Value::String("bootstrap_expect".into()),
            serde_yaml::Value::String(plan.nodes.len().to_string()),
        );
        m
    });

    let inv_clone = Arc::clone(&inventory);
    let pw = cluster_password.clone();
    let oh = Arc::clone(&output_handler);
    let key_path = management_key_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        run_jetpack_playbook("configure.yml", PLAYBOOK_CONFIGURE, &inv_clone, &pw, key_path.as_deref(), None, Some(configure_vars), Some(oh), true)
    }).await;

    match result {
        Ok(Ok(r)) if r.success => {
            info!("rqlite cluster configured and formed via async Jetpack ({} nodes)", r.hosts_processed);
            for node in &plan.nodes {
                emit_cluster_event(&state, node.idx as i32, "healthy", "Healthy");
            }
        }
        Ok(Ok(r)) => {
            error!("Cluster configuration failed: hosts_processed={}, success={}", r.hosts_processed, r.success);
            emit_cluster_event(&state, -1, "error", "Cluster configuration failed");
            return;
        }
        Ok(Err(e)) => {
            error!("Cluster configuration error: {}", e);
            emit_cluster_event(&state, -1, "error", &format!("Cluster configuration error: {}", e));
            return;
        }
        Err(e) => {
            error!("Cluster configuration task panicked: {}", e);
            emit_cluster_event(&state, -1, "error", "Cluster configuration task panicked");
            return;
        }
    }

    if is_aborted(&state) {
        emit_cluster_event(&state, -1, "aborted", "Deployment aborted — use Cleanup to remove containers, or Retry to continue");
        return;
    }

    // Phase E: Migrate store and switch to HA mode
    emit_cluster_event(&state, -1, "migrating", "Migrating data to cluster...");
    for node in &plan.nodes {
        emit_cluster_event(&state, node.idx as i32, "synchronising", "Syncing data...");
    }

    // Build full cluster topology for failover-aware HA
    let ha_nodes: Vec<ha::HaNode> = plan.nodes.iter().map(|n| ha::HaNode {
        host: format!("{}:4001", n.ip),
        role: n.role.clone(),
    }).collect();
    match ha::enable_ha_remote(&state, &ha_nodes).await {
        Ok(()) => {
            info!("HA mode enabled with remote rqlite cluster ({} nodes)", ha_nodes.len());
            for node in &plan.nodes {
                emit_cluster_event(&state, node.idx as i32, "healthy", "Healthy");
            }
            emit_cluster_event(&state, -1, "complete", "Cluster active");
        }
        Err(e) => {
            error!("Failed to enable HA mode: {}", e);
            emit_cluster_event(&state, -1, "error", &format!("Migration failed: {}", e));
        }
    }
}


/// Dissolve the cluster: stop rqlite on all nodes, destroy LXCs, migrate back to SQLite.
pub async fn dissolve_cluster(state: &AppState) -> Result<()> {
    // Load the cluster plan from settings
    let plan_json = state.store.get_setting("cluster_plan").await
        .map_err(|e| anyhow::anyhow!("Failed to get cluster plan: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No cluster plan found — was the cluster created through Dragonfly?"))?;

    let plan: ClusterPlan = serde_json::from_str(&plan_json)
        .context("Failed to parse cluster plan")?;

    info!("Dissolving cluster with {} nodes", plan.nodes.len());
    emit_cluster_event(state, -1, "dissolving", "Dissolving cluster...");

    // Step 1: Migrate rqlite → SQLite (use existing ha.rs logic)
    // Connect with full cluster topology for failover resilience
    let hosts: Vec<String> = {
        let mut cores: Vec<String> = plan.nodes.iter()
            .filter(|n| n.role == "core")
            .map(|n| format!("{}:4001", n.ip))
            .collect();
        let replicas: Vec<String> = plan.nodes.iter()
            .filter(|n| n.role != "core")
            .map(|n| format!("{}:4001", n.ip))
            .collect();
        cores.extend(replicas);
        cores
    };

    let rqlite_store = RqliteStore::open_cluster(&hosts).await
        .map_err(|e| anyhow::anyhow!("Failed to connect to rqlite for migration: {}", e))?;

    let sqlite_path = "/var/lib/dragonfly/dragonfly.sqlite3";
    let sqlite_store = SqliteStore::open(sqlite_path).await
        .map_err(|e| anyhow::anyhow!("Failed to open SQLite: {}", e))?;

    ha::migrate_rqlite_to_sqlite(&rqlite_store, &sqlite_store).await?;

    // Step 2: Destroy LXCs via Proxmox API
    let client = connect_to_proxmox(state, "create").await
        .context("Failed to connect to Proxmox")?;

    for node in &plan.nodes {
        // Stop the LXC first
        let stop_path = format!(
            "/api2/json/nodes/{}/lxc/{}/status/stop",
            node.proxmox_node, node.vmid
        );
        match client.post(&stop_path, &serde_json::json!({})).await {
            Ok(resp) => {
                // Wait for stop task to complete via UPID
                let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
                if let Some(upid) = body.get("data").and_then(|d| d.as_str()) {
                    let _ = wait_for_proxmox_task(&client, &node.proxmox_node, upid).await;
                }
            }
            Err(e) => warn!("Failed to stop LXC {} on {}: {:?}", node.vmid, node.proxmox_node, e),
        }

        // Delete the LXC (now stopped)
        let delete_path = format!(
            "/api2/json/nodes/{}/lxc/{}",
            node.proxmox_node, node.vmid
        );
        match client.delete(&delete_path).await {
            Ok(resp) => {
                // Wait for delete task to complete
                let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
                if let Some(upid) = body.get("data").and_then(|d| d.as_str()) {
                    let _ = wait_for_proxmox_task(&client, &node.proxmox_node, upid).await;
                }
                info!("Deleted LXC {} on {}", node.vmid, node.proxmox_node);
            }
            Err(e) => warn!("Failed to delete LXC {} on {}: {:?}", node.vmid, node.proxmox_node, e),
        }
    }

    // Step 3: Remove cluster plan and HA flag
    let _ = state.store.put_setting("cluster_plan", "").await;
    let _ = tokio::fs::remove_file(ha::HA_FLAG_FILE).await;

    emit_cluster_event(state, -1, "dissolved", "Cluster dissolved");
    info!("Cluster dissolved successfully");
    Ok(())
}

/// Fetch the auto-generated MAC address for an LXC container from its Proxmox config.
///
/// Queries `/api2/json/nodes/{node}/lxc/{vmid}/config` and parses the `hwaddr=` field
/// from `net0..net7`. Returns `None` if the MAC cannot be determined.
async fn fetch_lxc_mac(
    client: &ProxmoxApiClient,
    node: &str,
    vmid: u32,
) -> Option<String> {
    let path = format!("/api2/json/nodes/{}/lxc/{}/config", node, vmid);
    let resp = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to fetch LXC {} config for MAC: {}", vmid, e);
            return None;
        }
    };

    let val: serde_json::Value = match serde_json::from_slice(&resp.body) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let data = val.get("data")?;
    for i in 0..8 {
        let net_key = format!("net{}", i);
        if let Some(net_cfg) = data.get(&net_key).and_then(|n| n.as_str()) {
            for part in net_cfg.split(',') {
                if let Some(mac) = part.strip_prefix("hwaddr=") {
                    if mac.len() == 17 && mac.contains(':') {
                        return Some(mac.to_lowercase());
                    }
                }
            }
        }
    }

    warn!("No MAC address found in LXC {} config", vmid);
    None
}

/// Register a cluster-deployed LXC as a Machine entry and create DNS records.
///
/// Creates a Machine with `MachineSource::ProxmoxLxc`, sets its IP and hostname,
/// persists it, and triggers DNS record sync (forward A + reverse PTR).
async fn register_cluster_lxc(
    state: &AppState,
    node: &PlannedNode,
    cluster_name: &str,
    proxmox_node: &str,
    mac: Option<&str>,
) {
    // Use real MAC from Proxmox — never fabricate fake MACs
    let mac_addr = match mac {
        Some(m) => m.to_string(),
        None => {
            warn!("No MAC for LXC {} ({}) — skipping machine registration", node.vmid, node.hostname);
            return;
        }
    };

    let identity = MachineIdentity::from_mac(&mac_addr);
    let now = Utc::now();

    let mut machine = Machine {
        id: dragonfly_common::machine::new_machine_id(),
        identity,
        status: dragonfly_common::machine::MachineStatus {
            state: MachineState::Discovered,
            current_ip: Some(node.ip.to_string()),
            last_seen: Some(now),
            ..Default::default()
        },
        hardware: dragonfly_common::machine::HardwareInfo {
            is_virtual: true,
            virt_platform: Some("proxmox-lxc".to_string()),
            ..Default::default()
        },
        config: dragonfly_common::machine::MachineConfig {
            hostname: Some(node.hostname.clone()),
            memorable_name: node.hostname.clone(),
            ..dragonfly_common::machine::MachineConfig::with_mac(&mac_addr)
        },
        metadata: dragonfly_common::machine::MachineMetadata {
            created_at: now,
            updated_at: now,
            labels: std::collections::HashMap::new(),
            source: MachineSource::ProxmoxLxc {
                cluster: cluster_name.to_string(),
                node: proxmox_node.to_string(),
                ctid: node.vmid,
            },
        },
    };

    let machine_id = machine.id;
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            info!(
                "Registered cluster LXC {} ({}) as machine {}",
                node.vmid, node.hostname, machine_id
            );

            // DNS sync — create forward A + reverse PTR records
            if let Err(e) = crate::dns_sync::sync_machine_dns(
                &state.store,
                &machine,
                dragonfly_common::dns::DnsRecordSource::ClusterDeploy,
            )
            .await
            {
                warn!("DNS sync failed for cluster LXC {}: {}", node.hostname, e);
            }
        }
        Err(e) => {
            error!(
                "Failed to register cluster LXC {} as machine: {}",
                node.vmid, e
            );
        }
    }
}

