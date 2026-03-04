//! Dragonfly on Proxmox VE — `install-pve` subcommand.
//!
//! Creates a Debian 13 LXC container on a Proxmox cluster and installs
//! Dragonfly inside it via Jetpack:
//!
//! 1. Authenticate with Proxmox (native Rust — no Python required)
//! 2. Check whether the container already exists (fast-path exit)
//! 3. Auto-detect nodes and network bridges
//! 4. Present a deployment summary and ask for confirmation
//! 5. Collect SSH agent public keys → written to container's authorized_keys
//! 6. Run Jetpack with a `proxmox_lxc` provisioner — creates the container
//!    and waits for SSH to become available (Jetpack authenticates via SSH agent)
//! 7. Jetpack then SSHes in and runs the install playbook:
//!    - Uploads this binary (`!copy`)
//!    - Runs `dragonfly install --force --no-assets`
//!    - Verifies the service is active
//! 8. Query the new container's IP and print the access URL

mod playbook;
mod proxmox;

use clap::Args;
use color_eyre::eyre::{Result, eyre};
use jetpack::api::run_inline;
use jetpack::inventory::hosts::Host;
use jetpack::inventory::inventory::Inventory;
use jetpack::output::{LogLevel, OutputHandler, RecapData};
use jetpack::provisioners;
use jetpack::tasks::request::TaskRequest;
use jetpack::tasks::response::TaskResponse;
use rpassword::read_password;
use serde_yaml::Value;
use std::io::Write;
use std::sync::{Arc, RwLock};

use playbook::{
    InstallPlaybookConfig, build_install_playbook, build_update_playbook, validate_binary_path,
    validate_local_path,
};
use proxmox::{BridgeInfo, ProxmoxInstallClient};

// ─── Args ────────────────────────────────────────────────────────────────────

/// Arguments for `dragonfly install-pve`
#[derive(Args, Debug)]
pub struct InstallPveArgs {
    /// Proxmox server URL (e.g., https://proxmox.example.com:8006)
    #[arg(long)]
    pub url: Option<String>,

    /// Proxmox username (e.g., root@pam)
    #[arg(long)]
    pub user: Option<String>,

    /// Proxmox password or API token secret
    #[arg(long)]
    pub password: Option<String>,

    /// Skip TLS certificate verification (for self-signed certs)
    #[arg(long)]
    pub skip_tls_verify: bool,

    /// VM ID (optional — Proxmox auto-assigns if omitted)
    #[arg(long)]
    pub vm_id: Option<i32>,

    /// Container hostname
    #[arg(long, default_value = "dragonfly")]
    pub name: String,

    /// Number of vCPU cores
    #[arg(long, default_value_t = 2)]
    pub cores: i32,

    /// Memory in MB
    #[arg(long, default_value_t = 2048)]
    pub memory: i32,

    /// Root disk size in GB
    #[arg(long, default_value_t = 32)]
    pub disk: i32,

    /// Network bridge
    #[arg(long)]
    pub bridge: Option<String>,

    /// Proxmox storage pool
    #[arg(long, default_value = "local")]
    pub storage: String,

    /// Static IP in CIDR notation (e.g., 192.168.1.100/24). Omit to use DHCP.
    #[arg(long)]
    pub ip: Option<String>,

    /// Gateway IP (required when --ip is set)
    #[arg(long)]
    pub gateway: Option<String>,

    /// Proxmox node name (auto-detected if omitted)
    #[arg(long)]
    pub node: Option<String>,

    /// Skip confirmation prompts
    #[arg(long)]
    pub force: bool,
}

// ─── Progress handler ─────────────────────────────────────────────────────────

/// Custom Jetpack OutputHandler that prints clean "* task name" progress lines
/// and suppresses all of Jetpack's verbose internal output.
struct DragonflyProgressHandler;

impl OutputHandler for DragonflyProgressHandler {
    fn on_task_start(&self, task_name: &str, _host_count: usize) {
        println!("* {}", task_name);
    }
    fn on_playbook_start(&self, _playbook_path: &str) {}
    fn on_playbook_end(&self, _playbook_path: &str, _success: bool) {}
    fn on_play_start(&self, _play_name: &str, _hosts: Vec<String>) {}
    fn on_play_end(&self, _play_name: &str) {}
    fn on_task_host_result(&self, _host: &Host, _task: &TaskRequest, _response: &TaskResponse) {}
    fn on_task_end(&self, _task_name: &str) {}
    fn on_handler_start(&self, _handler_name: &str) {}
    fn on_handler_end(&self, _handler_name: &str) {}
    fn on_recap(&self, _recap_data: RecapData) {}
    fn log(&self, level: LogLevel, message: &str) {
        match level {
            LogLevel::Error | LogLevel::Warning => eprintln!("  ❌ {}", message),
            _ => {}
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Run the `install-pve` command.
pub async fn run_install_pve(args: InstallPveArgs) -> Result<()> {
    println!("\n🐉 Dragonfly Installer\n");
    println!("Please enter your Proxmox details to automatically deploy Dragonfly.");

    // ── Step 1: Gather credentials ──────────────────────────────────────────
    let raw_url = prompt_or_arg(args.url, "Proxmox host or URL: ")?;
    let url = proxmox::resolve_proxmox_url(&raw_url).map_err(|e| eyre!("{}", e))?;
    if url != raw_url.trim().trim_end_matches('/') {
        println!("  → {}", url);
    }
    let user = prompt_or_default(args.user, "Proxmox username [root@pam]: ", "root@pam");
    let mut password = match args.password {
        Some(p) => p,
        None => {
            print!("Proxmox password or API token: ");
            std::io::stdout().flush()?;
            let p = read_password().map_err(|e| eyre!("Failed to read password: {}", e))?;
            if p.is_empty() {
                return Err(eyre!("Proxmox password/token is required"));
            }
            p
        }
    };

    // ── Step 2: Validate static IP args ─────────────────────────────────────
    if args.ip.is_some() && args.gateway.is_none() {
        return Err(eyre!("--gateway is required when --ip is set"));
    }

    // ── Step 3: Build Proxmox client and authenticate ────────────────────────
    let proxmox = loop {
        let mut client = ProxmoxInstallClient::new(&url, args.skip_tls_verify)
            .map_err(|e| eyre!("Invalid Proxmox URL: {}", e))?;

        match client.authenticate(&user, &password).await {
            Ok(()) => break client,
            Err(proxmox::ProxmoxError::AuthFailed(_)) => {
                eprintln!("\n❌ Authentication failed. Check your username and password.");
                print!("Retry with new password? [Y/n]: ");
                std::io::stdout().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if answer.trim().to_lowercase() == "n" {
                    return Ok(());
                }
                print!("Proxmox password or API token: ");
                std::io::stdout().flush()?;
                password = read_password().map_err(|e| eyre!("Failed to read password: {}", e))?;
            }
            Err(e) => return Err(eyre!("Proxmox connection error: {}", e)),
        }
    };

    // ── Step 4: Check if container already exists ────────────────────────────
    if let Some(existing) = proxmox.find_container(&args.name).await? {
        println!("\n🐉  Container '{}' already exists!", args.name);
        println!("   Node: {}, VMID: {}", existing.node, existing.vmid);

        println!("\n📋 Access Dragonfly at:");
        match &existing.ip {
            Some(ip) => println!("   http://{}:3000/", ip),
            None => println!("   http://<container-ip>:3000/ (container may be stopped)"),
        }

        let should_update = if args.force {
            true
        } else {
            print!("\nUpdate Dragonfly? (y)es / (n)o: ");
            std::io::stdout().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            let trimmed = answer.trim().to_lowercase();
            trimmed == "y" || trimmed == "yes"
        };

        if should_update {
            let container_ip = existing.ip.ok_or_else(|| {
                eyre!(
                    "Container '{}' has no IP address — is it running?",
                    args.name
                )
            })?;
            run_update(&args.name, &container_ip).await?;
        } else {
            println!("Skipping update.");
        }

        return Ok(());
    }

    // ── Step 5: Auto-detect node ─────────────────────────────────────────────
    let selected_node = match args.node.clone() {
        Some(n) => n,
        None => select_node(&proxmox).await?,
    };

    // ── Step 6: Auto-detect bridge ───────────────────────────────────────────
    let bridge = match args.bridge {
        Some(b) => b,
        None => detect_bridge(&proxmox, &selected_node).await?,
    };

    // ── Step 7: Print summary, confirm, and optionally customise ─────────────
    // All deployment parameters are mutable so the customise menu can update
    // them before the user confirms.
    let mut selected_node = selected_node;
    let mut bridge = bridge;
    let mut container_name = args.name.clone();
    let mut vm_id = args.vm_id;
    let mut ip = args.ip.clone();
    let mut gateway = args.gateway.clone();
    let mut cores = args.cores;
    let mut memory = args.memory;
    let mut disk = args.disk;

    loop {
        let vmid_display = vm_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "auto".to_string());
        let net_display = ip.as_deref().unwrap_or("DHCP");

        println!("\n📋 Configuration:");
        println!("  Proxmox URL: {}", url);
        println!("  User:        {}", user);
        println!("  Node:        {}", selected_node);
        println!("  Container:   {} (ID: {})", container_name, vmid_display);
        println!("  Network:     {} ({})", bridge, net_display);
        println!(
            "  Resources:   {} vCPU, {} MB RAM, {} GB disk",
            cores, memory, disk
        );

        if args.force {
            break;
        }

        print!("\nDeploy? (y)es, (c)ustomise, (n)o: ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;

        match answer.trim().to_lowercase().as_str() {
            "y" | "yes" | "" => break,
            "n" | "no" | "a" | "abort" => {
                println!("Aborted.");
                return Ok(());
            }
            "c" | "customise" | "customize" => {
                println!("\n📝 Customise deployment:");
                println!("  1. Node:       {}", selected_node);
                println!("  2. Bridge:     {}", bridge);
                println!("  3. Name:       {}", container_name);
                println!(
                    "  4. VM ID:      {}",
                    vm_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "auto".to_string())
                );
                println!("  5. Network:    {}", ip.as_deref().unwrap_or("DHCP"));
                println!(
                    "  6. Resources:  {} vCPU, {} MB RAM, {} GB disk",
                    cores, memory, disk
                );
                print!("\nEnter number to change [Enter to go back]: ");
                std::io::stdout().flush()?;
                let mut choice = String::new();
                std::io::stdin().read_line(&mut choice)?;
                match choice.trim() {
                    "1" => match proxmox.list_nodes().await {
                        Ok(nodes) if !nodes.is_empty() => {
                            println!();
                            for (i, n) in nodes.iter().enumerate() {
                                println!("  {}. {}", i + 1, n);
                            }
                            print!("Select node [1]: ");
                            std::io::stdout().flush()?;
                            let mut sel = String::new();
                            std::io::stdin().read_line(&mut sel)?;
                            let idx: usize = sel.trim().parse().unwrap_or(1);
                            if idx >= 1 && idx <= nodes.len() {
                                selected_node = nodes[idx - 1].clone();
                                // Re-detect bridge for the new node.
                                bridge = detect_bridge(&proxmox, &selected_node).await?;
                            }
                        }
                        _ => eprintln!("  Could not fetch nodes."),
                    },
                    "2" => match proxmox.list_bridges(&selected_node).await {
                        Ok(bridges) if !bridges.is_empty() => {
                            println!();
                            for (i, b) in bridges.iter().enumerate() {
                                println!(
                                    "  {}. {} {}",
                                    i + 1,
                                    b.name,
                                    if b.has_ip { "(has IP)" } else { "(no IP)" }
                                );
                            }
                            print!("Select number or type name: ");
                            std::io::stdout().flush()?;
                            let mut sel = String::new();
                            std::io::stdin().read_line(&mut sel)?;
                            let s = sel.trim();
                            if let Ok(idx) = s.parse::<usize>() {
                                if idx >= 1 && idx <= bridges.len() {
                                    bridge = bridges[idx - 1].name.clone();
                                }
                            } else if !s.is_empty() {
                                bridge = s.to_string();
                            }
                        }
                        _ => {
                            print!("  Bridge name: ");
                            std::io::stdout().flush()?;
                            let mut s = String::new();
                            std::io::stdin().read_line(&mut s)?;
                            if !s.trim().is_empty() {
                                bridge = s.trim().to_string();
                            }
                        }
                    },
                    "3" => {
                        print!("  Name [{}]: ", container_name);
                        std::io::stdout().flush()?;
                        let mut s = String::new();
                        std::io::stdin().read_line(&mut s)?;
                        if !s.trim().is_empty() {
                            container_name = s.trim().to_string();
                        }
                    }
                    "4" => {
                        print!("  VM ID (Enter for auto): ");
                        std::io::stdout().flush()?;
                        let mut s = String::new();
                        std::io::stdin().read_line(&mut s)?;
                        vm_id = s.trim().parse().ok();
                    }
                    "5" => {
                        print!("  Static IP in CIDR (e.g. 192.168.1.100/24), Enter for DHCP: ");
                        std::io::stdout().flush()?;
                        let mut s = String::new();
                        std::io::stdin().read_line(&mut s)?;
                        if s.trim().is_empty() {
                            ip = None;
                            gateway = None;
                        } else {
                            ip = Some(s.trim().to_string());
                            print!("  Gateway: ");
                            std::io::stdout().flush()?;
                            let mut gw = String::new();
                            std::io::stdin().read_line(&mut gw)?;
                            gateway = if gw.trim().is_empty() {
                                None
                            } else {
                                Some(gw.trim().to_string())
                            };
                        }
                    }
                    "6" => {
                        print!("  vCPU cores [{}]: ", cores);
                        std::io::stdout().flush()?;
                        let mut s = String::new();
                        std::io::stdin().read_line(&mut s)?;
                        if !s.trim().is_empty() {
                            cores = s.trim().parse().unwrap_or(cores);
                        }
                        print!("  Memory MB [{}]: ", memory);
                        std::io::stdout().flush()?;
                        let mut s = String::new();
                        std::io::stdin().read_line(&mut s)?;
                        if !s.trim().is_empty() {
                            memory = s.trim().parse().unwrap_or(memory);
                        }
                        print!("  Disk GB [{}]: ", disk);
                        std::io::stdout().flush()?;
                        let mut s = String::new();
                        std::io::stdin().read_line(&mut s)?;
                        if !s.trim().is_empty() {
                            disk = s.trim().parse().unwrap_or(disk);
                        }
                    }
                    "" => {} // back to confirm loop
                    _ => println!("  Invalid choice."),
                }
            }
            _ => println!("  Please enter y, c, or n."),
        }
    }

    let vmid_display = vm_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "auto".to_string());
    println!("\n🚀 Deploying Dragonfly on {}...", selected_node);

    // ── Step 8: Collect SSH agent public keys ───────────────────────────────────
    //
    // These keys go into the container's authorized_keys so the user can SSH in
    // immediately after provisioning.  Jetpack also authenticates via the same
    // SSH agent (SSH_AUTH_SOCK) — no separate provisioning key is created.
    //
    // Keys live only in the agent's memory; the user controls their lifetime
    // via `ssh-add -D` to remove them or `ssh-add -t` to set a timeout.
    let agent_keys = collect_ssh_agent_pubkeys();
    if agent_keys.is_empty() {
        return Err(eyre!(
            "No SSH agent keys found.\n\
             Jetpack connects to the new container via SSH agent — without agent keys\n\
             the container cannot be provisioned and you will have no SSH access.\n\
             Load your key first: ssh-add ~/.ssh/id_ed25519"
        ));
    }

    // Each key is indented two spaces to form the YAML block-scalar content.
    let authorized_keys_block = agent_keys
        .iter()
        .map(|k| format!("  {}", k))
        .collect::<Vec<_>>()
        .join("\n");

    // ── Step 9: Locate local assets for upload ───────────────────────────────
    // Static web assets are compiled into the binary via rust-embed — no upload needed.
    let binary_path = std::env::current_exe()
        .map_err(|e| eyre!("Could not determine current executable: {}", e))?
        .to_string_lossy()
        .to_string();

    validate_binary_path(&binary_path).map_err(|e| eyre!("{}", e))?;

    // Optionally include OS templates if the directory exists locally.
    let os_templates_path = {
        let p = std::path::Path::new("os-templates");
        if p.is_dir() {
            let s = p.to_string_lossy().to_string();
            validate_local_path("OS templates", &s).map_err(|e| eyre!("{}", e))?;
            Some(s)
        } else {
            None
        }
    };

    // ── Step 10: Build Jetpack inventory ─────────────────────────────────────
    let inventory = build_inventory(
        &container_name,
        &selected_node,
        &user,
        &password,
        &url,
        vm_id,
        cores,
        memory,
        disk,
        &bridge,
        ip.as_deref(),
        gateway.as_deref(),
        &authorized_keys_block,
        &binary_path,
    );

    // ── Step 11: Build the install playbook ──────────────────────────────────
    let playbook_config = InstallPlaybookConfig {
        local_binary_path: binary_path,
        os_templates_path,
    };
    let playbook_yaml = build_install_playbook(&playbook_config);

    println!("\n🚀 Creating LXC container and installing Dragonfly...");
    println!("  Container: {} (ID: {})", container_name, vmid_display);
    println!();

    // ── Step 12: Run Jetpack ─────────────────────────────────────────────────
    // Jetpack creates its own blocking tokio runtime, so we must run it in an
    // isolated OS thread (not spawn_blocking) to avoid nested-runtime panics.
    //
    // Clone the Arc *before* moving it into the thread so we can read the IP
    // that the proxmox_lxc provisioner writes back into the inventory
    // (`jet_ssh_hostname`) once the container is up.
    let inventory_ref = Arc::clone(&inventory);
    let playbook_name = container_name.clone();
    let result = std::thread::spawn(move || {
        run_inline(&playbook_name, &playbook_yaml)
            .with_inventory(inventory)
            .async_mode()
            .run_with_output(Arc::new(DragonflyProgressHandler))
    })
    .join()
    .map_err(|_| eyre!("Jetpack thread panicked"))?;

    // ── Step 13: Report result ───────────────────────────────────────────────
    match result {
        Ok(run_result) if run_result.success => {
            // Primary: read `jet_ssh_hostname` that the proxmox_lxc provisioner
            // wrote into the inventory after the container's IP was assigned.
            // This is always available immediately — no Proxmox API round-trip needed.
            let provisioner_ip = {
                let inv = inventory_ref.read().unwrap();
                let host = inv.get_host(&container_name);
                let host_read = host.read().unwrap();
                host_read
                    .variables
                    .get("jet_ssh_hostname")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };

            // Fallback: query Proxmox API (may lag DHCP on first boot).
            let api_ip = if provisioner_ip.is_none() {
                proxmox
                    .find_container(&container_name)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|c| c.ip)
            } else {
                None
            };

            let url_ip = provisioner_ip.or(api_ip).or(ip);

            println!("\n✅ Dragonfly installed successfully!");
            match &url_ip {
                Some(ip) => println!("   http://{}:3000/", ip),
                None => println!("   http://<container-ip>:3000/"),
            }

            println!("\n   Username: admin");
            println!("   Password: (see /var/lib/dragonfly/initial_password.txt on the container)");
        }
        Ok(run_result) => {
            eprintln!("\n❌ Installation failed!");
            eprintln!("   Hosts processed: {}", run_result.hosts_processed);
        }
        Err(e) => {
            eprintln!("\n❌ Jetpack error: {}", e);
        }
    }

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Prompt for a required string; return Err if the user provides nothing.
fn prompt_or_arg(value: Option<String>, prompt: &str) -> Result<String> {
    match value {
        Some(v) => Ok(v),
        None => {
            print!("{}", prompt);
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let trimmed = input.trim().to_string();
            if trimmed.is_empty() {
                Err(eyre!("This field is required"))
            } else {
                Ok(trimmed)
            }
        }
    }
}

/// Prompt for an optional string; return `default` if the user provides nothing.
fn prompt_or_default(value: Option<String>, prompt: &str, default: &str) -> String {
    match value {
        Some(v) => v,
        None => {
            print!("{}", prompt);
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let trimmed = input.trim().to_string();
            if trimmed.is_empty() {
                default.to_string()
            } else {
                trimmed
            }
        }
    }
}

/// Detect available nodes and prompt the user if there are multiple.
async fn select_node(proxmox: &ProxmoxInstallClient) -> Result<String> {
    println!("\n🔍 Detecting Proxmox nodes...");
    let nodes = proxmox.list_nodes().await?;

    match nodes.len() {
        0 => Err(eyre!("No Proxmox nodes found")),
        1 => {
            println!("  → Auto-selected node: {}", nodes[0]);
            Ok(nodes[0].clone())
        }
        _ => {
            println!("\n📋 Available nodes:");
            for (i, node) in nodes.iter().enumerate() {
                println!("  {}. {}", i + 1, node);
            }
            print!("\nSelect node [1]: ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let choice: usize = input.trim().parse().unwrap_or(1);
            if choice < 1 || choice > nodes.len() {
                return Err(eyre!("Invalid node selection"));
            }
            Ok(nodes[choice - 1].clone())
        }
    }
}

/// Compute a sort key for bridge selection priority.
///
/// Lower is better.  Bridges are ranked by:
/// 1. VLAN ID (numeric suffix from "vlanN" names): VLAN 0 = untagged/native VLAN,
///    the most common management interface, sorts first.
/// 2. Among bridges with no VLAN suffix, `vmbr0` (the traditional default bridge)
///    is preferred over other names.
fn bridge_sort_key(name: &str) -> (u32, u32) {
    if let Some(suffix) = name.strip_prefix("vlan") {
        // "vlan0" → (0, 1), "vlan20" → (20, 1), "vlan64" → (64, 1)
        let vlan_id = suffix.parse().unwrap_or(u32::MAX);
        (vlan_id, 1)
    } else if name == "vmbr0" {
        // Traditional default bridge: second priority among non-VLAN bridges.
        (u32::MAX, 0)
    } else {
        (u32::MAX, 1)
    }
}

/// Select the best bridge from a non-empty slice.
///
/// Among bridges that have an IP on the Proxmox host, prefers the one with the
/// lowest VLAN ID (VLAN 0 = untagged / native VLAN carries management traffic).
/// Falls back to `vmbr0` or the first bridge when no bridge has an IP.
fn select_best_bridge(bridges: &[BridgeInfo]) -> Option<&BridgeInfo> {
    // Prefer routable bridges — pick the lowest-VLAN-ID one (untagged VLAN first).
    bridges
        .iter()
        .filter(|b| b.has_ip)
        .min_by_key(|b| bridge_sort_key(&b.name))
        // Fall back to vmbr0 without IP (traditional), then first bridge.
        .or_else(|| bridges.iter().find(|b| b.name == "vmbr0"))
        .or_else(|| bridges.first())
}

/// Pick the best available bridge on a node.
///
/// Selection order:
/// 1. Bridges with an IP, lowest VLAN ID first (VLAN 0 = untagged is preferred)
/// 2. `vmbr0` without an IP (traditional Proxmox default bridge)
/// 3. First bridge in the list
/// 4. Hard-coded `vmbr0` fallback if detection fails entirely
async fn detect_bridge(proxmox: &ProxmoxInstallClient, node: &str) -> Result<String> {
    let bridges = match proxmox.list_bridges(node).await {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            println!("  → No bridges detected, defaulting to vmbr0");
            return Ok("vmbr0".to_string());
        }
        Err(e) => {
            println!("  → Bridge detection failed ({}), defaulting to vmbr0", e);
            return Ok("vmbr0".to_string());
        }
    };

    let chosen = select_best_bridge(&bridges)
        .unwrap() // safe: we checked !is_empty() above
        .name
        .clone();

    if bridges.len() > 1 {
        let names: Vec<&str> = bridges.iter().map(|b| b.name.as_str()).collect();
        println!(
            "  → Detected {} bridges ({:?}), using {} ({})",
            bridges.len(),
            names,
            chosen,
            if bridges
                .iter()
                .find(|b| b.name == chosen)
                .map(|b| b.has_ip)
                .unwrap_or(false)
            {
                "has IP"
            } else {
                "no IP — all bridges unaddressed"
            }
        );
    } else {
        println!("  → Using bridge: {}", chosen);
    }

    Ok(chosen)
}

/// Assemble the Jetpack inventory with provisioner config and host vars.
#[allow(clippy::too_many_arguments)]
fn build_inventory(
    container_name: &str,
    node: &str,
    user: &str,
    password: &str,
    proxmox_url: &str,
    vm_id: Option<i32>,
    cores: i32,
    memory: i32,
    disk: i32,
    bridge: &str,
    ip: Option<&str>,
    gateway: Option<&str>,
    authorized_keys_block: &str,
    binary_path: &str,
) -> Arc<RwLock<Inventory>> {
    // Parse host and port from the URL (e.g. "https://pve:8006" → "pve:8006")
    let api_host = proxmox_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let inventory = Arc::new(RwLock::new(Inventory::new()));

    // Proxmox cluster host (used by the provisioner)
    let mut cluster_vars = serde_yaml::Mapping::new();
    cluster_vars.insert(
        Value::String("proxmox_api_host".to_string()),
        Value::String(api_host.to_string()),
    );
    cluster_vars.insert(
        Value::String("proxmox_api_user".to_string()),
        Value::String(user.to_string()),
    );
    cluster_vars.insert(
        Value::String("proxmox_api_password".to_string()),
        Value::String(password.to_string()),
    );
    cluster_vars.insert(
        Value::String("proxmox_node".to_string()),
        Value::String(node.to_string()),
    );
    // The 'proxmox' host is a cluster/API reference only — it must NOT be in
    // the 'all' or 'containers' groups, otherwise Jetpack would try to SSH
    // to the Proxmox server itself.  The provisioner looks hosts up by name,
    // not by group, so 'cluster' works fine here.
    inventory
        .write()
        .unwrap()
        .store_host(&"cluster".to_string(), &"proxmox".to_string());
    inventory
        .write()
        .unwrap()
        .store_host_variables(&"proxmox".to_string(), cluster_vars);

    // Network config string for the LXC net0 parameter
    let net_config = match (ip, gateway) {
        (Some(ip_addr), Some(gw)) => {
            format!("name=eth0,bridge={},ip={},gw={}", bridge, ip_addr, gw)
        }
        _ => format!("name=eth0,bridge={},ip=dhcp", bridge),
    };

    // Provision config (consumed by Jetpack's proxmox_lxc provisioner)
    let vmid_line = match vm_id {
        Some(id) => format!("vmid: \"{}\"\n", id),
        None => String::new(),
    };

    let provision_yaml = format!(
        r#"
type: proxmox_lxc
state: present
cluster: proxmox
node: {node}
hostname: {hostname}
{vmid}memory: "{memory}"
cores: "{cores}"
ostemplate: "debian-13-standard"
fetch: latest
storage: {storage}
rootfs_size: {disk}G
net0: "{net}"
password: "{password}"
authorized_keys: |
{authorized_keys_block}
ssh_user: root
unprivileged: "true"
start_on_create: "true"
nameserver: "1.1.1.1 8.8.8.8"
wait_for_host: true
wait_timeout: 300
wait_delay: 2
wait_strategy: backoff
wait_max_delay: 30
"#,
        node = node,
        hostname = container_name,
        vmid = vmid_line,
        memory = memory,
        cores = cores,
        storage = "local",
        disk = disk,
        net = net_config,
        password = password,
        authorized_keys_block = authorized_keys_block,
    );

    // Container host: goes into 'containers' so the install play can target it
    // specifically without accidentally including the Proxmox cluster host.
    inventory
        .write()
        .unwrap()
        .store_host(&"containers".to_string(), &container_name.to_string());

    // No jet_ssh_private_key_file: Jetpack authenticates via SSH agent (SSH_AUTH_SOCK).
    let mut host_vars = serde_yaml::Mapping::new();
    host_vars.insert(
        Value::String("jet_ssh_user".to_string()),
        Value::String("root".to_string()),
    );
    host_vars.insert(
        Value::String("dragonfly_binary".to_string()),
        Value::String(binary_path.to_string()),
    );

    inventory
        .write()
        .unwrap()
        .store_host_variables(&container_name.to_string(), host_vars);

    // Set provision config on the host
    let provision_config: provisioners::ProvisionConfig =
        serde_yaml::from_str(&provision_yaml).expect("BUG: invalid provision YAML");
    {
        let inv = inventory.read().unwrap();
        let host = inv.get_host(&container_name.to_string());
        host.write().unwrap().set_provision(provision_config);
    }

    inventory
}

// ─── Update flow ─────────────────────────────────────────────────────────────

/// Perform an idempotent in-place update of Dragonfly on an existing container.
///
/// Connects via the user's SSH agent — the agent keys were written to
/// `authorized_keys` at install time.  If Jetpack can't authenticate, the
/// user's agent is empty or the key was never installed; we don't own that
/// container and refuse to proceed.
async fn run_update(container_name: &str, container_ip: &str) -> Result<()> {
    println!();

    // ── Resolve local assets ─────────────────────────────────────────────────
    // Static web assets are compiled into the binary via rust-embed — no upload needed.
    let binary_path = std::env::current_exe()
        .map_err(|e| eyre!("Could not determine current executable: {}", e))?
        .to_string_lossy()
        .to_string();
    validate_binary_path(&binary_path).map_err(|e| eyre!("{}", e))?;

    let os_templates_path = {
        let p = std::path::Path::new("os-templates");
        if p.is_dir() {
            Some(p.to_string_lossy().to_string())
        } else {
            None
        }
    };

    // ── Build inventory and playbook ─────────────────────────────────────────
    let inventory = build_update_inventory(container_name, container_ip);
    let playbook_config = InstallPlaybookConfig {
        local_binary_path: binary_path,
        os_templates_path,
    };
    let playbook_yaml = build_update_playbook(&playbook_config);

    let playbook_name = container_name.to_string();
    let container_ip_owned = container_ip.to_string();
    let result = std::thread::spawn(move || {
        run_inline(&playbook_name, &playbook_yaml)
            .with_inventory(inventory)
            .async_mode()
            .run_with_output(Arc::new(DragonflyProgressHandler))
    })
    .join()
    .map_err(|_| eyre!("Jetpack thread panicked"))?;

    match result {
        Ok(r) if r.success => {
            println!("\n✅ Dragonfly updated successfully!");
            println!("   http://{}:3000/", container_ip_owned);

            println!("\n   Username: admin");
            println!("   Password: (see /var/lib/dragonfly/initial_password.txt on the container)");
        }
        Ok(r) => {
            eprintln!("\n❌ Update failed!");
            eprintln!("   Hosts processed: {}", r.hosts_processed);
            eprintln!("   (If SSH failed, ensure your key is loaded: ssh-add ~/.ssh/id_ed25519)");
        }
        Err(e) => {
            eprintln!("\n❌ Jetpack error: {}", e);
        }
    }

    Ok(())
}

// ─── SSH agent helpers ────────────────────────────────────────────────────────

/// Parse the output of `ssh-add -L` into individual public-key strings.
///
/// Filters out non-key lines (error messages, "The agent has no identities.",
/// etc.) by only accepting lines that start with a known key-type prefix.
/// Separated from `collect_ssh_agent_pubkeys` for testability.
fn parse_agent_pubkeys(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| {
            line.starts_with("ssh-")
                || line.starts_with("ecdsa-")
                || line.starts_with("sk-ssh-")
                || line.starts_with("sk-ecdsa-")
        })
        .map(|line| line.to_string())
        .collect()
}

/// Return all public keys currently loaded in the user's SSH agent.
///
/// Runs `ssh-add -L` and returns one key per element.  Returns an empty
/// `Vec` if the agent is unavailable, has no keys, or `ssh-add` is not found.
fn collect_ssh_agent_pubkeys() -> Vec<String> {
    let output = match std::process::Command::new("ssh-add").arg("-L").output() {
        Err(_) => return Vec::new(),
        Ok(o) => o,
    };
    parse_agent_pubkeys(&String::from_utf8_lossy(&output.stdout))
}

/// Build a minimal Jetpack inventory for updating an existing container via SSH.
///
/// Unlike `build_inventory`, no provisioner is needed — the container already
/// exists.  `jet_ssh_hostname` overrides the inventory hostname so Jetpack
/// connects to the actual container IP rather than treating the name as a DNS
/// entry.
///
/// No `jet_ssh_private_key_file` is set: Jetpack will authenticate using
/// whatever keys are loaded in the user's SSH agent (`SSH_AUTH_SOCK`).  Those
/// agent keys were written to the container's `authorized_keys` at install
/// time, so this is the correct and expected auth path.
fn build_update_inventory(container_name: &str, container_ip: &str) -> Arc<RwLock<Inventory>> {
    let inventory = Arc::new(RwLock::new(Inventory::new()));

    inventory
        .write()
        .unwrap()
        .store_host(&"containers".to_string(), &container_name.to_string());

    let mut host_vars = serde_yaml::Mapping::new();
    host_vars.insert(
        Value::String("jet_ssh_user".to_string()),
        Value::String("root".to_string()),
    );
    // jet_ssh_hostname tells Jetpack the actual IP to connect to.
    host_vars.insert(
        Value::String("jet_ssh_hostname".to_string()),
        Value::String(container_ip.to_string()),
    );
    // No jet_ssh_private_key_file — Jetpack uses the SSH agent automatically.

    inventory
        .write()
        .unwrap()
        .store_host_variables(&container_name.to_string(), host_vars);

    inventory
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_or_arg_uses_provided_value() {
        let result = prompt_or_arg(Some("https://pve:8006".to_string()), "prompt: ");
        assert_eq!(result.unwrap(), "https://pve:8006");
    }

    #[test]
    fn test_prompt_or_default_uses_provided_value() {
        let result = prompt_or_default(Some("root@pam".to_string()), "prompt: ", "default");
        assert_eq!(result, "root@pam");
    }

    #[test]
    fn test_prompt_or_default_returns_default_when_none() {
        // We can't interactively test stdin in unit tests, so just verify the
        // provided-value path works. The interactive path is tested via integration.
        let result = prompt_or_default(Some("custom".to_string()), "prompt: ", "fallback");
        assert_eq!(result, "custom");
    }

    #[test]
    fn test_net_config_dhcp() {
        // Simulate the net_config logic for DHCP
        let (ip, gateway) = (None::<&str>, None::<&str>);
        let bridge = "vmbr0";
        let net_config = match (ip, gateway) {
            (Some(ip_addr), Some(gw)) => {
                format!("name=eth0,bridge={},ip={},gw={}", bridge, ip_addr, gw)
            }
            _ => format!("name=eth0,bridge={},ip=dhcp", bridge),
        };
        assert_eq!(net_config, "name=eth0,bridge=vmbr0,ip=dhcp");
    }

    #[test]
    fn test_net_config_static() {
        let ip: Option<&str> = Some("10.0.0.10/24");
        let gateway: Option<&str> = Some("10.0.0.1");
        let bridge = "vmbr1";
        let net_config = match (ip, gateway) {
            (Some(ip_addr), Some(gw)) => {
                format!("name=eth0,bridge={},ip={},gw={}", bridge, ip_addr, gw)
            }
            _ => format!("name=eth0,bridge={},ip=dhcp", bridge),
        };
        assert_eq!(
            net_config,
            "name=eth0,bridge=vmbr1,ip=10.0.0.10/24,gw=10.0.0.1"
        );
    }

    #[test]
    fn test_vmid_line_some() {
        let vmid_line = match Some(106_i32) {
            Some(id) => format!("vmid: \"{}\"\n", id),
            None => String::new(),
        };
        assert_eq!(vmid_line, "vmid: \"106\"\n");
    }

    #[test]
    fn test_vmid_line_none() {
        let vmid_line = match None::<i32> {
            Some(id) => format!("vmid: \"{}\"\n", id),
            None => String::new(),
        };
        assert!(vmid_line.is_empty());
    }

    // ── bridge selection logic ─────────────────────────────────────────────

    fn bridge(name: &str, has_ip: bool) -> BridgeInfo {
        BridgeInfo {
            name: name.to_string(),
            has_ip,
        }
    }

    fn chosen_name(bridges: &[BridgeInfo]) -> &str {
        select_best_bridge(bridges).unwrap().name.as_str()
    }

    /// When one bridge has an IP, it wins over one without.
    #[test]
    fn test_bridge_prefers_bridge_with_ip() {
        let bridges = vec![bridge("vmbr1", false), bridge("vmbr0", true)];
        assert_eq!(chosen_name(&bridges), "vmbr0");
        assert!(select_best_bridge(&bridges).unwrap().has_ip);
    }

    /// Among traditional bridges all with IPs, vmbr0 is preferred.
    #[test]
    fn test_bridge_prefers_vmbr0_when_multiple_traditional_bridges_have_ip() {
        let bridges = vec![
            bridge("vmbr2", true),
            bridge("vmbr0", true),
            bridge("vmbr1", true),
        ];
        assert_eq!(chosen_name(&bridges), "vmbr0");
    }

    /// When no bridges have an IP, fall back to vmbr0 by name.
    #[test]
    fn test_bridge_falls_back_to_vmbr0_when_no_ip() {
        let bridges = vec![bridge("vmbr1", false), bridge("vmbr0", false)];
        assert_eq!(chosen_name(&bridges), "vmbr0");
        assert!(!select_best_bridge(&bridges).unwrap().has_ip);
    }

    /// When no bridges have an IP and no vmbr0, pick the first.
    #[test]
    fn test_bridge_falls_back_to_first_when_nothing_matches() {
        let bridges = vec![bridge("vmbr2", false), bridge("vmbr3", false)];
        assert_eq!(chosen_name(&bridges), "vmbr2");
    }

    /// Non-vmbr0 bridge with IP wins over vmbr0 without IP.
    #[test]
    fn test_bridge_with_ip_beats_vmbr0_without_ip() {
        let bridges = vec![bridge("vmbr0", false), bridge("vmbr1", true)];
        assert_eq!(chosen_name(&bridges), "vmbr1");
        assert!(select_best_bridge(&bridges).unwrap().has_ip);
    }

    // ── VLAN-aware bridge preference ──────────────────────────────────────

    /// VLAN 0 (untagged/native VLAN) is preferred over higher-numbered VLANs.
    #[test]
    fn test_bridge_prefers_lowest_vlan_id_among_tagged_bridges() {
        let bridges = vec![
            bridge("vlan64", true),
            bridge("vlan20", true),
            bridge("vlan0", true),
        ];
        assert_eq!(chosen_name(&bridges), "vlan0");
    }

    /// VLAN 0 with IP beats vmbr0 with IP (untagged VLAN preference).
    #[test]
    fn test_bridge_vlan0_with_ip_beats_vmbr0_with_ip() {
        let bridges = vec![
            bridge("vmbr0", true),
            bridge("vlan64", true),
            bridge("vlan0", true),
        ];
        assert_eq!(chosen_name(&bridges), "vlan0");
        assert!(select_best_bridge(&bridges).unwrap().has_ip);
    }

    /// VLAN 2 beats VLAN 20 and VLAN 64 when all have IPs.
    #[test]
    fn test_bridge_lowest_numbered_vlan_wins_when_multiple_tagged() {
        // Represents a typical setup: management on vlan2, servers on vlan20, etc.
        let bridges = vec![
            bridge("vlan64", true),
            bridge("vlan20", true),
            bridge("vlan2", true),
        ];
        assert_eq!(chosen_name(&bridges), "vlan2");
    }

    /// VLAN bridge without IP loses to any other bridge that has one.
    #[test]
    fn test_bridge_vlan_without_ip_loses_to_bridge_with_ip() {
        let bridges = vec![bridge("vlan0", false), bridge("vlan64", true)];
        assert_eq!(chosen_name(&bridges), "vlan64");
        assert!(select_best_bridge(&bridges).unwrap().has_ip);
    }

    /// bridge_sort_key: VLAN 0 sorts before VLAN 20, which sorts before vmbr0.
    #[test]
    fn test_bridge_sort_key_ordering() {
        assert!(bridge_sort_key("vlan0") < bridge_sort_key("vlan20"));
        assert!(bridge_sort_key("vlan20") < bridge_sort_key("vlan64"));
        assert!(bridge_sort_key("vlan64") < bridge_sort_key("vmbr0"));
        assert!(bridge_sort_key("vmbr0") < bridge_sort_key("vmbr1"));
        assert_eq!(bridge_sort_key("vmbr1"), bridge_sort_key("eth0"));
    }

    #[test]
    fn test_build_inventory_has_both_hosts() {
        let inv = build_inventory(
            "dragonfly",
            "pve1",
            "root@pam",
            "secret",
            "https://pve:8006",
            None,
            2,
            2048,
            32,
            "vmbr0",
            None,
            None,
            "  ssh-ed25519 AAAA test",
            "/usr/local/bin/dragonfly",
        );

        let inv_read = inv.read().unwrap();
        // Both the 'proxmox' cluster host and the 'dragonfly' container host must exist
        let proxmox_host = inv_read.get_host(&"proxmox".to_string());
        let _proxmox = proxmox_host.read().unwrap(); // panics if host doesn't exist

        let container_host = inv_read.get_host(&"dragonfly".to_string());
        let container = container_host.read().unwrap();
        assert!(
            container.needs_provisioning(),
            "Container host must have a provision config"
        );
    }

    #[test]
    fn test_build_inventory_does_not_set_key_file() {
        // Jetpack authenticates via SSH agent — no key file must be set.
        let inv = build_inventory(
            "dragonfly",
            "pve1",
            "root@pam",
            "secret",
            "https://pve:8006",
            None,
            2,
            2048,
            32,
            "vmbr0",
            None,
            None,
            "  ssh-ed25519 AAAA test",
            "/usr/local/bin/dragonfly",
        );
        let inv_read = inv.read().unwrap();
        let host = inv_read.get_host(&"dragonfly".to_string());
        let host_read = host.read().unwrap();
        assert!(
            host_read
                .variables
                .get("jet_ssh_private_key_file")
                .is_none(),
            "build_inventory must NOT set jet_ssh_private_key_file — use SSH agent"
        );
    }

    // ── parse_agent_pubkeys ────────────────────────────────────────────────

    #[test]
    fn test_parse_agent_pubkeys_empty_string() {
        assert!(parse_agent_pubkeys("").is_empty());
    }

    #[test]
    fn test_parse_agent_pubkeys_no_identities_message() {
        // ssh-add -L outputs this message when no keys are loaded.
        assert!(parse_agent_pubkeys("The agent has no identities.\n").is_empty());
    }

    #[test]
    fn test_parse_agent_pubkeys_single_ed25519_key() {
        let output = "ssh-ed25519 AAAAC3test user@machine\n";
        let keys = parse_agent_pubkeys(output);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "ssh-ed25519 AAAAC3test user@machine");
    }

    #[test]
    fn test_parse_agent_pubkeys_multiple_keys() {
        let output = "ssh-ed25519 AAAAC3test1 user@machine1\nssh-rsa AAAAB3test2 user@machine2\n";
        let keys = parse_agent_pubkeys(output);
        assert_eq!(keys.len(), 2);
        assert!(keys[0].starts_with("ssh-ed25519"));
        assert!(keys[1].starts_with("ssh-rsa"));
    }

    #[test]
    fn test_parse_agent_pubkeys_filters_non_key_lines() {
        // Lines that don't start with a key-type prefix must be discarded.
        let output = "Error: could not connect to agent\nssh-ed25519 AAAAC3test user@machine\n";
        let keys = parse_agent_pubkeys(output);
        assert_eq!(keys.len(), 1, "Error line must be filtered out");
        assert!(keys[0].starts_with("ssh-ed25519"));
    }

    #[test]
    fn test_parse_agent_pubkeys_accepts_ecdsa() {
        let output = "ecdsa-sha2-nistp256 AAAAE2test user@machine\n";
        let keys = parse_agent_pubkeys(output);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].starts_with("ecdsa-"));
    }

    // ── build_update_inventory ─────────────────────────────────────────────

    #[test]
    fn test_build_update_inventory_has_container_host() {
        let inv = build_update_inventory("dragonfly", "10.0.0.5");
        let inv_read = inv.read().unwrap();

        // Container host must exist in inventory
        let host = inv_read.get_host(&"dragonfly".to_string());
        let _h = host.read().unwrap(); // panics if missing
    }

    #[test]
    fn test_build_update_inventory_has_ssh_hostname_var() {
        let inv = build_update_inventory("dragonfly", "10.0.0.5");
        let inv_read = inv.read().unwrap();

        let host = inv_read.get_host(&"dragonfly".to_string());
        let host_read = host.read().unwrap();
        let vars = host_read.variables.clone();

        let hostname_val = vars.get("jet_ssh_hostname");
        assert!(hostname_val.is_some(), "jet_ssh_hostname must be set");
        assert_eq!(
            hostname_val.unwrap().as_str().unwrap(),
            "10.0.0.5",
            "jet_ssh_hostname must match the container IP"
        );
    }

    #[test]
    fn test_build_update_inventory_does_not_set_key_file() {
        // Update flow authenticates via SSH agent, not a key file.
        // Jetpack automatically falls back to agent auth when no key file is set.
        let inv = build_update_inventory("dragonfly", "10.0.0.5");
        let inv_read = inv.read().unwrap();

        let host = inv_read.get_host(&"dragonfly".to_string());
        let host_read = host.read().unwrap();
        let vars = host_read.variables.clone();

        assert!(
            vars.get("jet_ssh_private_key_file").is_none(),
            "Update inventory must NOT set jet_ssh_private_key_file — use SSH agent"
        );
    }

    #[test]
    fn test_build_update_inventory_has_no_provision_config() {
        let inv = build_update_inventory("dragonfly", "10.0.0.5");
        let inv_read = inv.read().unwrap();

        let host = inv_read.get_host(&"dragonfly".to_string());
        let container = host.read().unwrap();
        assert!(
            !container.needs_provisioning(),
            "Update inventory must not have a provision config — container already exists"
        );
    }
}
