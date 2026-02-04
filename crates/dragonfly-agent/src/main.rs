mod boot_menu;
mod kexec;
mod probe;
mod workflow;

use reqwest::Client;
use anyhow::{Result, Context};
use dragonfly_common::models::DiskInfo;
use dragonfly_crd::Hardware;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use clap::Parser;
use tracing::{info, error, warn, debug};
// Use wildcard import for sysinfo to bring traits into scope
use sysinfo::*;
use workflow::{AgentWorkflowRunner, AgentAction, checkin_native};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Show the boot menu directly (for testing the TUI)
    #[arg(long)]
    menu: bool,

    /// Server URL (default: http://localhost:3000)
    #[arg(long)]
    server: Option<String>,

    /// Check-in interval in seconds
    #[arg(long, default_value = "30")]
    checkin_interval: u64,

    /// Only run specific actions (1-indexed, comma-separated)
    /// Example: --action 1 (first action only)
    /// Example: --action 1,2,3 (first three actions)
    /// Example: --action 5 (fifth action only)
    #[arg(long, value_delimiter = ',')]
    action: Option<Vec<usize>>,
}

/// Parameters parsed from kernel command line (for Mage boot environment)
#[derive(Debug, Default)]
struct KernelParams {
    /// Dragonfly server URL (dragonfly.url=)
    url: Option<String>,
    /// Boot mode: discovery or imaging (dragonfly.mode=)
    mode: Option<String>,
    /// MAC address (dragonfly.mac=)
    mac: Option<String>,
    /// Hardware ID if known (dragonfly.hardware=)
    hardware_id: Option<String>,
    /// Workflow ID for imaging mode (dragonfly.workflow=)
    workflow_id: Option<String>,
}

impl KernelParams {
    /// Parse Dragonfly parameters from /proc/cmdline
    fn from_cmdline() -> Self {
        let mut params = KernelParams::default();

        let cmdline = match fs::read_to_string("/proc/cmdline") {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read /proc/cmdline: {}", e);
                return params;
            }
        };

        for param in cmdline.split_whitespace() {
            if let Some(value) = param.strip_prefix("dragonfly.url=") {
                params.url = Some(value.to_string());
            } else if let Some(value) = param.strip_prefix("dragonfly.mode=") {
                params.mode = Some(value.to_string());
            } else if let Some(value) = param.strip_prefix("dragonfly.mac=") {
                params.mac = Some(value.to_string());
            } else if let Some(value) = param.strip_prefix("dragonfly.hardware=") {
                params.hardware_id = Some(value.to_string());
            } else if let Some(value) = param.strip_prefix("dragonfly.workflow=") {
                params.workflow_id = Some(value.to_string());
            }
        }

        if params.url.is_some() || params.mode.is_some() {
            info!("Parsed kernel parameters: url={:?}, mode={:?}, mac={:?}, hardware={:?}, workflow={:?}",
                params.url, params.mode, params.mac, params.hardware_id, params.workflow_id);
        }

        params
    }

    /// Check if we have Dragonfly kernel parameters (indicates Mage boot)
    fn has_dragonfly_params(&self) -> bool {
        self.url.is_some() || self.mode.is_some()
    }
}

// Detect disks on the system via /sys/block (pure Rust, no C deps)
fn detect_disks() -> Vec<DiskInfo> {
    let mut disks = Vec::new();

    // Read /sys/block directly - kernel exposes all block devices here
    let sys_block = std::path::Path::new("/sys/block");
    if !sys_block.exists() {
        tracing::warn!("/sys/block not found - not on Linux?");
        return disks;
    }

    let entries = match fs::read_dir(sys_block) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to read /sys/block: {}", e);
            return disks;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip virtual devices
        if name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("dm-")
            || name.starts_with("zram")
        {
            continue;
        }

        // Only include real disk devices
        let is_disk = name.starts_with("sd")
            || name.starts_with("nvme")
            || name.starts_with("vd")
            || name.starts_with("xvd")
            || name.starts_with("hd");

        if !is_disk {
            continue;
        }

        let device = format!("/dev/{}", name);

        // Read size from /sys/block/<dev>/size (in 512-byte sectors)
        let size_path = entry.path().join("size");
        let size_bytes = fs::read_to_string(&size_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|sectors| sectors * 512)
            .unwrap_or(0);

        // Read model from /sys/block/<dev>/device/model
        let model_path = entry.path().join("device/model");
        let model = fs::read_to_string(&model_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        tracing::debug!("Found disk {} via sysfs: {} bytes", device, size_bytes);

        disks.push(DiskInfo {
            device,
            size_bytes,
            model,
            calculated_size: None,
        });
    }

    tracing::info!("Detected {} disks", disks.len());
    for disk in &disks {
        tracing::info!(
            "  Disk: {} ({} bytes){}",
            disk.device,
            disk.size_bytes,
            disk.model.as_ref().map_or("".to_string(), |m| format!(", Model: {}", m))
        );
    }

    disks
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger (but not for menu mode - it interferes with TUI)
    if !args.menu {
        tracing_subscriber::fmt::init();
    }

    // If --menu flag, show boot menu directly and exit
    if args.menu {
        // Probe for existing OS to show in menu
        let existing_os = probe::probe_for_existing_os().ok().flatten();
        let server_url = args.server.as_deref();
        let selection = boot_menu::show_boot_menu(existing_os.as_ref(), server_url).await?;
        println!("Selected: {:?}", selection);
        return Ok(());
    }

    // Parse kernel command line parameters (for Mage boot environment)
    let kernel_params = KernelParams::from_cmdline();

    if kernel_params.has_dragonfly_params() {
        info!("Detected Mage boot environment (dragonfly.* kernel parameters present)");
    }

    // Get API URL from (in order of priority):
    // 1. Kernel command line (dragonfly.url=)
    // 2. Command line argument (--server)
    // 3. Environment variable (DRAGONFLY_API_URL)
    // 4. Default
    let api_url = kernel_params.url.clone()
        .or(args.server.clone())
        .or_else(|| env::var("DRAGONFLY_API_URL").ok())
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    // --- Get required system info FIRST --- 
    // Get MAC address and IP address (using improved logic)
    let mac_address = get_mac_address().context("Failed to get MAC address")?;
    let ip_address_str = get_ip_address().context("Failed to get IP address")?;
    info!("Agent identified its primary IP as: {}", ip_address_str);

    // Parse the determined IP address for binding
    let local_ip: Option<std::net::IpAddr> = match ip_address_str.parse() {
        Ok(ip) => Some(ip),
        Err(e) => {
            warn!("Failed to parse determined IP address '{}' for binding: {}. Client will use default interface.", ip_address_str, e);
            None
        }
    };
    
    // --- Create HTTP client, binding to the determined IP if possible --- 
    let client_builder = Client::builder();
    let client = match local_ip {
        Some(ip) => {
            info!("Attempting to bind HTTP client to local address: {}", ip);
            client_builder
                .local_address(ip)
                .build()
                .context("Failed to build HTTP client with local address binding")?
        }
        None => {
            info!("Building HTTP client without specific local address binding.");
            client_builder
                .build()
                .context("Failed to build default HTTP client")?
        }
    };
    
    // Get system information (rest of it)
    let mut sys = System::new_all();
    sys.refresh_all();
    
    // Get hostname
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    
    // --- Detect CPU, Core Count, and RAM --- 
    // Ensure sysinfo is refreshed first
    sys.refresh_cpu();
    sys.refresh_memory();

    let cpu_model = sys.cpus().first().map(|cpu| cpu.brand().to_string());
    // Prefer physical cores, fallback to logical cores (cpus().len())
    let cpu_cores = sys.physical_core_count().map(|c| c as u32).or_else(|| Some(sys.cpus().len() as u32));
    let total_ram_bytes = sys.total_memory();
    // Convert total RAM to GiB for logging (optional, but often more readable)
    let total_ram_gib = total_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    
    info!("Detected CPU: {:?}", cpu_model.as_deref().unwrap_or("Unknown"));
    info!("Detected CPU Cores: {:?}", cpu_cores); // Log Option<u32>
    info!("Detected RAM: {} bytes ({:.2} GiB)", total_ram_bytes, total_ram_gib);
    // --- End CPU/RAM Detection ---
    
    // Detect disks
    let disks = detect_disks();

    info!("Starting Dragonfly agent (Mage boot: {})", kernel_params.has_dragonfly_params());

    // Build Hardware CRD from detected info for workflow execution context
    let hardware = build_hardware_from_detected_info(
        &mac_address,
        &ip_address_str,
        &hostname,
        cpu_model.as_deref(),
        cpu_cores,
        total_ram_bytes,
        &disks,
    );

    // Discovery mode = rescue shell. Print system info and exec into a shell.
    if kernel_params.mode.as_deref() == Some("discovery") {
        println!();
        println!("=== Dragonfly Rescue Environment ===");
        println!("MAC: {}", mac_address);
        println!("IP:  {}", ip_address_str);
        println!("Hostname: {}", hostname);
        if let Some(ref cpu) = cpu_model {
            println!("CPU: {} ({} cores)", cpu, cpu_cores.unwrap_or(0));
        }
        println!("RAM: {:.1} GiB", total_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0));
        for disk in &disks {
            println!("Disk: {} ({} bytes)", disk.device, disk.size_bytes);
        }
        println!("=========================================");
        println!("Type 'reboot' to restart the machine.");
        println!();

        // Replace this process with a shell so the user gets an interactive console
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new("/bin/sh")
            .arg("-l")
            .exec();
        // exec() only returns on error
        eprintln!("Failed to exec shell: {}", err);
        std::process::exit(1);
    }

    // Run the provisioning check-in loop
    run_native_provisioning_loop(
        &client,
        &api_url,
        &mac_address,
        Some(&hostname),
        Some(&ip_address_str),
        hardware,
        Duration::from_secs(args.checkin_interval),
        args.action.clone(),
        kernel_params.mode.as_deref(),
    ).await
}

/// Build a Hardware CRD from detected system information
fn build_hardware_from_detected_info(
    mac: &str,
    ip: &str,
    hostname: &str,
    _cpu_model: Option<&str>,
    _cpu_cores: Option<u32>,
    _total_ram_bytes: u64,
    disks: &[DiskInfo],
) -> Hardware {
    use dragonfly_crd::{HardwareSpec, InterfaceSpec, DhcpSpec, IpSpec, DiskSpec, InstanceMetadata, Instance};

    // Build primary interface with DHCP
    let mut primary_dhcp = DhcpSpec::new(mac);
    primary_dhcp.hostname = Some(hostname.to_string());
    primary_dhcp.ip = Some(IpSpec {
        address: ip.to_string(),
        netmask: None,
        gateway: None,
    });

    let primary_interface = InterfaceSpec {
        dhcp: Some(primary_dhcp),
        netboot: None,
    };

    // Build disk specs from detected disks
    let disk_specs: Vec<DiskSpec> = disks.iter().map(|d| {
        DiskSpec {
            device: d.device.clone(),
        }
    }).collect();

    // Build instance metadata
    let hardware_id = format!("hw-{}", mac.replace(':', ""));
    let instance_metadata = InstanceMetadata {
        instance: Instance {
            id: hardware_id.clone(),
            hostname: hostname.to_string(),
        },
    };

    // Build hardware spec
    let spec = HardwareSpec {
        interfaces: vec![primary_interface],
        disks: disk_specs,
        metadata: Some(instance_metadata),
        bmc: None,
        user_data: None,
        os_choice: None,
    };

    // Create hardware with generated ID based on MAC
    Hardware::new(&hardware_id, spec)
}

/// Run the provisioning check-in loop
///
/// Implements the "invisible PXE" philosophy:
/// - If there's an existing OS: quick timeout, boot it if server is slow
/// - If no existing OS: wait indefinitely for server (nothing else to do)
/// - User can always press ENTER/SPACEBAR to access the boot menu
/// - The check-in is slipstreamed into existing flows, making any delay invisible
async fn run_native_provisioning_loop(
    client: &Client,
    server_url: &str,
    mac: &str,
    hostname: Option<&str>,
    ip_address: Option<&str>,
    hardware: Hardware,
    checkin_interval: Duration,
    action_filter: Option<Vec<usize>>,
    boot_mode: Option<&str>,
) -> Result<()> {
    let is_imaging = boot_mode == Some("imaging");
    info!("Starting native provisioning (mode={:?})", boot_mode);

    // Probe disks for existing OS FIRST (before any check-in)
    let existing_os = match probe::probe_for_existing_os() {
        Ok(os) => {
            if let Some(ref detected) = os {
                info!(
                    name = %detected.name,
                    device = %detected.device,
                    "Detected existing OS on disk"
                );
            }
            os
        }
        Err(e) => {
            warn!(error = %e, "Failed to probe for existing OS, continuing anyway");
            None
        }
    };

    // Use hostname from existing OS if available, otherwise use system hostname
    let effective_hostname = existing_os.as_ref()
        .and_then(|os| os.hostname.as_ref())
        .map(|h| h.as_str())
        .or(hostname);

    if let Some(detected_hostname) = existing_os.as_ref().and_then(|os| os.hostname.as_ref()) {
        info!(hostname = %detected_hostname, "Using hostname from existing OS");
    }

    // IMAGING MODE: Skip the 3s splash/timeout entirely.
    // The server told us to image this machine — we check in patiently with retries
    // until the server responds, then execute the workflow. No fake LocalBoot, no menu.
    // If the workflow fails (download crash, network error), retry from check-in.
    if is_imaging {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            info!(attempt, "Imaging mode - checking in with server");
            let response = checkin_with_retry(
                client, server_url, mac, effective_hostname, ip_address, existing_os.as_ref(),
            ).await?;

            info!(
                machine_id = %response.machine_id,
                name = %response.memorable_name,
                action = ?response.action,
                attempt,
                "Imaging mode check-in successful"
            );

            match handle_agent_action(
                &response,
                &existing_os,
                client,
                server_url,
                &hardware,
                &action_filter,
            ).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // Workflow failed — retry from check-in. The server still has the
                    // workflow assigned; it'll tell us to Execute again.
                    // Backoff: 0s, 1s, 2s, 4s, 8s (capped)
                    let backoff_secs = if attempt <= 1 { 0 } else { 1u64 << (attempt - 2).min(3) };
                    error!(
                        error = %e,
                        attempt,
                        backoff_secs,
                        "Workflow failed, will retry from check-in"
                    );
                    if backoff_secs > 0 {
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    }
                }
            }
        }
    }

    // DISCOVERY MODE (or no mode): Use the interactive splash with timeout.
    // If there's an existing OS and the server is slow, boot into it.
    // User can press ENTER/SPACEBAR for the menu.
    let client_clone = client.clone();
    let server_url_owned = server_url.to_string();
    let mac_owned = mac.to_string();
    let hostname_owned = effective_hostname.map(|s| s.to_string());
    let ip_address_owned = ip_address.map(|s| s.to_string());
    let existing_os_clone = existing_os.clone();

    let checkin_result = boot_menu::wait_for_checkin_with_interrupt(
        || async move {
            checkin_native(
                &client_clone,
                &server_url_owned,
                &mac_owned,
                hostname_owned.as_deref(),
                ip_address_owned.as_deref(),
                existing_os_clone.as_ref(),
            ).await
        },
        existing_os.as_ref(),
    ).await?;

    // Handle the result
    let initial_response = match checkin_result {
        None => {
            // User requested menu
            let selection = boot_menu::show_boot_menu(existing_os.as_ref(), Some(server_url)).await?;
            return handle_menu_selection(
                selection,
                &existing_os,
                client,
                server_url,
                &hardware,
                &action_filter,
            ).await;
        }
        Some(response) => response,
    };

    // If we have a machine_id, we got a real response
    if !initial_response.machine_id.is_empty() {
        info!(
            machine_id = %initial_response.machine_id,
            name = %initial_response.memorable_name,
            is_new = %initial_response.is_new,
            action = ?initial_response.action,
            "Check-in successful"
        );
    }

    // Handle initial response
    handle_agent_action(
        &initial_response,
        &existing_os,
        client,
        server_url,
        &hardware,
        &action_filter,
    ).await?;

    // If we get here after LocalBoot/Execute, the action didn't terminate
    // Enter the main loop for ongoing check-ins (only if action was Wait)
    if initial_response.action == AgentAction::Wait {
        loop {
            tokio::time::sleep(checkin_interval).await;

            match checkin_native(client, server_url, mac, effective_hostname, ip_address, existing_os.as_ref()).await {
                Ok(response) => {
                    debug!(action = ?response.action, "Check-in response");
                    handle_agent_action(
                        &response,
                        &existing_os,
                        client,
                        server_url,
                        &hardware,
                        &action_filter,
                    ).await?;
                }
                Err(e) => {
                    // After initial success, we can be more lenient with retries
                    error!(error = %e, "Check-in failed, will retry");
                }
            }
        }
    }

    Ok(())
}

/// Check in with the server, retrying with exponential backoff until success.
///
/// Used in imaging mode where we MUST get a response — there's no fallback.
/// The server assigned this workflow; we wait until it tells us what to do.
async fn checkin_with_retry(
    client: &Client,
    server_url: &str,
    mac: &str,
    hostname: Option<&str>,
    ip_address: Option<&str>,
    existing_os: Option<&probe::DetectedOs>,
) -> Result<workflow::CheckInResponse> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match checkin_native(client, server_url, mac, hostname, ip_address, existing_os).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                // Cap backoff at 10s — the server is local, retries should be quick
                let backoff_ms = (1000u64 * 2u64.pow(attempt.min(4).saturating_sub(1))).min(10_000);
                warn!(
                    error = %e,
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Imaging mode check-in failed, retrying"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
}

/// Handle a menu selection from the boot menu
async fn handle_menu_selection(
    selection: boot_menu::MenuSelection,
    existing_os: &Option<probe::DetectedOs>,
    client: &Client,
    server_url: &str,
    hardware: &Hardware,
    action_filter: &Option<Vec<usize>>,
) -> Result<()> {
    use boot_menu::MenuSelection;

    match selection {
        MenuSelection::BootExistingOs => {
            if existing_os.is_some() {
                info!("User selected: boot existing OS - rebooting to local disk");
                std::process::Command::new("reboot")
                    .status()
                    .context("Failed to reboot")?;
            } else {
                warn!("No existing OS to boot");
            }
        }
        MenuSelection::MemoryTest => {
            info!("User selected: memory test");
            // TODO: Boot memtest86+ via kexec
            warn!("Memory test not yet implemented");
        }
        MenuSelection::Wipe => {
            info!("User selected: wipe disk");
            // TODO: Implement disk wipe
            warn!("Disk wipe not yet implemented - requires confirmation workflow");
        }
        MenuSelection::InstallOs(template) => {
            info!(template = %template, "User selected: install OS");
            // TODO: Create workflow for OS installation
            warn!("OS installation via menu not yet implemented");
        }
        MenuSelection::BootIso(url) => {
            info!(url = %url, "User selected: boot ISO");
            // TODO: Implement ISO boot via memdisk/sanboot
            warn!("ISO boot not yet implemented");
        }
        MenuSelection::BootRescue => {
            info!("User selected: boot rescue environment");
            // TODO: Boot rescue environment
            warn!("Rescue environment not yet implemented");
        }
        MenuSelection::VendorDiagnostics => {
            info!("User selected: vendor diagnostics");
            // TODO: Detect vendor and boot appropriate diagnostics
            warn!("Vendor diagnostics not yet implemented");
        }
        MenuSelection::RemoveFromDragonfly => {
            info!("User selected: remove from Dragonfly");
            // TODO: Call API to unregister machine
            warn!("Remove from Dragonfly not yet implemented");
        }
        MenuSelection::ExecuteWorkflow(workflow_id) => {
            info!(workflow_id = %workflow_id, "Executing workflow from menu");
            let mut hw = hardware.clone();
            hw.metadata.name = "menu-selected".to_string();

            let runner = workflow::AgentWorkflowRunner::new(
                client.clone(),
                server_url.to_string(),
                hw,
            ).with_action_filter(action_filter.clone());

            match runner.execute(&workflow_id).await {
                Ok(()) => info!(workflow_id = %workflow_id, "Workflow completed"),
                Err(e) => error!(workflow_id = %workflow_id, error = %e, "Workflow failed"),
            }
        }
        MenuSelection::Wait => {
            info!("User selected: wait for instructions");
            // Nothing to do - would enter the check-in loop
        }
        MenuSelection::ExitToShell => {
            info!("User selected: exit to shell");
            // Check if we're in Alpine/Mage (PXE boot environment) vs normal Linux
            let is_mage = std::path::Path::new("/etc/alpine-release").exists()
                || std::env::var("DRAGONFLY_MAGE").is_ok();

            if is_mage {
                // Drop to maintenance shell
                println!("\n\x1b[1;33mDropping to maintenance shell...\x1b[0m");
                println!("Type 'exit' to return to boot menu, or 'reboot' to restart.\n");
                let _ = Command::new("/bin/sh").status();
                // If shell exits, we could loop back to menu, but for now just exit
            }
            // Exit the agent - on normal Linux this just returns to shell
            std::process::exit(0);
        }
    }

    Ok(())
}

/// Handle an action from the server
async fn handle_agent_action(
    response: &workflow::CheckInResponse,
    existing_os: &Option<probe::DetectedOs>,
    client: &Client,
    server_url: &str,
    hardware: &Hardware,
    action_filter: &Option<Vec<usize>>,
) -> Result<()> {
    match response.action {
        AgentAction::Wait => {
            debug!("Server says wait");
            Ok(())
        }
        AgentAction::Execute => {
            if let Some(ref workflow_id) = response.workflow_id {
                info!(workflow_id = %workflow_id, "Server assigned workflow, executing...");

                // Update hardware name to match machine_id
                let mut hw = hardware.clone();
                hw.metadata.name = response.machine_id.clone();

                let runner = AgentWorkflowRunner::new(
                    client.clone(),
                    server_url.to_string(),
                    hw,
                ).with_action_filter(action_filter.clone());

                runner.execute(workflow_id).await
                    .context(format!("Workflow {} failed", workflow_id))?;

                if action_filter.is_some() {
                    info!("Action filter specified - exiting");
                    std::process::exit(0);
                }
            } else {
                warn!("Server said Execute but no workflow_id provided");
            }
            Ok(())
        }
        AgentAction::Reboot => {
            info!("Server requested reboot");
            Command::new("reboot").status().context("Failed to reboot")?;
            Ok(())
        }
        AgentAction::LocalBoot => {
            if let Some(os) = existing_os {
                info!(name = %os.name, "Booting into existing OS via reboot");
                Command::new("reboot").status().context("Failed to reboot")?;
            } else {
                warn!("Server said LocalBoot but no existing OS detected");
            }
            Ok(())
        }
    }
}

fn get_mac_address() -> Result<String> {
    // First try the ip command
    if let Ok(output) = Command::new("ip")
        .args(["link", "show"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Skip loopback interfaces
            for line in stdout.lines() {
                if line.contains("link/ether") && !line.contains("lo:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let mac = parts[1].to_string();
                        tracing::info!("Found actual MAC address: {}", mac);
                        return Ok(mac);
                    }
                }
            }
        }
    }
    
    // Then try with ifconfig
    if let Ok(output) = Command::new("ifconfig")
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Skip loopback interfaces
            for line in stdout.lines() {
                if line.contains("ether") && !line.contains("lo:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let mac = parts[1].to_string();
                        tracing::info!("Found actual MAC address: {}", mac);
                        return Ok(mac);
                    }
                }
            }
        }
    }
    
    // Fallback to looking for network interfaces directly
    let net_dir = Path::new("/sys/class/net");
    if net_dir.exists() {
        for entry in fs::read_dir(net_dir)? {
            let entry = entry?;
            let path = entry.path();
            let if_name = path.file_name().unwrap().to_string_lossy();
            
            // Skip loopback interface
            if if_name == "lo" {
                continue;
            }
            
            let address_path = path.join("address");
            if address_path.exists() {
                if let Ok(mac) = fs::read_to_string(address_path) {
                    let mac = mac.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        tracing::info!("Found actual MAC address: {}", mac);
                        return Ok(mac);
                    }
                }
            }
        }
    }
    
    // Last resort fallback - use a deterministic ID based on hostname
    // This ensures we still get the same ID on subsequent runs
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let mut hasher = DefaultHasher::new();
    hostname.hash(&mut hasher);
    let hash = hasher.finish();
    
    let mac = format!("02:00:00:{:02x}:{:02x}:{:02x}", 
        (hash >> 16) as u8,
        (hash >> 8) as u8,
        hash as u8);
    
    tracing::warn!("Could not detect MAC address, using hostname-based fallback: {}", mac);
    Ok(mac)
}

fn get_ip_address() -> Result<String> {
    // 1. Try to find the IP on the interface used for the default route
    match get_ip_from_default_route_interface() {
        Ok(Some(ip)) => {
            info!("Found IP {} from default route interface", ip);
            return Ok(ip);
        }
        Ok(None) => {
            info!("No default route found or no IP on default interface, scanning all interfaces...");
            // Proceed to scan all interfaces
        }
        Err(e) => {
            warn!("Error checking default route interface: {}. Scanning all interfaces...", e);
            // Proceed to scan all interfaces
        }
    }

    // 2. Fallback: Scan all interfaces if default route method failed or yielded no IP
    info!("Scanning all interfaces for a suitable IP address...");
    let output = Command::new("ip")
        .args(["-4", "addr", "show"])
        .output()
        .context("Failed to run 'ip addr show'")?;

    if !output.status.success() {
        anyhow::bail!("'ip addr show' command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_interface: Option<String> = None;
    let mut candidates: Vec<(String, String)> = Vec::new(); // (interface_name, ip_address)
    let bad_prefixes = ["docker", "virbr", "veth", "cni", "flannel"];
    let bad_masters = ["cni0", "docker0"]; // Add known bad master interfaces
    let preferred_prefixes = ["eth", "en", "wl"]; // Common physical/wifi prefixes

    for line in stdout.lines() {
        // Check for start of a new interface block (e.g., "2: eth0: <...")
        if let Some(colon_pos) = line.find(':') {
            if line[..colon_pos].chars().all(|c| c.is_digit(10)) {
                // Looks like an interface index line
                // Log the raw interface line *before* filtering
                tracing::debug!("Processing interface line: {}", line.trim());

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    let if_name = parts[1].trim_end_matches(':').to_string();
                    let is_lo = if_name == "lo";
                    let is_up = line.contains("<UP,") || line.contains(",UP>");
                    let has_bad_prefix = bad_prefixes.iter().any(|prefix| if_name.starts_with(prefix));
                    // Check if the interface is attached to a known bad master
                    let is_attached_to_bad_master = bad_masters.iter().any(|master| line.contains(&format!(" master {}", master)));

                    // Determine if this interface should be considered
                    if is_lo || !is_up || has_bad_prefix || is_attached_to_bad_master {
                        if is_attached_to_bad_master {
                            tracing::debug!("Ignoring interface {} because it is attached to a bad master", if_name);
                        } else if has_bad_prefix {
                             tracing::debug!("Ignoring interface {} because it has a bad prefix", if_name);
                        } // Add other debug logs if needed
                        current_interface = None; // Skip this interface block
                    } else {
                        current_interface = Some(if_name); // Good candidate interface
                    }
                } else {
                     current_interface = None; // Malformed line?
                }
                continue; // Move to the next line after processing interface header
            }
        }

        // Check for inet line within an active, considered interface block
        if let Some(ref if_name) = current_interface {
            if line.trim().starts_with("inet ") {
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Some(ip) = parts[1].split('/').next() {
                        // Basic validation and filtering for the IP address itself
                        // Interface checks (prefix, master, up state) were already done when setting current_interface
                        if !ip.starts_with("127.") && !ip.starts_with("169.254.") {
                            // No need to re-check bad_prefixes on if_name here
                            candidates.push((if_name.clone(), ip.to_string()));
                            tracing::debug!("Found candidate IP {} on interface {}", ip, if_name);
                        }
                    }
                }
            }
        }
    }

    // Log all candidates found before prioritization
    if candidates.is_empty() {
        warn!("No suitable IP address candidates found after filtering scanning all interfaces.");
    } else {
        info!("Found {} IP address candidates from scanning all interfaces:", candidates.len());
        for (if_name, ip) in &candidates {
            info!("  - Interface: {}, IP: {}", if_name, ip);
        }
    }

    // Prioritize candidates based on preferred interface prefixes
    if let Some((if_name, ip)) = candidates.iter().find(|(name, _)| preferred_prefixes.iter().any(|p| name.starts_with(p))) {
        info!("Selected preferred IP {} from interface {} based on prefix matching (fallback scan).", ip, if_name);
        return Ok(ip.clone());
    }

    // If no preferred interface found, return the first valid candidate
    if let Some((if_name, ip)) = candidates.first() {
        info!("Selected first available IP {} from interface {} (fallback scan, no preferred prefix match).", ip, if_name);
        return Ok(ip.clone());
    }

    // If no suitable IP found after filtering
    warn!("Could not find any suitable IP address. Falling back to 127.0.0.1");
    Ok("127.0.0.1".to_string())
}

// Helper function to get IP from the default route interface
fn get_ip_from_default_route_interface() -> Result<Option<String>> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .context("Failed to run 'ip route show default'")?;

    if !output.status.success() {
        // Command might fail if there is no default route, which is not an error in itself
        info!("'ip route show default' command failed or no default route set.");
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let default_route_line = stdout.lines().next(); // Default route should be the first line

    if let Some(line) = default_route_line {
        info!("Default route line: {}", line);
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(dev_index) = parts.iter().position(|&p| p == "dev") {
            if let Some(if_name) = parts.get(dev_index + 1) {
                info!("Found default route interface: {}", if_name);
                // Now get the IP address for this specific interface
                let addr_output = Command::new("ip")
                    .args(["-4", "addr", "show", "dev", if_name])
                    .output()
                    .context(format!("Failed to run 'ip addr show dev {}'", if_name))?;

                if !addr_output.status.success() {
                    warn!("Failed to get address for default interface {}. Status: {}", if_name, addr_output.status);
                    return Ok(None);
                }

                let addr_stdout = String::from_utf8_lossy(&addr_output.stdout);
                for addr_line in addr_stdout.lines() {
                    if addr_line.trim().starts_with("inet ") {
                        let addr_parts: Vec<&str> = addr_line.trim().split_whitespace().collect();
                        if addr_parts.len() >= 2 {
                            if let Some(ip) = addr_parts[1].split('/').next() {
                                if !ip.starts_with("127.") && !ip.starts_with("169.254.") {
                                    info!("Found valid IP {} on default interface {}", ip, if_name);
                                    return Ok(Some(ip.to_string()));
                                }
                            }
                        }
                    }
                }
                warn!("No valid inet address found on default interface {}", if_name);
                return Ok(None); // Found interface but no suitable IP
            } else {
                warn!("Could not parse interface name after 'dev' in default route line");
            }
        } else {
            warn!("Could not find 'dev' keyword in default route line");
        }
    } else {
        info!("No output from 'ip route show default' (no default route?)");
    }

    Ok(None) // No default route found or couldn't parse it
} 
