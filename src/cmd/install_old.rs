use clap::Args;
use color_eyre::eyre::{bail, Result, WrapErr}; // Add bail!
use std::net::Ipv4Addr; // Use specific types
use std::io::Write; // Import Write trait for stdout().flush()
use tracing::{debug, error, info, warn}; // Use tracing macros
use std::path::PathBuf;
use std::process::{Command, Output}; // For running commands
use std::time::Instant;
use tokio::fs; // For async file operations
use ipnetwork::Ipv4Network;
use network_interface::NetworkInterfaceConfig;
use std::sync::Arc;
use lazy_static::lazy_static;
use std::sync::Mutex as StdMutex;
use std::collections::VecDeque;
 // Import task_local
 // Import signal for Ctrl+C
use tokio::sync::watch; // Import watch

// Import state and globals from server crate
use dragonfly_server::{
    InstallationState, 
    INSTALL_STATE_REF, 
    EVENT_MANAGER_REF
};

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Optional: Specify the network interface to use for IP detection.
    #[arg(long)]
    pub interface: Option<String>, // Made public if needed elsewhere, or keep private

    /// Optional: Specify the starting IP address offset from the host IP.
    #[arg(long, default_value_t = 1)]
    pub start_offset: u8,

    /// Optional: Maximum number of IPs to check before giving up.
    #[arg(long, default_value_t = 20)]
    pub max_ip_search: u8,

    // Add other install-specific args here
}

// Helper function to update the global installation state and send SSE event
async fn update_install_state(new_state: InstallationState) {
    info!("[update_install_state] Called with state: {:?}", new_state);
    eprintln!("[DEBUG] update_install_state called for state: {:?}", new_state);
    // --- Update State --- 
    let state_arc_mutex: Option<Arc<tokio::sync::Mutex<InstallationState>>> = {
        INSTALL_STATE_REF.read().unwrap().as_ref().cloned()
    };

    if let Some(state_ref) = state_arc_mutex {
        let mut state = state_ref.lock().await; 
        *state = new_state.clone();
        info!("[update_install_state] Global state updated.");
    } else {
         info!("[update_install_state] Install state ref NOT found (UI state won't update globally).");
    }
    
    // --- Send Event --- 
    // Attempt to get EventManager
    let event_manager_arc: Option<Arc<dragonfly_server::event_manager::EventManager>> = {
        EVENT_MANAGER_REF.read().unwrap().as_ref().cloned()
    };

    if let Some(event_manager) = event_manager_arc {
        // Event manager is available, send the current state update
        let payload = serde_json::json!({
            "message": new_state.get_message(),
            "animation": new_state.get_animation_class(),
        });
        let event_data = format!("install_status:{}", payload.to_string()); 
        info!("[update_install_state] Sending event data: {}", event_data);
        
        if let Err(e) = event_manager.send(event_data) {
            error!("[update_install_state] Failed to send event: {}", e);
        } else {
            info!("[update_install_state] Event sent successfully.");
        }
    } else {
        // Event manager not available yet. The sse_events handler will send the current state upon connection.
        info!("[update_install_state] Event manager ref not found. Event will be sent when UI connects.");
    }
}

pub async fn sudo_prompt() -> Result<()> {
    // Just run sudo echo -n "" to prompt for sudo password
    let output = Command::new("sudo")
        .arg("echo")
        .arg("-n")
        .output()?;
    Ok(())
}

// The main function for the install command
pub async fn run_install(args: InstallArgs, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
    // Start the webserver immediately
    let server_handle = tokio::spawn(async move {
        // Server task inherits environment.
        // Logging is controlled by global subscriber set in main.rs.
        
        // Use in-memory SQLite for the initial phase
        std::env::set_var("DATABASE_URL", "sqlite::memory:");

        // Set flag indicating server is running as part of install
        std::env::set_var("DRAGONFLY_INSTALL_SERVER_MODE", "true");
        
        // Ensure INSTALLER_MODE is NOT set (this was correct)
        if std::env::var("DRAGONFLY_INSTALLER_MODE").is_ok() {
            std::env::remove_var("DRAGONFLY_INSTALLER_MODE");
        }
        
        // Start the server - logging is controlled by global subscriber or RUST_LOG
        // This call initializes the global refs EVENT_MANAGER_REF and INSTALL_STATE_REF
        let _ = dragonfly_server::run().await;
    });

    // --- Wait for Server Statics Readiness --- 
    info!("Waiting for server components (state and event manager) to initialize...");
    let max_wait_attempts = 20; // ~10 seconds total
    for attempt in 0..max_wait_attempts {
        // Check if both global references have been initialized by the server thread
        let state_ready = INSTALL_STATE_REF.read().unwrap().is_some();
        let events_ready = EVENT_MANAGER_REF.read().unwrap().is_some();
        
        if state_ready && events_ready {
            info!("Server components initialized successfully.");
            break; // Exit the loop once both are ready
        }
        
        if attempt == max_wait_attempts - 1 {
            // Log a warning if the timeout is reached, but proceed anyway
            warn!("Server components did not initialize within the timeout. UI updates might be delayed or missed.");
        } else {
             // Wait briefly before the next check
             debug!("Waiting for server components... (Attempt {}/{})", attempt + 1, max_wait_attempts);
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
    // --- End Wait --- 

    // --- Start Background Installation Task --- 
    // Clone the receiver *before* spawning the task that moves it
    let mut shutdown_rx_clone = shutdown_rx.clone(); 

    println!("🐉 Welcome to Dragonfly.");
    println!("🚀 Open http://localhost:3000 to get started. We're ready for you to look around!");

    // Only show sudo message if passwordless sudo is not available
    // Note: Need to check passwordless_sudo before this point
    let passwordless_sudo = check_passwordless_sudo().await;
    if !passwordless_sudo {
        println!("🔐 Meanwhile, you'll need to enter your sudo password for the next stages of the installer.");
        // Handle the Result from sudo_prompt
        let _ = sudo_prompt().await;
    }

    // Set initial state (WaitingSudo) - use the helper
    // This should now reliably update the global state and send the event because we waited
    update_install_state(InstallationState::WaitingSudo).await;
    
    let install_handle = tokio::spawn(async move {
        // Now `shutdown_rx` is moved into this task
        let start_time = Instant::now();
        
        // --- Actual installation steps --- 
        // Use tokio::select! to race steps against shutdown signal
        tokio::select! {
            // Branch 1: Actual Installation Steps
            result = async { 
                // --- 1. Determine Host IP and Network --- 
                update_install_state(InstallationState::DetectingNetwork).await;
                let (host_ip, _netmask, network) = get_host_ip_and_mask(args.interface.as_deref())
                    .wrap_err("Failed to determine host IP (required for install)")?;
                
                // --- 2. Find Available Floating IP --- 
                let bootstrap_ip = find_available_ip(host_ip, network, args.start_offset, args.max_ip_search)
                    .await
                    .wrap_err("Failed to find an available IP address for the bootstrap node")?;
                
                // --- 3. Install k3s --- 
                update_install_state(InstallationState::InstallingK3s).await;
                install_k3s().await.wrap_err("Failed to set up k3s")?;

                // --- 4. Configure kubectl --- 
                let kubeconfig_path = configure_kubectl().await.wrap_err("Failed to configure kubectl")?;
                std::env::set_var("KUBECONFIG", kubeconfig_path.to_string_lossy().to_string());

                // --- 5. Wait for Node Ready --- 
                update_install_state(InstallationState::WaitingK3s).await;
                wait_for_node_ready(&kubeconfig_path).await.wrap_err("Timed out waiting for Kubernetes node")?;

                // --- 6. Install Helm --- 
                install_helm().await.wrap_err("Failed to set up Helm")?;

                // --- 7. Install Tinkerbell Stack --- 
                update_install_state(InstallationState::DeployingTinkerbell).await;
                install_tinkerbell_stack(bootstrap_ip, network, &kubeconfig_path).await.wrap_err("Failed to install Tinkerbell stack")?;

                // --- 8. Install Dragonfly Helm Chart (if applicable) --- 
                update_install_state(InstallationState::DeployingDragonfly).await;
                install_dragonfly_chart(bootstrap_ip, &kubeconfig_path).await.wrap_err("Failed to install Dragonfly chart")?;

                // --- 9. Mark as Ready --- 
                update_install_state(InstallationState::Ready).await;
                
                let elapsed = start_time.elapsed();
                info!("✅ Dragonfly installation completed in {:.1?}!", elapsed);
                
                // --- 10. Wait for 3 seconds to show the flame animation --- 
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                
                // --- 11. Send browser redirect event ---
                send_redirect_event(bootstrap_ip).await;
                
                // --- 12. Automatically shut down the installer after 2 more seconds ---
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                info!("🚀 Redirecting to k3s-hosted Dragonfly and shutting down installer");
                
                Ok::<(), color_eyre::Report>(()) // Explicit type for Ok needed inside async block
            } => { result } // If installation finishes first, return its result
            
            // Branch 2: Shutdown Signal Received
             // Use the original shutdown_rx (which was moved into this async block)
             _ = shutdown_rx.changed() => {
                info!("Shutdown signal received during installation, aborting...");
                // Return an error indicating cancellation
                Err(color_eyre::eyre::eyre!("Installation cancelled by user (Ctrl+C)"))
            }
        }
    });
    
    // Handle the result of the installation task
    match install_handle.await {
        Ok(Ok(_)) => {
            info!("Background installation task finished successfully.");
            // Send shutdown signal to main thread to exit gracefully
            let _ = shutdown_rx_clone.changed().await;
        }
        Ok(Err(e)) => {
            error!("Background installation task failed: {:#}", e);
            update_install_state(InstallationState::Failed(e.to_string())).await;
            eprintln!("Installation failed in background: {}", e);
             // Propagate error to main
             return Err(e);
        }
        Err(e) => { // JoinError (panic or cancellation)
            error!("Installation task panicked or was cancelled: {:#}", e);
            update_install_state(InstallationState::Failed("Installer task panicked or was cancelled".to_string())).await;
            eprintln!("Installation task failed: {}", e);
             // Return a new error
            return Err(color_eyre::eyre::eyre!("Installation task did not complete: {}", e));
        }
    }

    // Shutdown the server now
    info!("Shutdown signal received by main install thread. Aborting server task...");
    server_handle.abort(); // Forcefully stop the server task
    // Optionally wait a very short time for abort, but don't hang
    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), server_handle).await;
    
    info!("Installer exiting cleanly.");
    Ok(())
}

// Helper function to send browser redirect event
async fn send_redirect_event(bootstrap_ip: Ipv4Addr) {
    info!("Preparing to redirect browser to http://{}:3000", bootstrap_ip);
    
    // Get event manager reference
    let event_manager_arc: Option<Arc<dragonfly_server::event_manager::EventManager>> = {
        EVENT_MANAGER_REF.read().unwrap().as_ref().cloned()
    };

    if let Some(event_manager) = event_manager_arc {
        // Create a payload with the redirect URL
        let redirect_url = format!("http://{}:3000", bootstrap_ip);
        let payload = serde_json::json!({
            "url": redirect_url,
            "countdown": 1  // 1 second countdown
        });
        
        // Send a special "browser_redirect" event
        let event_data = format!("browser_redirect:{}", payload.to_string());
        info!("Sending redirect event: {}", event_data);
        
        if let Err(e) = event_manager.send(event_data) {
            error!("Failed to send redirect event: {}", e);
        } else {
            info!("Redirect event sent successfully");
        }
    } else {
        error!("Event manager not found, cannot send redirect event");
    }
}

// --- Helper function implementations (from previous response) ---

// Placeholder for run_shell_command - Implement robustly
fn run_shell_command(script: &str, description: &str) -> Result<()> {
    debug!("Running shell command: {}", description);
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .wrap_err_with(|| format!("Failed to execute command: {}", description))?;

    if !output.status.success() {
        error!("Command '{}' failed with status: {}", description, output.status);
        error!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
        error!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        color_eyre::eyre::bail!("Command '{}' failed", description);
    } else {
         debug!("Command '{}' succeeded.", description);
    }
    Ok(())
}

// Placeholder for run_command - Implement robustly
fn run_command(cmd: &str, args: &[&str], description: &str) -> Result<Output> {
    debug!("Running command: {} {}", cmd, args.join(" "));
     let output = Command::new(cmd)
        .args(args)
        .output()
        .wrap_err_with(|| format!("Failed to execute command: {}", description))?;

     if !output.status.success() {
        error!("Command '{}' failed with status: {}", description, output.status);
        error!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
        error!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        color_eyre::eyre::bail!("Command '{}' failed", description);
    } else {
        debug!("Command '{}' succeeded.", description);
    }
     Ok(output)
}


// Placeholder for is_command_present - Implement robustly
fn is_command_present(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").output().is_ok() // Simple check
}

// Helper function to find the primary network interface and its IP/netmask
fn get_host_ip_and_mask(interface_name: Option<&str>) -> Result<(Ipv4Addr, Ipv4Addr, Ipv4Network)> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};

    // Get all network interfaces
    let interfaces = NetworkInterface::show()
        .wrap_err("Failed to retrieve network interfaces")?;
    
    debug!("Found {} network interfaces", interfaces.len());

    let mut candidate: Option<(Ipv4Addr, Ipv4Addr, Ipv4Network)> = None;

    // Loop through interfaces to find a suitable one
    for iface in interfaces {
        // Skip loopback, virtual bridges (libvirt, docker, virtualbox), or interfaces without MAC address
        let name = &iface.name;
        if name == "lo" || 
           name.starts_with("virbr") || 
           name.starts_with("docker") || 
           name.starts_with("vboxnet") || 
           iface.mac_addr.is_none() 
        {
            debug!("Skipping interface {}: loopback or virtual bridge/interface", name);
            continue;
        }

        // If a specific interface is requested, only consider that one
        if let Some(requested_name) = interface_name {
            if name != requested_name {
                debug!("Skipping interface {}: not the requested interface", name);
                continue;
            }
        }

        // Find first IPv4 address with netmask
        for addr in &iface.addr {
            if let network_interface::Addr::V4(v4_addr) = addr {
                // Check both IP and netmask are defined
                let ip = v4_addr.ip;
                
                // Make sure we have a netmask
                if let Some(netmask) = v4_addr.netmask {
                    // Try to create a network from the IP and netmask
                    match Ipv4Network::with_netmask(ip, netmask) {
                        Ok(network) => {
                            debug!("Found interface {}: IP={}, netmask={}, network={}", 
                                   iface.name, ip, netmask, network);
                            
                            // If user specified this interface, return it immediately
                            if interface_name.is_some() {
                                return Ok((ip, netmask, network));
                            }
                            
                            // Otherwise, save as a candidate and prefer non-local IPs
                            if !is_private_or_local_ip(ip) {
                                // Public IP gets priority
                                return Ok((ip, netmask, network));
                            } else if candidate.is_none() {
                                // First private IP we found
                                candidate = Some((ip, netmask, network));
                            }
                        },
                        Err(e) => {
                            warn!("Invalid network for interface {}: {}", iface.name, e);
                        }
                    }
                }
            }
        }
    }

    // If we have a candidate, use it
    if let Some((ip, netmask, network)) = candidate {
        return Ok((ip, netmask, network));
    }

    // If we reached here, we couldn't find a suitable interface
    if let Some(name) = interface_name {
        bail!("Could not find a usable IPv4 address on interface '{}'", name)
    } else {
        bail!("Could not find any network interface with a usable IPv4 address. Try specifying an interface with --interface")
    }
}

// Check if an IP is private (RFC1918) or link-local
fn is_private_or_local_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || ip.is_loopback() || ip.is_unspecified()
}

// Find an available IP address on the network
async fn find_available_ip(
    host_ip: Ipv4Addr,
    network: ipnetwork::Ipv4Network,
    start_offset: u8,
    max_tries: u8,
) -> Result<Ipv4Addr> {
    info!("Searching for available IP in network {} starting from offset {} of host {}", 
          network, start_offset, host_ip);

    // Calculate starting IP by adding offset to host IP
    let start_ip_int = u32::from(host_ip).wrapping_add(start_offset as u32);
    let mut current_ip = Ipv4Addr::from(start_ip_int);
    
    // Get network and broadcast addresses
    let network_addr = network.network();
    let broadcast_addr = network.broadcast();

    for i in 0..max_tries {
        // Ensure the IP is actually within the calculated network range
        if !network.contains(current_ip) {
            warn!("IP search crossed subnet boundary at {}. Stopping search.", current_ip);
            break; // Stop if we leave the subnet
        }

        // Skip network address, broadcast address, and the host's own IP
        if current_ip == network_addr || current_ip == broadcast_addr || current_ip == host_ip {
            debug!("Skipping reserved/host IP: {}", current_ip);
        } else {
            debug!("Checking if IP {} is available...", current_ip);
            
            // Check if the IP is available using ping
            match check_ip_availability(current_ip).await {
                Ok(true) => {
                    info!("IP {} appears to be available", current_ip);
                    return Ok(current_ip); // Found an available IP
                }
                Ok(false) => {
                    debug!("IP {} is already in use", current_ip);
                }
                Err(e) => {
                    warn!("Error checking IP {}: {}", current_ip, e);
                }
            }
        }

        // Move to the next IP
        let next_ip_int = u32::from(current_ip).wrapping_add(1);
        current_ip = Ipv4Addr::from(next_ip_int);

        // Safety check to avoid infinite loops
        if i + 1 == max_tries {
            warn!("Reached maximum IP search attempts ({})", max_tries);
        }
    }

    bail!("Could not find an available IP address in network {} after checking {} addresses", 
          network, max_tries)
}

// Check if an IP address is available (not in use)
async fn check_ip_availability(ip: Ipv4Addr) -> Result<bool> {
    let ip_str = ip.to_string();
    debug!("Checking availability of IP: {}", ip_str);
    
    // Determine the right ping command arguments based on platform
    #[cfg(target_os = "windows")]
    let args = ["-n", "1", "-w", "500", &ip_str]; // Windows: -n count, -w timeout in ms
    
    #[cfg(not(target_os = "windows"))]
    let args = ["-c", "1", "-W", "1", &ip_str]; // Unix: -c count, -W timeout in seconds
    
    // Run ping command with a timeout
    let output = Command::new("ping")
        .args(&args)
        .output()
        .wrap_err_with(|| format!("Failed to execute ping command for {}", ip_str))?;
    
    // Check result: if ping succeeds, the IP is taken; if it fails, the IP is likely available
    Ok(!output.status.success())
}

async fn install_k3s() -> Result<()> {
    // Add macOS Docker check
    #[cfg(target_os = "macos")]
    {
        debug!("Running on macOS, checking Docker...");
        let docker_check = Command::new("docker")
            .arg("info")
            .output();
            
        match docker_check {
            Ok(output) if output.status.success() => {
                info!("Docker is installed and running.");
            }
            Ok(output) => {
                 error!("Docker command failed with status: {}. Stderr: {}", 
                       output.status, String::from_utf8_lossy(&output.stderr));
                 bail!("Docker is installed but not running or responding. Please start Docker Desktop.");
            }
            Err(e) => {
                 error!("Failed to execute Docker command: {}", e);
                 bail!("Docker command not found. Please install Docker Desktop from https://www.docker.com/products/docker-desktop/");
            }
        }
    }

    debug!("Checking if k3s is already installed");
    
    // Check for existing k3s config and service
    let config_exists = check_file_exists("/etc/rancher/k3s/k3s.yaml").await;
    
    // Conditionally define service_exists based on OS
    #[cfg(not(target_os = "macos"))]
    let service_exists = is_command_present("k3s");
    #[cfg(target_os = "macos")]
    let service_exists = false; // k3s doesn't run as a direct service on macOS

    #[cfg(not(target_os = "macos"))]
    let is_running = check_service_running("k3s").await;
    #[cfg(target_os = "macos")]
    let is_running = false; // Assume not running as a service on macOS initially
    
    // Adjust logic for macOS where k3s runs in Docker (handled by k3d or similar)
    if cfg!(not(target_os = "macos")) && service_exists && config_exists && is_running {
        info!("K3s is already installed and running (Linux)");
        return Ok(());
    }
    
    // Handle partially installed k3s on Linux
    if cfg!(not(target_os = "macos")) && service_exists && !is_running {
        info!("K3s service exists but isn't running, starting service (Linux)...");
        restart_k3s_service().await?;
        return Ok(());
    }
    
    // Full installation needed
    if cfg!(target_os = "macos") {
        // Use k3d to create cluster on macOS, as direct install isn't typical
        info!("Using k3d to create k3s cluster in Docker (macOS)");
        // Check if k3d is installed
        if !is_command_present("k3d") {
             bail!("k3d command not found. Please install k3d: https://k3d.io/#installation");
        }
        // Check if cluster already exists
        let cluster_check = Command::new("k3d")
            .args(["cluster", "list", "dragonfly"])
            .output()?;
        let cluster_exists = String::from_utf8_lossy(&cluster_check.stdout).contains("dragonfly");
        
        if !cluster_exists {
            info!("Creating k3d cluster 'dragonfly'...");
            // Create k3d cluster, disable traefik, map necessary ports
             run_command("k3d", &[
                 "cluster", "create", "dragonfly",
                 "--k3s-arg", "--disable=traefik@server:0", // Disable built-in Traefik
                 "-p", "80:80@loadbalancer",   // Map HTTP
                 "-p", "443:443@loadbalancer", // Map HTTPS
                 "-p", "3000:3000@loadbalancer", // Map Dragonfly UI/API
                 "-p", "8080:8080@loadbalancer", // Map Tinkerbell Hook
                 // Add other ports needed by Tinkerbell (TFTP, DHCP, DNS)? 
                 // Mapping UDP ports with k3d needs careful consideration
             ], "create k3d cluster")?;
             info!("k3d cluster 'dragonfly' created.");
        } else {
             info!("k3d cluster 'dragonfly' already exists.");
        }
        // k3d handles starting the k3s server within Docker
    } else {
        // Linux k3s installation
        info!("Installing k3s (single-node Linux)");
        let script = r#"curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--disable traefik' sh -"#;
        run_shell_command(script, "k3s installation script")?;

        // Verify installation
        if !is_command_present("k3s") {
            bail!("k3s installation command ran, but 'k3s' command not found afterwards.");
        }
        
        // Wait briefly for k3s to create its config
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Make sure the service is up
        if !check_service_running("k3s").await {
            info!("Starting k3s service...");
            restart_k3s_service().await?;
        }
    }
    
    info!("K3s setup completed successfully");
    Ok(())}

async fn check_service_running(service_name: &str) -> bool {
    let output = Command::new("systemctl")
        .args(["is-active", service_name])
        .output();
        
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.trim() == "active"
        },
        Err(_) => false,
    }
}

async fn restart_k3s_service() -> Result<()> {
    debug!("Restarting k3s service");
    let restart_cmd = "sudo systemctl restart k3s";
    run_shell_command(restart_cmd, "restart k3s service")?;
    
    // Check if service started successfully
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    if check_service_running("k3s").await {
        debug!("K3s service started successfully");
        Ok(())
    } else {
        color_eyre::eyre::bail!("Failed to start k3s service after restart attempt");
    }
}

async fn configure_kubectl() -> Result<PathBuf> {
    debug!("Configuring kubectl access");
    let source_path = PathBuf::from("/etc/rancher/k3s/k3s.yaml");
    let dest_path = std::env::current_dir()?.join("k3s.yaml");

    // Check if the destination file already exists and is valid
    if dest_path.exists() {
        debug!("kubectl config already exists at {:?}, testing validity", dest_path);
        
        // Test if the existing config works
        let test_result = Command::new("kubectl")
            .args(["--kubeconfig", dest_path.to_str().unwrap(), "cluster-info"])
            .output();
            
        if let Ok(output) = test_result {
            if output.status.success() {
                debug!("Existing kubectl config is valid");
                return Ok(dest_path);
            }
            
            debug!("Existing kubectl config is invalid, will recreate");
        }
    }

    // Wait for k3s to create the config file
    let mut attempts = 0;
    while !source_path.exists() && attempts < 12 {
        debug!("Waiting for k3s.yaml to be created (attempt {}/12)...", attempts + 1);
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        attempts += 1;
    }
    
    if !source_path.exists() {
        color_eyre::eyre::bail!("k3s config file not found at {:?} after 60 seconds. Was k3s installed correctly?", source_path);
    }

    // Determine if sudo is likely needed for copy/chown
    let uid = unsafe { libc::geteuid() };
    let needs_sudo = uid != 0; // Simple check if running as root

    debug!("Copying {:?} to {:?}", source_path, dest_path);
    let cp_cmd = format!(
        "{} cp {} {}",
        if needs_sudo { "sudo" } else { "" },
        source_path.display(),
        dest_path.display()
    );
    run_shell_command(&cp_cmd.trim(), "copy k3s.yaml")?; // trim leading space if no sudo

    // Get current user for chown
    let user = std::env::var("SUDO_USER") // If run with sudo, chown to the original user
        .or_else(|_| std::env::var("USER")) // Otherwise, use current user
        .wrap_err("Could not determine user for chown")?;

    let chown_cmd = format!(
        "{} chown {} {}",
        if needs_sudo { "sudo" } else { "" },
        user,
        dest_path.display()
    );
    run_shell_command(&chown_cmd.trim(), "chown k3s.yaml")?; // trim leading space if no sudo

    debug!("k3s.yaml copied and permissions set for user '{}'", user);
    Ok(dest_path)
}

async fn wait_for_node_ready(kubeconfig_path: &PathBuf) -> Result<()> {
    info!("Waiting for Kubernetes node to become ready...");
    let max_wait = std::time::Duration::from_secs(300); // 5 minutes timeout
    let check_interval = std::time::Duration::from_secs(5);
    let start_time = std::time::Instant::now();
    
    // Print a dot every few seconds to show progress
    let mut dots_printed = 0;
    let mut node_ready = false;
    let mut coredns_ready = false;

    loop {
        if start_time.elapsed() > max_wait {
            color_eyre::eyre::bail!("Timed out waiting for Kubernetes node to become ready after {} seconds.", max_wait.as_secs());
        }

        // Step 1: Check if the node itself is ready
        if !node_ready {
            let output_result = Command::new("kubectl")
                .args(["get", "nodes", "--no-headers"])
                .env("KUBECONFIG", kubeconfig_path)
                .output();

            match output_result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    
                    // Node is ready if "Ready" appears in the output and "NotReady" doesn't
                    if output.status.success() && 
                    stdout.contains(" Ready") && 
                    !stdout.contains("NotReady") {
                        debug!("Kubernetes node has become ready");
                        node_ready = true;
                    } else {
                        // Node exists but is not ready yet
                        debug!("Waiting for node to become ready: {}", stdout.trim());
                    }
                },
                Err(e) => {
                    // Most likely the API server is still starting
                    debug!("kubectl command error (will retry): {}", e);
                }
            }
        }

        // Step 2: Once node is ready, check for CoreDNS readiness
        if node_ready && !coredns_ready {
            // First check if CoreDNS pods exist
            let coredns_exists_result = Command::new("kubectl")
                .args(["get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns", "--no-headers"])
                .env("KUBECONFIG", kubeconfig_path)
                .output();
                
            let pods_exist = if let Ok(output) = &coredns_exists_result {
                output.status.success() && !String::from_utf8_lossy(&output.stdout).trim().is_empty()
            } else {
                false
            };
                
            if pods_exist {
                // Check if at least one CoreDNS pod is ready
                let coredns_status = Command::new("kubectl")
                    .args(["get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns", 
                           "-o", "jsonpath='{.items[*].status.conditions[?(@.type==\"Ready\")].status}'"])
                    .env("KUBECONFIG", kubeconfig_path)
                    .output();
                    
                if let Ok(status) = coredns_status {
                    let status_str = String::from_utf8_lossy(&status.stdout).trim().trim_matches('\'').to_string();
                    if status_str.contains("True") {
                        debug!("CoreDNS is ready");
                        coredns_ready = true;
                    } else {
                        debug!("Waiting for CoreDNS to become ready: {}", status_str);
                    }
                }
            } else {
                debug!("CoreDNS pods not found yet");
            }
        }

        // Print status
        print!(".");
        std::io::stdout().flush().wrap_err("Failed to flush stdout")?;
        dots_printed += 1;

        // Check if both conditions are met
        if node_ready && coredns_ready {
            // Add a newline after dots if we printed any
            if dots_printed > 0 {
                println!();
            }
            info!("Kubernetes node and CoreDNS are ready");
            return Ok(());
        }

        tokio::time::sleep(check_interval).await;
    }
}

async fn install_helm() -> Result<()> {
    debug!("Checking if Helm is already installed");
    if is_command_present("helm") {
        // Additionally check the helm version works
        let version_check = Command::new("helm")
            .args(["version", "--short"])
            .output();
            
        if let Ok(output) = version_check {
            if output.status.success() {
                info!("Helm is already installed and working");
                return Ok(());
            }
        }
    }
    
    info!("Installing Helm");
    let script = r#"curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"#;
    run_shell_command(script, "Helm installation script")?;

    // Verify installation
    if !is_command_present("helm") {
        color_eyre::eyre::bail!("Helm installation command ran, but 'helm' command not found afterwards.");
    }

    info!("Helm installed successfully");
    Ok(())
}

async fn install_dragonfly_chart(bootstrap_ip: Ipv4Addr, kubeconfig_path: &PathBuf) -> Result<()> {
    // --- Clone the GitHub repository for the Helm chart ---
    info!("Fetching Dragonfly Helm charts from GitHub...");
    
    // Create a temporary directory for the repo
    let repo_dir = std::env::temp_dir().join("dragonfly-charts");
    
    // Remove the directory if it already exists
    if repo_dir.exists() {
        fs::remove_dir_all(&repo_dir).await
            .wrap_err_with(|| format!("Failed to clean up previous charts directory: {:?}", repo_dir))?;
    }
    
    // Clone the repository
    let clone_cmd = format!(
        "git clone --depth 1 https://github.com/Zorlin/dragonfly-charts.git {}",
        repo_dir.display()
    );
    run_shell_command(&clone_cmd, "clone Dragonfly Helm charts").wrap_err("Failed to clone Helm charts repository")?;
    
    // Path to the chart
    let chart_path = repo_dir.join("dragonfly");
    
    // Check if the chart path exists
    if !chart_path.exists() {
        bail!("Helm chart not found in expected location: {:?}", chart_path);
    }
    
    // --- Generate values.yaml ---
    let values_content = format!(
        r#"global:
    publicIP: {bootstrap_ip}
"#,
        bootstrap_ip = bootstrap_ip,
    );

    let values_path = PathBuf::from("values.yaml");
    fs::write(&values_path, values_content).await
        .wrap_err_with(|| format!("Failed to write Helm values to {:?}", values_path))?;
    debug!("Generated Helm values file: {:?}", values_path);

    // --- Run Helm Install/Upgrade with the local chart path ---
    let helm_args = [
        "upgrade", "--install", "dragonfly",
        chart_path.to_str().ok_or_else(|| color_eyre::eyre::eyre!("Chart path is not valid UTF-8"))?,
        "--create-namespace",
        "--namespace", "tink",
        "--wait",
        "--timeout", "10m",
        "-f", values_path.to_str().ok_or_else(|| color_eyre::eyre::eyre!("values.yaml path is not valid UTF-8"))?
    ];

    info!("Deploying Dragonfly");
    run_command("helm", &helm_args, "install/upgrade Dragonfly Helm chart")?;
    Ok(())
}

async fn install_tinkerbell_stack(bootstrap_ip: Ipv4Addr, network: Ipv4Network, kubeconfig_path: &PathBuf) -> Result<()> {
    // Check if the Tinkerbell stack is already installed
    let release_exists = {
        let release_check = Command::new("helm")
            .args(["list", "-n", "tink", "--filter", "tink-stack", "--short"])
            .output()?;
            
        release_check.status.success() && 
        !String::from_utf8_lossy(&release_check.stdout).trim().is_empty()
    };
    
    // Log whether we're installing or upgrading
    if release_exists {
        info!("Tinkerbell stack already exists, will upgrade");
    } else {
        info!("Tinkerbell stack not found, will install");
    }

    // --- Ensure k3s is ready and Pod CIDR is available ---
    // First, wait for node to be fully initialized
    let node_info = Command::new("kubectl")
        .args(["get", "node", "-o", "wide"])
        .env("KUBECONFIG", kubeconfig_path)
        .output()
        .wrap_err("Failed to get node information")?;
    
    debug!("Node status: {}", String::from_utf8_lossy(&node_info.stdout));
    
    // Get Pod CIDR - this is critical, so we don't use fallbacks
    info!("Getting Pod CIDR from Kubernetes nodes...");
    let pod_cidr_output = Command::new("kubectl")
        .args(["get", "nodes", "-o", "jsonpath='{.items[*].spec.podCIDR}'"])
        .env("KUBECONFIG", kubeconfig_path)
        .output()
        .wrap_err("Failed to get pod CIDRs")?;
    
    let pod_cidr_str = String::from_utf8_lossy(&pod_cidr_output.stdout)
        .trim()
        .trim_matches('\'')
        .to_string();
    
    debug!("Raw Pod CIDR output: '{}'", pod_cidr_str);
    
    let pod_cidrs: Vec<String> = pod_cidr_str
        .split(|c| c == ' ' || c == ',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    
    if pod_cidrs.is_empty() {
        bail!("Failed to detect Pod CIDR. This is required for Tinkerbell installation.\nVerify the Kubernetes node is fully initialized with 'kubectl --kubeconfig={} get nodes -o wide'", 
              kubeconfig_path.display());
    }
    
    info!("Successfully detected Pod CIDR(s): {:?}", pod_cidrs);
    
    // Prepare the trustedProxies configuration
    let mut trusted_proxies = pod_cidrs;
    
    // Add the host network to trusted proxies
    let network_cidr = network.to_string();
    debug!("Adding host network CIDR to trusted proxies: {}", network_cidr);
    trusted_proxies.push(network_cidr);
    
    // Use bootstrap_ip for smee host
    let smee_host_ip = bootstrap_ip;
    
    // --- Generate values.yaml ---
    let values_content = format!(
        r#"global:
  trustedProxies:
{}
  publicIP: {bootstrap_ip}
smee:
  dhcp:
    enabled: false
    allowUnknownHosts: true
    mode: auto-proxy
    httpIPXE:
      scriptUrl:
        scheme: "http"
        host: "{smee_host_ip}"
        port: 3000
        path: "/"
  additionalArgs:
    - "--dhcp-http-ipxe-script-prepend-mac=true"
stack:
  hook:
    enabled: false # We handle Hook downloads via the Dragonfly server
    persistence:
      hostPath: /var/lib/dragonfly
"#,
        trusted_proxies.iter().map(|p| format!("    - \"{}\"", p)).collect::<Vec<_>>().join("\n"),
        bootstrap_ip = bootstrap_ip,
        smee_host_ip = smee_host_ip,
    );

    let values_path = PathBuf::from("values.yaml");
    fs::write(&values_path, values_content).await
        .wrap_err_with(|| format!("Failed to write Helm values to {:?}", values_path))?;
    debug!("Generated Helm values file: {:?}", values_path);

    // --- Clone the GitHub repository for the Helm chart ---
    info!("Fetching Dragonfly Helm charts from GitHub...");
    
    // Create a temporary directory for the repo
    let repo_dir = std::env::temp_dir().join("dragonfly-charts");
    
    // Remove the directory if it already exists
    if repo_dir.exists() {
        fs::remove_dir_all(&repo_dir).await
            .wrap_err_with(|| format!("Failed to clean up previous charts directory: {:?}", repo_dir))?;
    }
    
    // Clone the repository
    let clone_cmd = format!(
        "git clone --depth 1 https://github.com/Zorlin/dragonfly-charts.git {}",
        repo_dir.display()
    );
    run_shell_command(&clone_cmd, "clone Dragonfly Helm charts").wrap_err("Failed to clone Helm charts repository")?;
    
    // Path to the chart
    let chart_path = repo_dir.join("tinkerbell").join("stack");
    
    // Check if the chart path exists
    if !chart_path.exists() {
        bail!("Helm chart not found in expected location: {:?}", chart_path);
    }

    // --- Build the Helm chart dependencies ---
    info!("Building Helm chart dependencies...");
    let dependency_build_cmd = format!(
        "cd {} && helm dependency build",
        chart_path.display()
    );
    run_shell_command(&dependency_build_cmd, "build Helm chart dependencies")
        .wrap_err("Failed to build Helm chart dependencies")?;

    // --- Run Helm Install/Upgrade with the local chart path ---
    let helm_args = [
        "upgrade", "--install", "tink-stack",
        chart_path.to_str().ok_or_else(|| color_eyre::eyre::eyre!("Chart path is not valid UTF-8"))?,
        "--create-namespace",
        "--namespace", "tink",
        "--wait",
        "--timeout", "10m",
        "-f", values_path.to_str().ok_or_else(|| color_eyre::eyre::eyre!("values.yaml path is not valid UTF-8"))?,
    ];

    info!("Deploying Dragonfly Tinkerbell stack...");
    run_command("helm", &helm_args, "install/upgrade Dragonfly Tinkerbell Helm chart")?;

    // Verify the deployment
    let deployment_check = Command::new("kubectl")
        .args(["get", "pods", "-n", "tink", "--no-headers"])
        .env("KUBECONFIG", kubeconfig_path)
        .output()
        .wrap_err("Failed to check deployment status")?;
    
    if deployment_check.status.success() {
        let pods_output = String::from_utf8_lossy(&deployment_check.stdout).trim().to_string();
        if !pods_output.is_empty() && 
           !pods_output.contains("Pending") && 
           !pods_output.contains("Error") && 
           !pods_output.contains("CrashLoopBackOff") {
            info!("Dragonfly Tinkerbell stack is running properly");
        } else {
            warn!("Dragonfly Tinkerbell stack deployed but some pods may not be ready. Check with 'kubectl --kubeconfig={} get pods -n tink'", 
                  kubeconfig_path.display());
        }
    }

    // Clean up - remove the cloned repository
    debug!("Cleaning up temporary chart repository...");
    let _ = fs::remove_dir_all(&repo_dir).await; // Best effort cleanup, don't fail if it doesn't work

    info!("Dragonfly Tinkerbell stack {} successfully", if release_exists { "upgraded" } else { "installed" });
    Ok(())
}


/// Convert an IP and prefix length to CIDR notation
fn network_to_cidr(ip: Ipv4Addr, prefix_len: u8) -> Result<String> {
    // Ensure prefix length is valid (0-32)
    if prefix_len > 32 {
        bail!("Invalid prefix length: {}", prefix_len);
    }
    
    // Apply the netmask to the IP address to get the network address
    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    let network_addr = Ipv4Addr::from(ip_u32 & mask);
    
    // Return in CIDR notation
    Ok(format!("{}/{}", network_addr, prefix_len))
}

/// Convert a netmask (like 255.255.255.0) to a prefix length (like 24)
fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from(netmask).count_ones();
    bits as u8
}

// Helper function to check if a file exists and is readable
async fn check_file_exists(path: impl AsRef<std::path::Path>) -> bool {
    if let Ok(metadata) = tokio::fs::metadata(path.as_ref()).await {
        metadata.is_file()
    } else {
        false
    }
}

// Helper function to check if passwordless sudo is available
async fn check_passwordless_sudo() -> bool {
    let output = Command::new("sudo")
        .args(["-n", "true"])  // -n means non-interactive
        .output();
        
    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

