use std::process::Command;
use std::path::{Path, PathBuf};
use tokio::sync::watch;
use tokio::signal::unix::{signal, SignalKind};
use anyhow::{Result, Context, anyhow, bail};
use tracing::{info, error, warn, debug};
use tracing_appender;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use dirs;
use std::os::unix::fs::PermissionsExt;
use nix::libc;
use std::str;
use tokio::fs;
use serde_yaml;
use std::path::Path as StdPath;
use crate::status::{check_kubernetes_connectivity, get_webui_address};
use crate::store::DragonflyStore;

// The different deployment modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    Simple,
    Flight,
    Swarm,
}

impl DeploymentMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeploymentMode::Simple => "simple",
            DeploymentMode::Flight => "flight",
            DeploymentMode::Swarm => "swarm",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "simple" => Some(DeploymentMode::Simple),
            "flight" => Some(DeploymentMode::Flight),
            "swarm" => Some(DeploymentMode::Swarm),
            _ => None,
        }
    }
}

// Constants for file paths
const MODE_DIR: &str = "/etc/dragonfly";
const MODE_FILE: &str = "/etc/dragonfly/mode";
const SYSTEMD_UNIT_FILE: &str = "/etc/systemd/system/dragonfly.service";
const K3S_CONFIG_DIR: &str = "/etc/dragonfly/k3s";
const EXECUTABLE_TARGET_PATH: &str = "/usr/local/bin/dragonfly";
const HANDOFF_READY_FILE: &str = "/var/lib/dragonfly/handoff_ready";

// Get the current mode (or None if not set)
pub async fn get_current_mode() -> Result<Option<DeploymentMode>> {
    // Try to get the mode from ReDB
    const REDB_PATH: &str = "/var/lib/dragonfly/dragonfly.redb";

    if Path::new(REDB_PATH).exists() {
        match crate::store::RedbStore::open(REDB_PATH) {
            Ok(store) => {
                match store.get_setting("deployment_mode").await {
                    Ok(Some(mode_str)) => {
                        let mode = DeploymentMode::from_str(&mode_str);
                        if mode.is_some() {
                            debug!("Found deployment mode '{}' in ReDB", mode_str);
                            return Ok(mode);
                        }
                    }
                    Ok(None) => {
                        debug!("No deployment mode found in ReDB");
                    }
                    Err(e) => {
                        warn!("Failed to read deployment mode from ReDB: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to open ReDB for mode check: {}", e);
            }
        }
    }

    // Fall back to checking the mode file if database check failed
    if Path::new(MODE_FILE).exists() {
        debug!("Checking mode file for deployment mode");
        let content = tokio::fs::read_to_string(MODE_FILE)
            .await
            .context("Failed to read mode file")?;

        let mode = DeploymentMode::from_str(content.trim());
        return Ok(mode);
    }

    // No mode found in database or file
    debug!("No deployment mode found in database or file");
    Ok(None)
}

// Save the current mode
pub async fn save_mode(mode: DeploymentMode, already_elevated: bool) -> Result<()> {
    const DB_DIR: &str = "/var/lib/dragonfly";
    const REDB_PATH: &str = "/var/lib/dragonfly/dragonfly.redb";

    // Ensure the directory exists
    let db_dir_path = Path::new(DB_DIR);
    if !db_dir_path.exists() {
        if !already_elevated && !nix::unistd::geteuid().is_root() {
            bail!("Database directory {} does not exist. Please run with sudo or as root to create it.", DB_DIR);
        }
        tokio::fs::create_dir_all(db_dir_path)
            .await
            .with_context(|| format!("Failed to create database directory: {}", DB_DIR))?;
        info!("Created database directory: {}", DB_DIR);
    }

    // Open ReDB and save the mode
    let store = crate::store::RedbStore::open(REDB_PATH)
        .map_err(|e| anyhow!("Failed to open ReDB at {}: {}", REDB_PATH, e))?;

    let mode_str = mode.as_str();
    store.put_setting("deployment_mode", mode_str)
        .await
        .map_err(|e| anyhow!("Failed to save deployment mode: {}", e))?;

    info!("Successfully saved deployment mode '{}' to ReDB: {}", mode_str, REDB_PATH);
    Ok(())
}

// Add a platform detection function
fn is_macos() -> bool {
    // Use synchronous check
    std::env::consts::OS == "macos" || std::env::consts::OS == "darwin"
}

// Generate systemd socket unit for Simple mode
pub async fn generate_systemd_socket_unit(
    service_name: &str,
    description: &str
) -> Result<()> {
    // Create the socket file for socket activation
    let socket_content = format!(
        r#"[Unit]
Description={} Socket
Documentation=https://github.com/your-repo/dragonfly

[Socket]
ListenStream=3000
# Accept=no means we're using socket activation
Accept=no
SocketUser=root
SocketMode=0666

[Install]
WantedBy=sockets.target
"#,
        description
    );

    // Write the socket file
    let socket_file = format!("/etc/systemd/system/{}.socket", service_name);
    tokio::fs::write(&socket_file, socket_content)
        .await
        .context("Failed to write systemd socket file")?;
    
    info!("Generated systemd socket unit file: {}", socket_file);
    
    Ok(())
}

// Generate systemd service unit for Simple mode
pub async fn generate_systemd_unit(
    service_name: &str, 
    exec_path: &str, 
    description: &str
) -> Result<()> {
    // First create the socket unit
    generate_systemd_socket_unit(service_name, description).await?;
    
    // Now create the service file
    let unit_content = format!(
        r#"[Unit]
Description={}
Documentation=https://github.com/your-repo/dragonfly
After=network.target
Requires={}.socket

[Service]
Type=notify
Environment="DRAGONFLY_SERVICE=1"
ExecStart={}
# Don't restart immediately; add a short delay
Restart=on-failure
RestartSec=1
# Make sure the service starts only when the socket is ready
# This ensures proper socket activation
WatchdogSec=10

# Hardening options
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"#,
        description, service_name, exec_path
    );

    // Write the unit file
    let unit_file = format!("/etc/systemd/system/{}.service", service_name);
    tokio::fs::write(&unit_file, unit_content)
        .await
        .context("Failed to write systemd unit file")?;

    // Reload systemd to recognize the new unit
    let output = Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .context("Failed to reload systemd")?;

    if !output.status.success() {
        warn!("Failed to reload systemd: {}", String::from_utf8_lossy(&output.stderr));
    }

    info!("Generated systemd service unit file: {}", unit_file);
    
    Ok(())
}

// Ensure log directory exists with proper permissions
pub fn ensure_log_directory() -> Result<String, anyhow::Error> {
    let log_dir = if cfg!(target_os = "macos") {
        // ~/Library/Logs/Dragonfly
        dirs::home_dir()
            .ok_or_else(|| anyhow!("Could not find home directory"))?
            .join("Library/Logs/Dragonfly")
    } else if cfg!(target_os = "linux") {
        // /var/log/dragonfly
        PathBuf::from("/var/log/dragonfly")
    } else {
        // Default to ~/.dragonfly/logs for other systems
        dirs::home_dir()
            .ok_or_else(|| anyhow!("Could not find home directory"))?
            .join(".dragonfly/logs")
    };

    let log_dir_str = log_dir.to_str()
        .ok_or_else(|| anyhow!("Log directory path is not valid UTF-8"))?
        .to_string();

    if !log_dir.exists() {
        match std::fs::create_dir_all(&log_dir) {
            Ok(_) => {
                info!("Created log directory: {}", log_dir.display());
                #[cfg(target_os = "linux")]
                {
                    if !has_root_privileges() {
                        warn!("Log directory created, but running without root. Cannot set ownership/permissions for /var/log/dragonfly. Logs might not be writable.");
                    } else {
                        let current_uid = unsafe { libc::getuid() };
                        let current_gid = unsafe { libc::getgid() };
                        match nix::unistd::chown(log_dir.as_path(), Some(current_uid.into()), Some(current_gid.into())) {
                            Ok(_) => info!("Set ownership of log directory to current user ({}:{})", current_uid, current_gid),
                            Err(e) => warn!("Failed to set ownership of log directory {}: {}. This might be okay if already owned correctly.", log_dir.display(), e),
                        }
                        match std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o775)) {
                            Ok(_) => info!("Set permissions of log directory to 775"),
                            Err(e) => warn!("Failed to set permissions for log directory {}: {}", log_dir.display(), e),
                        }
                    }
                }
            }
            Err(e) => {
                if !log_dir.exists() {
                    return Err(anyhow!("Failed to create log directory {}: {}", log_dir.display(), e));
                } else {
                    warn!("Log directory {} already existed or was created concurrently.", log_dir.display());
                }
            }
        }
    }

    Ok(log_dir_str)
}

// Start the service via service manager
#[cfg(unix)]
pub fn start_service() -> Result<()> {
    // Check if we're on macOS
    if std::env::consts::OS == "macos" || std::env::consts::OS == "darwin" {
        info!("Running on macOS - continuing in foreground mode");
        // Just return successfully without daemonizing or using service management
        return Ok(());
    }

    // For non-macOS Unix systems, use systemctl to start the socket and service
    info!("Starting dragonfly systemd socket and service...");
    
    // Enable and start the socket first
    let socket_enable = Command::new("systemctl")
        .args(["enable", "dragonfly.socket"])
        .output()
        .context("Failed to enable systemd socket")?;
        
    if !socket_enable.status.success() {
        let stderr = String::from_utf8_lossy(&socket_enable.stderr);
        warn!("Failed to enable systemd socket: {}", stderr);
    }
    
    // Enable the service too
    let service_enable = Command::new("systemctl")
        .args(["enable", "dragonfly.service"])
        .output()
        .context("Failed to enable systemd service")?;
        
    if !service_enable.status.success() {
        let stderr = String::from_utf8_lossy(&service_enable.stderr);
        warn!("Failed to enable systemd service: {}", stderr);
    }
    
    // Start the socket first for socket activation
    let socket_output = Command::new("systemctl")
        .args(["start", "dragonfly.socket"])
        .output()
        .context("Failed to start systemd socket")?;
        
    if !socket_output.status.success() {
        let stderr = String::from_utf8_lossy(&socket_output.stderr);
        return Err(anyhow!("Failed to start systemd socket: {}", stderr));
    }
    
    // Start the service
    let output = Command::new("systemctl")
        .args(["start", "dragonfly.service"])
        .output()
        .context("Failed to start systemd service")?;
        
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Failed to start systemd service: {}", stderr));
    }
    
    info!("Socket and service started successfully");
    
    // Exit this process now that the service is started
    info!("Exiting current process as the service is now running in the background");
    std::process::exit(0);
}

// Stub for non-Unix platforms
#[cfg(not(unix))]
pub fn start_service() -> Result<()> {
    warn!("Service management is not supported on this platform");
    Ok(())
}

// Helper function to ensure /var/lib/dragonfly directory exists and is owned by the current user on macOS
async fn ensure_var_lib_ownership() -> Result<()> {
    // Only needed on macOS
    if !is_macos() {
        return Ok(());
    }
    
    let var_lib_dir = PathBuf::from("/var/lib/dragonfly");
    
    // First try to create the directory if it doesn't exist
    if !var_lib_dir.exists() {
        info!("Creating /var/lib/dragonfly directory");
        
        // Try to create with regular permissions first
        if let Err(e) = tokio::fs::create_dir_all(&var_lib_dir).await {
            info!("Failed to create /var/lib/dragonfly directly, using elevated permissions: {}", e);
            
            // Need to use admin privileges
            let user = std::env::var("USER").context("Failed to get current username")?;
            let script = format!(
                r#"do shell script "mkdir -p '{}' && chown '{}' '{}' && chmod 755 '{}'" with administrator privileges with prompt \"Dragonfly needs permission to create data directory\""#,
                var_lib_dir.display(),
                user,
                var_lib_dir.display(),
                var_lib_dir.display()
            );
            
            let osa_output_result = Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .output()
                .context("Failed to execute osascript for sudo prompt");

            // Handle the result of the command execution
            match osa_output_result {
                Ok(osa_output) => {
                    if !osa_output.status.success() {
                        let stderr_str = String::from_utf8_lossy(&osa_output.stderr);
                        warn!("Failed to create and chown /var/lib/dragonfly: {}", stderr_str);
                        // Continue anyway since this is not critical
                    } else {
                        info!("Created and set ownership of /var/lib/dragonfly to user {}", user);
                    }
                }
                Err(e) => {
                    warn!("Error executing osascript for directory creation: {}", e);
                }
            }
        } else {
            // Directory was created, now set ownership
            let user = std::env::var("USER").context("Failed to get current username")?;
            let script = format!(
                r#"do shell script "chown '{}' '{}'" with administrator privileges with prompt \"Dragonfly needs permission to set ownership of data directory\""#,
                user,
                var_lib_dir.display()
            );
            
            let osa_output = Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .output();
            
            if let Ok(output) = osa_output {
                if output.status.success() {
                    info!("Set ownership of /var/lib/dragonfly to user {}", user);
                } else {
                    let stderr_str = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to set ownership of /var/lib/dragonfly: {}", stderr_str);
                    // Continue anyway since this is not critical
                }
            } else if let Err(e) = osa_output {
                 warn!("Error executing osascript for ownership setting: {}", e);
            }
        }
    } else {
        // Directory already exists, just ensure ownership
        let user = std::env::var("USER").context("Failed to get current username")?;
        
        // Check current ownership
        let stat_output = Command::new("stat")
            .args(["-f", "%Su", var_lib_dir.to_str().unwrap()])
            .output();
            
        if let Ok(output) = stat_output {
            let current_owner = String::from_utf8_lossy(&output.stdout).trim().to_string();
            
            if current_owner != user {
                info!("Changing ownership of /var/lib/dragonfly from {} to {}", current_owner, user);
                
                let script = format!(
                    r#"do shell script "chown -R '{}' '{}'" with administrator privileges with prompt \"Dragonfly needs permission to set ownership of data directory\""#,
                    user,
                    var_lib_dir.display()
                );
                
                let osa_output = Command::new("osascript")
                    .arg("-e")
                    .arg(&script)
                    .output();
                
                if let Ok(output) = osa_output {
                    if output.status.success() {
                        info!("Set ownership of /var/lib/dragonfly to user {}", user);
                    } else {
                        let stderr_str = String::from_utf8_lossy(&output.stderr);
                        warn!("Failed to set ownership of /var/lib/dragonfly: {}", stderr_str);
                        // Continue anyway since this is not critical
                    }
                 } else if let Err(e) = osa_output {
                     warn!("Error executing osascript for ownership change: {}", e);
                 }
            } else {
                info!("/var/lib/dragonfly is already owned by user {}", user);
            }
        } else if let Err(e) = stat_output {
             warn!("Error executing stat command for ownership check: {}", e);
        }
    }
    
    Ok(())
}

// Check if the current process has root privileges
fn has_root_privileges() -> bool {
    #[cfg(unix)]
    {
        // Check if we can access a typically root-only directory
        if let Ok(uid) = std::process::Command::new("id")
            .args(["-u"])
            .output()
        {
            if let Ok(uid_str) = String::from_utf8(uid.stdout) {
                if let Ok(uid_num) = uid_str.trim().parse::<u32>() {
                    return uid_num == 0;
                }
            }
        }
        
        // Fallback to checking if we can write to a protected directory
        std::fs::metadata("/root").is_ok()
    }
    
    #[cfg(not(unix))]
    {
        // On other platforms, always return false
        return false;
    }
}

// Configure the system for Simple mode
pub async fn configure_simple_mode() -> Result<()> {
    info!("Configuring system for Simple mode");

    // Get the path to the current executable
    let current_exec_path = std::env::current_exe()
        .context("Failed to get current executable path")?;
    
    // Initialize logger
    let log_dir_path = ensure_log_directory()?;
    
    // Copy executable to /usr/local/bin if needed
    let target_path = Path::new(EXECUTABLE_TARGET_PATH);
    if !target_path.exists() {
        info!("Copying executable to {}", EXECUTABLE_TARGET_PATH);
        
        // Check if we're on macOS
        if is_macos() {
            // For macOS, try a normal copy first
            match Command::new("cp")
                .args([&current_exec_path.to_string_lossy(), EXECUTABLE_TARGET_PATH])
                .output()
            {
                Ok(output) if output.status.success() => {
                    info!("Executable copied to {}", EXECUTABLE_TARGET_PATH);
                    
                    // Set executable permissions
                    if let Ok(chmod_output) = Command::new("chmod")
                        .args(["+x", EXECUTABLE_TARGET_PATH])
                        .output()
                    {
                        if !chmod_output.status.success() {
                            warn!("Failed to set executable permissions: {}", 
                                  String::from_utf8_lossy(&chmod_output.stderr));
                        }
                    }
                },
                _ => {
                    info!("Need elevated permissions to copy executable to {}", EXECUTABLE_TARGET_PATH);

                    // Need to use sudo, with one command that does everything:
                    // 1. Copy executable
                    // 2. Set executable permissions
                    // 3. Create mode directory and set mode file
                    let source_path = current_exec_path.to_string_lossy().replace("'", "'\\''");
                    
                    // Build a script that does everything we need with a single privilege elevation
                    let script = format!(
                        r#"do shell script "cp '{}' '{}' && chmod +x '{}' && mkdir -p {} && echo {} > {} && chmod 755 {} && mkdir -p '{}' && chmod 755 '{}'" with administrator privileges with prompt \"Dragonfly needs permission to configure Simple mode\""#,
                        source_path,
                        EXECUTABLE_TARGET_PATH,
                        EXECUTABLE_TARGET_PATH,
                        MODE_DIR,
                        DeploymentMode::Simple.as_str(),
                        MODE_FILE,
                        MODE_DIR,
                        log_dir_path,
                        log_dir_path
                    );
                    
                    let osa_output = Command::new("osascript")
                        .arg("-e")
                        .arg(&script)
                        .output()
                        .context("Failed to execute osascript for sudo prompt")?;
                        
                    if !osa_output.status.success() {
                        let stderr = String::from_utf8_lossy(&osa_output.stderr);
                        return Err(anyhow!("Failed to configure with admin privileges: {}", stderr));
                    }
                    
                    info!("System configured with admin privileges");
                }
            }
        } else {
            // For Linux, try with sudo if regular copy fails
            match tokio::fs::copy(&current_exec_path, EXECUTABLE_TARGET_PATH).await {
                Ok(_) => {
                    info!("Executable copied to {}", EXECUTABLE_TARGET_PATH);
                    
                    // Set executable permissions
                    let chmod_output = Command::new("chmod")
                        .args(["+x", EXECUTABLE_TARGET_PATH])
                        .output()
                        .context("Failed to set executable permissions")?;
                        
                    if !chmod_output.status.success() {
                        warn!("Failed to set executable permissions: {}", 
                              String::from_utf8_lossy(&chmod_output.stderr));
                    }
                },
                Err(e) => {
                    info!("Need elevated permissions to copy executable to {}: {}", EXECUTABLE_TARGET_PATH, e);

                    // Try with pkexec first (graphical sudo)
                    let pkexec_available = Command::new("which")
                        .arg("pkexec")
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false);
                        
                    if pkexec_available {
                        info!("Trying with pkexec for graphical sudo prompt");
                        
                        // Do everything in one command
                        let script = format!(
                            "pkexec sh -c 'cp \"{}\" \"{}\" && chmod +x \"{}\" && mkdir -p {} && echo {} > {} && chmod 755 {} && mkdir -p {} && chmod 755 {}'",
                            current_exec_path.display(),
                            EXECUTABLE_TARGET_PATH,
                            EXECUTABLE_TARGET_PATH,
                            MODE_DIR,
                            DeploymentMode::Simple.as_str(),
                            MODE_FILE,
                            MODE_DIR,
                            log_dir_path,
                            log_dir_path
                        );
                        
                        let pkexec_output = Command::new("sh")
                            .arg("-c")
                            .arg(&script)
                            .output();
                            
                        match pkexec_output {
                            Ok(output) if output.status.success() => {
                                info!("System configured with pkexec");
                            },
                            _ => {
                                info!("pkexec failed or was cancelled, trying regular sudo");
                                
                                // Try with regular sudo, doing everything in one command
                                let sudo_script = format!(
                                    "sudo sh -c 'cp \"{}\" \"{}\" && chmod +x \"{}\" && mkdir -p {} && echo {} > {} && chmod 755 {} && mkdir -p {} && chmod 755 {}'",
                                    current_exec_path.display(),
                                    EXECUTABLE_TARGET_PATH,
                                    EXECUTABLE_TARGET_PATH,
                                    MODE_DIR,
                                    DeploymentMode::Simple.as_str(),
                                    MODE_FILE,
                                    MODE_DIR,
                                    log_dir_path,
                                    log_dir_path
                                );
                                
                                let sudo_output = Command::new("sh")
                                    .arg("-c")
                                    .arg(&sudo_script)
                                    .output()
                                    .context("Failed to execute sudo command")?;
                                    
                                if !sudo_output.status.success() {
                                    let stderr = String::from_utf8_lossy(&sudo_output.stderr);
                                    return Err(anyhow!("Failed to configure with sudo: {}", stderr));
                                }
                                
                                info!("System configured with sudo");
                            }
                        }
                    } else {
                        // Just use regular sudo
                        let sudo_script = format!(
                            "sudo sh -c 'cp \"{}\" \"{}\" && chmod +x \"{}\" && mkdir -p {} && echo {} > {} && chmod 755 {} && mkdir -p {} && chmod 755 {}'",
                            current_exec_path.display(),
                            EXECUTABLE_TARGET_PATH,
                            EXECUTABLE_TARGET_PATH,
                            MODE_DIR,
                            DeploymentMode::Simple.as_str(),
                            MODE_FILE,
                            MODE_DIR,
                            log_dir_path,
                            log_dir_path
                        );
                        
                        let sudo_output = Command::new("sh")
                            .arg("-c")
                            .arg(&sudo_script)
                            .output()
                            .context("Failed to execute sudo command")?;
                            
                        if !sudo_output.status.success() {
                            let stderr = String::from_utf8_lossy(&sudo_output.stderr);
                            return Err(anyhow!("Failed to configure with sudo: {}", stderr));
                        }
                        
                        info!("System configured with sudo");
                    }
                }
            }
        }
    } else {
        info!("Executable already exists at {}", EXECUTABLE_TARGET_PATH);
    }
    
    // Use the target path for service configuration if it exists, otherwise use current path
    let exec_path = if target_path.exists() {
        target_path.to_path_buf()
    } else {
        current_exec_path
    };
    
    // Create log directory before setting up services if not already handled by elevated commands
        let log_dir = "/var/log/dragonfly";
        if !std::path::Path::new(log_dir).exists() {
            // Create directory with appropriate permissions
            if let Err(e) = tokio::fs::create_dir_all(log_dir).await {
                warn!("Could not create log directory {}: {}", log_dir, e);
                // Try with sudo
                let _ = Command::new("sudo")
                    .args(["mkdir", "-p", log_dir])
                    .output();
                let _ = Command::new("sudo")
                    .args(["chmod", "755", log_dir])
                    .output();
            }
        }
        info!("Log directory ready at {}", log_dir);
    
    // Check if we're on macOS
    let is_macos = std::env::consts::OS == "macos" || std::env::consts::OS == "darwin";
    
    if !is_macos {
        info!("Setting up systemd socket and service");
        generate_systemd_unit(
            "dragonfly", 
            exec_path.to_str().unwrap(), 
            "Dragonfly Simple Mode"
        ).await?;
        
        // Enable the socket first (for socket activation)
        info!("Enabling systemd socket and service");
        let socket_enable = Command::new("systemctl")
            .args(["enable", "dragonfly.socket"])
            .output()
            .context("Failed to enable dragonfly.socket")?;

        if !socket_enable.status.success() {
            warn!("Failed to enable dragonfly.socket: {}", String::from_utf8_lossy(&socket_enable.stderr));
        } else {
            info!("Systemd socket enabled successfully");
        }
        
        // Enable the service
        let service_enable = Command::new("systemctl")
            .args(["enable", "dragonfly.service"])
            .output()
            .context("Failed to enable dragonfly.service")?;

        if !service_enable.status.success() {
            warn!("Failed to enable dragonfly.service: {}", String::from_utf8_lossy(&service_enable.stderr));
        } else {
            info!("Systemd service enabled successfully");
        }
        
        // Start the socket first (this is important for socket activation)
        let socket_start = Command::new("systemctl")
            .args(["start", "dragonfly.socket"])
            .output()
            .context("Failed to start dragonfly.socket")?;
            
        if !socket_start.status.success() {
            warn!("Failed to start dragonfly.socket: {}", String::from_utf8_lossy(&socket_start.stderr));
        } else {
            info!("Systemd socket started successfully");
        }
        
        // Now start the service
        let service_start = Command::new("systemctl")
            .args(["start", "dragonfly.service"])
            .output()
            .context("Failed to start dragonfly.service")?;
            
        if !service_start.status.success() {
            warn!("Failed to start dragonfly.service: {}", String::from_utf8_lossy(&service_start.stderr));
        } else {
            info!("Systemd service started successfully");
        }
    }
    
    // Create a directory for data storage
    if is_macos {
        let home = std::env::var("HOME").context("Failed to get user home directory")?;
        let data_dir = PathBuf::from(&home).join(".dragonfly");
        tokio::fs::create_dir_all(&data_dir).await.ok();
    } else {
        let data_dir = PathBuf::from("/var/lib/dragonfly");
        tokio::fs::create_dir_all(&data_dir).await.ok();
    }

    // NOTE: Mode is saved by the UI handler via app_state.store BEFORE calling this function
    // Do NOT call save_mode() here as it would try to open ReDB separately and cause a lock conflict
    
    let is_macos = std::env::consts::OS == "macos" || std::env::consts::OS == "darwin";
    
    info!("System configured for Simple mode. Dragonfly will run as a service on startup.");
    info!("Logs will be written to {}/dragonfly.log", log_dir_path);
    
    if !is_macos {
        info!("Starting service now...");
        // Start the service via the service manager (which will exit this process on non-macOS)
        start_service()?;
    } else {
        info!("Running in foreground mode on macOS");
    }
    
    Ok(())
}

// Start the handoff server for Flight mode
pub async fn start_handoff_listener(mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
    // Set up a signal handler for SIGUSR1
    let mut sigusr1 = signal(SignalKind::user_defined1())
        .context("Failed to install SIGUSR1 handler")?;
    
    let handoff_file = PathBuf::from(HANDOFF_READY_FILE);
    
    info!("Starting handoff listener");
    
    tokio::select! {
        // Wait for the handoff file to be created
        _ = async {
            loop {
                if tokio::fs::metadata(&handoff_file).await.is_ok() {
                    info!("Handoff file detected - initiating handoff");
                    
                    // Read the content to get the pid if available
                    if let Ok(content) = tokio::fs::read_to_string(&handoff_file).await {
                        if let Ok(pid) = content.trim().parse::<i32>() {
                            info!("Sending ACK to k3s pod with pid {}", pid);
                            // Send ACK to the k3s pod if pid is available
                            let _ = Command::new("kill")
                                .args(["-SIGUSR2", &pid.to_string()])
                                .output();
                        }
                    }
                    
                    // Remove the handoff file
                    let _ = tokio::fs::remove_file(&handoff_file).await;
                    
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        } => {
            info!("Handoff initiated by file - gracefully shutting down");
            return Ok(());
        },
        
        // Wait for SIGUSR1 signal
        _ = sigusr1.recv() => {
            info!("Received SIGUSR1 signal - initiating handoff");
            
            // ACK the signal by writing to a file
            let _ = tokio::fs::write(handoff_file, format!("{}", std::process::id()))
                .await
                .context("Failed to write handoff ACK file");
                
            return Ok(());
        },
        
        // Wait for shutdown signal
        _ = shutdown_rx.changed() => {
            info!("Shutdown received - terminating handoff listener");
            return Ok(());
        }
    }
    
    // Remove the unreachable code
}

// Configure the system for Flight mode
pub async fn configure_flight_mode(store: std::sync::Arc<dyn DragonflyStore>) -> Result<()> {
    info!("Configuring system for Flight mode");
    
    // Always attempt the configuration steps for Flight mode
    // The checks inside these functions (like artifact download) will handle idempotency.
    
    // Execute multiple prerequisite tasks in parallel
    let k8s_check_fut = async {
        info!("Checking Kubernetes connectivity...");
        match check_kubernetes_connectivity().await {
            Ok(()) => {
                info!("Kubernetes connectivity confirmed. Will use K8s/etcd for storage if configured.");
            },
            Err(e) => {
                // K8s is OPTIONAL - Flight mode works fine with ReDB as storage backend
                info!("Kubernetes not available ({}). Using ReDB for storage.", e);
            }
        }
        Ok::<(), anyhow::Error>(()) // Always succeed - K8s is optional
    };
    
    // Add WebUI check future
    let webui_check_fut = async {
        info!("Checking WebUI service status...");
        match check_webui_service_status().await {
            Ok(true) => {
                info!("WebUI service status confirmed as ready.");
                Ok(())
            },
            Ok(false) => {
                warn!("WebUI service is not ready, but continuing with Flight mode configuration.");
                // Return Ok since this is not fatal for the configuration
                Ok(())
            },
            Err(e) => {
                warn!("Error checking WebUI service status: {}. Continuing with Flight mode configuration.", e);
                // Return Ok since this is not fatal for the configuration
                Ok(())
            }
        }
    };
    
    // Add the agent builder task
    let agent_builder_fut = async {
        info!("Building Dragonfly Agent APK overlay...");
        
        // Create the artifacts directory if it doesn't exist
        let artifacts_dir = StdPath::new("/var/lib/dragonfly/ipxe-artifacts");
        if !artifacts_dir.exists() {
            match fs::create_dir_all(artifacts_dir).await {
                Ok(_) => debug!("Created artifacts directory: {:?}", artifacts_dir),
                Err(e) => warn!("Failed to create artifacts directory: {}", e)
            }
        }
        
        // Set the target path for the APK overlay
        let target_apkovl_path = artifacts_dir.join("localhost.apkovl.tar.gz");
        
        // Determine the base URL for the agent to connect back to
        let base_url = format!("http://{}:3000", get_loadbalancer_ip().await?);
        
        // URL for the agent binary
        let agent_binary_url = "https://github.com/Zorlin/dragonfly/raw/refs/heads/main/dragonfly-agent-musl";
        
        // Generate the APK overlay
        match crate::api::generate_agent_apkovl(&target_apkovl_path, &base_url, agent_binary_url).await {
            Ok(_) => {
                info!("Successfully built Dragonfly Agent APK overlay at {:?}", target_apkovl_path);
                Ok(())
            },
            Err(e) => {
                warn!("Failed to build Dragonfly Agent APK overlay: {}. PXE booting might not work correctly.", e);
                // This is non-fatal for Flight mode configuration
                Ok(())
            }
        }
    };
    
    // Add iPXE binaries download future
    let ipxe_download_fut = async {
        info!("Checking/Downloading iPXE binaries...");
        match crate::api::download_ipxe_binaries().await {
            Ok(_) => info!("iPXE binaries check/download complete."),
            Err(e) => {
                warn!("Failed to download/verify iPXE binaries: {}", e);
                // Non-fatal for configuration, might affect PXE booting later
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    // Download Mage (Alpine netboot) artifacts for both architectures
    let mage_download_fut = async {
        info!("Downloading Mage boot environment for x86_64...");
        if let Err(e) = crate::api::download_mage_artifacts("3.23", "x86_64").await {
            warn!("Failed to download x86_64 Mage artifacts: {}", e);
        }

        info!("Downloading Mage boot environment for aarch64...");
        if let Err(e) = crate::api::download_mage_artifacts("3.23", "aarch64").await {
            warn!("Failed to download aarch64 Mage artifacts: {}", e);
        }

        Ok::<(), anyhow::Error>(())
    };

    // Download or build dragonfly-agent binaries for both architectures
    let agent_build_fut = async {
        // Create mage directories for each arch
        let _ = std::fs::create_dir_all("/var/lib/dragonfly/mage/x86_64");
        let _ = std::fs::create_dir_all("/var/lib/dragonfly/mage/aarch64");

        // Try to download pre-built binaries first, fall back to local build
        for (arch, target) in [("x86_64", "x86_64-unknown-linux-musl"), ("aarch64", "aarch64-unknown-linux-musl")] {
            let dest = format!("/var/lib/dragonfly/mage/{}/dragonfly-agent", arch);
            let dest_path = std::path::Path::new(&dest);

            // Skip if already exists
            if dest_path.exists() {
                info!("{} agent binary already exists, skipping", arch);
                continue;
            }

            // Try downloading from GitHub releases first
            let download_url = format!(
                "https://github.com/Zorlin/dragonfly/releases/download/latest/dragonfly-agent-{}",
                arch
            );
            info!("Trying to download {} agent from {}", arch, download_url);

            let download_result = async {
                let client = reqwest::Client::new();
                let response = client.get(&download_url).send().await?;
                if response.status().is_success() {
                    let bytes = response.bytes().await?;
                    tokio::fs::write(&dest, &bytes).await?;
                    // Make executable
                    let mut perms = tokio::fs::metadata(&dest).await?.permissions();
                    perms.set_mode(0o755);
                    tokio::fs::set_permissions(&dest, perms).await?;
                    Ok::<(), anyhow::Error>(())
                } else {
                    Err(anyhow!("HTTP {}", response.status()))
                }
            }.await;

            if download_result.is_ok() {
                info!("{} agent binary downloaded successfully", arch);
                continue;
            }

            // Fall back to local build if download failed
            warn!("Failed to download {} agent, trying local build...", arch);
            info!("Building dragonfly-agent for {}...", target);
            let output = tokio::process::Command::new("cargo")
                .args(["build", "--release", "--package", "dragonfly-agent", "--target", target])
                .output()
                .await;

            if let Ok(output) = output {
                if output.status.success() {
                    let src = format!("target/{}/release/dragonfly-agent", target);
                    if let Err(e) = std::fs::copy(&src, &dest) {
                        warn!("Failed to copy {} agent: {}", arch, e);
                    } else {
                        info!("{} agent binary ready (built locally)", arch);
                    }
                } else {
                    warn!("{} agent build failed: {}", arch, String::from_utf8_lossy(&output.stderr));
                }
            } else {
                warn!("{} agent build command failed to execute", arch);
            }
        }

        Ok::<(), anyhow::Error>(())
    };

    // Generate Mage APK overlays for both architectures (uses locally-built agents)
    let mage_apkovl_fut = async {
        let base_url = std::env::var("DRAGONFLY_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        // Generate for x86_64
        info!("Generating Mage APK overlay for x86_64...");
        if let Err(e) = crate::api::generate_mage_apkovl_arch(&base_url, "x86_64").await {
            warn!("Failed to generate x86_64 APK overlay: {}", e);
        }

        // Generate for aarch64
        info!("Generating Mage APK overlay for aarch64...");
        if let Err(e) = crate::api::generate_mage_apkovl_arch(&base_url, "aarch64").await {
            warn!("Failed to generate aarch64 APK overlay: {}", e);
        }

        Ok::<(), anyhow::Error>(())
    };

    // Add a future for updating the Tinkerbell stack (ONLY if K8s is available)
    let tinkerbell_update_fut = async {
        // Check if K8s is available before trying Tinkerbell update
        match check_kubernetes_connectivity().await {
            Ok(()) => {
                info!("K8s available - starting Tinkerbell stack update...");
                match enter_flight_mode().await {
                    Ok(_) => info!("Tinkerbell stack update completed"),
                    Err(e) => {
                        warn!("Tinkerbell stack update failed: {}. Continuing with native provisioning.", e);
                    }
                }
            }
            Err(_) => {
                // K8s not available - skip Tinkerbell update, use native provisioning
                info!("K8s not available - skipping Tinkerbell stack update, using native ReDB provisioning");
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    // Run prerequisite tasks - some in parallel, some sequential
    // Phase 1: Downloads and builds (parallel)
    match tokio::try_join!(
        k8s_check_fut,
        webui_check_fut,
        agent_builder_fut,
        ipxe_download_fut,
        mage_download_fut,
        agent_build_fut,
        tinkerbell_update_fut
    ) {
        Ok(_) => info!("Phase 1 complete: downloads and builds."),
        Err(e) => {
            error!("Failed during Flight mode phase 1: {}", e);
            return Err(e);
        }
    }

    // Phase 2: APK overlay generation (needs agent binary from phase 1)
    match tokio::try_join!(mage_apkovl_fut) {
        Ok(_) => {
            info!("Successfully configured Flight mode.");
        },
        Err(e) => {
            error!("Failed during Flight mode configuration: {}", e);
            return Err(e);
        }
    }

    // NOTE: Mode is saved by the UI handler via app_state.store BEFORE calling this function
    // Do NOT call save_mode() here as it would try to open ReDB separately and cause a lock conflict

    // Initialize OS templates now that Flight mode is configured
    info!("Initializing OS templates for Flight mode...");
    match crate::os_templates::init_os_templates(store).await {
        Ok(_) => info!("OS templates initialized successfully"),
        Err(e) => warn!("Failed to initialize OS templates: {}", e),
    }

    info!("System successfully configured for Flight mode.");
    Ok(())
}

// Enter Flight Mode
pub async fn enter_flight_mode() -> Result<()> {
    // Check the Kubernetes API is available - handle the color_eyre Result<()> return type
    match check_kubernetes_connectivity().await {
        Ok(()) => info!("Kubernetes connectivity confirmed."),
        Err(e) => {
            error!("Error checking Kubernetes connectivity: {}. Cannot enter Flight mode.", e);
            // Convert color_eyre error to anyhow
            return Err(anyhow!("Error checking Kubernetes connectivity: {}", e));
        }
    }

    // Check if the WebUI service is ready
    match check_webui_service_status().await {
        Ok(true) => info!("WebUI service status confirmed as ready."),
        Ok(false) => {
            error!("WebUI service is not ready. Cannot enter Flight mode.");
            bail!("WebUI service is not ready");
        }
        Err(e) => {
            error!("Error checking WebUI service status: {}. Cannot enter Flight mode.", e);
            return Err(anyhow!("Error checking WebUI service status: {}", e));
        }
    }

    // --- Check current Helm values for Smee DHCP ---
    info!("Checking current Helm values for tinkerbell...");
    let helm_get_values_output = Command::new("helm")
        .args(["get", "values", "tinkerbell", "-n", "tinkerbell", "-o", "yaml"])
        .output();
        
    let needs_upgrade = match helm_get_values_output {
        Ok(output) if output.status.success() => {
            let values_yaml = String::from_utf8_lossy(&output.stdout);
            debug!("Current Helm values:\n{}", values_yaml);
            
            // Parse YAML to check smee.dhcp.enabled
            match serde_yaml::from_str::<serde_yaml::Value>(&values_yaml) {
                Ok(values) => {
                    // Navigate the YAML structure
                    let smee_dhcp_enabled = values
                        .get("smee")
                        .and_then(|smee| smee.get("dhcp"))
                        .and_then(|dhcp| dhcp.get("enabled"))
                        .and_then(|enabled| enabled.as_bool())
                        .unwrap_or(true); // Default to true if not found (conservative)
                        
                    if smee_dhcp_enabled {
                        info!("Smee DHCP is already enabled in Helm values. No upgrade needed.");
                        false // No upgrade needed
                    } else {
                        info!("Smee DHCP is currently disabled. Helm upgrade required.");
                        true // Upgrade needed
                    }
                }
                Err(e) => {
                    warn!("Failed to parse Helm values YAML: {}. Assuming upgrade is needed.", e);
                    true // Assume upgrade needed if parsing fails
                }
            }
        }
        Ok(output) => {
             warn!("'helm get values' command failed: {}. Assuming upgrade is needed.", 
                   String::from_utf8_lossy(&output.stderr));
            true // Assume upgrade needed if command fails
        }
        Err(e) => {
            warn!("Failed to execute 'helm get values': {}. Assuming upgrade is needed.", e);
            true // Assume upgrade needed if execution fails
        }
    };

    // Only proceed with upgrade if needed
    if needs_upgrade {
        info!("Proceeding with Helm upgrade to enable Smee DHCP...");
        
        // --- Activate Smee's DHCP service in Flight mode using Helm ---
        // Check if the Tinkerbell stack release actually exists (redundant but safe)
    let release_exists = {
        let release_check = Command::new("helm")
            .args(["list", "-n", "tinkerbell", "--filter", "tinkerbell", "--short"])
                .output()
                .with_context(|| "Failed to check deployment status after upgrade")?;

        release_check.status.success() &&
        !String::from_utf8_lossy(&release_check.stdout).trim().is_empty()
    };

        if !release_exists {
            // This shouldn't happen if get values succeeded, but check anyway
             return Err(anyhow!("Tinkerbell stack release 'tinkerbell' not found. Cannot upgrade."));
    }

    // --- Clone the GitHub repository for the Helm chart ---
    info!("Fetching Dragonfly Helm charts from GitHub for upgrade...");
    let repo_dir = std::env::temp_dir().join("dragonfly-charts");
    if repo_dir.exists() {
            fs::remove_dir_all(&repo_dir).await.ok(); // Clean up previous clone if necessary
        }
        let clone_cmd = format!("git clone --depth 1 https://github.com/Zorlin/dragonfly-charts.git {}", repo_dir.display());
        run_shell_command(&clone_cmd, "clone Dragonfly Helm charts")?;
        let chart_path = repo_dir.join("tinkerbell");
        let upgrade_chart_path = chart_path.join("stack");
        if !upgrade_chart_path.exists() {
            bail!("Helm chart stack directory not found in expected location: {:?}", upgrade_chart_path);
    }

    // --- Build the Helm chart dependencies ---
    info!("Building Helm chart dependencies...");
        let dependency_build_cmd = format!("cd {} && helm dependency build stack/", chart_path.display());
        run_shell_command(&dependency_build_cmd, "build Helm chart dependencies")?;

        // --- Run Helm Upgrade ---
    let helm_args = [
        "upgrade", "tinkerbell",
            upgrade_chart_path.to_str().ok_or_else(|| anyhow!("Chart path is not valid UTF-8"))?,
        "--namespace", "tinkerbell",
        "--wait",
        "--timeout", "10m",
        "--reuse-values",
            "--set", "smee.dhcp.enabled=true"
        ];

        info!("Upgrading Dragonfly Tinkerbell stack to enable Smee DHCP...");
        match run_command("helm", &helm_args, "upgrade Dragonfly Tinkerbell Helm chart") {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                debug!("Helm upgrade output: {}", stdout);
                info!("Helm upgrade completed successfully");
            },
            Err(e) => {
                error!("Helm upgrade failed: {}", e);
                
                // Try to get more diagnostic information
                let helm_list = Command::new("helm")
                    .args(["list", "-n", "tinkerbell", "-a"])
                    .output();

                if let Ok(list_output) = helm_list {
                    if list_output.status.success() {
                        let list_stdout = String::from_utf8_lossy(&list_output.stdout);
                        error!("Current Helm releases in tinkerbell namespace:\n{}", list_stdout);
                    }
                }

                let pod_list = Command::new("kubectl")
                    .args(["get", "pods", "-n", "tinkerbell", "-o", "wide"])
                    .output();
                
                if let Ok(pod_output) = pod_list {
                    if pod_output.status.success() {
                        let pod_stdout = String::from_utf8_lossy(&pod_output.stdout);
                        error!("Current pods in tink namespace:\n{}", pod_stdout);
                    }
                }
                
                // Return the original error with context
                return Err(anyhow!("Failed to upgrade Tinkerbell stack: {}. Check logs for diagnostics.", e));
            }
        }

        // --- Clean up --- 
    debug!("Cleaning up temporary chart repository...");
        let _ = fs::remove_dir_all(&repo_dir).await; // Best effort cleanup

        info!("Helm upgrade completed successfully.");
    } else {
        info!("Skipping Helm upgrade as Smee DHCP is already enabled.");
    }

    Ok(())
}

// Deploy k3s and initiate handoff
// TODO - Move this to install.rs!
pub async fn deploy_k3s_and_handoff() -> Result<()> {
    // Get the current process ID for ACK
    let my_pid = std::process::id();
    
    // Check if we're on macOS
    if is_macos() {
        // macOS-specific code for using k3s in Docker
        info!("Running on macOS, setting up k3s in Docker");
        
        // Check if Docker is installed and running
        let docker_running = Command::new("docker")
            .args(["info"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
            
        if !docker_running {
            return Err(anyhow!("Docker is not installed or not running. Please install and start Docker Desktop."));
        }
        
        // Check if k3s container is already running
        let k3s_exists = Command::new("docker")
            .args(["ps", "-q", "--filter", "name=k3s-server"])
            .output()
            .map(|output| !String::from_utf8_lossy(&output.stdout).trim().is_empty())
            .unwrap_or(false);
        
        if !k3s_exists {
            // Run k3s in Docker
            info!("Starting k3s in Docker");
            let run_output = Command::new("docker")
                .args([
                    "run", "--name", "k3s-server", 
                    "-d", "--privileged",
                    "-p", "6443:6443",       // Kubernetes API
                    "-p", "80:80",           // HTTP
                    "-p", "443:443",         // HTTPS
                    "-p", "8080:8080",       // Tinkerbell Hook service
                    "-p", "69:69/udp",       // TFTP (for PXE)
                    "-p", "53:53/udp",       // DNS
                    "-p", "67:67/udp",       // DHCP
                    "-v", "k3s-server:/var/lib/rancher/k3s",
                    "--restart", "always",
                    "rancher/k3s:latest", "server", "--disable", "traefik"
                ])
                .output()
                .context("Failed to start k3s Docker container")?;
                
            if !run_output.status.success() {
                let stderr = String::from_utf8_lossy(&run_output.stderr);
                return Err(anyhow!("Failed to start k3s in Docker: {}", stderr));
            }
            
            // Wait for k3s to start
            info!("Waiting for k3s container to initialize...");
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
        } else {
            info!("k3s Docker container already exists");
            
            // Check if it's running
            let is_running = Command::new("docker")
                .args(["ps", "-q", "--filter", "name=k3s-server", "--filter", "status=running"])
                .output()
                .map(|output| !String::from_utf8_lossy(&output.stdout).trim().is_empty())
                .unwrap_or(false);
                
            if !is_running {
                // Start the container if it exists but isn't running
                info!("Starting existing k3s container");
                let start_output = Command::new("docker")
                    .args(["start", "k3s-server"])
                    .output()
                    .context("Failed to start existing k3s container")?;
                    
                if !start_output.status.success() {
                    let stderr = String::from_utf8_lossy(&start_output.stderr);
                    return Err(anyhow!("Failed to start existing k3s container: {}", stderr));
                }
                
                // Wait for k3s to start
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        }
        
        // Copy the kubeconfig from the container
        info!("Extracting kubeconfig from k3s container");
        let home = std::env::var("HOME").context("Failed to get home directory")?;
        let kubeconfig_dir = format!("{}/.kube", home);
        tokio::fs::create_dir_all(&kubeconfig_dir).await.ok(); // Ignore error if dir exists
        
        // First, copy the kubeconfig file
        let copy_cmd = format!(
            "docker cp k3s-server:/etc/rancher/k3s/k3s.yaml {}/.kube/config",
            home
        );

        let copy_output = Command::new("sh")
            .arg("-c")
            .arg(&copy_cmd)
            .output()
            .context("Failed to copy kubeconfig from container")?;
            
        if !copy_output.status.success() {
            let stderr = String::from_utf8_lossy(&copy_output.stderr);
            return Err(anyhow!("Failed to copy kubeconfig from container: {}", stderr));
        }

        // Then, modify the kubeconfig file using sed
        // macOS uses BSD sed which works differently than GNU sed
        let sed_cmd = format!(
            "sed -i '' 's/127.0.0.1/kubernetes.docker.internal/g' {}/.kube/config",
            home
        );

        let sed_output = Command::new("sh")
            .arg("-c")
            .arg(&sed_cmd)
            .output()
            .context("Failed to update kubeconfig server address")?;
            
        if !sed_output.status.success() {
            let stderr = String::from_utf8_lossy(&sed_output.stderr);
            info!("Warning when updating kubeconfig: {}", stderr);
            // This is non-fatal, the user might need to manually edit the file
        }
        
        // Set KUBECONFIG environment variable for kubectl and helm
        let kubeconfig_path = format!("{}/.kube/config", home);
        // SAFETY: Single-threaded initialization before spawning async tasks
        unsafe { std::env::set_var("KUBECONFIG", &kubeconfig_path); }
        info!("Set KUBECONFIG environment variable to: {}", kubeconfig_path);

        // Add kubernetes.docker.internal to /etc/hosts if not already there
        let hosts_check = Command::new("grep")
            .args(["kubernetes.docker.internal", "/etc/hosts"])
            .output();
            
        if hosts_check.map(|output| !output.status.success()).unwrap_or(true) {
            info!("Adding kubernetes.docker.internal to /etc/hosts");
            let hosts_cmd = "echo '127.0.0.1 kubernetes.docker.internal' | sudo tee -a /etc/hosts";
            let _ = Command::new("sh")
                .arg("-c")
                .arg(hosts_cmd)
                .output();
            // We don't check for errors here because it might require sudo
            // The user can add this manually if needed
        }
        
        // Install Helm if needed
        info!("Installing Helm if needed");
        install_helm().await?;
        
        // Install Tinkerbell stack (would normally happen here)
        info!("Installing Tinkerbell stack");
        // This would call tinkerbell stack installation function
    } else {
        // Linux native k3s installation
        info!("Installing k3s for Flight mode (Linux native)");
        
        // Check if k3s is already installed
        let k3s_installed = Path::new("/etc/rancher/k3s/k3s.yaml").exists() && 
                          check_service_running("k3s").await;
        
        if !k3s_installed {
            // Install k3s
            info!("Installing k3s (single-node)");
            let script = r#"curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='--disable traefik' sh -"#;
            let output = Command::new("sh")
                .arg("-c")
                .arg(script)
                .output()
                .context("Failed to execute k3s installation script")?;
                
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!("k3s installation failed: {}", stderr));
            }
            
            // Wait for k3s to start
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        } else {
            info!("k3s is already installed, skipping installation");
        }
        
        // Verify k3s is running
        if !check_service_running("k3s").await {
            // Try to restart k3s
            info!("Starting k3s service");
            let restart_output = Command::new("systemctl")
                .args(["restart", "k3s"])
                .output()
                .context("Failed to restart k3s service")?;
                
            if !restart_output.status.success() {
                let stderr = String::from_utf8_lossy(&restart_output.stderr);
                return Err(anyhow!("Failed to restart k3s service: {}", stderr));
            }
            
            // Wait for the service to start
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            
            // Check again
            if !check_service_running("k3s").await {
                return Err(anyhow!("k3s service failed to start after installation"));
            }
        }
        
        // Configure kubectl
        info!("Configuring kubectl");
        let kubeconfig_path = configure_kubectl().await?;
        
        // Wait for node to be ready
        info!("Waiting for Kubernetes node to become ready");
        wait_for_node_ready(&kubeconfig_path).await?;
        
        // Install helm if needed
        info!("Installing Helm if needed");
        install_helm().await?;
        
        // Install Tinkerbell stack
        info!("Installing Tinkerbell stack");
        // This would normally call the tinkerbell stack installation function
    }
    
    // Write the handoff ready file with our PID
    tokio::fs::write(HANDOFF_READY_FILE, format!("{}", my_pid))
        .await
        .context("Failed to write handoff ready file")?;
    
    info!("K3s deployment completed - handoff ready file created");
    
    // Set up a signal handler for SIGUSR2 (ACK)
    let mut sigusr2 = signal(SignalKind::user_defined2())
        .context("Failed to install SIGUSR2 handler")?;
    
    // Wait for ACK or timeout
    let ack_received = tokio::select! {
        _ = sigusr2.recv() => {
            info!("Received ACK from Rust server - handoff successful");
            true
        },
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
            warn!("No ACK received from Rust server within timeout - continuing anyway");
            false
        }
    };
    
    // If no ACK received, it might mean the Rust server is already terminated
    if !ack_received {
        // Check if the handoff file still exists and remove it
        if Path::new(HANDOFF_READY_FILE).exists() {
            let _ = tokio::fs::remove_file(HANDOFF_READY_FILE).await;
        }
    }
    
    // Start the server in k3s
    info!("Starting Dragonfly server in k3s");
    
    // TODO: Add code to start server in k3s
    
    Ok(())
}

// Helper function to check if a service is running
async fn check_service_running(service_name: &str) -> bool {
    // Check if we're on macOS
    if std::env::consts::OS == "macos" || std::env::consts::OS == "darwin" {
        // For macOS, use pgrep to check if process is running
        let output = Command::new("pgrep")
            .arg("-f")
            .arg(service_name)
            .output();
            
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                !stdout.trim().is_empty()
            },
            Err(_) => false,
        }
    } else {
        // For Linux, use systemctl
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
}

// Helper function to configure kubectl
async fn configure_kubectl() -> Result<PathBuf> {
    let source_path = PathBuf::from("/etc/rancher/k3s/k3s.yaml");
    let dest_path = std::env::current_dir()?.join("k3s.yaml");

    // Check if the destination file already exists and is valid
    if dest_path.exists() {
        // Test if the existing config works
        let test_result = Command::new("kubectl")
            .args(["--kubeconfig", dest_path.to_str().unwrap(), "cluster-info"])
            .output();
            
        if let Ok(output) = test_result {
            if output.status.success() {
                return Ok(dest_path);
            }
        }
    }

    // Wait for k3s to create the config file
    let mut attempts = 0;
    while !source_path.exists() && attempts < 12 {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        attempts += 1;
    }
    
    if !source_path.exists() {
        return Err(anyhow!("k3s config file not found after 60 seconds"));
    }

    // Determine if sudo is needed by checking if we can read the file directly
    // This avoids using libc directly for better musl compatibility
    let needs_sudo = match tokio::fs::metadata(&source_path).await {
        Ok(_) => false, // If we can stat the file, we likely have access
        Err(_) => true,  // If we can't, we likely need sudo
    };

    // Copy the file
    let cp_cmd = format!(
        "{} cp {} {}",
        if needs_sudo { "sudo" } else { "" },
        source_path.display(),
        dest_path.display()
    );
    
    let cp_output = Command::new("sh")
        .arg("-c")
        .arg(cp_cmd.trim())
        .output()
        .context("Failed to copy k3s.yaml")?;
        
    if !cp_output.status.success() {
        return Err(anyhow!("Failed to copy k3s.yaml: {}", 
            String::from_utf8_lossy(&cp_output.stderr)));
    }

    // Get current user for chown
    let user = std::env::var("SUDO_USER") // If run with sudo, chown to the original user
        .or_else(|_| std::env::var("USER")) // Otherwise, use current user
        .context("Could not determine user for chown")?;

    // Change ownership
    let chown_cmd = format!(
        "{} chown {} {}",
        if needs_sudo { "sudo" } else { "" },
        user,
        dest_path.display()
    );
    
    let chown_output = Command::new("sh")
        .arg("-c")
        .arg(chown_cmd.trim())
        .output()
        .context("Failed to chown k3s.yaml")?;
        
    if !chown_output.status.success() {
        return Err(anyhow!("Failed to change ownership of k3s.yaml: {}", 
            String::from_utf8_lossy(&chown_output.stderr)));
    }

    Ok(dest_path)
}

// Helper function to wait for the node to be ready
async fn wait_for_node_ready(kubeconfig_path: &PathBuf) -> Result<()> {
    let max_wait = std::time::Duration::from_secs(300); // 5 minutes timeout
    let start_time = std::time::Instant::now();
    
    let mut node_ready = false;
    let mut coredns_ready = false;

    while start_time.elapsed() < max_wait {
        // Check if the node is ready
        if !node_ready {
            let output_result = Command::new("kubectl")
                .args(["get", "nodes", "--no-headers"])
                .env("KUBECONFIG", kubeconfig_path)
                .output();

            if let Ok(output) = output_result {
                let stdout = String::from_utf8_lossy(&output.stdout);
                
                if output.status.success() && 
                   stdout.contains(" Ready") && 
                   !stdout.contains("NotReady") {
                    info!("Kubernetes node is ready");
                    node_ready = true;
                }
            }
        }

        // Check if CoreDNS is ready
        if node_ready && !coredns_ready {
            let coredns_exists_result = Command::new("kubectl")
                .args(["get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns", "--no-headers"])
                .env("KUBECONFIG", kubeconfig_path)
                .output();
                
            if let Ok(output) = &coredns_exists_result {
                if output.status.success() && !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
                    let coredns_status = Command::new("kubectl")
                        .args(["get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns", 
                               "-o", "jsonpath='{.items[*].status.conditions[?(@.type==\"Ready\")].status}'"])
                        .env("KUBECONFIG", kubeconfig_path)
                        .output();
                        
                    if let Ok(status) = coredns_status {
                        let status_str = String::from_utf8_lossy(&status.stdout)
                            .trim()
                            .trim_matches('\'')
                            .to_string();
                            
                        if status_str.contains("True") {
                            info!("CoreDNS is ready");
                            coredns_ready = true;
                        }
                    }
                }
            }
        }

        // Exit if both are ready
        if node_ready && coredns_ready {
            return Ok(());
        }

        // Wait before checking again
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }

    // If we get here, we timed out
    Err(anyhow!("Timed out waiting for Kubernetes node to become ready"))
}

// Helper function to install Helm
async fn install_helm() -> Result<()> {
    // Check if Helm is already installed
    let helm_installed = Command::new("helm")
        .args(["version", "--short"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
        
    if helm_installed {
        info!("Helm is already installed");
        return Ok(());
    }
    
    info!("Installing Helm");
    let script = r#"curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"#;
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .context("Failed to execute Helm installation script")?;
        
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Helm installation failed: {}", stderr));
    }
    
    info!("Helm installed successfully");
    Ok(())
}

// Configure the system for Swarm mode
pub async fn configure_swarm_mode() -> Result<()> {
    info!("Configuring system for Swarm mode");
    
    // NOTE: Mode is saved by the UI handler via app_state.store BEFORE calling this function

    // Ensure /var/lib/dragonfly exists and is owned by the current user on macOS
    if let Err(e) = ensure_var_lib_ownership().await {
        warn!("Failed to ensure /var/lib/dragonfly ownership: {}", e);
        // Non-critical, continue anyway
    }
    
    // TODO: Implement Citadel integration for Swarm mode

    info!("System configured for Swarm mode.");
    
    let is_macos = std::env::consts::OS == "macos" || std::env::consts::OS == "darwin";
    
    if !is_macos {
        // Start the service via service manager (which will exit on non-macOS)
        start_service()?;
    } else {
        info!("Running in foreground mode on macOS");
    }
    
    Ok(())
}

fn setup_logging(log_dir: &str) -> Result<(), anyhow::Error> {
    // Combine log directory and file name
    let log_path = Path::new(log_dir).join("dragonfly.log");
    
    // Create a non-blocking writer to the log file
    let file_appender = tracing_appender::rolling::daily(log_dir, "dragonfly.log");
    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(file_appender);

    // Build the subscriber
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(non_blocking_writer))
        .with(fmt::layer().with_writer(std::io::stdout)) // Also log to stdout
        .with(EnvFilter::from_default_env() // Read RUST_LOG from environment
            .add_directive("info".parse()?) // Default level is info
            .add_directive("tower_http=warn".parse()?) // Quieter HTTP logs
            .add_directive("minijinja=warn".parse()?) // Quieter template logs
        )
        .init();
        
    // Log the path where logs are being written
    info!("Logging initialized. Log file: {}", log_path.display());

    Ok(())
} 

// TODO: Move helper functions below to a shared utility module

// Placeholder for run_shell_command - Implement robustly
fn run_shell_command(script: &str, description: &str) -> Result<()> {
    debug!("Running shell command: {}", description);
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .with_context(|| format!("Failed to execute command: {}", description))?;

    if !output.status.success() {
        error!("Command '{}' failed with status: {}", description, output.status);
        error!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
        error!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        // Use anyhow::bail here as the function returns anyhow::Result
        bail!("Command '{}' failed", description);
    } else {
         debug!("Command '{}' succeeded.", description);
    }
    Ok(())
}

// Placeholder for run_command - Implement robustly
fn run_command(cmd: &str, args: &[&str], description: &str) -> Result<std::process::Output> { // Specify Output type
    debug!("Running command: {} {}", cmd, args.join(" "));
     let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute command: {}", description))?;

     if !output.status.success() {
        error!("Command '{}' failed with status: {}", description, output.status);
        error!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
        error!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        // Use anyhow::bail here as the function returns anyhow::Result
        bail!("Command '{}' failed", description);
    } else {
        debug!("Command '{}' succeeded.", description);
    }
     Ok(output)
}

// Function to check if WebUI service is ready (based on get_webui_address)
async fn check_webui_service_status() -> anyhow::Result<bool> {
    // Convert color_eyre::Result to anyhow::Result
    match get_webui_address().await {
        Ok(Some(_)) => Ok(true), // Address available means service is ready
        Ok(None) => Ok(false),   // No address means not ready
        Err(e) => Err(anyhow!("Error checking WebUI service: {}", e))
    }
}

// Helper function to get the load balancer IP for connections
async fn get_loadbalancer_ip() -> Result<String> {
    // Try to get the load balancer IP from the service
    match get_webui_address().await {
        Ok(Some(url)) => {
            // Extract host from URL (remove http:// prefix and port)
            if let Ok(parsed_url) = url::Url::parse(&url) {
                if let Some(host) = parsed_url.host_str() {
                    return Ok(host.to_string());
                }
            }
        }
        _ => {
            // Failed to get URL or URL was None
            debug!("Could not determine load balancer IP from web UI service");
        }
    }
    
    // If we can't get the load balancer IP, try to get the node IP
    let kubectl_output = Command::new("kubectl")
        .args(["get", "nodes", "-o", "jsonpath='{.items[0].status.addresses[?(@.type==\"InternalIP\")].address}'"])
        .output();
        
    if let Ok(output) = kubectl_output {
        if output.status.success() {
            let node_ip = String::from_utf8_lossy(&output.stdout)
                .trim()
                .trim_matches('\'')
                .to_string();
                
            if !node_ip.is_empty() {
                debug!("Using node IP as load balancer address: {}", node_ip);
                return Ok(node_ip);
            }
        }
    }
    
    // Fallback to localhost
    debug!("Using localhost as load balancer address");
    Ok("localhost".to_string())
} 
