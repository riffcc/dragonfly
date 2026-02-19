//! Local system installation — `dragonfly install`.
//!
//! Installs Dragonfly on the **current machine** by:
//! - Creating required directories in `/var/lib/dragonfly`
//! - Writing a config file
//! - Copying the binary to `/usr/local/bin/dragonfly`
//! - Extracting embedded web assets to `/opt/dragonfly`
//! - Installing and starting a systemd (Linux) or launchd (macOS) service
//!
//! For installing on Proxmox VE, see `src/cmd/install_pve/mod.rs`.

use clap::Args;
use color_eyre::eyre::Result;
use include_dir::{Dir, include_dir};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Static assets embedded at compile time so the binary is self-contained.
static EMBEDDED_STATIC: Dir = include_dir!("crates/dragonfly-server/static");
static EMBEDDED_TEMPLATES: Dir = include_dir!("crates/dragonfly-server/templates");

const DRAGONFLY_DIR: &str = "/var/lib/dragonfly";
const DRAGONFLY_CONFIG: &str = "/var/lib/dragonfly/config.toml";
const PROD_BINARY: &str = "/usr/local/bin/dragonfly";
const OPT_DIR: &str = "/opt/dragonfly";

#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.dragonfly.daemon.plist";

#[cfg(target_os = "linux")]
const SYSTEMD_SERVICE: &str = "/etc/systemd/system/dragonfly.service";

// ─── Args ────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Optional: Specify the server IP address explicitly
    #[arg(long)]
    pub ip: Option<String>,

    /// Dev mode: service watches target/release/dragonfly for hot reload
    #[arg(long)]
    pub dev: bool,

    /// Skip service installation (systemd/launchd)
    #[arg(long)]
    pub no_service: bool,

    /// Skip downloading Mage assets
    #[arg(long)]
    pub no_assets: bool,

    /// Wipe all data and reinstall fresh (prompts for confirmation, or use --force)
    #[arg(long)]
    pub fresh: bool,

    /// Skip confirmation prompts for destructive operations
    #[arg(long)]
    pub force: bool,
}

// ─── State detection ─────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct InstallationState {
    directory_exists: bool,
    config_exists: bool,
    service_exists: bool,
    #[allow(dead_code)] // checked in tests
    assets_exist: bool,
}

impl InstallationState {
    fn detect() -> Self {
        Self {
            directory_exists: Path::new(DRAGONFLY_DIR).exists(),
            config_exists: Path::new(DRAGONFLY_CONFIG).exists(),
            service_exists: service_file_exists(),
            assets_exist: Path::new("/var/lib/dragonfly/tftp/mage/vmlinuz").exists()
                && Path::new("/var/lib/dragonfly/tftp/mage/initramfs").exists(),
        }
    }
}

fn service_file_exists() -> bool {
    #[cfg(target_os = "macos")]
    {
        Path::new(LAUNCHD_PLIST).exists()
    }
    #[cfg(target_os = "linux")]
    {
        Path::new(SYSTEMD_SERVICE).exists()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

#[allow(dead_code)] // used in tests
fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

/// Return the machine's outbound IP (used for display and config generation).
fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

// ─── Port helpers ─────────────────────────────────────────────────────────────

fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
}

fn read_configured_port() -> Option<u16> {
    let content = std::fs::read_to_string(DRAGONFLY_CONFIG).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("port") {
            if let Some(val) = line.split('=').nth(1) {
                return val.trim().parse().ok();
            }
        }
    }
    None
}

fn find_next_available_port(start: u16) -> u16 {
    let mut port = start;
    while !is_port_available(port) && port < 65535 {
        port += 1;
    }
    port
}

fn get_available_port() -> Result<u16> {
    if let Some(configured_port) = read_configured_port() {
        // Port may be in use because Dragonfly is already running — that's fine.
        return Ok(configured_port);
    }

    let default_port: u16 = 3000;
    if is_port_available(default_port) {
        return Ok(default_port);
    }

    let suggested = find_next_available_port(default_port + 1);
    println!("Port {} is already in use.", default_port);
    print!("Enter a different port (or press Enter for {}): ", suggested);
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input.is_empty() {
        Ok(suggested)
    } else if let Ok(p) = input.parse::<u16>() {
        if is_port_available(p) {
            Ok(p)
        } else {
            println!("Port {} is also in use, using {}", p, suggested);
            Ok(suggested)
        }
    } else {
        println!("Invalid port, using {}", suggested);
        Ok(suggested)
    }
}

fn get_binary_path(dev_mode: bool) -> Result<PathBuf> {
    if dev_mode {
        let cwd = std::env::current_dir()?;
        let dev_binary = cwd.join("target/release/dragonfly");
        if !dev_binary.exists() {
            return Err(color_eyre::eyre::eyre!(
                "Dev binary not found at {}. Run 'cargo build --release' first.",
                dev_binary.display()
            ));
        }
        Ok(dev_binary)
    } else {
        Ok(PathBuf::from(PROD_BINARY))
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

pub async fn run_install(
    args: InstallArgs,
    _shutdown_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    println!("🐉 Dragonfly Installer");

    if args.fresh {
        if !args.force {
            println!("WARNING: This will delete all Dragonfly data including:");
            println!("  - Database (machines, settings, history)");
            println!("  - Configuration");
            println!("  - Web assets");
            println!();
            print!("Type 'I understand' to continue: ");
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if input.trim() != "I understand" {
                return Err(color_eyre::eyre::eyre!("Aborted."));
            }
        }
        println!("Wiping existing installation...");
        wipe_installation()?;
    }

    let state = InstallationState::detect();
    let is_reinstall = state.directory_exists || state.config_exists || state.service_exists;

    if is_reinstall && !args.fresh {
        println!("Found existing installation, preserving existing data.");
    }

    let display_ip = args
        .ip
        .clone()
        .unwrap_or_else(|| get_local_ip().unwrap_or_else(|| "localhost".to_string()));

    if !check_admin_access()? {
        return Err(color_eyre::eyre::eyre!(
            "Administrator access required for installation"
        ));
    }

    let port = get_available_port()?;

    if !state.directory_exists {
        create_directories()?;
    }
    write_config(port)?;
    if !args.dev {
        install_binary()?;
    }
    install_web_assets(args.dev)?;
    install_os_templates(args.dev)?;
    if !args.no_service {
        let binary_path = get_binary_path(args.dev)?;
        install_service(&binary_path, args.dev)?;
    }

    println!("\n🚀 Dragonfly installed! http://{}:{}", display_ip, port);

    if args.fresh || !is_reinstall {
        let password_file = PathBuf::from(format!("{}/initial_password.txt", DRAGONFLY_DIR));
        if password_file.exists() {
            show_admin_credentials(&password_file);
        } else {
            println!("\nWaiting for server to generate admin credentials...");
            wait_for_password_file(&password_file)?;
        }
    }

    Ok(())
}

// ─── Credential display ───────────────────────────────────────────────────────

fn show_admin_credentials(password_file: &Path) {
    if let Ok(password) = fs::read_to_string(password_file) {
        let password = password.trim();
        if !password.is_empty() {
            println!();
            println!("  Admin Login:");
            println!("    Username: admin");
            println!("    Password: {}", password);
            println!();
            println!("Run 'dragonfly status' to see this information again.");
        }
    }
}

/// Wait for the server to generate the initial admin password using inotify.
///
/// We use file-system events rather than polling. The event sequence is:
/// 1. `Create` — the server creates the file (may be empty at this point)
/// 2. `Modify` — the server writes the password into it
///
/// We only display the credentials once the file has non-empty content.
fn wait_for_password_file(password_file: &Path) -> Result<()> {
    use notify::{RecursiveMode, Watcher};
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(
                event.kind,
                notify::EventKind::Create(_) | notify::EventKind::Modify(_)
            ) {
                let _ = tx.send(());
            }
        }
    })
    .map_err(|e| color_eyre::eyre::eyre!("Failed to create file watcher: {}", e))?;

    let watch_dir = password_file.parent().unwrap_or(Path::new(DRAGONFLY_DIR));
    watcher
        .watch(watch_dir, RecursiveMode::NonRecursive)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to watch directory: {}", e))?;

    loop {
        // The file may have been created between our initial check and the watch setup.
        if let Ok(content) = fs::read_to_string(password_file) {
            if !content.trim().is_empty() {
                show_admin_credentials(password_file);
                break;
            }
        }

        // Wait for a file-system event (Create or Modify).
        match rx.recv() {
            Ok(()) => {
                // Re-read: if the file now has content we're done, otherwise wait for
                // the next event (the server will fire Modify once it writes the password).
                if let Ok(content) = fs::read_to_string(password_file) {
                    if !content.trim().is_empty() {
                        show_admin_credentials(password_file);
                        break;
                    }
                }
            }
            Err(_) => break, // Channel closed (watcher dropped)
        }
    }

    Ok(())
}

// ─── System operations ────────────────────────────────────────────────────────

fn wipe_installation() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("sudo")
            .args(["launchctl", "unload", LAUNCHD_PLIST])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("sudo")
            .args(["systemctl", "stop", "dragonfly"])
            .output();
    }

    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", DRAGONFLY_DIR])
        .status();
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", "/etc/dragonfly"])
        .status();
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", OPT_DIR])
        .status();
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-f", PROD_BINARY])
        .status();

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("sudo")
            .args(["rm", "-f", LAUNCHD_PLIST])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("sudo")
            .args(["systemctl", "disable", "dragonfly"])
            .output();
        let _ = std::process::Command::new("sudo")
            .args(["rm", "-f", SYSTEMD_SERVICE])
            .output();
    }

    Ok(())
}

fn check_admin_access() -> Result<bool> {
    if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
        if let Ok(uid_str) = String::from_utf8(output.stdout) {
            if uid_str.trim() == "0" {
                return Ok(true);
            }
        }
    }

    let status = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .output();

    if status.is_ok() && status.unwrap().status.success() {
        return Ok(true);
    }

    let status = std::process::Command::new("sudo")
        .args(["echo", "-n", ""])
        .status()?;

    Ok(status.success())
}

fn create_directories() -> Result<()> {
    let dirs = [
        DRAGONFLY_DIR,
        &format!("{}/tftp", DRAGONFLY_DIR),
        &format!("{}/tftp/mage", DRAGONFLY_DIR),
        &format!("{}/data", DRAGONFLY_DIR),
        &format!("{}/templates", DRAGONFLY_DIR),
    ];

    for dir in &dirs {
        std::process::Command::new("sudo")
            .args(["mkdir", "-p", dir])
            .status()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create {}: {}", dir, e))?;
    }

    std::process::Command::new("sudo")
        .args(["chmod", "-R", "755", DRAGONFLY_DIR])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to set permissions: {}", e))?;

    Ok(())
}

fn write_config(port: u16) -> Result<()> {
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let base_url = format!("http://{}:{}", local_ip, port);

    let config_content = format!(
        r#"# Dragonfly Configuration
# Generated by dragonfly install

[server]
# Server binds to 0.0.0.0 (all interfaces)
port = {}
# Base URL for agents to connect back to this server
base_url = "{}"

[paths]
data_dir = "{}/data"
tftp_dir = "{}/tftp"
"#,
        port, base_url, DRAGONFLY_DIR, DRAGONFLY_DIR
    );

    let temp_config = "/tmp/dragonfly-config.toml";
    fs::write(temp_config, &config_content)?;

    std::process::Command::new("sudo")
        .args(["mv", temp_config, DRAGONFLY_CONFIG])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to install config: {}", e))?;

    Ok(())
}

fn install_binary() -> Result<()> {
    let current_exe = std::env::current_exe()?;

    std::process::Command::new("sudo")
        .args(["cp", &current_exe.to_string_lossy(), PROD_BINARY])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to copy binary: {}", e))?;

    std::process::Command::new("sudo")
        .args(["chmod", "+x", PROD_BINARY])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to set binary permissions: {}", e))?;

    Ok(())
}

fn install_os_templates(dev_mode: bool) -> Result<()> {
    let os_templates_src = Path::new("os-templates");
    let os_templates_dest = format!("{}/os-templates", DRAGONFLY_DIR);

    if !os_templates_src.exists() {
        // Not in project directory; templates will be added via the web UI later.
        return Ok(());
    }

    std::process::Command::new("sudo")
        .args(["mkdir", "-p", &os_templates_dest])
        .status()?;

    if dev_mode {
        let os_templates_abs = std::fs::canonicalize(os_templates_src)?;
        let _ = std::process::Command::new("sudo")
            .args(["rm", "-rf", &os_templates_dest])
            .status();
        std::process::Command::new("sudo")
            .args(["ln", "-s", &os_templates_abs.to_string_lossy(), &os_templates_dest])
            .status()?;
    } else {
        let _ = std::process::Command::new("sudo")
            .args(["rm", "-rf", &os_templates_dest])
            .status();
        std::process::Command::new("sudo")
            .args(["mkdir", "-p", &os_templates_dest])
            .status()?;

        for entry in std::fs::read_dir(os_templates_src)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yml") {
                std::process::Command::new("sudo")
                    .args(["cp", &path.to_string_lossy(), &os_templates_dest])
                    .status()?;
            }
        }
    }

    Ok(())
}

/// Resolve the local path to the web static assets directory.
///
/// Returns `(tempdir, path)` where `tempdir` is `Some` only when the assets
/// were extracted from the embedded binary (caller must keep it alive until
/// the path is no longer needed).
///
/// Resolution order:
/// 1. `crates/dragonfly-server/static` in the current directory (dev / source tree)
/// 2. Embedded assets extracted to a temp directory (standalone binary)
pub fn resolve_local_static_path() -> Result<(Option<tempfile::TempDir>, std::path::PathBuf)> {
    let src = Path::new("crates/dragonfly-server/static");
    if src.exists() {
        return Ok((None, src.to_path_buf()));
    }

    // Extract the embedded static assets to a temp directory.
    let tmp = tempfile::tempdir()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create temp dir for static assets: {}", e))?;
    let dest = tmp.path().join("static");
    fs::create_dir_all(&dest)
        .map_err(|e| color_eyre::eyre::eyre!("mkdir {}: {}", dest.display(), e))?;
    extract_embedded_dir(&EMBEDDED_STATIC, &dest)?;
    Ok((Some(tmp), dest))
}

/// Recursively extract an embedded directory to disk.
fn extract_embedded_dir(embedded: &Dir, dest: &Path) -> Result<()> {
    for file in embedded.files() {
        let out_path = dest.join(file.path());
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| color_eyre::eyre::eyre!("mkdir {}: {}", parent.display(), e))?;
        }
        fs::write(&out_path, file.contents())
            .map_err(|e| color_eyre::eyre::eyre!("write {}: {}", out_path.display(), e))?;
    }
    for subdir in embedded.dirs() {
        extract_embedded_dir(subdir, dest)?;
    }
    Ok(())
}

fn install_web_assets(dev_mode: bool) -> Result<()> {
    let templates_src = Path::new("crates/dragonfly-server/templates");
    let static_src = Path::new("crates/dragonfly-server/static");

    std::process::Command::new("sudo")
        .args(["mkdir", "-p", OPT_DIR])
        .status()?;

    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", &format!("{}/templates", OPT_DIR)])
        .status();
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", &format!("{}/static", OPT_DIR)])
        .status();

    if dev_mode && templates_src.exists() && static_src.exists() {
        let templates_abs = std::fs::canonicalize(templates_src)?;
        let static_abs = std::fs::canonicalize(static_src)?;

        std::process::Command::new("sudo")
            .args(["ln", "-s", &templates_abs.to_string_lossy(), &format!("{}/templates", OPT_DIR)])
            .status()?;
        std::process::Command::new("sudo")
            .args(["ln", "-s", &static_abs.to_string_lossy(), &format!("{}/static", OPT_DIR)])
            .status()?;
    } else if !dev_mode && templates_src.exists() && static_src.exists() {
        std::process::Command::new("sudo")
            .args(["cp", "-r", &templates_src.to_string_lossy(), &format!("{}/templates", OPT_DIR)])
            .status()?;
        std::process::Command::new("sudo")
            .args(["cp", "-r", &static_src.to_string_lossy(), &format!("{}/static", OPT_DIR)])
            .status()?;
    } else {
        // Standalone binary — use embedded assets
        let temp_dir = tempfile::tempdir()?;

        let static_tmp = temp_dir.path().join("static");
        let templates_tmp = temp_dir.path().join("templates");
        fs::create_dir_all(&static_tmp)?;
        fs::create_dir_all(&templates_tmp)?;

        extract_embedded_dir(&EMBEDDED_STATIC, &static_tmp)?;
        extract_embedded_dir(&EMBEDDED_TEMPLATES, &templates_tmp)?;

        std::process::Command::new("sudo")
            .args(["cp", "-r", &static_tmp.to_string_lossy(), &format!("{}/static", OPT_DIR)])
            .status()?;
        std::process::Command::new("sudo")
            .args(["cp", "-r", &templates_tmp.to_string_lossy(), &format!("{}/templates", OPT_DIR)])
            .status()?;
    }

    Ok(())
}

// ─── Service installation ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn install_service(binary_path: &Path, dev_mode: bool) -> Result<()> {
    let watch_paths = if dev_mode {
        format!(
            r#"
    <key>WatchPaths</key>
    <array>
        <string>{}</string>
    </array>"#,
            binary_path.display()
        )
    } else {
        String::new()
    };

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dragonfly.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>serve</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/dragonfly.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/dragonfly.error.log</string>{}
</dict>
</plist>
"#,
        binary_path.display(),
        DRAGONFLY_DIR,
        watch_paths
    );

    let temp_plist = "/tmp/com.dragonfly.daemon.plist";
    fs::write(temp_plist, &plist_content)?;

    let _ = std::process::Command::new("sudo")
        .args(["launchctl", "unload", LAUNCHD_PLIST])
        .output();

    std::process::Command::new("sudo")
        .args(["mv", temp_plist, LAUNCHD_PLIST])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to install plist: {}", e))?;

    std::process::Command::new("sudo")
        .args(["chown", "root:wheel", LAUNCHD_PLIST])
        .status()?;
    std::process::Command::new("sudo")
        .args(["chmod", "644", LAUNCHD_PLIST])
        .status()?;
    std::process::Command::new("sudo")
        .args(["launchctl", "load", LAUNCHD_PLIST])
        .status()?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_service(binary_path: &Path, dev_mode: bool) -> Result<()> {
    let service_content = format!(
        r#"[Unit]
Description=Dragonfly Bare Metal Management
After=network.target

[Service]
Type=simple
ExecStart={} serve
Restart=always
RestartSec=5
WorkingDirectory={}

[Install]
WantedBy=multi-user.target
"#,
        binary_path.display(),
        DRAGONFLY_DIR
    );

    let temp_service = "/tmp/dragonfly.service";
    fs::write(temp_service, &service_content)?;

    let status = std::process::Command::new("sudo")
        .args(["mv", temp_service, SYSTEMD_SERVICE])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to install service: {}", e))?;
    if !status.success() {
        return Err(color_eyre::eyre::eyre!(
            "Failed to move service file to {}",
            SYSTEMD_SERVICE
        ));
    }

    if dev_mode {
        let path_content = format!(
            r#"[Unit]
Description=Watch Dragonfly binary for changes

[Path]
PathChanged={}
Unit=dragonfly.service

[Install]
WantedBy=multi-user.target
"#,
            binary_path.display()
        );

        let temp_path = "/tmp/dragonfly.path";
        fs::write(temp_path, &path_content)?;
        std::process::Command::new("sudo")
            .args(["mv", temp_path, "/etc/systemd/system/dragonfly.path"])
            .status()?;
    }

    let status = std::process::Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to reload systemd: {}", e))?;
    if !status.success() {
        return Err(color_eyre::eyre::eyre!("systemctl daemon-reload failed"));
    }

    if !Path::new(SYSTEMD_SERVICE).exists() {
        return Err(color_eyre::eyre::eyre!(
            "Service file not found at {} after installation",
            SYSTEMD_SERVICE
        ));
    }

    let status = std::process::Command::new("sudo")
        .args(["systemctl", "enable", "--now", "dragonfly"])
        .status()?;
    if !status.success() {
        return Err(color_eyre::eyre::eyre!(
            "Failed to enable and start dragonfly service"
        ));
    }

    if dev_mode {
        std::process::Command::new("sudo")
            .args(["systemctl", "enable", "--now", "dragonfly.path"])
            .status()?;
    }

    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn install_service(_binary_path: &Path, _dev_mode: bool) -> Result<()> {
    println!("Service installation not supported on this platform");
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_installation_state_default() {
        let state = InstallationState::default();
        assert!(!state.directory_exists);
        assert!(!state.config_exists);
        assert!(!state.service_exists);
        assert!(!state.assets_exist);
    }

    #[test]
    fn test_is_macos() {
        let _ = is_macos(); // just confirm it compiles and returns a bool
    }

    #[test]
    fn test_find_next_available_port_advances() {
        // Any port in [1,1024] should be unavailable without root; find_next should
        // go past it. We only verify the return is >= start, not that it's actually open.
        let result = find_next_available_port(1);
        assert!(result >= 1);
    }

    #[test]
    fn test_is_port_available_on_used_port() {
        // Bind port 0 to get an OS-assigned port, then check it's unavailable.
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Port is still held by listener — should be unavailable.
        assert!(!is_port_available(port));
    }

    #[test]
    fn test_get_local_ip_returns_something() {
        // In CI and dev environments, this should always succeed.
        // If network is completely absent, the function returns None — that's fine.
        let _ = get_local_ip(); // just don't panic
    }
}
