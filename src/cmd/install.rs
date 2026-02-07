use clap::Args;
use color_eyre::eyre::Result;
use include_dir::{include_dir, Dir};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Static assets and templates embedded at compile time.
/// This allows `dragonfly install` to work from a standalone binary download.
static EMBEDDED_STATIC: Dir = include_dir!("crates/dragonfly-server/static");
static EMBEDDED_TEMPLATES: Dir = include_dir!("crates/dragonfly-server/templates");

const DRAGONFLY_DIR: &str = "/var/lib/dragonfly";
const DRAGONFLY_CONFIG: &str = "/var/lib/dragonfly/config.toml";
const PROD_BINARY: &str = "/usr/local/bin/dragonfly";
const OPT_DIR: &str = "/opt/dragonfly";

// Platform-specific service paths
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.dragonfly.daemon.plist";

#[cfg(target_os = "linux")]
const SYSTEMD_SERVICE: &str = "/etc/systemd/system/dragonfly.service";

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

/// Track what's already installed
#[derive(Debug, Default)]
struct InstallationState {
    directory_exists: bool,
    config_exists: bool,
    service_exists: bool,
    assets_exist: bool,
}

impl InstallationState {
    fn detect() -> Self {
        let directory_exists = Path::new(DRAGONFLY_DIR).exists();
        let config_exists = Path::new(DRAGONFLY_CONFIG).exists();
        let service_exists = service_file_exists();
        let assets_exist = Path::new("/var/lib/dragonfly/tftp/mage/vmlinuz").exists()
            && Path::new("/var/lib/dragonfly/tftp/mage/initramfs").exists();

        Self {
            directory_exists,
            config_exists,
            service_exists,
            assets_exist,
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

fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

/// Get this machine's local IP address (first non-loopback IPv4)
fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    // Connect to a public IP (doesn't actually send anything) to find our outbound IP
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

/// Check if a port is available
fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
}

/// Get an available port, prompting user if default is taken
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
    // Check if there's already a configured port
    if let Some(configured_port) = read_configured_port() {
        // If configured port is available, use it
        if is_port_available(configured_port) {
            return Ok(configured_port);
        }
        // Port is in use - likely dragonfly is already running, that's fine
        // We'll just reuse the same port config
        return Ok(configured_port);
    }

    // No existing config, use default
    let default_port: u16 = 3000;

    if is_port_available(default_port) {
        return Ok(default_port);
    }

    // Find next available port to suggest
    let suggested = find_next_available_port(default_port + 1);

    println!("Port {} is already in use.", default_port);
    print!(
        "Enter a different port (or press Enter for {}): ",
        suggested
    );
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

/// Get the binary path to use in the service
fn get_binary_path(dev_mode: bool) -> Result<PathBuf> {
    if dev_mode {
        // Dev mode: use target/release/dragonfly relative to current dir
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
        // Production mode: will copy to /usr/local/bin
        Ok(PathBuf::from(PROD_BINARY))
    }
}

pub async fn run_install(
    args: InstallArgs,
    _shutdown_rx: tokio::sync::watch::Receiver<()>,
) -> Result<()> {
    println!("🐉 Dragonfly Installer");

    // Handle --fresh: wipe everything first
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

    // Detect current state
    let state = InstallationState::detect();
    let is_reinstall = state.directory_exists || state.config_exists || state.service_exists;

    if is_reinstall && !args.fresh {
        println!("Found existing installation, preserving existing data.");
    }

    // Get local IP for display purposes (server binds to 0.0.0.0)
    let display_ip = args
        .ip
        .clone()
        .unwrap_or_else(|| get_local_ip().unwrap_or_else(|| "localhost".to_string()));

    // Check sudo/admin access
    if !check_admin_access()? {
        return Err(color_eyre::eyre::eyre!(
            "Administrator access required for installation"
        ));
    }

    // Get available port (prompts user if default is in use)
    let port = get_available_port()?;

    // Do the work silently
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

    // Success
    println!("\n🚀 Dragonfly installed! http://{}:{}", display_ip, port);

    // On fresh install, wait for the password file and show credentials
    if args.fresh || !is_reinstall {
        let password_file = PathBuf::from(format!("{}/initial_password.txt", DRAGONFLY_DIR));

        // Check if file already exists
        if password_file.exists() {
            show_admin_credentials(&password_file);
        } else {
            println!("\nWaiting for server to generate admin credentials...");
            wait_for_password_file(&password_file)?;
        }
    }

    Ok(())
}

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

fn wait_for_password_file(password_file: &Path) -> Result<()> {
    use notify::{RecursiveMode, Watcher};
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            // Check for file creation or modification
            if matches!(
                event.kind,
                notify::EventKind::Create(_) | notify::EventKind::Modify(_)
            ) {
                let _ = tx.send(());
            }
        }
    })
    .map_err(|e| color_eyre::eyre::eyre!("Failed to create file watcher: {}", e))?;

    // Watch the parent directory for the password file to appear
    let watch_dir = password_file.parent().unwrap_or(Path::new(DRAGONFLY_DIR));
    watcher
        .watch(watch_dir, RecursiveMode::NonRecursive)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to watch directory: {}", e))?;

    // Wait for notification
    loop {
        // Check if file exists now (may have been created between our check and watch setup)
        if password_file.exists() {
            show_admin_credentials(password_file);
            break;
        }

        // Wait for file system event
        match rx.recv() {
            Ok(()) => {
                if password_file.exists() {
                    // Small delay to ensure file is fully written
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    show_admin_credentials(password_file);
                    break;
                }
            }
            Err(_) => break, // Channel closed, watcher dropped
        }
    }

    Ok(())
}

fn wipe_installation() -> Result<()> {
    // Stop service first
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

    // Remove the ENTIRE dragonfly directory (database, data, config, everything)
    // This is critical because is_dragonfly_installed() checks for this directory
    // and the database stores deployment_mode setting
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", DRAGONFLY_DIR])
        .status();

    // Remove the mode file and config directory
    // This is critical because get_current_mode() falls back to /etc/dragonfly/mode
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", "/etc/dragonfly"])
        .status();

    // Remove web assets
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", OPT_DIR])
        .status();

    // Remove production binary
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-f", PROD_BINARY])
        .status();

    // Remove service file
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
    // Check if we're already root by running `id -u`
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

    // Prompt for sudo
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
    // Detect local IP for base_url
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

// TODO: Enable when releases are available
// const GITHUB_WEB_ASSETS_URL: &str = "https://github.com/zorlin/dragonfly/releases/latest/download/dragonfly-web.zip";

fn install_os_templates(dev_mode: bool) -> Result<()> {
    let os_templates_src = Path::new("os-templates");
    let os_templates_dest = format!("{}/os-templates", DRAGONFLY_DIR);

    if !os_templates_src.exists() {
        // Not in project directory, skip OS template copy
        // Templates will be downloaded on demand if not present
        return Ok(());
    }

    std::process::Command::new("sudo")
        .args(["mkdir", "-p", &os_templates_dest])
        .status()?;

    if dev_mode {
        // In dev mode, symlink for easy updates
        let os_templates_abs = std::fs::canonicalize(os_templates_src)?;

        let _ = std::process::Command::new("sudo")
            .args(["rm", "-rf", &os_templates_dest])
            .status();

        std::process::Command::new("sudo")
            .args([
                "ln",
                "-s",
                &os_templates_abs.to_string_lossy(),
                &os_templates_dest,
            ])
            .status()?;
    } else {
        // Production: copy all .yml files
        let _ = std::process::Command::new("sudo")
            .args(["rm", "-rf", &os_templates_dest])
            .status();

        std::process::Command::new("sudo")
            .args(["mkdir", "-p", &os_templates_dest])
            .status()?;

        // Copy all .yml files from os-templates/
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

/// Extract an embedded directory tree to a destination path on disk.
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

    // Remove existing assets first
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", &format!("{}/templates", OPT_DIR)])
        .status();
    let _ = std::process::Command::new("sudo")
        .args(["rm", "-rf", &format!("{}/static", OPT_DIR)])
        .status();

    // Dev mode with project directory: symlink for hot reload
    if dev_mode && templates_src.exists() && static_src.exists() {
        let templates_abs = std::fs::canonicalize(templates_src)?;
        let static_abs = std::fs::canonicalize(static_src)?;

        std::process::Command::new("sudo")
            .args([
                "ln",
                "-s",
                &templates_abs.to_string_lossy(),
                &format!("{}/templates", OPT_DIR),
            ])
            .status()?;
        std::process::Command::new("sudo")
            .args([
                "ln",
                "-s",
                &static_abs.to_string_lossy(),
                &format!("{}/static", OPT_DIR),
            ])
            .status()?;
    } else if !dev_mode && templates_src.exists() && static_src.exists() {
        // Production install from project directory: copy files
        std::process::Command::new("sudo")
            .args([
                "cp",
                "-r",
                &templates_src.to_string_lossy(),
                &format!("{}/templates", OPT_DIR),
            ])
            .status()?;
        std::process::Command::new("sudo")
            .args([
                "cp",
                "-r",
                &static_src.to_string_lossy(),
                &format!("{}/static", OPT_DIR),
            ])
            .status()?;
    } else {
        // Standalone binary — extract embedded assets
        let temp_dir = tempfile::tempdir()?;

        let static_tmp = temp_dir.path().join("static");
        let templates_tmp = temp_dir.path().join("templates");
        fs::create_dir_all(&static_tmp)?;
        fs::create_dir_all(&templates_tmp)?;

        extract_embedded_dir(&EMBEDDED_STATIC, &static_tmp)?;
        extract_embedded_dir(&EMBEDDED_TEMPLATES, &templates_tmp)?;

        std::process::Command::new("sudo")
            .args([
                "cp",
                "-r",
                &static_tmp.to_string_lossy(),
                &format!("{}/static", OPT_DIR),
            ])
            .status()?;
        std::process::Command::new("sudo")
            .args([
                "cp",
                "-r",
                &templates_tmp.to_string_lossy(),
                &format!("{}/templates", OPT_DIR),
            ])
            .status()?;
    }

    Ok(())
}

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

    // Unload existing service if present
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

    // Load the service
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

    std::process::Command::new("sudo")
        .args(["mv", temp_service, SYSTEMD_SERVICE])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to install service: {}", e))?;

    // If dev mode, create a path unit to watch the binary
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

    std::process::Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to reload systemd: {}", e))?;

    // Enable and start the service
    std::process::Command::new("sudo")
        .args(["systemctl", "enable", "--now", "dragonfly"])
        .status()?;

    // If dev mode, also enable the path watcher
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
        // Just verify the function compiles and returns a bool
        let _ = is_macos();
    }
}
