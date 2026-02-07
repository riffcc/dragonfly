use anyhow::{Context, anyhow};
use axum::extract::MatchedPath;
use axum::{Router, extract::Extension, http::StatusCode, response::IntoResponse, routing::get};
use axum_login::AuthManagerLayerBuilder;
use listenfd::ListenFd;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Mutex;
use tokio::sync::watch;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tower_sessions::SessionManagerLayer;
use tower_sessions_sqlx_store::SqliteStore;
use tracing::{Level, Span, debug, error, info, warn};

use crate::auth::{AdminBackend, Settings, auth_router};
// Legacy db module removed — all storage via Store trait
use crate::event_manager::EventManager;
use crate::services::{DhcpServiceConfig, ServiceRunner, ServicesConfig, TftpServiceConfig};
use dragonfly_dhcp::{DhcpMode, LeaseTable};
use std::path::PathBuf;

// Add MiniJinja imports
use minijinja::Environment;
use minijinja::path_loader;
use minijinja_autoreload::AutoReloader;

// Add Serialize for the enum
use serde::Serialize;
// Add back AtomicBool and Ordering imports
use std::sync::atomic::{AtomicBool, Ordering};

// Add back necessary tracing_subscriber imports
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt};

// Ensure prelude is still imported if needed elsewhere
// use tracing_subscriber::prelude::*;

mod api;
mod auth;
pub mod event_manager;
mod filters; // Uncomment unused module
pub mod handlers;
pub mod image_cache;
pub mod mode;
pub mod network_detect;
pub mod os_templates;
pub mod provisioning;
pub mod services;
pub mod store;
pub mod ui;

// Expose status module for integration tests
pub mod status;

// Add tokio::fs for directory check
use tokio::fs as async_fs;

// Global static for accessing event manager from other modules
use once_cell::sync::Lazy;
use std::sync::RwLock;
pub static EVENT_MANAGER_REF: Lazy<RwLock<Option<std::sync::Arc<EventManager>>>> =
    Lazy::new(|| RwLock::new(None));

// Global static for installation state (used ONLY during install process itself)
pub static INSTALL_STATE_REF: Lazy<RwLock<Option<Arc<Mutex<InstallationState>>>>> =
    Lazy::new(|| RwLock::new(None));

const CONFIG_PATH: &str = "/var/lib/dragonfly/config.toml";

/// Read server port from config file, default to 3000 if not found
fn read_port_from_config() -> u16 {
    let content = match std::fs::read_to_string(CONFIG_PATH) {
        Ok(c) => c,
        Err(_) => return 3000,
    };

    // Simple TOML parsing - look for "port = NNNN"
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("port") && !line.starts_with("port =") || line.starts_with("port =") {
            if let Some(val) = line.split('=').nth(1) {
                if let Ok(port) = val.trim().parse::<u16>() {
                    return port;
                }
            }
        }
    }
    3000
}

/// Read base_url from config file, returns None if not found
pub fn read_base_url_from_config() -> Option<String> {
    let content = std::fs::read_to_string(CONFIG_PATH).ok()?;

    // Simple TOML parsing - look for 'base_url = "..."'
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("base_url") {
            if let Some(val) = line.split('=').nth(1) {
                let val = val.trim().trim_matches('"');
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

// Stub function to check installation status (Replace with real check later)
// Checks environment variable DRAGONFLY_FORCE_INSTALLED=true for testing
// Also checks for /var/lib/dragonfly and dragonfly StatefulSet status
pub async fn is_dragonfly_installed() -> bool {
    // Check for the existence of the local directory (local installation)
    let dir_path = "/var/lib/dragonfly";
    let dir_exists = match async_fs::metadata(dir_path).await {
        Ok(metadata) => metadata.is_dir(),
        Err(e) => {
            // Log specific error only if it's NOT NotFound
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    "Installation check: Error checking directory {}: {}",
                    dir_path, e
                );
            }
            false
        }
    };

    if dir_exists {
        debug!("Installation check: Directory '{}' found.", dir_path);
        debug!("Detected installed state");
        return true;
    }

    // 3. Check if we can connect to Kubernetes with KUBECONFIG and find Tinkerbell
    debug!(
        "Installation check: Local directory not found, checking for remote Kubernetes with Tinkerbell..."
    );
    if let Ok(client) = kube::Client::try_default().await {
        // Check if tink-system namespace exists (indicates Tinkerbell is deployed)
        use k8s_openapi::api::core::v1::Namespace;
        use kube::api::Api;

        let namespaces: Api<Namespace> = Api::all(client);
        if let Ok(_) = namespaces.get("tink-system").await {
            debug!("Detected Kubernetes with Tinkerbell");
            return true;
        } else {
            debug!(
                "Installation check: Connected to Kubernetes but tink-system namespace not found."
            );
        }
    } else {
        debug!("Installation check: Could not connect to Kubernetes cluster.");
    }

    debug!(
        "Installation check: Not installed (no local directory, no remote Kubernetes with Tinkerbell)."
    );
    false
}

// Enum to hold either static or reloading environment
#[derive(Clone)]
pub enum TemplateEnv {
    Static(Arc<Environment<'static>>),
    #[cfg(debug_assertions)]
    Reloading(Arc<AutoReloader>),
}

// Define the InstallationState enum here or import it
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum InstallationState {
    WaitingSudo,
    DetectingNetwork,
    InstallingK3s,
    WaitingK3s,
    DeployingTinkerbell,
    DeployingDragonfly,
    Ready,
    Failed(String), // Add Failed variant with error message
}

impl InstallationState {
    pub fn get_message(&self) -> &str {
        match self {
            // Phase 1
            InstallationState::WaitingSudo => {
                "Dragonfly is ready to install. Enter your password in your install window — let's do this."
            }
            // Phase (Implied, added previously)
            InstallationState::DetectingNetwork => {
                "Dragonfly is detecting network configuration..."
            }
            // Phase 2
            InstallationState::InstallingK3s => "Dragonfly is installing k3s.",
            // Phase 3
            InstallationState::WaitingK3s => "Dragonfly is waiting for k3s to be ready.",
            // Phase 4
            InstallationState::DeployingTinkerbell => "Dragonfly is deploying Tinkerbell.",
            // Phase 5
            InstallationState::DeployingDragonfly => "Dragonfly is deploying... Dragonfly.",
            // Phase 6
            InstallationState::Ready => "Dragonfly is ready.",
            // Error
            InstallationState::Failed(_) => {
                "Installation failed. Check installer logs for details."
            }
        }
    }
    pub fn get_animation_class(&self) -> &str {
        match self {
            // Phase 1 (Waiting) -> Idle (no specific animation)
            InstallationState::WaitingSudo => "rocket-idle",
            // Phase (Implied, added previously) -> Scanning (pulse/glow)
            InstallationState::DetectingNetwork => "rocket-scanning",
            // Phase 2 (Installing K3s) -> Sparks
            InstallationState::InstallingK3s => "rocket-sparks",
            // Phase 3 (Waiting K3s) -> Glowing
            InstallationState::WaitingK3s => "rocket-glowing",
            // Phase 4 (Deploying Tinkerbell) -> Smoke
            InstallationState::DeployingTinkerbell => "rocket-smoke",
            // Phase 5 (Deploying Dragonfly) -> Flicker
            InstallationState::DeployingDragonfly => "rocket-flicker",
            // Phase 6 (Ready) -> Fire + Shift (lift-off)
            InstallationState::Ready => "rocket-fire rocket-shift",
            // Error -> Error state
            InstallationState::Failed(_) => "rocket-error",
        }
    }
}

// Application state struct
#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Mutex<Settings>>,
    pub event_manager: Arc<EventManager>,
    pub setup_mode: bool,                 // Explicit CLI setup mode
    pub first_run: bool,                  // First run based on settings
    pub shutdown_tx: watch::Sender<()>,   // Channel to signal shutdown
    pub shutdown_rx: watch::Receiver<()>, // Receiver for shutdown (clonable for services)
    // Use the new enum for the environment
    pub template_env: TemplateEnv,
    // Add flags for Scenario B
    pub is_installed: bool,
    pub is_demo_mode: bool, // True if explicitly DEMO or if not installed
    pub is_installation_server: bool, // True if started via install command
    // Add client IP tracking
    pub client_ip: Arc<Mutex<Option<String>>>,
    // Store API tokens in memory for immediate use after creation
    pub tokens: Arc<Mutex<std::collections::HashMap<String, String>>>,
    // Native provisioning service (optional - None uses legacy behavior)
    pub provisioning: Option<Arc<provisioning::ProvisioningService>>,
    // Unified v0.1.0 storage backend for machines, workflows, templates, settings
    pub store: Arc<dyn store::v1::Store>,
    // Track if network services (DHCP/TFTP) are running
    pub network_services_started: Arc<AtomicBool>,
    // Image cache for JIT QCOW2 conversion
    pub image_cache: Arc<image_cache::ImageCache>,
    // Shutdown sender for network services (allows independent restart)
    pub services_shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    // Shared DHCP lease table — survives service restarts, queryable from API
    pub dhcp_lease_table: Arc<tokio::sync::RwLock<LeaseTable>>,
}

/// Map settings store dhcp_mode string to DhcpMode enum
fn dhcp_mode_from_setting(mode_str: &str) -> DhcpMode {
    match mode_str {
        "selective" => DhcpMode::Proxy,
        "flexible" => DhcpMode::AutoProxy,
        "full" => DhcpMode::Reservation,
        _ => DhcpMode::AutoProxy, // default
    }
}

/// Map DhcpMode enum to settings store string
pub fn dhcp_mode_to_setting(mode: DhcpMode) -> &'static str {
    match mode {
        DhcpMode::Proxy => "selective",
        DhcpMode::AutoProxy => "flexible",
        DhcpMode::Reservation => "full",
    }
}

/// Build DhcpServiceConfig from settings store and Network entity
async fn build_dhcp_config_from_store(store: &Arc<dyn store::v1::Store>) -> DhcpServiceConfig {
    let mode_str = store
        .get_setting("dhcp_mode")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "flexible".to_string());

    let mode = dhcp_mode_from_setting(&mode_str);

    // For Full mode, derive pool/gateway/subnet/dns from the target Network entity
    let (pool_range_start, pool_range_end, subnet_mask, gateway, dns_servers) =
        if mode == DhcpMode::Reservation {
            match find_full_dhcp_network(store).await {
                Some(net) => {
                    let pool_start = net
                        .pool_start
                        .as_deref()
                        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
                    let pool_end = net
                        .pool_end
                        .as_deref()
                        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
                    let mask = cidr_to_subnet_mask(&net.subnet);
                    let gw = net
                        .gateway
                        .as_deref()
                        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
                    let mut dns: Vec<std::net::Ipv4Addr> = net
                        .dns_servers
                        .iter()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if dns.is_empty() {
                        info!("No DNS servers configured on network '{}', using public defaults (1.1.1.1, 8.8.8.8)", net.name);
                        dns = vec![
                            std::net::Ipv4Addr::new(1, 1, 1, 1),
                            std::net::Ipv4Addr::new(8, 8, 8, 8),
                        ];
                    }
                    (pool_start, pool_end, mask, gw, dns)
                }
                None => {
                    warn!("Full DHCP mode configured but no target network found");
                    (None, None, None, None, Vec::new())
                }
            }
        } else {
            (None, None, None, None, Vec::new())
        };

    DhcpServiceConfig {
        mode,
        boot_filename_bios: "undionly.kpxe".to_string(),
        boot_filename_uefi: "ipxe.efi".to_string(),
        http_boot_url: None,
        pool_range_start,
        pool_range_end,
        subnet_mask,
        gateway,
        dns_servers,
    }
}

/// Find the network designated for Full DHCP mode.
/// Priority: dhcp_full_network_id setting → native network → first network
async fn find_full_dhcp_network(
    store: &Arc<dyn store::v1::Store>,
) -> Option<dragonfly_common::Network> {
    // Check explicit setting first
    if let Some(id_str) = store
        .get_setting("dhcp_full_network_id")
        .await
        .ok()
        .flatten()
    {
        if let Ok(id) = id_str.parse::<uuid::Uuid>() {
            if let Ok(Some(net)) = store.get_network(id).await {
                return Some(net);
            }
        }
    }

    // Fallback: find native network
    if let Ok(networks) = store.list_networks().await {
        networks.into_iter().find(|n| n.is_native)
    } else {
        None
    }
}

/// Convert CIDR subnet string "10.0.0.0/24" to subnet mask Ipv4Addr
fn cidr_to_subnet_mask(subnet: &str) -> Option<std::net::Ipv4Addr> {
    let prefix_len: u8 = subnet.split('/').nth(1)?.parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    Some(std::net::Ipv4Addr::from(mask))
}

/// Download Spark ELF kernel for bare metal discovery.
/// Idempotent — skips if the correct version is already present.
async fn download_spark_elf() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dest = "/var/lib/dragonfly/spark.elf";
    let tmp_dest = "/var/lib/dragonfly/spark.elf.tmp";
    let version_file = "/var/lib/dragonfly/spark.elf.version";
    let current_version = env!("CARGO_PKG_VERSION");

    // Check if we already have the right version
    if std::path::Path::new(dest).exists() {
        if let Ok(cached_version) = tokio::fs::read_to_string(version_file).await {
            if cached_version.trim() == current_version {
                debug!("Spark ELF already at v{}", current_version);
                return Ok(());
            }
            info!(
                "Spark ELF outdated (cached: v{}, need: v{}), re-downloading",
                cached_version.trim(),
                current_version
            );
        } else {
            info!("Spark ELF exists but no version marker, re-downloading");
        }
    } else {
        info!("Spark ELF not found, downloading");
    }

    let download_url = format!(
        "https://github.com/riffcc/dragonfly/releases/download/v{}/spark.elf",
        current_version
    );
    info!("Downloading Spark v{} from {}", current_version, download_url);

    let client = reqwest::Client::new();
    let response = client.get(&download_url).send().await
        .map_err(|e| anyhow!("Failed to connect to GitHub for Spark download: {}", e))?;

    if !response.status().is_success() {
        warn!("Failed to download Spark: HTTP {} ({})", response.status(), download_url);
        return Ok(());
    }

    let bytes = response.bytes().await?;

    // Validate: must be non-empty and start with ELF magic
    if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
        warn!(
            "Downloaded Spark is invalid ({} bytes, not an ELF file). Keeping existing copy.",
            bytes.len()
        );
        return Ok(());
    }

    // Atomic write: download to temp, validate, then rename
    tokio::fs::write(tmp_dest, &bytes).await?;
    let mut perms = tokio::fs::metadata(tmp_dest).await?.permissions();
    perms.set_mode(0o755);
    tokio::fs::set_permissions(tmp_dest, perms).await?;
    tokio::fs::rename(tmp_dest, dest).await?;
    tokio::fs::write(version_file, current_version).await?;
    info!("Spark ELF v{} downloaded ({} bytes)", current_version, bytes.len());
    Ok(())
}

/// Start network services (DHCP/TFTP)
/// This can be called at startup or dynamically when settings change
pub async fn start_network_services(app_state: &AppState, shutdown_rx: watch::Receiver<()>) {
    // Check if services are already running
    if app_state
        .network_services_started
        .swap(true, Ordering::SeqCst)
    {
        return;
    }

    // Build DHCP config from settings store
    let dhcp_config = build_dhcp_config_from_store(&app_state.store).await;
    let mode_label = dhcp_mode_to_setting(dhcp_config.mode);

    // Create services configuration
    let services_config = ServicesConfig {
        dhcp: Some(dhcp_config),
        tftp: Some(TftpServiceConfig {
            boot_dir: PathBuf::from("/var/lib/dragonfly/tftp"),
        }),
        server_ip: std::net::Ipv4Addr::new(0, 0, 0, 0), // Bind to all interfaces
        http_port: read_port_from_config(),               // Use same port as HTTP server
    };

    // Create service runner with native store for hardware lookup and shared lease table
    let service_runner = ServiceRunner::with_lease_table(
        services_config,
        app_state.store.clone(),
        app_state.dhcp_lease_table.clone(),
    );

    // Create a bool-based shutdown channel for the services
    // (ServiceRunner expects watch::Receiver<bool>)
    let (services_shutdown_tx, services_shutdown_rx) = watch::channel(false);

    // Store the shutdown sender so we can restart services later
    {
        let mut tx_guard = app_state.services_shutdown_tx.lock().await;
        *tx_guard = Some(services_shutdown_tx.clone());
    }

    // Forward the main shutdown signal to the services shutdown channel
    let mut main_shutdown_rx = shutdown_rx;
    tokio::spawn(async move {
        let _ = main_shutdown_rx.changed().await;
        let _ = services_shutdown_tx.send(true);
    });

    // Start services in a background task
    let mode_label_owned = mode_label.to_string();
    tokio::spawn(async move {
        match service_runner.start(services_shutdown_rx).await {
            Ok(handles) => {
                if handles.dhcp.is_some() {
                    println!("  DHCP: 0.0.0.0:67 ({})", mode_label_owned);
                }
                if handles.tftp.is_some() {
                    println!("  TFTP: 0.0.0.0:69");
                }
            }
            Err(e) => {
                error!("Failed to start network services: {}", e);
            }
        }
    });
}

/// Restart network services with updated configuration from settings store
pub async fn restart_network_services(app_state: &AppState) {
    info!("Restarting network services with updated DHCP configuration");

    // Signal existing services to stop
    {
        let mut tx_guard = app_state.services_shutdown_tx.lock().await;
        if let Some(tx) = tx_guard.take() {
            let _ = tx.send(true);
        }
    }

    // Reset the started flag so start_network_services will proceed
    app_state
        .network_services_started
        .store(false, Ordering::SeqCst);

    // Start with fresh configuration
    let shutdown_rx = app_state.shutdown_rx.clone();
    start_network_services(app_state, shutdown_rx).await;
}

pub async fn run() -> anyhow::Result<()> {
    // --- Initialize Logging FIRST ---
    // Use EnvFilter to respect RUST_LOG, defaulting to INFO if not set.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Build the subscriber
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer());
    // --- Logging Initialized ---

    // Determine modes SECOND (after logging is set up)
    let is_installation_server = std::env::var("DRAGONFLY_INSTALL_SERVER_MODE").is_ok();
    let is_explicit_demo_mode = std::env::var("DRAGONFLY_DEMO_MODE").is_ok();
    let setup_mode = std::env::var("DRAGONFLY_SETUP_MODE").is_ok();

    // Determine installation status
    let is_installed = is_dragonfly_installed().await;

    // Determine final demo mode status
    // It's demo mode if explicitly set OR if Dragonfly is not installed (and not the installer server itself)
    let is_demo_mode = is_explicit_demo_mode || (!is_installed && !is_installation_server);

    // --- Populate Install State IMMEDIATELY if needed ---
    if is_installation_server {
        let state = Arc::new(Mutex::new(InstallationState::WaitingSudo));
        match INSTALL_STATE_REF.write() {
            Ok(mut global_ref) => {
                *global_ref = Some(state.clone());
            }
            Err(e) => {
                eprintln!("CRITICAL: Failed ... INSTALL_STATE_REF ...: {}", e);
            }
        }
    }

    // --- Create and Store Event Manager EARLY ---
    // Create event manager (needed even if installing for SSE updates)
    let event_manager = Arc::new(EventManager::new());
    // Store the event manager in the global static ASAP
    match EVENT_MANAGER_REF.write() {
        Ok(mut global_ref) => {
            *global_ref = Some(event_manager.clone());
            // eprintln!("[DEBUG lib.rs] EVENT_MANAGER_REF populated.");
        }
        Err(e) => {
            // Use eprintln! as tracing might not be set up
            eprintln!(
                "CRITICAL: Failed to acquire write lock for EVENT_MANAGER_REF: {}. SSE events may not send.",
                e
            );
        }
    }
    // -------------------------------------------

    // --- COMPLETELY REMOVED LOGGING INITIALIZATION FROM LIB.RS ---
    // Calls like info!() etc. will use whatever global dispatcher exists (or none).

    // --- Start Server Setup ---
    // Conditional info!() calls remain appropriate for specific verbose messages
    // during install, but general logging now respects RUST_LOG.

    let _is_install_mode = is_installation_server;

    // Initialize unified SQLite storage
    const SQLITE_PATH: &str = "/var/lib/dragonfly/dragonfly.sqlite3";
    let sqlite_store = store::v1::SqliteStore::open(SQLITE_PATH)
        .await
        .map_err(|e| anyhow!("Failed to open SQLite store: {}", e))?;
    let db_pool = sqlite_store.pool().clone();
    let store: Arc<dyn store::v1::Store> = Arc::new(sqlite_store);

    // --- Auto-configure Flight mode ---
    // Dragonfly always runs in Flight mode now - no setup wizard needed
    let current_mode_str = store.get_setting("deployment_mode").await.ok().flatten();
    if current_mode_str.is_none() {
        // Auto-set Flight mode on first run
        if let Err(e) = store.put_setting("deployment_mode", "flight").await {
            warn!("Failed to auto-set Flight mode: {}", e);
        }
        if let Err(e) = store.put_setting("setup_completed", "true").await {
            warn!("Failed to mark setup completed: {}", e);
        }
    }
    // --- Initialize OS templates and boot artifacts ---
    if !is_installation_server {
        let event_manager_clone = event_manager.clone();
        let store_for_templates = store.clone();
        tokio::spawn(async move {
            if let Err(e) = os_templates::init_os_templates(store_for_templates).await {
                warn!("Failed to initialize OS templates: {}", e);
            }
            let _ = event_manager_clone.send("templates_ready".to_string());
        });

        // Detect and create default network if none exists
        let store_for_network = store.clone();
        tokio::spawn(async move {
            if let Err(e) = network_detect::init_default_network(store_for_network).await {
                warn!("Failed to detect default network: {}", e);
            }
        });

        // Verify/download Mage boot artifacts (x86_64 only)
        if let Err(_) = crate::api::verify_mage_artifacts(&["x86_64"]) {
            debug!("Downloading boot artifacts...");
            if let Err(e) = crate::api::download_mage_artifacts("3.23", "x86_64").await {
                return Err(anyhow!("Failed to download boot artifacts: {}", e));
            }
            crate::api::verify_mage_artifacts(&["x86_64"])
                .map_err(|e| anyhow!("Boot artifact verification failed: {}", e))?;
        }

        // Download dragonfly-agent binary for x86_64 (needed for Mage apkovl)
        let agent_dest = std::path::Path::new("/var/lib/dragonfly/mage/x86_64/dragonfly-agent");
        if !agent_dest.exists() {
            info!("Downloading dragonfly-agent binary...");
            let download_url = format!(
                "https://github.com/riffcc/dragonfly/releases/download/v{}/dragonfly-agent-linux-amd64",
                env!("CARGO_PKG_VERSION")
            );
            let client = reqwest::Client::new();
            match client.get(download_url).send().await {
                Ok(response) if response.status().is_success() => {
                    match response.bytes().await {
                        Ok(bytes) => {
                            if let Err(e) = tokio::fs::write(agent_dest, &bytes).await {
                                warn!("Failed to write agent binary: {}", e);
                            } else {
                                // Make executable
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    if let Ok(metadata) = tokio::fs::metadata(agent_dest).await {
                                        let mut perms = metadata.permissions();
                                        perms.set_mode(0o755);
                                        let _ = tokio::fs::set_permissions(agent_dest, perms).await;
                                    }
                                }
                                info!("Downloaded dragonfly-agent binary");
                            }
                        }
                        Err(e) => warn!("Failed to read agent binary response: {}", e),
                    }
                }
                Ok(response) => warn!(
                    "Failed to download agent binary: HTTP {}",
                    response.status()
                ),
                Err(e) => warn!("Failed to download agent binary: {}", e),
            }
        }
    }

    // --- Graceful Shutdown Setup ---
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    // Load or generate admin credentials
    let _credentials = match auth::load_credentials(&store).await {
        Ok(cred) => cred,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match auth::generate_default_credentials(&store).await {
                Ok(creds) => creds,
                Err(e) => return Err(anyhow!("Failed to initialize admin credentials: {}", e)),
            }
        }
        Err(e) => return Err(anyhow!("Failed to load admin credentials: {}", e)),
    };

    // Load settings from SQLite or use defaults
    let settings = match store.get_setting("require_login").await {
        Ok(Some(val)) => {
            let mut s = auth::Settings::default();
            s.require_login = val == "true";
            s
        }
        _ => {
            let s = auth::Settings::default();
            let _ = store
                .put_setting("require_login", &s.require_login.to_string())
                .await;
            s
        }
    };

    // Reset setup flag if in setup mode
    if setup_mode {
        let _ = store.put_setting("setup_completed", "false").await;
    }

    // Determine first run status
    let first_run = !settings.setup_completed || setup_mode; // Essential

    // --- MiniJinja Setup ---
    let preferred_template_path = "/opt/dragonfly/templates";
    let fallback_template_path = "crates/dragonfly-server/templates";
    let template_path = if std::path::Path::new(preferred_template_path).exists() {
        preferred_template_path
    } else {
        fallback_template_path
    }
    .to_string();

    let template_env = {
        #[cfg(debug_assertions)]
        {
            let templates_reloaded_flag = Arc::new(AtomicBool::new(false));
            let flag_clone_for_closure = templates_reloaded_flag.clone();
            let reloader = AutoReloader::new(move |notifier| {
                let mut env = Environment::new();
                let path_for_closure = template_path.clone();
                env.set_loader(path_loader(&path_for_closure));
                if let Err(e) = ui::setup_minijinja_environment(&mut env) {
                    error!("Failed to set up MiniJinja environment: {}", e);
                }
                flag_clone_for_closure.store(true, Ordering::SeqCst);
                notifier.watch_path(path_for_closure.as_str(), true);
                Ok(env)
            });
            let reloader_arc = Arc::new(reloader);
            let reloader_clone = reloader_arc.clone();
            let flag_clone_for_loop = templates_reloaded_flag.clone();
            let event_manager_weak = Arc::downgrade(&event_manager);
            tokio::spawn(async move {
                loop {
                    if let Ok(_) = reloader_clone.acquire_env() {
                        if flag_clone_for_loop.swap(false, Ordering::SeqCst) {
                            if let Some(event_manager) = event_manager_weak.upgrade() {
                                let _ = event_manager.send("template_changed:refresh".to_string());
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            });
            TemplateEnv::Reloading(reloader_arc)
        }
        #[cfg(not(debug_assertions))]
        {
            let release_template_path = "/opt/dragonfly/templates";
            let mut env = Environment::new();
            env.set_loader(path_loader(release_template_path));
            if let Err(e) = ui::setup_minijinja_environment(&mut env) {
                error!("Failed to set up MiniJinja environment: {}", e);
            }
            TemplateEnv::Static(Arc::new(env))
        }
    };
    // --- End MiniJinja Setup ---

    // --- Native Provisioning Setup ---
    // Native provisioning is always enabled by default (disable with DRAGONFLY_DISABLE_PROVISIONING=1)
    let native_provisioning_disabled = std::env::var("DRAGONFLY_DISABLE_PROVISIONING").is_ok();
    let provisioning_service = if !native_provisioning_disabled && !is_installation_server {
        info!("Native provisioning enabled - initializing ProvisioningService");

        // Get boot server URL with auto-detection (env var > SQLite > auto-detect > localhost)
        let boot_server_url = mode::get_base_url(Some(store.as_ref())).await;
        info!("Using boot server URL: {}", boot_server_url);

        // Build iPXE configuration
        let ipxe_config = dragonfly_ipxe::IpxeConfig {
            base_url: boot_server_url,
            spark_url: std::env::var("DRAGONFLY_SPARK_URL").ok(),
            mage_kernel_url: std::env::var("DRAGONFLY_MAGE_KERNEL_URL").ok(),
            mage_initramfs_url: std::env::var("DRAGONFLY_MAGE_INITRAMFS_URL").ok(),
            kernel_params: vec![],
            console: std::env::var("DRAGONFLY_CONSOLE").ok(),
            verbose: false,
        };

        // Always use Flight mode
        let provisioning_mode = mode::DeploymentMode::Flight;

        let service =
            provisioning::ProvisioningService::new(store.clone(), ipxe_config, provisioning_mode);

        Some(Arc::new(service))
    } else {
        if !native_provisioning_disabled && is_installation_server {
            debug!("Skipping native provisioning during installation");
        }
        None
    };
    // --- End Native Provisioning Setup ---

    // --- Image Cache Setup ---
    // JIT conversion of QCOW2 images (Ubuntu cloud images) to raw format
    let image_cache_dir = PathBuf::from("/var/lib/dragonfly/image-cache");
    let image_cache_url = mode::get_base_url(Some(store.as_ref())).await;
    let image_cache = Arc::new(image_cache::ImageCache::new(
        image_cache_dir,
        image_cache_url,
    ));
    if let Err(e) = image_cache.init().await {
        warn!("Failed to initialize image cache: {}", e);
    }
    // --- End Image Cache Setup ---

    // Create application state
    let app_state = AppState {
        settings: Arc::new(Mutex::new(settings.clone())), // Clone settings here
        event_manager: event_manager.clone(),             // Use the one created earlier
        setup_mode,
        first_run,
        shutdown_tx: shutdown_tx.clone(),
        shutdown_rx: shutdown_rx.clone(),
        template_env,
        // Add the new flags
        is_installed,
        is_demo_mode,
        is_installation_server,
        // Initialize client IP tracking
        client_ip: Arc::new(Mutex::new(None)),
        // Store API tokens in memory for immediate use after creation
        tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
        // Native provisioning service (if enabled)
        provisioning: provisioning_service.clone(),
        // Unified v0.1.0 storage backend
        store,
        // Track if network services (DHCP/TFTP) are running
        network_services_started: Arc::new(AtomicBool::new(false)),
        // Image cache for JIT QCOW2 conversion
        image_cache: image_cache.clone(),
        // Services shutdown sender for independent restart
        services_shutdown_tx: Arc::new(Mutex::new(None)),
        // Shared DHCP lease table
        dhcp_lease_table: Arc::new(tokio::sync::RwLock::new(LeaseTable::new())),
    };

    // Load Proxmox API tokens from database to memory
    if !app_state.is_installation_server {
        let _ = handlers::proxmox::load_proxmox_tokens_to_memory(&app_state).await;
    }

    // Start the Proxmox sync task
    handlers::proxmox::start_proxmox_sync_task(
        std::sync::Arc::new(app_state.clone()),
        shutdown_rx.clone(),
    )
    .await;

    // Session store setup
    let session_store = SqliteStore::new(db_pool.clone()); // Create store from the pool
    session_store.migrate().await?;

    // Session layer setup - use very permissive settings to ensure consistent behavior
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_http_only(false); // Allow JavaScript access to cookies

    // Auth backend setup
    // Pass the store for authentication
    let backend = AdminBackend::new(app_state.store.clone());

    // Build the auth layer
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    // --- Build Router ---
    let app = Router::new()
        .merge(auth_router())
        .merge(ui::ui_router())
        .route("/favicon.ico", get(handle_favicon))
        // Boot endpoints - /boot/{mac} for iPXE scripts, /boot/{arch}/{asset} for kernel/initramfs
        .route("/boot/{mac}", get(api::ipxe_script))
        // Spark ELF - bare metal discovery agent (loaded by GRUB via multiboot2)
        .route("/boot/spark.elf", get(api::serve_spark_elf))
        // Memtest86+ binary for memory testing
        .route("/boot/memtest86plus.bin", get(api::serve_memtest))
        // PXELINUX bootloader files
        .route("/boot/lpxelinux.0", get(api::serve_lpxelinux))
        .route("/boot/ldlinux.c32", get(api::serve_ldlinux))
        .route("/boot/mboot.c32", get(api::serve_mboot))
        .route("/boot/libcom32.c32", get(api::serve_libcom32))
        .route("/boot/pxelinux.cfg/default", get(api::serve_pxelinux_config))
        // Dynamic boot assets - supports x86_64, aarch64, and arm64 (iPXE uses arm64)
        .route("/boot/{arch}/{asset}", get(api::serve_boot_asset_handler))
        // OS images (served during provisioning)
        .route("/os/debian-13/amd64", get(|| async { api::serve_os_image("debian-13", "amd64").await }))
        .route("/os/debian-13/arm64", get(|| async { api::serve_os_image("debian-13", "arm64").await }))
        // Cached images (JIT-converted QCOW2 to raw)
        .route("/images/{name}", get(api::serve_cached_image))
        // Legacy route for backwards compatibility
        .route("/{mac}", get(api::ipxe_script))
        .route("/ipxe/{*path}", get(api::serve_ipxe_artifact))
        // ISO images for sanboot (served during boot-from-ISO)
        .nest_service("/isos", ServeDir::new("/var/lib/dragonfly/isos"))
        .nest("/api", api::api_router())
        .nest_service("/static", {
            #[cfg(debug_assertions)]
            let static_path = "crates/dragonfly-server/static";
            #[cfg(not(debug_assertions))]
            let static_path = "/opt/dragonfly/static";
            ServeDir::new(static_path)
        })
        .layer(CookieManagerLayer::new())
        .layer(auth_layer)
        // Configure a more verbose TraceLayer (after IP tracking)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
                    // Get matched path if available
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str)
                        .unwrap_or(request.uri().path());

                    tracing::debug_span!(
                        "http-request",
                        method = %request.method(),
                        uri = %request.uri(),
                        matched_path = matched_path, // Log matched path
                        version = ?request.version(),
                        headers = ?request.headers(),
                    )
                })
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO).latency_unit(tower_http::LatencyUnit::Micros))
                .on_failure(|error: tower_http::classify::ServerErrorsFailureClass, latency: std::time::Duration, span: &Span| {
                    // Log failures verbosely
                    tracing::error!(parent: span, latency = ?latency, error = ?error, "Request failed");
                })
        )
        .with_state(app_state.clone()); // State applied here

    // Start handoff listener and network services
    if !is_installation_server {
        let handoff_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = mode::start_handoff_listener(handoff_shutdown_rx).await {
                error!("Handoff listener failed: {}", e);
            }
        });

        // Download iPXE binaries (idempotent — skips if already present)
        match api::download_ipxe_binaries().await {
            Ok(_) => info!("iPXE binaries ready"),
            Err(e) => warn!(
                "Failed to download iPXE binaries: {} — PXE boot may not work",
                e
            ),
        }

        // Download Spark ELF (idempotent — skips if correct version already present)
        if let Err(e) = download_spark_elf().await {
            warn!("Failed to download Spark ELF: {} — bare metal discovery may not work", e);
        }

        start_network_services(&app_state, shutdown_rx.clone()).await;
    }

    // --- Start Server ---
    let default_port: u16 = read_port_from_config();
    let mut listenfd = ListenFd::from_env();
    let socket_activation = std::env::var("LISTEN_FDS").is_ok();

    let listener = match listenfd
        .take_tcp_listener(0)
        .context("Failed to take TCP listener from env")
    {
        Ok(Some(listener)) => {
            tokio::net::TcpListener::from_std(listener).context("Failed to convert TCP listener")?
        }
        Ok(None) | Err(_) => {
            let mut port = default_port;
            loop {
                let addr = SocketAddr::from(([0, 0, 0, 0], port));
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => break listener,
                    Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                        let mut suggested = port + 1;
                        while suggested < 65535 {
                            if std::net::TcpListener::bind(("0.0.0.0", suggested)).is_ok() {
                                break;
                            }
                            suggested += 1;
                        }
                        eprintln!(
                            "Port {} in use. Enter port (or Enter for {}): ",
                            port, suggested
                        );
                        let mut input = String::new();
                        if std::io::stdin().read_line(&mut input).is_ok() {
                            let input = input.trim();
                            port = if input.is_empty() {
                                suggested
                            } else {
                                input.parse().unwrap_or(suggested)
                            };
                        } else {
                            return Err(anyhow::anyhow!("Port {} is already in use", port));
                        }
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to bind to port {}: {}", port, e));
                    }
                }
            }
        }
    };

    // Main startup message
    if !is_installation_server {
        println!(
            "🐉 Dragonfly listening on http://{}",
            listener
                .local_addr()
                .context("Failed to get local address")?
        );
    }

    // Shutdown signal handling
    let shutdown_signal = async move {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
            println!("\nShutting down...");
        };

        #[cfg(unix)]
        let terminate = async {
            if let Ok(mut signal) = signal(SignalKind::terminate()) {
                signal.recv().await;
                println!("\nShutting down...");
            }
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        let _ = shutdown_tx.send(());

        // Force exit after 5 seconds
        tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            std::process::exit(0);
        });
    };

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await
    .context("Server error")?;

    Ok(())
}

async fn handle_favicon() -> impl IntoResponse {
    #[cfg(debug_assertions)]
    let path = "crates/dragonfly-server/static/favicon/favicon.ico";
    #[cfg(not(debug_assertions))]
    let path = "/opt/dragonfly/static/favicon/favicon.ico";

    match tokio::fs::read(path).await {
        Ok(contents) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "image/x-icon")],
            contents,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Favicon not found").into_response(),
    }
}

// Check if database exists at the standard installation path
pub async fn database_exists() -> bool {
    std::path::Path::new("/var/lib/dragonfly/dragonfly.sqlite3").exists()
}

// Add encryption module
pub mod encryption;

// Test helpers module
#[cfg(test)]
pub mod test_helpers;

#[cfg(test)]
pub use test_helpers::create_test_app_state;
