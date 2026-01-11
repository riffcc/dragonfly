use axum::{routing::{get}, extract::Extension, Router, response::{IntoResponse}, http::StatusCode};
use axum_login::{AuthManagerLayerBuilder};
use tower_sessions::{SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;
use std::sync::{Arc};
use tokio::sync::Mutex;
use tower_http::trace::{TraceLayer, DefaultOnRequest, DefaultOnResponse};
use tracing::{info, error, warn, debug, Level, Span};
use std::net::SocketAddr;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use anyhow::{Context, anyhow};
use listenfd::ListenFd;
use axum::extract::MatchedPath;

use crate::auth::{AdminBackend, auth_router, Settings};
use crate::db::init_db;
use crate::event_manager::EventManager;
use crate::services::{ServiceRunner, ServicesConfig, DhcpServiceConfig, TftpServiceConfig};
use dragonfly_dhcp::DhcpMode;
use std::path::PathBuf;

// Add MiniJinja imports
use minijinja::path_loader;
use minijinja::{Environment};
use minijinja_autoreload::AutoReloader;

// Add Serialize for the enum
use serde::Serialize;
// Add back AtomicBool and Ordering imports
use std::sync::atomic::{AtomicBool, Ordering};

// Add back necessary tracing_subscriber imports
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter};

// Ensure prelude is still imported if needed elsewhere
// use tracing_subscriber::prelude::*;

mod auth;
mod api;
mod db;
mod filters; // Uncomment unused module
pub mod handlers;
pub mod ui;
pub mod event_manager;
pub mod os_templates;
pub mod mode;
pub mod store;
pub mod provisioning;
pub mod services;
pub mod tinkerbell;

// Expose status module for integration tests
pub mod status;

// Add tokio::fs for directory check
use tokio::fs as async_fs;

// Global static for accessing event manager from other modules
use std::sync::RwLock;
use once_cell::sync::Lazy;
pub static EVENT_MANAGER_REF: Lazy<RwLock<Option<std::sync::Arc<EventManager>>>> = Lazy::new(|| {
    RwLock::new(None)
});

// Global static for installation state (used ONLY during install process itself)
pub static INSTALL_STATE_REF: Lazy<RwLock<Option<Arc<Mutex<InstallationState>>>>> = Lazy::new(|| {
    RwLock::new(None)
});

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
        if line.starts_with("port") {
            if let Some(val) = line.split('=').nth(1) {
                if let Ok(port) = val.trim().parse::<u16>() {
                    return port;
                }
            }
        }
    }
    3000
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
                warn!("Installation check: Error checking directory {}: {}", dir_path, e);
            }
            false
        },
    };

    if dir_exists {
        debug!("Installation check: Directory '{}' found.", dir_path);
        info!("Installation check: Detected installed state (local directory exists).");
        return true;
    }

    // 3. Check if we can connect to Kubernetes with KUBECONFIG and find Tinkerbell
    debug!("Installation check: Local directory not found, checking for remote Kubernetes with Tinkerbell...");
    if let Ok(client) = kube::Client::try_default().await {
        // Check if tink-system namespace exists (indicates Tinkerbell is deployed)
        use kube::api::Api;
        use k8s_openapi::api::core::v1::Namespace;

        let namespaces: Api<Namespace> = Api::all(client);
        if let Ok(_) = namespaces.get("tink-system").await {
            info!("Installation check: Detected remote Kubernetes with Tinkerbell (tink-system namespace found).");
            return true;
        } else {
            debug!("Installation check: Connected to Kubernetes but tink-system namespace not found.");
        }
    } else {
        debug!("Installation check: Could not connect to Kubernetes cluster.");
    }

    debug!("Installation check: Not installed (no local directory, no remote Kubernetes with Tinkerbell).");
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
            InstallationState::WaitingSudo => "Dragonfly is ready to install. Enter your password in your install window — let's do this.",
            // Phase (Implied, added previously)
            InstallationState::DetectingNetwork => "Dragonfly is detecting network configuration...",
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
            InstallationState::Failed(_) => "Installation failed. Check installer logs for details.",
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
    pub setup_mode: bool,  // Explicit CLI setup mode
    pub first_run: bool,   // First run based on settings
    pub shutdown_tx: watch::Sender<()>,  // Channel to signal shutdown
    // Use the new enum for the environment
    pub template_env: TemplateEnv,
    // Add flags for Scenario B
    pub is_installed: bool,
    pub is_demo_mode: bool, // True if explicitly DEMO or if not installed
    pub is_installation_server: bool, // True if started via install command
    // Add client IP tracking
    pub client_ip: Arc<Mutex<Option<String>>>,
    // Store the raw Pool<Sqlite> here
    pub dbpool: sqlx::Pool<sqlx::Sqlite>,
    // Store API tokens in memory for immediate use after creation
    pub tokens: Arc<Mutex<std::collections::HashMap<String, String>>>,
    // Native provisioning service (optional - None uses legacy behavior)
    pub provisioning: Option<Arc<provisioning::ProvisioningService>>,
    // Native storage backend (ReDB by default)
    pub store: Arc<dyn store::DragonflyStore>,
}

// Clean up any existing processes
async fn cleanup_existing_processes() {
    // No complex process handling - removed
}

pub async fn run() -> anyhow::Result<()> {
    // --- Initialize Logging FIRST --- 
    // Use EnvFilter to respect RUST_LOG, defaulting to INFO if not set.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

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
            Ok(mut global_ref) => { *global_ref = Some(state.clone()); },
            Err(e) => { eprintln!("CRITICAL: Failed ... INSTALL_STATE_REF ...: {}", e); }
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
        }, 
        Err(e) => { 
            // Use eprintln! as tracing might not be set up
            eprintln!("CRITICAL: Failed to acquire write lock for EVENT_MANAGER_REF: {}. SSE events may not send.", e);
        }
    }
    // -------------------------------------------

    // --- COMPLETELY REMOVED LOGGING INITIALIZATION FROM LIB.RS --- 
    // Calls like info!() etc. will use whatever global dispatcher exists (or none).

    // --- Start Server Setup --- 
    // Conditional info!() calls remain appropriate for specific verbose messages
    // during install, but general logging now respects RUST_LOG.

    let _is_install_mode = is_installation_server;

    if is_demo_mode {
        if is_explicit_demo_mode {
            // This info message will now respect RUST_LOG level
            info!("Starting server explicitly in DEMO MODE - no hardware will be touched");
        } else if !is_installed && !is_installation_server {
            info!("Dragonfly not installed - starting server in DEMO MODE - no hardware will be touched");
        }
    } else if !is_installed && is_installation_server {
        info!("Starting server in INSTALLATION MODE");
    } else if is_installed {
        info!("Dragonfly installed - starting server in normal mode");
    }

    // Initialize the database 
    let db_pool = init_db().await?; // DB init is essential

    // Initialize timing database tables
    db::init_timing_tables().await?; // Essential

    // Load historical timing data
    tinkerbell::load_historical_timings().await?; // Essential

    // --- Storage Backend Setup (EARLY - needed for mode check and settings) ---
    // Initialize ReDB as the default storage backend BEFORE anything else
    const REDB_PATH: &str = "/var/lib/dragonfly/dragonfly.redb";
    let native_store: Arc<dyn store::DragonflyStore> = match store::RedbStore::open(REDB_PATH) {
        Ok(s) => {
            info!("Initialized ReDB storage at {}", REDB_PATH);
            Arc::new(s)
        }
        Err(e) => {
            // Fall back to memory store if ReDB fails (e.g., during demo mode)
            warn!("Failed to open ReDB at {}: {}. Using in-memory store.", REDB_PATH, e);
            Arc::new(store::MemoryStore::new())
        }
    };

    // --- Get Deployment Mode from ReDB ---
    let current_mode_str = native_store.get_setting("deployment_mode").await.ok().flatten();
    let current_mode = current_mode_str.as_deref().and_then(|s| match s {
        "flight" => Some(mode::DeploymentMode::Flight),
        "simple" => Some(mode::DeploymentMode::Simple),
        "swarm" => Some(mode::DeploymentMode::Swarm),
        _ => None,
    });

    // Log the current deployment mode
    match &current_mode {
        Some(mode::DeploymentMode::Flight) => info!("Starting server in Flight mode"),
        Some(mode::DeploymentMode::Simple) => info!("Starting server in Simple mode"),
        Some(mode::DeploymentMode::Swarm) => info!("Starting server in Swarm mode"),
        None => info!("No deployment mode set"),
    }

    let is_flight_mode = matches!(current_mode, Some(mode::DeploymentMode::Flight));
    
    if is_flight_mode && !is_installation_server {
        info!("Starting OS templates initialization for Flight mode...");
        let event_manager_clone = event_manager.clone(); // Clone for the task
        let store_for_templates = native_store.clone();
        tokio::spawn(async move {
            match os_templates::init_os_templates(store_for_templates).await {
                Ok(_) => { info!("OS templates initialized successfully"); },
                Err(e) => { warn!("Failed to initialize OS templates: {}", e); }
            }
            // Send event after templates are initialized
            let _ = event_manager_clone.send("templates_ready".to_string());
        });
    } else {
        debug!("Skipping OS templates initialization (not in Flight mode)");
    } // End conditional OS template init

    // --- Graceful Shutdown Setup --- 
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    // Start the timing cleanup task
    tinkerbell::start_timing_cleanup_task(shutdown_rx.clone()).await; // Essential
    
    // Event Manager already created and stored above

    // Start the workflow polling task - only in Flight mode
    if is_flight_mode && !is_installation_server {
        info!("Starting workflow polling task with interval of 1s for Flight mode");
        tinkerbell::start_workflow_polling_task(event_manager.clone(), shutdown_rx.clone()).await;
    } else {
        debug!("Skipping workflow polling task (not in Flight mode)");
    }

    // Load or generate admin credentials
    let _credentials = match auth::load_credentials().await {
        Ok(cred) => {
            info!("Loaded admin credentials successfully");
            cred
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No existing admin credentials found, generating default");
            match auth::generate_default_credentials().await {
                Ok(creds) => creds,
                Err(e) => {
                    error!("Failed to generate default admin credentials: {}", e);
                    return Err(anyhow!("Failed to initialize admin credentials: {}", e));
                }
            }
        }
        Err(e) => {
            error!("Error loading admin credentials: {}", e);
            return Err(anyhow!("Failed to load admin credentials: {}", e));
        }
    };

    // Load settings from ReDB or use defaults
    let settings = match native_store.get_setting("require_login").await {
        Ok(Some(val)) => {
            let require_login = val == "true";
            info!("Loaded require_login={} from ReDB", require_login);
            let mut s = auth::Settings::default();
            s.require_login = require_login;
            s
        }
        _ => {
            info!("No settings in ReDB, using defaults (require_login=true)");
            let s = auth::Settings::default();
            // Save defaults to ReDB
            let _ = native_store.put_setting("require_login", &s.require_login.to_string()).await;
            s
        }
    };

    // Reset setup flag if in setup mode
    if setup_mode {
        if !is_installation_server { info!("Setup mode enabled, resetting setup completion status"); }
        let _ = native_store.put_setting("setup_completed", "false").await;
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
    }.to_string();

    let template_env = { // Logs inside handled by tracing setup
        #[cfg(debug_assertions)]
        {
            info!("Setting up MiniJinja with auto-reload for development");
            let templates_reloaded_flag = Arc::new(AtomicBool::new(false));
            let flag_clone_for_closure = templates_reloaded_flag.clone();
            let reloader = AutoReloader::new(move |notifier| {
                info!("MiniJinja environment is being (re)created...");
                let mut env = Environment::new();
                let path_for_closure = template_path.clone();
                env.set_loader(path_loader(&path_for_closure));
                
                // Set up filters and globals
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
                info!("Starting MiniJinja watcher loop...");
                loop {
                    match reloader_clone.acquire_env() {
                        Ok(_) => {
                            if flag_clone_for_loop.swap(false, Ordering::SeqCst) {
                                info!("Templates reloaded - sending refresh event");
                                if let Some(event_manager) = event_manager_weak.upgrade() {
                                    if let Err(e) = event_manager.send("template_changed:refresh".to_string()) {
                                        warn!("Failed to send template refresh event: {}", e);
                                    } else {
                                        info!("Reload event sent successfully.");
                                    }
                                } else {
                                    warn!("EventManager dropped, cannot send reload event.");
                                }
                            }
                        },
                        Err(e) => {
                            error!("MiniJinja watcher refresh failed: {}", e);
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
            info!("Using templates from {}", release_template_path);
            let mut env = Environment::new();
            env.set_loader(path_loader(release_template_path));

            // Set up filters and globals
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

        // Get boot server URL from environment or use default
        let boot_server_url = std::env::var("DRAGONFLY_BOOT_SERVER_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        // Build iPXE configuration
        let ipxe_config = dragonfly_ipxe::IpxeConfig {
            base_url: boot_server_url,
            mage_kernel_url: std::env::var("DRAGONFLY_MAGE_KERNEL_URL").ok(),
            mage_initramfs_url: std::env::var("DRAGONFLY_MAGE_INITRAMFS_URL").ok(),
            kernel_params: vec![],
            console: std::env::var("DRAGONFLY_CONSOLE").ok(),
            verbose: false,
        };

        // Use the deployment mode from ReDB (already read earlier), default to Simple
        let provisioning_mode = current_mode.clone().unwrap_or(mode::DeploymentMode::Simple);

        info!("Native provisioning mode: {:?}", provisioning_mode);

        let service = provisioning::ProvisioningService::new(
            native_store.clone(),
            ipxe_config,
            provisioning_mode,
        );

        Some(Arc::new(service))
    } else {
        if !native_provisioning_disabled && is_installation_server {
            debug!("Skipping native provisioning during installation");
        }
        None
    };
    // --- End Native Provisioning Setup ---

    // Create application state
    let app_state = AppState {
        settings: Arc::new(Mutex::new(settings.clone())), // Clone settings here
        event_manager: event_manager.clone(), // Use the one created earlier
        setup_mode,
        first_run,
        shutdown_tx: shutdown_tx.clone(),
        template_env,
        // Add the new flags
        is_installed,
        is_demo_mode,
        is_installation_server,
        // Initialize client IP tracking
        client_ip: Arc::new(Mutex::new(None)),
        // Store the db_pool directly
        dbpool: db_pool.clone(),
        // Store API tokens in memory for immediate use after creation
        tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
        // Native provisioning service (if enabled)
        provisioning: provisioning_service.clone(),
        // Native storage backend
        store: native_store,
    };

    // Load Proxmox API tokens from database to memory for immediate use
    if !app_state.is_installation_server {
        info!("Loading Proxmox tokens from database to memory...");
        if let Err(e) = handlers::proxmox::load_proxmox_tokens_to_memory(&app_state).await {
            warn!("Failed to load Proxmox tokens from database: {}", e);
        }
    }

    // Start the Proxmox sync task (regardless of deployment mode)
    // This will check if machines removed from Proxmox should be removed from Dragonfly
    info!("Starting Proxmox synchronization task with interval of 90s");
    handlers::proxmox::start_proxmox_sync_task(std::sync::Arc::new(app_state.clone()), shutdown_rx.clone()).await;

    // Session store setup
    let session_store = SqliteStore::new(db_pool.clone()); // Create store from the pool
    session_store.migrate().await?;

    // Session layer setup - use very permissive settings to ensure consistent behavior
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_http_only(false);  // Allow JavaScript access to cookies

    // Auth backend setup
    // Pass the pool and settings directly from AppState
    let backend = AdminBackend::new(app_state.dbpool.clone(), app_state.settings.lock().await.clone());
    
    // Build the auth layer
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer)
        .build();

    // --- Build Router --- 
    let app = Router::new()
        .merge(auth_router())
        .merge(ui::ui_router())
        .route("/favicon.ico", get(handle_favicon))
        // Boot endpoints - /boot/{mac} for iPXE scripts, /boot/{arch}/{asset} for kernel/initramfs
        .route("/boot/{mac}", get(api::ipxe_script))
        // x86_64 boot assets
        .route("/boot/x86_64/kernel", get(|| async { api::serve_boot_asset("x86_64", "kernel").await }))
        .route("/boot/x86_64/initramfs", get(|| async { api::serve_boot_asset("x86_64", "initramfs").await }))
        .route("/boot/x86_64/modloop", get(|| async { api::serve_boot_asset("x86_64", "modloop").await }))
        .route("/boot/x86_64/apkovl.tar.gz", get(|| async { api::serve_boot_asset("x86_64", "apkovl.tar.gz").await }))
        // aarch64 boot assets
        .route("/boot/aarch64/kernel", get(|| async { api::serve_boot_asset("aarch64", "kernel").await }))
        .route("/boot/aarch64/initramfs", get(|| async { api::serve_boot_asset("aarch64", "initramfs").await }))
        .route("/boot/aarch64/modloop", get(|| async { api::serve_boot_asset("aarch64", "modloop").await }))
        .route("/boot/aarch64/apkovl.tar.gz", get(|| async { api::serve_boot_asset("aarch64", "apkovl.tar.gz").await }))
        // OS images (served during provisioning)
        .route("/os/debian-13/amd64", get(|| async { api::serve_os_image("debian-13", "amd64").await }))
        .route("/os/debian-13/arm64", get(|| async { api::serve_os_image("debian-13", "arm64").await }))
        // Legacy route for backwards compatibility
        .route("/{mac}", get(api::ipxe_script))
        .route("/ipxe/{*path}", get(api::serve_ipxe_artifact))
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
        .layer(Extension(db_pool.clone()))
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

    // Handoff listener setup
    if let Some(mode) = &current_mode {
        if *mode == mode::DeploymentMode::Flight {
            if !is_installation_server { info!("Running in Flight mode - starting handoff listener"); }
            let handoff_shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = mode::start_handoff_listener(handoff_shutdown_rx).await {
                    error!("Handoff listener failed: {}", e);
                }
            });
        }
    }

    // --- Native Network Services (DHCP/TFTP) ---
    // Start DHCP and TFTP servers in Flight mode for bare metal provisioning
    if is_flight_mode && !is_installation_server {
        info!("Starting native network services for Flight mode");

        // Create services configuration
        let services_config = ServicesConfig {
            dhcp: Some(DhcpServiceConfig {
                mode: DhcpMode::AutoProxy, // Auto-discovery of unknown machines
                boot_filename_bios: "undionly.kpxe".to_string(),
                boot_filename_uefi: "ipxe.efi".to_string(),
                http_boot_url: None,
            }),
            tftp: Some(TftpServiceConfig {
                boot_dir: PathBuf::from("/var/lib/dragonfly/tftp"),
            }),
            server_ip: std::net::Ipv4Addr::new(0, 0, 0, 0), // Bind to all interfaces
        };

        // Create service runner with native store for hardware lookup
        let service_runner = ServiceRunner::new(services_config, app_state.store.clone());

        // Create a bool-based shutdown channel for the services
        // (ServiceRunner expects watch::Receiver<bool>)
        let (services_shutdown_tx, services_shutdown_rx) = watch::channel(false);

        // Forward the main shutdown signal to the services shutdown channel
        let mut main_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let _ = main_shutdown_rx.changed().await;
            let _ = services_shutdown_tx.send(true);
        });

        // Start services in a background task
        tokio::spawn(async move {
            match service_runner.start(services_shutdown_rx).await {
                Ok(handles) => {
                    if handles.dhcp.is_some() {
                        info!("DHCP server started in AutoProxy mode");
                    }
                    if handles.tftp.is_some() {
                        info!("TFTP server started serving from /var/lib/dragonfly/tftp");
                    }
                }
                Err(e) => {
                    error!("Failed to start network services: {}", e);
                }
            }
        });
    }
    // --- End Native Network Services ---

    // --- Start Server ---
    let default_port: u16 = read_port_from_config();
    let mut listenfd = ListenFd::from_env();
    let socket_activation = std::env::var("LISTEN_FDS").is_ok();
    if socket_activation && !is_installation_server {
        info!("Socket activation detected via LISTEN_FDS={}", std::env::var("LISTEN_FDS").unwrap_or_else(|_| "?".to_string()));
    }

    let listener = match listenfd.take_tcp_listener(0).context("Failed to take TCP listener from env") {
        Ok(Some(listener)) => {
            if !is_installation_server { info!("Acquired socket via socket activation"); }
            tokio::net::TcpListener::from_std(listener).context("Failed to convert TCP listener")?
        },
        Ok(None) | Err(_) => {
            let mut port = default_port;
            loop {
                let addr = SocketAddr::from(([0, 0, 0, 0], port));
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        if !is_installation_server {
                            info!("Binding to port {}", port);
                        }
                        break listener;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                        // Find next available port to suggest
                        let mut suggested = port + 1;
                        while suggested < 65535 {
                            if std::net::TcpListener::bind(("0.0.0.0", suggested)).is_ok() {
                                break;
                            }
                            suggested += 1;
                        }

                        eprintln!("\nPort {} is already in use.", port);
                        eprint!("Enter a different port (or press Enter for {}): ", suggested);
                        std::io::Write::flush(&mut std::io::stderr()).ok();

                        let mut input = String::new();
                        if std::io::stdin().read_line(&mut input).is_ok() {
                            let input = input.trim();
                            if input.is_empty() {
                                port = suggested;
                            } else if let Ok(p) = input.parse::<u16>() {
                                port = p;
                            } else {
                                eprintln!("Invalid port number, using {}", suggested);
                                port = suggested;
                            }
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
    if !is_installation_server { // Conditional Log
        info!("Dragonfly server listening on http://{}", listener.local_addr().context("Failed to get local address")?);
    }

    // --- Shutdown Signal Handling --- 
    let shutdown_signal = async move {
        // Set up a simple future for Ctrl+C
        let ctrl_c = async { 
            tokio::signal::ctrl_c().await.unwrap_or_else(|e| {
                error!("Failed to listen for Ctrl+C: {}", e);
            });
            info!("Received Ctrl+C");
            println!("\nShutting down...");
        };
        
        #[cfg(unix)]
        let terminate = async { 
            if let Ok(mut signal) = signal(SignalKind::terminate()) {
                signal.recv().await;
                info!("Received SIGTERM");
                println!("\nReceived SIGTERM, shutting down...");
            }
        };
        
        #[cfg(not(unix))] 
        let terminate = std::future::pending::<()>();
        
        // Wait for any signal
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
        
        // Send the shutdown signal
        let _ = shutdown_tx.send(());
        info!("Sending shutdown signal to all components");
        
        // Force exit after 5 seconds if graceful shutdown hasn't completed
        tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            println!("Forcing exit after timeout");
            std::process::exit(0);
        });
    };

    // Start serving with graceful shutdown
    println!("Server started, press Ctrl+C to stop");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()) // Explicitly add ConnectInfo
        .with_graceful_shutdown(shutdown_signal)
        .await
        .context("Server error")?;

    if !is_installation_server { info!("Shutdown complete"); } // Cond Log

    Ok(())
}

async fn handle_favicon() -> impl IntoResponse {
    #[cfg(debug_assertions)]
    let path = "crates/dragonfly-server/static/favicon/favicon.ico";
    #[cfg(not(debug_assertions))]
    let path = "/opt/dragonfly/static/favicon/favicon.ico";

    match tokio::fs::read(path).await {
        Ok(contents) => (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "image/x-icon")], contents).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Favicon not found").into_response()
    }
}

// Access functions for main.rs to use
pub use db::database_exists;

// Add a filter to check if a string is a valid IP address
fn is_valid_ip(ip: String) -> bool {
    // Use regex to check if string is a valid IPv4 address
    let ip_regex = regex::Regex::new(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap();
    ip_regex.is_match(&ip)
}

// Add encryption module
pub mod encryption;
