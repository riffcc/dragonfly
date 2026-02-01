use axum::{
    extract::{Query, State, OriginalUri},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use dragonfly_common::models::{Machine, MachineStatus, DiskInfo};
use dragonfly_common::Machine as V1Machine;
use crate::store::conversions::machine_to_common;
use tracing::{debug, error, info, warn};
use std::collections::HashMap;
use chrono::{DateTime, Utc, TimeZone};
use cookie::{Cookie, SameSite};
use std::fs;
use serde::{Serialize, Deserialize};
// SQLite db functions removed - using ReDB store directly
use crate::auth::{self, AuthSession, Settings, Credentials};
use minijinja::{Error as MiniJinjaError, ErrorKind as MiniJinjaErrorKind};
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

// Stub types for workflow info (Tinkerbell integration removed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInfo {
    pub state: String,
    pub current_action: Option<String>,
    pub progress: u8,
    pub tasks: Vec<TaskInfo>,
    pub estimated_completion: Option<String>,
    pub template_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub name: String,
    pub status: String,
    pub started_at: String,
    pub duration: u64,
    pub reported_duration: u64,
    pub estimated_duration: u64,
    pub progress: u8,
}

// Import global state
use crate::{AppState, INSTALL_STATE_REF, InstallationState};

// Import format_os_name from api.rs
use crate::api::{format_os_name, get_os_icon, get_os_info};

// Extract theme from cookies
pub fn get_theme_from_cookie(headers: &HeaderMap) -> String {
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_pair in cookie_str.split(';') {
                if let Ok(cookie) = Cookie::parse(cookie_pair.trim()) {
                    if cookie.name() == "dragonfly_theme" {
                        return cookie.value().to_string();
                    }
                }
            }
        }
    }
    "light".to_string()
}

// Update struct for MiniJinja context, matching data from api.rs handler
#[derive(Serialize)] // Use Serialize for MiniJinja
pub struct WorkflowProgressTemplate {
    // Fields provided by get_workflow_progress in api.rs
    pub machine_id: Uuid,
    pub workflow_info: WorkflowInfo, // Not Option<> as api.rs ensures it exists before calling render
}

#[derive(Serialize)]
pub struct IndexTemplate {
    pub title: String,
    pub machines: Vec<Machine>,
    pub status_counts: HashMap<String, usize>,
    pub status_counts_json: String,
    pub theme: String,
    pub is_authenticated: bool,
    pub display_dates: HashMap<String, String>,
    pub installation_in_progress: bool,
    pub initial_install_message: String,
    pub initial_animation_class: String,
    pub is_demo_mode: bool,
    pub current_path: String,
}

#[derive(Serialize)]
pub struct MachineListTemplate {
    pub machines: Vec<Machine>,
    pub theme: String,
    pub is_authenticated: bool,
    pub is_admin: bool,
    pub workflow_infos: HashMap<uuid::Uuid, WorkflowInfo>,
    pub current_path: String,
}

// No Serialize derive needed for Askama
#[derive(Serialize)] 
pub struct MachineDetailsTemplate {
    pub machine_json: String, // Serialized machine data
    pub theme: String,
    pub is_authenticated: bool,
    pub created_at_formatted: String,
    pub updated_at_formatted: String,
    pub workflow_info_json: String, // Serialized workflow info data
    pub machine: Machine, // Original machine struct for convenience
    pub workflow_info: Option<WorkflowInfo>, // Original workflow info for convenience
    pub current_path: String,
    pub ip_address_type: String, // New field for IP address type
}

#[derive(Serialize)]
pub struct SettingsTemplate {
    pub theme: String,
    pub is_authenticated: bool,
    pub admin_username: String,
    pub require_login: bool,
    pub default_os_none: bool,
    pub default_os_ubuntu2204: bool,
    pub default_os_ubuntu2404: bool,
    pub default_os_debian12: bool,
    pub default_os_debian13: bool,
    pub default_os_proxmox: bool,
    pub has_initial_password: bool,
    pub rendered_password: String,
    pub show_admin_settings: bool,
    pub error_message: Option<String>,
    pub current_path: String,
}

#[derive(Serialize)]
pub struct ErrorTemplate {
    pub theme: String,
    pub is_authenticated: bool,
    pub title: String,
    pub message: String,
    pub error_details: String,
    pub back_url: String,
    pub back_text: String,
    pub show_retry: bool,
    pub retry_url: String,
    pub current_path: String,
}

// Define a struct for grouping machines by Proxmox host/cluster
#[derive(Debug, Clone, Serialize)]
pub struct ProxmoxCluster {
    pub display_name: String,
    pub cluster_name: Option<String>,
    pub hosts: Vec<Machine>,
    pub vms: Vec<Machine>,
}

#[derive(Serialize, Debug)]
pub struct ComputeTemplate {
    theme: String,
    is_authenticated: bool,
    is_admin: bool,
    clusters: Vec<ProxmoxCluster>,
    current_path: String,
}

// Updated render_minijinja function
pub fn render_minijinja<T: Serialize>(
    app_state: &crate::AppState,
    template_name: &str, 
    context: T
) -> Response {
    // Get the environment based on the mode (static or reloading)
    let render_result = match &app_state.template_env {
        crate::TemplateEnv::Static(env) => {
            env.get_template(template_name)
               .and_then(|tmpl| tmpl.render(context))
        }
        #[cfg(debug_assertions)]
        crate::TemplateEnv::Reloading(reloader) => {
            // Acquire the environment from the reloader
            match reloader.acquire_env() {
                Ok(env) => {
                    env.get_template(template_name)
                       .and_then(|tmpl| tmpl.render(context))
                }
                Err(e) => {
                    error!("Failed to acquire MiniJinja env from reloader: {}", e);
                    // Convert minijinja::Error to rendering result error
                    Err(MiniJinjaError::new(MiniJinjaErrorKind::InvalidOperation, 
                        format!("Failed to acquire env from reloader: {}", e)))
                }
            }
        }
    };

    // Handle the final rendering result
    match render_result {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("MiniJinja render/load error for {}: {}", template_name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Template error: {}", e)).into_response()
        }
    }
}

// Create router with state
pub fn ui_router() -> Router<crate::AppState> {
    Router::new()
        .route("/", get(index))
        .route("/machines", get(machine_list))
        .route("/machines/{id}", get(machine_details))
        .route("/compute", get(compute_page))
        .route("/tags", get(tags_page))
        .route("/theme/toggle", get(toggle_theme))
        .route("/settings", get(settings_page))
        .route("/settings", post(update_settings))
}

// Count machines by status and return a HashMap
fn count_machines_by_status(machines: &[Machine]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();

    // Initialize counts for all statuses to ensure they're present in the chart
    counts.insert("Discovered".to_string(), 0);
    counts.insert("Ready to Install".to_string(), 0);
    counts.insert("Initializing".to_string(), 0);
    counts.insert("Installing".to_string(), 0);
    counts.insert("Writing".to_string(), 0);
    counts.insert("Installed".to_string(), 0);
    counts.insert("Existing OS".to_string(), 0);
    counts.insert("Offline".to_string(), 0);
    counts.insert("Failed".to_string(), 0);

    // Count actual statuses
    for machine in machines {
        let status_key = match &machine.status {
            MachineStatus::Discovered => "Discovered",
            MachineStatus::ReadyToInstall => "Ready to Install",
            MachineStatus::Initializing => "Initializing",
            MachineStatus::Installing => "Installing",
            MachineStatus::Writing => "Writing",
            MachineStatus::Installed => "Installed",
            MachineStatus::ExistingOS => "Existing OS",
            MachineStatus::Offline => "Offline",
            MachineStatus::Failed(_) => "Failed",
        };

        *counts.get_mut(status_key).unwrap() += 1;
    }

    counts
}

// Helper to format DateTime<Utc> to a friendly string
fn format_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

// Function to generate demo machines
fn generate_demo_machines() -> Vec<Machine> {
    let mut machines = Vec::new();
    let base_time = Utc.with_ymd_and_hms(2023, 4, 15, 12, 0, 0).unwrap();
    let base_mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0x00];
    let base_ip = Ipv4Addr::new(10, 0, 42, 0);

    // Generate topaz-control[01:03]
    for i in 1..=3 {
        let hostname = format!("topaz-control{:02}", i);
        let mac_suffix = i as u8;
        let ip_suffix = 10 + i as u8;
        machines.push(create_demo_machine(
            &hostname, 
            base_mac, 
            mac_suffix, 
            base_ip, 
            ip_suffix, 
            base_time.clone(), 
            MachineStatus::Installed,
            Some(500), // 500GB disk
        ));
    }

    // Generate topaz-worker[01:06]
    for i in 1..=6 {
        let hostname = format!("topaz-worker{:02}", i);
        let mac_suffix = 10 + i as u8;
        let ip_suffix = 20 + i as u8;
        machines.push(create_demo_machine(
            &hostname, 
            base_mac, 
            mac_suffix, 
            base_ip, 
            ip_suffix, 
            base_time.clone(), 
            MachineStatus::Installed,
            Some(2000), // 2TB disk
        ));
    }

    // Generate cubefs-master[01:03]
    for i in 1..=3 {
        let hostname = format!("cubefs-master{:02}", i);
        let mac_suffix = 20 + i as u8;
        let ip_suffix = 30 + i as u8;
        machines.push(create_demo_machine(
            &hostname, 
            base_mac, 
            mac_suffix,
            base_ip, 
            ip_suffix, 
            base_time.clone(), 
            MachineStatus::Installed,
            Some(500), // 500GB disk
        ));
    }

    // Generate cubefs-datanode[01:06]
    for i in 1..=6 {
        let hostname = format!("cubefs-datanode{:02}", i);
        let mac_suffix = 30 + i as u8;
        let ip_suffix = 40 + i as u8;
        let status = if i <= 5 { 
            MachineStatus::Installed 
        } else { 
            // Make one datanode show as "installing" for variety
            MachineStatus::Writing 
        };
        machines.push(create_demo_machine(
            &hostname, 
            base_mac, 
            mac_suffix, 
            base_ip, 
            ip_suffix, 
            base_time.clone(), 
            status,
            Some(4000), // 4TB disk
        ));
    }

    machines
}

// Helper function to create a demo machine
fn create_demo_machine(
    hostname: &str,
    base_mac: [u8; 6],
    mac_suffix: u8,
    base_ip: Ipv4Addr,
    ip_suffix: u8,
    base_time: DateTime<Utc>,
    status: MachineStatus,
    disk_size_gb: Option<u64>,
) -> Machine {
    // Generate a deterministic UUID based on hostname
    let mut mac = base_mac;
    mac[5] = mac_suffix;
    
    // Use UUID v5 to create a deterministic UUID from the hostname
    // This allows machine details to be found consistently in demo mode
    let namespace = uuid::Uuid::NAMESPACE_DNS;
    let uuid = uuid::Uuid::new_v5(&namespace, hostname.as_bytes());
    let created_at = base_time + chrono::Duration::minutes(mac_suffix as i64);
    let updated_at = created_at + chrono::Duration::hours(1);
    
    let mut ip_octets = base_ip.octets();
    ip_octets[3] = ip_suffix;
    let ip = IpAddr::V4(Ipv4Addr::from(ip_octets));

    // Format MAC address with colons
    let mac_string = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // Generate memorable name using BIP39 words based on MAC address
    let memorable_name = dragonfly_common::mac_to_words::mac_to_words_safe(&mac_string);

    // Create a disk to match the requested disk size
    let disk = DiskInfo {
        device: format!("/dev/sda"),
        size_bytes: disk_size_gb.unwrap_or(500) * 1_073_741_824, // Convert GB to bytes
        model: Some(format!("Demo Disk {}", disk_size_gb.unwrap_or(500))),
        calculated_size: Some(format!("{} GB", disk_size_gb.unwrap_or(500))),
    };

    // Create the machine with the correct fields
    Machine {
        id: uuid,
        hostname: Some(hostname.to_string()),
        mac_address: mac_string,
        ip_address: ip.to_string(), // No Option<> here, ip_address is a String
        status,
        os_choice: Some("ubuntu-2204".to_string()),
        os_installed: Some("Ubuntu 22.04".to_string()),
        disks: vec![disk],
        nameservers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        memorable_name: Some(memorable_name),
        created_at,
        updated_at,
        bmc_credentials: None,
        installation_progress: 0,
        installation_step: None,
        last_deployment_duration: None,
        // Initialize new hardware fields to None for demo data
        cpu_model: None,
        cpu_cores: None,
        total_ram_bytes: None,
        proxmox_vmid: None,
        proxmox_node: None,
        proxmox_cluster: None, // Add the new field, initialize to None for demo
        is_proxmox_host: false, // Add the new field, default to false for demo data
        reimage_requested: false, // Demo machines don't have pending reimages
    }
}

#[axum::debug_handler]
pub async fn index(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    auth_session: AuthSession,
    uri: OriginalUri,
) -> Response {
    let theme = get_theme_from_cookie(&headers);
    let is_authenticated = auth_session.user.is_some();
    let require_login = app_state.store.get_setting("require_login").await.ok().flatten().map(|v| v == "true").unwrap_or(true);
    let current_path = uri.path().to_string();

    // --- Login check FIRST (before any other logic) ---
    // If require_login is enabled and user is not authenticated, redirect to login
    // This applies regardless of mode or installation state (except demo mode)
    if require_login && !is_authenticated && !app_state.is_demo_mode {
        info!("Login required, redirecting to /login");
        return Redirect::to("/login").into_response();
    }

    // --- Scenario B Logic ---
    if app_state.is_demo_mode {
        // Case B.3: Not installed (or explicitly demo) -> Show Demo Experience
        info!("Rendering Demo Experience (root route)");
        // The rest of this function will now handle rendering the demo dashboard
        // Ensure is_demo_mode is passed to the template
    } else if app_state.is_installed {
        // Installed - proceed to normal UI (Dashboard)
        debug!("Rendering dashboard");
    } else {
        // This case means it's *not* demo, *not* installed.
        // Check if it's the installation server running.
        if app_state.is_installation_server {
            // This is the expected state during installation. Proceed normally.
            // The template will handle showing the installation progress UI.
            info!("Install server running, rendering index page for installation progress.");
        } else {
            // It's NOT the install server, so this state is truly unexpected.
            warn!("Root route accessed in unexpected state (not demo, not installed, not install server). Rendering error.");
            let context = ErrorTemplate {
                theme,
                is_authenticated: false, // Assume not authenticated
                title: "Unexpected Server State".to_string(),
                message: "The server is in an unexpected state. Installation might be incomplete or the server requires setup.".to_string(),
                error_details: "Error code: UI_ROOT_UNEXPECTED_STATE_FINAL".to_string(), // Use a distinct code
                back_url: "/".to_string(),
                back_text: "Retry".to_string(),
                show_retry: true,
                retry_url: "/".to_string(),
                current_path,
            };
            return render_minijinja(&app_state, "error.html", context);
        }
    }
    // --- End Scenario B Logic ---

    // --- Continue with Dashboard/Demo Rendering --- 
    let installation_in_progress = std::env::var("DRAGONFLY_INSTALL_SERVER_MODE").is_ok() || app_state.is_installation_server;
    let mut initial_install_message = String::new();
    let mut initial_animation_class = String::new();

    // If installing, get initial state
    if installation_in_progress {
        // Clone the Arc out of the RwLock guard before awaiting
        let install_state_arc_mutex: Option<Arc<tokio::sync::Mutex<InstallationState>>> = {
            INSTALL_STATE_REF.read().unwrap().as_ref().cloned()
        };

        if let Some(state_arc_mutex) = install_state_arc_mutex {
            let initial_state = state_arc_mutex.lock().await.clone(); 
            initial_install_message = initial_state.get_message().to_string();
            initial_animation_class = initial_state.get_animation_class().to_string();
        }
    }
    
    // Prepare context for the template
    // Fetch real/demo data based on app_state.is_demo_mode
    let (machines, status_counts, status_counts_json, display_dates) = if !installation_in_progress {
        if app_state.is_demo_mode { // Check the state flag now
            // In demo mode, generate fake demo machines
            let demo_machines = generate_demo_machines();
            let counts = count_machines_by_status(&demo_machines);
            let counts_json = serde_json::to_string(&counts).unwrap_or_else(|_| "{}".to_string());
            let dates = demo_machines.iter()
                .map(|mach| (mach.id.to_string(), format_datetime(&mach.created_at)))
                .collect();
            (demo_machines, counts, counts_json, dates)
        } else {
            // Normal mode - fetch machines from v1 Store (ReDB with UUIDv7)
            let m: Vec<Machine> = match app_state.store.list_machines().await {
                Ok(machine_list) => {
                    machine_list.iter().map(|m| machine_to_common(m)).collect()
                }
                Err(e) => {
                    error!("Failed to list machines from store: {}", e);
                    vec![]
                }
            };

            let counts = count_machines_by_status(&m);
            let counts_json = serde_json::to_string(&counts).unwrap_or_else(|_| "{}".to_string());
            let dates = m.iter()
                .map(|mach| (mach.id.to_string(), format_datetime(&mach.created_at)))
                .collect();
            (m, counts, counts_json, dates)
        }
    } else {
        // Provide empty defaults if installing
        (vec![], HashMap::new(), "{}".to_string(), HashMap::new())
    };

    let context = IndexTemplate {
        title: "Dragonfly".to_string(),
        machines,
        status_counts,
        status_counts_json,
        theme,
        is_authenticated,
        display_dates,
        installation_in_progress,
        initial_install_message,
        initial_animation_class,
        is_demo_mode: app_state.is_demo_mode, // Use the state flag
        current_path,
    };

    render_minijinja(&app_state, "index.html", context)
}

pub async fn machine_list(
    State(app_state): State<crate::AppState>,
    headers: HeaderMap,
    auth_session: AuthSession,
    uri: OriginalUri,
) -> Response {
    let theme = get_theme_from_cookie(&headers);
    let is_authenticated = auth_session.user.is_some();
    let is_admin = is_authenticated;
    let current_path = uri.path().to_string();

    let require_login = app_state.store.get_setting("require_login").await.ok().flatten().map(|v| v == "true").unwrap_or(true);

    // Login check (applies to both normal and demo mode if require_login is true)
    if require_login && !is_authenticated {
        info!("Login required for /machines, redirecting to /login");
        // HTMX redirect
        let mut response = Redirect::to("/login").into_response();
        response.headers_mut().insert("HX-Redirect", "/login".parse().unwrap());
        return response;
    }

    // Determine if we are in demo mode (using the state flag)
    let is_demo_mode = app_state.is_demo_mode;

    // If in demo mode, show demo machines
    if is_demo_mode {
        // Generate demo machines
        let machines = generate_demo_machines();
        // Create an empty workflow info map
        let workflow_infos = HashMap::new();

        let context = MachineListTemplate {
            machines,
            theme,
            is_authenticated,
            is_admin,
            workflow_infos,
            current_path,
        };
        return render_minijinja(&app_state, "machine_list.html", context);
    } else { // Normal mode
        // Normal mode - fetch machines from v1 Store (ReDB with UUIDv7)
        let machines_result = match app_state.store.list_machines().await {
            Ok(machine_list) => {
                let machines: Vec<Machine> = machine_list
                    .iter()
                    .map(|m| machine_to_common(m))
                    .collect();
                Ok(machines)
            }
            Err(e) => Err(e)
        };

        match machines_result {
            Ok(machines) => {
                // Workflow info fetching removed (Tinkerbell integration removed)
                let workflow_infos = HashMap::new();

                let context = MachineListTemplate {
                    machines,
                    theme,
                    is_authenticated,
                    is_admin,
                    workflow_infos,
                    current_path,
                };
                render_minijinja(&app_state, "machine_list.html", context)
            },
            Err(e) => {
                error!("Error fetching machines from ReDB: {}", e);
                let context = MachineListTemplate {
                    machines: vec![],
                    theme,
                    is_authenticated,
                    is_admin,
                    workflow_infos: HashMap::new(),
                    current_path,
                };
                render_minijinja(&app_state, "machine_list.html", context)
            }
        }
    }
}

pub async fn machine_details(
    State(app_state): State<crate::AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    auth_session: AuthSession,
    uri: OriginalUri,
) -> Response {
    // Get theme preference from cookie
    let theme = get_theme_from_cookie(&headers);
    let is_authenticated = auth_session.user.is_some();
    let current_path = uri.path().to_string();
    
    // Check if login is required site-wide
    let require_login = app_state.store.get_setting("require_login").await.ok().flatten().map(|v| v == "true").unwrap_or(true);
    
    // If require_login is enabled and user is not authenticated,
    // redirect to login page
    if require_login && !is_authenticated {
        return Redirect::to("/login").into_response();
    }
    
    // Check if we are in demo mode
    let is_demo_mode = std::env::var("DRAGONFLY_DEMO_MODE").is_ok();
    
    // Parse UUID from string
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => {
            // If in demo mode, find the machine in our demo dataset
            if is_demo_mode {
                let demo_machines = generate_demo_machines();
                // Use string comparison for more reliable matching in templates
                if let Some(machine) = demo_machines.iter().find(|m| m.id.to_string() == uuid.to_string()) {
                    let created_at_formatted = machine.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    let updated_at_formatted = machine.updated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    
                    // Create a mock workflow info if the machine is in installing status
                    let workflow_info = if machine.status == MachineStatus::Writing {
                        Some(WorkflowInfo {
                            state: "running".to_string(),
                            current_action: Some("Writing disk image".to_string()),
                            progress: 65,
                            tasks: vec![
                                TaskInfo {
                                    name: "Installing operating system".to_string(),
                                    status: "STATE_RUNNING".to_string(),
                                    started_at: (Utc::now() - chrono::Duration::minutes(15)).to_rfc3339(),
                                    duration: 900, // 15 minutes in seconds
                                    reported_duration: 900,
                                    estimated_duration: 1800, // 30 minutes in seconds
                                    progress: 65,
                                }
                            ],
                            estimated_completion: Some("About 10 minutes remaining".to_string()),
                            template_name: "ubuntu-2204".to_string(),
                        })
                    } else {
                        None
                    };

                    // Serialize machine and workflow_info to JSON strings
                    let machine_json = serde_json::to_string(machine)
                        .unwrap_or_else(|e| {
                            error!("Failed to serialize demo machine to JSON: {}", e);
                            "{}".to_string() // Default to empty JSON object on error
                        });
                    // ADD DEBUG LOG
                    info!("Serialized demo machine JSON: {}", machine_json);
                    
                    let workflow_info_json = serde_json::to_string(&workflow_info)
                        .unwrap_or_else(|e| {
                             error!("Failed to serialize demo workflow info to JSON: {}", e);
                             "null".to_string() // Default to JSON null on error
                         });
                    // ADD DEBUG LOG
                    info!("Serialized demo workflow JSON: {}", workflow_info_json);                         
                    
                    // Determine IP address type
                    let ip_address_type = if machine.ip_address.is_empty() || 
                                                machine.ip_address == "0.0.0.0" {
                        "DHCP".to_string()
                    } else {
                        "Static/IPAM".to_string()
                    };

                    // Create the Askama template context
                    let context = MachineDetailsTemplate {
                        machine_json, // Pass JSON string
                        theme,
                        is_authenticated,
                        created_at_formatted,
                        updated_at_formatted,
                        workflow_info_json, // Pass JSON string
                        machine: machine.clone(), // Pass original struct too
                        workflow_info, // Pass original option too
                        current_path,
                        ip_address_type, // Pass the determined type
                    };
                    // Use render_minijinja
                    return render_minijinja(&app_state, "machine_details.html", context);
                } else {
                    // Machine not found in demo mode, show error using MiniJinja
                    let context = ErrorTemplate {
                        theme,
                        is_authenticated,
                        title: "Demo Machine Not Found".to_string(),
                        message: "The requested demo machine was not found.".to_string(),
                        error_details: format!("UUID: {}", uuid),
                        back_url: "/machines".to_string(),
                        back_text: "Back to Machines".to_string(),
                        show_retry: false,
                        retry_url: "".to_string(),
                        current_path,
                    };
                    // Use render_minijinja
                    return render_minijinja(&app_state, "error.html", context);
                }
            }
            
            // Normal mode - get machine by ID from v1 Store (ReDB with UUIDv7)
            let machine_result: Result<Option<Machine>, anyhow::Error> = match app_state.store.get_machine(uuid).await {
                Ok(Some(m)) => Ok(Some(machine_to_common(&m))),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow::anyhow!("Store error: {}", e)),
            };

            match machine_result {
                Ok(Some(machine)) => {
                    info!("Rendering machine details page for machine {}", uuid);
                    
                    // Format dates before constructing the template
                    let created_at_formatted = machine.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    let updated_at_formatted = machine.updated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    
                    // Workflow information stub (Tinkerbell removed - using our own provisioning)
                    let workflow_info: Option<WorkflowInfo> = None;
                    
                    // Serialize machine and workflow_info to JSON strings
                    let machine_json = serde_json::to_string(&machine)
                        .unwrap_or_else(|e| {
                            error!("Failed to serialize machine {} to JSON: {}", machine.id, e);
                            "{}".to_string() // Default to empty JSON object on error
                        });
                    // ADD DEBUG LOG
                    info!("Serialized machine JSON for {}: {}", machine.id, machine_json);
                    
                    let workflow_info_json = serde_json::to_string(&workflow_info)
                        .unwrap_or_else(|e| {
                             error!("Failed to serialize workflow info for machine {} to JSON: {}", machine.id, e);
                             "null".to_string() // Default to JSON null on error
                         });
                    // ADD DEBUG LOG
                    info!("Serialized workflow JSON for {}: {}", machine.id, workflow_info_json);                         

                    // Determine IP address type
                    let ip_address_type = if machine.ip_address.is_empty() || 
                                                machine.ip_address == "0.0.0.0" {
                        "DHCP".to_string()
                    } else {
                        "Static/IPAM".to_string()
                    };

                    // Create the Askama template context
                    let context = MachineDetailsTemplate {
                        machine_json, // Pass JSON string
                        theme,
                        is_authenticated,
                        created_at_formatted,
                        updated_at_formatted,
                        workflow_info_json, // Pass JSON string
                        machine: machine.clone(), // Pass original struct too
                        workflow_info, // Pass original option too
                        current_path,
                        ip_address_type, // Pass the determined type
                    };
                    // Use render_minijinja
                    return render_minijinja(&app_state, "machine_details.html", context);
                },
                Ok(None) => {
                    error!("Machine not found: {}", uuid);
                    let context = ErrorTemplate {
                        theme,
                        is_authenticated,
                        title: "Machine Not Found".to_string(),
                        message: "The requested machine could not be found.".to_string(),
                        error_details: format!("UUID: {}", uuid),
                        back_url: "/machines".to_string(),
                        back_text: "Back to Machines".to_string(),
                        show_retry: false,
                        retry_url: "".to_string(),
                        current_path,
                    };
                    render_minijinja(&app_state, "error.html", context)
                },
                Err(e) => {
                    error!("Database error fetching machine {}: {}", uuid, e);
                    let context = ErrorTemplate {
                        theme,
                        is_authenticated,
                        title: "Database Error".to_string(),
                        message: "An error occurred while fetching the machine from the database.".to_string(),
                        error_details: format!("Error: {}", e),
                        back_url: "/machines".to_string(),
                        back_text: "Back to Machines".to_string(),
                        show_retry: true,
                        retry_url: format!("/machines/{}", uuid),
                        current_path,
                    };
                    render_minijinja(&app_state, "error.html", context)
                }
            }
        },
        Err(e) => {
            error!("Invalid UUID: {}", e);
            // Use MiniJinja for error template
            let context = ErrorTemplate { // Use ErrorTemplate
                theme,
                is_authenticated,
                title: "Invalid Request".to_string(),
                message: "The provided machine ID was not a valid format.".to_string(),
                error_details: format!("Invalid UUID: {}", id),
                back_url: "/machines".to_string(),
                back_text: "Back to Machines".to_string(),
                show_retry: false,
                retry_url: "".to_string(),
                current_path,
            };
            render_minijinja(&app_state, "error.html", context) // Render error template
        }
    }
}

// Handler for theme toggling
pub async fn toggle_theme(
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // Get theme from URL parameters, default to "light"
    let theme = params.get("theme").cloned().unwrap_or_else(|| "light".to_string());
    
    // Create cookie with proper builder pattern
    let mut cookie = Cookie::new("dragonfly_theme", theme);
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::days(365));
    cookie.set_same_site(SameSite::Lax);
    
    // Get the return URL from parameters or default to home page
    let return_to = params.get("return_to").cloned().unwrap_or_else(|| "/".to_string());
    
    // Set cookie header and redirect
    (
        [(header::SET_COOKIE, cookie.to_string())],
        Redirect::to(&return_to)
    ).into_response()
}

// Handler for the settings page
pub async fn settings_page(
    State(app_state): State<crate::AppState>,
    auth_session: AuthSession,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    // Get current theme from cookie
    let theme = get_theme_from_cookie(&headers);
    
    // Check if user is authenticated
    let is_authenticated = auth_session.user.is_some();
    let current_path = uri.path().to_string();
    
    // Get current settings from ReDB
    let store = &app_state.store;
    let require_login = store.get_setting("require_login").await
        .ok().flatten()
        .map(|v| v == "true")
        .unwrap_or(true); // default to requiring login
    let default_os = store.get_setting("default_os").await
        .ok().flatten();

    info!("Settings page: default_os from ReDB = {:?}", default_os);
    
    // If require_login is enabled and user is not authenticated,
    // redirect to login page
    if require_login && !is_authenticated {
        return Redirect::to("/login").into_response();
    }
    
    let show_admin_settings = is_authenticated;
    
    // Correctly access the username from the AdminUser struct within the Option
    let admin_username = match &auth_session.user {
        Some(user) => user.username.clone(),
        None => "(Not logged in)".to_string(),
    };
    
    // Check if initial password file exists (only for admins)
    let (has_initial_password, rendered_password) = if is_authenticated {
        info!("Checking for initial password file at: initial_password.txt");
        let current_dir = match std::env::current_dir() {
            Ok(dir) => dir.display().to_string(),
            Err(_) => "unknown".to_string(),
        };
        info!("Current directory: {}", current_dir);
        
        match fs::read_to_string("/var/lib/dragonfly/initial_password.txt") {
            Ok(password) => {
                info!("Found initial password file, will display to admin");
                (true, password)
            },
            Err(e) => {
                info!("No initial password file found: {}", e);
                (false, String::new())
            }
        }
    } else {
        (false, String::new())
    };
    
    // Replace Askama render with placeholder
    let context = SettingsTemplate {
        theme,
        is_authenticated,
        admin_username,
        require_login,
        default_os_none: default_os.is_none(),
        default_os_ubuntu2204: default_os.as_deref() == Some("ubuntu-2204"),
        default_os_ubuntu2404: default_os.as_deref() == Some("ubuntu-2404"),
        default_os_debian12: default_os.as_deref() == Some("debian-12"),
        default_os_debian13: default_os.as_deref() == Some("debian-13"),
        default_os_proxmox: default_os.as_deref() == Some("proxmox"),
        has_initial_password,
        rendered_password,
        show_admin_settings,
        error_message: None,
        current_path,
    };
    // Pass AppState to render_minijinja
    render_minijinja(&app_state, "settings.html", context)
}

#[derive(serde::Deserialize, Default)]
pub struct SettingsForm {
    #[serde(default)]
    pub theme: Option<String>,
    pub require_login: Option<String>,
    pub default_os: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_confirm: Option<String>,
    pub setup_completed: Option<String>,
    pub admin_email: Option<String>,
    pub oauth_enabled: Option<String>,
    pub oauth_provider: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub proxmox_host: Option<String>,
    pub proxmox_username: Option<String>,
    pub proxmox_password: Option<String>,
    pub proxmox_port: Option<String>,
}

// Handler for settings form submission
#[axum::debug_handler]
pub async fn update_settings(
    State(app_state): State<crate::AppState>,
    mut auth_session: AuthSession,
    uri: OriginalUri,
    headers: axum::http::HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Response {
    let is_authenticated = auth_session.user.is_some();
    // Get theme from form, or fall back to cookie, or default to "system"
    let theme = form.theme.clone().unwrap_or_else(|| {
        headers.get(axum::http::header::COOKIE)
            .and_then(|c| c.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';')
                    .find(|c| c.trim().starts_with("dragonfly_theme="))
                    .map(|c| c.trim().trim_start_matches("dragonfly_theme=").to_string())
            })
            .unwrap_or_else(|| "system".to_string())
    });
    let current_path = uri.path().to_string();

    // Only require admin authentication for admin settings
    // If trying to change admin settings but not authenticated, redirect to login
    if (form.require_login.is_some() || 
        form.default_os.is_some() || 
        form.username.is_some() || 
        form.password.is_some() || 
        form.password_confirm.is_some() ||
        form.setup_completed.is_some() ||
        form.admin_email.is_some() ||
        form.oauth_provider.is_some() ||
        form.oauth_client_id.is_some() ||
        form.oauth_client_secret.is_some() ||
        form.proxmox_host.is_some() ||
        form.proxmox_username.is_some() ||
        form.proxmox_password.is_some() ||
        form.proxmox_port.is_some()) && !is_authenticated {
        return Redirect::to("/login").into_response();
    }

    // Only update admin settings if user is authenticated
    if is_authenticated {
        let store = &app_state.store;

        // Load current settings from ReDB
        let current_setup_completed = store.get_setting("setup_completed").await
            .ok().flatten()
            .map(|v| v == "true")
            .unwrap_or(false);

        // Construct the new settings
        let settings = Settings {
            require_login: form.require_login.is_some(),
            default_os: form.default_os.as_ref().filter(|os| !os.is_empty()).cloned(),
            setup_completed: form.setup_completed.is_some() || current_setup_completed,
            admin_username: form.username.clone().unwrap_or_else(|| "admin".to_string()),
            admin_password_hash: String::new(), // Password handled separately
            admin_email: form.admin_email.clone().unwrap_or_default(),
            oauth_enabled: form.oauth_enabled.is_some(),
            oauth_provider: form.oauth_provider.clone(),
            oauth_client_id: form.oauth_client_id.clone(),
            oauth_client_secret: form.oauth_client_secret.clone(),
            proxmox_host: None,
            proxmox_username: None,
            proxmox_password: None,
            proxmox_port: None,
            proxmox_skip_tls_verify: None,
        };

        info!("Saving settings: require_login={}, default_os={:?}, setup_completed={:?}",
              settings.require_login, settings.default_os, settings.setup_completed);

        // Save settings to ReDB store
        let store = &app_state.store;

        if let Err(e) = store.put_setting("require_login", &settings.require_login.to_string()).await {
            error!("Failed to save require_login: {}", e);
        }

        if let Some(ref os) = settings.default_os {
            if let Err(e) = store.put_setting("default_os", os).await {
                error!("Failed to save default_os: {}", e);
            }
        } else {
            // Clear default_os if set to None
            let _ = store.delete_setting("default_os").await;
        }

        if let Err(e) = store.put_setting("setup_completed", &settings.setup_completed.to_string()).await {
            error!("Failed to save setup_completed: {}", e);
        }

        info!("Settings saved to ReDB store.");

        // Update admin password if provided and confirmed
        // Check form.password instead of form.password
        if let (Some(password), Some(confirm)) = (&form.password, &form.password_confirm) {
            if !password.is_empty() && password == confirm {
                // Load current credentials to get username (or use default 'admin')
                let username = match auth::load_credentials(&app_state.store).await {
                    Ok(creds) => creds.username,
                    Err(_) => {
                        warn!("Could not load current credentials, defaulting username to 'admin' for password change.");
                        "admin".to_string()
                    }
                };

                // Hash the new password
                match Credentials::create(username, password.clone()) {
                    Ok(new_creds) => {
                        if let Err(e) = auth::save_credentials(&app_state.store, &new_creds).await {
                            error!("Failed to save new admin password: {}", e);
                            // Prepare error message and template for display
                            let error_message = Some(format!("Failed to save credentials: {}", e));
                            
                            // Get current settings for template
                            let admin_username = settings.admin_username.clone();
                            let require_login = settings.require_login;
                            let default_os = settings.default_os.clone();
                            
                            // These fields are not in Settings, use defaults
                            let has_initial_password = false;
                            let rendered_password = "".to_string();
                            let show_admin_settings = is_authenticated;
                            
                            // Create template with error message
                            let context = SettingsTemplate {
                                theme: theme.clone(),
                                is_authenticated,
                                admin_username,
                                require_login,
                                default_os_none: default_os.is_none(),
                                default_os_ubuntu2204: default_os.as_deref() == Some("ubuntu-2204"),
                                default_os_ubuntu2404: default_os.as_deref() == Some("ubuntu-2404"),
                                default_os_debian12: default_os.as_deref() == Some("debian-12"),
                                default_os_debian13: default_os.as_deref() == Some("debian-13"),
                                default_os_proxmox: default_os.as_deref() == Some("proxmox"),
                                                        has_initial_password,
                                rendered_password,
                                show_admin_settings,
                                error_message,
                                current_path, // Add current_path here
                            };

                            // Return the error template
                            let mut cookie = Cookie::new("dragonfly_theme", theme.clone());
                            cookie.set_path("/");
                            cookie.set_max_age(time::Duration::days(365));
                            cookie.set_same_site(SameSite::Lax);

                            return (
                                [(header::SET_COOKIE, cookie.to_string())],
                                render_minijinja(&app_state, "settings.html", context)
                            ).into_response();
                        } else {
                            // Password updated successfully, delete initial password file if it exists
                            if std::path::Path::new("/var/lib/dragonfly/initial_password.txt").exists() {
                                if let Err(e) = std::fs::remove_file("/var/lib/dragonfly/initial_password.txt") {
                                    warn!("Failed to remove initial_password.txt: {}", e);
                                }
                            }
                            // Force logout after password change
                            let _ = auth_session.logout().await;
                            return Redirect::to("/login?message=password_updated").into_response();
                        }
                    }
                    Err(e) => {
                        error!("Failed to hash new password: {}", e);
                        // Prepare error message and template for display
                        let error_message = Some(format!("Failed to hash password: {}", e));
                        
                        // Get current settings for template
                        let admin_username = settings.admin_username.clone();
                        let require_login = settings.require_login;
                        let default_os = settings.default_os.clone();
                        
                        // These fields are not in Settings, use defaults
                        let has_initial_password = false;
                        let rendered_password = "".to_string();
                        let show_admin_settings = is_authenticated;
                        
                        // Create template with error message
                        let context = SettingsTemplate {
                            theme: theme.clone(),
                            is_authenticated,
                            admin_username,
                            require_login,
                            default_os_none: default_os.is_none(),
                            default_os_ubuntu2204: default_os.as_deref() == Some("ubuntu-2204"),
                            default_os_ubuntu2404: default_os.as_deref() == Some("ubuntu-2404"),
                            default_os_debian12: default_os.as_deref() == Some("debian-12"),
                            default_os_debian13: default_os.as_deref() == Some("debian-13"),
                            default_os_proxmox: default_os.as_deref() == Some("proxmox"),
                                                has_initial_password,
                            rendered_password,
                            show_admin_settings,
                            error_message,
                            current_path, // Add current_path here
                        };

                        // Return the error template
                        let mut cookie = Cookie::new("dragonfly_theme", theme.clone());
                        cookie.set_path("/");
                        cookie.set_max_age(time::Duration::days(365));
                        cookie.set_same_site(SameSite::Lax);

                        return (
                            [(header::SET_COOKIE, cookie.to_string())],
                            render_minijinja(&app_state, "settings.html", context)
                        ).into_response();
                    }
                }
            }
        }

        // Check form password and confirm (moving this out of previous if-let block to fix scope)
        if form.password.is_some() || form.password_confirm.is_some() {
            let password = form.password.as_deref().unwrap_or("");
            let confirm = form.password_confirm.as_deref().unwrap_or("");
            
            if (!password.is_empty() || !confirm.is_empty()) && password != confirm {
                // Passwords provided but don't match
                error!("Password mismatch in settings form");
                // Prepare error message and template for display
                let error_message = Some("Passwords do not match.".to_string());
                
                // Get current settings for template
                let admin_username = settings.admin_username.clone();
                let require_login = settings.require_login;
                let default_os = settings.default_os.clone();
                
                // These fields are not in Settings, use defaults
                let has_initial_password = false;
                let rendered_password = "".to_string();
                let show_admin_settings = is_authenticated;
                
                // Create template with error message
                let context = SettingsTemplate {
                    theme: theme.clone(),
                    is_authenticated,
                    admin_username,
                    require_login,
                    default_os_none: default_os.is_none(),
                    default_os_ubuntu2204: default_os.as_deref() == Some("ubuntu-2204"),
                    default_os_ubuntu2404: default_os.as_deref() == Some("ubuntu-2404"),
                    default_os_debian12: default_os.as_deref() == Some("debian-12"),
                    default_os_debian13: default_os.as_deref() == Some("debian-13"),
                    default_os_proxmox: default_os.as_deref() == Some("proxmox"),
                                has_initial_password,
                    rendered_password,
                    show_admin_settings,
                    error_message,
                    current_path, // Make sure current_path is passed here
                };

                // Return the error template
                let mut cookie = Cookie::new("dragonfly_theme", theme.clone());
                cookie.set_path("/");
                cookie.set_max_age(time::Duration::days(365));
                cookie.set_same_site(SameSite::Lax);

                return (
                    [(header::SET_COOKIE, cookie.to_string())],
                    render_minijinja(&app_state, "settings.html", context)
                ).into_response();
            }
        }
    }

    // Theme can be updated by all users (even non-authenticated)
    // Create cookie with proper builder pattern
    let mut cookie = Cookie::new("dragonfly_theme", theme);
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::days(365));
    cookie.set_same_site(SameSite::Lax);
    
    // Set cookie header and redirect back to settings page
    (
        [(header::SET_COOKIE, cookie.to_string())],
        Redirect::to("/settings")
    ).into_response()
}

// Environment setup for MiniJinja
pub fn setup_minijinja_environment(env: &mut minijinja::Environment) -> Result<(), anyhow::Error> {
    // Add OS name formatter - handles null/None values gracefully
    env.add_filter("format_os", |value: minijinja::Value| -> String {
        match value.as_str() {
            Some(os) if !os.is_empty() => format_os_name(os),
            _ => "No OS yet".to_string(),
        }
    });

    // Add OS icon formatter - handles null/None values gracefully
    env.add_filter("format_os_icon", |value: minijinja::Value| -> String {
        match value.as_str() {
            Some(os) if !os.is_empty() => get_os_icon(os),
            _ => String::new(),
        }
    });

    // Add combined OS info formatter that returns a serializable struct
    env.add_filter("get_os_info", |value: minijinja::Value| -> minijinja::Value {
        match value.as_str() {
            Some(os) => {
                let info = get_os_info(os);
                minijinja::value::Value::from_serialize(&info)
            },
            None => minijinja::Value::UNDEFINED,
        }
    });
    
    // Register datetime formatting filter
    env.add_filter("datetime_format", |args: &[minijinja::Value]| -> Result<String, minijinja::Error> {
        if args.len() < 2 {
            return Err(minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "datetime_format requires a datetime and format string"
            ));
        }
        
        // Extract the datetime from the first argument
        let dt_str = args[0].as_str().ok_or_else(|| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "datetime must be a string in ISO format"
            )
        })?;
        
        // Parse the datetime
        let dt = match chrono::DateTime::parse_from_rfc3339(dt_str) {
            Ok(dt) => dt.with_timezone(&chrono::Utc),
            Err(_) => {
                return Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    "could not parse datetime string"
                ));
            }
        };
        
        // Extract the format string
        let fmt = args[1].as_str().ok_or_else(|| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "format must be a string"
            )
        })?;
        
        // Format the datetime
        Ok(dt.format(fmt).to_string())
    });
    
    // Set up more configuration as needed
    env.add_global("now", minijinja::Value::from(chrono::Utc::now().to_rfc3339()));
    
    // Add custom filter for robust JSON serialization
    env.add_filter("to_json", |value: minijinja::Value| -> Result<String, minijinja::Error> {
        match serde_json::to_string(&value) {
            Ok(s) => Ok(s),
            Err(e) => Err(minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                format!("Failed to serialize value to JSON: {}", e)
            )),
        }
    });
    
    Ok(())
}

// ---- Alert Messages ----

#[derive(Serialize, Debug, Clone)]
pub struct AlertMessage {
    level: String, // e.g., "success", "error", "info", "warning"
    message: String,
}

impl AlertMessage {
    pub fn success(message: &str) -> Self {
        AlertMessage { level: "success".to_string(), message: message.to_string() }
    }
    pub fn error(message: &str) -> Self {
        AlertMessage { level: "error".to_string(), message: message.to_string() }
    }
    // Add info and warning if needed
}

// Trait to add alert messages to responses (e.g., via cookies)
pub trait AddAlert {
    fn add_alert(self, alert: AlertMessage) -> Self;
}

impl AddAlert for Response {
    fn add_alert(mut self, alert: AlertMessage) -> Self {
        match serde_json::to_string(&alert) {
            Ok(json_alert) => {
                // Use Cookie builder for better configuration
                let cookie = cookie::Cookie::build(("dragonfly_alert", json_alert))
                    .path("/")
                    .http_only(true)
                    .secure(false) // Set to true in production with HTTPS
                    .same_site(cookie::SameSite::Lax);
                    // .finish(); // Removed deprecated finish

                // The CookieBuilder itself can often be used directly
                self.headers_mut().insert(
                    axum::http::header::SET_COOKIE,
                    // Use build() to get the final Cookie if needed, or pass builder directly if allowed
                    cookie.build().to_string().parse().unwrap(), 
                );
            }
            Err(e) => {
                error!("Failed to serialize alert message: {}", e);
                // Optionally add a fallback mechanism or just log the error
            }
        }
        self
    }
}

pub async fn compute_page(
    State(app_state): State<AppState>,
    auth_session: AuthSession,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    let theme = get_theme_from_cookie(&headers);
    let is_authenticated = auth_session.user.is_some();
    let is_admin = is_authenticated;
    let current_path = uri.path().to_string();

    let require_login = app_state.store.get_setting("require_login").await.ok().flatten().map(|v| v == "true").unwrap_or(true);

    // Login check
    if require_login && !is_authenticated {
        info!("Login required for /compute, redirecting to /login");
        let mut response = Redirect::to("/login").into_response();
        response.headers_mut().insert("HX-Redirect", "/login".parse().unwrap());
        return response;
    }

    // Fetch all machines from the v1 Store
    let all_machines: Vec<Machine> = match app_state.store.list_machines().await {
        Ok(v1_machines) => v1_machines.iter().map(|m| crate::store::conversions::machine_to_common(m)).collect(),
        Err(e) => {
            error!("Error fetching machines for compute page: {}", e);
            // Optionally render an error page or return an empty list
            vec![]
        }
    };

    // Group machines by Proxmox CLUSTER name
    let mut clusters_map: HashMap<String, Vec<Machine>> = HashMap::new();
    let mut standalone_machines: Vec<Machine> = Vec::new();

    for machine in all_machines {
        // Group by proxmox_cluster if it exists
        if let Some(cluster_name) = &machine.proxmox_cluster {
            if !cluster_name.is_empty() { // Avoid grouping under empty string
                 clusters_map.entry(cluster_name.clone()).or_default().push(machine);
            } else {
                 // Treat machines with empty cluster name but node/vmid as standalone for now
                 warn!("Machine {} has Proxmox info but an empty cluster name.", machine.id);
                 standalone_machines.push(machine);
            }
        } else {
            // Machines without a proxmox_cluster field are treated as standalone
            standalone_machines.push(machine);
        }
    }

    // Convert the map into the Vec<ProxmoxCluster> structure for the template
    let clusters: Vec<ProxmoxCluster> = clusters_map.into_iter()
        .map(|(cluster_name, machines_in_cluster)| {
            // Separate hosts and VMs
            let mut hosts: Vec<Machine> = Vec::new();
            let mut vms: Vec<Machine> = Vec::new();
            for machine in machines_in_cluster {
                if machine.is_proxmox_host {
                    hosts.push(machine);
                } else {
                    vms.push(machine);
                }
            }
            
            // Determine the display name for the cluster group
            // Prioritize the hostname of the first host found, fallback to cluster name
            let display_name = hosts.first()
                .and_then(|h| h.hostname.as_deref().or(h.proxmox_node.as_deref())) // Use hostname or node name of first host
                .unwrap_or(&cluster_name) // Fallback to the cluster name itself if no hosts found (unlikely)
                .to_string();

            ProxmoxCluster {
                display_name, // Use the determined display name
                cluster_name: Some(cluster_name.clone()), // The actual cluster identifier
                hosts, // List of hosts in this cluster
                vms, // List of VMs in this cluster
            }
        })
        .collect();

    // Log standalone machines
    if !standalone_machines.is_empty() {
        warn!("Found {} standalone/unassociated machines not displayed on the Compute page.", standalone_machines.len());
        // TODO: Decide how/if to display standalone machines on this page
    }

    let context = ComputeTemplate {
        theme,
        is_authenticated,
        is_admin,
        clusters, // Now grouped by actual cluster name
        current_path,
    };

    render_minijinja(&app_state, "compute.html", context)
}

// Handler for the tags page
pub async fn tags_page(
    State(app_state): State<crate::AppState>,
    headers: HeaderMap,
    auth_session: AuthSession,
    uri: OriginalUri,
) -> Response {
    // Get theme preference from cookie
    let theme = get_theme_from_cookie(&headers);
    let is_authenticated = auth_session.user.is_some();
    let current_path = uri.path().to_string();

    // Check if user is authenticated if login is required
    let require_login = app_state.store.get_setting("require_login").await.ok().flatten().map(|v| v == "true").unwrap_or(true);
    if require_login && !is_authenticated && !app_state.is_demo_mode {
        return Redirect::to("/login").into_response();
    }

    // Fetch all machines from the v1 Store to display in the tag editor
    let machines: Vec<Machine> = match app_state.store.list_machines().await {
        Ok(v1_machines) => v1_machines.iter().map(|m| crate::store::conversions::machine_to_common(m)).collect(),
        Err(e) => {
            error!("Failed to fetch machines for tags page: {}", e);
            vec![]
        }
    };
    
    // Create template context
    let context = serde_json::json!({
        "theme": theme,
        "is_authenticated": is_authenticated,
        "current_path": current_path,
        "machines": machines,
        "is_admin": auth_session.user.is_some(),
    });
    
    // Render the tags page template
    render_minijinja(&app_state, "tags.html", context)
}
