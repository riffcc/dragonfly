use crate::AppState;
use crate::auth::AuthSession;
use crate::provisioning::HardwareCheckIn;
use crate::store::conversions::{machine_to_common, revert_pending_changes};
use crate::ui; // Import the ui module
use crate::{INSTALL_STATE_REF, InstallationState};
use axum::body::{Body, Bytes};
use axum::extract::DefaultBodyLimit;
use axum::{
    Router,
    extract::{ConnectInfo, Form, FromRequest, Json, Path, Query, State},
    http::{HeaderMap, StatusCode, header::HeaderValue},
    response::{
        Html, IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{delete, get, post, put},
};
use dragonfly_common::Error;
use dragonfly_common::models::{
    BmcCredentialsUpdateRequest, HostnameUpdateRequest, HostnameUpdateResponse,
    InstallationProgressUpdateRequest, Machine, MachineStatus, OsInstalledUpdateRequest,
    OsInstalledUpdateResponse, RegisterRequest, StatusUpdateRequest,
};
use dragonfly_common::models::{ErrorResponse, OsAssignmentRequest};
use futures::StreamExt; // For .next() on stream
use futures::stream;
use http_body::Frame;
use http_body_util::{Empty, StreamBody};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::path::Path as FilePath;
use std::path::Path as StdPath;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};
use url::Url;
use uuid::Uuid;

pub fn api_router() -> Router<crate::AppState> {
    // Core API routes
    Router::new()
        .route("/machines", get(get_all_machines).post(register_machine))
        .route("/machines/install-status", get(get_install_status))
        .route("/machines/{id}/os", get(get_machine_os).post(assign_os))
        .route("/machines/{id}/reimage", post(reimage_machine)) // Add new reimage endpoint
        .route("/machines/{id}/abort-reimage", post(abort_reimage)) // Cancel pending reimage
        .route(
            "/machines/{id}/hostname",
            get(get_hostname_form).put(update_hostname),
        )
        .route("/machines/{id}/status", put(update_status))
        .route(
            "/machines/{id}/status-and-progress",
            get(get_machine_status_and_progress_partial),
        )
        .route("/machines/{id}/os-installed", put(update_os_installed))
        .route("/machines/{id}/bmc", post(update_bmc))
        // Add route for BMC power actions
        .route(
            "/machines/{id}/bmc/power-action",
            post(crate::handlers::machines::bmc_power_action_handler),
        )
        .route(
            "/machines/{id}/workflow-progress",
            get(get_workflow_progress),
        )
        .route(
            "/machines/{id}/tags",
            get(api_get_machine_tags).put(api_update_machine_tags),
        )
        .route("/machines/{id}/tags/{tag}", delete(api_delete_machine_tag))
        .route(
            "/machines/{id}",
            get(get_machine)
                .put(update_machine)
                .patch(patch_machine)
                .delete(delete_machine),
        )
        .route("/installation/progress", put(update_installation_progress))
        .route("/events", get(machine_events))
        .route("/heartbeat", get(heartbeat))
        // --- Proxmox Routes ---
        .route("/proxmox/status", get(proxmox_status))
        .route(
            "/proxmox/connect",
            post(crate::handlers::proxmox::connect_proxmox_handler),
        )
        .route(
            "/proxmox/discover",
            get(crate::handlers::proxmox::discover_proxmox_handler),
        )
        .route("/proxmox/token", post(update_proxmox_token))
        .route(
            "/proxmox/create-tokens",
            post(crate::handlers::proxmox::create_proxmox_tokens_handler),
        )
        // Add new tag management routes
        .route("/tags", get(api_get_tags).post(api_create_tag))
        .route("/tags/{tag_name}", delete(api_delete_tag))
        .route("/tags/{tag_name}/machines", get(api_get_machines_by_tag))
        // --- Agent Routes ---
        .route("/agent/checkin", post(agent_checkin_handler))
        .route(
            "/agent/request-install",
            post(agent_request_install_handler),
        )
        .route("/agent/remove", post(agent_remove_handler))
        .route("/agent/boot-mode", post(agent_boot_mode_handler))
        .route("/agent/isos", get(agent_list_isos_handler))
        // --- ISO Management Routes ---
        .route("/isos", get(list_isos_handler))
        .route(
            "/isos/upload",
            post(upload_iso_handler).layer(DefaultBodyLimit::disable()),
        ) // No body limit for ISO uploads (streamed to disk)
        .route("/isos/{filename}", delete(delete_iso_handler))
        // --- Settings Routes ---
        .route("/settings", get(api_get_settings).put(api_update_settings))
        .route("/settings/mode", get(api_get_mode).put(api_set_mode))
        // --- User Management Routes ---
        .route("/users", get(api_get_users).post(api_create_user))
        .route(
            "/users/{id}",
            get(api_get_user)
                .put(api_update_user)
                .delete(api_delete_user),
        )
        // --- SSH Key Import ---
        .route("/fetch-keys", get(api_fetch_keys))
        // --- Workflow Routes (for agent) ---
        .route("/workflows/{id}", get(get_workflow_handler))
        .route("/workflows/{id}/events", post(workflow_events_handler))
        .route("/templates/{name}", get(get_template_handler))
        // --- Template Management Routes ---
        .route("/templates", get(list_templates_handler))
        .route("/templates/{name}/toggle", post(toggle_template_handler))
        .route(
            "/templates/{name}/content",
            get(get_template_content_handler).put(update_template_content_handler),
        )
        // --- Network Routes ---
        .route(
            "/networks",
            get(list_networks_handler).post(create_network_handler),
        )
        .route(
            "/networks/{id}",
            get(get_network_handler)
                .put(update_network_handler)
                .delete(delete_network_handler),
        )
        // --- DHCP Lease Routes ---
        .route("/dhcp/leases", get(list_dhcp_leases_handler))
        .route(
            "/dhcp/leases/{mac}",
            delete(terminate_dhcp_lease_handler),
        )
        // --- Machine Apply Route ---
        .route("/machines/{id}/apply", post(apply_machine_config_handler))
        .route(
            "/machines/{id}/proxmox/apply-config",
            post(apply_proxmox_config),
        )
        .route(
            "/machines/{id}/revert-pending",
            post(revert_pending_handler),
        )
        // --- DNS Routes ---
        .route("/dns/zones", get(dns_list_zones_handler))
        .route(
            "/dns/zones/{zone}/records",
            get(dns_list_records_handler).post(dns_create_record_handler),
        )
        .route(
            "/dns/zones/{zone}/records/{id}",
            put(dns_update_record_handler).delete(dns_delete_record_handler),
        )
        .route("/dns/records/by-machine/{machine_id}", get(dns_records_by_machine_handler))
        // --- Unified Credentials Routes ---
        .route("/credentials", get(credentials_list_handler))
        .route("/credentials/add", post(credentials_add_handler))
        .route("/credentials/{id}/rotate", post(credentials_rotate_handler))
        .route("/credentials/{id}", delete(credentials_delete_handler))
        // --- High Availability Routes ---
        .route("/ha/status", get(ha_status_handler))
        .route("/ha/enable", post(ha_enable_handler))
        .route("/ha/disable", post(ha_disable_handler))
        // --- Cluster Deployment Routes ---
        .route("/cluster/create", post(cluster_create_handler))
        .route("/cluster/abort", post(cluster_abort_handler))
        .route("/cluster/status", get(cluster_status_handler))
        .route("/cluster/management-key", get(cluster_management_key_handler))
        .route("/cluster/management-key/rotate", post(cluster_rotate_key_handler))
        // --- Maintenance Routes ---
        .route("/maintenance/dev-mode", get(dev_mode_status_handler).post(dev_mode_toggle_handler))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 50)) // 50 MB
}

// Content constants
const HOSTS_CONTENT: &str = r#"127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
"#;

const HOSTNAME_CONTENT: &str = "localhost";
const APK_ARCH_CONTENT: &str = "x86_64"; // Assuming amd64/x86_64 for now
const LBU_LIST_CONTENT: &str = "+usr/local";
const REPOSITORIES_CONTENT: &str = r#"https://dl-cdn.alpinelinux.org/alpine/v3.23/main
https://dl-cdn.alpinelinux.org/alpine/v3.23/community
"#;
const WORLD_CONTENT: &str = r#"alpine-baselayout
alpine-conf
alpine-keys
alpine-release
apk-tools
busybox
libc-utils
kexec-tools
libgcc
wget
util-linux
"#;

/// Source for the dragonfly-agent binary in the APK overlay
pub enum AgentSource<'a> {
    /// Download from a URL
    Url(&'a str),
    /// Copy from a local filesystem path
    LocalPath(&'a StdPath),
}

/// Generates the localhost.apkovl.tar.gz file needed by the Dragonfly Agent iPXE script.
pub async fn generate_agent_apkovl(
    target_apkovl_path: &StdPath,
    base_url: &str,
    agent_source: AgentSource<'_>,
) -> Result<(), dragonfly_common::Error> {
    info!("Generating agent APK overlay at: {:?}", target_apkovl_path);

    // 1. Create a temporary directory
    let temp_dir = tempdir().map_err(|e| {
        dragonfly_common::Error::Internal(format!(
            "Failed to create temp directory for apkovl: {}",
            e
        ))
    })?;
    let temp_path = temp_dir.path();
    info!("Building apkovl structure in: {:?}", temp_path);

    // 2. Create directory structure
    fs::create_dir_all(temp_path.join("etc/local.d"))
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to create dir etc/local.d: {}", e))
        })?;
    fs::create_dir_all(temp_path.join("etc/apk/protected_paths.d"))
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!(
                "Failed to create dir etc/apk/protected_paths.d: {}",
                e
            ))
        })?;
    fs::create_dir_all(temp_path.join("etc/runlevels/default"))
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!(
                "Failed to create dir etc/runlevels/default: {}",
                e
            ))
        })?;
    fs::create_dir_all(temp_path.join("usr/local/bin"))
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to create dir usr/local/bin: {}", e))
        })?;
    fs::create_dir_all(temp_path.join("var/log/dragonfly"))
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!(
                "Failed to create dir var/log/dragonfly: {}",
                e
            ))
        })?;

    // 3. Write static files
    fs::write(temp_path.join("etc/hosts"), HOSTS_CONTENT)
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to write etc/hosts: {}", e))
        })?;
    fs::write(temp_path.join("etc/hostname"), HOSTNAME_CONTENT)
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to write etc/hostname: {}", e))
        })?;
    fs::write(temp_path.join("etc/apk/arch"), APK_ARCH_CONTENT)
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to write etc/apk/arch: {}", e))
        })?;
    fs::write(
        temp_path.join("etc/apk/protected_paths.d/lbu.list"),
        LBU_LIST_CONTENT,
    )
    .await
    .map_err(|e| dragonfly_common::Error::Internal(format!("Failed to write lbu.list: {}", e)))?;
    fs::write(temp_path.join("etc/apk/repositories"), REPOSITORIES_CONTENT)
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to write repositories: {}", e))
        })?;
    fs::write(temp_path.join("etc/apk/world"), WORLD_CONTENT)
        .await
        .map_err(|e| dragonfly_common::Error::Internal(format!("Failed to write world: {}", e)))?;

    // Create empty mtab needed by Alpine init
    fs::write(temp_path.join("etc/mtab"), "")
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to write etc/mtab: {}", e))
        })?;

    // Create empty .default_boot_services
    fs::write(temp_path.join("etc/.default_boot_services"), "")
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!(
                "Failed to write .default_boot_services: {}",
                e
            ))
        })?;

    // 4. Write agent wrapper script (called by inittab on tty1)
    let wrapper_path = temp_path.join("usr/local/bin/dragonfly-wrapper");
    let wrapper_content = format!(
        r#"#!/bin/sh
# Wrapper for dragonfly-agent - runs on tty1 via inittab for proper terminal access

# Clear screen and show banner
clear
echo "=== Mage: Dragonfly Boot Environment ==="
echo "Server: {}"
echo ""

# Run the agent (exec replaces this shell)
exec /usr/local/bin/dragonfly-agent --server "{}"
"#,
        base_url, base_url
    );
    fs::write(&wrapper_path, wrapper_content)
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to write wrapper script: {}", e))
        })?;
    set_executable_permission(&wrapper_path).await?;

    // 5. Write custom inittab - runs agent on tty1 instead of getty
    let inittab_content = r#"# Dragonfly Mage inittab
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default

# Run dragonfly-agent on tty1 (respawn if it exits)
tty1::respawn:/usr/local/bin/dragonfly-wrapper

# Keep getty on other ttys for emergency access
tty2::respawn:/sbin/getty 38400 tty2
tty3::respawn:/sbin/getty 38400 tty3

::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
"#;
    fs::write(temp_path.join("etc/inittab"), inittab_content)
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to write inittab: {}", e))
        })?;

    // 6. Get the agent binary (download or copy based on source)
    let dest_agent_path = temp_path.join("usr/local/bin/dragonfly-agent");
    match agent_source {
        AgentSource::Url(url) => {
            download_file(url, &dest_agent_path).await?;
        }
        AgentSource::LocalPath(path) => {
            fs::copy(path, &dest_agent_path).await.map_err(|e| {
                dragonfly_common::Error::Internal(format!(
                    "Failed to copy agent binary from {:?}: {}",
                    path, e
                ))
            })?;
        }
    }
    set_executable_permission(&dest_agent_path).await?;

    // 7. Create the tar.gz archive
    info!("Creating tarball: {:?}", target_apkovl_path);
    let output = Command::new("tar")
        .arg("-czf")
        .arg(target_apkovl_path)
        .arg("-C")
        .arg(temp_path)
        .arg(".")
        .output()
        .await
        .map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to execute tar command: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(dragonfly_common::Error::Internal(format!(
            "Tar command failed: {}",
            stderr
        )));
    }

    info!("Successfully generated apkovl: {:?}", target_apkovl_path);
    Ok(())
}

// Helper function to set executable permission (Unix specific)
async fn set_executable_permission(path: &StdPath) -> Result<(), dragonfly_common::Error> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).await.map_err(|e| {
        dragonfly_common::Error::Internal(format!("Failed to get metadata for {:?}: {}", path, e))
    })?;

    let mut perms = metadata.permissions();
    perms.set_mode(0o755); // rwxr-xr-x

    fs::set_permissions(path, perms).await.map_err(|e| {
        dragonfly_common::Error::Internal(format!(
            "Failed to set executable permission on {:?}: {}",
            path, e
        ))
    })
}

// Helper function to download a file from a URL
async fn download_file(url: &str, target_path: &StdPath) -> Result<(), dragonfly_common::Error> {
    info!("Downloading {} to {:?}", url, target_path);

    // Create a reqwest client
    let client = reqwest::Client::new();

    // Send GET request to download the file
    let response = client.get(url).send().await.map_err(|e| {
        dragonfly_common::Error::Internal(format!("Failed to download file from {}: {}", url, e))
    })?;

    // Check if the request was successful
    if !response.status().is_success() {
        return Err(dragonfly_common::Error::Internal(format!(
            "Failed to download file from {}: HTTP status {}",
            url,
            response.status()
        )));
    }

    // Get the file content as bytes
    let bytes = response.bytes().await.map_err(|e| {
        dragonfly_common::Error::Internal(format!(
            "Failed to read response body from {}: {}",
            url, e
        ))
    })?;

    // Create the file and write the content
    fs::write(target_path, bytes).await.map_err(|e| {
        dragonfly_common::Error::Internal(format!(
            "Failed to write downloaded file to {:?}: {}",
            target_path, e
        ))
    })?;

    info!("Successfully downloaded {} to {:?}", url, target_path);
    Ok(())
}

#[axum::debug_handler]
async fn register_machine(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Response {
    use crate::store::conversions::machine_from_register_request;
    use dragonfly_common::models::RegisterResponse;

    info!(
        "Registering machine with MAC: {}, CPU: {:?}, Cores: {:?}, RAM: {:?}",
        payload.mac_address, payload.cpu_model, payload.cpu_cores, payload.total_ram_bytes
    );

    // Check if machine already exists by MAC
    let normalized_mac = dragonfly_common::normalize_mac(&payload.mac_address);
    if let Ok(Some(existing)) = state.store.get_machine_by_mac(&normalized_mac).await {
        // Machine exists - update it instead
        info!("Machine already exists with ID {}, updating", existing.id);
        let mut machine = existing;
        machine.config.hostname = payload.hostname.clone();
        if let Some(cpu) = &payload.cpu_model {
            machine.hardware.cpu_model = Some(cpu.clone());
        }
        if let Some(cores) = payload.cpu_cores {
            machine.hardware.cpu_cores = Some(cores);
        }
        if let Some(ram) = payload.total_ram_bytes {
            machine.hardware.memory_bytes = Some(ram);
        }
        machine.metadata.updated_at = chrono::Utc::now();

        if let Err(e) = state.store.put_machine(&machine).await {
            error!("Failed to update existing machine: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Update Failed".to_string(),
                    message: e.to_string(),
                }),
            )
                .into_response();
        }

        let _ = state
            .event_manager
            .send(format!("machine_updated:{}", machine.id));
        return (
            StatusCode::OK,
            Json(RegisterResponse {
                machine_id: machine.id,
                next_step: "awaiting_os_assignment".to_string(),
            }),
        )
            .into_response();
    }

    // Create new machine from registration request
    let machine = machine_from_register_request(&payload);
    let machine_id = machine.id;

    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine discovered event
            let _ = state
                .event_manager
                .send(format!("machine_discovered:{}", machine_id));

            let response = RegisterResponse {
                machine_id,
                next_step: "awaiting_os_assignment".to_string(),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed to register machine: {}", e);
            let error_response = ErrorResponse {
                error: "Registration Failed".to_string(),
                message: e.to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

#[axum::debug_handler]
async fn get_all_machines(
    State(state): State<crate::AppState>,
    auth_session: AuthSession,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    // Check if this is an HTMX request
    let is_htmx = req.headers().get("HX-Request").is_some();

    // Check if user is authenticated as admin
    let is_admin = auth_session.user.is_some();

    // Query v1 Store (SQLite) for machines
    let machines: Vec<Machine> = match state.store.list_machines().await {
        Ok(machine_list) => machine_list.iter().map(|m| machine_to_common(m)).collect(),
        Err(e) => {
            error!("Failed to list machines from store: {}", e);
            vec![]
        }
    };

    // Workflow info stub (Tinkerbell removed - using our own provisioning)
    let workflow_infos: HashMap<uuid::Uuid, crate::ui::WorkflowInfo> = HashMap::new();

    if is_htmx {
        // For HTMX requests, return HTML table rows
        if machines.is_empty() {
            Html(
                r#"<tr>
                        <td colspan="6" class="px-6 py-8 text-center text-gray-500 italic">
                            No machines added or discovered yet.
                        </td>
                    </tr>"#,
            )
            .into_response()
        } else {
            // Return HTML rows for each machine
            let mut html = String::new();
            for machine in machines {
                let id_string = machine.id.to_string();
                let display_name = machine
                    .hostname
                    .as_ref()
                    .or(machine.memorable_name.as_ref())
                    .map(|s| s.as_str())
                    .unwrap_or(&id_string);

                let secondary_name =
                    if machine.hostname.is_some() && machine.memorable_name.is_some() {
                        machine
                            .memorable_name
                            .as_ref()
                            .map(|s| s.as_str())
                            .unwrap_or("")
                    } else {
                        ""
                    };

                let os_display = match &machine.os_installed {
                    Some(os) => os.clone(),
                    None => {
                        if machine.status.is_installing() {
                            if let Some(os) = &machine.os_choice {
                                format!("🚧 {}", format_os_name(os))
                            } else {
                                "🚀 Installing OS".to_string()
                            }
                        } else if let Some(os) = &machine.os_choice {
                            os.clone()
                        } else {
                            "None".to_string()
                        }
                    }
                };

                // Admin-only buttons (Assign OS, Update Status, Delete)
                let admin_buttons = if is_admin {
                    format!(
                        r#"
                                {}
                                <button
                                    @click="showStatusModal('{}')"
                                    class="px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full bg-blue-500 text-white hover:bg-blue-600"
                                >
                                    Update Status
                                </button>
                                <button
                                    @click="showDeleteModal('{}')"
                                    class="text-red-600 hover:text-red-900"
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </button>
                            "#,
                        // Conditionally include the Assign OS button
                        if machine.status == MachineStatus::Discovered {
                            format!(
                                r#"
                                    <button
                                        @click="showOsModal('{}')"
                                        class="px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
                                    >
                                        Assign OS
                                    </button>
                                "#,
                                machine.id
                            )
                        } else {
                            String::new()
                        },
                        machine.id,
                        machine.id
                    )
                } else {
                    // Empty string when not admin
                    String::new()
                };

                html.push_str(&format!(r#"
                            <tr class="hover:bg-gray-50 dark:hover:bg-gradient-to-r dark:hover:from-gray-800 dark:hover:to-gray-900 dark:hover:bg-opacity-50 dark:hover:backdrop-blur-sm transition-colors duration-150 cursor-pointer" @click="window.location='/machines/{}'">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="text-sm font-medium text-gray-900">
                                        {}
                                    </div>
                                    <div class="text-xs text-gray-500">
                                        {}
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="text-sm text-gray-500 tech-mono">{}</div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="text-sm text-gray-500 tech-mono">{}</div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full {}">
                                        {}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="text-sm text-gray-500">
                                        {}
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                    <div class="flex space-x-3" @click.stop>
                                        {}
                                    </div>
                                </td>
                            </tr>
                        "#,
                        machine.id,
                        display_name,
                        secondary_name,
                        machine.mac_address,
                        machine.ip_address,
                        match machine.status {
                            MachineStatus::Installed => "px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-400/10 dark:text-green-300 dark:border dark:border-green-500/20",
                            MachineStatus::Initializing | MachineStatus::Installing | MachineStatus::Writing => "px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800 dark:bg-yellow-400/10 dark:text-yellow-300 dark:border dark:border-yellow-500/20",
                            MachineStatus::Discovered | MachineStatus::ReadyToInstall => "px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-400/10 dark:text-blue-300 dark:border dark:border-blue-500/20",
                            MachineStatus::ExistingOS => "px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full bg-sky-100 text-sky-800 dark:bg-sky-400/10 dark:text-sky-300 dark:border dark:border-sky-500/20",
                            _ => "px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-400/10 dark:text-red-300 dark:border dark:border-red-500/20"
                        },
                        match &machine.status {
                            MachineStatus::Installed => String::from("Installed"),
                            MachineStatus::Initializing | MachineStatus::Installing | MachineStatus::Writing => String::from("Installing"),
                            MachineStatus::Discovered | MachineStatus::ReadyToInstall => String::from("Discovered"),
                            _ => machine.status.to_string()
                        },
                        os_display,
                        admin_buttons
                        ));
            }
            Html(html).into_response()
        }
    } else {
        // For non-HTMX requests, return JSON
        (StatusCode::OK, Json(machines)).into_response()
    }
}

#[axum::debug_handler]
async fn get_machine(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    match state.store.get_machine(id).await {
        Ok(Some(v1_machine)) => {
            // Convert v1 Machine to common Machine for API response
            let machine = machine_to_common(&v1_machine);

            // Workflow info stub (Tinkerbell removed - using our own provisioning)
            let workflow_info: Option<crate::ui::WorkflowInfo> = None;

            // Create the wrapped JSON response
            let response_data = json!({
                "machine": machine,
                "workflow_info": workflow_info,
            });

            (StatusCode::OK, Json(response_data)).into_response()
        }
        Ok(None) => {
            let error_response = ErrorResponse {
                error: "Not Found".to_string(),
                message: format!("Machine with ID {} not found", id),
            };
            (StatusCode::NOT_FOUND, Json(error_response)).into_response()
        }
        Err(e) => {
            error!("Failed to retrieve machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Database Error".to_string(),
                message: e.to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

// Combined OS assignment handler
#[axum::debug_handler]
async fn assign_os(
    State(app_state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    // Check if user is authenticated as admin
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Admin authentication required for this operation"
            })),
        )
            .into_response();
    }

    // Check content type to determine how to extract the OS choice
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    info!("Content-Type received: {}", content_type);

    let os_choice = if content_type.starts_with("application/json") {
        // Extract JSON
        match axum::Json::<OsAssignmentRequest>::from_request(req, &()).await {
            Ok(Json(payload)) => Some(payload.os_choice),
            Err(e) => {
                error!("Failed to parse JSON request: {}", e);
                None
            }
        }
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        // Extract form data
        match axum::Form::<OsAssignmentRequest>::from_request(req, &()).await {
            Ok(Form(payload)) => Some(payload.os_choice),
            Err(e) => {
                error!("Failed to parse form request: {}", e);
                None
            }
        }
    } else {
        error!("Unsupported content type: {}", content_type);
        None
    };

    match os_choice {
        Some(os_choice) => assign_os_internal(&app_state, id, os_choice).await,
        None => {
            let error_response = ErrorResponse {
                error: "Bad Request".to_string(),
                message: "Failed to extract OS choice from request".to_string(),
            };
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}

// Shared implementation - uses v1 Store (SQLite with UUIDv7)
async fn assign_os_internal(app_state: &AppState, id: Uuid, os_choice: String) -> Response {
    info!("Assigning OS {} to machine {}", os_choice, id);

    // Get machine directly by UUID from v1 store
    let mut machine = match app_state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let error_html = format!(
                r###"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> Machine with ID {} not found.
                </div>
            "###,
                id
            );
            return (
                StatusCode::NOT_FOUND,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                error_html,
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to get machine: {}", e);
            let error_html = format!(
                r###"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> Database error: {}.
                </div>
            "###,
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                error_html,
            )
                .into_response();
        }
    };

    // Update os_choice - empty string means "clear the choice"
    if os_choice.is_empty() {
        machine.config.os_choice = None;
    } else {
        machine.config.os_choice = Some(os_choice.clone());
    }
    machine.metadata.updated_at = chrono::Utc::now();

    // Save back to store
    match app_state.store.put_machine(&machine).await {
        Ok(()) => {
            let html = if os_choice.is_empty() {
                format!(
                    r###"
                <div class="p-4 mb-4 text-sm text-green-700 bg-green-100 rounded-lg" role="alert">
                    <span class="font-medium">Success!</span> OS choice cleared for machine {}. Keeping current OS.
                </div>
                "###,
                    id
                )
            } else {
                format!(
                    r###"
                <div class="p-4 mb-4 text-sm text-green-700 bg-green-100 rounded-lg" role="alert">
                    <span class="font-medium">Success!</span> OS choice set to {} for machine {}.
                    <p>To apply this change, click the "Reimage" button.</p>
                </div>
                "###,
                    os_choice, id
                )
            };

            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                html,
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to save machine: {}", e);
            let error_html = format!(
                r###"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> Database error: {}.
                </div>
            "###,
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                error_html,
            )
                .into_response()
        }
    }
}

#[axum::debug_handler]
async fn update_status(
    State(state): State<AppState>,
    _auth_session: AuthSession,
    Path(id): Path<Uuid>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    // Check content type to determine how to extract the status
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    info!("Content-Type received: {}", content_type);

    let status = if content_type.starts_with("application/json") {
        // Extract JSON
        match axum::Json::<StatusUpdateRequest>::from_request(req, &()).await {
            Ok(Json(payload)) => Some(payload.status),
            Err(e) => {
                error!("Failed to parse JSON request: {}", e);
                None
            }
        }
    } else {
        // Extract form data
        match axum::Form::<std::collections::HashMap<String, String>>::from_request(req, &()).await
        {
            Ok(form) => match form.0.get("status") {
                Some(status_str) => match status_str.as_str() {
                    "Discovered" => Some(MachineStatus::Discovered),
                    "ReadyToInstall" => Some(MachineStatus::ReadyToInstall),
                    "Installed" => Some(MachineStatus::Installed),
                    "Failed" => Some(MachineStatus::Failed("Manual error state".to_string())),
                    "Offline" => Some(MachineStatus::Offline),
                    _ => None,
                },
                None => None,
            },
            Err(e) => {
                error!("Failed to parse form data: {}", e);
                None
            }
        }
    };

    let status = match status {
        Some(s) => s,
        None => {
            return Html(format!(
                r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> Invalid or missing status field.
                </div>
            "#
            ))
            .into_response();
        }
    };

    info!("Updating status for machine {} to {:?}", id, status);

    // Get machine from v1 Store
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Html(format!(
                r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> Machine with ID {} not found.
                </div>
            "#,
                id
            ))
            .into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            return Html(format!(
                r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> Database error: {}.
                </div>
            "#,
                e
            ))
            .into_response();
        }
    };

    // Convert MachineStatus to v1 MachineState
    use dragonfly_common::MachineState;
    machine.status.state = match &status {
        MachineStatus::Discovered => MachineState::Discovered,
        MachineStatus::ReadyToInstall => MachineState::ReadyToInstall,
        MachineStatus::Initializing => MachineState::Initializing,
        MachineStatus::Installing => MachineState::Installing,
        MachineStatus::Writing => MachineState::Writing,
        MachineStatus::Installed => MachineState::Installed,
        MachineStatus::Failed(msg) => MachineState::Failed {
            message: msg.clone(),
        },
        MachineStatus::ExistingOS => MachineState::ExistingOs {
            os_name: "Unknown".to_string(),
        },
        MachineStatus::Offline => MachineState::Offline,
    };
    machine.metadata.updated_at = chrono::Utc::now();

    // If status is Discovered, check for default OS
    if status == MachineStatus::Discovered {
        if let Ok(Some(default_os)) = state.store.get_setting("default_os").await {
            if !default_os.is_empty() {
                info!(
                    "Applying default OS '{}' to newly registered machine {}",
                    default_os, id
                );
                machine.config.os_choice = Some(default_os);
            }
        }
    }

    // Save to v1 Store
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine updated event
            let _ = state.event_manager.send(format!("machine_updated:{}", id));

            // Return HTML success message
            Html(format!(
                r#"
                <div class="p-4 mb-4 text-sm text-green-700 bg-green-100 rounded-lg" role="alert">
                    <span class="font-medium">Success!</span> Machine status has been updated.
                </div>
                <script>
                    // Close the modal
                    statusModal = false;
                    // Refresh the machine list
                    htmx.trigger(document.querySelector('tbody'), 'refreshMachines');
                </script>
            "#
            ))
            .into_response()
        }
        Err(e) => {
            error!("Failed to update status for machine {}: {}", id, e);
            Html(format!(
                r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> Database error: {}.
                </div>
            "#,
                e
            ))
            .into_response()
        }
    }
}

#[axum::debug_handler]
async fn update_hostname(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
    Json(payload): Json<HostnameUpdateRequest>,
) -> Response {
    // Check if user is authenticated as admin
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Admin authentication required for this operation"
            })),
        )
            .into_response();
    }

    info!(
        "Updating hostname for machine {} to {}",
        id, payload.hostname
    );

    // Get machine from v1 Store
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let error_response = ErrorResponse {
                error: "Not Found".to_string(),
                message: format!("Machine with ID {} not found", id),
            };
            return (StatusCode::NOT_FOUND, Json(error_response)).into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Database Error".to_string(),
                message: e.to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // Update hostname - treat empty string as None (clear hostname)
    machine.config.hostname = if payload.hostname.is_empty() {
        None
    } else {
        Some(payload.hostname.clone())
    };
    machine.metadata.updated_at = chrono::Utc::now();

    // Save to v1 Store
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine updated event
            let _ = state.event_manager.send(format!("machine_updated:{}", id));

            let response = HostnameUpdateResponse {
                success: true,
                message: format!("Hostname updated for machine {}", id),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed to update hostname for machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Database Error".to_string(),
                message: e.to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

#[axum::debug_handler]
async fn update_os_installed(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<OsInstalledUpdateRequest>,
) -> Response {
    info!(
        "Updating OS installed for machine {} to {}",
        id, payload.os_installed
    );

    // Get machine from v1 store
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            warn!(
                "Machine with ID {} not found when attempting to update OS installed.",
                id
            );
            let error_response = ErrorResponse {
                error: "Not Found".to_string(),
                message: format!("Machine with ID {} not found", id),
            };
            return (StatusCode::NOT_FOUND, Json(error_response)).into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: e.to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // Update os_installed
    machine.config.os_installed = Some(payload.os_installed.clone());
    machine.metadata.updated_at = chrono::Utc::now();

    // Save back to store
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine updated event
            let _ = state.event_manager.send(format!("machine_updated:{}", id));

            let response = OsInstalledUpdateResponse {
                success: true,
                message: format!("OS installed updated for machine {}", id),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed to update OS installed for machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: e.to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

#[axum::debug_handler]
async fn update_bmc(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
    Form(payload): Form<BmcCredentialsUpdateRequest>,
) -> Response {
    use dragonfly_common::{BmcConfig, BmcType as StoreBmcType};

    // Check if user is authenticated as admin
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Admin authentication required for this operation"
            })),
        )
            .into_response();
    }

    info!("Updating BMC credentials for machine {}", id);

    // Get machine from v1 store
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let error_message = format!("Machine with ID {} not found", id);
            return (
                StatusCode::NOT_FOUND,
                Html(format!(
                    r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> {}.
                </div>
            "#,
                    error_message
                )),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            let error_message = format!("Store error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!(
                    r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> {}.
                </div>
            "#,
                    error_message
                )),
            )
                .into_response();
        }
    };

    // Create BMC config from the form data
    let bmc_type = match payload.bmc_type.as_str() {
        "IPMI" => StoreBmcType::Ipmi,
        "Redfish" => StoreBmcType::Redfish,
        _ => StoreBmcType::Ipmi, // Default to IPMI
    };

    // Encrypt password before storing
    let encrypted_password = match crate::encryption::encrypt_string(&payload.bmc_password) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to encrypt BMC password: {}", e);
            let error_message = format!("Encryption error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!(
                    r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> {}.
                </div>
            "#,
                    error_message
                )),
            )
                .into_response();
        }
    };

    machine.config.bmc = Some(BmcConfig {
        address: payload.bmc_address.clone(),
        username: payload.bmc_username.clone(),
        password_encrypted: encrypted_password,
        bmc_type,
    });
    machine.metadata.updated_at = chrono::Utc::now();

    // Save back to store
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine updated event
            let _ = state.event_manager.send(format!("machine_updated:{}", id));

            (
                StatusCode::OK,
                Html(format!(
                    r#"
                <div class="p-4 mb-4 text-sm text-green-700 bg-green-100 rounded-lg" role="alert">
                    <span class="font-medium">Success!</span> BMC credentials updated.
                </div>
                <script>
                    setTimeout(function() {{
                        window.location.reload();
                    }}, 1500);
                </script>
            "#
                )),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to update BMC credentials for machine {}: {}", id, e);
            let error_message = format!("Store error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!(
                    r#"
                <div class="p-4 mb-4 text-sm text-red-700 bg-red-100 rounded-lg" role="alert">
                    <span class="font-medium">Error!</span> {}.
                </div>
            "#,
                    error_message
                )),
            )
                .into_response()
        }
    }
}

// Handler to get the hostname edit form
#[axum::debug_handler]
async fn get_hostname_form(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.store.get_machine(id).await {
        Ok(Some(v1_machine)) => {
            let current_hostname = v1_machine.config.hostname.clone().unwrap_or_default();
            // Use raw string literals to avoid escaping issues
            let html = format!(
                r###"
                <div class="sm:flex sm:items-start">
                    <div class="mt-3 text-center sm:mt-0 sm:text-left w-full">
                        <h3 class="text-base font-semibold leading-6 text-gray-900">
                            Update Machine Hostname
                        </h3>
                        <div class="mt-2">
                            <form hx-post="/machines/{}/hostname" hx-target="#hostname-modal">
                                <label for="hostname" class="block text-sm font-medium text-gray-700">Hostname</label>
                                <input type="text" name="hostname" id="hostname" value="{}" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm" placeholder="Enter hostname">
                                <div class="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                                    <button type="submit" class="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 sm:ml-3 sm:w-auto">
                                        Update
                                    </button>
                                    <button type="button" class="mt-3 inline-flex w-full justify-center rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50 sm:mt-0 sm:w-auto" onclick="document.getElementById('hostname-modal').classList.add('hidden')">
                                        Cancel
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                "###,
                id, current_hostname
            );

            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                html,
            )
        }
        Ok(None) => {
            let error_html = format!(
                r###"<div class="p-4 text-red-500">Machine with ID {} not found</div>"###,
                id
            );
            (
                StatusCode::NOT_FOUND,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                error_html,
            )
        }
        Err(e) => {
            let error_html = format!(r###"<div class="p-4 text-red-500">Error: {}</div>"###, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                error_html,
            )
        }
    }
}

// Handler for initial iPXE script generation (DHCP points here)
// Determines whether to chain to HookOS or the Dragonfly Agent
//
// When native provisioning is enabled, uses ProvisioningService for boot decisions.
// Otherwise, falls back to legacy db-based approach.
pub async fn ipxe_script(State(state): State<AppState>, Path(mac): Path<String>) -> Response {
    // URL-decode the MAC address (iPXE URL-encodes colons as %3A)
    let mac = urlencoding::decode(&mac)
        .map(|s| s.into_owned())
        .unwrap_or(mac);

    if !mac.contains(':') || mac.split(':').count() != 6 {
        warn!("Received invalid MAC format in iPXE request: {}", mac);
        return (StatusCode::BAD_REQUEST, "Invalid MAC Address Format").into_response();
    }

    info!("Generating initial iPXE script for MAC: {}", mac);

    // Use native provisioning if enabled
    if let Some(ref provisioning) = state.provisioning {
        match provisioning.get_boot_script(&mac).await {
            Ok(script) => {
                // Log the first 3 lines of the script for debugging
                let preview: String = script.lines().take(5).collect::<Vec<_>>().join(" | ");
                info!("Returning iPXE script for MAC {}: {}", mac, preview);
                return (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "text/plain")],
                    script,
                )
                    .into_response();
            }
            Err(e) => {
                error!("Provisioning error for MAC {}: {}", mac, e);
                let error_response = ErrorResponse {
                    error: "Provisioning Error".to_string(),
                    message: e.to_string(),
                };
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
            }
        }
    }

    // Legacy fallback: Read required base URL from environment variable
    let base_url = match env::var("DRAGONFLY_BASE_URL") {
        Ok(url) => url,
        Err(_) => {
            error!(
                "CRITICAL: DRAGONFLY_BASE_URL environment variable is not set. iPXE booting requires this configuration."
            );
            let error_response = ErrorResponse {
                error: "Configuration Error".to_string(),
                message: "Server is missing required DRAGONFLY_BASE_URL configuration.".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // All machines boot into Mage (Dragonfly Agent) — the agent handles
    // both discovery of new machines and re-provisioning of known ones.
    match state.store.list_machines().await {
        Ok(machines) => {
            let known = machines
                .iter()
                .any(|m| m.identity.primary_mac == mac || m.identity.all_macs.contains(&mac));
            if known {
                info!("Known MAC {}, chaining to Dragonfly Agent", mac);
            } else {
                info!("Unknown MAC {}, chaining to Dragonfly Agent", mac);
            }
            let script = format!("#!ipxe\nchain {}/ipxe/dragonfly-agent.ipxe", base_url);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                script,
            )
                .into_response()
        }
        Err(e) => {
            error!("Store error while looking up MAC {}: {}", mac, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: e.to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

#[axum::debug_handler]
async fn delete_machine(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use dragonfly_common::MachineSource;

    // Check if user is authenticated as admin
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Admin authentication required for this operation"
            })),
        )
            .into_response();
    }

    info!("Request to delete machine: {}", id);

    let delete_in_proxmox = params
        .get("delete_in_proxmox")
        .map(|v| v == "true")
        .unwrap_or(false);

    // If requested, also delete the VM/LXC in Proxmox before removing from DB
    if delete_in_proxmox {
        match state.store.get_machine(id).await {
            Ok(Some(machine)) => {
                let (api_type, node, vmid) = match &machine.metadata.source {
                    MachineSource::Proxmox { node, vmid, .. } => ("qemu", node.clone(), *vmid),
                    MachineSource::ProxmoxLxc { node, ctid, .. } => ("lxc", node.clone(), *ctid),
                    _ => {
                        // Not a Proxmox VM/LXC — nothing to delete in Proxmox
                        info!(
                            "Machine {} is not a Proxmox VM/LXC, skipping Proxmox deletion",
                            id
                        );
                        ("", String::new(), 0)
                    }
                };
                if !api_type.is_empty() {
                    use proxmox_client::HttpApiClient;
                    // Try "power" token (needs VM.Allocate), fall back to "config"
                    let client_result =
                        crate::handlers::proxmox::connect_to_proxmox(&state, "power")
                            .await
                            .or(
                                crate::handlers::proxmox::connect_to_proxmox(&state, "config")
                                    .await,
                            );
                    let client = match client_result {
                        Ok(c) => Some(c),
                        Err(e) => {
                            warn!(
                                "Cannot connect to Proxmox to delete {} {}: {}",
                                api_type, vmid, e
                            );
                            None
                        }
                    };
                    if let Some(client) = client {
                        let path = format!("/api2/json/nodes/{}/{}/{}", node, api_type, vmid);
                        match client.delete(&path).await {
                            Ok(_) => info!(
                                "Deleted {} {} on node '{}' in Proxmox",
                                api_type, vmid, node
                            ),
                            Err(e) => warn!(
                                "Failed to delete {} {} in Proxmox: {} — removing from Dragonfly anyway",
                                api_type, vmid, e
                            ),
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(e) => warn!(
                "Failed to read machine {} before Proxmox deletion: {}",
                id, e
            ),
        }
    }

    // Delete from v1 Store
    match state.store.delete_machine(id).await {
        Ok(true) => {
            info!("Successfully deleted machine {}", id);

            // Emit machine deleted event
            let _ = state.event_manager.send(format!("machine_deleted:{}", id));

            (
                StatusCode::OK,
                Json(json!({ "success": true, "message": "Machine successfully deleted." })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Machine not found in database" })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete machine from database: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Database error: {}", e) })),
            )
                .into_response()
        }
    }
}

// Add this function to handle machine updates
#[axum::debug_handler]
async fn update_machine(
    State(state): State<AppState>,
    auth_session: AuthSession,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(id): Path<Uuid>,
    Json(machine_payload): Json<Machine>,
) -> Response {
    let client_ip = addr.ip().to_string();
    info!("Update request for machine {} from IP: {}", id, client_ip);

    // Authorization Logic - check if admin or agent's own IP
    let is_admin = auth_session.user.is_some();

    // Get machine from v1 Store
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "Not Found",
                    "message": format!("Machine with ID {} not found", id)
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Database error during machine lookup: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Database Error",
                    "message": e.to_string()
                })),
            )
                .into_response();
        }
    };

    // Authorization: admin is always authorized, otherwise we'd need IP check
    // For now, since we don't store IP in v1 Machine, just require admin
    if !is_admin {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Forbidden",
                "message": "Admin authentication required for machine updates"
            })),
        )
            .into_response();
    }

    // Ensure the ID from the path matches the payload ID
    if machine_payload.id != id {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "ID Mismatch",
            "message": "The machine ID in the URL path does not match the ID in the request body."
        }))).into_response();
    }

    info!("Updating machine {} with full payload", id);

    // Apply updates from payload to v1 Machine
    machine.config.hostname = machine_payload.hostname;
    machine.config.os_choice = machine_payload.os_choice;

    // Update hardware info if provided
    if let Some(cpu) = machine_payload.cpu_model {
        machine.hardware.cpu_model = Some(cpu);
    }
    if let Some(cores) = machine_payload.cpu_cores {
        machine.hardware.cpu_cores = Some(cores);
    }
    if let Some(ram) = machine_payload.total_ram_bytes {
        machine.hardware.memory_bytes = Some(ram);
    }

    // Update status
    use dragonfly_common::MachineState;
    machine.status.state = match &machine_payload.status {
        MachineStatus::Discovered => MachineState::Discovered,
        MachineStatus::ReadyToInstall => MachineState::ReadyToInstall,
        MachineStatus::Initializing => MachineState::Initializing,
        MachineStatus::Installing => MachineState::Installing,
        MachineStatus::Writing => MachineState::Writing,
        MachineStatus::Installed => MachineState::Installed,
        MachineStatus::ExistingOS => MachineState::ExistingOs {
            os_name: "Unknown".to_string(),
        },
        MachineStatus::Failed(msg) => MachineState::Failed {
            message: msg.clone(),
        },
        MachineStatus::Offline => MachineState::Offline,
    };

    machine.metadata.updated_at = chrono::Utc::now();

    // Save to v1 Store
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine updated event
            let _ = state.event_manager.send(format!("machine_updated:{}", id));

            // Return the updated machine as common Machine
            let response_machine = machine_to_common(&machine);
            (StatusCode::OK, Json(response_machine)).into_response()
        }
        Err(e) => {
            error!("Failed to update machine {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Database Error",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// PATCH /api/machines/{id} — partial update using UpdateMachineRequest
async fn patch_machine(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
    Json(req): Json<crate::store::conversions::UpdateMachineRequest>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Forbidden",
                "message": "Admin authentication required"
            })),
        )
            .into_response();
    }

    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "Not Found",
                    "message": format!("Machine {} not found", id)
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Store error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Database Error",
                    "message": e.to_string()
                })),
            )
                .into_response();
        }
    };

    crate::store::conversions::apply_machine_update(&mut machine, req);

    match state.store.put_machine(&machine).await {
        Ok(()) => {
            let _ = state.event_manager.send(format!("machine_updated:{}", id));
            let response_machine = machine_to_common(&machine);
            (StatusCode::OK, Json(response_machine)).into_response()
        }
        Err(e) => {
            error!("Failed to update machine {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Database Error",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

// Handler to get the OS assignment form
async fn get_machine_os(Path(id): Path<Uuid>) -> Response {
    Html(format!(r#"
        <div class="sm:flex sm:items-start">
            <div class="mt-3 text-center sm:mt-0 sm:text-left w-full">
                <h3 class="text-lg leading-6 font-medium text-gray-900">
                    Assign Operating System
                </h3>
                <div class="mt-2">
                    <form hx-post="/api/machines/{}/os" hx-swap="none" @submit="osModal = false">
                        <div class="mt-4">
                            <label for="os_choice" class="block text-sm font-medium text-gray-700">Operating System</label>
                            <select
                                id="os_choice"
                                name="os_choice"
                                class="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm rounded-md"
                            >
                                <option value="ubuntu-2204">Ubuntu 22.04</option>
                                <option value="ubuntu-2404">Ubuntu 24.04</option>
                                <option value="debian-12">Debian 12</option>
                                <option value="proxmox">Proxmox VE</option>
                            </select>
                        </div>
                        <div class="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                            <button
                                type="submit"
                                class="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 sm:ml-3 sm:w-auto"
                            >
                                Assign
                            </button>
                            <button
                                type="button"
                                class="mt-3 inline-flex w-full justify-center rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50 sm:mt-0 sm:w-auto"
                                @click="osModal = false"
                            >
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    "#, id)).into_response()
}

// Rename from sse_events to machine_events to match the function name used in the working implementation
async fn machine_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = std::result::Result<Event, Infallible>>> {
    let rx = state.event_manager.subscribe(); // Remove mut

    let stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(event_string) => {
                // FIX: Correct parsing and variable naming
                let parts: Vec<&str> = event_string.splitn(2, ':').collect();
                let (event_type, event_payload_str) = if parts.len() == 2 {
                    // Renamed event_id_str to event_payload_str for clarity
                    (parts[0], Some(parts[1]))
                } else {
                    (event_string.as_str(), None)
                };

                // Special handling for events that send raw JSON payload
                if event_type == "ip_download_progress" || event_type == "workflow_progress" || event_type == "cluster" {
                    if let Some(payload_str) = event_payload_str {
                        // Directly use the JSON string as data for this specific event type
                        let sse_event = Event::default().event(event_type).data(payload_str); // Use the payload string directly
                        Some((Ok(sse_event), rx))
                    } else {
                        warn!(
                            "Received {} event without payload: {}",
                            event_type, event_string
                        );
                        // Optionally send a comment or skip
                        let comment_event = Event::default().comment(format!(
                            "Warning: {} event received without payload.",
                            event_type
                        ));
                        Some((Ok(comment_event), rx))
                    }
                } else {
                    // Existing logic for other events (like machine_updated, machine_discovered, etc.)
                    let data_payload = if let Some(id_str) = event_payload_str {
                        // Use the renamed variable
                        json!({ "type": event_type, "id": id_str })
                    } else {
                        // Ensure there's always a payload, even without ID
                        json!({ "type": event_type })
                    };

                    // Serialize JSON to string for SSE data field
                    match serde_json::to_string(&data_payload) {
                        Ok(json_string) => {
                            let sse_event = Event::default().event(event_type).data(json_string);
                            Some((Ok(sse_event), rx))
                        }
                        Err(e) => {
                            error!("Failed to serialize SSE event data to JSON: {}", e);
                            let comment_event = Event::default()
                                .comment("Internal error: failed to serialize event.");
                            Some((Ok(comment_event), rx))
                        }
                    }
                }
            }
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(1))
            .text("ping"),
    )
}

async fn generate_ipxe_script(script_name: &str) -> Result<String, dragonfly_common::Error> {
    info!("Generating IPXE script: {}", script_name);

    match script_name {
        "hookos.ipxe" => {
            // Get Dragonfly base URL (required)
            let base_url_str = env::var("DRAGONFLY_BASE_URL")
                .map_err(|_| {
                    error!("CRITICAL: DRAGONFLY_BASE_URL environment variable is not set. HookOS iPXE script requires this.");
                    Error::Internal("Server is missing required DRAGONFLY_BASE_URL configuration.".to_string())
                })?;

            // --- Derive Tinkerbell defaults from DRAGONFLY_BASE_URL ---
            let default_tinkerbell_host = Url::parse(&base_url_str)
                .ok()
                .and_then(|url| url.host_str().map(String::from))
                .unwrap_or_else(|| {
                    warn!("Could not parse DRAGONFLY_BASE_URL host, using fallback '127.0.0.1' for Tinkerbell defaults.");
                    "127.0.0.1".to_string()
                });

            const DEFAULT_GRPC_PORT: u16 = 42113;
            let default_grpc_authority =
                format!("{}:{}", default_tinkerbell_host, DEFAULT_GRPC_PORT);
            let default_syslog_host = default_tinkerbell_host.clone(); // Default syslog host is just the host part
            // -----------------------------------------------------------

            // Get Tinkerbell config, using derived values as defaults
            let grpc_authority = env::var("TINKERBELL_GRPC_AUTHORITY").unwrap_or_else(|_| {
                info!(
                    "TINKERBELL_GRPC_AUTHORITY not set, deriving default: {}",
                    default_grpc_authority
                );
                default_grpc_authority
            });
            let syslog_host = env::var("TINKERBELL_SYSLOG_HOST").unwrap_or_else(|_| {
                info!(
                    "TINKERBELL_SYSLOG_HOST not set, deriving default: {}",
                    default_syslog_host
                );
                default_syslog_host
            });
            let tinkerbell_tls = env::var("TINKERBELL_TLS")
                .map(|s| s.parse().unwrap_or(false))
                .unwrap_or(false);

            // Format the HookOS iPXE script using Dragonfly URL for artifacts and Tinkerbell details for params
            Ok(format!(
                r#"#!ipxe

echo Loading HookOS via Dragonfly...

set arch ${{buildarch}}
# Dragonfly + Tinkerbell only supports 64 bit archectures.
# The build architecture does not necessarily represent the architecture of the machine on which iPXE is running.
# https://ipxe.org/cfg/buildarch

iseq ${{arch}} i386 && set arch x86_64 ||
iseq ${{arch}} arm32 && set arch aarch64 ||
iseq ${{arch}} arm64 && set arch aarch64 ||
set base-url {}
set retries:int32 0
set retry_delay:int32 0

set worker_id ${{mac}}
set grpc_authority {}
set syslog_host {}
set tinkerbell_tls {}

echo worker_id=${{mac}}
echo grpc_authority={}
echo syslog_host={}
echo tinkerbell_tls={}

set idx:int32 0
:retry_kernel
kernel ${{base-url}}/ipxe/hookos/vmlinuz-${{arch}} \
syslog_host=${{syslog_host}} grpc_authority=${{grpc_authority}} tinkerbell_tls=${{tinkerbell_tls}} worker_id=${{worker_id}} hw_addr=${{mac}} \
console=tty1 console=tty2 console=ttyAMA0,115200 console=ttyAMA1,115200 console=ttyS0,115200 console=ttyS1,115200 tink_worker_image=quay.io/tinkerbell/tink-worker:v0.12.1 \
intel_iommu=on iommu=pt nomodeset initrd=initramfs-${{arch}} && goto download_initrd || iseq ${{idx}} ${{retries}} && goto kernel-error || inc idx && echo retry in ${{retry_delay}} seconds ; sleep ${{retry_delay}} ; goto retry_kernel

:download_initrd
set idx:int32 0
:retry_initrd
initrd ${{base-url}}/ipxe/hookos/initramfs-${{arch}} && goto boot || iseq ${{idx}} ${{retries}} && goto initrd-error || inc idx && echo retry in ${{retry_delay}} seconds ; sleep ${{retry_delay}} ; goto retry_initrd

:boot
set idx:int32 0
:retry_boot
boot || iseq ${{idx}} ${{retries}} && goto boot-error || inc idx && echo retry in ${{retry_delay}} seconds ; sleep ${{retry_delay}} ; goto retry_boot

:kernel-error
echo Failed to load kernel
imgfree
exit

:initrd-error
echo Failed to load initrd
imgfree
exit

:boot-error
echo Failed to boot
imgfree
exit
"#,
                base_url_str,   // Use Dragonfly base URL for artifacts
                grpc_authority, // Use determined gRPC authority (env var or derived default)
                syslog_host,    // Use determined syslog host (env var or derived default)
                tinkerbell_tls, // Use determined TLS setting
                grpc_authority, // for echo
                syslog_host,    // for echo
                tinkerbell_tls  // for echo
            ))
        }
        "dragonfly-agent.ipxe" => {
            // Get Dragonfly base URL for agent artifacts
            let base_url = env::var("DRAGONFLY_BASE_URL")
                .map_err(|_| {
                    error!("CRITICAL: DRAGONFLY_BASE_URL environment variable is not set. Agent iPXE script requires this.");
                    Error::Internal("Server is missing required DRAGONFLY_BASE_URL configuration.".to_string())
                })?;

            // Detect architecture from iPXE buildarch variable
            // Default to x86_64, script will detect at runtime
            Ok(format!(
                r#"#!ipxe
# Detect architecture
iseq ${{buildarch}} arm64 && set arch aarch64 || set arch x86_64

kernel {base_url}/boot/${{arch}}/kernel \
  ip=dhcp \
  alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v3.23/main \
  modules=loop,squashfs,sd-mod,usb-storage \
  initrd=initramfs \
  modloop={base_url}/boot/${{arch}}/modloop \
  apkovl={base_url}/boot/${{arch}}/apkovl.tar.gz \
  kexec_load_disabled=0 \
  console=tty1 \
  console=ttyS0,115200 \
  nomodeset \
  rw
initrd {base_url}/boot/${{arch}}/initramfs
boot
"#
            ))
        }
        _ => {
            warn!("Cannot generate unknown IPXE script: {}", script_name); // Log the specific script name
            Err(Error::NotFound) // Use the unit variant correctly
        }
    }
}

fn create_streaming_response(
    stream: ReceiverStream<Result<Bytes, Error>>,
    content_type: &str,
    content_length: Option<u64>,
    content_range: Option<String>,
) -> Response {
    // Map the stream from Result<Bytes> to Result<Frame<Bytes>, BoxError>
    let mapped_stream = stream.map(|result| {
        match result {
            Ok(bytes) => {
                // Removed check for empty EOF marker
                // Simply map non-empty bytes to a data frame
                Ok(Frame::data(bytes))
            }
            Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    });

    // Create a stream body with explicit end signal
    let body = StreamBody::new(mapped_stream);

    // Determine status code based on whether it's a partial response
    let status_code = if content_range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };

    // Start building the response
    let mut builder = Response::builder()
        .status(status_code)
        .header(axum::http::header::CONTENT_TYPE, content_type)
        // Always accept ranges
        .header(axum::http::header::ACCEPT_RANGES, "bytes")
        // Always set no compression
        .header(axum::http::header::CONTENT_ENCODING, "identity");

    if let Some(length) = content_length {
        // If Content-Length is known, set it and DO NOT use chunked encoding.
        // This applies to both 200 OK and 206 Partial Content.
        builder = builder.header(axum::http::header::CONTENT_LENGTH, length.to_string());
    } else {
        // Only use chunked encoding if length is truly unknown (should typically only be for 200 OK).
        // It's an error to have a 206 response without Content-Length.
        if status_code == StatusCode::OK {
            builder = builder.header(axum::http::header::TRANSFER_ENCODING, "chunked");
        } else {
            // This case (206 without Content-Length) ideally shouldn't happen with our logic.
            // Log a warning if it does.
            warn!("Attempting to create 206 response without Content-Length!");
        }
    }

    // Include Content-Range if it's a partial response
    if let Some(range_header_value) = content_range {
        builder = builder.header(axum::http::header::CONTENT_RANGE, range_header_value);
    }

    // Build the final response
    builder.body(Body::new(body)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::new(Empty::new()))
            .unwrap()
    })
}

async fn read_file_as_stream(
    path: &StdPath,
    range_header: Option<&HeaderValue>, // Add parameter for Range header
    state: Option<&AppState>,           // Add optional state for event emission
    machine_id: Option<Uuid>,           // Add optional machine ID for tracking
) -> Result<
    (
        ReceiverStream<Result<Bytes, Error>>,
        Option<u64>,
        Option<String>,
    ),
    Error,
> {
    // Return size and Content-Range
    info!(
        "[STREAM_READ] Beginning read_file_as_stream for path: {}, range: {:?}, machine_id: {:?}",
        path.display(),
        range_header.map(|h| h.to_str().unwrap_or("invalid")),
        machine_id
    );

    let mut file = fs::File::open(path)
        .await
        .map_err(|e| Error::Internal(format!("Failed to open file {}: {}", path.display(), e)))?; // Added mut back
    let (tx, rx) = mpsc::channel::<Result<Bytes, Error>>(32);
    let path_buf = path.to_path_buf();

    // Get total file size
    let metadata = fs::metadata(path).await.map_err(|e| {
        Error::Internal(format!("Failed to get metadata {}: {}", path.display(), e))
    })?;
    let total_size = metadata.len();

    // Get file name for progress tracking
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(String::from);

    let (start, _end, response_length, content_range_header) = // Marked end as unused
        if let Some(range_val) = range_header {
            if let Ok(range_str) = range_val.to_str() {
                if let Some((start, end)) = parse_range_header(range_str, total_size, file_name.as_deref(), state).await {
                    let length = end - start + 1;
                    let content_range = format!("bytes {}-{}/{}", start, end, total_size);
                    // info!("Serving range request: {} for file {}", content_range, path.display()); // Commented out log
                    (start, end, length, Some(content_range))
                } else {
                    warn!("Invalid Range header format: {}", range_str);
                    // Invalid range, serve the whole file
                    (0, total_size.saturating_sub(1), total_size, None)
                }
            } else {
                warn!("Invalid Range header value (not UTF-8)");
                // Invalid range, serve the whole file
                (0, total_size.saturating_sub(1), total_size, None)
            }
        } else {
            // No range header, serve the whole file
            (0, total_size.saturating_sub(1), total_size, None)
        };

    let response_content_length = Some(response_length);
    let content_range_header_clone = content_range_header.clone(); // Clone for the task
    // Clone state and machine_id needed for the background task *before* spawning
    // Ensures owned values are moved into the async block, avoiding lifetime issues.
    let task_state_owned = state.cloned(); // Creates Option<AppState>
    let task_machine_id_copied = machine_id; // Copies Option<Uuid>

    tokio::spawn(async move {
        // Handle Range requests differently: read the whole range at once
        if content_range_header_clone.is_some() {
            // Use the clone
            if start > 0 {
                if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
                    error!("Failed to seek file {}: {}", path_buf.display(), e);
                    let _ = tx
                        .send(Err(Error::Internal(format!("File seek error: {}", e))))
                        .await;
                    return;
                }
            }

            // Allocate buffer for the exact range size
            let mut buffer = Vec::with_capacity(response_length as usize); // Use with_capacity

            // Create a reader limited to the exact range size
            let mut limited_reader = file.take(response_length);

            // Read the exact range using the limited reader
            match limited_reader.read_to_end(&mut buffer).await {
                Ok(_) => {
                    // Track progress for range requests too
                    // For range requests, we use the start offset as an indicator of download progress
                    if let (Some(state_ref), Some(machine_id_captured)) =
                        (&task_state_owned, task_machine_id_copied)
                    {
                        if total_size > 0 {
                            // Use start position + current range size as effective progress indicator
                            let bytes_read = buffer.len() as u64;
                            let effective_progress = start + bytes_read;

                            info!(
                                "[RANGE_READ] Range request: start={}, bytes_read={}, total_size={}, effective_progress={}",
                                start, bytes_read, total_size, effective_progress
                            );

                            // Clone state for progress tracking
                            let owned_state = state_ref.clone();

                            // Spawn progress tracking in a separate task
                            tokio::spawn(async move {
                                track_download_progress(
                                    Some(machine_id_captured),
                                    effective_progress,
                                    total_size,
                                    owned_state,
                                )
                                .await;
                            });
                        }
                    }

                    // Send the complete range as a single chunk
                    if tx.send(Ok(Bytes::from(buffer))).await.is_err() {
                        warn!(
                            "Client stream receiver dropped for file {} while sending range",
                            path_buf.display()
                        );
                    }
                    // Task finishes, tx is dropped, stream closes.
                }
                Err(e) => {
                    error!(
                        "Failed to read exact range for file {}: {}",
                        path_buf.display(),
                        e
                    );
                    let _ = tx
                        .send(Err(Error::Internal(format!(
                            "File read_exact error: {}",
                            e
                        ))))
                        .await;
                }
            }
        } else {
            // Original streaming logic for full file requests
            let mut buffer = vec![0; 65536]; // 64KB buffer
            let mut remaining = response_length; // For full file, response_length == total_size
            let mut total_bytes_sent: u64 = 0;

            while remaining > 0 {
                let read_size = std::cmp::min(remaining as usize, buffer.len());
                match file.read(&mut buffer[..read_size]).await {
                    Ok(0) => {
                        //info!("Reached EOF while serving file {} (remaining: {} bytes)", path_buf.display(), remaining);
                        break; // EOF reached
                    }
                    Ok(n) => {
                        // Handles n > 0
                        let chunk = Bytes::copy_from_slice(&buffer[0..n]);
                        remaining -= n as u64;
                        total_bytes_sent += n as u64; // Add this line to update total bytes sent!

                        // ADDED LOG: Log bytes read and total sent
                        debug!(path = %path_buf.display(), bytes_read = n, total_bytes_sent = total_bytes_sent, total_size = total_size, "[STREAM_READ_LOOP] Read chunk");

                        // Use the owned/copied state and machine_id captured by the 'move' closure
                        // Match against the Option<&AppState> and Option<Uuid> directly
                        if let (Some(state_ref), Some(machine_id_captured)) =
                            (&task_state_owned, task_machine_id_copied)
                        {
                            if total_size > 0 {
                                // Avoid division by zero
                                debug!(
                                    "[PROGRESS_DEBUG][CACHE_READ] Calling track_download_progress (machine_id: {}, sent: {}, total: {})",
                                    machine_id_captured, total_bytes_sent, total_size
                                );
                                // Clone the AppState here to get an owned value for the inner task.
                                let owned_state = state_ref.clone(); // <-- Add this line
                                // Spawn progress tracking in a separate task to avoid blocking the stream
                                tokio::spawn(async move {
                                    // Pass the already owned AppState.
                                    track_download_progress(
                                        Some(machine_id_captured),
                                        total_bytes_sent,
                                        total_size,
                                        owned_state,
                                    )
                                    .await; // <-- Use owned_state here
                                });
                            } // else: Skipping progress track because total_size is 0 (logged elsewhere if needed)
                        } // else: Skipping progress track because machine_id or state is missing

                        if tx.send(Ok(chunk)).await.is_err() {
                            warn!(
                                "Client stream receiver dropped for file {}",
                                path_buf.display()
                            );
                            break; // Exit loop if receiver is gone
                        }
                    }
                    Err(e) => {
                        let err = Error::Internal(format!(
                            "File read error for {}: {}",
                            path_buf.display(),
                            e
                        ));
                        if tx.send(Err(err)).await.is_err() {
                            warn!(
                                "Client stream receiver dropped while sending error for {}",
                                path_buf.display()
                            );
                        }
                        break; // Exit loop on read error
                    }
                }
            }
        }

        // Task finishes, tx is dropped, stream closes.
        debug!("Finished streaming task for: {}", path_buf.display());
    });

    // Return the stream, the length of the *content being sent*, and the *original* Content-Range header string
    Ok((
        tokio_stream::wrappers::ReceiverStream::new(rx),
        response_content_length,
        content_range_header,
    ))
}

// Serve iPXE artifacts (scripts and binaries)
// Function to serve an iPXE artifact file from a configured directory
pub async fn serve_ipxe_artifact(
    headers: HeaderMap,
    Path(requested_path): Path<String>,
    State(state): State<AppState>, // Add AppState to access event manager and client_ip
) -> Response {
    // Define constants for directories and URLs
    const DEFAULT_ARTIFACT_DIR: &str = "/var/lib/dragonfly/ipxe-artifacts";
    const ARTIFACT_DIR_ENV_VAR: &str = "DRAGONFLY_IPXE_ARTIFACT_DIR";
    const ALLOWED_IPXE_SCRIPTS: &[&str] = &["dragonfly-agent"];
    const AGENT_APKOVL_PATH: &str =
        "/var/lib/dragonfly/ipxe-artifacts/dragonfly-agent/localhost.apkovl.tar.gz";
    let agent_binary_url = format!(
        "https://github.com/riffcc/dragonfly/releases/download/v{}/dragonfly-agent-linux-amd64",
        env!("CARGO_PKG_VERSION")
    );

    // --- Get Machine ID from Client IP ---
    let client_ip = state.client_ip.lock().await.clone();
    let machine_id: Option<Uuid> = if let Some(ip) = &client_ip {
        info!("[PROGRESS_DEBUG] Looking up machine by IP: {}", ip);
        match state.store.get_machine_by_ip(ip).await {
            Ok(Some(machine)) => {
                info!(
                    "[PROGRESS_DEBUG] Found machine ID {} for IP {}",
                    machine.id, ip
                );
                Some(machine.id)
            }
            Ok(None) => {
                info!(
                    "[PROGRESS_DEBUG] No machine found for IP {} requesting artifact {}",
                    ip, requested_path
                );
                None
            }
            Err(e) => {
                info!(
                    "[PROGRESS_DEBUG] Store error looking up machine by IP {}: {}",
                    ip, e
                );
                None
            }
        }
    } else {
        info!(
            "[PROGRESS_DEBUG] Client IP not found in state for artifact request {}",
            requested_path
        );
        None
    };
    // ----------------------------------

    // Get the base directory from env var or use default
    let base_dir = env::var(ARTIFACT_DIR_ENV_VAR).unwrap_or_else(|_| {
        debug!(
            "{} not set, using default: {}",
            ARTIFACT_DIR_ENV_VAR, DEFAULT_ARTIFACT_DIR
        );
        DEFAULT_ARTIFACT_DIR.to_string()
    });
    let base_path = PathBuf::from(base_dir);

    // Path sanitization - Allow '/' but prevent '..'
    if requested_path.contains("..") || requested_path.contains('\\') {
        warn!(
            "Attempted iPXE artifact path traversal using '..' or '\': {}",
            requested_path
        );
        return (StatusCode::BAD_REQUEST, "Invalid artifact path").into_response();
    }

    let artifact_path = base_path.join(&requested_path);

    // --- Serve from Cache First ---
    if artifact_path.exists() {
        info!(
            "[SERVE_ARTIFACT] Cached artifact exists at {}, will use read_file_as_stream",
            artifact_path.display()
        );
        // Determine content type AND if it's an IPXE script
        let (content_type, is_ipxe) = if requested_path.ends_with(".ipxe") {
            ("text/plain", true)
        } else if requested_path.ends_with(".tar.gz") {
            ("application/gzip", false) // Ensure this returns a tuple
        } else {
            ("application/octet-stream", false) // Ensure this returns a tuple
        };

        // Allowlist check for IPXE scripts from cache
        if is_ipxe {
            // Check the boolean flag
            let stem = StdPath::new(&requested_path)
                .file_stem()
                .and_then(|s| s.to_str());
            if let Some(stem_str) = stem {
                if !ALLOWED_IPXE_SCRIPTS.contains(&stem_str) {
                    warn!(
                        "Attempt to serve non-allowlisted IPXE script stem from cache: {}",
                        stem_str
                    );
                    return (StatusCode::NOT_FOUND, "iPXE Script Not Found").into_response();
                }
            } else {
                warn!(
                    "Could not extract stem from IPXE script path: {}",
                    requested_path
                );
                return (StatusCode::BAD_REQUEST, "Invalid IPXE Script Path").into_response();
            }
        }

        // Serve allowed script or binary artifact from cache using streaming
        // Pass the potentially found machine_id for progress tracking
        match read_file_as_stream(
            &artifact_path,
            headers.get(axum::http::header::RANGE),
            Some(&state),
            machine_id,
        )
        .await
        {
            Ok((stream, file_size, content_range)) => {
                info!("Streaming cached artifact from disk: {}", requested_path);
                return create_streaming_response(stream, content_type, file_size, content_range); // Pass content_range
            }
            Err(e) => {
                error!("Failed to stream cached iPXE artifact: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error reading iPXE artifact",
                )
                    .into_response();
            }
        }
    } else {
        // --- File Not Found: Generate or Download ---
        info!(
            "[SERVE_ARTIFACT] Artifact {} not found locally, will need to generate or download",
            requested_path
        );

        // FIRST check if it is the specific apkovl path that needs generation
        // Compare against the RELATIVE path expected from the URL
        if requested_path == "dragonfly-agent/localhost.apkovl.tar.gz" {
            // --- Special Case: Generate apkovl on demand ---
            // Use the full absolute path for generation logic
            let generation_target_path = PathBuf::from(AGENT_APKOVL_PATH);
            info!(
                "Generating {} on demand...",
                generation_target_path.display()
            );

            // Get base URL with auto-detection fallback
            let base_url = crate::mode::get_base_url(Some(state.store.as_ref())).await;

            // Check if we need to regenerate (base_url changed or file doesn't exist)
            let url_marker_path = generation_target_path.with_extension("url");
            let needs_regeneration = if generation_target_path.exists() {
                // Check if base_url changed
                match tokio::fs::read_to_string(&url_marker_path).await {
                    Ok(stored_url) => stored_url.trim() != base_url,
                    Err(_) => true, // No marker file, regenerate
                }
            } else {
                true // File doesn't exist
            };

            if !needs_regeneration {
                info!("Serving cached apkovl (base_url unchanged: {})", base_url);
                match read_file_as_stream(&generation_target_path, None, None, None).await {
                    Ok((stream, file_size, _)) => {
                        return create_streaming_response(
                            stream,
                            "application/gzip",
                            file_size,
                            None,
                        );
                    }
                    Err(e) => {
                        warn!("Failed to read cached apkovl, will regenerate: {}", e);
                    }
                }
            }

            info!("Generating apkovl with base_url: {}", base_url);

            match generate_agent_apkovl(
                &generation_target_path,
                &base_url,
                AgentSource::Url(&agent_binary_url),
            )
            .await
            {
                Ok(()) => {
                    info!(
                        "Successfully generated {}, now serving...",
                        generation_target_path.display()
                    );
                    // Save the base_url marker for cache invalidation
                    if let Err(e) = tokio::fs::write(&url_marker_path, &base_url).await {
                        warn!("Failed to write URL marker file: {}", e);
                    }
                    // Serve the newly generated file (no range needed here as it was just created)
                    match read_file_as_stream(&generation_target_path, None, None, None).await {
                        Ok((stream, file_size, _)) => {
                            return create_streaming_response(
                                stream,
                                "application/gzip",
                                file_size,
                                None,
                            );
                        }
                        Err(e) => {
                            error!(
                                "Failed to stream newly generated apkovl {}: {}",
                                generation_target_path.display(),
                                e
                            );
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Error reading newly generated apkovl",
                            )
                                .into_response();
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to generate {}: {}",
                        generation_target_path.display(),
                        e
                    );
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "Failed to generate {}: {}",
                            generation_target_path.display(),
                            e
                        ),
                    )
                        .into_response();
                }
            }
        }
        // NEXT check if it's a generic .ipxe script that needs generation
        else if requested_path.ends_with(".ipxe") {
            // --- Generate iPXE scripts on the fly ---
            // Use the relative path for script generation lookup
            match generate_ipxe_script(&requested_path).await {
                Ok(script) => {
                    info!("Generated {} script dynamically.", requested_path);
                    // Cache in background using the full artifact_path
                    let path_clone = artifact_path.clone();
                    let script_clone = script.clone();
                    let requested_path_clone = requested_path.clone(); // Clone for the task
                    tokio::spawn(async move {
                        // Ensure parent directory exists before writing
                        if let Some(parent) = path_clone.parent() {
                            if let Err(e) = fs::create_dir_all(parent).await {
                                warn!(
                                    "Failed to create directory for caching {}: {}",
                                    requested_path_clone, e
                                );
                                return;
                            }
                        }
                        if let Err(e) = fs::write(&path_clone, &script_clone).await {
                            warn!(
                                "Failed to cache generated {} script: {}",
                                requested_path_clone, e
                            );
                        }
                    });

                    // For iPXE scripts, let's build our own response
                    let content_length = script.len() as u64;

                    // Create a response that's optimized for iPXE
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(axum::http::header::CONTENT_TYPE, "text/plain")
                        .header(
                            axum::http::header::CONTENT_LENGTH,
                            content_length.to_string(),
                        )
                        .header(axum::http::header::CONTENT_ENCODING, "identity") // No compression
                        .body(Body::from(script))
                        .unwrap_or_else(|_| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to build response",
                            )
                                .into_response()
                        });
                }
                Err(Error::NotFound { .. }) => {
                    warn!(
                        "IPXE script {} not found or could not be generated.",
                        requested_path
                    );
                    // Fall through to final 404
                }
                Err(e) => {
                    // Other error during generation (e.g., missing env var)
                    error!("Failed to generate {} script: {}", requested_path, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to generate script: {}", e),
                    )
                        .into_response();
                }
            }
            // If we fall through here, it means generate_ipxe_script returned NotFound
        }
        // FINALLY, assume it's a binary artifact to download/stream
        else {
            // --- Download/Stream Other Binary Artifacts ---
            let remote_url = match requested_path.as_str() {
                // Alpine Linux netboot artifacts for Dragonfly Agent
                "dragonfly-agent/vmlinuz" => {
                    "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/vmlinuz-lts"
                }
                "dragonfly-agent/initramfs-lts" => {
                    "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/initramfs-lts"
                }
                "dragonfly-agent/modloop" => {
                    "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/modloop-lts"
                }
                // Ubuntu 22.04
                "ubuntu/jammy-server-cloudimg-amd64.img" => {
                    "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
                }
                // Ubuntu 24.04
                "ubuntu/noble-server-cloudimg-amd64.img" => {
                    "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
                }
                _ => {
                    // If it wasn't an .ipxe script and not a known binary, it's unknown.
                    warn!("Unknown artifact requested: {}", requested_path);
                    return (StatusCode::NOT_FOUND, "Unknown iPXE artifact").into_response();
                }
            };

            // Use the efficient streaming download with caching for known artifacts
            // Use artifact_path (full path) for caching
            match stream_download_with_caching(
                remote_url,
                &artifact_path,
                headers.get(axum::http::header::RANGE),
                machine_id, // Pass the machine_id found via IP lookup
                Some(&state),
            )
            .await
            {
                Ok((stream, content_length, content_range)) => {
                    info!("Streaming artifact {} from remote source", requested_path);
                    return create_streaming_response(
                        stream,
                        "application/octet-stream",
                        content_length,
                        content_range,
                    );
                }
                Err(e) => {
                    error!("Failed to stream artifact {}: {}", requested_path, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Error streaming artifact: {}", e),
                    )
                        .into_response();
                }
            }
        }

        // If code reaches here, it means an IPXE script was requested but generate_ipxe_script
        // returned NotFound, so return 404.
        (
            StatusCode::NOT_FOUND,
            "Unknown or Ungeneratable IPXE Script",
        )
            .into_response()
    }
}

// Add this function after parse_range_header
// Helper function to track and report image download progress
async fn track_download_progress(
    machine_id: Option<Uuid>,
    bytes_downloaded: u64,
    total_size: u64,
    state: AppState, // Changed from Option<&AppState> to AppState
) {
    info!(
        machine_id = ?machine_id,
        bytes_downloaded = bytes_downloaded,
        total_size = total_size,
        "[PROGRESS_TRACK] CALLED track_download_progress with values: bytes_downloaded={}, total_size={}, machine_id={:?}",
        bytes_downloaded, total_size, machine_id
    );

    debug!(
        machine_id = ?machine_id,
        bytes_downloaded = bytes_downloaded,
        total_size = total_size,
        "[PROGRESS_DEBUG] Entering track_download_progress"
    );

    if total_size == 0 {
        // Changed to INFO
        info!("[PROGRESS_DEBUG] Exiting track_download_progress early: total_size is 0");
        return; // Skip progress for zero-sized files
    }

    let progress_float = (bytes_downloaded as f64 / total_size as f64) * 100.0;
    let task_name = "stream image"; // TODO: Can we get the actual filename here?

    // If we have a machine ID, send task-specific event
    if let Some(id) = machine_id {
        debug!(machine_id = %id, progress = progress_float, task_name = task_name, "Updating store progress");
        // Update the machine's task progress in v1 store
        match state.store.get_machine(id).await {
            Ok(Some(mut machine)) => {
                machine.config.installation_progress = progress_float.min(100.0) as u8;
                machine.config.installation_step = Some(task_name.to_string());
                machine.metadata.updated_at = chrono::Utc::now();
                if let Err(e) = state.store.put_machine(&machine).await {
                    warn!(machine_id = %id, error = %e, "Failed to update download progress in store");
                }
            }
            Ok(None) => {
                warn!(machine_id = %id, "Machine not found when updating download progress");
            }
            Err(e) => {
                warn!(machine_id = %id, error = %e, "Failed to get machine for progress update");
            }
        }

        // For real-time UI updates, emit a more detailed event with floating point precision
        let task_progress_event = format!(
            "task_progress:{}:{}:{:.3}:{}:{}",
            id,               // Machine ID
            task_name,        // Task name
            progress_float,   // Floating point percentage (with 3 decimal precision)
            bytes_downloaded, // Current bytes
            total_size        // Total bytes
        );

        debug!(machine_id = %id, event = %task_progress_event, "Attempting to send task_progress event");
        // Emit the detailed task progress event
        if let Err(e) = state.event_manager.send(task_progress_event.clone()) {
            // Clone for logging
            warn!(machine_id = %id, error = %e, "Failed to emit task_progress event: {}", task_progress_event);
        }

        // Also emit standard machine updated event for compatibility
        // debug!(machine_id = %id, "Sending generic machine_updated event");
        // let _ = state.event_manager.send(format!("machine_updated:{}", id));
    }

    // Also send IP-based progress event for any HTTP requests
    let client_ip_guard = state.client_ip.lock().await;
    if let Some(client_ip) = client_ip_guard.as_ref() {
        // Find machine by IP if possible (for cases where we don't have machine_id)
        let ip_machine_id = if machine_id.is_none() {
            match state.store.get_machine_by_ip(client_ip).await {
                Ok(Some(machine)) => Some(machine.id),
                _ => None,
            }
        } else {
            machine_id
        };

        // Emit IP-based progress event
        let ip_progress_event_payload = serde_json::json!({
            "ip": client_ip,
            "progress": progress_float, // Send float
            "bytes_downloaded": bytes_downloaded,
            "total_size": total_size,
            "file_name": task_name, // Still uses hardcoded "Stream image"
            "machine_id": ip_machine_id
        });

        // Construct the event string
        let ip_progress_event_string = format!(
            "ip_download_progress:{}",
            ip_progress_event_payload.to_string()
        );

        info!(client_ip = %client_ip, event_payload = %ip_progress_event_payload, "[PROGRESS_SEND] Attempting to send ip_download_progress event NOW"); // ADDED LOUD LOG
        let send_result = state.event_manager.send(ip_progress_event_string.clone()); // Clone for logging

        if let Err(e) = send_result {
            warn!(client_ip = %client_ip, error = %e, "[PROGRESS_SEND] Failed to emit IP-based progress event: {}", ip_progress_event_string);
        } else {
            info!(client_ip = %client_ip, event_payload = %ip_progress_event_payload, "[PROGRESS_SEND] Successfully sent ip_download_progress event"); // ADDED SUCCESS LOG
        }
    } // End of: if let Some(client_ip) = client_ip_guard.as_ref()

    debug!("Exiting track_download_progress");
}

// Modify stream_download_with_caching to track progress
async fn stream_download_with_caching(
    url: &str,
    cache_path: &StdPath,
    range_header: Option<&HeaderValue>, // Add parameter for Range header
    machine_id: Option<Uuid>,           // Add optional machine ID for tracking
    state: Option<&AppState>,           // Add optional state for event emission
) -> Result<
    (
        ReceiverStream<Result<Bytes, Error>>,
        Option<u64>,
        Option<String>,
    ),
    Error,
> {
    // Return Content-Range
    info!(
        "[STREAM_DOWNLOAD] Beginning stream_download_with_caching for URL: {}, cache_path: {}, range: {:?}, machine_id: {:?}",
        url,
        cache_path.display(),
        range_header.map(|h| h.to_str().unwrap_or("invalid")),
        machine_id
    );

    // Create parent directory if needed
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|e| Error::Internal(format!("Failed to create directory: {}", e)))?;
    }

    // Check if file is already cached
    if cache_path.exists() {
        // Even when serving from cache, track progress for range requests
        if let (Some(machine_id), Some(state), Some(range_val)) = (machine_id, state, range_header)
        {
            if let Ok(range_str) = range_val.to_str() {
                let file_size = fs::metadata(cache_path).await.map(|m| m.len()).unwrap_or(0);

                if let Some((start, end)) =
                    parse_range_header(range_str, file_size, None, Some(state)).await
                {
                    let bytes_downloaded = end - start + 1;

                    // Use the start position as a progress indicator for range requests
                    // This gives a rough approximation of download progress across multiple range requests
                    let effective_progress = start + bytes_downloaded;

                    info!(
                        "[RANGE_PROGRESS] Cached file with range: start={}, end={}, bytes={}, total={}, effective_progress={}",
                        start, end, bytes_downloaded, file_size, effective_progress
                    );

                    // Track download progress with the effective bytes downloaded
                    tokio::spawn(track_download_progress(
                        Some(machine_id),
                        effective_progress,
                        file_size,
                        state.clone(),
                    ));
                }
            }
        }

        // info!("Serving cached artifact from: {:?}", cache_path); // Commented out log
        return read_file_as_stream(cache_path, range_header, state, machine_id).await; // Pass Range header
    }

    info!("Downloading and caching artifact from: {}", url);

    // Start HTTP request with reqwest feature for streaming
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Internal(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Internal(format!(
            "HTTP error: {}",
            response.status()
        )));
    }

    // Get content length if available
    let content_length = response.content_length();
    if let Some(length) = content_length {
        info!(
            "[PROGRESS_DEBUG] Download size from Content-Length: {} bytes",
            length
        );
    } else {
        info!("[PROGRESS_DEBUG] No Content-Length header received from remote server.");
    }

    let file = fs::File::create(cache_path)
        .await
        .map_err(|e| Error::Internal(format!("Failed to create cache file: {}", e)))?;
    let file = Arc::new(tokio::sync::Mutex::new(file));
    let (tx, rx) = mpsc::channel::<Result<Bytes, Error>>(32);

    let url_clone = url.to_string();
    let cache_path_clone = cache_path.to_path_buf();

    // For tracking download progress
    let total_size = content_length.unwrap_or(0);
    let mut total_bytes_downloaded: u64 = 0;
    let tracking_machine_id = machine_id;
    let app_state_clone = state.cloned();

    tokio::spawn(async move {
        let mut client_disconnected = false;
        let mut download_error = false;

        // Get the stream. `bytes_stream` consumes the response object.
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    let chunk_clone = chunk.clone();
                    let chunk_size = chunk.len() as u64;

                    // Write chunk to cache file concurrently
                    let file_clone = Arc::clone(&file);
                    let write_handle = tokio::spawn(async move {
                        let mut file = file_clone.lock().await;
                        file.write_all(&chunk_clone).await
                    });

                    // Update progress tracking
                    total_bytes_downloaded += chunk_size;

                    // ADDED LOG: Log chunk size and total downloaded
                    debug!(url = %url_clone, chunk_size = chunk_size, total_bytes_downloaded = total_bytes_downloaded, total_size = total_size, "[STREAM_DOWNLOAD_LOOP] Downloaded chunk");

                    if let (Some(machine_id), Some(state)) = (tracking_machine_id, &app_state_clone)
                    {
                        if total_size > 0 {
                            // ADDED LOG: Confirm call to track_download_progress
                            debug!(
                                "[PROGRESS_DEBUG] Calling track_download_progress (machine_id: {}, downloaded: {}, total: {})",
                                machine_id, total_bytes_downloaded, total_size
                            );

                            // ADDED LOG: Log before calling track_download_progress function
                            debug!(url = %url_clone, machine_id = %machine_id, bytes_downloaded = total_bytes_downloaded, total_size = total_size, "[STREAM_DOWNLOAD_LOOP] PRE-PROGRESS CALL");

                            track_download_progress(
                                Some(machine_id),
                                total_bytes_downloaded,
                                total_size,
                                state.clone(),
                            )
                            .await;
                        }
                    }

                    // Attempt to send to client only if not already disconnected
                    if !client_disconnected {
                        if tx.send(Ok(chunk)).await.is_err() {
                            warn!(
                                "Client stream receiver dropped for {}. Continuing download in background.",
                                url_clone
                            );
                            client_disconnected = true;
                            // DO NOT break here - let download continue for caching
                        }
                    }

                    // Await the write operation regardless of client connection status
                    match write_handle.await {
                        // Await the JoinHandle itself
                        Ok(Ok(())) => {
                            // Write successful, continue loop
                        }
                        Ok(Err(e)) => {
                            // Write operation failed
                            warn!(
                                "Failed to write chunk to cache file {}: {}",
                                cache_path_clone.display(),
                                e
                            );
                            download_error = true;
                            break; // Abort download if we can't write to cache
                        }
                        Err(e) => {
                            // Task failed (e.g., panicked)
                            warn!(
                                "Cache write task failed (join error) for {}: {}",
                                cache_path_clone.display(),
                                e
                            );
                            download_error = true;
                            break; // Abort download if write task fails
                        }
                    }
                }
                Err(e) => {
                    // e is reqwest::Error here
                    error!("Download stream error for {}: {}", url_clone, e);
                    // Send error to client if still connected
                    if !client_disconnected {
                        let err = Error::Internal(format!("Download stream error: {}", e));
                        if tx.send(Err(err)).await.is_err() {
                            warn!(
                                "Client stream receiver dropped while sending download error for {}",
                                url_clone
                            );
                            // Client disconnected while we were trying to send an error
                            client_disconnected = true;
                        }
                    }
                    download_error = true;
                    break; // Stop processing on download error
                }
            }
            // If download_error is true, the inner match already broke, so we'll exit.
        }

        // Explicitly drop the response stream to release network resources potentially sooner
        drop(stream);

        // Report final progress on successful download
        if !download_error && total_size > 0 {
            if let (Some(machine_id), Some(state)) = (tracking_machine_id, &app_state_clone) {
                track_download_progress(Some(machine_id), total_size, total_size, state.clone())
                    .await;
            }
        }

        // Ensure file is flushed and closed first
        if let Ok(mut file) = Arc::try_unwrap(file)
            .map_err(|_| "Failed to unwrap Arc")
            .and_then(|mutex| Ok(mutex.into_inner()))
        {
            if let Err(e) = file.flush().await {
                warn!(
                    "Failed to flush cache file {}: {}",
                    cache_path_clone.display(),
                    e
                );
            }
            // File is closed when it goes out of scope here
        }

        // Only send EOF signal if the download completed without error AND the client is still connected
        if !download_error && !client_disconnected {
            info!(
                "Download complete for {}, client still connected.",
                url_clone
            );
            // Removed explicit EOF signal
            // debug!("Sending EOF signal for {}", url_clone);
            // let _ = tx.send(Ok(Bytes::new())).await;
        } else if !download_error && client_disconnected {
            info!(
                "Download complete and cached for {} after client disconnected.",
                url_clone
            );
        } else {
            // An error occurred during download or caching
            warn!(
                "Download for {} did not complete successfully due to errors.",
                url_clone
            );
            // Optionally remove the potentially incomplete cache file
            // if let Err(e) = fs::remove_file(&cache_path_clone).await {
            //     warn!("Failed to remove incomplete cache file {}: {}", cache_path_clone.display(), e);
            // }
        }
    });

    // After download completes or if error, handle the stream
    let (stream, content_length) = (
        tokio_stream::wrappers::ReceiverStream::new(rx),
        content_length,
    );

    // We cached the full file, but the *initial* request might have been a range request.
    // If so, we need to read the *cached* file with range support now.
    if range_header.is_some() {
        info!(
            "Download complete, now serving range request from cached file: {:?}",
            cache_path
        );
        // Re-call read_file_as_stream with the range header on the now-cached file
        read_file_as_stream(cache_path, range_header, state, machine_id).await // Pass machine_id here too
    } else {
        // No range requested initially, return the full stream we prepared during download
        Ok((stream, content_length, None)) // No Content-Range for full file
    }
}

// Helper to parse Range header. Returns (start, end)
async fn parse_range_header(
    range_str: &str,
    total_size: u64,
    _file_name: Option<&str>,  // Marked unused, event logic removed
    _state: Option<&AppState>, // Marked unused, event logic removed
) -> Option<(u64, u64)> {
    if !range_str.starts_with("bytes=") {
        return None;
    }
    let range_val = &range_str[6..]; // Skip "bytes="
    let parts: Vec<&str> = range_val.split('-').collect();
    if parts.len() != 2 {
        return None;
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    let start = if start_str.is_empty() {
        // Suffix range: "-<length>"
        if end_str.is_empty() {
            return None;
        } // Invalid: "-"
        let suffix_len = end_str.parse::<u64>().ok()?;
        if suffix_len >= total_size {
            0
        } else {
            total_size - suffix_len
        }
    } else {
        // Normal range: "start-" or "start-end"
        start_str.parse::<u64>().ok()?
    };

    let end = if end_str.is_empty() {
        // Range "start-" means start to end of file
        total_size.saturating_sub(1)
    } else {
        // Range "start-end"
        end_str.parse::<u64>().ok()?
    };

    // Validate range: start <= end < total_size
    if start > end || end >= total_size {
        warn!(
            "Invalid range request: start={}, end={}, total_size={}",
            start, end, total_size
        );
        return None;
    }

    // Optional: Emit progress event for the range being served
    // if let Some(s) = state { // Check if state exists before trying to use it
    //     let bytes_downloaded = end - start + 1;
    //     let event_data = serde_json::json!({
    //         "progress": 100.0, // A single range request is considered 100% of that range
    //         "bytes_downloaded": bytes_downloaded,
    //         "total_size": total_size,
    //         "file_name": file_name.unwrap_or("unknown")
    //     }).to_string();

    //     // Prefer emitting IP-based progress if possible
    //     let client_ip_guard = s.client_ip.lock().await;
    //     if let Some(client_ip) = client_ip_guard.as_ref() {
    //          let ip_progress_event = format!("ip_download_progress:{{ \"ip\": \"{}\", {} }}", client_ip, &event_data[1..]); // Construct JSON manually
    //          // info!("Sending event: {}", ip_progress_event); // Commented out log
    //          let _ = s.event_manager.send(ip_progress_event);
    //     } else if let Some(f_name) = file_name {
    //         // Fallback to file-based progress if IP is unavailable
    //         let file_progress_event = format!("file_progress:{}:{}:{}", f_name, 100.0, event_data);
    //         let _ = s.event_manager.send(file_progress_event);
    //     }
    // }

    Some((start, end))
}

// Restore original function name and intended purpose (returning HTML partial)
pub async fn get_workflow_progress(
    State(app_state): State<AppState>, // Add AppState
    Path(id): Path<Uuid>,
) -> Response {
    info!(
        "Request for workflow progress HTML partial for machine {}",
        id
    );

    let machine: Machine = match app_state.store.get_machine(id).await {
        Ok(Some(m)) => crate::store::conversions::machine_to_common(&m),
        Ok(None) => {
            error!("Machine not found: {}", id);
            return (StatusCode::NOT_FOUND, Html("<div>Machine not found</div>")).into_response();
        }
        Err(e) => {
            error!("Error fetching machine {}: {}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div>Store error</div>"),
            )
                .into_response();
        }
    };

    // Workflow progress stub (Tinkerbell removed - using our own provisioning)
    // Return empty div - no workflow information available
    (StatusCode::OK, Html("<div></div>")).into_response()
}

// ... (rest of api.rs) ...

// Stub for heartbeat
pub async fn heartbeat() -> Response {
    (StatusCode::OK, "OK").into_response()
}

/// Handle agent check-in from Mage environment
///
/// Called when the dragonfly-agent boots and registers with the server.
/// Returns instructions for what the agent should do next.
pub async fn agent_checkin_handler(
    State(state): State<crate::AppState>,
    Json(checkin): Json<HardwareCheckIn>,
) -> Response {
    info!(mac = %checkin.mac, hostname = ?checkin.hostname, "Agent check-in received");

    let provisioning = match &state.provisioning {
        Some(p) => p,
        None => {
            error!("Provisioning service not initialized");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "Provisioning service not available" })),
            )
                .into_response();
        }
    };

    match provisioning.handle_checkin(&checkin).await {
        Ok(response) => {
            info!(
                machine_id = %response.machine_id,
                is_new = response.is_new,
                action = ?response.action,
                "Agent check-in successful"
            );

            // Emit machine_updated event to trigger UI refresh
            // This is critical for auto-updating the UI when machines transition
            // from Installing to Installed (or any other state change from agent check-in)
            let _ = state
                .event_manager
                .send(format!("machine_updated:{}", response.machine_id));

            Json(response).into_response()
        }
        Err(e) => {
            error!(error = %e, mac = %checkin.mac, "Agent check-in failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// Get workflow by ID for agent execution
pub async fn get_workflow_handler(
    State(state): State<crate::AppState>,
    Path(workflow_id): Path<String>,
) -> Response {
    debug!(workflow_id = %workflow_id, "Fetching workflow for agent");

    // Parse workflow ID as UUID
    let workflow_uuid = match Uuid::parse_str(&workflow_id) {
        Ok(uuid) => uuid,
        Err(e) => {
            warn!(workflow_id = %workflow_id, error = %e, "Invalid workflow UUID");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid workflow ID format" })),
            )
                .into_response();
        }
    };

    // Fetch workflow from store
    match state.store.get_workflow(workflow_uuid).await {
        Ok(Some(workflow)) => {
            info!(workflow_id = %workflow_id, "Returning workflow to agent");
            Json(workflow).into_response()
        }
        Ok(None) => {
            warn!(workflow_id = %workflow_id, "Workflow not found");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Workflow not found" })),
            )
                .into_response()
        }
        Err(e) => {
            error!(error = %e, workflow_id = %workflow_id, "Failed to fetch workflow");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// Query parameters for template handler
#[derive(Debug, Deserialize)]
pub struct TemplateQuery {
    /// Optional machine ID for machine-specific variable substitution
    pub machine_id: Option<String>,
}

/// Get template by name for agent execution
///
/// Templates define the actions to execute for OS installation.
/// Templates are stored in the database and loaded from YAML files on startup.
/// Template variables {{ ssh_authorized_keys }}, {{ ssh_import_id }}, {{ default_user }},
/// {{ friendly_name }}, and {{ instance_id }} are substituted before returning the template.
/// Generate cloud-init v2 network-config for template substitution.
///
/// This produces YAML that goes into `/var/lib/cloud/seed/nocloud/network-config`.
/// Cloud-init renders it to the distro's native format (ifupdown on Debian, Netplan on Ubuntu).
fn generate_network_config(machine: &dragonfly_common::Machine) -> String {
    use dragonfly_common::NetworkMode;

    let mode = &machine.config.network_mode;
    let nameservers = &machine.config.nameservers;
    let domain = machine.config.domain.as_deref().unwrap_or("");

    match mode {
        NetworkMode::Dhcp => {
            "version: 2\nethernets:\n  id0:\n    match:\n      name: e*\n    dhcp4: true"
                .to_string()
        }
        NetworkMode::DhcpStaticDns => {
            let mut cfg =
                "version: 2\nethernets:\n  id0:\n    match:\n      name: e*\n    dhcp4: true"
                    .to_string();
            if !nameservers.is_empty() {
                cfg.push_str("\n    nameservers:\n      addresses:");
                for ns in nameservers {
                    cfg.push_str(&format!("\n        - {}", ns));
                }
                if !domain.is_empty() {
                    cfg.push_str(&format!("\n      search:\n        - {}", domain));
                }
            }
            cfg
        }
        NetworkMode::StaticIpv4 => {
            let c = machine.config.static_ipv4.as_ref();
            let addr = c.map(|c| c.address.as_str()).unwrap_or("192.168.1.100");
            let prefix = c.map(|c| c.prefix_len).unwrap_or(24);
            let gw = c
                .and_then(|c| c.gateway.as_deref())
                .unwrap_or("192.168.1.1");

            let mut cfg = format!(
                "version: 2\nethernets:\n  id0:\n    match:\n      name: e*\n    addresses:\n      - {}/{}\n    routes:\n      - to: default\n        via: {}",
                addr, prefix, gw
            );
            append_nameservers(&mut cfg, nameservers, domain);
            cfg
        }
        NetworkMode::StaticIpv6 => {
            let c = machine.config.static_ipv6.as_ref();
            let addr = c.map(|c| c.address.as_str()).unwrap_or("::1");
            let prefix = c.map(|c| c.prefix_len).unwrap_or(64);
            let gw = c.and_then(|c| c.gateway.as_deref());

            let mut cfg = format!(
                "version: 2\nethernets:\n  id0:\n    match:\n      name: e*\n    addresses:\n      - {}/{}",
                addr, prefix
            );
            if let Some(gw) = gw {
                cfg.push_str(&format!(
                    "\n    routes:\n      - to: default\n        via: {}",
                    gw
                ));
            }
            append_nameservers(&mut cfg, nameservers, domain);
            cfg
        }
        NetworkMode::StaticDualStack => {
            let v4 = machine.config.static_ipv4.as_ref();
            let v6 = machine.config.static_ipv6.as_ref();
            let v4_addr = v4.map(|c| c.address.as_str()).unwrap_or("192.168.1.100");
            let v4_prefix = v4.map(|c| c.prefix_len).unwrap_or(24);
            let v4_gw = v4
                .and_then(|c| c.gateway.as_deref())
                .unwrap_or("192.168.1.1");
            let v6_addr = v6.map(|c| c.address.as_str()).unwrap_or("::1");
            let v6_prefix = v6.map(|c| c.prefix_len).unwrap_or(64);
            let v6_gw = v6.and_then(|c| c.gateway.as_deref());

            let mut cfg = format!(
                "version: 2\nethernets:\n  id0:\n    match:\n      name: e*\n    addresses:\n      - {}/{}\n      - {}/{}",
                v4_addr, v4_prefix, v6_addr, v6_prefix
            );
            cfg.push_str(&format!(
                "\n    routes:\n      - to: default\n        via: {}",
                v4_gw
            ));
            if let Some(gw) = v6_gw {
                cfg.push_str(&format!("\n      - to: default\n        via: {}", gw));
            }
            append_nameservers(&mut cfg, nameservers, domain);
            cfg
        }
    }
}

/// Helper: append nameservers + search domain to a cloud-init v2 network config string
fn append_nameservers(cfg: &mut String, nameservers: &[String], domain: &str) {
    if !nameservers.is_empty() {
        cfg.push_str("\n    nameservers:\n      addresses:");
        for ns in nameservers {
            cfg.push_str(&format!("\n        - {}", ns));
        }
        if !domain.is_empty() {
            cfg.push_str(&format!("\n      search:\n        - {}", domain));
        }
    }
}

///
/// If `machine_id` query param is provided, machine-specific variables are substituted:
/// - {{ friendly_name }} = hostname (if set) or memorable_name
/// - {{ instance_id }} = machine UUID
pub async fn get_template_handler(
    State(state): State<crate::AppState>,
    Path(template_name): Path<String>,
    Query(query): Query<TemplateQuery>,
) -> Response {
    debug!(template_name = %template_name, machine_id = ?query.machine_id, "Fetching template for agent");

    // Fetch settings for template variable substitution
    let ssh_keys = state
        .store
        .get_setting("ssh_keys")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let ssh_key_subscriptions = state
        .store
        .get_setting("ssh_key_subscriptions")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "[]".to_string());
    let default_user = state
        .store
        .get_setting("default_user")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "root".to_string());
    let default_password_raw = state
        .store
        .get_setting("default_password")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    // Determine ssh_pwauth based on whether password is set
    // If password is empty, use locked password ("!") to prevent passwordless login
    let ssh_pwauth = !default_password_raw.is_empty();
    let default_password = if default_password_raw.is_empty() {
        "!".to_string() // Locked password - no login possible
    } else {
        default_password_raw
    };

    // Parse subscriptions: GitHub/GitLab → ssh_import_id, URL → fetch keys now
    let mut import_ids: Vec<String> = Vec::new();
    let mut url_subscription_keys: Vec<String> = Vec::new();
    if let Ok(subs) = serde_json::from_str::<Vec<serde_json::Value>>(&ssh_key_subscriptions) {
        for sub in subs {
            if let (Some(sub_type), Some(value)) = (
                sub.get("type").and_then(|t| t.as_str()),
                sub.get("value").and_then(|v| v.as_str()),
            ) {
                match sub_type {
                    "github" => {
                        import_ids.push(format!("gh:{}", value));
                        // Also fetch actual keys — ssh-import-id only exists on Debian/Ubuntu
                        let keys_url = format!("https://github.com/{}.keys", value);
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(10))
                            .build()
                            .unwrap_or_default();
                        match client.get(&keys_url).send().await {
                            Ok(response) if response.status().is_success() => {
                                if let Ok(keys_text) = response.text().await {
                                    let mut count = 0u32;
                                    for line in keys_text.lines() {
                                        let key = line.trim();
                                        if !key.is_empty() && !key.starts_with('#') {
                                            url_subscription_keys.push(key.to_string());
                                            count += 1;
                                        }
                                    }
                                    info!(github_user = %value, keys_count = count, "Fetched SSH keys from GitHub");
                                }
                            }
                            Ok(response) => {
                                warn!(github_user = %value, status = %response.status(), "Failed to fetch GitHub keys (ssh-import-id fallback will be used)");
                            }
                            Err(e) => {
                                warn!(github_user = %value, error = %e, "Failed to fetch GitHub keys (ssh-import-id fallback will be used)");
                            }
                        }
                    }
                    "gitlab" => {
                        import_ids.push(format!("gl:{}", value));
                        // Also fetch actual keys — ssh-import-id only exists on Debian/Ubuntu
                        let keys_url = format!("https://gitlab.com/{}.keys", value);
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(10))
                            .build()
                            .unwrap_or_default();
                        match client.get(&keys_url).send().await {
                            Ok(response) if response.status().is_success() => {
                                if let Ok(keys_text) = response.text().await {
                                    let mut count = 0u32;
                                    for line in keys_text.lines() {
                                        let key = line.trim();
                                        if !key.is_empty() && !key.starts_with('#') {
                                            url_subscription_keys.push(key.to_string());
                                            count += 1;
                                        }
                                    }
                                    info!(gitlab_user = %value, keys_count = count, "Fetched SSH keys from GitLab");
                                }
                            }
                            Ok(response) => {
                                warn!(gitlab_user = %value, status = %response.status(), "Failed to fetch GitLab keys (ssh-import-id fallback will be used)");
                            }
                            Err(e) => {
                                warn!(gitlab_user = %value, error = %e, "Failed to fetch GitLab keys (ssh-import-id fallback will be used)");
                            }
                        }
                    }
                    "url" => {
                        // Fetch keys from URL subscription at provisioning time
                        let url = sub.get("url").and_then(|u| u.as_str()).unwrap_or(value);
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(10))
                            .build()
                            .unwrap_or_default();
                        match client.get(url).send().await {
                            Ok(response) if response.status().is_success() => {
                                match response.text().await {
                                    Ok(keys_text) => {
                                        let mut count = 0u32;
                                        for line in keys_text.lines() {
                                            let key = line.trim();
                                            if !key.is_empty() && !key.starts_with('#') {
                                                url_subscription_keys.push(key.to_string());
                                                count += 1;
                                            }
                                        }
                                        info!(url = %url, keys_count = count, "Fetched SSH keys from URL subscription");
                                    }
                                    Err(e) => {
                                        warn!(url = %url, error = %e, "Failed to read SSH keys from URL subscription");
                                    }
                                }
                            }
                            Ok(response) => {
                                warn!(url = %url, status = %response.status(), "URL subscription returned non-success status");
                            }
                            Err(e) => {
                                warn!(url = %url, error = %e, "Failed to fetch SSH keys from URL subscription (will retry next provisioning)");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Format ssh_import_id as YAML array value — now inside user entry at 4-space indent,
    // so list items go at 6-space indent
    let ssh_import_id_yaml = if import_ids.is_empty() {
        "[]".to_string()
    } else {
        let ids: String = import_ids
            .iter()
            .map(|id| format!("\n      - {}", id))
            .collect::<Vec<_>>()
            .join("");
        ids
    };

    // Format ssh_authorized_keys as YAML array value (templates have "ssh_authorized_keys: {{ ssh_authorized_keys }}")
    // Deduplicate by key identity (type + base64data), ignoring comment field
    let mut seen_identities: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut direct_keys: Vec<&str> = Vec::new();
    for line in ssh_keys.lines() {
        let key = line.trim();
        if key.is_empty() || key.starts_with('#') {
            continue;
        }
        let identity: String = key.splitn(3, ' ').take(2).collect::<Vec<_>>().join(" ");
        if seen_identities.insert(identity) {
            direct_keys.push(key);
        }
    }
    // Merge keys fetched from URL subscriptions (also deduplicated)
    for key in &url_subscription_keys {
        let identity: String = key.splitn(3, ' ').take(2).collect::<Vec<_>>().join(" ");
        if seen_identities.insert(identity) {
            direct_keys.push(key.as_str());
        }
    }
    let ssh_authorized_keys_yaml = if direct_keys.is_empty() {
        "[]".to_string()
    } else {
        // Multiline array format: ssh_authorized_keys is at 4-space indent (inside users list entry),
        // so list items go at 6-space indent
        let keys: String = direct_keys
            .iter()
            .map(|k| format!("\n      - \"{}\"", k))
            .collect::<Vec<_>>()
            .join("");
        keys
    };

    // Default cloud-init v2 network config (DHCP)
    let default_network_config =
        "version: 2\nethernets:\n  id0:\n    match:\n      name: e*\n    dhcp4: true".to_string();

    // Fetch machine-specific variables if machine_id is provided
    let (friendly_name, instance_id, network_config_cloudinit) = if let Some(ref machine_id_str) =
        query.machine_id
    {
        match Uuid::parse_str(machine_id_str) {
            Ok(machine_uuid) => {
                match state.store.get_machine(machine_uuid).await {
                    Ok(Some(machine)) => {
                        // Priority: hostname (user-set) > memorable_name (auto-generated) > "localhost"
                        let name = machine
                            .config
                            .hostname
                            .clone()
                            .unwrap_or_else(|| machine.config.memorable_name.clone());
                        let name = if name.is_empty() || name == "localhost" {
                            machine.config.memorable_name.clone()
                        } else {
                            name
                        };
                        info!(
                            machine_id = %machine_uuid,
                            friendly_name = %name,
                            network_mode = ?machine.config.network_mode,
                            "Using machine-specific config for template"
                        );

                        let net_cfg = generate_network_config(&machine);
                        (name, machine_uuid.to_string(), net_cfg)
                    }
                    Ok(None) => {
                        warn!(machine_id = %machine_id_str, "Machine not found, using defaults");
                        (
                            "localhost".to_string(),
                            machine_id_str.clone(),
                            default_network_config.clone(),
                        )
                    }
                    Err(e) => {
                        warn!(machine_id = %machine_id_str, error = %e, "Failed to fetch machine, using defaults");
                        (
                            "localhost".to_string(),
                            machine_id_str.clone(),
                            default_network_config.clone(),
                        )
                    }
                }
            }
            Err(e) => {
                warn!(machine_id = %machine_id_str, error = %e, "Invalid machine UUID, using defaults");
                (
                    "localhost".to_string(),
                    machine_id_str.clone(),
                    default_network_config.clone(),
                )
            }
        }
    } else {
        // No machine_id provided - use placeholder values
        (
            "localhost".to_string(),
            "00000000-0000-0000-0000-000000000000".to_string(),
            default_network_config,
        )
    };

    // Fetch template from store
    match state.store.get_template(&template_name).await {
        Ok(Some(mut template)) => {
            // Substitute template variables in writefile actions
            for action in &mut template.spec.actions {
                if let dragonfly_crd::ActionStep::Writefile(cfg) = action {
                    if let Some(content) = &mut cfg.content {
                        *content = content
                            .replace("{{ default_user }}", &default_user)
                            .replace("{{ default_password }}", &default_password)
                            .replace("{{ ssh_pwauth }}", &ssh_pwauth.to_string())
                            .replace("{{ ssh_authorized_keys }}", &ssh_authorized_keys_yaml)
                            .replace("{{ ssh_import_id }}", &ssh_import_id_yaml)
                            .replace("{{ friendly_name }}", &friendly_name)
                            .replace("{{ instance_id }}", &instance_id)
                            .replace("{{ network_config_cloudinit }}", &network_config_cloudinit);
                    }
                }
            }

            // JIT conversion: convert QCOW2 images to raw and rewrite URLs
            // This blocks until conversion is complete (or returns cached URL immediately)
            if let Err(e) =
                crate::image_cache::rewrite_template_urls(&mut template, &state.image_cache).await
            {
                error!(template_name = %template_name, error = %e, "Failed to rewrite image URLs");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("Image conversion failed: {}", e) })),
                )
                    .into_response();
            }

            // Check if auto-enroll with Spark is enabled
            // If so, append efibootmgr action to set PXE as first boot option
            let auto_enroll = state
                .store
                .get_setting("auto_enroll_with_spark")
                .await
                .ok()
                .flatten()
                .map(|s| s == "true")
                .unwrap_or(false);

            if auto_enroll {
                info!(template_name = %template_name, "Auto-enroll enabled: inserting boot order actions before final boot action");
                // Find the position of the last kexec/reboot action and insert before it
                let boot_action_idx = template.spec.actions.iter().rposition(|a| {
                    matches!(
                        a,
                        dragonfly_crd::ActionStep::Kexec(_) | dragonfly_crd::ActionStep::Reboot(_)
                    )
                });

                let insert_pos = boot_action_idx.unwrap_or(template.spec.actions.len());

                // Insert seabios first (it will end up after efibootmgr)
                template.spec.actions.insert(
                    insert_pos,
                    dragonfly_crd::ActionStep::Seabios(dragonfly_crd::SeabiosConfig::default()),
                );
                // Insert efibootmgr before seabios
                template.spec.actions.insert(
                    insert_pos,
                    dragonfly_crd::ActionStep::Efibootmgr(
                        dragonfly_crd::EfibootmgrConfig::default(),
                    ),
                );
            }

            info!(
                template_name = %template_name,
                actions_count = template.spec.actions.len(),
                action_names = ?template.action_names(),
                ssh_keys_count = direct_keys.len(),
                ssh_import_ids = ?import_ids,
                auto_enroll = auto_enroll,
                "Returning template to agent with injected SSH config"
            );
            // Debug: log raw JSON being sent
            if let Ok(json) = serde_json::to_string(&template) {
                debug!(json_length = json.len(), "Template JSON payload");
            }
            Json(template).into_response()
        }
        Ok(None) => {
            warn!(template_name = %template_name, "Template not found");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("Template not found: {}", template_name) })),
            ).into_response()
        }
        Err(e) => {
            error!(template_name = %template_name, error = %e, "Failed to fetch template");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to fetch template" })),
            )
                .into_response()
        }
    }
}

/// Workflow event data from agent
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // Fields are populated by deserialization but not all are read
pub struct WorkflowEventPayload {
    #[serde(rename = "type")]
    pub event_type: String,
    pub workflow: Option<String>,
    pub action: Option<String>,
    pub progress: Option<WorkflowProgress>,
    pub success: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // Fields are populated by deserialization but not all are read
pub struct WorkflowProgress {
    pub percent: u8,
    pub message: String,
    pub bytes_transferred: Option<u64>,
    pub bytes_total: Option<u64>,
    pub eta_secs: Option<u64>,
    pub phase: Option<String>,
    pub phase_number: Option<u32>,
    pub total_phases: Option<u32>,
}

/// Receive workflow events from agent for real-time UI updates
///
/// The agent POSTs progress events here as it executes workflow actions.
/// We broadcast them via SSE so the UI can show real-time progress.
pub async fn workflow_events_handler(
    State(state): State<crate::AppState>,
    Path(workflow_id): Path<String>,
    Json(event): Json<WorkflowEventPayload>,
) -> Response {
    debug!(
        workflow_id = %workflow_id,
        event_type = %event.event_type,
        "Received workflow event from agent"
    );

    // Look up the workflow to get the machine_id (hardware_ref)
    let machine_id = if let Ok(wf_uuid) = uuid::Uuid::parse_str(&workflow_id) {
        match state.store.get_workflow(wf_uuid).await {
            Ok(Some(wf)) => {
                debug!(workflow_id = %workflow_id, hardware_ref = %wf.spec.hardware_ref, "Found workflow");
                Some(wf.spec.hardware_ref.clone())
            }
            Ok(None) => {
                warn!(workflow_id = %workflow_id, "Workflow not found in store");
                None
            }
            Err(e) => {
                warn!(workflow_id = %workflow_id, error = %e, "Error looking up workflow");
                None
            }
        }
    } else {
        warn!(workflow_id = %workflow_id, "Invalid workflow ID format (not a UUID)");
        None
    };

    // Update machine's installation_progress if this is a progress event
    if event.event_type == "action_progress" {
        if let (Some(mid), Some(progress)) = (&machine_id, &event.progress) {
            if let Ok(machine_uuid) = uuid::Uuid::parse_str(mid) {
                if let Ok(Some(mut machine)) = state.store.get_machine(machine_uuid).await {
                    // Don't update progress if machine is already Installed or at 100% (prevents race with kexec)
                    if matches!(
                        machine.status.state,
                        dragonfly_common::MachineState::Installed
                    ) || machine.config.installation_progress >= 100
                    {
                        // Machine already marked as installed or at 100%, skip progress update
                    } else {
                        // Normalize per-action progress to overall workflow progress
                        let action_name = event.action.as_deref().unwrap_or("unknown");
                        let normalized_progress =
                            normalize_workflow_progress(action_name, progress.percent);

                        // Only update if progress moved forward (strict - never overwrite same value)
                        if normalized_progress > machine.config.installation_progress {
                            machine.config.installation_progress = normalized_progress;
                            machine.config.installation_step = Some(progress.message.clone());
                            machine.metadata.updated_at = chrono::Utc::now();

                            // Transition from Initializing to Installing when we start receiving progress
                            if matches!(
                                machine.status.state,
                                dragonfly_common::MachineState::Initializing
                            ) {
                                machine.status.state = dragonfly_common::MachineState::Installing;
                            }

                            // Re-check: is the workflow already completed?
                            // The action_started handler for reboot/kexec marks the workflow
                            // as StateSuccess BEFORE marking the machine as Installed.
                            // So checking workflow state catches the race reliably — by the
                            // time we get here, put_workflow has committed even if put_machine
                            // hasn't yet. This prevents stale writefile progress events from
                            // overwriting machine state back to Installing.
                            let workflow_done =
                                if let Ok(wf_uuid) = uuid::Uuid::parse_str(&workflow_id) {
                                    if let Ok(Some(wf)) = state.store.get_workflow(wf_uuid).await {
                                        matches!(
                                            wf.status.as_ref().map(|s| &s.state),
                                            Some(dragonfly_crd::WorkflowState::StateSuccess)
                                                | Some(dragonfly_crd::WorkflowState::StateFailed)
                                        )
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                            // Also re-check machine state as a secondary guard
                            let machine_done = if let Ok(Some(current)) =
                                state.store.get_machine(machine_uuid).await
                            {
                                matches!(
                                    current.status.state,
                                    dragonfly_common::MachineState::Installed
                                ) || current.config.installation_progress > normalized_progress
                            } else {
                                false
                            };

                            let should_save = !workflow_done && !machine_done;

                            if should_save {
                                let _ = state.store.put_machine(&machine).await;
                            } else {
                                debug!(
                                    machine_id = %mid,
                                    action = %action_name,
                                    workflow_done = %workflow_done,
                                    machine_done = %machine_done,
                                    "Discarding stale progress event (installation already finalized)"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Build event message for SSE broadcast - include machine_id for UI updates
    let mid_str = machine_id.as_deref().unwrap_or("unknown");
    let event_message = match event.event_type.as_str() {
        "action_progress" => {
            if let Some(progress) = &event.progress {
                // Normalize per-action progress to overall workflow progress for SSE too
                let action_name = event.action.as_deref().unwrap_or("unknown");
                let normalized_percent = normalize_workflow_progress(action_name, progress.percent);

                // Send JSON payload with event_type: prefix for SSE handler
                let json_payload = serde_json::json!({
                    "workflow_id": workflow_id,
                    "machine_id": mid_str,
                    "action": action_name,
                    "percent": normalized_percent,
                    "message": progress.message,
                    "bytes_transferred": progress.bytes_transferred.unwrap_or(0),
                    "bytes_total": progress.bytes_total.unwrap_or(0)
                });
                format!("workflow_progress:{}", json_payload)
            } else {
                format!(
                    "workflow_progress:{{\"workflow_id\":\"{}\",\"machine_id\":\"{}\",\"action\":\"unknown\",\"percent\":0,\"message\":\"No progress data\",\"bytes_transferred\":0,\"bytes_total\":0}}",
                    workflow_id, mid_str
                )
            }
        }
        "started" => {
            // Update workflow state to Running in the store
            if let Ok(wf_uuid) = uuid::Uuid::parse_str(&workflow_id) {
                if let Ok(Some(mut wf)) = state.store.get_workflow(wf_uuid).await {
                    if let Some(ref mut status) = wf.status {
                        status.state = dragonfly_crd::WorkflowState::StateRunning;
                        status.started_at = Some(chrono::Utc::now());
                    } else {
                        wf.status = Some(dragonfly_crd::WorkflowStatus {
                            state: dragonfly_crd::WorkflowState::StateRunning,
                            started_at: Some(chrono::Utc::now()),
                            ..Default::default()
                        });
                    }
                    let _ = state.store.put_workflow(&wf).await;
                    debug!(workflow_id = %workflow_id, "Workflow state updated to Running");
                }
            }
            format!("workflow_started:{}:{}", workflow_id, mid_str)
        }
        "action_started" => {
            let action_name = event.action.as_deref().unwrap_or("unknown");

            // When kexec or reboot action STARTS, mark machine as Installed AND workflow as complete
            // The machine WILL reboot and we may never get completion event
            if action_name == "kexec" || action_name == "reboot" {
                // Mark workflow as complete in the store FIRST
                // This prevents the reimage loop: without this, the workflow stays
                // StatePending/Running and the next check-in would re-execute it
                if let Ok(wf_uuid) = uuid::Uuid::parse_str(&workflow_id) {
                    if let Ok(Some(mut wf)) = state.store.get_workflow(wf_uuid).await {
                        if let Some(ref mut status) = wf.status {
                            status.state = dragonfly_crd::WorkflowState::StateSuccess;
                            status.completed_at = Some(chrono::Utc::now());
                        }
                        let _ = state.store.put_workflow(&wf).await;
                        info!(workflow_id = %workflow_id, "Workflow marked as Success (final boot action starting)");
                    }
                }

                // Mark machine as Installed
                // Guard: skip if already Installed (duplicate event from async reporter
                // after the synchronous notification from reboot.rs already processed this).
                // Without this guard, the second event reads os_choice=None (already cleared)
                // and overwrites os_installed with None, wiping the installed OS name.
                if let Some(mid) = &machine_id {
                    if let Ok(machine_uuid) = uuid::Uuid::parse_str(mid) {
                        if let Ok(Some(mut machine)) = state.store.get_machine(machine_uuid).await {
                            if matches!(
                                machine.status.state,
                                dragonfly_common::MachineState::Installed
                            ) {
                                debug!(
                                    machine_id = %mid,
                                    action = %action_name,
                                    "Machine already Installed - skipping duplicate action_started event"
                                );
                            } else {
                                info!(
                                    machine_id = %mid,
                                    action = %action_name,
                                    "Final boot action starting - marking machine as Installed NOW"
                                );
                                machine.status.state = dragonfly_common::MachineState::Installed;
                                machine.config.installation_progress = 100;
                                machine.config.installation_step =
                                    Some("Installation complete".to_string());
                                machine.config.reimage_requested = false;
                                machine.config.os_installed = machine.config.os_choice.clone();
                                machine.config.os_choice = None;
                                machine.metadata.updated_at = chrono::Utc::now();
                                let _ = state.store.put_machine(&machine).await;
                                let _ =
                                    state.event_manager.send(format!("machine_updated:{}", mid));
                            }
                        }
                    }
                }
            }

            format!("action_started:{}:{}:{}", workflow_id, mid_str, action_name)
        }
        "action_completed" => {
            let action_name = event.action.as_deref().unwrap_or("unknown");
            let success = event.success.unwrap_or(false);

            // If kexec/reboot completed successfully, mark machine as Installed NOW
            // (the machine may never PXE boot again if it boots from local disk)
            // Guard: skip if already Installed (action_started already handled this)
            if (action_name == "kexec" || action_name == "reboot") && success {
                if let Some(mid) = &machine_id {
                    if let Ok(machine_uuid) = uuid::Uuid::parse_str(mid) {
                        match state.store.get_machine(machine_uuid).await {
                            Ok(Some(mut machine)) => {
                                if matches!(
                                    machine.status.state,
                                    dragonfly_common::MachineState::Installed
                                ) {
                                    debug!(
                                        machine_id = %mid,
                                        action = %action_name,
                                        "Machine already Installed - skipping duplicate action_completed event"
                                    );
                                } else {
                                    info!(
                                        machine_id = %mid,
                                        current_state = ?machine.status.state,
                                        "Final boot action completed - marking machine as Installed"
                                    );
                                    machine.status.state =
                                        dragonfly_common::MachineState::Installed;
                                    machine.config.installation_progress = 100;
                                    machine.config.installation_step =
                                        Some("Installation complete".to_string());
                                    machine.config.reimage_requested = false;
                                    machine.config.os_installed = machine.config.os_choice.clone();
                                    machine.config.os_choice = None;
                                    machine.metadata.updated_at = chrono::Utc::now();
                                    let _ = state.store.put_machine(&machine).await;
                                    let _ = state
                                        .event_manager
                                        .send(format!("machine_updated:{}", mid));
                                }
                            }
                            Ok(None) => {
                                warn!(machine_id = %mid, "Machine not found when handling boot action completion");
                            }
                            Err(e) => {
                                warn!(machine_id = %mid, error = %e, "Error getting machine for boot action completion");
                            }
                        }
                    }
                }
            }

            format!(
                "action_completed:{}:{}:{}:{}",
                workflow_id, mid_str, action_name, success
            )
        }
        "completed" => {
            let success = event.success.unwrap_or(false);
            info!(
                workflow_id = %workflow_id,
                machine_id = %mid_str,
                success = success,
                "Workflow completed"
            );

            // Update workflow state in the store
            if let Ok(wf_uuid) = uuid::Uuid::parse_str(&workflow_id) {
                if let Ok(Some(mut wf)) = state.store.get_workflow(wf_uuid).await {
                    if let Some(ref mut status) = wf.status {
                        status.state = if success {
                            dragonfly_crd::WorkflowState::StateSuccess
                        } else {
                            dragonfly_crd::WorkflowState::StateFailed
                        };
                        status.completed_at = Some(chrono::Utc::now());
                    }
                    let _ = state.store.put_workflow(&wf).await;
                    debug!(workflow_id = %workflow_id, success = success, "Workflow state updated in store");
                }
            }

            // Mark machine as Installed when workflow completes successfully
            // Guard: skip if already Installed (action_started for reboot/kexec already
            // handled this). Without this guard, os_choice is already None (cleared by
            // action_started), so os_installed gets overwritten with None → "no OS yet".
            if success {
                if let Some(mid) = &machine_id {
                    if let Ok(machine_uuid) = uuid::Uuid::parse_str(mid) {
                        if let Ok(Some(mut machine)) = state.store.get_machine(machine_uuid).await {
                            if matches!(
                                machine.status.state,
                                dragonfly_common::MachineState::Installed
                            ) {
                                debug!(
                                    machine_id = %mid,
                                    "Machine already Installed - skipping duplicate completed event"
                                );
                            } else {
                                info!(
                                    machine_id = %mid,
                                    "Workflow completed successfully - marking machine as Installed"
                                );
                                machine.status.state = dragonfly_common::MachineState::Installed;
                                machine.config.installation_progress = 100;
                                machine.config.installation_step =
                                    Some("Installation complete".to_string());
                                machine.config.reimage_requested = false;
                                machine.config.os_installed = machine.config.os_choice.clone();
                                machine.config.os_choice = None;
                                // Cloud-init will apply the hostname we set, so mark it as reported
                                if let Some(ref hostname) = machine.config.hostname {
                                    info!(
                                        machine_id = %mid,
                                        hostname = %hostname,
                                        "Marking hostname as applied (cloud-init will set it)"
                                    );
                                    machine.config.reported_hostname = Some(hostname.clone());
                                }
                                machine.metadata.updated_at = chrono::Utc::now();
                                let _ = state.store.put_machine(&machine).await;
                            }
                        }
                    }
                }
            }

            // Emit machine_updated so UI refreshes the machine row
            let _ = state
                .event_manager
                .send(format!("machine_updated:{}", mid_str));
            format!("workflow_completed:{}:{}:{}", workflow_id, mid_str, success)
        }
        _ => format!(
            "workflow_event:{}:{}:{}",
            workflow_id, mid_str, event.event_type
        ),
    };

    // Broadcast to SSE subscribers
    let _ = state.event_manager.send(event_message);

    // Return success
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

// ============================================================================
// Spark Boot Agent
// ============================================================================

/// Spark ELF path - bare metal discovery agent (elf32 for BIOS iPXE)
const SPARK_ELF_PATH: &str = "/var/lib/dragonfly/spark.elf";
/// Spark ELF path - x86_64 variant for EFI iPXE
const SPARK_EFI_ELF_PATH: &str = "/var/lib/dragonfly/spark-efi.elf";
/// GRUB EFI shim - GRUB standalone with embedded Spark for EFI multiboot
const GRUB_SPARK_EFI_PATH: &str = "/var/lib/dragonfly/grub-spark.efi";
/// iPXE EFI binary - served via HTTP for UEFI HTTP Boot clients
const IPXE_EFI_PATH: &str = "/var/lib/dragonfly/tftp/ipxe.efi";

/// Memtest86+ binary path
const MEMTEST_PATH: &str = "/var/lib/dragonfly/boot/memtest86plus.bin";

/// GRUB chainloader path - provides framebuffer support for iPXE boot
const GRUB_CHAIN_PATH: &str = "/var/lib/dragonfly/grub-spark.0";

/// Serve Spark ELF binary for iPXE multiboot
///
/// Spark is the bare-metal discovery agent that:
/// - Detects hardware (CPU, memory, disks, NICs)
/// - Checks for existing bootable OS
/// - Reports to Dragonfly server
/// - Chainloads to Mage for imaging when needed
pub async fn serve_spark_elf() -> Response {
    let spark_path = std::path::Path::new(SPARK_ELF_PATH);

    if !spark_path.exists() {
        warn!("404 /boot/spark.elf: File not found at {:?}", spark_path);
        return (
            StatusCode::NOT_FOUND,
            "Spark ELF not found. Copy spark.elf to /var/lib/dragonfly/spark.elf",
        )
            .into_response();
    }

    match tokio::fs::read(spark_path).await {
        Ok(content) => {
            info!("200 /boot/spark.elf: Serving {} bytes", content.len());
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("500 /boot/spark.elf: Failed to read: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read Spark ELF: {}", e),
            )
                .into_response()
        }
    }
}

/// Serve Spark ELF (x86_64) for EFI iPXE multiboot
///
/// EFI iPXE cannot load elf32-i386 binaries — it needs the original
/// x86_64 ELF. Same kernel, different ELF header format.
pub async fn serve_spark_efi_elf() -> Response {
    let spark_path = std::path::Path::new(SPARK_EFI_ELF_PATH);

    if !spark_path.exists() {
        warn!("404 /boot/spark-efi.elf: File not found at {:?}", spark_path);
        return (
            StatusCode::NOT_FOUND,
            "Spark EFI ELF not found. Copy spark-efi.elf to /var/lib/dragonfly/spark-efi.elf",
        )
            .into_response();
    }

    match tokio::fs::read(spark_path).await {
        Ok(content) => {
            info!("200 /boot/spark-efi.elf: Serving {} bytes", content.len());
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("500 /boot/spark-efi.elf: Failed to read: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read Spark EFI ELF: {}", e),
            )
                .into_response()
        }
    }
}

/// Serve GRUB EFI shim for EFI PXE multiboot
///
/// EFI iPXE can't do multiboot2. This standalone GRUB EFI binary has
/// Spark embedded and boots it via multiboot2 after doing DHCP to
/// discover the Dragonfly server address.
pub async fn serve_grub_spark_efi() -> Response {
    let path = std::path::Path::new(GRUB_SPARK_EFI_PATH);

    if !path.exists() {
        warn!("404 /boot/grub-spark.efi: File not found at {:?}", path);
        return (
            StatusCode::NOT_FOUND,
            "GRUB Spark EFI not found. Build with: cd crates/dragonfly-spark && bash build.sh",
        )
            .into_response();
    }

    match tokio::fs::read(path).await {
        Ok(content) => {
            info!("200 /boot/grub-spark.efi: Serving {} bytes", content.len());
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("500 /boot/grub-spark.efi: Failed to read: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read GRUB Spark EFI: {}", e),
            )
                .into_response()
        }
    }
}

/// Serve iPXE EFI binary over HTTP for UEFI HTTP Boot
///
/// UEFI HTTP Boot clients download iPXE via HTTP instead of TFTP.
/// The DHCP server directs HTTPClient vendors to this URL.
/// Once iPXE loads, it does its own DHCP exchange and follows
/// the normal iPXE boot script flow.
pub async fn serve_ipxe_efi() -> Response {
    let path = std::path::Path::new(IPXE_EFI_PATH);

    if !path.exists() {
        warn!("404 /boot/ipxe.efi: File not found at {:?}", path);
        return (
            StatusCode::NOT_FOUND,
            "iPXE EFI not found. It should be downloaded automatically at startup.",
        )
            .into_response();
    }

    match tokio::fs::read(path).await {
        Ok(content) => {
            info!("200 /boot/ipxe.efi: Serving {} bytes (HTTP Boot)", content.len());
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/efi")],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("500 /boot/ipxe.efi: Failed to read: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read iPXE EFI: {}", e),
            )
                .into_response()
        }
    }
}

/// Serve memtest86+ binary for iPXE kernel boot
pub async fn serve_memtest() -> Response {
    let path = std::path::Path::new(MEMTEST_PATH);

    if !path.exists() {
        warn!("404 /boot/memtest86plus.bin: File not found at {:?}", path);
        return (
            StatusCode::NOT_FOUND,
            "memtest86plus.bin not found. Download from https://memtest.org and place in /var/lib/dragonfly/boot/",
        ).into_response();
    }

    match tokio::fs::read(path).await {
        Ok(content) => {
            info!(
                "200 /boot/memtest86plus.bin: Serving {} bytes",
                content.len()
            );
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("500 /boot/memtest86plus.bin: Failed to read: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read memtest86plus.bin: {}", e),
            )
                .into_response()
        }
    }
}

/// Serve PXELINUX bootloader
pub async fn serve_lpxelinux() -> Response {
    serve_static_file("/var/lib/dragonfly/lpxelinux.0", "lpxelinux.0").await
}

/// Serve ldlinux.c32 module
pub async fn serve_ldlinux() -> Response {
    serve_static_file("/var/lib/dragonfly/ldlinux.c32", "ldlinux.c32").await
}

/// Serve mboot.c32 multiboot module
pub async fn serve_mboot() -> Response {
    serve_static_file("/var/lib/dragonfly/mboot.c32", "mboot.c32").await
}

/// Serve libcom32.c32 library
pub async fn serve_libcom32() -> Response {
    serve_static_file("/var/lib/dragonfly/libcom32.c32", "libcom32.c32").await
}

async fn serve_static_file(file_path: &str, name: &str) -> Response {
    let path = std::path::Path::new(file_path);

    if !path.exists() {
        warn!("404 {}: Not found", name);
        return (StatusCode::NOT_FOUND, "File not found").into_response();
    }

    match tokio::fs::read(path).await {
        Ok(content) => {
            info!("200 {}: Serving {} bytes", name, content.len());
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("500 {}: Failed to read: {}", name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {}", e)).into_response()
        }
    }
}

/// Serve PXELINUX config file
pub async fn serve_pxelinux_config() -> Response {
    let config_path = "/var/lib/dragonfly/pxelinux.cfg/default";
    let path = std::path::Path::new(config_path);

    if !path.exists() {
        warn!("404 pxelinux.cfg/default: Not found");
        return (StatusCode::NOT_FOUND, "PXELINUX config not found").into_response();
    }

    match tokio::fs::read(path).await {
        Ok(content) => {
            info!("200 pxelinux.cfg/default: Serving {} bytes", content.len());
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("500 pxelinux.cfg/default: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {}", e)).into_response()
        }
    }
}

// ============================================================================
// Mage Boot Environment
// ============================================================================

/// Mage artifacts directory
const MAGE_DIR: &str = "/var/lib/dragonfly/mage";

/// Alpine mirror for netboot artifacts
const ALPINE_MIRROR: &str = "https://dl-cdn.alpinelinux.org/alpine";

/// Download Mage (Alpine netboot) artifacts
///
/// Downloads Alpine Linux netboot files for use as Dragonfly's boot environment:
/// - vmlinuz (kernel)
/// - initramfs (initial RAM filesystem)
/// - modloop (kernel modules squashfs)
///
/// # Arguments
/// * `alpine_version` - Alpine version (e.g., "3.21")
/// * `arch` - Architecture: "x86_64" or "aarch64"
pub async fn download_mage_artifacts(alpine_version: &str, arch: &str) -> anyhow::Result<()> {
    // Store in arch-specific subdirectory
    let mage_dir = FilePath::new(MAGE_DIR).join(arch);

    // Create directory if it doesn't exist
    if !mage_dir.exists() {
        info!("Creating Mage directory: {:?}", mage_dir);
        std::fs::create_dir_all(&mage_dir)?;
    }

    // Construct base URL for Alpine netboot
    let netboot_base = format!(
        "{}/v{}/releases/{}/netboot",
        ALPINE_MIRROR, alpine_version, arch
    );

    // Alpine netboot files (use -lts variants for LTS kernel)
    let files = vec![
        ("vmlinuz", "vmlinuz-lts"),
        ("initramfs", "initramfs-lts"),
        ("modloop", "modloop-lts"),
    ];

    info!(
        "Downloading Mage (Alpine {}) artifacts from {}",
        alpine_version, netboot_base
    );

    // Create download futures for parallel execution
    let download_futures = files
        .iter()
        .map(|(local_name, remote_name)| {
            let local_name = local_name.to_string();
            let remote_name = remote_name.to_string();
            let netboot_base = netboot_base.clone();
            let mage_dir = mage_dir.to_path_buf();

            async move {
                let dest_path = mage_dir.join(&local_name);

                // Skip if file already exists and has content
                if dest_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&dest_path) {
                        if metadata.len() > 0 {
                            info!(
                                "Mage artifact {} already exists, skipping download",
                                local_name
                            );
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                }

                // Try primary name first
                let url = format!("{}/{}", netboot_base, remote_name);
                info!("Downloading Mage artifact: {} -> {}", url, local_name);

                let response = reqwest::get(&url).await;

                match response {
                    Ok(resp) if resp.status().is_success() => {
                        let content = resp.bytes().await?;
                        if content.is_empty() {
                            anyhow::bail!("Downloaded {} is empty", local_name);
                        }
                        std::fs::write(&dest_path, &content)?;
                        info!("Downloaded {} ({} bytes)", local_name, content.len());
                    }
                    _ => {
                        // Try fallback name (vmlinuz-virt instead of vmlinuz-lts)
                        let fallback_name = remote_name.replace("-lts", "-virt");
                        let fallback_url = format!("{}/{}", netboot_base, fallback_name);
                        info!("Primary download failed, trying fallback: {}", fallback_url);

                        let fallback_resp = reqwest::get(&fallback_url).await?;
                        if !fallback_resp.status().is_success() {
                            anyhow::bail!(
                                "Failed to download {}: HTTP {}",
                                local_name,
                                fallback_resp.status()
                            );
                        }

                        let content = fallback_resp.bytes().await?;
                        if content.is_empty() {
                            anyhow::bail!("Downloaded {} is empty", local_name);
                        }
                        std::fs::write(&dest_path, &content)?;
                        info!(
                            "Downloaded {} from fallback ({} bytes)",
                            local_name,
                            content.len()
                        );
                    }
                }

                Ok(())
            }
        })
        .collect::<Vec<_>>();

    // Execute all downloads in parallel
    futures::future::try_join_all(download_futures).await?;

    info!("Mage artifacts downloaded successfully to {:?}", mage_dir);
    Ok(())
}

/// Verify that all required Mage boot artifacts exist and are non-empty
///
/// Checks that vmlinuz, initramfs, and modloop exist for each architecture.
/// Returns an error if any required file is missing or empty.
///
/// # Arguments
/// * `architectures` - Slice of architecture names to verify (e.g., &["x86_64", "aarch64"])
pub fn verify_mage_artifacts(architectures: &[&str]) -> anyhow::Result<()> {
    let required_files = ["vmlinuz", "initramfs", "modloop"];
    let mut missing = Vec::new();
    let mut empty = Vec::new();

    for arch in architectures {
        let mage_dir = FilePath::new(MAGE_DIR).join(arch);

        for file in &required_files {
            let file_path = mage_dir.join(file);

            if !file_path.exists() {
                missing.push(format!("{}/{}", arch, file));
            } else if let Ok(metadata) = std::fs::metadata(&file_path) {
                if metadata.len() == 0 {
                    empty.push(format!("{}/{}", arch, file));
                }
            }
        }
    }

    if !missing.is_empty() || !empty.is_empty() {
        let mut errors = Vec::new();
        if !missing.is_empty() {
            errors.push(format!("Missing Mage artifacts: {}", missing.join(", ")));
        }
        if !empty.is_empty() {
            errors.push(format!("Empty Mage artifacts: {}", empty.join(", ")));
        }
        anyhow::bail!("{}", errors.join("; "));
    }

    info!(
        "Verified all Mage artifacts exist for: {}",
        architectures.join(", ")
    );
    Ok(())
}

/// Generate Mage APK overlay with dragonfly-agent
///
/// Creates a localhost.apkovl.tar.gz file containing the agent and startup configuration
/// for the Mage boot environment.
///
/// # Arguments
/// * `base_url` - Dragonfly server URL for agent to connect to
/// * `arch` - Architecture: "x86_64" or "aarch64"
///
/// Uses the locally-built agent binary (no network download - supports airgapped environments)
pub async fn generate_mage_apkovl_arch(
    base_url: &str,
    arch: &str,
) -> Result<(), dragonfly_common::Error> {
    let mage_dir = FilePath::new(MAGE_DIR).join(arch);
    let target_path = mage_dir.join("localhost.apkovl.tar.gz");
    let agent_binary_path = mage_dir.join("dragonfly-agent");

    // Ensure Mage directory exists
    if !mage_dir.exists() {
        std::fs::create_dir_all(&mage_dir).map_err(|e| {
            dragonfly_common::Error::Internal(format!("Failed to create Mage directory: {}", e))
        })?;
    }

    // Check that agent binary exists (should be built by agent_build_fut)
    if !agent_binary_path.exists() {
        return Err(dragonfly_common::Error::Internal(format!(
            "Agent binary not found at {:?} - build failed?",
            agent_binary_path
        )));
    }

    // Generate APK overlay using local agent binary
    generate_agent_apkovl(
        &target_path,
        base_url,
        AgentSource::LocalPath(&agent_binary_path),
    )
    .await
}

/// Handler for /boot/{arch}/{asset} routes - extracts path parameters
pub async fn serve_boot_asset_handler(
    State(state): State<AppState>,
    axum::extract::Path((arch, asset)): axum::extract::Path<(String, String)>,
) -> Response {
    serve_boot_asset(&arch, &asset, &state).await
}

/// Serve boot assets (kernel, initramfs, modloop, apkovl) for a specific architecture
///
/// Maps URL paths to internal Mage files:
/// - /boot/{arch}/kernel -> vmlinuz
/// - /boot/{arch}/initramfs -> initramfs
/// - /boot/{arch}/modloop -> modloop
/// - /boot/{arch}/apkovl.tar.gz -> localhost.apkovl.tar.gz (dynamically generated)
pub async fn serve_boot_asset(arch: &str, asset: &str, state: &AppState) -> Response {
    // Normalize architecture names
    // - iPXE BIOS uses i386 (32-bit) but can boot x86_64 kernels
    // - iPXE EFI uses x86_64
    // - iPXE ARM uses arm64, we use aarch64 internally
    let normalized_arch = match arch {
        "x86_64" | "i386" => "x86_64", // BIOS iPXE reports i386, but boots x86_64 fine
        "aarch64" | "arm64" => "aarch64",
        _ => {
            warn!("404 /boot/{}/{}: Unknown architecture", arch, asset);
            return (
                StatusCode::NOT_FOUND,
                format!(
                    "Unknown architecture: {} (supported: x86_64, i386, aarch64, arm64)",
                    arch
                ),
            )
                .into_response();
        }
    };

    // Map URL names to internal file names
    let filename = match asset {
        "kernel" => "vmlinuz",
        "initramfs" => "initramfs",
        "modloop" => "modloop",
        "apkovl.tar.gz" => "localhost.apkovl.tar.gz",
        _ => {
            warn!("404 /boot/{}/{}: Unknown asset type", arch, asset);
            return (
                StatusCode::NOT_FOUND,
                format!("Unknown boot asset: {}", asset),
            )
                .into_response();
        }
    };

    let file_path = FilePath::new(MAGE_DIR).join(normalized_arch).join(filename);

    // Special handling for apkovl - generate dynamically if needed
    if asset == "apkovl.tar.gz" {
        let base_url = crate::mode::get_base_url(Some(state.store.as_ref())).await;
        let url_marker_path = file_path.with_extension("url");

        // Check if we need to regenerate
        let needs_regeneration = if file_path.exists() {
            match tokio::fs::read_to_string(&url_marker_path).await {
                Ok(stored_url) => stored_url.trim() != base_url,
                Err(_) => true,
            }
        } else {
            true
        };

        if needs_regeneration {
            info!(
                "Generating apkovl for {} with base_url: {}",
                normalized_arch, base_url
            );
            match generate_mage_apkovl_arch(&base_url, normalized_arch).await {
                Ok(()) => {
                    // Save URL marker
                    if let Err(e) = tokio::fs::write(&url_marker_path, &base_url).await {
                        warn!("Failed to write URL marker: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to generate apkovl: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to generate apkovl: {}", e),
                    )
                        .into_response();
                }
            }
        }
    }

    if !file_path.exists() {
        warn!(
            "404 /boot/{}/{}: File not found at {:?}",
            arch, asset, file_path
        );
        return (
            StatusCode::NOT_FOUND,
            format!(
                "Boot asset not found: {}/{} (run Flight mode setup first)",
                normalized_arch, asset
            ),
        )
            .into_response();
    }

    // Read file and serve
    match tokio::fs::read(&file_path).await {
        Ok(content) => {
            info!(
                "200 /boot/{}/{}: Serving {} bytes from {:?}",
                arch,
                asset,
                content.len(),
                file_path
            );
            let content_type = match asset {
                "apkovl.tar.gz" => "application/gzip",
                _ => "application/octet-stream",
            };
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, content_type)],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!(
                "500 /boot/{}/{}: Failed to read {:?}: {}",
                arch, asset, file_path, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read boot asset: {}", e),
            )
                .into_response()
        }
    }
}

/// Download iPXE binaries for PXE boot
///
/// Downloads:
/// - ipxe.efi (UEFI boot)
/// - undionly.kpxe (BIOS legacy boot)
///
/// Binaries are placed in /var/lib/dragonfly/tftp/ for the TFTP server.
pub async fn download_ipxe_binaries() -> anyhow::Result<()> {
    let tftp_dir = FilePath::new("/var/lib/dragonfly/tftp");

    // Create directory structure if it doesn't exist
    if !tftp_dir.exists() {
        info!("Creating TFTP directory: {:?}", tftp_dir);
        std::fs::create_dir_all(&tftp_dir)?;
    }

    // iPXE binaries to download from boot.ipxe.org
    let binaries = vec![
        ("ipxe.efi", "https://boot.ipxe.org/x86_64-efi/ipxe.efi"),
        ("undionly.kpxe", "https://boot.ipxe.org/undionly.kpxe"),
    ];

    // Create download futures for parallel execution
    let download_futures = binaries
        .iter()
        .map(|(filename, url)| {
            let filename = filename.to_string();
            let url = url.to_string();
            let tftp_dir = tftp_dir.to_path_buf();

            async move {
                let dest_path = tftp_dir.join(&filename);

                // Skip if file already exists and has content
                if dest_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(&dest_path) {
                        if metadata.len() > 0 {
                            info!("iPXE binary {} already exists, skipping download", filename);
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                }

                info!("Downloading {} from {}", filename, url);
                let response = reqwest::get(&url).await?;

                if !response.status().is_success() {
                    anyhow::bail!(
                        "Failed to download {}: HTTP {}",
                        filename,
                        response.status()
                    );
                }

                let content = response.bytes().await?;

                if content.is_empty() {
                    anyhow::bail!("Downloaded {} is empty", filename);
                }

                std::fs::write(&dest_path, &content)?;
                info!(
                    "Downloaded {} ({} bytes) to {:?}",
                    filename,
                    content.len(),
                    dest_path
                );

                Ok(())
            }
        })
        .collect::<Vec<_>>();

    // Execute all downloads in parallel
    futures::future::try_join_all(download_futures).await?;

    info!("iPXE binaries downloaded successfully to {:?}", tftp_dir);
    Ok(())
}

// ============================================================================
// OS Image Downloads (JIT)
// ============================================================================

/// OS images directory
const OS_IMAGES_DIR: &str = "/var/lib/dragonfly/os-images";

/// Serve OS image file
pub async fn serve_os_image(os: &str, arch: &str) -> Response {
    let path = match os {
        "debian-13" => {
            let filename = format!("debian-13-generic-{}.tar.xz", arch);
            FilePath::new(OS_IMAGES_DIR).join("debian").join(filename)
        }
        _ => {
            return (StatusCode::NOT_FOUND, "Unknown OS".to_string()).into_response();
        }
    };

    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            format!("OS image not downloaded. Use API to download first."),
        )
            .into_response();
    }

    match tokio::fs::read(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/x-xz")],
            content,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read: {}", e),
        )
            .into_response(),
    }
}

/// Serve cached image file (JIT-converted QCOW2 to raw)
pub async fn serve_cached_image(
    State(state): State<crate::AppState>,
    Path(name): Path<String>,
) -> Response {
    let cache_dir = state.image_cache.cache_dir();
    let path = cache_dir.join(&name);

    // Security: ensure the path stays within cache directory
    match path.canonicalize() {
        Ok(canonical) if canonical.starts_with(cache_dir) => {
            match tokio::fs::read(&canonical).await {
                Ok(content) => {
                    let content_type = if name.ends_with(".tar.zst") {
                        "application/zstd"
                    } else if name.ends_with(".tar.xz") {
                        "application/x-xz"
                    } else {
                        "application/octet-stream"
                    };
                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, content_type)],
                        content,
                    )
                        .into_response()
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                    StatusCode::NOT_FOUND,
                    format!("Cached image not found: {}", name),
                )
                    .into_response(),
                Err(e) => {
                    error!(name = %name, error = %e, "Failed to read cached image");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to read: {}", e),
                    )
                        .into_response()
                }
            }
        }
        Ok(_) => {
            warn!(name = %name, "Path traversal attempt detected");
            (StatusCode::BAD_REQUEST, "Invalid path").into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            format!("Cached image not found: {}", name),
        )
            .into_response(),
        Err(e) => {
            error!(name = %name, error = %e, "Failed to resolve cached image path");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to resolve path: {}", e),
            )
                .into_response()
        }
    }
}

// OS information struct
#[derive(Debug, Clone, serde::Serialize)]
pub struct OsInfo {
    pub name: String,
    pub icon: String,
}

// Get OS icon for a specific OS
pub fn get_os_icon(os: &str) -> String {
    let os_lower = os.to_lowercase();
    match os_lower.as_str() {
        os if os.contains("ubuntu") => {
            "<i class=\"fab fa-ubuntu text-orange-500 dark:text-orange-500 no-invert\"></i>"
        }
        os if os.contains("debian") => "<i class=\"fab fa-debian text-red-500\"></i>",
        "proxmox" => "<i class=\"fas fa-server text-blue-500\"></i>",
        os if os.contains("windows") => "<i class=\"fab fa-windows text-blue-400\"></i>",
        os if os.contains("rocky") => "<i class=\"fas fa-mountain text-green-500\"></i>",
        os if os.contains("fedora") => "<i class=\"fab fa-fedora text-blue-600\"></i>",
        os if os.contains("alma") => "<i class=\"fas fa-hat-cowboy text-amber-600\"></i>",
        _ => "<i class=\"fas fa-square-question text-gray-500\"></i>", // Unknown OS
    }
    .to_string()
}

// Make format_os_name public
pub fn format_os_name(os: &str) -> String {
    let os_lower = os.to_lowercase();

    // Handle Ubuntu formats
    if os_lower.contains("ubuntu") {
        if os_lower.contains("22.04") || os_lower.contains("2204") {
            return "Ubuntu 22.04".to_string();
        } else if os_lower.contains("24.04") || os_lower.contains("2404") {
            return "Ubuntu 24.04".to_string();
        } else if let Some(version) = os_lower
            .split(&['(', ')', ' ', '-', '_'][..])
            .find(|s| s.contains(".") && s.len() <= 6)
        {
            return format!("Ubuntu {}", version);
        } else {
            return "Ubuntu".to_string();
        }
    }

    // Handle Debian formats
    if os_lower.contains("debian") {
        if os_lower.contains("12") || os_lower.contains("bookworm") {
            return "Debian 12".to_string();
        } else if let Some(version) = os_lower
            .split(&[' ', '(', ')', '-', '_'][..])
            .find(|s| s.parse::<u32>().is_ok())
        {
            return format!("Debian {}", version);
        } else {
            return "Debian".to_string();
        }
    }

    // Handle specific formats
    match os_lower.as_str() {
        "ubuntu-2204" => "Ubuntu 22.04",
        "ubuntu-2404" => "Ubuntu 24.04",
        "debian-12" => "Debian 12",
        "proxmox" => "Proxmox VE",
        _ => os, // Return original string if no match
    }
    .to_string()
}

// Get both OS name and icon
pub fn get_os_info(os: &str) -> OsInfo {
    OsInfo {
        name: format_os_name(os),
        icon: get_os_icon(os),
    }
}

/// Normalize per-action progress (0-100) to overall workflow progress (0-100)
///
/// The workflow runs actions in order, each getting a slice of the overall progress:
/// - partition:   0% -  5% (quick disk setup)
/// - image2disk:  5% - 90% (bulk of the work - download + write)
/// - writefile:  90% - 95% (config file writes)
/// - reboot/kexec: 95% - 99% (final boot - never reports 100%, system reboots)
///
/// This ensures progress always moves forward and the final boot action ends near 100%.
pub fn normalize_workflow_progress(action_name: &str, action_progress: u8) -> u8 {
    let (start, end) = match action_name {
        "partition" => (0, 5),
        "image2disk" => (5, 90),
        "writefile" => (90, 95),
        "kexec" | "reboot" => (95, 99),
        _ => {
            // Unknown action - just pass through, capped at 99
            return action_progress.min(99);
        }
    };

    // Map action's 0-100% to its slice of overall progress
    let range = end - start;
    let normalized = start + ((action_progress as u32 * range as u32) / 100) as u8;
    normalized.min(99) // Never report 100% until workflow actually completes
}

async fn update_installation_progress(
    State(state): State<AppState>, // State is used for event manager
    _auth_session: AuthSession,    // Mark as unused - updates come from agent/tinkerbell
    Path(id): Path<Uuid>,
    Json(payload): Json<InstallationProgressUpdateRequest>,
) -> Response {
    info!(
        "Updating installation progress for machine {} to {}% (step: {:?})",
        id, payload.progress, payload.step
    );

    // Get machine from v1 store
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let error_response = ErrorResponse {
                error: "Not Found".to_string(),
                message: format!("Machine with ID {} not found", id),
            };
            return (StatusCode::NOT_FOUND, Json(error_response)).into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: e.to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // Update installation progress
    machine.config.installation_progress = payload.progress;
    machine.config.installation_step = payload.step.clone();
    machine.metadata.updated_at = chrono::Utc::now();

    // Save back to store
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine updated event so the UI fetches new progress HTML
            let _ = state.event_manager.send(format!("machine_updated:{}", id));
            (
                StatusCode::OK,
                Json(json!({ "status": "progress_updated", "machine_id": id })),
            )
                .into_response()
        }
        Err(e) => {
            error!(
                "Failed to update installation progress for machine {}: {}",
                id, e
            );
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: e.to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

// Add new handler for getting machine tags
#[axum::debug_handler]
async fn api_get_machine_tags(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    match state.store.get_machine(id).await {
        Ok(Some(machine)) => (StatusCode::OK, Json(machine.config.tags)).into_response(),
        Ok(None) => {
            let error_response = ErrorResponse {
                error: "Not Found".to_string(),
                message: format!("Machine with ID {} not found", id),
            };
            (StatusCode::NOT_FOUND, Json(error_response)).into_response()
        }
        Err(e) => {
            error!("Failed to get tags for machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: format!("Failed to retrieve tags: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

// Add new handler for updating machine tags
#[axum::debug_handler]
async fn api_update_machine_tags(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
    Json(tags): Json<Vec<String>>,
) -> Response {
    // Check if user is authenticated as admin
    if let Err(response) = crate::auth::require_admin(&auth_session) {
        return response;
    }

    // Get machine from v1 store
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let error_response = ErrorResponse {
                error: "Not Found".to_string(),
                message: format!("Machine with ID {} not found", id),
            };
            return (StatusCode::NOT_FOUND, Json(error_response)).into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: format!("Failed to retrieve machine: {}", e),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response();
        }
    };

    // Update tags
    machine.config.tags = tags;
    machine.metadata.updated_at = chrono::Utc::now();

    // Save back to store
    match state.store.put_machine(&machine).await {
        Ok(()) => {
            // Emit machine updated event
            let _ = state.event_manager.send(format!("machine_updated:{}", id));
            // Sync tags to Proxmox (fire-and-forget)
            let state_clone = state.clone();
            let machine_clone = machine.clone();
            tokio::spawn(async move {
                crate::handlers::proxmox::sync_tags_to_proxmox(&state_clone, &machine_clone).await;
            });
            (
                StatusCode::OK,
                Json(json!({ "success": true, "message": "Tags updated" })),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to update tags for machine {}: {}", id, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: format!("Failed to update tags: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

// New handler to get the current installation status
#[axum::debug_handler]
async fn get_install_status() -> Response {
    // Read the current state from the global static
    let install_state_arc_mutex: Option<Arc<tokio::sync::Mutex<InstallationState>>> = {
        // Acquire read lock, clone the Arc if it exists, then drop the lock immediately
        INSTALL_STATE_REF.read().unwrap().as_ref().cloned()
    };

    match install_state_arc_mutex {
        Some(state_ref) => {
            // Clone the state inside the read guard
            let current_state = state_ref.lock().await.clone();
            // Serialize the state to JSON
            let payload = json!({
                "status": current_state,
                "message": current_state.get_message(),
                "animation": current_state.get_animation_class(),
            });
            (StatusCode::OK, Json(payload)).into_response()
        }
        None => {
            // Not in install mode
            let payload = json!({
                "status": "NotInstalling",
                "message": "Dragonfly is not currently installing.",
                "animation": "",
            });
            (StatusCode::OK, Json(payload)).into_response()
        }
    }
}

// Add handler for deleting a specific machine tag
#[axum::debug_handler]
async fn api_delete_machine_tag(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path((id, tag)): Path<(Uuid, String)>,
) -> Response {
    // Check if user is authenticated as admin
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Admin authentication required for this operation"
            })),
        )
            .into_response();
    }

    // Get machine from v1 Store and update tags
    let result = match state.store.get_machine(id).await {
        Ok(Some(mut machine)) => {
            // Filter out the tag to delete
            machine.config.tags.retain(|t| t != &tag);
            machine.metadata.updated_at = chrono::Utc::now();

            // Update the machine in store
            match state.store.put_machine(&machine).await {
                Ok(()) => {
                    // Emit machine updated event
                    let _ = state.event_manager.send(format!("machine_updated:{}", id));
                    // Sync tags to Proxmox (fire-and-forget)
                    let state_clone = state.clone();
                    let machine_clone = machine.clone();
                    tokio::spawn(async move {
                        crate::handlers::proxmox::sync_tags_to_proxmox(
                            &state_clone,
                            &machine_clone,
                        )
                        .await;
                    });
                    (
                        StatusCode::OK,
                        Json(json!({"success": true, "message": "Tag deleted"})),
                    )
                }
                Err(e) => {
                    error!(
                        "Failed to update tags after deletion for machine {}: {}",
                        id, e
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": "Store error",
                            "message": format!("Failed to update tags: {}", e)
                        })),
                    )
                }
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Machine not found"})),
        ),
        Err(e) => {
            error!("Failed to get machine {} for tag deletion: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Store error",
                    "message": format!("Failed to retrieve machine: {}", e)
                })),
            )
        }
    };

    result.into_response()
}

// NEW HANDLER for the partial update
#[axum::debug_handler]
async fn get_machine_status_and_progress_partial(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    // Explicitly return Response
    info!("Request for status-and-progress partial for machine {}", id);

    let machine: Machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => crate::store::conversions::machine_to_common(&m),
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Html("<!-- Machine not found -->")).into_response();
        }
        Err(e) => {
            error!("Store error fetching machine {} for partial: {}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<!-- Store Error -->"),
            )
                .into_response();
        }
    };

    // Workflow info stub (Tinkerbell removed - using our own provisioning)
    let workflow_info: Option<crate::ui::WorkflowInfo> = None;

    // Prepare context for the partial template
    // Note: The partial will need access to machine and workflow_info
    let context = json!({
        "machine": machine,
        "workflow_info": workflow_info, // Will be null if not installing or error
    });

    // Render the new partial template using render_minijinja directly
    // REMOVE THE MATCH BLOCK BELOW
    /*
    match ui::render_minijinja(&state, "partials/status_and_progress.html", context) {
        Ok(html) => (StatusCode::OK, Html(html)).into_response(), // Add .into_response() back
        Err(e) => {
            error!("Failed to render status_and_progress partial: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Html("<!-- Render Error -->")).into_response() // Add .into_response() back
        }
    }
    */
    // CALL THE FUNCTION DIRECTLY INSTEAD
    ui::render_minijinja(&state, "partials/status_and_progress.html", context)
}

// Utility function to extract client IP

// --- Tag Management API ---
/// Get all tags in the system
#[axum::debug_handler]
async fn api_get_tags(State(state): State<AppState>, auth_session: AuthSession) -> Response {
    // Check if user is authenticated as admin
    if let Err(response) = crate::auth::require_admin(&auth_session) {
        return response;
    }

    match state.store.list_all_tags().await {
        Ok(tags) => (StatusCode::OK, Json(tags)).into_response(),
        Err(e) => {
            error!("Failed to get all tags: {}", e);
            let error_response = ErrorResponse {
                error: "Database Error".to_string(),
                message: format!("Failed to retrieve tags: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

/// Create a new tag
#[axum::debug_handler]
async fn api_create_tag(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    // Check if user is authenticated as admin
    if let Err(response) = crate::auth::require_admin(&auth_session) {
        return response;
    }

    // Extract tag name from JSON payload
    let tag_name = match payload.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing tag name", "message": "Tag name is required"})),
            )
                .into_response();
        }
    };

    // Validate tag name - no empty tags
    if tag_name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid tag name", "message": "Tag name cannot be empty"})),
        )
            .into_response();
    }

    match state.store.create_tag(&tag_name).await {
        Ok(true) => {
            let _ = state.event_manager.send("tags_updated".to_string());
            (
                StatusCode::CREATED,
                Json(json!({"success": true, "message": "Tag created"})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "Tag exists", "message": "A tag with this name already exists"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to create tag '{}': {}", tag_name, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error", "message": format!("Failed to create tag: {}", e)}))
            ).into_response()
        }
    }
}

/// Delete a tag from the system
#[axum::debug_handler]
async fn api_delete_tag(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(tag_name): Path<String>,
) -> Response {
    // Check if user is authenticated as admin
    if let Err(response) = crate::auth::require_admin(&auth_session) {
        return response;
    }

    match state.store.delete_tag(&tag_name).await {
        Ok(true) => {
            // Emit tag deleted event
            let _ = state.event_manager.send("tags_updated".to_string());
            (
                StatusCode::OK,
                Json(json!({"success": true, "message": "Tag deleted"})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Not found", "message": "Tag not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete tag '{}': {}", tag_name, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error", "message": format!("Failed to delete tag: {}", e)}))
            ).into_response()
        }
    }
}

/// Get all machines with a specific tag
#[axum::debug_handler]
async fn api_get_machines_by_tag(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(tag_name): Path<String>,
) -> Response {
    // Check if user is authenticated as admin
    if let Err(response) = crate::auth::require_admin(&auth_session) {
        return response;
    }

    match state.store.list_machines_by_tag(&tag_name).await {
        Ok(v1_machines) => {
            let machines: Vec<Machine> = v1_machines
                .iter()
                .map(|m| crate::store::conversions::machine_to_common(m))
                .collect();
            (StatusCode::OK, Json(machines)).into_response()
        }
        Err(e) => {
            error!("Failed to get machines for tag {}: {}", tag_name, e);
            let error_response = ErrorResponse {
                error: "Store Error".to_string(),
                message: format!("Failed to retrieve machines: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

// New reimage handler
#[axum::debug_handler]
async fn reimage_machine(
    auth_session: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    use dragonfly_common::MachineState;

    // Check if user is authenticated as admin
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Admin authentication required for this operation"
            })),
        )
            .into_response();
    }

    info!("Initiating reimage for machine {}", id);

    // Get the machine first to make sure we have a valid OS choice
    let mut v1_machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "Not Found",
                    "message": format!("Machine with ID {} not found", id)
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Store Error",
                    "message": e.to_string()
                })),
            )
                .into_response();
        }
    };

    // Determine OS to install: prefer os_choice, fall back to os_installed, then ExistingOs state
    // This matches the display logic in machine_to_common() so what the user sees is what reimages
    let os_choice = v1_machine
        .config
        .os_choice
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            v1_machine
                .config
                .os_installed
                .clone()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            // Fall back to ExistingOs state (same as display logic)
            if let dragonfly_common::MachineState::ExistingOs { ref os_name } =
                v1_machine.status.state
            {
                Some(os_name.clone())
            } else {
                None
            }
        });

    let os_choice = match os_choice {
        Some(os) => {
            if v1_machine.config.os_choice.is_none() {
                info!("Using detected OS '{}' for reinstall", os);
                v1_machine.config.os_choice = Some(os.clone());
            }
            os
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Bad Request",
                    "message": "No OS choice set for this machine. Please assign an OS first."
                })),
            )
                .into_response();
        }
    };

    // Verify the template exists
    match state.store.get_template(&os_choice).await {
        Ok(Some(_)) => {} // Template exists, proceed
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, Json(json!({
                "error": "Bad Request",
                "message": format!("Template '{}' not found. Cannot reimage with unknown OS.", os_choice)
            }))).into_response();
        }
        Err(e) => {
            error!("Failed to check template {}: {}", os_choice, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Store Error",
                    "message": e.to_string()
                })),
            )
                .into_response();
        }
    }

    // Set the machine status to ReadyToInstall and mark reimage requested
    v1_machine.status.state = MachineState::ReadyToInstall;
    v1_machine.config.os_choice = Some(os_choice.clone()); // Ensure os_choice is set for check-in
    v1_machine.config.reimage_requested = true; // Molly guard: allows imaging even with existing OS
    v1_machine.config.installation_progress = 0;
    v1_machine.config.installation_step = None;
    v1_machine.metadata.updated_at = chrono::Utc::now();

    // Save the updated machine state
    if let Err(e) = state.store.put_machine(&v1_machine).await {
        error!("Failed to set machine {} status to Installing: {}", id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Store Error",
                "message": e.to_string()
            })),
        )
            .into_response();
    }

    // Create workflow immediately so iPXE boot script returns Mage directly
    // Cancel any existing active workflows first — user explicitly clicked Reimage,
    // so any stale workflows (possibly for a different OS) should be replaced
    let existing_workflows = match state.store.get_workflows_for_machine(id).await {
        Ok(wfs) => wfs,
        Err(e) => {
            error!(
                "Failed to check existing workflows for machine {}: {}",
                id, e
            );
            Vec::new()
        }
    };

    for wf in &existing_workflows {
        let is_active = matches!(
            wf.status.as_ref().map(|s| &s.state),
            Some(dragonfly_crd::WorkflowState::StatePending)
                | Some(dragonfly_crd::WorkflowState::StateRunning)
        );
        if is_active {
            if let Ok(wf_uuid) = uuid::Uuid::parse_str(&wf.metadata.name) {
                info!(
                    "Cancelling stale workflow {} (template: {}) for machine {} — replacing with {}",
                    wf.metadata.name, wf.spec.template_ref, id, os_choice
                );
                let _ = state.store.delete_workflow(wf_uuid).await;
            }
        }
    }

    // Create fresh workflow with the correct OS
    let workflow_id = uuid::Uuid::now_v7();
    let mut workflow =
        dragonfly_crd::Workflow::new(workflow_id.to_string(), id.to_string(), &os_choice);
    workflow.status = Some(dragonfly_crd::WorkflowStatus {
        state: dragonfly_crd::WorkflowState::StatePending,
        current_action: None,
        progress: 0,
        global_timeout: None,
        started_at: None,
        completed_at: None,
        error: None,
        actions: Vec::new(),
    });

    if let Err(e) = state.store.put_workflow(&workflow).await {
        error!("Failed to create workflow for machine {}: {}", id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Store Error",
                "message": format!("Failed to create workflow: {}", e)
            })),
        )
            .into_response();
    }
    info!(
        "Created imaging workflow {} for machine {} with OS {}",
        workflow_id, id, os_choice
    );

    // Convert to common Machine for Proxmox reboot
    let machine: Machine = crate::store::conversions::machine_to_common(&v1_machine);

    // Emit machine updated event
    let _ = state.event_manager.send(format!("machine_updated:{}", id));

    // If this is a Proxmox VM, reboot it into PXE boot mode
    if machine.proxmox_vmid.is_some() && machine.proxmox_node.is_some() {
        info!("Rebooting Proxmox VM {} for reimage", id);
        // Create a request to reboot into PXE
        let power_action = crate::handlers::machines::BmcPowerActionRequest {
            action: "reboot-pxe".to_string(),
        };

        // Call the power action handler
        match crate::handlers::machines::bmc_power_action_handler(
            State(state.clone()),
            Path(id),
            Json(power_action),
        )
        .await
        {
            Ok(_) => {
                info!("Successfully initiated PXE reboot for Proxmox VM {}", id);
            }
            Err(e) => {
                // Log the error but continue - machine state is updated, just reboot failed
                error!("Failed to reboot Proxmox VM {}: {:?}", id, e);
            }
        }
    } else {
        info!("Machine {} is not a Proxmox VM, skipping reboot", id);
    }

    // Return success response
    let response_html = format!(
        r###"
        <div class="p-4 mb-4 text-sm text-green-700 bg-green-100 rounded-lg" role="alert">
            <span class="font-medium">Success!</span> Reimaging machine {} with {}.
            <p>Installation has started and may take several minutes to complete.</p>
        </div>
    "###,
        id, os_choice
    );

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html")],
        response_html,
    )
        .into_response()
}

/// Abort a pending reimage - cancels before the machine actually starts installing
#[axum::debug_handler]
async fn abort_reimage(
    auth_session: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    use dragonfly_common::MachineState;

    // Check if user is authenticated as admin
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "message": "Admin authentication required for this operation"
            })),
        )
            .into_response();
    }

    info!("Aborting pending reimage for machine {}", id);

    // Get the machine
    let mut v1_machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "Not Found",
                    "message": format!("Machine with ID {} not found", id)
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to get machine {}: {}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Store Error",
                    "message": e.to_string()
                })),
            )
                .into_response();
        }
    };

    // Only allow abort if machine is in ReadyToInstall state
    if !matches!(v1_machine.status.state, MachineState::ReadyToInstall) {
        return (StatusCode::CONFLICT, Json(json!({
            "error": "Invalid State",
            "message": format!("Cannot abort reimage - machine is in {:?} state, not ReadyToInstall", v1_machine.status.state)
        }))).into_response();
    }

    // Clear the reimage request and reset state
    v1_machine.config.reimage_requested = false;
    v1_machine.config.installation_progress = 0;
    v1_machine.config.installation_step = None;

    // Determine what state to return to
    // If os_installed is set, go to Installed; otherwise Discovered
    v1_machine.status.state = if v1_machine.config.os_installed.is_some() {
        MachineState::Installed
    } else {
        MachineState::Discovered
    };

    v1_machine.metadata.updated_at = chrono::Utc::now();

    // Save the updated machine state
    if let Err(e) = state.store.put_machine(&v1_machine).await {
        error!("Failed to abort reimage for machine {}: {}", id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Store Error",
                "message": e.to_string()
            })),
        )
            .into_response();
    }

    // Emit machine updated event
    let _ = state.event_manager.send(format!("machine_updated:{}", id));

    info!("Successfully aborted pending reimage for machine {}", id);

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "message": "Pending reimage cancelled",
            "new_state": v1_machine.status.state.as_str()
        })),
    )
        .into_response()
}

// Add new endpoint to configure Proxmox API tokens
/// GET /api/proxmox/status — return current Proxmox connection status
#[axum::debug_handler]
pub async fn proxmox_status(State(state): State<AppState>) -> impl IntoResponse {
    let settings =
        crate::handlers::proxmox::get_proxmox_settings_from_store_pub(state.store.as_ref()).await;

    match settings {
        Ok(Some(s)) => Json(serde_json::json!({
            "configured": true,
            "host": s.host,
            "port": s.port,
            "username": s.username,
            "skip_tls_verify": s.skip_tls_verify,
            "has_power_token": s.vm_power_token.is_some(),
            "has_create_token": s.vm_create_token.is_some(),
            "has_config_token": s.vm_config_token.is_some(),
            "has_sync_token": s.vm_sync_token.is_some(),
        }))
        .into_response(),
        Ok(None) => Json(serde_json::json!({
            "configured": false,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e.to_string()
            })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ProxmoxTokenRequest {
    token_type: String,
    token_value: String,
}

// API endpoint to update a specific Proxmox API token
#[axum::debug_handler]
pub async fn update_proxmox_token(
    State(state): State<AppState>,
    Json(request): Json<ProxmoxTokenRequest>,
) -> impl IntoResponse {
    use crate::encryption::encrypt_string;
    use dragonfly_common::models::ErrorResponse;

    info!(
        "Updating Proxmox API token for type: {}",
        request.token_type
    );

    // Validate token type
    if !["create", "power", "config", "sync"].contains(&request.token_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "INVALID_TOKEN_TYPE".to_string(),
                message: "Token type must be one of: create, power, config, sync".to_string(),
            }),
        )
            .into_response();
    }

    // Encrypt the token before storing
    let encrypted = match encrypt_string(&request.token_value) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "ENCRYPTION_FAILED".to_string(),
                    message: format!("Failed to encrypt token: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Update the token in the Store
    let result: Result<(), anyhow::Error> = async {
        let store = state.store.as_ref();
        let mut settings = crate::handlers::proxmox::get_proxmox_settings_from_store_pub(store)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No Proxmox settings exist"))?;

        match request.token_type.as_str() {
            "create" => settings.vm_create_token = Some(encrypted),
            "power" => settings.vm_power_token = Some(encrypted),
            "config" => settings.vm_config_token = Some(encrypted),
            "sync" => settings.vm_sync_token = Some(encrypted),
            _ => unreachable!(),
        }
        settings.updated_at = chrono::Utc::now();
        crate::handlers::proxmox::put_proxmox_settings_to_store_pub(store, &settings).await
    }
    .await;

    match result {
        Ok(_) => {
            info!(
                "Successfully updated Proxmox API token for {} operations",
                request.token_type
            );
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "message": format!("Successfully updated {} token", request.token_type)
                })),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to update Proxmox API token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "TOKEN_UPDATE_FAILED".to_string(),
                    message: format!("Failed to update token: {}", e),
                }),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Settings API
// ============================================================================

/// Response for GET /api/settings
#[derive(serde::Serialize)]
pub struct SettingsResponse {
    pub deployment_mode: Option<String>,
    pub default_os: Option<String>,
    pub setup_completed: bool,
    /// When true, efibootmgr sets PXE as first boot option after installation
    pub auto_enroll_with_spark: bool,
}

/// Request for PUT /api/settings
#[derive(serde::Deserialize)]
pub struct SettingsUpdateRequest {
    #[serde(default)]
    pub deployment_mode: Option<String>,
    #[serde(default)]
    pub default_os: Option<String>,
    /// When true, efibootmgr sets PXE as first boot option after installation
    #[serde(default)]
    pub auto_enroll_with_spark: Option<bool>,
}

/// Fetch SSH keys from an external URL (GitHub, GitLab, or custom URL)
#[axum::debug_handler]
pub async fn api_fetch_keys(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let url = match params.get("url") {
        Some(url) => url,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "MISSING_URL",
                    "message": "url parameter is required"
                })),
            )
                .into_response();
        }
    };

    // Validate URL
    if !url.starts_with("https://") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INVALID_URL",
                "message": "URL must use HTTPS"
            })),
        )
            .into_response();
    }

    // Fetch keys from URL
    let client = reqwest::Client::new();
    match client.get(url).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "FETCH_FAILED",
                        "message": format!("Failed to fetch keys: HTTP {}", response.status())
                    })),
                )
                    .into_response();
            }

            match response.text().await {
                Ok(keys) => Json(json!({
                    "keys": keys
                }))
                .into_response(),
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "READ_FAILED",
                        "message": format!("Failed to read response: {}", e)
                    })),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "FETCH_FAILED",
                "message": format!("Failed to fetch keys: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Get current settings
#[axum::debug_handler]
pub async fn api_get_settings(State(state): State<AppState>) -> impl IntoResponse {
    let deployment_mode = state
        .store
        .get_setting("deployment_mode")
        .await
        .ok()
        .flatten();
    let default_os = state.store.get_setting("default_os").await.ok().flatten();
    let setup_completed = state
        .store
        .get_setting("setup_completed")
        .await
        .ok()
        .flatten()
        .map(|s| s == "true")
        .unwrap_or(false);
    let auto_enroll_with_spark = state
        .store
        .get_setting("auto_enroll_with_spark")
        .await
        .ok()
        .flatten()
        .map(|s| s == "true")
        .unwrap_or(false);

    Json(SettingsResponse {
        deployment_mode,
        default_os,
        setup_completed,
        auto_enroll_with_spark,
    })
}

/// Update settings
#[axum::debug_handler]
pub async fn api_update_settings(
    State(state): State<AppState>,
    Json(request): Json<SettingsUpdateRequest>,
) -> impl IntoResponse {
    let mut updated = Vec::new();

    // Update deployment_mode if provided
    if let Some(ref mode) = request.deployment_mode {
        // Validate mode
        if !["simple", "flight", "swarm"].contains(&mode.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "INVALID_MODE",
                    "message": "deployment_mode must be one of: simple, flight, swarm"
                })),
            )
                .into_response();
        }

        if let Err(e) = state.store.put_setting("deployment_mode", mode).await {
            error!("Failed to update deployment_mode: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "SETTINGS_UPDATE_FAILED",
                    "message": format!("Failed to update deployment_mode: {}", e)
                })),
            )
                .into_response();
        }
        updated.push("deployment_mode");
        info!("Updated deployment_mode to: {}", mode);

        // If switching to flight mode, configure it
        if mode == "flight" {
            let store_clone = state.store.clone();
            let event_manager = state.event_manager.clone();
            let app_state_clone = state.clone();
            tokio::spawn(async move {
                match crate::mode::configure_flight_mode(store_clone).await {
                    Ok(_) => {
                        info!("Flight mode configuration completed");
                        crate::start_network_services(
                            &app_state_clone,
                            app_state_clone.shutdown_rx.clone(),
                        )
                        .await;
                        let _ = event_manager.send("mode_configured:flight".to_string());
                    }
                    Err(e) => {
                        error!("Flight mode configuration failed: {}", e);
                        let _ =
                            event_manager.send(format!("mode_configuration_failed:flight:{}", e));
                    }
                }
            });
        }
    }

    // Update default_os if provided
    if let Some(ref os) = request.default_os {
        if let Err(e) = state.store.put_setting("default_os", os).await {
            error!("Failed to update default_os: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "SETTINGS_UPDATE_FAILED",
                    "message": format!("Failed to update default_os: {}", e)
                })),
            )
                .into_response();
        }
        updated.push("default_os");
        info!("Updated default_os to: {}", os);
    }

    // Update auto_enroll_with_spark if provided
    if let Some(enabled) = request.auto_enroll_with_spark {
        let value = if enabled { "true" } else { "false" };
        if let Err(e) = state
            .store
            .put_setting("auto_enroll_with_spark", value)
            .await
        {
            error!("Failed to update auto_enroll_with_spark: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "SETTINGS_UPDATE_FAILED",
                    "message": format!("Failed to update auto_enroll_with_spark: {}", e)
                })),
            )
                .into_response();
        }
        updated.push("auto_enroll_with_spark");
        info!("Updated auto_enroll_with_spark to: {}", enabled);
    }

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "updated": updated
        })),
    )
        .into_response()
}

/// Response for GET /api/settings/mode
#[derive(serde::Serialize)]
pub struct ModeResponse {
    pub mode: Option<String>,
}

/// Request for PUT /api/settings/mode
#[derive(serde::Deserialize)]
pub struct ModeUpdateRequest {
    pub mode: String,
}

/// Get current deployment mode
#[axum::debug_handler]
pub async fn api_get_mode(State(state): State<AppState>) -> impl IntoResponse {
    let mode = state
        .store
        .get_setting("deployment_mode")
        .await
        .ok()
        .flatten();
    Json(ModeResponse { mode })
}

/// Set deployment mode
#[axum::debug_handler]
pub async fn api_set_mode(
    State(state): State<AppState>,
    Json(request): Json<ModeUpdateRequest>,
) -> impl IntoResponse {
    // Validate mode
    if !["simple", "flight", "swarm"].contains(&request.mode.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INVALID_MODE",
                "message": "mode must be one of: simple, flight, swarm"
            })),
        )
            .into_response();
    }

    if let Err(e) = state
        .store
        .put_setting("deployment_mode", &request.mode)
        .await
    {
        error!("Failed to set deployment mode: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "MODE_UPDATE_FAILED",
                "message": format!("Failed to set mode: {}", e)
            })),
        )
            .into_response();
    }

    info!("Deployment mode set to: {}", request.mode);

    // If switching to flight mode, configure it
    if request.mode == "flight" {
        let store_clone = state.store.clone();
        let event_manager = state.event_manager.clone();
        let app_state_clone = state.clone();
        tokio::spawn(async move {
            match crate::mode::configure_flight_mode(store_clone).await {
                Ok(_) => {
                    info!("Flight mode configuration completed");
                    crate::start_network_services(
                        &app_state_clone,
                        app_state_clone.shutdown_rx.clone(),
                    )
                    .await;
                    let _ = event_manager.send("mode_configured:flight".to_string());
                }
                Err(e) => {
                    error!("Flight mode configuration failed: {}", e);
                    let _ = event_manager.send(format!("mode_configuration_failed:flight:{}", e));
                }
            }
        });
    }

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "mode": request.mode
        })),
    )
        .into_response()
}

// ============================================================================
// User Management API
// ============================================================================

/// User response for API
#[derive(serde::Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<crate::store::v1::User> for UserResponse {
    fn from(user: crate::store::v1::User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

/// Request for creating a new user
#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

/// Request for updating a user
#[derive(serde::Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// Get all users
#[axum::debug_handler]
pub async fn api_get_users(
    State(state): State<AppState>,
    auth_session: AuthSession,
) -> impl IntoResponse {
    // Require authentication
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "UNAUTHORIZED",
                "message": "Authentication required"
            })),
        )
            .into_response();
    }

    match state.store.list_users().await {
        Ok(users) => {
            let responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();
            Json(responses).into_response()
        }
        Err(e) => {
            error!("Failed to fetch users: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "DATABASE_ERROR",
                    "message": "Failed to fetch users"
                })),
            )
                .into_response()
        }
    }
}

/// Get a single user
#[axum::debug_handler]
pub async fn api_get_user(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "UNAUTHORIZED",
                "message": "Authentication required"
            })),
        )
            .into_response();
    }

    let user_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "INVALID_ID",
                    "message": "Invalid user ID format"
                })),
            )
                .into_response();
        }
    };

    match state.store.get_user(user_id).await {
        Ok(Some(user)) => Json(UserResponse::from(user)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "NOT_FOUND",
                "message": "User not found"
            })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to fetch user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "DATABASE_ERROR",
                    "message": "Failed to fetch user"
                })),
            )
                .into_response()
        }
    }
}

/// Create a new user
#[axum::debug_handler]
pub async fn api_create_user(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Json(request): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "UNAUTHORIZED",
                "message": "Authentication required"
            })),
        )
            .into_response();
    }

    // Validate input
    if request.username.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INVALID_INPUT",
                "message": "Username cannot be empty"
            })),
        )
            .into_response();
    }

    if request.password.len() < 4 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "INVALID_INPUT",
                "message": "Password must be at least 4 characters"
            })),
        )
            .into_response();
    }

    // Check if username already exists
    if let Ok(Some(_)) = state.store.get_user_by_username(&request.username).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "DUPLICATE_USER",
                "message": "A user with this username already exists"
            })),
        )
            .into_response();
    }

    // Hash the password
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(request.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            error!("Failed to hash password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "HASH_ERROR",
                    "message": "Failed to create user"
                })),
            )
                .into_response();
        }
    };

    let now = chrono::Utc::now().to_rfc3339();
    let user_id = uuid::Uuid::now_v7();

    let user = crate::store::v1::User {
        id: user_id,
        username: request.username.clone(),
        password_hash,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    match state.store.put_user(&user).await {
        Ok(()) => {
            info!("Created new user: {} (id: {})", request.username, user_id);
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": user_id.to_string(),
                    "username": request.username,
                    "created_at": now,
                    "updated_at": now
                })),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to create user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "DATABASE_ERROR",
                    "message": "Failed to create user"
                })),
            )
                .into_response()
        }
    }
}

/// Update a user
#[axum::debug_handler]
pub async fn api_update_user(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<String>,
    Json(request): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "UNAUTHORIZED",
                "message": "Authentication required"
            })),
        )
            .into_response();
    }

    let user_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "INVALID_ID",
                    "message": "Invalid user ID format"
                })),
            )
                .into_response();
        }
    };

    // Get existing user
    let mut user = match state.store.get_user(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "NOT_FOUND",
                    "message": "User not found"
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to check user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "DATABASE_ERROR",
                    "message": "Failed to update user"
                })),
            )
                .into_response();
        }
    };

    let now = chrono::Utc::now().to_rfc3339();

    // Update username if provided
    if let Some(ref username) = request.username {
        if !username.trim().is_empty() && username != &user.username {
            // Check if new username is already taken
            if let Ok(Some(existing)) = state.store.get_user_by_username(username).await {
                if existing.id != user_id {
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": "DUPLICATE_USER",
                            "message": "A user with this username already exists"
                        })),
                    )
                        .into_response();
                }
            }
            user.username = username.clone();
        }
    }

    // Update password if provided
    if let Some(ref password) = request.password {
        if !password.is_empty() {
            use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
            use rand::rngs::OsRng;

            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
                Ok(hash) => hash.to_string(),
                Err(e) => {
                    error!("Failed to hash password: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": "HASH_ERROR",
                            "message": "Failed to update password"
                        })),
                    )
                        .into_response();
                }
            };
            user.password_hash = password_hash;
        }
    }

    user.updated_at = now;

    match state.store.put_user(&user).await {
        Ok(()) => {
            info!("Updated user id: {}", user_id);
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "id": user_id.to_string()
                })),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to update user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "DATABASE_ERROR",
                    "message": "Failed to update user"
                })),
            )
                .into_response()
        }
    }
}

/// Delete a user
#[axum::debug_handler]
pub async fn api_delete_user(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let current_user = match auth_session.user {
        Some(user) => user,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "UNAUTHORIZED",
                    "message": "Authentication required"
                })),
            )
                .into_response();
        }
    };

    let user_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "INVALID_ID",
                    "message": "Invalid user ID format"
                })),
            )
                .into_response();
        }
    };

    // Prevent deleting yourself (compare usernames since auth uses username for session)
    if current_user.username
        == state
            .store
            .get_user(user_id)
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_default()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "CANNOT_DELETE_SELF",
                "message": "You cannot delete your own account"
            })),
        )
            .into_response();
    }

    // Check how many users exist - don't allow deleting the last user
    let users = state.store.list_users().await.unwrap_or_default();
    if users.len() <= 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "LAST_USER",
                "message": "Cannot delete the last user"
            })),
        )
            .into_response();
    }

    match state.store.delete_user(user_id).await {
        Ok(true) => {
            info!("Deleted user id: {}", user_id);
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "id": user_id.to_string()
                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "NOT_FOUND",
                "message": "User not found"
            })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "DATABASE_ERROR",
                    "message": "Failed to delete user"
                })),
            )
                .into_response()
        }
    }
}

// === Template Management Handlers ===

/// Template info for the UI
#[derive(Debug, serde::Serialize)]
pub struct TemplateInfo {
    pub name: String,
    pub display_name: String,
    pub icon: String,
    pub enabled: bool,
    pub builtin: bool,
}

/// List all templates with their enabled/disabled state
pub async fn list_templates_handler(State(state): State<crate::AppState>) -> Response {
    // Get disabled templates from settings
    let disabled_templates: Vec<String> = state
        .store
        .get_setting("disabled_templates")
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Get all templates from store
    let templates = match state.store.list_templates().await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to list templates: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to list templates" })),
            )
                .into_response();
        }
    };

    // Map to TemplateInfo
    let template_infos: Vec<TemplateInfo> = templates
        .iter()
        .map(|t| {
            let name = t.metadata.name.clone();
            let (display_name, icon) = match name.as_str() {
                "ubuntu-2404" => ("Ubuntu 24.04 LTS".to_string(), "ubuntu".to_string()),
                "ubuntu-2204" => ("Ubuntu 22.04 LTS".to_string(), "ubuntu".to_string()),
                "debian-13" => ("Debian 13 (Trixie)".to_string(), "debian".to_string()),
                "debian-12" => ("Debian 12 (Bookworm)".to_string(), "debian".to_string()),
                "proxmox" => ("Proxmox VE".to_string(), "proxmox".to_string()),
                "rocky-10" => ("Rocky Linux 10".to_string(), "rocky".to_string()),
                _ => (name.clone(), "generic".to_string()),
            };
            let builtin = matches!(
                name.as_str(),
                "ubuntu-2404" | "ubuntu-2204" | "debian-13" | "debian-12" | "proxmox" | "rocky-10"
            );
            TemplateInfo {
                name: name.clone(),
                display_name,
                icon,
                enabled: !disabled_templates.contains(&name),
                builtin,
            }
        })
        .collect();

    Json(template_infos).into_response()
}

/// Toggle template enabled/disabled state
pub async fn toggle_template_handler(
    State(state): State<crate::AppState>,
    Path(template_name): Path<String>,
) -> Response {
    // Get current disabled templates
    let mut disabled_templates: Vec<String> = state
        .store
        .get_setting("disabled_templates")
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Toggle
    let now_enabled = if disabled_templates.contains(&template_name) {
        disabled_templates.retain(|t| t != &template_name);
        true
    } else {
        disabled_templates.push(template_name.clone());
        false
    };

    // Save
    if let Err(e) = state
        .store
        .put_setting(
            "disabled_templates",
            &serde_json::to_string(&disabled_templates).unwrap(),
        )
        .await
    {
        error!("Failed to save disabled_templates: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to save setting" })),
        )
            .into_response();
    }

    info!(template = %template_name, enabled = now_enabled, "Template toggled");
    Json(json!({ "name": template_name, "enabled": now_enabled })).into_response()
}

/// Get template content as YAML
pub async fn get_template_content_handler(
    State(state): State<crate::AppState>,
    Path(template_name): Path<String>,
) -> Response {
    // Try to read from file first (source of truth)
    let file_path = format!("/var/lib/dragonfly/os-templates/{}.yml", template_name);
    match tokio::fs::read_to_string(&file_path).await {
        Ok(content) => Json(json!({ "name": template_name, "content": content })).into_response(),
        Err(_) => {
            // Fall back to store
            match state.store.get_template(&template_name).await {
                Ok(Some(template)) => match serde_yaml::to_string(&template) {
                    Ok(yaml) => {
                        Json(json!({ "name": template_name, "content": yaml })).into_response()
                    }
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": format!("Failed to serialize template: {}", e) })),
                    )
                        .into_response(),
                },
                Ok(None) => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Template not found" })),
                )
                    .into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": format!("Failed to get template: {}", e) })),
                )
                    .into_response(),
            }
        }
    }
}

/// Update template content
#[derive(Debug, serde::Deserialize)]
pub struct UpdateTemplateRequest {
    pub content: String,
}

pub async fn update_template_content_handler(
    State(state): State<crate::AppState>,
    Path(template_name): Path<String>,
    Json(request): Json<UpdateTemplateRequest>,
) -> Response {
    // Validate YAML
    let template: dragonfly_crd::Template = match serde_yaml::from_str(&request.content) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Invalid YAML: {}", e) })),
            )
                .into_response();
        }
    };

    // Validate template
    if let Err(e) = template.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Invalid template: {}", e) })),
        )
            .into_response();
    }

    // Save to file
    let file_path = format!("/var/lib/dragonfly/os-templates/{}.yml", template_name);
    if let Err(e) = tokio::fs::write(&file_path, &request.content).await {
        error!("Failed to write template file: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to save template: {}", e) })),
        )
            .into_response();
    }

    // Update in store
    if let Err(e) = state.store.put_template(&template).await {
        error!("Failed to update template in store: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to update template: {}", e) })),
        )
            .into_response();
    }

    info!(template = %template_name, "Template updated");
    Json(json!({ "success": true, "name": template_name })).into_response()
}

// =============================================================================
// Agent self-service endpoints (called from Spark bare-metal boot manager)
//
// These are unauthenticated but verify MAC matches the stored machine record.
// =============================================================================

/// Request body for agent install request
#[derive(Debug, Deserialize)]
struct AgentInstallRequest {
    machine_id: String,
    mac: String,
    template_name: String,
}

/// Request body for agent remove/boot-iso
#[derive(Debug, Deserialize)]
struct AgentMachineRequest {
    machine_id: String,
    mac: String,
}

/// Request body for agent boot mode (memtest, rescue, iso)
#[derive(Debug, Deserialize)]
struct AgentBootModeRequest {
    machine_id: String,
    mac: String,
    mode: String,
    #[serde(default)]
    iso_name: Option<String>,
}

/// Verify that the MAC in the request matches the MAC stored for the machine.
/// Returns the machine if verification succeeds, or an error response.
async fn verify_agent_mac(
    store: &dyn crate::store::v1::Store,
    machine_id_str: &str,
    request_mac: &str,
) -> Result<dragonfly_common::Machine, Response> {
    let machine_uuid = Uuid::parse_str(machine_id_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "message": "Invalid machine_id" })),
        )
            .into_response()
    })?;

    let machine = store
        .get_machine(machine_uuid)
        .await
        .map_err(|e| {
            error!("Store error looking up machine: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "message": "Store error" })),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "success": false, "message": "Machine not found" })),
            )
                .into_response()
        })?;

    // Verify MAC matches
    let normalized_request_mac = dragonfly_common::normalize_mac(request_mac);
    let stored_mac = dragonfly_common::normalize_mac(&machine.identity.primary_mac);
    if normalized_request_mac != stored_mac {
        warn!(
            machine_id = machine_id_str,
            request_mac = %normalized_request_mac,
            stored_mac = %stored_mac,
            "Agent MAC verification failed"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "message": "MAC mismatch" })),
        )
            .into_response());
    }

    Ok(machine)
}

/// POST /api/agent/request-install
///
/// Called by Spark when user selects "Install OS" and picks a template.
/// Assigns the OS template and flags the machine for reimage.
pub async fn agent_request_install_handler(
    State(state): State<crate::AppState>,
    Json(req): Json<AgentInstallRequest>,
) -> Response {
    info!(machine_id = %req.machine_id, template = %req.template_name, "Agent install request");

    let mut machine = match verify_agent_mac(state.store.as_ref(), &req.machine_id, &req.mac).await
    {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    // Verify template exists
    match state.store.get_template(&req.template_name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({
                "success": false, "message": format!("Template '{}' not found", req.template_name)
            }))).into_response();
        }
        Err(e) => {
            error!("Store error checking template: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false, "message": "Store error"
                })),
            )
                .into_response();
        }
    }

    // Assign OS and flag for reimage
    machine.config.os_choice = Some(req.template_name.clone());
    machine.config.reimage_requested = true;

    if let Err(e) = state.store.put_machine(&machine).await {
        error!("Failed to update machine: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false, "message": "Failed to update machine"
            })),
        )
            .into_response();
    }

    info!(
        machine_id = %req.machine_id,
        template = %req.template_name,
        "Machine flagged for reimage via agent request"
    );

    let _ = state
        .event_manager
        .send(format!("machine_updated:{}", req.machine_id));

    Json(json!({ "success": true, "message": "Install requested" })).into_response()
}

/// POST /api/agent/remove
///
/// Called by Spark when user selects "Remove from Dragonfly".
/// Deletes the machine from the store.
pub async fn agent_remove_handler(
    State(state): State<crate::AppState>,
    Json(req): Json<AgentMachineRequest>,
) -> Response {
    info!(machine_id = %req.machine_id, "Agent remove request");

    let machine = match verify_agent_mac(state.store.as_ref(), &req.machine_id, &req.mac).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    match state.store.delete_machine(machine.id).await {
        Ok(true) => {
            info!(machine_id = %req.machine_id, "Machine removed via agent request");
            let _ = state
                .event_manager
                .send(format!("machine_deleted:{}", req.machine_id));
            Json(json!({ "success": true, "message": "Machine removed" })).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "message": "Machine not found" })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete machine: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false, "message": "Failed to delete machine"
                })),
            )
                .into_response()
        }
    }
}

/// POST /api/agent/boot-mode
///
/// Called by Spark to request a special boot mode for the machine.
/// Supported modes: "memtest", "rescue", "iso"
/// For ISO mode, `iso_name` must be provided.
///
/// Stores boot-mode tags on the machine. On next PXE boot, the provisioning
/// system checks these tags and generates the appropriate iPXE script:
/// - memtest → boot memtest86+ directly
/// - rescue → boot Mage in discovery mode
/// - iso → iPXE sanboot of server-hosted ISO
///
/// Tags are one-shot: cleared after generating the boot script.
pub async fn agent_boot_mode_handler(
    State(state): State<crate::AppState>,
    Json(req): Json<AgentBootModeRequest>,
) -> Response {
    info!(machine_id = %req.machine_id, mode = %req.mode, "Agent boot-mode request");

    // Validate mode
    match req.mode.as_str() {
        "memtest" | "rescue" => {}
        "iso" => {
            if req.iso_name.as_ref().map_or(true, |n| n.is_empty()) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false, "message": "iso_name required for iso mode"
                    })),
                )
                    .into_response();
            }
            // Verify ISO exists on disk
            let iso_name = req.iso_name.as_ref().unwrap();
            let iso_path = std::path::Path::new("/var/lib/dragonfly/isos").join(iso_name);
            if !iso_path.exists() || !iso_path.is_file() {
                return (StatusCode::NOT_FOUND, Json(json!({
                    "success": false, "message": format!("ISO '{}' not found on server", iso_name)
                }))).into_response();
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false, "message": format!("Unknown boot mode: {}", req.mode)
                })),
            )
                .into_response();
        }
    }

    let mut machine = match verify_agent_mac(state.store.as_ref(), &req.machine_id, &req.mac).await
    {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    // Clear any existing boot-mode and boot-iso tags
    machine
        .config
        .tags
        .retain(|t| !t.starts_with("boot-mode:") && !t.starts_with("boot-iso:"));

    // Set boot-mode tag
    machine.config.tags.push(format!("boot-mode:{}", req.mode));

    // For ISO mode, also set boot-iso tag
    if req.mode == "iso" {
        if let Some(ref iso_name) = req.iso_name {
            machine.config.tags.push(format!("boot-iso:{}", iso_name));
        }
    }

    if let Err(e) = state.store.put_machine(&machine).await {
        error!("Failed to update machine with boot mode: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false, "message": "Failed to store boot mode"
            })),
        )
            .into_response();
    }

    info!(machine_id = %req.machine_id, mode = %req.mode, "Boot mode override set");
    let _ = state
        .event_manager
        .send(format!("machine_updated:{}", req.machine_id));

    Json(json!({ "success": true, "message": format!("Boot mode '{}' configured", req.mode) }))
        .into_response()
}

/// GET /api/agent/isos
///
/// Returns a plain JSON array of ISO filenames available on the server.
/// Uses a simple format (no object wrapper) for easy parsing by Spark's
/// bare-metal no_std JSON parser.
///
/// Response format: `["debian-13.iso","ubuntu-24.04.iso"]`
pub async fn agent_list_isos_handler() -> Response {
    let iso_dir = std::path::Path::new("/var/lib/dragonfly/isos");

    if !iso_dir.exists() {
        return Json(json!([])).into_response();
    }

    let mut isos: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(iso_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".iso") || name.ends_with(".ISO") {
                        isos.push(name.to_string());
                    }
                }
            }
        }
    }
    isos.sort();

    Json(json!(isos)).into_response()
}

/// GET /api/isos
///
/// Returns detailed list of ISO files for the web UI.
pub async fn list_isos_handler(auth_session: AuthSession) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    let iso_dir = std::path::Path::new("/var/lib/dragonfly/isos");

    if !iso_dir.exists() {
        return Json(json!({ "isos": serde_json::Value::Array(vec![]) })).into_response();
    }

    let mut isos = Vec::new();
    if let Ok(entries) = std::fs::read_dir(iso_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".iso") || name.ends_with(".ISO") {
                        let metadata = std::fs::metadata(&path).ok();
                        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                        let modified = metadata
                            .as_ref()
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        isos.push(json!({
                            "name": name,
                            "size": size,
                            "modified": modified
                        }));
                    }
                }
            }
        }
    }
    isos.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    Json(json!({ "isos": isos })).into_response()
}

/// POST /api/isos/upload
///
/// Upload an ISO file to /var/lib/dragonfly/isos/
/// Streams data to disk to support large files (multi-GB ISOs).
pub async fn upload_iso_handler(
    auth_session: AuthSession,
    mut multipart: axum::extract::Multipart,
) -> Response {
    use tokio::io::AsyncWriteExt;

    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    let iso_dir = std::path::Path::new("/var/lib/dragonfly/isos");
    if let Err(e) = tokio::fs::create_dir_all(iso_dir).await {
        error!("Failed to create ISO directory: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Failed to create ISO directory"
            })),
        )
            .into_response();
    }

    let mut field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "No file provided"
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to parse multipart upload: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Failed to parse upload"
                })),
            )
                .into_response();
        }
    };

    let file_name = match field.file_name() {
        Some(name) => {
            // Sanitize filename - only allow alphanumeric, dash, underscore, dot
            let sanitized: String = name
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                .collect();
            if sanitized.is_empty()
                || (!sanitized.ends_with(".iso") && !sanitized.ends_with(".ISO"))
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Invalid filename - must end with .iso"
                    })),
                )
                    .into_response();
            }
            sanitized
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "No filename provided"
                })),
            )
                .into_response();
        }
    };

    let dest = iso_dir.join(&file_name);

    // Stream chunks to disk instead of buffering entire file in memory
    let mut file = match tokio::fs::File::create(&dest).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to create ISO file {}: {}", file_name, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to create file"
                })),
            )
                .into_response();
        }
    };

    let mut total_bytes: u64 = 0;
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                if let Err(e) = file.write_all(&chunk).await {
                    error!("Failed to write chunk to {}: {}", file_name, e);
                    // Clean up partial file
                    drop(file);
                    let _ = tokio::fs::remove_file(&dest).await;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": "Failed to write file"
                        })),
                    )
                        .into_response();
                }
                total_bytes += chunk.len() as u64;
            }
            Ok(None) => break, // Upload complete
            Err(e) => {
                error!("Failed to read upload chunk for {}: {:?}", file_name, e);
                // Clean up partial file
                drop(file);
                let _ = tokio::fs::remove_file(&dest).await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Upload interrupted"
                    })),
                )
                    .into_response();
            }
        }
    }

    if let Err(e) = file.flush().await {
        error!("Failed to flush ISO file {}: {}", file_name, e);
    }

    info!("ISO uploaded: {} ({} bytes)", file_name, total_bytes);
    Json(json!({
        "success": true,
        "name": file_name,
        "size": total_bytes
    }))
    .into_response()
}

/// DELETE /api/isos/{filename}
///
/// Delete an ISO file from /var/lib/dragonfly/isos/
pub async fn delete_iso_handler(
    auth_session: AuthSession,
    Path(filename): Path<String>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized"
            })),
        )
            .into_response();
    }

    // Sanitize to prevent path traversal
    let sanitized: String = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();

    if sanitized.is_empty() || sanitized.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid filename"
            })),
        )
            .into_response();
    }

    let path = std::path::Path::new("/var/lib/dragonfly/isos").join(&sanitized);

    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "ISO not found"
            })),
        )
            .into_response();
    }

    match std::fs::remove_file(&path) {
        Ok(()) => {
            info!("ISO deleted: {}", sanitized);
            Json(json!({ "success": true })).into_response()
        }
        Err(e) => {
            error!("Failed to delete ISO: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to delete file"
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Network CRUD Handlers
// ============================================================================

async fn list_networks_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state.store.list_networks().await {
        Ok(networks) => Json(networks).into_response(),
        Err(e) => {
            error!("Failed to list networks: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn get_network_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state.store.get_network(id).await {
        Ok(Some(network)) => Json(network).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Network not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get network: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn create_network_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Json(payload): Json<dragonfly_common::Network>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    info!("Creating network: {}", payload.name);
    match state.store.put_network(&payload).await {
        Ok(()) => (StatusCode::CREATED, Json(&payload)).into_response(),
        Err(e) => {
            error!("Failed to create network: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn update_network_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
    Json(mut payload): Json<dragonfly_common::Network>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    // Ensure path ID matches payload
    payload.id = id;
    payload.updated_at = chrono::Utc::now();

    // Check if DHCP config changed (need old state before saving)
    let old_net = state.store.get_network(id).await.ok().flatten();
    let dhcp_changed = old_net.as_ref().is_some_and(|old| {
        old.dhcp_enabled != payload.dhcp_enabled
            || old.dhcp_mode != payload.dhcp_mode
            || old.pool_start != payload.pool_start
            || old.pool_end != payload.pool_end
    });

    match state.store.put_network(&payload).await {
        Ok(()) => {
            let _ = state.event_manager.send("network_updated".to_string());

            // Restart DHCP services if any DHCP-relevant field changed
            if dhcp_changed {
                crate::restart_network_services(&state).await;
            }

            Json(&payload).into_response()
        }
        Err(e) => {
            error!("Failed to update network: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

/// Check if a given network has dhcp_mode "full" (needs service restart on change)
async fn is_full_dhcp_target_network(state: &AppState, network_id: Uuid) -> bool {
    if let Ok(Some(net)) = state.store.get_network(network_id).await {
        return net.dhcp_mode == "full";
    }
    false
}

async fn delete_network_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state.store.delete_network(id).await {
        Ok(true) => {
            let _ = state.event_manager.send("network_deleted".to_string());
            Json(json!({"success": true})).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Network not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete network: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Machine Apply Handler (stub - will execute Jetpack playbook)
// ============================================================================

async fn apply_machine_config_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    // Get machine
    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Machine not found"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    if !machine.config.pending_apply {
        return Json(json!({"success": true, "message": "No pending changes to apply"}))
            .into_response();
    }

    // Mark as applied — keep new values, clear pending tracking + snapshot
    machine.config.pending_apply = false;
    machine.config.pending_fields.clear();
    machine.config.pending_snapshot = None;
    machine.metadata.updated_at = chrono::Utc::now();

    // Update current_ip to reflect the static config that will be applied
    if let Some(ref static_ipv4) = machine.config.static_ipv4 {
        if matches!(
            machine.config.network_mode,
            dragonfly_common::NetworkMode::StaticIpv4
                | dragonfly_common::NetworkMode::StaticDualStack
        ) {
            machine.status.current_ip = Some(static_ipv4.address.clone());
        }
    }

    match state.store.put_machine(&machine).await {
        Ok(()) => {
            let _ = state.event_manager.send(format!("machine_updated:{}", id));
            let response_machine = machine_to_common(&machine);
            Json(json!({"success": true, "message": "Configuration marked as applied", "machine": response_machine})).into_response()
        }
        Err(e) => {
            error!("Failed to update machine after apply: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

/// POST /api/machines/{id}/proxmox/apply-config — push cores/RAM config to Proxmox API
async fn apply_proxmox_config(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
) -> Response {
    use proxmox_client::HttpApiClient;

    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    let machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Machine not found"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let (node, vmid, is_lxc) = match &machine.metadata.source {
        dragonfly_common::MachineSource::Proxmox { node, vmid, .. } => (node.clone(), *vmid, false),
        dragonfly_common::MachineSource::ProxmoxLxc { node, ctid, .. } => {
            (node.clone(), *ctid, true)
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Not a Proxmox VM or LXC"})),
            )
                .into_response();
        }
    };

    // Build config JSON to push
    let mut config = serde_json::Map::new();
    if let Some(cores) = machine.hardware.cpu_cores {
        config.insert("cores".to_string(), json!(cores));
    }
    if let Some(mem_bytes) = machine.hardware.memory_bytes {
        // Proxmox uses megabytes
        let mem_mb = mem_bytes / (1024 * 1024);
        config.insert("memory".to_string(), json!(mem_mb));
    }

    if config.is_empty() {
        return Json(json!({"success": true, "message": "No config changes to push"}))
            .into_response();
    }

    let vm_type = if is_lxc { "lxc" } else { "qemu" };
    let config_path = format!("/api2/json/nodes/{}/{}/{}/config", node, vm_type, vmid);
    let params = serde_json::Value::Object(config.clone());

    match crate::handlers::proxmox::connect_to_proxmox(&state, "config").await {
        Ok(client) => match client.put(&config_path, &params).await {
            Ok(response) => {
                if response.status >= 200 && response.status < 300 {
                    info!(
                        "Successfully pushed config to Proxmox VM {} (node {}): {:?}",
                        vmid, node, config
                    );
                    Json(json!({"success": true, "message": "Configuration pushed to Proxmox"}))
                        .into_response()
                } else {
                    error!(
                        "Proxmox config push failed for VM {}: status {}",
                        vmid, response.status
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": "Proxmox returned error",
                            "message": format!("Status {}", response.status)
                        })),
                    )
                        .into_response()
                }
            }
            Err(e) => {
                error!("Proxmox config push error for VM {}: {}", vmid, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "Failed to push config to Proxmox",
                        "message": e.to_string()
                    })),
                )
                    .into_response()
            }
        },
        Err(e) => {
            error!("Failed to connect to Proxmox for config push: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to connect to Proxmox",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// POST /api/machines/{id}/revert-pending — clear pending state without applying
async fn revert_pending_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<Uuid>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    let mut machine = match state.store.get_machine(id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Machine not found"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    revert_pending_changes(&mut machine);

    match state.store.put_machine(&machine).await {
        Ok(()) => {
            let _ = state.event_manager.send(format!("machine_updated:{}", id));
            let response_machine = machine_to_common(&machine);
            Json(serde_json::to_value(response_machine).unwrap_or(json!({}))).into_response()
        }
        Err(e) => {
            error!("Failed to revert pending for machine {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

// =============================================================================
// DHCP Lease Management
// =============================================================================

/// GET /api/dhcp/leases — List all active DHCP leases
async fn list_dhcp_leases_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    let table = state.dhcp_lease_table.read().await;
    let leases = table.active_leases();
    Json(leases).into_response()
}

/// DELETE /api/dhcp/leases/{mac} — Terminate a specific DHCP lease
async fn terminate_dhcp_lease_handler(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(mac): Path<String>,
) -> Response {
    if auth_session.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    let mut table = state.dhcp_lease_table.write().await;
    if table.remove_lease(&mac) {
        Json(json!({"success": true})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Lease not found"})),
        )
            .into_response()
    }
}

// === High Availability Handlers ===

/// GET /api/ha/status — return HA cluster status
async fn ha_status_handler(
    State(state): State<crate::AppState>,
) -> impl IntoResponse {
    let status = state.ha_manager.status().await;
    Json(status)
}

/// POST /api/ha/enable — enable HA mode (download rqlite, migrate data, start cluster)
async fn ha_enable_handler(
    State(state): State<crate::AppState>,
) -> Response {
    use crate::store::v1::SqliteStore;

    // Check if already enabled
    if crate::ha::HaManager::is_ha_enabled() {
        return (
            StatusCode::CONFLICT,
            "High Availability is already enabled",
        )
            .into_response();
    }

    // We need access to the current SQLite store for migration
    // The store in AppState implements Store trait — we need the concrete SqliteStore
    // For now, open a second read-only connection to the SQLite db for migration
    let sqlite_path = "/var/lib/dragonfly/dragonfly.sqlite3";
    let sqlite_store = match SqliteStore::open(sqlite_path).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to open SQLite for migration: {}", e),
            )
                .into_response();
        }
    };

    match state.ha_manager.enable_ha(&sqlite_store).await {
        Ok(_new_store) => {
            // Note: The store swap happens on next restart for safety.
            // The HA flag file is written, so next startup will use rqlite.
            Json(json!({
                "success": true,
                "message": "High Availability enabled. Data migrated to rqlite. The cluster is now active."
            }))
            .into_response()
        }
        Err(e) => {
            error!("Failed to enable HA: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to enable HA: {}", e),
            )
                .into_response()
        }
    }
}

/// POST /api/ha/disable — disable HA mode (migrate back to SQLite, stop rqlite, destroy LXCs)
///
/// Rule 425: Also handles the case where HA is NOT enabled but a cluster_plan
/// exists from a failed/aborted deployment.  Destroys orphaned LXCs and clears
/// the plan so the user is never stuck.
async fn ha_disable_handler(
    State(state): State<crate::AppState>,
) -> Response {
    let has_cluster_plan = state.store.get_setting("cluster_plan").await
        .ok()
        .flatten()
        .map(|p| !p.is_empty())
        .unwrap_or(false);

    // Rule 425: If there's a stale cluster_plan but HA isn't enabled,
    // clean up the orphaned LXCs and clear the plan.
    if !crate::ha::HaManager::is_ha_enabled() && !has_cluster_plan {
        return (
            StatusCode::CONFLICT,
            "High Availability is not enabled",
        )
            .into_response();
    }

    if !crate::ha::HaManager::is_ha_enabled() && has_cluster_plan {
        // Failed/aborted deployment left orphaned state — clean it up
        info!("Cleaning up orphaned cluster plan (HA not enabled)");
        match crate::cluster::abort_cluster(&state).await {
            Ok(()) => {
                return Json(json!({
                    "success": true,
                    "message": "Orphaned cluster plan cleaned up. LXCs destroyed."
                }))
                .into_response();
            }
            Err(e) => {
                error!("Failed to clean up orphaned cluster: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to clean up: {}", e),
                )
                    .into_response();
            }
        }
    }

    // Check if this is a cluster deployment (has cluster_plan)
    // (has_cluster_plan already computed above)
    let has_cluster_plan = state.store.get_setting("cluster_plan").await
        .ok()
        .flatten()
        .map(|p| !p.is_empty())
        .unwrap_or(false);

    if has_cluster_plan {
        // Use cluster dissolve which handles LXC destruction
        match crate::cluster::dissolve_cluster(&state).await {
            Ok(()) => {
                // Also stop local rqlite if running
                let _ = state.ha_manager.stop().await;
                Json(json!({
                    "success": true,
                    "message": "Cluster dissolved. LXCs destroyed. Back to standalone SQLite."
                }))
                .into_response()
            }
            Err(e) => {
                error!("Failed to dissolve cluster: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to dissolve cluster: {}", e),
                )
                    .into_response()
            }
        }
    } else {
        // Legacy single-node HA disable
        let rqlite_store = match crate::ha::read_ha_config() {
            Some(config) => {
                let hosts = config.hosts_by_priority();
                crate::store::v1::RqliteStore::open_cluster(&hosts).await
            }
            None => {
                let url = state.ha_manager.rqlite_url();
                crate::store::v1::RqliteStore::open(&url).await
            }
        };
        let rqlite_store = match rqlite_store {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to connect to rqlite for migration: {}", e),
                )
                    .into_response();
            }
        };

        let sqlite_path = "/var/lib/dragonfly/dragonfly.sqlite3";
        match state.ha_manager.disable_ha(&rqlite_store, sqlite_path).await {
            Ok(_new_store) => {
                Json(json!({
                    "success": true,
                    "message": "Converted back to standalone SQLite. rqlite stopped."
                }))
                .into_response()
            }
            Err(e) => {
                error!("Failed to disable HA: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to disable HA: {}", e),
                )
                    .into_response()
            }
        }
    }
}

// === Cluster Deployment Handlers ===

/// POST /api/cluster/create — Build and deploy an HA cluster across Proxmox nodes
async fn cluster_create_handler(
    State(state): State<crate::AppState>,
) -> Response {
    // Check if already enabled
    if crate::ha::HaManager::is_ha_enabled() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "HA is already enabled"})),
        )
            .into_response();
    }

    // If a deployment is already running, signal it to abort and wait for it to finish.
    // This enables retry: the idempotent design means the next run picks up where it left off.
    if state.cluster_deploying.load(std::sync::atomic::Ordering::Relaxed) {
        info!("Retry requested — signalling current deployment to abort");
        state.cluster_abort.store(true, std::sync::atomic::Ordering::Relaxed);
        // Wait for the current deployment task to finish (DeployGuard clears the flag on drop)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if !state.cluster_deploying.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if std::time::Instant::now() > deadline {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "Timed out waiting for previous deployment to stop"})),
                )
                    .into_response();
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        info!("Previous deployment finished, starting retry");
    }

    // Mark deploying immediately so status endpoint reflects it
    state.cluster_deploying.store(true, std::sync::atomic::Ordering::Relaxed);

    // Auto-clear stale plans — hostname scanning detects and reuses existing containers.
    // Rule 425: NEVER block the user with stale state they can't clear from the UI.
    if let Ok(Some(existing)) = state.store.get_setting("cluster_plan").await {
        if !existing.is_empty() {
            info!("Clearing stale cluster plan before new deployment — hostname scanning will find existing containers");
            state.cluster_abort.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = state.store.put_setting("cluster_plan", "").await;
        }
    }

    // Spawn the entire planning + deployment flow as a background task.
    // Planning queries all Proxmox nodes for storage, which can take minutes.
    // The plan is persisted inside deploy_cluster() before any creation.
    let deploy_state = state.clone();
    tokio::spawn(async move {
        match crate::cluster::build_cluster_plan(&deploy_state).await {
            Ok(plan) => {
                // Emit the plan to SSE so the UI can show node cards immediately
                let plan_event = serde_json::json!({
                    "type": "cluster",
                    "phase": "planned",
                    "nodes": plan.nodes.iter().map(|n| serde_json::json!({
                        "idx": n.idx,
                        "hostname": n.hostname,
                        "proxmox_node": n.proxmox_node,
                        "vmid": n.vmid,
                        "ip": n.ip.to_string(),
                        "role": n.role,
                    })).collect::<Vec<serde_json::Value>>(),
                });
                let _ = deploy_state.event_manager.send(format!("cluster:{}", plan_event));

                crate::cluster::deploy_cluster(deploy_state, plan).await;
            }
            Err(e) => {
                error!("Failed to build cluster plan: {}", e);
                let payload = serde_json::json!({
                    "type": "cluster",
                    "idx": -1,
                    "phase": "error",
                    "msg": format!("Failed to build cluster plan: {}", e),
                });
                let _ = deploy_state.event_manager.send(format!("cluster:{}", payload));
                deploy_state.cluster_deploying.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    // Return immediately — the UI subscribes to SSE for progress
    Json(json!({
        "success": true,
        "message": "Cluster deployment started — planning in progress",
    })).into_response()
}

/// POST /api/cluster/abort — Abort an in-flight cluster deployment and clean up
///
/// Rule 425: Never leave state the user has to clean up manually.
/// Sets the abort flag for the running deploy task, then cleans up any
/// already-created LXCs and clears the stored cluster plan.
async fn cluster_abort_handler(
    State(state): State<crate::AppState>,
) -> Response {
    info!("Cluster abort requested");

    match crate::cluster::abort_cluster(&state).await {
        Ok(()) => {
            Json(json!({
                "success": true,
                "message": "Deployment aborted and cleaned up"
            }))
            .into_response()
        }
        Err(e) => {
            error!("Cluster abort failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Abort failed: {}", e)})),
            )
                .into_response()
        }
    }
}

/// GET /api/cluster/status — Get current cluster deployment status
///
/// Returns the stored cluster plan (if any) and whether deployment is active.
/// The UI uses this on page load to reconnect to an in-progress deployment.
async fn cluster_status_handler(
    State(state): State<crate::AppState>,
) -> impl IntoResponse {
    let plan_json = state.store.get_setting("cluster_plan").await
        .ok()
        .flatten()
        .unwrap_or_default();
    let actively_deploying = state.cluster_deploying.load(std::sync::atomic::Ordering::Relaxed);

    // Read current deployment phase info for reconnecting clients
    let global_phase = state.cluster_phase.lock()
        .map(|p| p.clone()).unwrap_or_default();
    let node_phases = state.cluster_node_phases.lock()
        .map(|m| m.clone()).unwrap_or_default();

    if plan_json.is_empty() {
        return Json(json!({
            "deployed": false,
            "deploying": actively_deploying,
            "phase": global_phase,
            "nodes": [],
        }));
    }

    let ha_enabled = crate::ha::HaManager::is_ha_enabled();

    match serde_json::from_str::<crate::cluster::ClusterPlan>(&plan_json) {
        Ok(plan) => {
            Json(json!({
                "deployed": true,
                // True if the deployment task is actively running, or plan exists but HA not yet enabled (stuck/failed)
                "deploying": actively_deploying || !ha_enabled,
                "phase": global_phase,
                "nodes": plan.nodes.iter().map(|n| {
                    let node_phase = node_phases.get(&n.idx)
                        .cloned()
                        .unwrap_or_default();
                    json!({
                        "idx": n.idx,
                        "hostname": n.hostname,
                        "proxmox_node": n.proxmox_node,
                        "vmid": n.vmid,
                        "ip": n.ip.to_string(),
                        "role": n.role,
                        "state": n.state,
                        "phase": node_phase,
                    })
                }).collect::<Vec<_>>(),
            }))
        }
        Err(_) => {
            // Unparseable plan — stale data from old format. Clear it automatically.
            // Rule 425: don't leave garbage for the user to clean up.
            let _ = state.store.put_setting("cluster_plan", "").await;
            Json(json!({
                "deployed": false,
                "deploying": false,
                "nodes": [],
            }))
        }
    }
}

// =============================================================================
// SSH Management Key
// =============================================================================

/// Get the current management key status (public key fingerprint, creation date).
/// Never returns the private key.
async fn cluster_management_key_handler(
    State(state): State<crate::AppState>,
) -> impl IntoResponse {
    let pubkey = state.store.get_setting("cluster_management_pubkey").await
        .ok().flatten().unwrap_or_default();

    if pubkey.is_empty() {
        return Json(json!({
            "exists": false,
        }));
    }

    // Parse the public key to get the fingerprint
    let fingerprint = ssh_key::PublicKey::from_openssh(&pubkey)
        .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    Json(json!({
        "exists": true,
        "public_key": pubkey,
        "fingerprint": fingerprint,
    }))
}

/// Rotate the management key: generates a new keypair, stores it, and returns the new fingerprint.
/// Note: Existing cluster nodes will need the new key deployed on next provision/restart.
async fn cluster_rotate_key_handler(
    State(state): State<crate::AppState>,
) -> impl IntoResponse {
    // Clear existing key so ensure_management_key() generates fresh
    let _ = state.store.put_setting("cluster_management_pubkey", "").await;
    let _ = state.store.put_setting("cluster_management_privkey", "").await;

    match crate::cluster::ensure_management_key_public(&state).await {
        Ok((pubkey, _)) => {
            let fingerprint = ssh_key::PublicKey::from_openssh(&pubkey)
                .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            Json(json!({
                "success": true,
                "public_key": pubkey,
                "fingerprint": fingerprint,
            }))
        }
        Err(e) => {
            Json(json!({
                "success": false,
                "error": format!("{}", e),
            }))
        }
    }
}

// =============================================================================
// Maintenance — Developer Mode
// =============================================================================

/// GET /api/maintenance/dev-mode — check if developer mode is active
async fn dev_mode_status_handler(
    State(state): State<crate::AppState>,
) -> impl IntoResponse {
    let dev_path = state.dev_template_path.read().unwrap();
    let enabled = dev_path.is_some();
    let template_path = dev_path.clone().unwrap_or_default();

    Json(json!({
        "enabled": enabled,
        "template_path": template_path,
    }))
}

#[derive(Deserialize)]
struct DevModeRequest {
    enabled: bool,
    #[serde(default)]
    template_path: Option<String>,
}

/// POST /api/maintenance/dev-mode — hot-swap template env without restart
async fn dev_mode_toggle_handler(
    State(state): State<crate::AppState>,
    Json(request): Json<DevModeRequest>,
) -> impl IntoResponse {
    use minijinja::path_loader;
    use crate::TemplateEnv;

    if request.enabled {
        let raw_path = match request.template_path {
            Some(ref p) if !p.is_empty() => p.clone(),
            _ => return Json(json!({
                "success": false,
                "message": "Template path is required when enabling developer mode",
            })),
        };

        // Validate path exists
        let raw = std::path::Path::new(&raw_path);
        if !raw.exists() {
            return Json(json!({
                "success": false,
                "message": format!("Path does not exist: {}", raw_path),
            }));
        }

        // Resolve the templates directory:
        // 1. If the path already contains templates directly (has base.html), use as-is
        // 2. If the path is a git checkout root, look for crates/dragonfly-server/templates/
        // 3. Otherwise, fail with a helpful message
        let template_path = if raw.join("base.html").exists() {
            raw_path.clone()
        } else if raw.join("crates/dragonfly-server/templates/base.html").exists() {
            raw.join("crates/dragonfly-server/templates").to_string_lossy().to_string()
        } else {
            return Json(json!({
                "success": false,
                "message": format!(
                    "No templates found at '{}'. Provide either a Dragonfly git checkout root or the templates directory directly.",
                    raw_path
                ),
            }));
        };

        // Safety check: verify essential templates exist
        let essential = ["base.html", "login.html", "settings.html", "index.html"];
        let tp = std::path::Path::new(&template_path);
        for name in &essential {
            if !tp.join(name).exists() {
                return Json(json!({
                    "success": false,
                    "message": format!("Missing essential template '{}' in {}", name, template_path),
                }));
            }
        }

        // Create a reloading environment pointing to disk
        let path_clone = template_path.clone();
        let reloader = minijinja_autoreload::AutoReloader::new(move |notifier| {
            let mut env = minijinja::Environment::new();
            env.set_loader(path_loader(&path_clone));
            if let Err(e) = crate::ui::setup_minijinja_environment(&mut env) {
                tracing::error!("Failed to set up MiniJinja environment: {}", e);
            }
            notifier.set_fast_reload(true);
            Ok(env)
        });

        // Hot-swap the template env
        {
            let mut env_lock = state.template_env.write().unwrap();
            *env_lock = TemplateEnv::Reloading(std::sync::Arc::new(reloader));
        }

        // Store path so status handler can report it
        *state.dev_template_path.write().unwrap() = Some(template_path.clone());

        info!("Developer mode enabled: templates from {}", template_path);

        Json(json!({
            "success": true,
            "message": format!("Developer mode enabled. Templates now loaded from {}", template_path),
        }))
    } else {
        // Switch back to embedded templates
        let mut env = minijinja::Environment::new();
        minijinja_embed::load_templates!(&mut env);
        if let Err(e) = crate::ui::setup_minijinja_environment(&mut env) {
            tracing::error!("Failed to set up MiniJinja environment: {}", e);
        }

        {
            let mut env_lock = state.template_env.write().unwrap();
            *env_lock = TemplateEnv::Static(std::sync::Arc::new(env));
        }

        *state.dev_template_path.write().unwrap() = None;

        info!("Developer mode disabled: using embedded templates");

        Json(json!({
            "success": true,
            "message": "Developer mode disabled. Using embedded templates.",
        }))
    }
}

// =============================================================================
// Unified Credentials API
// =============================================================================

#[derive(serde::Serialize, Clone)]
struct CredentialInfo {
    id: String,
    credential_type: String,
    label: String,
    status: String,
    detail: String,
    rotatable: bool,
    deletable: bool,
}

/// Helper: compute SSH key fingerprint from stored public key
fn ssh_fingerprint(pubkey: &str) -> String {
    ssh_key::PublicKey::from_openssh(pubkey)
        .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// GET /api/credentials — list all credentials as a unified view
async fn credentials_list_handler(
    State(state): State<crate::AppState>,
) -> impl IntoResponse {
    let mut credentials: Vec<CredentialInfo> = Vec::new();

    // 1. Proxmox credentials
    if let Ok(Some(settings)) = crate::handlers::proxmox::get_proxmox_settings_from_store_pub(
        state.store.as_ref()
    ).await {
        let token_count = [
            &settings.vm_create_token,
            &settings.vm_power_token,
            &settings.vm_config_token,
            &settings.vm_sync_token,
        ].iter().filter(|t| t.is_some()).count();

        if token_count > 0 || !settings.host.is_empty() {
            let status = if token_count == 4 { "active" } else if token_count > 0 { "partial" } else { "missing" };
            credentials.push(CredentialInfo {
                id: "proxmox".to_string(),
                credential_type: "proxmox".to_string(),
                label: format!("Proxmox ({})", settings.username),
                status: status.to_string(),
                detail: format!("{}/4 tokens", token_count),
                rotatable: false,
                deletable: true,
            });
        }
    }

    // 2. SSH Cluster Key
    let cluster_pub = state.store.get_setting("cluster_management_pubkey").await
        .ok().flatten().unwrap_or_default();
    if !cluster_pub.is_empty() {
        credentials.push(CredentialInfo {
            id: "ssh-cluster".to_string(),
            credential_type: "ssh-cluster".to_string(),
            label: "Cluster Key".to_string(),
            status: "active".to_string(),
            detail: ssh_fingerprint(&cluster_pub),
            rotatable: true,
            deletable: true,
        });
    }

    // 3. SSH Machine Key
    let machine_pub = state.store.get_setting("machine_management_pubkey").await
        .ok().flatten().unwrap_or_default();
    if !machine_pub.is_empty() {
        credentials.push(CredentialInfo {
            id: "ssh-machine".to_string(),
            credential_type: "ssh-machine".to_string(),
            label: "Machine Key".to_string(),
            status: "active".to_string(),
            detail: ssh_fingerprint(&machine_pub),
            rotatable: true,
            deletable: true,
        });
    }

    Json(json!({ "credentials": credentials }))
}

#[derive(Deserialize)]
struct AddCredentialRequest {
    command: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<i32>,
    #[serde(default)]
    skip_tls_verify: Option<bool>,
    #[serde(default)]
    import_guests: Option<bool>,
}

/// POST /api/credentials/add — add or generate a credential by command string
async fn credentials_add_handler(
    State(state): State<crate::AppState>,
    Json(request): Json<AddCredentialRequest>,
) -> impl IntoResponse {
    let cmd = request.command.trim();

    if cmd.starts_with("proxmox:") {
        // Parse proxmox:username:password
        let rest = &cmd["proxmox:".len()..];
        let colon_pos = match rest.find(':') {
            Some(pos) => pos,
            None => return Json(json!({
                "success": false,
                "message": "Invalid format. Use proxmox:username:password"
            })),
        };
        let username = &rest[..colon_pos];
        let password = &rest[colon_pos + 1..];

        if username.is_empty() || password.is_empty() {
            return Json(json!({
                "success": false,
                "message": "Username and password cannot be empty"
            }));
        }

        // Get host/port from request or existing settings
        let (host, port, skip_tls) = {
            let settings = state.settings.lock().await;
            (
                request.host.clone().or_else(|| settings.proxmox_host.clone())
                    .unwrap_or_default(),
                request.port.or_else(|| settings.proxmox_port.map(|p| p as i32))
                    .unwrap_or(8006),
                request.skip_tls_verify.or_else(|| settings.proxmox_skip_tls_verify)
                    .unwrap_or(false),
            )
        };

        if host.is_empty() {
            return Json(json!({
                "success": false,
                "message": "No Proxmox host configured. Provide host in the form."
            }));
        }

        let token_request = crate::handlers::proxmox::ProxmoxTokensCreateRequest {
            host: host.clone(),
            port,
            username: username.to_string(),
            password: password.to_string(),
            skip_tls_verify: skip_tls,
        };

        let import_guests = request.import_guests.unwrap_or(false);

        match crate::handlers::proxmox::generate_proxmox_tokens_with_credentials(&token_request).await {
            Ok(token_set) => {
                match crate::handlers::proxmox::save_proxmox_tokens(&state, token_set).await {
                    Ok(_) => {
                        // Run discovery to import nodes (and guests if requested)
                        let (_, discover_json) = crate::handlers::proxmox::connect_proxmox_discover(
                            &state, &host, import_guests, false,
                        ).await;
                        let discover_data = discover_json.0;
                        let import_info = discover_data.get("import_result")
                            .and_then(|r| r.as_object());
                        let nodes = import_info
                            .and_then(|r| r.get("imported_nodes"))
                            .and_then(|n| n.as_u64())
                            .unwrap_or(0);
                        let guests = import_info
                            .and_then(|r| r.get("imported_guests"))
                            .and_then(|n| n.as_u64())
                            .unwrap_or(0);
                        let mut msg = format!("Connected to Proxmox as {}. Discovered {} nodes", username, nodes);
                        if import_guests && guests > 0 {
                            msg.push_str(&format!(", {} guests imported", guests));
                        }
                        Json(json!({
                            "success": true,
                            "message": msg,
                        }))
                    }
                    Err(e) => Json(json!({
                        "success": false,
                        "message": format!("Tokens created but failed to save: {}", e),
                    })),
                }
            }
            Err(e) => Json(json!({
                "success": false,
                "message": format!("Failed to create Proxmox tokens: {}", e),
            })),
        }
    } else if cmd == "ssh-keygen cluster" {
        match crate::cluster::ensure_management_key_public(&state).await {
            Ok((pubkey, _)) => {
                let fp = ssh_fingerprint(&pubkey);
                Json(json!({
                    "success": true,
                    "message": format!("Cluster key generated ({})", fp),
                }))
            }
            Err(e) => Json(json!({
                "success": false,
                "message": format!("Failed to generate cluster key: {}", e),
            })),
        }
    } else if cmd == "ssh-keygen machine" {
        match crate::cluster::ensure_machine_key_public(&state).await {
            Ok((pubkey, _)) => {
                let fp = ssh_fingerprint(&pubkey);
                Json(json!({
                    "success": true,
                    "message": format!("Machine key generated ({})", fp),
                }))
            }
            Err(e) => Json(json!({
                "success": false,
                "message": format!("Failed to generate machine key: {}", e),
            })),
        }
    } else {
        Json(json!({
            "success": false,
            "message": format!("Unknown command: {}. Use proxmox:user:pass, ssh-keygen cluster, or ssh-keygen machine", cmd),
        }))
    }
}

/// POST /api/credentials/{id}/rotate — rotate a credential
async fn credentials_rotate_handler(
    State(state): State<crate::AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match id.as_str() {
        "proxmox" => Json(json!({
            "success": false,
            "message": "Use 'Add' to re-connect with Proxmox credentials",
        })),
        "ssh-cluster" => {
            let _ = state.store.put_setting("cluster_management_pubkey", "").await;
            let _ = state.store.put_setting("cluster_management_privkey", "").await;
            match crate::cluster::ensure_management_key_public(&state).await {
                Ok((pubkey, _)) => {
                    let fp = ssh_fingerprint(&pubkey);
                    Json(json!({
                        "success": true,
                        "message": format!("Cluster key rotated ({})", fp),
                    }))
                }
                Err(e) => Json(json!({
                    "success": false,
                    "message": format!("Failed to rotate cluster key: {}", e),
                })),
            }
        }
        "ssh-machine" => {
            let _ = state.store.put_setting("machine_management_pubkey", "").await;
            let _ = state.store.put_setting("machine_management_privkey", "").await;
            match crate::cluster::ensure_machine_key_public(&state).await {
                Ok((pubkey, _)) => {
                    let fp = ssh_fingerprint(&pubkey);
                    Json(json!({
                        "success": true,
                        "message": format!("Machine key rotated ({})", fp),
                    }))
                }
                Err(e) => Json(json!({
                    "success": false,
                    "message": format!("Failed to rotate machine key: {}", e),
                })),
            }
        }
        _ => Json(json!({
            "success": false,
            "message": format!("Unknown credential: {}", id),
        })),
    }
}

/// DELETE /api/credentials/{id} — delete a credential
async fn credentials_delete_handler(
    State(state): State<crate::AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let _cleanup = params.get("cleanup").map(|v| v == "true").unwrap_or(false);

    match id.as_str() {
        "proxmox" => {
            // Clear tokens from store by setting them all to None
            if let Ok(Some(mut settings)) = crate::handlers::proxmox::get_proxmox_settings_from_store_pub(
                state.store.as_ref()
            ).await {
                settings.vm_create_token = None;
                settings.vm_power_token = None;
                settings.vm_config_token = None;
                settings.vm_sync_token = None;
                settings.host = String::new();
                settings.username = String::new();
                let _ = crate::handlers::proxmox::put_proxmox_settings_to_store_pub(
                    state.store.as_ref(), &settings
                ).await;
            }
            // Clear in-memory tokens
            {
                let mut tokens = state.tokens.lock().await;
                tokens.remove("proxmox_vm_create_token");
                tokens.remove("proxmox_vm_power_token");
                tokens.remove("proxmox_vm_config_token");
                tokens.remove("proxmox_vm_sync_token");
            }
            // Clear in-memory settings
            {
                let mut settings = state.settings.lock().await;
                settings.proxmox_host = None;
                settings.proxmox_port = None;
                settings.proxmox_username = None;
                settings.proxmox_skip_tls_verify = None;
            }
            Json(json!({
                "success": true,
                "message": "Proxmox credentials removed",
            }))
        }
        "ssh-cluster" => {
            let _ = state.store.put_setting("cluster_management_pubkey", "").await;
            let _ = state.store.put_setting("cluster_management_privkey", "").await;
            let _ = std::fs::remove_file("/var/lib/dragonfly/cluster-deploy/management_key");
            Json(json!({
                "success": true,
                "message": "Cluster key removed",
            }))
        }
        "ssh-machine" => {
            let _ = state.store.put_setting("machine_management_pubkey", "").await;
            let _ = state.store.put_setting("machine_management_privkey", "").await;
            let _ = std::fs::remove_file("/var/lib/dragonfly/machine_key");
            Json(json!({
                "success": true,
                "message": "Machine key removed",
            }))
        }
        _ => Json(json!({
            "success": false,
            "message": format!("Unknown credential: {}", id),
        })),
    }
}

// =============================================================================
// DNS Record Management
// =============================================================================

/// List DNS zones (derived from networks with Internal DNS provider + domain)
async fn dns_list_zones_handler(State(state): State<crate::AppState>) -> Response {
    let networks = match state.store.list_networks().await {
        Ok(n) => n,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{}", e)})),
            )
                .into_response()
        }
    };

    let zones: Vec<_> = networks
        .iter()
        .filter(|n| n.dns_provider == dragonfly_common::dns::DnsProvider::Internal)
        .filter_map(|n| {
            n.domain.as_ref().map(|domain| {
                json!({
                    "zone": domain,
                    "network_id": n.id,
                    "network_name": n.name,
                    "subnet": n.subnet,
                })
            })
        })
        .collect();

    Json(json!({ "zones": zones })).into_response()
}

/// List all DNS records in a zone
async fn dns_list_records_handler(
    State(state): State<crate::AppState>,
    Path(zone): Path<String>,
) -> Response {
    match state.store.list_dns_records(&zone).await {
        Ok(records) => Json(json!({ "records": records })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct CreateDnsRecordRequest {
    name: String,
    rtype: dragonfly_common::dns::DnsRecordType,
    rdata: String,
    #[serde(default = "default_dns_ttl")]
    ttl: u32,
    #[serde(default)]
    machine_id: Option<Uuid>,
}

fn default_dns_ttl() -> u32 {
    3600
}

/// Create a DNS record in a zone
async fn dns_create_record_handler(
    State(state): State<crate::AppState>,
    Path(zone): Path<String>,
    Json(req): Json<CreateDnsRecordRequest>,
) -> Response {
    match state
        .store
        .upsert_dns_record(
            &zone,
            &req.name,
            req.rtype,
            &req.rdata,
            req.ttl,
            dragonfly_common::dns::DnsRecordSource::Manual,
            req.machine_id,
        )
        .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            Json(json!({
                "success": true,
                "zone": zone,
                "name": req.name,
                "rtype": req.rtype,
                "rdata": req.rdata,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateDnsRecordRequest {
    name: Option<String>,
    rtype: Option<dragonfly_common::dns::DnsRecordType>,
    rdata: Option<String>,
    ttl: Option<u32>,
    machine_id: Option<Uuid>,
}

/// Update a DNS record
async fn dns_update_record_handler(
    State(state): State<crate::AppState>,
    Path((zone, id)): Path<(String, Uuid)>,
    Json(req): Json<UpdateDnsRecordRequest>,
) -> Response {
    // Get current records to find the one to update
    let records = match state.store.list_dns_records(&zone).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{}", e)})),
            )
                .into_response()
        }
    };

    let existing = match records.iter().find(|r| r.id == id) {
        Some(r) => r.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Record not found"})),
            )
                .into_response()
        }
    };

    // Build updated record
    let updated = dragonfly_common::dns::DnsRecord {
        id: existing.id,
        zone: zone.clone(),
        name: req.name.unwrap_or(existing.name),
        rtype: req.rtype.unwrap_or(existing.rtype),
        rdata: req.rdata.unwrap_or(existing.rdata),
        ttl: req.ttl.unwrap_or(existing.ttl),
        source: existing.source,
        machine_id: req.machine_id.or(existing.machine_id),
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    match state.store.put_dns_record(&updated).await {
        Ok(_) => Json(json!({
            "success": true,
            "record": updated,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

/// Delete a DNS record by ID
async fn dns_delete_record_handler(
    State(state): State<crate::AppState>,
    Path((_zone, id)): Path<(String, Uuid)>,
) -> Response {
    match state.store.delete_dns_record(id).await {
        Ok(true) => Json(json!({"success": true})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Record not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

/// Get all DNS records for a specific machine
async fn dns_records_by_machine_handler(
    State(state): State<crate::AppState>,
    Path(machine_id): Path<Uuid>,
) -> Response {
    // Scan all zones for records matching this machine_id
    let networks = match state.store.list_networks().await {
        Ok(n) => n,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{}", e)})),
            )
                .into_response()
        }
    };

    let mut all_records = Vec::new();
    for network in &networks {
        if let Some(domain) = &network.domain {
            if let Ok(records) = state.store.list_dns_records(domain).await {
                for r in records {
                    if r.machine_id == Some(machine_id) {
                        all_records.push(r);
                    }
                }
            }
        }
    }

    Json(json!({ "records": all_records })).into_response()
}
