use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use proxmox_client::HttpApiClient;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::handlers::proxmox;
use dragonfly_common::MachineSource;
use dragonfly_common::models::{ErrorResponse, Machine, MachineStatus}; // Import proxmox functions

// Struct to receive the power action request
#[derive(Deserialize, Debug)]
pub struct BmcPowerActionRequest {
    pub action: String, // e.g., "reboot-pxe", "power-on", "power-off", "reboot", "start", "stop", "shutdown"
}

// Handler for BMC power actions
#[axum::debug_handler]
pub async fn bmc_power_action_handler(
    State(state): State<AppState>,
    Path(machine_id): Path<Uuid>,
    Json(payload): Json<BmcPowerActionRequest>,
) -> Result<Response, Response> {
    info!(
        "Received power action '{}' for machine {}",
        payload.action, machine_id
    );

    // 1. Fetch v1 machine directly (need MachineSource for dispatch)
    let v1_machine = match state.store.get_machine(machine_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            error!("Machine {} not found for power action", machine_id);
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Machine not found".to_string(),
                    message: format!("Machine with ID {} not found", machine_id),
                }),
            )
                .into_response());
        }
        Err(e) => {
            error!("Store error fetching machine {}: {}", machine_id, e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Store error".to_string(),
                    message: e.to_string(),
                }),
            )
                .into_response());
        }
    };

    // 2. Dispatch based on machine source type
    let machine = crate::store::conversions::machine_to_common(&v1_machine);
    match &v1_machine.metadata.source {
        MachineSource::Proxmox { node, vmid, .. } => {
            info!(
                "Proxmox VM action: node={}, vmid={}, action={}",
                node, vmid, payload.action
            );
            handle_proxmox_vm_action(state, &machine, &payload.action).await
        }
        MachineSource::ProxmoxLxc { node, ctid, .. } => {
            info!(
                "Proxmox LXC action: node={}, ctid={}, action={}",
                node, ctid, payload.action
            );
            handle_proxmox_lxc_action(&state, node, *ctid, &payload.action).await
        }
        MachineSource::ProxmoxNode { node, .. } => {
            info!(
                "Proxmox node action: node={}, action={}",
                node, payload.action
            );
            handle_proxmox_node_action(&state, node, &payload.action).await
        }
        _ => {
            error!(
                "Power actions not supported for machine {} (source: {:?})",
                machine_id, v1_machine.metadata.source
            );
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: "Power actions not supported for this machine type".to_string(),
                message: "This machine does not have a supported power management backend (Proxmox VM, LXC, or node).".to_string()
            })).into_response())
        }
    }
}

// Helper function to handle actions for Proxmox VMs
async fn handle_proxmox_vm_action(
    state: AppState,
    machine: &Machine,
    action: &str,
) -> Result<Response, Response> {
    info!(
        "DEBUG: handle_proxmox_vm_action called with action '{}' for machine {}",
        action, machine.id
    );

    // Extract necessary Proxmox info from the machine object
    let node = match &machine.proxmox_node {
        Some(n) => n,
        None => {
            error!("Proxmox VM {} is missing node information", machine.id);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Missing Proxmox node info".to_string(),
                    message: "This VM is missing required Proxmox node information".to_string(),
                }),
            )
                .into_response());
        }
    };
    let vmid = match machine.proxmox_vmid {
        Some(id) => id,
        None => {
            error!("Proxmox VM {} is missing VM ID information", machine.id);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Missing Proxmox VM ID info".to_string(),
                    message: "This VM is missing required Proxmox VM ID information".to_string(),
                }),
            )
                .into_response());
        }
    };

    // Perform the requested action
    match action {
        "start" => {
            info!(
                "DEBUG: Handling 'start' action for Proxmox VM {} (Node: {}, VMID: {})",
                machine.id, node, vmid
            );
            // Start the VM
            let path = format!("/api2/json/nodes/{}/qemu/{}/status/start", node, vmid);
            match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API");
                    match c.post(&path, &()).await {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully started Proxmox VM {}", vmid);
                                Ok((
                                    StatusCode::OK,
                                    Json(serde_json::json!({
                                        "message": "VM started successfully"
                                    })),
                                )
                                    .into_response())
                            } else {
                                error!("Failed to start VM {}: Status {}", vmid, response.status);
                                Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: format!("Failed to start VM"),
                                        message: format!(
                                            "Proxmox returned status code {}",
                                            response.status
                                        ),
                                    }),
                                )
                                    .into_response())
                            }
                        }
                        Err(e) => {
                            error!("Failed to start VM {}: {}", vmid, e);
                            Err(map_proxmox_error_to_response(
                                proxmox::ProxmoxHandlerError::ApiError(e),
                            ))
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to connect to Proxmox for BMC action on {}: {}",
                        machine.id, e
                    );
                    error!("DEBUG: Proxmox connection error details: {:?}", e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox: {}", e),
                        message: "Could not establish connection to Proxmox server. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response())
                }
            }
        }
        "stop" => {
            info!(
                "DEBUG: Handling 'stop' action for Proxmox VM {} (Node: {}, VMID: {})",
                machine.id, node, vmid
            );
            // Stop the VM
            let path = format!("/api2/json/nodes/{}/qemu/{}/status/stop", node, vmid);
            match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API");
                    match c.post(&path, &()).await {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully stopped Proxmox VM {}", vmid);
                                Ok((
                                    StatusCode::OK,
                                    Json(serde_json::json!({
                                        "message": "VM stopped successfully"
                                    })),
                                )
                                    .into_response())
                            } else {
                                error!("Failed to stop VM {}: Status {}", vmid, response.status);
                                Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: format!("Failed to stop VM"),
                                        message: format!(
                                            "Proxmox returned status code {}",
                                            response.status
                                        ),
                                    }),
                                )
                                    .into_response())
                            }
                        }
                        Err(e) => {
                            error!("Failed to stop VM {}: {}", vmid, e);
                            Err(map_proxmox_error_to_response(
                                proxmox::ProxmoxHandlerError::ApiError(e),
                            ))
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to connect to Proxmox for BMC action on {}: {}",
                        machine.id, e
                    );
                    error!("DEBUG: Proxmox connection error details: {:?}", e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox: {}", e),
                        message: "Could not establish connection to Proxmox server. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response())
                }
            }
        }
        "reboot-pxe" => {
            info!(
                "Attempting reboot-pxe for Proxmox VM {} (Node: {}, VMID: {})",
                machine.id, node, vmid
            );

            // 1. Connect with config token for setting boot order
            info!(
                "Connecting to Proxmox for config operations (setting boot order) on VM {} (ID: {})",
                vmid, machine.id
            );
            let config_client = match proxmox::connect_to_proxmox(&state, "config").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API with config token");
                    c
                }
                Err(e) => {
                    error!(
                        "Failed to connect to Proxmox for boot configuration on {}: {}",
                        machine.id, e
                    );
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox for config operations: {}", e),
                        message: "Could not establish connection to Proxmox server for boot configuration. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response());
                }
            };

            // 2. Set boot order to network with config token
            match proxmox::set_vm_next_boot(&config_client, node, vmid, "network").await {
                Ok(_) => info!("Set next boot to network for VM {}", vmid),
                Err(e) => {
                    error!("Failed to set next boot to network for VM {}: {}", vmid, e);
                    return Err(map_proxmox_error_to_response(e));
                }
            }

            // 3. Connect with power token for rebooting
            info!(
                "Connecting to Proxmox for power operations (reboot) on VM {} (ID: {})",
                vmid, machine.id
            );
            let power_client = match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API with power token");
                    c
                }
                Err(e) => {
                    error!(
                        "Failed to connect to Proxmox for power operations on {}: {}",
                        machine.id, e
                    );
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox for power operations: {}", e),
                        message: "Successfully set boot order but could not establish connection to Proxmox server for reboot. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response());
                }
            };

            // 4. Reboot the VM with power token
            match proxmox::reboot_vm(&power_client, node, vmid).await {
                Ok(_) => {
                    info!("Successfully initiated Proxmox reboot for VM {}", vmid);

                    // 5. Update v1 Store status to Installing
                    info!("Updating machine {} status to Installing", machine.id);
                    let updated_machine: Machine = match state.store.get_machine(machine.id).await {
                        Ok(Some(mut v1_machine)) => {
                            v1_machine.status.state = dragonfly_common::MachineState::Installing;
                            v1_machine.metadata.updated_at = chrono::Utc::now();
                            if let Err(e) = state.store.put_machine(&v1_machine).await {
                                error!(
                                    "Failed to update machine {} status after Proxmox reboot: {}",
                                    machine.id, e
                                );
                            } else {
                                let _ = state
                                    .event_manager
                                    .send(format!("machine_updated:{}", machine.id));
                            }
                            crate::store::conversions::machine_to_common(&v1_machine)
                        }
                        Ok(None) => {
                            error!(
                                "Machine {} disappeared during workflow creation",
                                machine.id
                            );
                            return Ok((StatusCode::OK, Json(serde_json::json!({
                                "message": "Proxmox reboot-pxe initiated successfully, but failed to create workflow (machine disappeared)"
                            }))).into_response());
                        }
                        Err(e) => {
                            error!(
                                "Failed to retrieve updated machine {} for workflow creation: {}",
                                machine.id, e
                            );
                            return Ok((StatusCode::OK, Json(serde_json::json!({
                                "message": "Proxmox reboot-pxe initiated successfully, but failed to create workflow (Store error)"
                            }))).into_response());
                        }
                    };

                    // 6. Success - machine is now set for PXE boot and rebooted
                    // (Tinkerbell workflow creation removed - using our own provisioning)
                    let os_choice = updated_machine
                        .os_choice
                        .as_deref()
                        .unwrap_or("ubuntu-2204");
                    info!("VM {} successfully set for PXE boot and rebooted", vmid);

                    Ok((
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "message": "Proxmox reboot-pxe initiated successfully",
                            "machine_id": machine.id.to_string(),
                            "vm_id": vmid,
                            "os_choice": os_choice
                        })),
                    )
                        .into_response())
                }
                Err(e) => {
                    error!("Failed to reboot VM {}: {}", vmid, e);
                    // Map ProxmoxHandlerError to an Axum response
                    Err(map_proxmox_error_to_response(e))
                }
            }
        }
        "reboot" => {
            info!(
                "DEBUG: Handling 'reboot' action for Proxmox VM {} (Node: {}, VMID: {})",
                machine.id, node, vmid
            );
            // Simple reboot without changing boot order
            match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API");
                    match c
                        .post(
                            &format!("/api2/json/nodes/{}/qemu/{}/status/reboot", node, vmid),
                            &(),
                        )
                        .await
                    {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully rebooted Proxmox VM {}", vmid);
                                Ok((
                                    StatusCode::OK,
                                    Json(serde_json::json!({
                                        "message": "VM reboot initiated successfully"
                                    })),
                                )
                                    .into_response())
                            } else {
                                error!("Failed to reboot VM {}: Status {}", vmid, response.status);
                                Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: format!("Failed to reboot VM"),
                                        message: format!(
                                            "Proxmox returned status code {}",
                                            response.status
                                        ),
                                    }),
                                )
                                    .into_response())
                            }
                        }
                        Err(e) => {
                            error!("Failed to reboot VM {}: {}", vmid, e);
                            Err(map_proxmox_error_to_response(
                                proxmox::ProxmoxHandlerError::ApiError(e),
                            ))
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to connect to Proxmox for BMC action on {}: {}",
                        machine.id, e
                    );
                    error!("DEBUG: Proxmox connection error details: {:?}", e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox: {}", e),
                        message: "Could not establish connection to Proxmox server. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response())
                }
            }
        }
        "shutdown" => {
            info!(
                "Handling 'shutdown' (ACPI graceful) for Proxmox VM {} (Node: {}, VMID: {})",
                machine.id, node, vmid
            );
            let path = format!("/api2/json/nodes/{}/qemu/{}/status/shutdown", node, vmid);
            match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => match c.post(&path, &()).await {
                    Ok(response) => {
                        if response.status >= 200 && response.status < 300 {
                            info!("Successfully initiated shutdown for Proxmox VM {}", vmid);
                            Ok((
                                StatusCode::OK,
                                Json(json!({ "message": "VM shutdown initiated" })),
                            )
                                .into_response())
                        } else {
                            error!("Failed to shutdown VM {}: Status {}", vmid, response.status);
                            Err((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    error: "Failed to shutdown VM".to_string(),
                                    message: format!(
                                        "Proxmox returned status code {}",
                                        response.status
                                    ),
                                }),
                            )
                                .into_response())
                        }
                    }
                    Err(e) => {
                        error!("Failed to shutdown VM {}: {}", vmid, e);
                        Err(map_proxmox_error_to_response(
                            proxmox::ProxmoxHandlerError::ApiError(e),
                        ))
                    }
                },
                Err(e) => {
                    error!(
                        "Failed to connect to Proxmox for shutdown on {}: {}",
                        machine.id, e
                    );
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to connect to Proxmox: {}", e),
                            message: "Could not establish connection to Proxmox server."
                                .to_string(),
                        }),
                    )
                        .into_response())
                }
            }
        }
        _ => {
            warn!(
                "Unsupported action '{}' requested for Proxmox VM {}",
                action, machine.id
            );
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Unsupported action '{}' for Proxmox VM", action),
                    message: "This power action is not supported for Proxmox VMs".to_string(),
                }),
            )
                .into_response())
        }
    }
}

// Helper to map ProxmoxHandlerError to an Axum Response
fn map_proxmox_error_to_response(err: proxmox::ProxmoxHandlerError) -> Response {
    // Reuse the IntoResponse implementation from proxmox.rs
    err.into_response()
}

/// Execute a simple Proxmox POST action and return a standard response.
/// Used by both VM and LXC handlers to avoid repeating the connect → post → check pattern.
async fn proxmox_post_action(
    state: &AppState,
    path: &str,
    entity_type: &str,
    entity_id: u32,
    action_desc: &str,
) -> Result<Response, Response> {
    match proxmox::connect_to_proxmox(state, "power").await {
        Ok(c) => match c.post(path, &()).await {
            Ok(response) => {
                if response.status >= 200 && response.status < 300 {
                    info!("Successfully {} {} {}", action_desc, entity_type, entity_id);
                    Ok((
                        StatusCode::OK,
                        Json(json!({
                            "message": format!("{} {} {}", entity_type, entity_id, action_desc)
                        })),
                    )
                        .into_response())
                } else {
                    error!(
                        "Failed to {} {} {}: Status {}",
                        action_desc, entity_type, entity_id, response.status
                    );
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to {} {}", action_desc, entity_type),
                            message: format!("Proxmox returned status code {}", response.status),
                        }),
                    )
                        .into_response())
                }
            }
            Err(e) => {
                error!(
                    "Failed to {} {} {}: {}",
                    action_desc, entity_type, entity_id, e
                );
                Err(map_proxmox_error_to_response(
                    proxmox::ProxmoxHandlerError::ApiError(e),
                ))
            }
        },
        Err(e) => {
            error!("Failed to connect to Proxmox: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to connect to Proxmox: {}", e),
                    message: "Could not establish connection to Proxmox server.".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Handle power actions for Proxmox LXC containers.
/// LXC supports: start, stop, shutdown, reboot
/// LXC does NOT support: reboot-pxe (no PXE for containers)
async fn handle_proxmox_lxc_action(
    state: &AppState,
    node: &str,
    ctid: u32,
    action: &str,
) -> Result<Response, Response> {
    match action {
        "start" => {
            let path = format!("/api2/json/nodes/{}/lxc/{}/status/start", node, ctid);
            proxmox_post_action(state, &path, "LXC container", ctid, "started").await
        }
        "stop" => {
            let path = format!("/api2/json/nodes/{}/lxc/{}/status/stop", node, ctid);
            proxmox_post_action(state, &path, "LXC container", ctid, "stopped (hard)").await
        }
        "shutdown" => {
            let path = format!("/api2/json/nodes/{}/lxc/{}/status/shutdown", node, ctid);
            proxmox_post_action(state, &path, "LXC container", ctid, "shutdown initiated").await
        }
        "reboot" => {
            let path = format!("/api2/json/nodes/{}/lxc/{}/status/reboot", node, ctid);
            proxmox_post_action(state, &path, "LXC container", ctid, "reboot initiated").await
        }
        _ => {
            warn!(
                "Unsupported action '{}' for LXC container {} on node {}",
                action, ctid, node
            );
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Unsupported action '{}' for LXC container", action),
                    message: "LXC containers support: start, stop, shutdown, reboot".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Handle power actions for physical Proxmox nodes.
/// Nodes support: reboot, shutdown
/// Nodes do NOT support: start (can't remote-start a physical machine via API), stop (dangerous)
async fn handle_proxmox_node_action(
    state: &AppState,
    node: &str,
    action: &str,
) -> Result<Response, Response> {
    match action {
        "reboot" => {
            let path = format!("/api2/json/nodes/{}/status", node);
            match proxmox::connect_to_proxmox(state, "power").await {
                Ok(c) => {
                    let params = json!({"command": "reboot"});
                    match c.post(&path, &params).await {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully initiated reboot for Proxmox node {}", node);
                                Ok((
                                    StatusCode::OK,
                                    Json(json!({
                                        "message": format!("Node {} reboot initiated", node)
                                    })),
                                )
                                    .into_response())
                            } else {
                                error!(
                                    "Failed to reboot node {}: Status {}",
                                    node, response.status
                                );
                                Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: "Failed to reboot node".to_string(),
                                        message: format!(
                                            "Proxmox returned status code {}",
                                            response.status
                                        ),
                                    }),
                                )
                                    .into_response())
                            }
                        }
                        Err(e) => {
                            error!("Failed to reboot node {}: {}", node, e);
                            Err(map_proxmox_error_to_response(
                                proxmox::ProxmoxHandlerError::ApiError(e),
                            ))
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to connect to Proxmox: {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to connect to Proxmox: {}", e),
                            message: "Could not establish connection to Proxmox server."
                                .to_string(),
                        }),
                    )
                        .into_response())
                }
            }
        }
        "shutdown" => {
            let path = format!("/api2/json/nodes/{}/status", node);
            match proxmox::connect_to_proxmox(state, "power").await {
                Ok(c) => {
                    let params = json!({"command": "shutdown"});
                    match c.post(&path, &params).await {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully initiated shutdown for Proxmox node {}", node);
                                Ok((
                                    StatusCode::OK,
                                    Json(json!({
                                        "message": format!("Node {} shutdown initiated", node)
                                    })),
                                )
                                    .into_response())
                            } else {
                                error!(
                                    "Failed to shutdown node {}: Status {}",
                                    node, response.status
                                );
                                Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: "Failed to shutdown node".to_string(),
                                        message: format!(
                                            "Proxmox returned status code {}",
                                            response.status
                                        ),
                                    }),
                                )
                                    .into_response())
                            }
                        }
                        Err(e) => {
                            error!("Failed to shutdown node {}: {}", node, e);
                            Err(map_proxmox_error_to_response(
                                proxmox::ProxmoxHandlerError::ApiError(e),
                            ))
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to connect to Proxmox: {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("Failed to connect to Proxmox: {}", e),
                            message: "Could not establish connection to Proxmox server."
                                .to_string(),
                        }),
                    )
                        .into_response())
                }
            }
        }
        _ => {
            warn!("Unsupported action '{}' for physical node {}", action, node);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Unsupported action '{}' for physical node", action),
                    message:
                        "Physical nodes support: reboot, shutdown. Use IPMI/BMC for power on/off."
                            .to_string(),
                }),
            )
                .into_response())
        }
    }
}
