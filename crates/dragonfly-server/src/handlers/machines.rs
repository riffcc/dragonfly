use axum::{extract::{Path, State}, http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Deserialize;
use uuid::Uuid;
use tracing::{error, info, warn};
use proxmox_client::HttpApiClient;
use serde_json::json;

use crate::AppState;
use dragonfly_common::models::{ErrorResponse, Machine, MachineStatus};
use crate::tinkerbell;
use crate::handlers::proxmox; // Import proxmox functions

// Struct to receive the power action request
#[derive(Deserialize, Debug)]
pub struct BmcPowerActionRequest {
    pub action: String, // e.g., "reboot-pxe", "power-on", "power-off", "reboot"
}

// Handler for BMC power actions
#[axum::debug_handler]
pub async fn bmc_power_action_handler(
    State(state): State<AppState>, // Use state to get settings
    Path(machine_id): Path<Uuid>,
    Json(payload): Json<BmcPowerActionRequest>,
) -> Result<Response, Response> {
    info!("Received BMC power action '{}' for machine {}", payload.action, machine_id);
    info!("DEBUG: BMC power handler called with action '{}' for machine {}", payload.action, machine_id);

    // 1. Fetch machine details from the v1 Store
    let machine: Machine = match state.store_v1.get_machine(machine_id).await {
        Ok(Some(m)) => (&m).into(),
        Ok(None) => {
            error!("Machine {} not found for BMC action", machine_id);
            return Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
                error: "Machine not found".to_string(),
                message: format!("Machine with ID {} not found", machine_id)
            })).into_response());
        }
        Err(e) => {
            error!("Store error fetching machine {}: {}", machine_id, e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: "Store error".to_string(),
                message: e.to_string()
            })).into_response());
        }
    };

    // 2. Check machine type and execute action
    // Determine if this is a Proxmox VM by checking if the Proxmox-specific fields are populated
    if machine.proxmox_vmid.is_some() && machine.proxmox_node.is_some() {
        info!("DEBUG: Identified as Proxmox VM: vmid={:?}, node={:?}", machine.proxmox_vmid, machine.proxmox_node);
        handle_proxmox_vm_action(state, &machine, &payload.action).await
    } else {
        error!(
            "BMC actions not supported for this machine type (not a Proxmox VM) for machine {}",
            machine_id
        );
        Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "BMC actions not supported for this machine type".to_string(),
            message: "This machine does not support BMC power actions. Only Proxmox VMs are currently supported.".to_string()
        })).into_response())
    }
}

// Helper function to handle actions for Proxmox VMs
async fn handle_proxmox_vm_action(
    state: AppState,
    machine: &Machine,
    action: &str,
) -> Result<Response, Response> {
    info!("DEBUG: handle_proxmox_vm_action called with action '{}' for machine {}", action, machine.id);

    // Extract necessary Proxmox info from the machine object
    let node = match &machine.proxmox_node {
        Some(n) => n,
        None => {
            error!("Proxmox VM {} is missing node information", machine.id);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { 
                error: "Missing Proxmox node info".to_string(),
                message: "This VM is missing required Proxmox node information".to_string()
            })).into_response());
        }
    };
    let vmid = match machine.proxmox_vmid {
        Some(id) => id,
        None => {
            error!("Proxmox VM {} is missing VM ID information", machine.id);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { 
                error: "Missing Proxmox VM ID info".to_string(),
                message: "This VM is missing required Proxmox VM ID information".to_string()
            })).into_response());
        }
    };

    // Perform the requested action
    match action {
        "start" => {
            info!("DEBUG: Handling 'start' action for Proxmox VM {} (Node: {}, VMID: {})", machine.id, node, vmid);
            // Start the VM
            let path = format!("/api2/json/nodes/{}/qemu/{}/status/start", node, vmid);
            match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API");
                    match c.post(&path, &()).await {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully started Proxmox VM {}", vmid);
                                Ok((StatusCode::OK, Json(serde_json::json!({ 
                                    "message": "VM started successfully"
                                }))).into_response())
                            } else {
                                error!("Failed to start VM {}: Status {}", vmid, response.status);
                                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                                    error: format!("Failed to start VM"),
                                    message: format!("Proxmox returned status code {}", response.status)
                                })).into_response())
                            }
                        },
                        Err(e) => {
                            error!("Failed to start VM {}: {}", vmid, e);
                            Err(map_proxmox_error_to_response(proxmox::ProxmoxHandlerError::ApiError(e)))
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to connect to Proxmox for BMC action on {}: {}", machine.id, e);
                    error!("DEBUG: Proxmox connection error details: {:?}", e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox: {}", e),
                        message: "Could not establish connection to Proxmox server. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response())
                }
            }
        },
        "stop" => {
            info!("DEBUG: Handling 'stop' action for Proxmox VM {} (Node: {}, VMID: {})", machine.id, node, vmid);
            // Stop the VM
            let path = format!("/api2/json/nodes/{}/qemu/{}/status/stop", node, vmid);
            match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API");
                    match c.post(&path, &()).await {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully stopped Proxmox VM {}", vmid);
                                Ok((StatusCode::OK, Json(serde_json::json!({ 
                                    "message": "VM stopped successfully"
                                }))).into_response())
                            } else {
                                error!("Failed to stop VM {}: Status {}", vmid, response.status);
                                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                                    error: format!("Failed to stop VM"),
                                    message: format!("Proxmox returned status code {}", response.status)
                                })).into_response())
                            }
                        },
                        Err(e) => {
                            error!("Failed to stop VM {}: {}", vmid, e);
                            Err(map_proxmox_error_to_response(proxmox::ProxmoxHandlerError::ApiError(e)))
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to connect to Proxmox for BMC action on {}: {}", machine.id, e);
                    error!("DEBUG: Proxmox connection error details: {:?}", e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox: {}", e),
                        message: "Could not establish connection to Proxmox server. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response())
                }
            }
        },
        "reboot-pxe" => {
            info!("Attempting reboot-pxe for Proxmox VM {} (Node: {}, VMID: {})", machine.id, node, vmid);
            
            // 1. Connect with config token for setting boot order
            info!("Connecting to Proxmox for config operations (setting boot order) on VM {} (ID: {})", vmid, machine.id);
            let config_client = match proxmox::connect_to_proxmox(&state, "config").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API with config token");
                    c
                },
                Err(e) => {
                    error!("Failed to connect to Proxmox for boot configuration on {}: {}", machine.id, e);
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
            info!("Connecting to Proxmox for power operations (reboot) on VM {} (ID: {})", vmid, machine.id);
            let power_client = match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API with power token");
                    c
                },
                Err(e) => {
                    error!("Failed to connect to Proxmox for power operations on {}: {}", machine.id, e);
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

                    // 5. Update v1 Store status to Provisioning (InstallingOS)
                    info!("Updating machine {} status to InstallingOS", machine.id);
                    let updated_machine: Machine = match state.store_v1.get_machine(machine.id).await {
                        Ok(Some(mut v1_machine)) => {
                            v1_machine.status.state = crate::store::types::MachineState::Provisioning;
                            v1_machine.metadata.updated_at = chrono::Utc::now();
                            if let Err(e) = state.store_v1.put_machine(&v1_machine).await {
                                error!("Failed to update machine {} status after Proxmox reboot: {}", machine.id, e);
                            } else {
                                let _ = state.event_manager.send(format!("machine_updated:{}", machine.id));
                            }
                            (&v1_machine).into()
                        }
                        Ok(None) => {
                            error!("Machine {} disappeared during workflow creation", machine.id);
                            return Ok((StatusCode::OK, Json(serde_json::json!({
                                "message": "Proxmox reboot-pxe initiated successfully, but failed to create workflow (machine disappeared)"
                            }))).into_response());
                        }
                        Err(e) => {
                            error!("Failed to retrieve updated machine {} for workflow creation: {}", machine.id, e);
                            return Ok((StatusCode::OK, Json(serde_json::json!({
                                "message": "Proxmox reboot-pxe initiated successfully, but failed to create workflow (Store error)"
                            }))).into_response());
                        }
                    };

                    // 6. Create Tinkerbell workflow
                    info!("Creating Tinkerbell workflow for machine {}", machine.id);
                    
                    // Use the os_choice from the machine if available, or default to a sensible fallback
                    let os_choice = updated_machine.os_choice.as_deref().unwrap_or("ubuntu-2204");
                    match tinkerbell::create_workflow(&updated_machine, os_choice).await {
                        Ok(_) => {
                            info!("Successfully created Tinkerbell workflow for machine {}", machine.id);
                            // Check the response from set_next_boot and reboot operations in the logs
                            info!("VM {} successfully set for PXE boot and rebooted, workflow created", vmid);
                        },
                        Err(e) => {
                            // Log error but proceed, as Proxmox action succeeded
                            error!("Failed to create Tinkerbell workflow for machine {}: {}", machine.id, e);
                            // Return partial success
                            return Ok((StatusCode::OK, Json(serde_json::json!({ 
                                "message": "Proxmox reboot-pxe initiated successfully, but failed to create workflow",
                                "error": e.to_string()
                            }))).into_response());
                        }
                    }

                    Ok((StatusCode::OK, Json(serde_json::json!({ 
                        "message": "Proxmox reboot-pxe initiated and workflow created successfully",
                        "machine_id": machine.id.to_string(),
                        "vm_id": vmid,
                        "os_choice": os_choice
                    }))).into_response())
                },
                Err(e) => {
                    error!("Failed to reboot VM {}: {}", vmid, e);
                     // Map ProxmoxHandlerError to an Axum response
                     Err(map_proxmox_error_to_response(e))
                }
            }
        },
        "reboot" => {
            info!("DEBUG: Handling 'reboot' action for Proxmox VM {} (Node: {}, VMID: {})", machine.id, node, vmid);
            // Simple reboot without changing boot order
            match proxmox::connect_to_proxmox(&state, "power").await {
                Ok(c) => {
                    info!("DEBUG: Successfully connected to Proxmox API");
                    match c.post(&format!("/api2/json/nodes/{}/qemu/{}/status/reboot", node, vmid), &()).await {
                        Ok(response) => {
                            if response.status >= 200 && response.status < 300 {
                                info!("Successfully rebooted Proxmox VM {}", vmid);
                                Ok((StatusCode::OK, Json(serde_json::json!({ 
                                    "message": "VM reboot initiated successfully"
                                }))).into_response())
                            } else {
                                error!("Failed to reboot VM {}: Status {}", vmid, response.status);
                                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                                    error: format!("Failed to reboot VM"),
                                    message: format!("Proxmox returned status code {}", response.status)
                                })).into_response())
                            }
                        },
                        Err(e) => {
                            error!("Failed to reboot VM {}: {}", vmid, e);
                            Err(map_proxmox_error_to_response(proxmox::ProxmoxHandlerError::ApiError(e)))
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to connect to Proxmox for BMC action on {}: {}", machine.id, e);
                    error!("DEBUG: Proxmox connection error details: {:?}", e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: format!("Failed to connect to Proxmox: {}", e),
                        message: "Could not establish connection to Proxmox server. Make sure you have configured Proxmox correctly.".to_string()
                    })).into_response())
                }
            }
        },
        // TODO: Implement other actions like "power-on", "power-off"
        _ => {
            warn!("Unsupported action '{}' requested for Proxmox VM {}", action, machine.id);
            Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: format!("Unsupported action '{}' for Proxmox VM", action),
                message: "This power action is not supported for Proxmox VMs".to_string()
            })).into_response())
        }
    }
}

// Helper to map ProxmoxHandlerError to an Axum Response
fn map_proxmox_error_to_response(err: proxmox::ProxmoxHandlerError) -> Response {
     // Reuse the IntoResponse implementation from proxmox.rs
    err.into_response()
} 