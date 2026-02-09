use axum::http::StatusCode;
use proxmox_client::{Client as ProxmoxApiClient, Error as ProxmoxClientError, HttpApiClient};
use tracing::{error, info, warn};

use super::errors::{ProxmoxHandlerError, ProxmoxResult};

/// Sets the next boot device for a Proxmox VM.
pub async fn set_vm_next_boot(
    client: &ProxmoxApiClient,
    node: &str,
    vmid: u32,
    device: &str,
) -> ProxmoxResult<()> {
    info!(
        "Setting next boot device to '{}' for VM {} on node {}",
        device, vmid, node
    );

    let boot_param = if device == "network" {
        "order=net0;scsi0".to_string()
    } else if device == "disk" || device == "hd" {
        "order=scsi0;net0".to_string()
    } else if device.starts_with("order=") {
        device.to_string()
    } else {
        device.to_string()
    };

    info!("Using boot parameter: {}", boot_param);

    let path = format!("/api2/json/nodes/{}/qemu/{}/config", node, vmid);
    info!("Using API path: {}", path);

    let _params_map = vec![("boot", boot_param.as_str())];

    info!("Sending PUT request to set boot order");

    let params = serde_json::json!({ "boot": boot_param });

    match client.put(&path, &params).await {
        Ok(response) => {
            if response.status >= 200 && response.status < 300 {
                info!("Successfully set next boot device for VM {}", vmid);
                Ok(())
            } else {
                let error_msg = match serde_json::from_slice::<serde_json::Value>(&response.body) {
                    Ok(val) => {
                        warn!("Proxmox API error response for boot order change");
                        val.to_string()
                    }
                    Err(_) => format!("Received non-success status: {}", response.status),
                };
                error!(
                    "Failed to set next boot device for VM {}: Status={}, Body={}",
                    vmid, response.status, error_msg
                );

                let status_code = match StatusCode::from_u16(response.status) {
                    Ok(sc) => sc,
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };

                if response.status == 401 || response.status == 403 {
                    error!(
                        "Proxmox API Error: unauthorized - You need to create a VM configuration API token"
                    );

                    let token_error_msg = format!(
                        "Authorization failed for VM configuration change. Please go to Settings, reconnect to Proxmox to create proper API tokens. \
                         The 'config' token needs VM.Config.Options permission."
                    );

                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(
                        status_code,
                        token_error_msg,
                    )))
                } else {
                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(
                        status_code,
                        error_msg,
                    )))
                }
            }
        }
        Err(e) => {
            error!("Error setting next boot device for VM {}: {}", vmid, e);
            Err(ProxmoxHandlerError::ApiError(e))
        }
    }
}

/// Reboots a Proxmox VM.
pub async fn reboot_vm(client: &ProxmoxApiClient, node: &str, vmid: u32) -> ProxmoxResult<()> {
    info!("Attempting to reboot VM {} on node {}", vmid, node);
    let path = format!("/api2/json/nodes/{}/qemu/{}/status/reboot", node, vmid);

    match client.post(&path, &()).await {
        Ok(response) => {
            if response.status >= 200 && response.status < 300 {
                info!("Successfully initiated reboot for VM {}", vmid);
                Ok(())
            } else {
                let error_msg = match serde_json::from_slice::<serde_json::Value>(&response.body) {
                    Ok(val) => val.to_string(),
                    Err(_) => format!("Received non-success status: {}", response.status),
                };
                error!(
                    "Failed to reboot VM {}: Status={}, Body={}",
                    vmid, response.status, error_msg
                );

                let status_code = match StatusCode::from_u16(response.status) {
                    Ok(sc) => sc,
                    Err(_) => {
                        error!(
                            "Invalid status code received from Proxmox: {}",
                            response.status
                        );
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                };

                if response.status == 401 || response.status == 403 {
                    error!(
                        "Proxmox API Error: unauthorized - You need to create a VM power API token"
                    );

                    let token_error_msg = format!(
                        "Authorization failed for VM power operation. Please go to Settings, reconnect to Proxmox to create proper API tokens. \
                         The 'power' token needs VM.PowerMgmt permission."
                    );

                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(
                        status_code,
                        token_error_msg,
                    )))
                } else {
                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(
                        status_code,
                        error_msg,
                    )))
                }
            }
        }
        Err(e) => {
            error!("Error initiating reboot for VM {}: {}", vmid, e);
            if e.to_string().contains("VM is not running") {
                warn!("VM {} is not running, reboot command has no effect.", vmid);
                Ok(())
            } else {
                Err(ProxmoxHandlerError::ApiError(e))
            }
        }
    }
}
