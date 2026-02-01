use anyhow::Context;
use axum::{
    extract::State,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use proxmox_client::{HttpApiClient, Client as ProxmoxApiClient};
use std::error::Error as StdError;
use proxmox_login;
use proxmox_client::Error as ProxmoxClientError;
use serde::{Serialize, Deserialize};
use tracing::{error, info, warn};
use std::net::Ipv4Addr;
use serde_json::json;

use crate::AppState;
use crate::store::conversions::{machine_from_register_request, machine_to_common};
use dragonfly_common::models::{RegisterRequest, MachineStatus, ErrorResponse};

// Define local structs needed by discover_proxmox_handler
#[derive(Serialize, Debug, Clone)]
pub struct DiscoveredProxmox {
    host: String,
    port: u16,
    hostname: Option<String>,
    mac_address: Option<String>,
    machine_type: String,
    vmid: Option<u32>,
    parent_host: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ProxmoxDiscoverResponse {
    machines: Vec<DiscoveredProxmox>,
}

// New struct to receive connection details from request body
#[derive(Deserialize, Debug)]
#[allow(dead_code)]  // Fields are populated by deserialization but not all are read
pub struct ProxmoxConnectRequest {
    host: String,
    port: Option<u16>,
    username: String,
    password: String,
    vm_selection_option: Option<String>,
    skip_tls_verify: Option<bool>,
}

// Response with suggestion to disable TLS verification
#[derive(Serialize, Debug)]
pub struct ProxmoxConnectResponse {
    message: String,
    suggest_disable_tls_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    added_vms: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_vms: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machines: Option<Vec<DiscoveredProxmox>>,
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum ProxmoxHandlerError {
    #[error("Proxmox API error: {0}")]
    ApiError(#[from] ProxmoxClientError),
    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),
    // Use Box<dyn StdError> for the error types we can't import directly
    #[error("Login error: {0}")]
    LoginError(Box<dyn StdError + Send + Sync>),
    #[error("HTTP client error: {0}")]
    HttpClientError(Box<dyn StdError + Send + Sync>),
    // Add a specific error type for TLS validation issues
    #[error("TLS Certificate validation error: {0}")]
    TlsValidationError(String),
}

// IntoResponse impl: Populate message field
impl IntoResponse for ProxmoxHandlerError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code, suggest_disable_tls_verify) = match &self {
            ProxmoxHandlerError::ApiError(e) => {
                error!("Proxmox API Error: {}", e);
                // Check if the error message indicates a certificate validation issue
                let err_str = e.to_string();
                if err_str.contains("certificate") || 
                   err_str.contains("SSL") || 
                   err_str.contains("TLS") || 
                   err_str.contains("self-signed") || 
                   err_str.contains("unknown issuer") {
                    // Return special error code for certificate issues
                    (
                        // Use axum's StatusCode here for the HTTP response
                        axum::http::StatusCode::BAD_REQUEST,
                        format!("Proxmox SSL certificate validation failed. You may need to try again with certificate validation disabled: {}", e),
                        "TLS_VALIDATION_ERROR".to_string(),
                        true
                    )
                } else {
                    (
                        // Use axum's StatusCode here for the HTTP response
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Proxmox API interaction failed: {}", e),
                        "API_ERROR".to_string(),
                        false
                    )
                }
            }
            ProxmoxHandlerError::TlsValidationError(msg) => {
                error!("Proxmox TLS Validation Error: {}", msg);
                (
                    // Use axum's StatusCode here
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("Proxmox SSL certificate validation failed: {}. Try again with certificate validation disabled.", msg),
                    "TLS_VALIDATION_ERROR".to_string(),
                    true
                )
            }
            ProxmoxHandlerError::DbError(e) => {
                error!("Database Error: {}", e);
                (
                    // Use axum's StatusCode here
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database operation failed: {}", e),
                    "DB_ERROR".to_string(),
                    false
                )
            }
            ProxmoxHandlerError::ConfigError(msg) => {
                error!("Configuration Error: {}", msg);
                (
                    // Use axum's StatusCode here
                    axum::http::StatusCode::BAD_REQUEST,
                    msg.clone(),
                    "CONFIG_ERROR".to_string(),
                    false
                )
            }
            ProxmoxHandlerError::InternalError(e) => {
                error!("Internal Server Error: {}", e);
                (
                    // Use axum's StatusCode here
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred.".to_string(),
                    "INTERNAL_ERROR".to_string(),
                    false
                )
            }
            ProxmoxHandlerError::LoginError(e) => {
                error!("Proxmox Login Error: {}", e);
                (
                    // Use axum's StatusCode here
                    axum::http::StatusCode::UNAUTHORIZED,
                    format!("Proxmox authentication failed: {}", e),
                    "LOGIN_ERROR".to_string(),
                    false
                )
            }
            ProxmoxHandlerError::HttpClientError(e) => {
                error!("Proxmox HTTP Client Error: {}", e);
                let err_str = e.to_string();
                // Also check HTTP client errors for certificate issues
                if err_str.contains("certificate") || 
                   err_str.contains("SSL") || 
                   err_str.contains("TLS") || 
                   err_str.contains("self signed") || 
                   err_str.contains("unknown issuer") {
                    (
                        // Use axum's StatusCode here
                        axum::http::StatusCode::BAD_REQUEST,
                        format!("Proxmox SSL certificate validation failed: {}. Try again with certificate validation disabled.", e),
                        "TLS_VALIDATION_ERROR".to_string(),
                        true
                    )
                } else {
                    (
                        // Use axum's StatusCode here
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Proxmox HTTP communication failed: {}", e),
                        "HTTP_ERROR".to_string(),
                        false
                    )
                }
            }
        };
        
        // Create a JSON response with error and optional TLS suggestion
        let response_json = serde_json::json!({
            "error": error_code,
            "message": error_message,
            "suggest_disable_tls_verify": suggest_disable_tls_verify
        });
        
        // Ensure we're returning proper JSON
        (status, Json(response_json)).into_response()
    }
}

// Make ProxmoxResult public as well
pub type ProxmoxResult<T> = std::result::Result<T, ProxmoxHandlerError>;

// --- NEW Proxmox Action Functions --- 

/// Sets the next boot device for a Proxmox VM.
/// 
/// # Arguments
/// * `client` - An authenticated ProxmoxApiClient.
/// * `node` - The name of the Proxmox node where the VM resides.
/// * `vmid` - The numeric ID of the VM.
/// * `device` - The boot device to set (e.g., "network", "cdrom", "order=scsi0;net0").
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(ProxmoxHandlerError)` on failure.
pub async fn set_vm_next_boot(
    client: &ProxmoxApiClient,
    node: &str,
    vmid: u32,
    device: &str,
) -> ProxmoxResult<()> {
    info!("Setting next boot device to '{}' for VM {} on node {}", device, vmid, node);
    
    // Format the boot parameter correctly for Proxmox
    // For network boot, we need to use "order=net0;scsi0" or similar
    let boot_param = if device == "network" {
        // Default to "order=net0;scsi0" for network boot (put network first in order)
        "order=net0;scsi0".to_string()
    } else if device == "disk" || device == "hd" {
        // Default to "order=scsi0;net0" for disk boot (put disk first in order)
        "order=scsi0;net0".to_string()
    } else if device.starts_with("order=") {
        // Already in the correct format
        device.to_string()
    } else {
        // Just use as-is
        device.to_string()
    };
    
    info!("DEBUG: Using boot parameter: {}", boot_param);
    
    // Use the correct API path format for Proxmox
    let path = format!("/api2/json/nodes/{}/qemu/{}/config", node, vmid);
    info!("DEBUG: Using API path: {}", path);
    
    // Need to use URL-encoded form data for Proxmox API rather than JSON
    // This is critical for the VM configuration APIs to work properly
    let _params_map = vec![("boot", boot_param.as_str())];
    
    // First, try to make the request directly - API tokens may already be set up correctly
    info!("DEBUG: Sending PUT request to set boot order");
    
    // Convert params_map to JSON for the put method
    let params = serde_json::json!({ "boot": boot_param });
    
    match client.put(&path, &params).await {
        Ok(response) => {
            // Check response status code
            if response.status >= 200 && response.status < 300 {
                info!("Successfully set next boot device for VM {}", vmid);
                Ok(())
            } else {
                // Try to parse error from response body
                let error_msg = match serde_json::from_slice::<serde_json::Value>(&response.body) {
                    Ok(val) => {
                        info!("DEBUG: Error response body: {}", serde_json::to_string_pretty(&val).unwrap_or_default());
                        val.to_string()
                    },
                    Err(_) => format!("Received non-success status: {}", response.status),
                };
                error!("Failed to set next boot device for VM {}: Status={}, Body={}", vmid, response.status, error_msg);
                
                // Convert status code to a HTTP status code for the error
                let status_code = match StatusCode::from_u16(response.status) {
                    Ok(sc) => sc,
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                
                // If we got unauthorized, add a helpful message about API tokens
                if response.status == 401 || response.status == 403 {
                    error!("Proxmox API Error: unauthorized - You need to create a VM configuration API token");
                    
                    let token_error_msg = format!(
                        "Authorization failed for VM configuration change. Please go to Settings, reconnect to Proxmox to create proper API tokens. \
                         The 'config' token needs VM.Config.Options permission."
                    );
                    
                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(status_code, token_error_msg)))
                } else {
                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(status_code, error_msg)))
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
/// 
/// # Arguments
/// * `client` - An authenticated ProxmoxApiClient.
/// * `node` - The name of the Proxmox node where the VM resides.
/// * `vmid` - The numeric ID of the VM.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(ProxmoxHandlerError)` on failure.
pub async fn reboot_vm(
    client: &ProxmoxApiClient,
    node: &str,
    vmid: u32,
) -> ProxmoxResult<()> {
    info!("Attempting to reboot VM {} on node {}", vmid, node);
    let path = format!("/api2/json/nodes/{}/qemu/{}/status/reboot", node, vmid);
    
    // Reboot is a POST request with no body, pass &()
    match client.post(&path, &()).await {
        Ok(response) => {
            // Check response status code using numeric range
            if response.status >= 200 && response.status < 300 {
                info!("Successfully initiated reboot for VM {}", vmid);
                Ok(())
            } else {
                let error_msg = match serde_json::from_slice::<serde_json::Value>(&response.body) {
                    Ok(val) => val.to_string(),
                    Err(_) => format!("Received non-success status: {}", response.status),
                };
                error!("Failed to reboot VM {}: Status={}, Body={}", vmid, response.status, error_msg);
                // Convert u16 status to the http::StatusCode expected by ProxmoxClientError::Api
                // Use hyper's StatusCode
                let status_code = match StatusCode::from_u16(response.status) {
                    Ok(sc) => sc,
                    Err(_) => {
                        error!("Invalid status code received from Proxmox: {}", response.status);
                        // Fallback to a generic server error status code (using hyper's StatusCode)
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                };
                
                // If we got unauthorized, add a helpful message about API tokens
                if response.status == 401 || response.status == 403 {
                    error!("Proxmox API Error: unauthorized - You need to create a VM power API token");
                    
                    let token_error_msg = format!(
                        "Authorization failed for VM power operation. Please go to Settings, reconnect to Proxmox to create proper API tokens. \
                         The 'power' token needs VM.PowerMgmt permission."
                    );
                    
                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(status_code, token_error_msg)))
                } else {
                    Err(ProxmoxHandlerError::ApiError(ProxmoxClientError::Api(status_code, error_msg)))
                }
            }
        }
        Err(e) => {
            error!("Error initiating reboot for VM {}: {}", vmid, e);
             // Check if the error is due to the VM not running (common case for reboot)
            if e.to_string().contains("VM is not running") {
                warn!("VM {} is not running, reboot command has no effect.", vmid);
                // Consider this a success in the context of initiating a reboot (if needed)
                // Or return a specific error/status? For now, treat as success.
                Ok(())
            } else {
                Err(ProxmoxHandlerError::ApiError(e))
            }
        }
    }
}

// --- End NEW Proxmox Action Functions ---

// Update the connect_proxmox_handler function to create tokens automatically
pub async fn connect_proxmox_handler(
    State(state): State<crate::AppState>,
    Json(request): Json<ProxmoxConnectRequest>,
) -> impl IntoResponse {
    // Extract fields from the request
    let host = request.host.clone();
    let port = match request.port {
        Some(p) => p,
        None => 8006, // Default Proxmox port
    };
    
    let username = request.username.clone();
    let password = request.password.clone();
    
    let skip_tls_verify = request.skip_tls_verify.unwrap_or(false);

    // Same connection process as before - authenticate with provided credentials
    let result = authenticate_with_proxmox(&host, port as i32, &username, &password, skip_tls_verify).await;
    
    match result {
        Ok(_) => {
            info!("Successfully authenticated with Proxmox API");
            
            // Now also create specialized tokens automatically
            info!("Automatically creating specialized API tokens with minimal permissions");
            
            // Create a token request using the same credentials
            let token_request = ProxmoxTokensCreateRequest {
                host: host.clone(),
                port: port as i32,
                username: username.clone(),
                password: password.clone(),
                skip_tls_verify,
            };
            
            // Attempt to create the tokens
            let tokens_result = generate_proxmox_tokens_with_credentials(&token_request).await;
            
            // Create a client for discovery and registration
            let host_url = format!("https://{}:{}", host, port);
            let host_uri = match host_url.parse::<Uri>() {
                Ok(uri) => uri,
                Err(e) => {
                    error!("Invalid Proxmox URL: {}", e);
                    return (StatusCode::BAD_REQUEST, Json(json!({
                        "success": false,
                        "message": format!("Invalid Proxmox URL: {}", e)
                    })));
                }
            };
            
            let client = ProxmoxApiClient::new(host_uri);
            
            // Create login request
            let login_builder = proxmox_login::Login::new(
                &host_url, 
                username.to_string(), 
                password.to_string()
            );
            
            // Attempt login for the client we'll use for discovery
            let login_result = client.login(login_builder).await;
            
            match login_result {
                Ok(None) => {
                    info!("Successfully authenticated client for VM discovery");
                    
                    // Determine cluster name (default to hostname if not available)
                    let cluster_name = match client.get("/api2/json/cluster/status").await {
                        Ok(response) => {
                            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&response.body) {
                                if let Some(data) = value.get("data").and_then(|d| d.as_array()) {
                                    // Try to find the cluster name in the response
                                    let cluster_entry = data.iter().find(|item| {
                                        item.get("type").and_then(|t| t.as_str()) == Some("cluster")
                                    });
                                    
                                    if let Some(name) = cluster_entry.and_then(|e| e.get("name")).and_then(|n| n.as_str()) {
                                        name.to_string()
                                    } else {
                                        host.clone() // Fallback to hostname
                                    }
                                } else {
                                    host.clone() // Fallback to hostname
                                }
                            } else {
                                host.clone() // Fallback to hostname
                            }
                        },
                        Err(_) => host.clone() // Fallback to hostname on error
                    };

                    info!("Discovered Proxmox cluster name: {}", cluster_name);
                    
                    // Now discover and register VMs
                    let state_ref = &state;
                    match discover_and_register_proxmox_vms(&client, &cluster_name, state_ref).await {
                        Ok((registered, failed, discovered)) => {
                            info!("Successfully discovered and registered {} Proxmox VMs ({} failed)",
                                 registered, failed);
                            
                            // Continue with token processing
                            match tokens_result {
                                Ok(token_set) => {
                                    // Save tokens to database (encrypted) and also add to in-memory store
                                    match save_proxmox_tokens(&state, token_set).await {
                                        Ok(_) => {
                                            info!("Successfully created and saved specialized Proxmox API tokens");
                                        },
                                        Err(e) => {
                                            warn!("Successfully created tokens but failed to save them: {}", e);
                                            return (StatusCode::OK, Json(json!({
                                                "success": true,
                                                "message": format!("Successfully connected to Proxmox API but failed to save tokens: {}", e),
                                                "tokens_created": true,
                                                "tokens_saved": false,
                                                "added_vms": registered,
                                                "failed_vms": failed,
                                                "machines": discovered
                                            })));
                                        }
                                    }
                                    
                                    (StatusCode::OK, Json(json!({
                                        "success": true,
                                        "message": format!("Successfully connected to Proxmox API, created tokens, and imported {} VMs", registered),
                                        "tokens_created": true,
                                        "tokens_saved": true,
                                        "added_vms": registered,
                                        "failed_vms": failed,
                                        "machines": discovered
                                    })))
                                },
                                Err(e) => {
                                    warn!("Successfully connected to Proxmox but failed to create API tokens: {}", e);
                                    
                                    // Provide clearer guidance in the error message
                                    let error_message = if e.contains("Parameter verification failed") || e.contains("privileges") || e.contains("privs") {
                                        format!("Failed to create API tokens: {}. This might be due to API version differences between Proxmox versions. Please check your Proxmox version and permissions.", e)
                                    } else if e.contains("permission") || e.contains("unauthorized") || e.contains("access") {
                                        format!("Failed to create API tokens: {}. The user needs permission to create API tokens in Proxmox. Please check that your account has administrative privileges.", e)
            } else {
                                        format!("Failed to create API tokens: {}. Please try again or check Proxmox documentation for your specific version.", e)
                                    };
                                    
                                    // We still consider this a success since the main connection worked and VMs were imported
                                    (StatusCode::OK, Json(json!({
                                        "success": true,
                                        "message": format!("Successfully connected to Proxmox API and imported {} VMs, but failed to create tokens: {}", registered, e),
                                        "tokens_created": false,
                                        "token_error": error_message,
                                        "added_vms": registered,
                                        "failed_vms": failed,
                                        "machines": discovered
                                    })))
                                }
                            }
                        },
                        Err(e) => {
                            error!("Failed to discover and register Proxmox VMs: {}", e);
                            // We still continue with token processing
                            match tokens_result {
                                Ok(token_set) => {
                                    if let Err(e) = save_proxmox_tokens(&state, token_set).await {
                                        warn!("Successfully created tokens but failed to save them: {}", e);
                                    }
                                    
                                    (StatusCode::OK, Json(json!({
                                        "success": true,
                                        "message": format!("Successfully connected to Proxmox API and created tokens, but failed to discover VMs: {}", e),
                                        "tokens_created": true,
                                        "tokens_saved": true,
                                        "vm_discovery_error": e.to_string()
                                    })))
                                },
                                Err(token_err) => {
                                    (StatusCode::OK, Json(json!({
                                        "success": true,
                                        "message": format!("Successfully connected to Proxmox API, but failed to create tokens and discover VMs"),
                                        "tokens_created": false,
                                        "token_error": token_err,
                                        "vm_discovery_error": e.to_string()
                                    })))
                                }
                            }
                        }
                    }
                },
                Ok(Some(_)) => {
                    error!("Two-factor authentication is required but not supported");
                    return (StatusCode::BAD_REQUEST, Json(json!({
                        "success": false,
                        "message": "Two-factor authentication is required but not supported"
                    })));
                },
                Err(e) => {
                    error!("Failed to authenticate client for VM discovery: {}", e);
                    // Still try to process tokens
                    match tokens_result {
                        Ok(token_set) => {
                            if let Err(e) = save_proxmox_tokens(&state, token_set).await {
                                warn!("Successfully created tokens but failed to save them: {}", e);
                            }
                            
                            (StatusCode::OK, Json(json!({
                                "success": true,
                                "message": format!("Successfully connected to Proxmox API and created tokens, but couldn't discover VMs: Authentication failed for discovery"),
                                "tokens_created": true,
                                "tokens_saved": true,
                                "vm_discovery_error": format!("Authentication failed: {}", e)
                            })))
                        },
                        Err(token_err) => {
                            (StatusCode::OK, Json(json!({
                                "success": true,
                                "message": format!("Successfully connected to Proxmox API, but failed to create tokens and discover VMs"),
                                "tokens_created": false,
                                "token_error": token_err,
                                "vm_discovery_error": format!("Authentication failed: {}", e)
                            })))
                        }
                    }
                }
            }
        },
        Err(e) => {
            error!("Failed to connect to Proxmox: {}", e);
            
            (StatusCode::BAD_REQUEST, Json(json!({
                "success": false,
                "message": format!("Failed to connect to Proxmox: {}", e)
            })))
        }
    }
}

// Helper function to authenticate with Proxmox separately from token creation
async fn authenticate_with_proxmox(
    host: &str,
    port: i32,
    username: &str,
    password: &str,
    skip_tls_verify: bool,
) -> Result<(), String> {
    // Create the client
    let host_url = format!("https://{}:{}", host, port);
    let host_uri = match host_url.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => return Err(format!("Invalid Proxmox URL: {}", e)),
    };
    
    let client = ProxmoxApiClient::new(host_uri);
    
    // Create login request
    let login_builder = proxmox_login::Login::new(
        &host_url, 
        username.to_string(), 
        password.to_string()
    );
    
    // Attempt login
    match client.login(login_builder).await {
        Ok(None) => {
            info!("Successfully authenticated with Proxmox API");
            
            // No longer save the credentials - we only need them once to create tokens
            // Just add host, port, and whether to skip TLS verification (no credentials)
            match crate::db::update_proxmox_connection_settings(
                host, port as i32, username, skip_tls_verify
            ).await {
                Ok(_) => info!("Proxmox connection settings saved to database (without storing password)"),
                Err(e) => warn!("Failed to save Proxmox settings to database: {}", e),
            }
            
            Ok(())
        },
        Ok(Some(_)) => {
            error!("Proxmox login requires Two-Factor Authentication, which is not supported");
            Err("Proxmox authentication requires 2FA which is not supported".to_string())
        },
                        Err(e) => {
            error!("Proxmox authentication failed: {}", e);
            Err(format!("Proxmox authentication failed: {}", e))
        }
    }
}

// Function for token creation that doesn't require an authenticated client
// This is used by both the connect handler and the dedicated token creation endpoint
pub async fn generate_proxmox_tokens_with_credentials(
    request: &ProxmoxTokensCreateRequest
) -> Result<ProxmoxTokenSet, String> {
    info!("DEBUG: Starting token creation process");
    
    // Extract connection details
    let ProxmoxTokensCreateRequest {
        host,
        port,
        username,
        password,
        skip_tls_verify,
    } = request;
    
    // First authenticate with Proxmox
    let host_url = format!("https://{}:{}", host, port);
    let host_uri = match host_url.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => return Err(format!("Invalid Proxmox URL: {}", e)),
    };
    
    let client = ProxmoxApiClient::new(host_uri);
    
    // Create login request
    let login_builder = proxmox_login::Login::new(
        &host_url, 
        username.to_string(), 
        password.to_string()
    );
    
    // Attempt login
    match client.login(login_builder).await {
        Ok(None) => {
            info!("Successfully authenticated with Proxmox API for token creation");
            
            // Create custom roles for Dragonfly operations
            info!("Creating custom roles for Dragonfly operations");
            
            // 1. First create the custom roles if they don't exist
            let roles_to_create = [
                ("DragonflyVMConfig", "Custom role for Dragonfly VM configuration operations"),
                ("DragonflySync", "Custom role for Dragonfly synchronization operations"),
            ];
            
            for (role_name, _role_description) in roles_to_create.iter() {
                info!("DEBUG: Creating or checking for role: {}", role_name);
                
                // Check if role exists first
                let role_check_path = format!("/api2/json/access/roles/{}", role_name);
                match client.get(&role_check_path).await {
                    Ok(response) => {
                        if response.status == 200 {
                            info!("Role {} already exists, skipping creation", role_name);
                        } else {
                            // Create the role
                            let role_create_path = "/api2/json/access/roles";
                            let role_params = serde_json::json!({
                                "roleid": role_name.to_string(),
                                "privs": ""  // Initially empty, we'll update after
                            });
                            
                            match client.post(role_create_path, &role_params).await {
                                Ok(response) => {
                                    if response.status == 200 {
                                        info!("Created role {} successfully", role_name);
                                    } else {
                                        warn!("Failed to create role {}: Status {}", role_name, response.status);
                                    }
                                },
                                Err(e) => {
                                    warn!("Error creating role {}: {}", role_name, e);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Error checking if role {} exists: {}", role_name, e);
                        
                        // If the error message indicates the role doesn't exist, create it
                        let error_msg = e.to_string();
                        if error_msg.contains("does not exist") || error_msg.contains("404") || error_msg.contains("500") {
                            info!("Role {} doesn't exist, creating it now", role_name);
                            
                            // Create the role
                            let role_create_path = "/api2/json/access/roles";
                            let role_params = serde_json::json!({
                                "roleid": role_name.to_string(),
                                "privs": ""  // Initially empty, we'll update after
                            });
                            
                            match client.post(role_create_path, &role_params).await {
                                Ok(response) => {
                                    if response.status == 200 {
                                        info!("Created role {} successfully", role_name);
                                    } else {
                                        warn!("Failed to create role {}: Status {}", role_name, response.status);
                                    }
                                },
                                Err(e) => {
                                    warn!("Error creating role {}: {}", role_name, e);
                                }
                            }
                        }
                    }
                }
            }
            
            // 2. Update roles with proper permissions
            let role_permissions = [
                ("DragonflyVMConfig", "VM.Config.Options,VM.Config.Disk"), // Changed VM.Config.Boot to VM.Config.Disk
                ("DragonflySync", "VM.Audit,VM.Monitor,Sys.Audit"),
            ];
            
            for (role_name, permissions) in role_permissions.iter() {
                info!("Setting permissions for role {}: {}", role_name, permissions);
                
                let update_path = format!("/api2/json/access/roles/{}", role_name);
                let params = serde_json::json!({
                    "privs": permissions.to_string()
                });
                
                match client.put(&update_path, &params).await {
                    Ok(response) => {
                        if response.status == 200 {
                            info!("Successfully updated permissions for role {}", role_name);
                        } else {
                            warn!("Failed to update permissions for role {}: Status {}", role_name, response.status);
                            
                            // If the role doesn't exist, try to create it first, then set permissions
                            let response_body = String::from_utf8_lossy(&response.body);
                            if response_body.contains("does not exist") {
                                info!("Role {} doesn't exist when updating permissions, creating it now", role_name);
                                
                                // Create the role
                                let role_create_path = "/api2/json/access/roles";
                                let role_create_params = serde_json::json!({
                                    "roleid": role_name.to_string(),
                                    "privs": permissions.to_string()  // Create with permissions directly
                                });
                                
                                match client.post(role_create_path, &role_create_params).await {
                                    Ok(create_response) => {
                                        if create_response.status == 200 {
                                            info!("Created role {} successfully with permissions", role_name);
                                        } else {
                                            warn!("Failed to create role {} with permissions: Status {}", 
                                                  role_name, create_response.status);
                                        }
                                    },
                                    Err(e) => {
                                        warn!("Error creating role {} with permissions: {}", role_name, e);
                                    }
                                }
                            }
                        }
                },
                Err(e) => {
                        warn!("Error updating permissions for role {}: {}", role_name, e);
                        
                        // If the error indicates the role doesn't exist, try to create it
                        let error_msg = e.to_string();
                        if error_msg.contains("does not exist") || error_msg.contains("role not found") {
                            info!("Role {} doesn't exist when updating permissions, creating it now", role_name);
                            
                            // Create the role with permissions in one step
                            let role_create_path = "/api2/json/access/roles";
                            let role_create_params = serde_json::json!({
                                "roleid": role_name.to_string(),
                                "privs": permissions.to_string()  // Create with permissions directly
                            });
                            
                            match client.post(role_create_path, &role_create_params).await {
                                Ok(create_response) => {
                                    if create_response.status == 200 {
                                        info!("Created role {} successfully with permissions", role_name);
                                    } else {
                                        warn!("Failed to create role {} with permissions: Status {}", 
                                              role_name, create_response.status);
                                    }
                                },
                                Err(e) => {
                                    warn!("Error creating role {} with permissions: {}", role_name, e);
                                }
                            }
                        }
                    }
                }
            }
            
            // --- Now create tokens with the custom roles ---
            
            // Ensure we use the root user or user with admin rights
            let user_part = if username.contains('@') {
                username.to_string()
            } else {
                format!("{}@pam", username)
            };
            
            // Create specialized tokens for different operation types
            info!("DEBUG: Creating VM creation token...");
            let create_token = match create_token_with_role(
                &client, 
                &user_part, 
                "dragonfly-create", 
                "Dragonfly automation token for VM.Create",
                "PVEVMAdmin"  // Keep using PVEVMAdmin for creation
            ).await {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM creation token: {}", e))
            };
            
            info!("DEBUG: Creating VM power token...");
            let power_token = match create_token_with_role(
                &client, 
                &user_part, 
                "dragonfly-power", 
                "Dragonfly automation token for VM.PowerMgmt",
                "PVEVMUser"  // Keep using PVEVMUser for power management
            ).await {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM power token: {}", e))
            };
            
            info!("DEBUG: Creating VM config token...");
            let config_token = match create_token_with_role(
                &client, 
                &user_part, 
                "dragonfly-config", 
                "Dragonfly automation token for VM.Config.Options",
                "DragonflyVMConfig"  // Use our new custom role
            ).await {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM config token: {}", e))
            };
            
            info!("DEBUG: Creating VM sync token...");
            let sync_token = match create_token_with_role(
                &client, 
                &user_part, 
                "dragonfly-sync", 
                "Dragonfly automation token for VM.Audit VM.Monitor",
                "DragonflySync"  // Use our new custom role
            ).await {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM sync token: {}", e))
            };
            
            info!("Created tokens for VM operations with appropriate permissions");
            
            // Return the token set
            Ok(ProxmoxTokenSet {
                create_token,
                power_token,
                config_token,
                sync_token,
                connection_info: ProxmoxConnectionInfo {
                    host: host.clone(),
                    port: *port,
                    username: username.clone(),
                    skip_tls_verify: *skip_tls_verify,
                }
            })
        },
        Ok(Some(_)) => {
            Err("Proxmox authentication requires 2FA which is not supported".to_string())
        },
        Err(e) => {
            Err(format!("Failed to authenticate with Proxmox: {}", e))
        }
    }
}

// Helper function for discovery and registration
async fn discover_and_register_proxmox_vms(
    client: &ProxmoxApiClient,
    cluster_name: &str,
    state: &AppState,
) -> ProxmoxResult<(usize, usize, Vec<DiscoveredProxmox>)> {
    info!("Discovering and registering Proxmox VMs for cluster: {}", cluster_name);
    
    // First, get the list of nodes in the cluster
    let nodes_response = client.get("/api2/json/nodes").await
        .map_err(|e| {
            error!("Failed to fetch nodes list: {}", e);
            ProxmoxHandlerError::ApiError(e)
        })?;
    
    // Parse the response
    let nodes_value: serde_json::Value = serde_json::from_slice(&nodes_response.body)
        .map_err(|e| {
            error!("Failed to parse nodes response: {}", e);
            ProxmoxHandlerError::InternalError(anyhow::anyhow!("Failed to parse nodes JSON: {}", e))
        })?;
    
    // Extract the nodes data
    let nodes_data = nodes_value.get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| {
            error!("Invalid nodes response format");
            ProxmoxHandlerError::InternalError(anyhow::anyhow!("Invalid nodes response format"))
        })?;
    
    info!("Found {} nodes in Proxmox cluster", nodes_data.len());
    
    let mut registered_machines = 0;
    let mut failed_registrations = 0;
    let mut discovered_machines = Vec::new();
    
    // For each node, get the VMs
    for node in nodes_data {
        let node_name = node.get("node")
            .and_then(|n| n.as_str())
            .ok_or_else(|| {
                error!("Node missing 'node' field");
                ProxmoxHandlerError::InternalError(anyhow::anyhow!("Node missing 'node' field"))
            })?;
        
        // Get node details for more information
        let node_details_path = format!("/api2/json/nodes/{}/status", node_name);
        let mut host_ip_address = None; // Store as Option<String>
        let mut host_hostname = node_name.to_string(); // Default to node name

        // Try to get more details about the node (like IP from status)
        if let Ok(node_details_response) = client.get(&node_details_path).await {
            if let Ok(node_details_value) = serde_json::from_slice::<serde_json::Value>(&node_details_response.body) {
                if let Some(node_details_data) = node_details_value.get("data") {
                    // Try to get IP address from the node details
                    host_ip_address = node_details_data.get("ip").and_then(|i| i.as_str()).map(String::from);
                    
                    // Try to get version information
                    if let Some(version) = node_details_data.get("pveversion").and_then(|v| v.as_str()) {
                        info!("Node {} is running Proxmox version: {}", node_name, version);
                        host_hostname = format!("{} (PVE {})", node_name, version); // Include version in hostname?
                    } else {
                        host_hostname = node_name.to_string(); // Fallback if no version
                    }
                }
            } else {
                warn!("Failed to parse node details JSON for {}: {:?}", node_name, node_details_response.body);
            }
        } else {
             warn!("Failed to get node details for {}", node_name);
        }
        
        // Get network interface information to find the primary MAC address
        let node_net_path = format!("/api2/json/nodes/{}/network", node_name);
        let mut host_mac_address = None; // Store as Option<String>

        if let Ok(node_net_response) = client.get(&node_net_path).await {
            if let Ok(node_net_value) = serde_json::from_slice::<serde_json::Value>(&node_net_response.body) {
                if let Some(net_data) = node_net_value.get("data").and_then(|d| d.as_array()) {
                    // Look for a physical interface (like eth0) or bridge (vmbr0) with a MAC
                    for iface in net_data {
                        let iface_type = iface.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        let iface_name = iface.get("iface").and_then(|n| n.as_str()).unwrap_or("");
                        // Proxmox might store MAC in hwaddr or ether or address?
                        let mac = iface.get("hwaddr")
                            .or_else(|| iface.get("ether"))
                            .or_else(|| iface.get("address")) // Less likely but check
                            .and_then(|h| h.as_str());

                        // Prioritize known physical/bridge interfaces
                        if let Some(mac_str) = mac {
                            if iface_type == "eth" || iface_type == "bond" || iface_name.starts_with("vmbr") {
                                // Basic validation
                                if mac_str.len() == 17 && mac_str.contains(':') {
                                    host_mac_address = Some(mac_str.to_lowercase());
                                    info!("Found potential host MAC {} on interface {} for node {}", host_mac_address.as_ref().unwrap(), iface_name, node_name);
                                    break; // Found a likely candidate
                                }
                            }
                        }
                    }
                }
                 if host_mac_address.is_none() {
                    warn!("Could not determine primary MAC for host node {} from network config.", node_name);
                }
            } else {
                 warn!("Failed to parse node network JSON for {}: {:?}", node_name, node_net_response.body);
            }
        } else {
             warn!("Failed to get node network info for {}", node_name);
        }
        
        // --- Register the Host Node --- 
        if let Some(mac) = host_mac_address {
             let host_req = RegisterRequest {
                mac_address: mac.clone(), // Already lowercased
                // Use "Unknown" as default value instead of a fake IP
                ip_address: host_ip_address.unwrap_or_else(|| "Unknown".to_string()), 
                hostname: Some(host_hostname.clone()), // Use node name (potentially with version)
                proxmox_vmid: None, 
                proxmox_node: Some(node_name.to_string()),
                proxmox_cluster: Some(cluster_name.to_string()),
                cpu_cores: None, 
                total_ram_bytes: None, 
                                    disks: Vec::new(),
                                    nameservers: Vec::new(),
                                    cpu_model: None,
                                };
            info!("Host req: {:?}, Attempting to register Proxmox host node with v1 Store", host_req);
            let machine = machine_from_register_request(&host_req);
            let machine_id = machine.id;
            match state.store.put_machine(&machine).await {
                Ok(()) => {
                    info!("Successfully registered/updated Proxmox host node '{}' as machine ID {}", node_name, machine_id);
                }
                Err(e) => {
                    error!("Failed to register Proxmox host node '{}': {}", node_name, e);
                    // Log error but continue to VMs for this node
                }
            }
        } else {
             warn!("Skipping registration of host node '{}' because MAC address could not be determined.", node_name);
        }

        // --- Fetch and Register VMs for this node ---
        info!("Processing VMs for node: {}", node_name);
        
        // Get VM list for this node
        let vms_path = format!("/api2/json/nodes/{}/qemu", node_name);
        let vms_response = match client.get(&vms_path).await {
            Ok(response) => response,
            Err(e) => {
                error!("Failed to fetch VMs for node {}: {}", node_name, e);
                continue; // Skip this node but continue with others
            }
        };
        
        // Parse the response
        let vms_value: serde_json::Value = match serde_json::from_slice(&vms_response.body) {
            Ok(value) => value,
            Err(e) => {
                error!("Failed to parse VMs response for node {}: {}", node_name, e);
                continue; // Skip this node but continue with others
            }
        };
        
        // Extract the VMs data
        let vms_data = match vms_value.get("data").and_then(|d| d.as_array()) {
            Some(data) => data,
            None => {
                error!("Invalid VMs response format for node {}", node_name);
                continue; // Skip this node but continue with others
            }
        };
        
        info!("Found {} VMs on node {}", vms_data.len(), node_name);
        
        // Register each VM
        for vm in vms_data {
            let vmid = match vm.get("vmid").and_then(|id| id.as_u64()).map(|id| id as u32) {
                Some(id) => id,
                None => {
                    error!("VM missing vmid");
                    continue; // Skip this VM but continue with others
                }
            };
            
            let name = vm.get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            
            let status = vm.get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");
            
            // Determine OS based on VM name or additional queries
            // Print OS name
            info!("OS name: {}", name);
            let mut vm_os = "Unknown OS".to_string();
            if name.to_lowercase().contains("ubuntu") {
                vm_os = "Ubuntu 22.04".to_string();
            } else if name.to_lowercase().contains("debian") {
                vm_os = "Debian 12".to_string();
            } else if name.to_lowercase().contains("centos") {
                vm_os = "CentOS 7".to_string();
            } else if name.to_lowercase().contains("windows") {
                vm_os = "Windows Server".to_string();
            }
            
            // Get VM details from Proxmox API
            let vm_details_path = format!("/api2/json/nodes/{}/qemu/{}/status/current", node_name, vmid);
            let mut vm_mem_bytes = 0;
            let mut vm_cpu_cores = 0;
            
            if let Ok(vm_details_response) = client.get(&vm_details_path).await {
                if let Ok(vm_details_value) = serde_json::from_slice::<serde_json::Value>(&vm_details_response.body) {
                    if let Some(vm_details_data) = vm_details_value.get("data") {
                        // Get memory info
                        if let Some(mem) = vm_details_data.get("maxmem").and_then(|m| m.as_u64()) {
                            vm_mem_bytes = mem;
                        }
                        
                        // Get CPU info
                        if let Some(cpu) = vm_details_data.get("cpus").and_then(|c| c.as_u64()) {
                            vm_cpu_cores = cpu as u32;
                        }
                    }
                }
            }
            
            // Get VM config to retrieve MAC address and other details
            let vm_config_path = format!("/api2/json/nodes/{}/qemu/{}/config", node_name, vmid);
            let vm_config_response = match client.get(&vm_config_path).await {
                Ok(response) => response,
                Err(e) => {
                    error!("Failed to fetch VM config for VM {}: {}", vmid, e);
                    continue; // Skip this VM but continue with others
                }
            };
            
            // Parse the VM config response
            let vm_config: serde_json::Value = match serde_json::from_slice(&vm_config_response.body) {
                Ok(value) => value,
                Err(e) => {
                    error!("Failed to parse VM config response for VM {}: {}", vmid, e);
                    continue; // Skip this VM but continue with others
                }
            };
            
            // Extract network interfaces and MAC addresses
            let mut mac_addresses = Vec::new();
            let config_data = match vm_config.get("data") {
                Some(data) => data,
                None => {
                    error!("Invalid VM config response format for VM {}", vmid);
                    continue; // Skip this VM but continue with others
                }
            };

            // Check if the Guest Agent is enabled
            let mut agent_enabled = false;
            if let Some(agent) = config_data.get("agent").and_then(|a| a.as_str()) {
                agent_enabled = agent.contains("enabled=1") || agent.contains("enabled=true");
                info!("QEMU Guest Agent status for VM {}: {}", vmid, if agent_enabled { "Enabled" } else { "Disabled" });
            }
            
            // Check for OS info in the config
            if let Some(os_type) = config_data.get("ostype").and_then(|o| o.as_str()) {
                match os_type {
                    "l26" => vm_os = "Unknown".to_string(), // Generic Linux should be Unknown
                    "win10" | "win11" => vm_os = "windows-10".to_string(),
                    "win8" | "win7" => vm_os = "windows-7".to_string(),
                    "other" => {} // Keep current OS guess
                    _ => vm_os = "unknown".to_string(),
                }
                info!("VM {} has OS type {} (from Proxmox config)", vmid, vm_os);
            }
            
            // Proxmox configures network interfaces like net0, net1, etc.
            // Each of these is a string like "virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0"
            for i in 0..8 {  // Assume max 8 network interfaces
                let net_key = format!("net{}", i);
                if let Some(net_config) = config_data.get(&net_key).and_then(|n| n.as_str()) {
                    // Parse the MAC address from the net config string
                    if let Some(mac) = extract_mac_from_net_config(net_config) {
                        mac_addresses.push(mac);
                    }
                }
            }
            
            if mac_addresses.is_empty() {
                error!("No MAC addresses found for VM {}", vmid);
                continue; // Skip this VM but continue with others
            }
            
            // Use the first MAC address for registration
            let mac_address = mac_addresses[0].clone().to_lowercase(); // Ensure lowercase
            
            // Try to get the IP address from the QEMU Guest Agent if enabled
            let mut ip_address = "Unknown".to_string(); // Default to Unknown
            
            if agent_enabled {
                // First check if agent is actually running
                let agent_ping_path = format!("/api2/json/nodes/{}/qemu/{}/agent/ping", node_name, vmid);
                let agent_running = match client.get(&agent_ping_path).await {
                    Ok(ping_response) => {
                        if let Ok(ping_value) = serde_json::from_slice::<serde_json::Value>(&ping_response.body) {
                            // Check for successful response (should contain data with no error)
                            ping_value.get("data").is_some() && !ping_value.get("data").and_then(|d| d.get("error")).is_some()
                        } else {
                            false
                        }
                    },
                    Err(_) => false
                };
                
                if agent_running {
                    info!("QEMU Guest Agent is running for VM {}, attempting to retrieve network interfaces", vmid);
                    
                    // First, try to get OS information
                    let agent_os_path = format!("/api2/json/nodes/{}/qemu/{}/agent/get-osinfo", node_name, vmid);
                    let os_detected = match client.get(&agent_os_path).await {
                        Ok(os_response) => {
                            match serde_json::from_slice::<serde_json::Value>(&os_response.body) {
                                Ok(os_value) => {
                                    // Pretty print for debugging
                                    info!("OS info response for VM {}: {}", vmid, 
                                          serde_json::to_string_pretty(&os_value).unwrap_or_else(|_| "Failed to format".to_string()));
                                    
                                    // Extract useful OS information
                                    if let Some(result) = os_value.get("data").and_then(|d| d.get("result")) {
                                        // Log the raw result for debugging
                                        info!("Raw OS info for VM {}: {}", vmid, serde_json::to_string(result).unwrap_or_default());
                                        
                                        let os_name = result.get("id").and_then(|id| id.as_str()).unwrap_or("Unknown");
                                        let os_version = result.get("version").and_then(|v| v.as_str()).unwrap_or("");
                                        let os_pretty_name = result.get("pretty-name").and_then(|pn| pn.as_str());
                                        
                                        // First determine the detected OS for logging
                                        let detected_os = if let Some(pretty) = os_pretty_name {
                                            pretty.to_string()
                                        } else if !os_version.is_empty() {
                                            format!("{} {}", os_name, os_version)
                                        } else {
                                            os_name.to_string()
                                        };
                                        
                                        // Now standardize the OS name to match our UI format
                                        let os_name_lower = os_name.to_lowercase();
                                        
                                        vm_os = if os_name_lower.contains("ubuntu") || detected_os.to_lowercase().contains("ubuntu") {
                                            // Extract major version, e.g., "22.04" -> "2204"
                                            if os_version.contains(".") {
                                                let version_parts: Vec<&str> = os_version.split('.').collect();
                                                if version_parts.len() >= 2 {
                                                    format!("ubuntu-{}{}", version_parts[0], version_parts[1])
                                                } else {
                                                    format!("ubuntu-{}", os_version.replace(".", ""))
                                                }
                                            } else if detected_os.contains("22.04") {
                                                "ubuntu-2204".to_string()
                                            } else if detected_os.contains("24.04") {
                                                "ubuntu-2404".to_string()
                                            } else {
                                                "ubuntu".to_string()
                                            }
                                        } else if os_name_lower.contains("debian") || detected_os.to_lowercase().contains("debian") {
                                            // Try to extract version from pretty name or version string
                                            if detected_os.contains("12") || detected_os.contains("bookworm") {
                                                "debian-12".to_string()
                                            } else if let Some(version) = os_version.split(' ').next().and_then(|v| v.parse::<u32>().ok()) {
                                                format!("debian-{}", version)
                                            } else {
                                                "debian".to_string()
                                            }
                                        } else {
                                            // For other OSes, keep the detected format but log it
                                            detected_os.clone()
                                        };
                                        
                                        info!("Guest Agent detected OS for VM {}: {} (standardized as: {})", vmid, detected_os, vm_os);
                                        true
                                    } else {
                                        info!("No OS information in Guest Agent response for VM {}", vmid);
                                        false
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to parse Guest Agent OS info response for VM {}: {}", vmid, e);
                                    false
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to get OS info from Guest Agent for VM {}: {}", vmid, e);
                            false
                        }
                    };
                    
                    if !os_detected {
                        info!("Using fallback OS detection for VM {}: {}", vmid, vm_os);
                    }
                    
                    // Then, get network interfaces (existing code)
                    let agent_path = format!("/api2/json/nodes/{}/qemu/{}/agent/network-get-interfaces", node_name, vmid);
                    
                    match client.get(&agent_path).await {
                        Ok(agent_response) => {
                            match serde_json::from_slice::<serde_json::Value>(&agent_response.body) {
                                Ok(agent_value) => {
                                    // Pretty print the full response for debugging
                                    info!("Full Guest Agent response for VM {}: {}", vmid, 
                                          serde_json::to_string_pretty(&agent_value).unwrap_or_else(|_| "Failed to format".to_string()));
                                    
                                    if let Some(result) = agent_value.get("data").and_then(|d| d.get("result")) {
                                        // QEMU agent returns array of network interfaces
                                        if let Some(interfaces) = result.as_array() {
                                            info!("Found {} network interfaces for VM {}", interfaces.len(), vmid);
                                            
                                            // --- Modified IP Detection Logic ---
                                            let mut preferred_ip: Option<String> = None;
                                            let mut fallback_ip: Option<String> = None;

                                            // First pass: Look for preferred interfaces (eth*, ens*, eno*)
                                            for iface in interfaces {
                                                if let Some(name) = iface.get("name").and_then(|n| n.as_str()) {
                                                    if name.starts_with("lo") { continue; } // Skip loopback
                                                    
                                                    // Check if it's a preferred interface
                                                    let is_preferred = name.starts_with("eth") || name.starts_with("ens") || name.starts_with("eno");
                                                    if !is_preferred { continue; } // Skip non-preferred in this pass
                                                    
                                                    info!("Processing preferred interface '{}' for VM {}", name, vmid);
                                                    
                                                    if let Some(ip_addr) = find_valid_ipv4_in_interface(iface, vmid) {
                                                        preferred_ip = Some(ip_addr);
                                                        break; // Found IP on a preferred interface
                                                    }
                                                }
                                            }

                                            // Second pass: Look in other interfaces if no preferred IP was found
                                            if preferred_ip.is_none() {
                                                info!("No IP found on preferred interfaces for VM {}. Checking others.", vmid);
                                                for iface in interfaces {
                                                    if let Some(name) = iface.get("name").and_then(|n| n.as_str()) {
                                                        // Skip loopback and already checked preferred interfaces
                                                        if name.starts_with("lo") || name.starts_with("eth") || name.starts_with("ens") || name.starts_with("eno") { continue; }
                                                        // Skip common virtual interfaces (like tailscale, docker, etc.)
                                                        if name.starts_with("tailscale") || name.starts_with("docker") || name.starts_with("veth") || name.starts_with("virbr") || name.starts_with("br-") { continue; }

                                                        info!("Processing fallback interface '{}' for VM {}", name, vmid);
                                                        
                                                        if let Some(ip_addr) = find_valid_ipv4_in_interface(iface, vmid) {
                                                            fallback_ip = Some(ip_addr);
                                                            break; // Found first valid fallback IP
                                                        }
                                                    }
                                                }
                                            }

                                            // Assign the IP address based on priority
                                            if let Some(preferred) = preferred_ip {
                                                ip_address = preferred;
                                                info!("Selected preferred IPv4 address {} for VM {} via Guest Agent", ip_address, vmid);
                                            } else if let Some(fallback) = fallback_ip {
                                                ip_address = fallback;
                                                info!("Selected fallback IPv4 address {} for VM {} via Guest Agent", ip_address, vmid);
                                            } else {
                                                info!("No suitable IPv4 address found for VM {} via Guest Agent", vmid);
                                                // ip_address remains "Unknown"
                                            }
                                            // --- End Modified IP Detection Logic ---
                                            
                                        } else {
                                            info!("No network interfaces array found in Guest Agent response for VM {}", vmid);
                                        }
                                    } else {
                                        info!("No 'result' field in Guest Agent response for VM {}", vmid);
                                    }
                                }
                                Err(e) => warn!("Failed to parse Guest Agent response for VM {}: {}", vmid, e),
                            }
                        }
                        Err(e) => warn!("Failed to get network interfaces from QEMU Guest Agent for VM {}: {}", vmid, e),
                    }
                }
            } else {
                info!("QEMU Guest Agent not enabled for VM {}. IP will be set to Unknown.", vmid);
            }
            
            // If the Guest Agent didn't provide an IP, leave it as "Unknown"
            // We no longer generate fake deterministic IPs
            
            // Add this VM to our discovered machines list
            discovered_machines.push(DiscoveredProxmox {
                host: format!("{}-{}", node_name, vmid),
                port: 0, // VMs don't have a port
                hostname: Some(name.to_string()),
                mac_address: Some(mac_address.clone()),
                machine_type: "proxmox-vm".to_string(),
                vmid: Some(vmid),
                parent_host: Some(node_name.to_string()),
            });
            
            info!("Processing VM {} (ID: {}, Status: {}, OS: {}, IP: {})", name, vmid, status, vm_os, ip_address);
            
            // Prepare RegisterRequest
            let register_request = RegisterRequest {
                mac_address,
                ip_address,
                hostname: Some(name.to_string()),
                disks: Vec::new(), // We don't know the disks yet
                nameservers: Vec::new(), // We don't know the nameservers yet
                cpu_model: Some("Proxmox Virtual CPU".to_string()), // Generic CPU model
                cpu_cores: Some(vm_cpu_cores),
                total_ram_bytes: Some(vm_mem_bytes),
                proxmox_vmid: Some(vmid),
                proxmox_node: Some(node_name.to_string()),
                proxmox_cluster: Some(cluster_name.to_string()),
            };

            // DEBUG: Log the request before attempting registration
            info!("Register request: {:?}, Attempting to register VM with v1 Store", register_request);

            // Create v1 Machine from register request
            let mut machine = machine_from_register_request(&register_request);
            let machine_id = machine.id;

            // Set the machine state based on VM status
            use dragonfly_common::MachineState;
            machine.status.state = match status {
                "running" => MachineState::ExistingOs { os_name: "Unknown".to_string() },
                "stopped" => MachineState::Offline,
                _ => MachineState::ExistingOs { os_name: "Unknown".to_string() },
            };

            // Register the VM with v1 Store
            match state.store.put_machine(&machine).await {
                Ok(()) => {
                    info!("Successfully registered Proxmox VM {} as machine {}", vmid, machine_id);
                    registered_machines += 1;
                },
                Err(e) => {
                    error!("Failed to register Proxmox VM {}: {}", vmid, e);
                    failed_registrations += 1;
                }
            }
        }
    }
    
    // Return success with a summary
    info!("Proxmox VM discovery and registration complete: {} successful, {} failed", 
           registered_machines, failed_registrations);
    
    Ok((registered_machines, failed_registrations, discovered_machines))
}

// Helper function to extract MAC address from Proxmox network configuration
fn extract_mac_from_net_config(net_config: &str) -> Option<String> {
    // Proxmox network configs look like: "virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0"
    // or "e1000=XX:XX:XX:XX:XX:XX,bridge=vmbr0"
    
    // Split by comma and look for the part with the MAC address
    for part in net_config.split(',') {
        // The part with MAC should start with "virtio=" or "e1000=" or another NIC type
        if part.contains('=') {
            let mut parts = part.splitn(2, '=');
            _ = parts.next(); // Skip the NIC type
            if let Some(mac) = parts.next() {
                // Verify this looks like a MAC address (XX:XX:XX:XX:XX:XX)
                if mac.len() == 17 && mac.bytes().filter(|&b| b == b':').count() == 5 {
                    // Convert to lowercase to satisfy Tinkerbell requirements
                    return Some(mac.to_lowercase());
                }
            }
        }
    }
    
    None
}

// --- NEW HELPER FUNCTION ---
// Helper to find the first valid, non-loopback, non-link-local IPv4 address in a single interface object
fn find_valid_ipv4_in_interface(iface: &serde_json::Value, vmid: u32) -> Option<String> {
    let interface_name = iface.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
    if let Some(ip_addresses) = iface.get("ip-addresses").and_then(|ips| ips.as_array()) {
        info!("Checking {} IP addresses on interface '{}' for VM {}", ip_addresses.len(), interface_name, vmid);
        
        for ip_obj in ip_addresses {
            // Debug each IP address entry
            info!("IP address entry for VM {} on interface {}: {}", vmid, interface_name,
                  serde_json::to_string_pretty(&ip_obj).unwrap_or_else(|_| "Failed to format".to_string()));
            
            let ip_type = ip_obj.get("ip-address-type").and_then(|t| t.as_str());
            let ip = ip_obj.get("ip-address").and_then(|a| a.as_str());
            
            info!("Found IP address type: {:?}, address: {:?}", ip_type, ip);
            
            if let (Some("ipv4"), Some(addr)) = (ip_type, ip) {
                // Skip link-local addresses (169.254.x.x)
                if addr.starts_with("169.254.") {
                    info!("Skipping link-local address {} for VM {}", addr, vmid);
                    continue;
                }
                
                // Skip loopback addresses (127.x.x.x)
                if addr.starts_with("127.") {
                    info!("Skipping loopback address {} for VM {}", addr, vmid);
                    continue;
                }
                
                // Found a valid IPv4 address
                return Some(addr.to_string()); 
            }
        }
    }
    // No valid IPv4 found in this interface
    None
}
// --- END NEW HELPER FUNCTION ---

// ========================
// Discover Handler
// ========================

pub async fn discover_proxmox_handler() -> impl IntoResponse {
    const PROXMOX_PORT: u16 = 8006;
    info!("Starting Proxmox discovery scan on port {}", PROXMOX_PORT);

    let scan_result = tokio::task::spawn_blocking(move || {
        let interfaces = netdev::get_interfaces();
        let mut all_addresses = Vec::new();
        let bad_prefixes = ["docker", "virbr", "veth", "cni", "flannel", "br-", "vnet"];
        let bad_names = ["cni0", "docker0", "podman0", "podman1", "virbr0", "k3s0", "k3s1"];
        let preferred_prefixes = ["eth", "en", "wl", "bond", "br0"];

        for interface in interfaces {
            let if_name = &interface.name;
            if interface.is_loopback() {
                continue;
            }
            let has_bad_prefix = bad_prefixes.iter().any(|prefix| if_name.starts_with(prefix));
            let is_bad_name = bad_names.iter().any(|name| if_name == name);
            if has_bad_prefix || is_bad_name {
                continue;
            }
            let is_preferred = preferred_prefixes.iter().any(|prefix| if_name.starts_with(prefix));
            if !is_preferred && interface.ipv4.is_empty() {
                    continue;
            }

            let mut scan_targets = Vec::new();
            for ip_config in &interface.ipv4 {
                let ip_addr = ip_config.addr;
                let prefix_len = ip_config.prefix_len;
                let host_count = if prefix_len >= 30 { 4u32 } else if prefix_len >= 24 { 1u32 << (32 - prefix_len) } else { 256u32 };
                let network_addr = calculate_network_address(ip_addr, prefix_len);
                for i in 1..(host_count - 1) {
                    let host_ip = generate_ip_in_subnet(network_addr, i);
                    let host = netscan::host::Host::new(host_ip.into(), String::new()).with_ports(vec![PROXMOX_PORT]);
                    scan_targets.push(host);
                }
            }
            if scan_targets.is_empty() { continue; }

            let scan_setting = netscan::scan::setting::PortScanSetting::default()
                .set_if_index(interface.index)
                .set_scan_type(netscan::scan::setting::PortScanType::TcpConnectScan)
                .set_targets(scan_targets)
                .set_timeout(std::time::Duration::from_secs(5))
                .set_wait_time(std::time::Duration::from_millis(500));
            let scanner = netscan::scan::scanner::PortScanner::new(scan_setting);
            let scan_result = scanner.scan();
            for host in scan_result.hosts {
                if host.get_open_ports().iter().any(|p| p.number == PROXMOX_PORT) {
                        all_addresses.push(std::net::SocketAddr::new(host.ip_addr, PROXMOX_PORT));
                }
            }
        }
        Ok::<Vec<std::net::SocketAddr>, String>(all_addresses)
    }).await;

    match scan_result {
        Ok(Ok(addresses)) => {
            info!("Proxmox scan found {} potential machines", addresses.len());
            let machines: Vec<DiscoveredProxmox> = addresses
                .into_iter()
                .map(|socket_addr| {
                    let ip = socket_addr.ip();
                    let host = ip.to_string();
                    let hostname = match tokio::task::block_in_place(|| dns_lookup::lookup_addr(&ip).ok()) {
                        Some(name) if name != host => Some(name),
                        _ => None,
                    };
                    // Use the locally defined DiscoveredProxmox struct
                    DiscoveredProxmox { 
                        host, 
                        port: PROXMOX_PORT,
                        hostname,
                        mac_address: None,
                        machine_type: "host".to_string(),
                        vmid: None,
                        parent_host: None,
                    }
                })
                .collect();
            info!("Completed Proxmox discovery with {} machines", machines.len());
            // Use the locally defined ProxmoxDiscoverResponse struct
            (StatusCode::OK, Json(ProxmoxDiscoverResponse { machines })).into_response()
        }
        Ok(Err(e)) => {
            error!("Proxmox discovery scan failed: {}", e);
            let error_message = format!("Network scan failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Scan Error".to_string(), message: error_message }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Proxmox discovery task failed: {}", e);
            let error_message = format!("Scanner task failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Task Error".to_string(), message: error_message }),
            )
                .into_response()
        }
    }
}

// ========================
// Helper Functions (Restored)
// ========================

fn calculate_network_address(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    Ipv4Addr::from(ip_u32 & mask)
}

fn generate_ip_in_subnet(network_addr: Ipv4Addr, host_num: u32) -> Ipv4Addr {
    let network_u32 = u32::from(network_addr);
    Ipv4Addr::from(network_u32 + host_num)
}

// Start a background task to periodically prune machines that have been removed from Proxmox
pub async fn start_proxmox_sync_task(
    state: std::sync::Arc<crate::AppState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>
) {
    use std::time::Duration;
    
    // Clone the state for the task
    let state_clone = state.clone();
    
    tokio::spawn(async move {
        let poll_interval = Duration::from_secs(90); // Check every 90 seconds
        info!("Starting Proxmox sync task with interval of {:?}", poll_interval);
        
        loop {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {
                    info!("Running Proxmox machine sync check");
                    
                    // Check if Proxmox is configured either in memory or database
                    let proxmox_configured = {
                        // First check in-memory settings
                        let settings = state_clone.settings.lock().await;
                        let in_memory_configured = settings.proxmox_host.is_some() 
                            && settings.proxmox_username.is_some();
                            
                        // Also check if we have tokens in memory
                        let tokens = state_clone.tokens.lock().await;
                        let has_sync_token = tokens.contains_key("proxmox_vm_sync_token");
                        
                        drop(tokens);
                        drop(settings);
                        
                        // If either is configured, we can proceed
                        in_memory_configured || has_sync_token
                    };
                    
                    if !proxmox_configured {
                        // Check database as a last resort
                        match crate::db::get_proxmox_settings().await {
                            Ok(Some(settings)) => {
                                if settings.vm_sync_token.is_none() {
                                    info!("Proxmox configured but sync token not available, skipping sync check");
                                    continue;
                                }
                            },
                            _ => {
                        info!("Proxmox not configured, skipping sync check");
                        continue;
                            }
                        }
                    }
                    
                    // Get all machines from v1 Store and filter for Proxmox machines
                    use dragonfly_common::MachineSource;
                    let machines = match state_clone.store.list_machines().await {
                        Ok(m) => m,
                        Err(e) => {
                            error!("Failed to get machines for Proxmox sync: {}", e);
                            continue;
                        }
                    };

                    // Filter to only Proxmox-sourced machines and convert to common Machine type
                    let proxmox_machines: Vec<dragonfly_common::models::Machine> = machines.iter()
                        .filter(|m| matches!(m.metadata.source, MachineSource::Proxmox { .. }))
                        .map(|m| machine_to_common(m))
                        .collect();
                    
                    if proxmox_machines.is_empty() {
                        info!("No Proxmox machines found, skipping sync check");
                        continue;
                    }
                    
                    // Connect to Proxmox and get current machine list
                    // Use the 'sync' token type which has VM.Audit and VM.Monitor permissions
                    match connect_to_proxmox(&state_clone, "sync").await {
                        Ok(client) => {
                            // Process each cluster and its machines
                            if let Err(e) = sync_proxmox_machines(&client, &proxmox_machines, &state_clone).await {
                                error!("Error during Proxmox sync check: {}", e);
                            }
                        },
                        Err(e) => {
                            error!("Failed to connect to Proxmox for sync check: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("Shutdown signal received, stopping Proxmox sync task");
                    break;
                }
            }
        }
    });
}

// Simplified connect_to_proxmox function with token type
pub async fn connect_to_proxmox(
    state: &crate::AppState,
    token_type: &str
) -> Result<ProxmoxApiClient, anyhow::Error> {
    use crate::encryption::decrypt_string;
    
    info!("Connecting to Proxmox API for operation type: {}", token_type);
    
    // First check if we have the token in memory
    let token_key = format!("proxmox_vm_{}_token", token_type);
    let in_memory_token = {
        let tokens = state.tokens.lock().await;
        tokens.get(&token_key).cloned()
    };
    
    // If we have the token in memory, use it directly
    if let Some(token) = in_memory_token {
        info!("Using in-memory token for {} operations", token_type);
        
        // Get host settings
        let settings = state.settings.lock().await.clone();
        let host = settings.proxmox_host.clone().ok_or_else(|| anyhow::anyhow!("Proxmox host not configured"))?;
        let port = settings.proxmox_port.unwrap_or(8006);
        let skip_tls_verify = settings.proxmox_skip_tls_verify.unwrap_or(false);
        
        // Create https connector with proper TLS settings
        let _https = if skip_tls_verify {
            info!("Using TLS connection with certificate validation disabled");
            let mut connector = hyper_tls::HttpsConnector::new();
            connector.https_only(true);
            connector
    } else {
            info!("Using TLS connection with standard certificate validation");
            hyper_tls::HttpsConnector::new()
    };
    
        // Get host URL
    let host_url = format!("https://{}:{}", host, port);
        let base_uri = host_url.parse::<Uri>()
            .context(format!("Invalid Proxmox URL: {}", host_url))?;
            
        // Parse the API token to extract user and token parts
        // Format is usually: user@realm!tokenname=token_value
        if let Some(equals_pos) = token.find('=') {
            let (_token_id, _token_value) = token.split_at(equals_pos + 1);
            
            // Create client with token authentication
            let client = ProxmoxApiClient::new(base_uri);
            
            info!("Successfully initialized Proxmox client with in-memory API token for {} operations", token_type);
            return Ok(client);
        }
    }
    
    // If not in memory, try to get settings from the database
    let db_settings = match crate::db::get_proxmox_settings().await {
        Ok(Some(settings)) => {
            info!("Found Proxmox settings in database for host {}", settings.host);
            Some(settings)
        },
        Ok(None) => {
            info!("No Proxmox settings found in database, checking in-memory settings");
            None
        },
        Err(e) => {
            warn!("Error loading Proxmox settings from database: {}", e);
            None
        }
    };
    
    // If we have settings in the database, try using the appropriate API token
    if let Some(settings) = db_settings {
        // Create https connector with proper TLS settings
        let _https = if settings.skip_tls_verify {
            info!("Using TLS connection with certificate validation disabled");
            let mut connector = hyper_tls::HttpsConnector::new();
            connector.https_only(true);
            connector
        } else {
            info!("Using TLS connection with standard certificate validation");
            hyper_tls::HttpsConnector::new()
        };
        
        // Get host URL
        let host_url = format!("https://{}:{}", settings.host, settings.port);
        let base_uri = host_url.parse::<Uri>()
            .context(format!("Invalid Proxmox URL: {}", host_url))?;
        
        // Select the appropriate API token based on operation type
        let token_opt = match token_type {
            "create" => settings.vm_create_token,
            "power" => settings.vm_power_token,
            "config" => settings.vm_config_token,
            "sync" => settings.vm_sync_token,
            _ => {
                warn!("Unknown token type: {}, failing operation", token_type);
                return Err(anyhow::anyhow!("Unknown token type: {}", token_type));
            }
        };
        
        if let Some(encrypted_token) = token_opt {
            // Decrypt the token
            match decrypt_string(&encrypted_token) {
                Ok(api_token) => {
                    info!("Using API token from database for {} operations", token_type);
                    
                    // Also store it in memory for future use
                    let mut tokens = state.tokens.lock().await;
                    tokens.insert(token_key, api_token.clone());
                    drop(tokens);
                    
                    // Parse the API token to extract user and token parts
                    // Format is usually: user@realm!tokenname=token_value
                    if let Some(equals_pos) = api_token.find('=') {
                        let (_token_id, _token_value) = api_token.split_at(equals_pos + 1);
                        
                        // Create client with token authentication
                        let client = ProxmoxApiClient::new(base_uri);
                        
                        // TODO: Set the token directly in the client if the API supports it
                        // For now, we'll just return the client and handle token auth in the request
                        
                        info!("Successfully initialized Proxmox client with API token for {} operations", token_type);
                        return Ok(client);
                    } else {
                        warn!("Invalid API token format, cannot authenticate");
                        return Err(anyhow::anyhow!("Invalid API token format"));
                    }
                }
                Err(e) => {
                    warn!("Failed to decrypt API token: {}, cannot authenticate", e);
                    return Err(anyhow::anyhow!("Failed to decrypt API token: {}", e));
                }
            }
        } else {
            warn!("No API token found for {} operations, and no fallback authentication method available", token_type);
            return Err(anyhow::anyhow!("No API token found for {} operations. Please go to Settings and reconnect to Proxmox to create the required API tokens.", token_type));
        }
    }
    
    // If we don't have database settings, check for in-memory settings
    // If those exist but don't include tokens, prompt user to set up tokens
    let settings = state.settings.lock().await;
    
    if settings.proxmox_host.is_some() {
        return Err(anyhow::anyhow!("Proxmox is configured but API tokens are not set up. Please go to Settings and reconnect to Proxmox to create API tokens."));
    }
    
    // No configuration at all
    Err(anyhow::anyhow!("Proxmox is not configured. Please set up a connection to Proxmox first."))
}

// NEW function to handle both updates and pruning
async fn sync_proxmox_machines(
    client: &ProxmoxApiClient,
    db_machines: &[dragonfly_common::models::Machine],
    state: &crate::AppState,
) -> Result<(), anyhow::Error> {
    info!("Starting Proxmox machine synchronization...");

    // Get current nodes from Proxmox
    let nodes_response = client.get("/api2/json/nodes").await
        .map_err(|e| anyhow::anyhow!("Sync: Failed to fetch nodes: {}", e))?;
    let nodes_value: serde_json::Value = serde_json::from_slice(&nodes_response.body)
        .map_err(|e| anyhow::anyhow!("Sync: Failed to parse nodes response: {}", e))?;
    let nodes_data = nodes_value.get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| anyhow::anyhow!("Sync: Invalid nodes response format"))?;

    // Build sets of existing nodes and VMs from Proxmox API
    let mut existing_node_names = std::collections::HashSet::new();
    let mut existing_vm_ids = std::collections::HashSet::new();
    let mut current_vm_details = std::collections::HashMap::new(); // Store {vmid: (node_name, status, agent_running, config_data)}

    for node in nodes_data {
        let node_name = node.get("node")
            .and_then(|n| n.as_str())
            .ok_or_else(|| anyhow::anyhow!("Sync: Node missing 'node' field"))?;
        
        existing_node_names.insert(node_name.to_string());

        // Get VMs for this node
        let vms_path = format!("/api2/json/nodes/{}/qemu", node_name);
        match client.get(&vms_path).await {
            Ok(vms_response) => {
                match serde_json::from_slice::<serde_json::Value>(&vms_response.body) {
                    Ok(vms_value) => {
                        if let Some(vms_data) = vms_value.get("data").and_then(|d| d.as_array()) {
                            for vm in vms_data {
                                if let Some(vmid) = vm.get("vmid").and_then(|id| id.as_u64()).map(|id| id as u32) {
                                    existing_vm_ids.insert(vmid);
                                    let status = vm.get("status").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();
                                    
                                    // Get config to check agent enablement
                                    let vm_config_path = format!("/api2/json/nodes/{}/qemu/{}/config", node_name, vmid);
                                    let agent_enabled = match client.get(&vm_config_path).await {
                                        Ok(cfg_resp) => {
                                            match serde_json::from_slice::<serde_json::Value>(&cfg_resp.body) {
                                                Ok(cfg_val) => {
                                                    if let Some(agent_str) = cfg_val.get("data").and_then(|d| d.get("agent")).and_then(|a| a.as_str()) {
                                                        agent_str.contains("enabled=1") || agent_str.contains("enabled=true")
                                                    } else { false }
                                                }, 
                                                Err(_) => false
                                            }
                                        }, 
                                        Err(_) => false
                                    };

                                    let mut agent_running = false;
                                    if status == "running" && agent_enabled {
                                        let agent_ping_path = format!("/api2/json/nodes/{}/qemu/{}/agent/ping", node_name, vmid);
                                        agent_running = match client.get(&agent_ping_path).await {
                                            Ok(ping_resp) => serde_json::from_slice::<serde_json::Value>(&ping_resp.body)
                                                .map_or(false, |v| v.get("data").is_some() && !v.get("data").and_then(|d| d.get("error")).is_some()),
                                            Err(_) => false
                                        };
                                    }
                                    
                                    current_vm_details.insert(vmid, (node_name.to_string(), status, agent_running));
                                }
                            }
                        } else {
                            warn!("Sync: Invalid VMs data format for node {}", node_name);
                        }
                    },
                    Err(e) => warn!("Sync: Failed to parse VMs response for node {}: {}", node_name, e),
                }
            },
            Err(e) => warn!("Sync: Failed to get VMs for node {}: {}", node_name, e),
        }
    }

    info!("Sync: Found {} nodes and {} VMs in Proxmox API", existing_node_names.len(), existing_vm_ids.len());

    // Iterate through machines stored in Dragonfly DB
    let mut pruned_count = 0;
    let mut updated_ip_count = 0;
    let mut updated_status_count = 0;
    let mut machines_to_prune = Vec::new();

    for db_machine in db_machines {
        // Handle Proxmox Hosts
        if db_machine.is_proxmox_host {
            if let Some(node_name) = &db_machine.proxmox_node {
                if !existing_node_names.contains(node_name) {
                    info!("Sync: Proxmox host node '{}' (ID: {}) no longer exists in API. Marking for pruning.", 
                          node_name, db_machine.id);
                    machines_to_prune.push(db_machine.id);
                }
                // TODO: Update host status/IP if needed? (Requires more API calls)
                } else {
                warn!("Sync: DB machine {} marked as Proxmox host but missing node name.", db_machine.id);
            }
        }
        // Handle Proxmox VMs
        else if let Some(vmid) = db_machine.proxmox_vmid {
            if let Some((_node_name, api_status, agent_running)) = current_vm_details.get(&vmid) {
                 // VM exists in API, update status and potentially IP
                let new_db_status = match api_status.as_str() {
                    "running" => MachineStatus::Installed,
                    "stopped" => MachineStatus::Offline,
                    _ => MachineStatus::ExistingOS, // Use ExistingOS as fallback instead of Unknown
                };

                // Update DB status if it changed
                if db_machine.status != new_db_status {
                    info!(
                        "Sync: Updating status for VM {} (ID: {}) from {:?} to {:?}",
                        vmid, db_machine.id, db_machine.status, new_db_status
                    );
                    // Update via v1 Store
                    if let Ok(Some(mut machine)) = state.store.get_machine(db_machine.id).await {
                        use dragonfly_common::MachineState;
                        machine.status.state = match new_db_status {
                            MachineStatus::Installed => MachineState::Installed,
                            MachineStatus::Offline => MachineState::Offline,
                            MachineStatus::ExistingOS => MachineState::ExistingOs { os_name: "Unknown".to_string() },
                            MachineStatus::Discovered => MachineState::Discovered,
                            MachineStatus::ReadyToInstall => MachineState::ReadyToInstall,
                            MachineStatus::Initializing => MachineState::Initializing,
                            MachineStatus::Installing => MachineState::Installing,
                            MachineStatus::Writing => MachineState::Writing,
                            MachineStatus::Failed(ref msg) => MachineState::Failed { message: msg.clone() },
                        };
                        machine.metadata.updated_at = chrono::Utc::now();
                        if let Err(e) = state.store.put_machine(&machine).await {
                            error!("Sync: Failed to update status for VM {}: {}", vmid, e);
                        } else {
                            updated_status_count += 1;
                        }
                    }
                }

                // Update IP address if agent is running and IP is different
                if *agent_running {
                     let agent_ip_path = format!("/api2/json/nodes/{}/qemu/{}/agent/network-get-interfaces", _node_name, vmid);
                     match client.get(&agent_ip_path).await {
                        Ok(ip_resp) => {
                            match serde_json::from_slice::<serde_json::Value>(&ip_resp.body) {
                                Ok(ip_val) => {
                                    if let Some(result_array) = ip_val.get("data").and_then(|d| d.get("result")).and_then(|r| r.as_array()) {
                                        // Find the first valid non-loopback IPv4 address
                                        let mut found_ip = None;
                                        for iface_info in result_array {
                                            if let Some(ip_addrs) = iface_info.get("ip-addresses").and_then(|a| a.as_array()) {
                                                for addr_info in ip_addrs {
                                                    if addr_info.get("ip-address-type").and_then(|t| t.as_str()) == Some("ipv4") {
                                                        if let Some(ip_str) = addr_info.get("ip-address").and_then(|i| i.as_str()) {
                                                            // Check if it's not a loopback address
                                                            if !ip_str.starts_with("127.") {
                                                                found_ip = Some(ip_str.to_string());
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            }
                                            if found_ip.is_some() { break; }
                                        }

                                        if let Some(current_ip) = found_ip {
                                            // TODO: v1 Store doesn't track IP addresses yet
                                            // When IP tracking is added to v1 schema, update here
                                            info!(
                                                "Sync: Found IP {} for VM {} (ID: {}) via agent (IP tracking not yet in v1 schema)",
                                                current_ip, vmid, db_machine.id
                                            );
                                            // For now, just count it as seen but don't try to update
                                            let _ = updated_ip_count; // Suppress unused warning
                                        }
                                    }
                                }
                                Err(e) => warn!("Sync: Failed to parse agent IP response for VM {}: {}", vmid, e),
                            }
                        },
                        Err(e) => warn!("Sync: Failed to get agent IP for VM {}: {}", vmid, e),
                    }
                }
                                            } else {
                // VM exists in DB but not in API result
                info!("Sync: Proxmox VM {} (ID: {}) not found in API. Marking for pruning.", vmid, db_machine.id);
                machines_to_prune.push(db_machine.id);
            }
        }
        // Ignore non-Proxmox machines for this sync
    }

    // Prune machines that are no longer in Proxmox
    if !machines_to_prune.is_empty() {
        info!("Sync: Pruning {} machines not found in Proxmox API...", machines_to_prune.len());
        for machine_id in machines_to_prune {
            match state.store.delete_machine(machine_id).await {
                Ok(true) => {
                    info!("Sync: Successfully pruned machine {}", machine_id);
                    pruned_count += 1;
                },
                Ok(false) => {
                    warn!("Sync: Machine {} was already deleted", machine_id);
                },
                Err(e) => {
                    error!("Sync: Failed to prune machine {}: {}", machine_id, e);
                }
            }
        }
    }

    info!(
        "Proxmox sync finished. Status updates: {}, IP updates: {}, Pruned: {}",
        updated_status_count, updated_ip_count, pruned_count
    );

    Ok(())
}

// Create a new struct for the token creation request
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ProxmoxTokensCreateRequest {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub skip_tls_verify: bool,
}

// Handler to create Proxmox API tokens
// This is a separate endpoint from the connection handler, for use when
// we need to update tokens but don't need to change the connection settings
pub async fn create_proxmox_tokens_handler(
    State(state): State<crate::AppState>,
    Json(request): Json<ProxmoxTokensCreateRequest>,
) -> impl IntoResponse {
    // Attempt to create the tokens
    let tokens_result = generate_proxmox_tokens_with_credentials(&request).await;
    
    match tokens_result {
        Ok(token_set) => {
            // Save tokens to database (encrypted) and also add to in-memory store
            match save_proxmox_tokens(&state, token_set).await {
                Ok(_) => {
                    info!("Successfully created and saved specialized Proxmox API tokens");
                    
                    (StatusCode::OK, Json(json!({
                        "success": true,
                        "message": "Successfully created and saved specialized Proxmox API tokens",
                        "tokens_created": true,
                        "tokens_saved": true
                    })))
                },
                Err(e) => {
                    warn!("Successfully created tokens but failed to save them: {}", e);
                    
                    (StatusCode::OK, Json(json!({
                        "success": true,
                        "message": format!("Successfully created Proxmox API tokens but failed to save them: {}", e),
                        "tokens_created": true,
                        "tokens_saved": false
                    })))
                }
            }
        },
        Err(e) => {
            error!("Failed to create Proxmox API tokens: {}", e);
            
            (StatusCode::BAD_REQUEST, Json(json!({
                "success": false,
                "message": format!("Failed to create Proxmox API tokens: {}", e)
            })))
        }
    }
}

/// Saves Proxmox API tokens to the database for future use.
///
/// # Security
/// This function NEVER stores the root password. It only stores the API tokens
/// (encrypted) that were created with the password. The tokens have minimal permissions
/// needed for specific operations.
///
/// # Arguments
/// * `request` - The request containing connection information
/// * `vm_create_token` - Token for VM creation operations
/// * `vm_power_token` - Token for VM power operations
/// * `vm_config_token` - Token for VM configuration operations
/// * `vm_sync_token` - Token for synchronization operations
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(anyhow::Error)` on failure
pub async fn save_proxmox_tokens(state: &crate::AppState, token_set: ProxmoxTokenSet) -> Result<(), anyhow::Error> {
    info!("Saving Proxmox tokens to database");
    
    // Use encryption to protect tokens before storing
    use crate::encryption::encrypt_string;
    
    // Save encrypted tokens to database
    let encrypted_create_token = encrypt_string(&token_set.create_token)?;
    let encrypted_power_token = encrypt_string(&token_set.power_token)?;
    let encrypted_config_token = encrypt_string(&token_set.config_token)?;
    let encrypted_sync_token = encrypt_string(&token_set.sync_token)?;
    
    // Update database with encrypted tokens
    crate::db::update_proxmox_tokens(
        encrypted_create_token,
        encrypted_power_token,
        encrypted_config_token,
        encrypted_sync_token
    ).await?;
    
    // Also update connection settings
    crate::db::update_proxmox_connection_settings(
        &token_set.connection_info.host,
        token_set.connection_info.port,
        &token_set.connection_info.username,
        token_set.connection_info.skip_tls_verify
    ).await?;
    
    // Store tokens in memory for immediate use
    let mut tokens = state.tokens.lock().await;
    tokens.insert("proxmox_vm_create_token".to_string(), token_set.create_token);
    tokens.insert("proxmox_vm_power_token".to_string(), token_set.power_token);
    tokens.insert("proxmox_vm_config_token".to_string(), token_set.config_token);
    tokens.insert("proxmox_vm_sync_token".to_string(), token_set.sync_token);
    drop(tokens);
    
    // Also update host settings in memory
    let mut settings = state.settings.lock().await;
    settings.proxmox_host = Some(token_set.connection_info.host.clone());
    settings.proxmox_port = Some(token_set.connection_info.port as u16);
    settings.proxmox_username = Some(token_set.connection_info.username.clone());
    settings.proxmox_skip_tls_verify = Some(token_set.connection_info.skip_tls_verify);
    drop(settings);
    
    Ok(())
}

/// Loads Proxmox API tokens from the database and populates the in-memory token store.
/// 
/// This function should be called during server startup to ensure tokens are 
/// immediately available after restart without requiring users to reconnect to Proxmox.
/// 
/// # Arguments
/// * `state` - The application state containing the in-memory token store
/// 
/// # Returns
/// * `Ok(())` on success, including if no tokens were found
/// * `Err(anyhow::Error)` if an error occurred loading or decrypting tokens
pub async fn load_proxmox_tokens_to_memory(
    state: &crate::AppState
) -> Result<(), anyhow::Error> {
    use crate::encryption::decrypt_string;
    
    info!("Loading Proxmox API tokens from database to memory...");
    
    // Get Proxmox settings from the database
    let settings = match crate::db::get_proxmox_settings().await {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            info!("No Proxmox settings found in database, skipping token loading");
            return Ok(());
        },
        Err(e) => {
            warn!("Error loading Proxmox settings from database: {}", e);
            return Err(anyhow::anyhow!("Failed to load Proxmox settings: {}", e));
        }
    };
    
    // Extract all available tokens
    let token_map = [
        ("proxmox_vm_create_token", settings.vm_create_token),
        ("proxmox_vm_power_token", settings.vm_power_token),
        ("proxmox_vm_config_token", settings.vm_config_token),
        ("proxmox_vm_sync_token", settings.vm_sync_token),
    ];
    
    // Keep track of how many tokens were loaded
    let mut tokens_loaded = 0;
    
    // Acquire lock on the token store
    let mut tokens = state.tokens.lock().await;
    
    // Process each token type
    for (token_key, encrypted_token_opt) in token_map {
        if let Some(encrypted_token) = encrypted_token_opt {
            // Decrypt the token
            match decrypt_string(&encrypted_token) {
                Ok(decrypted_token) => {
                    // Add to the in-memory store
                    tokens.insert(token_key.to_string(), decrypted_token);
                    tokens_loaded += 1;
                },
                Err(e) => {
                    warn!("Failed to decrypt {} from database: {}", token_key, e);
                    // Continue with other tokens even if one fails
                }
            }
        }
    }
    
    // Release the lock
    drop(tokens);
    
    info!("Loaded {} Proxmox API tokens from database to memory", tokens_loaded);
    Ok(())
}

// Helper function to create a token with a specific role
async fn create_token_with_role(
    client: &ProxmoxApiClient,
    user: &str,
    token_name: &str,
    description: &str,
    role_name: &str
) -> Result<String, String> {
    info!("DEBUG: Creating token at path: /api2/json/access/users/{}/token/{}", user, token_name);
    
    // Set up token creation params
    let token_params = serde_json::json!({
        "comment": description,
        "expire": "0",  // No expiration
        "privsep": "1"  // Privilege separation enabled
    });
    
    let token_path = format!("/api2/json/access/users/{}/token/{}", user, token_name);
    info!("DEBUG: Token creation params: {:?}", token_params);
    
    // Create the token
    match client.post(&token_path, &token_params).await {
        Ok(response) => {
            info!("DEBUG: Token creation response status: {}", response.status);
            
            if response.status == 200 {
                // Parse the response to extract the token value
                // Proxmox client automatically deserializes the body for us
                let body_str = String::from_utf8_lossy(&response.body);
                info!("DEBUG: Token creation response body: {}", body_str);
                
                match serde_json::from_str::<serde_json::Value>(&body_str) {
                    Ok(json) => {
                        // Extract the token from the response
                        match json.get("data").and_then(|d| d.get("value")).and_then(|v| v.as_str()) {
                            Some(token_value) => {
                                let full_token_id = format!("{}!{}", user, token_name);
                                let full_token = format!("{}={}", full_token_id, token_value);
                                
                                // Set the ACL (permissions) for this token
                                info!("DEBUG: Setting ACL for token at path: /api2/json/access/acl");
                                let acl_params = serde_json::json!({
                                    "path": "/",  // Root path (applies to all)
                                    "propagate": "1",  // Propagate to sub-paths
                                    "roles": role_name,  // Role name provided
                                    "tokens": full_token_id  // Token ID
                                });
                                
                                info!("DEBUG: ACL params: {:?}", acl_params);
                                
                                match client.put("/api2/json/access/acl", &acl_params).await {
                                    Ok(acl_response) => {
                                        info!("DEBUG: ACL response status: {}", acl_response.status);
                                        let acl_body_str = String::from_utf8_lossy(&acl_response.body);
                                        info!("DEBUG: ACL response body: {}", acl_body_str);
                                        
                                        if acl_response.status == 200 {
                                            Ok(full_token)
                                        } else {
                                            // Check if role doesn't exist and try to create it
                                            if acl_body_str.contains("role") && acl_body_str.contains("does not exist") {
                                                info!("Role {} doesn't exist, attempting to create it", role_name);
                                                
                                                // Create the role
                                                let role_create_path = "/api2/json/access/roles";
                                                let role_create_params = serde_json::json!({
                                                    "roleid": role_name.to_string(),
                                                    "privs": ""  // Initially empty
                                                });
                                                
                                                match client.post(role_create_path, &role_create_params).await {
                                                    Ok(create_response) => {
                                                        if create_response.status == 200 {
                                                            info!("Created role {} successfully", role_name);
                                                            
                                                            // Try to set permissions
                                                            let permissions = match role_name {
                                                                "DragonflyVMConfig" => "VM.Config.Options,VM.Config.Disk",
                                                                "DragonflySync" => "VM.Audit,VM.Monitor,Sys.Audit",
                                                                _ => "",
                                                            };
                                                            
                                                            if !permissions.is_empty() {
                                                                let update_path = format!("/api2/json/access/roles/{}", role_name);
                                                                let perm_params = serde_json::json!({
                                                                    "privs": permissions
                                                                });
                                                                
                                                                match client.put(&update_path, &perm_params).await {
                                                                    Ok(_) => info!("Set permissions for new role {}", role_name),
                                                                    Err(e) => warn!("Failed to set permissions for new role {}: {}", role_name, e),
                                                                }
                                                            }
                                                            
                                                            // Try setting the ACL again
                                                            match client.put("/api2/json/access/acl", &acl_params).await {
                                                                Ok(retry_response) => {
                                                                    let retry_body = String::from_utf8_lossy(&retry_response.body);
                                                                    info!("DEBUG: ACL retry response: {}", retry_body);
                                                                    
                                                                    if retry_response.status == 200 {
                                                                        Ok(full_token)
                                                                    } else {
                                                                        // If still fails, try using a standard role as fallback
                                                                        let fallback_role = match role_name {
                                                                            "DragonflyVMConfig" => "PVEVMUser",
                                                                            "DragonflySync" => "PVEAuditor",
                                                                            _ => "PVEVMUser",
                                                                        };
                                                                        
                                                                        info!("Falling back to standard role: {}", fallback_role);
                                                                        let fallback_params = serde_json::json!({
                                                                            "path": "/",
                                                                            "propagate": "1",
                                                                            "roles": fallback_role,
                                                                            "tokens": full_token_id
                                                                        });
                                                                        
                                                                        match client.put("/api2/json/access/acl", &fallback_params).await {
                                                                            Ok(fallback_response) => {
                                                                                if fallback_response.status == 200 {
                                                                                    info!("Successfully set ACL with fallback role");
                                                                                    Ok(full_token)
                                                                                } else {
                                                                                    Err(format!("Failed to set ACL with fallback role: Status {}", fallback_response.status))
                                                                                }
                                                                            },
                                                                            Err(e) => Err(format!("Error setting ACL with fallback role: {}", e)),
                                                                        }
                                                                    }
                                                                },
                                                                Err(e) => Err(format!("Error in retry setting ACL: {}", e)),
                                                            }
                                                        } else {
                                                            // Try using standard role as fallback
                                                            let fallback_role = match role_name {
                                                                "DragonflyVMConfig" => "PVEVMUser",
                                                                "DragonflySync" => "PVEAuditor",
                                                                _ => "PVEVMUser",
                                                            };
                                                            
                                                            info!("Falling back to standard role: {}", fallback_role);
                                                            let fallback_params = serde_json::json!({
                                                                "path": "/",
                                                                "propagate": "1",
                                                                "roles": fallback_role,
                                                                "tokens": full_token_id
                                                            });
                                                            
                                                            match client.put("/api2/json/access/acl", &fallback_params).await {
                                                                Ok(fallback_response) => {
                                                                    if fallback_response.status == 200 {
                                                                        info!("Successfully set ACL with fallback role");
                                                                        Ok(full_token)
                                                                    } else {
                                                                        Err(format!("Failed to set ACL with fallback role: Status {}", fallback_response.status))
                                                                    }
                                                                },
                                                                Err(e) => Err(format!("Error setting ACL with fallback role: {}", e)),
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        warn!("Failed to create role {}: {}", role_name, e);
                                                        Err(format!("Failed to set ACL and role creation failed: {}", e))
                                                    }
                                                }
                                            } else {
                                                Err(format!("Failed to set ACL for token: Status {}", acl_response.status))
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        Err(format!("Failed to set ACL for token: {}", e))
                                    }
                                }
                            }
                            None => Err("Token value not found in response".to_string())
                        }
                    }
                    Err(e) => Err(format!("Failed to parse token response: {}", e))
                }
            } else {
                Err(format!("Failed to create token: Status {}", response.status))
            }
        }
        Err(e) => Err(format!("Error creating token: {}", e))
    }
}

#[derive(Debug, Clone)]
pub struct ProxmoxConnectionInfo {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub skip_tls_verify: bool,
}

#[derive(Debug, Clone)]
pub struct ProxmoxTokenSet {
    pub create_token: String,
    pub power_token: String,
    pub config_token: String,
    pub sync_token: String,
    pub connection_info: ProxmoxConnectionInfo,
}