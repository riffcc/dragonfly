use anyhow::Context;
use axum::{
    extract::State,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use proxmox_client::{HttpApiClient, Client as ProxmoxApiClient, TlsOptions, Token as ProxmoxToken};
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

/// Proxmox connection settings stored as JSON in the Store's settings KV.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxmoxSettings {
    pub id: i64,
    pub host: String,
    pub port: i32,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    pub ticket_timestamp: Option<i64>,
    pub skip_tls_verify: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_create_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_power_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_config_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_sync_token: Option<String>,
}

const PROXMOX_SETTINGS_KEY: &str = "proxmox_settings";

/// Load Proxmox settings from the Store's settings KV (public for use from api.rs).
pub async fn get_proxmox_settings_from_store_pub(
    store: &dyn crate::store::v1::Store,
) -> Result<Option<ProxmoxSettings>, anyhow::Error> {
    get_proxmox_settings_from_store(store).await
}

/// Save Proxmox settings to the Store's settings KV (public for use from api.rs).
pub async fn put_proxmox_settings_to_store_pub(
    store: &dyn crate::store::v1::Store,
    settings: &ProxmoxSettings,
) -> Result<(), anyhow::Error> {
    put_proxmox_settings_to_store(store, settings).await
}

/// Load Proxmox settings from the Store's settings KV.
async fn get_proxmox_settings_from_store(
    store: &dyn crate::store::v1::Store,
) -> Result<Option<ProxmoxSettings>, anyhow::Error> {
    match store.get_setting(PROXMOX_SETTINGS_KEY).await {
        Ok(Some(json)) => {
            let settings: ProxmoxSettings = serde_json::from_str(&json)?;
            Ok(Some(settings))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Failed to load Proxmox settings: {}", e)),
    }
}

/// Save Proxmox settings to the Store's settings KV as JSON.
async fn put_proxmox_settings_to_store(
    store: &dyn crate::store::v1::Store,
    settings: &ProxmoxSettings,
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string(settings)?;
    store
        .put_setting(PROXMOX_SETTINGS_KEY, &json)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to save Proxmox settings: {}", e))
}

/// Update connection settings (host, port, username, tls) in Store. Creates entry if needed.
async fn update_proxmox_connection_settings_in_store(
    store: &dyn crate::store::v1::Store,
    host: &str,
    port: i32,
    username: &str,
    skip_tls_verify: bool,
) -> Result<ProxmoxSettings, anyhow::Error> {
    let now = chrono::Utc::now();
    let mut settings = get_proxmox_settings_from_store(store)
        .await?
        .unwrap_or(ProxmoxSettings {
            id: 1,
            host: String::new(),
            port: 8006,
            username: String::new(),
            auth_ticket: None,
            csrf_token: None,
            ticket_timestamp: None,
            skip_tls_verify: false,
            created_at: now,
            updated_at: now,
            vm_create_token: None,
            vm_power_token: None,
            vm_config_token: None,
            vm_sync_token: None,
        });

    settings.host = host.to_string();
    settings.port = port;
    settings.username = username.to_string();
    settings.skip_tls_verify = skip_tls_verify;
    settings.updated_at = now;

    put_proxmox_settings_to_store(store, &settings).await?;
    Ok(settings)
}

/// Update encrypted tokens in Store's Proxmox settings.
async fn update_proxmox_tokens_in_store(
    store: &dyn crate::store::v1::Store,
    encrypted_create: String,
    encrypted_power: String,
    encrypted_config: String,
    encrypted_sync: String,
) -> Result<(), anyhow::Error> {
    let now = chrono::Utc::now();
    let mut settings = get_proxmox_settings_from_store(store)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Cannot update tokens: no Proxmox settings exist"))?;

    settings.vm_create_token = Some(encrypted_create);
    settings.vm_power_token = Some(encrypted_power);
    settings.vm_config_token = Some(encrypted_config);
    settings.vm_sync_token = Some(encrypted_sync);
    settings.updated_at = now;

    put_proxmox_settings_to_store(store, &settings).await
}

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
    import_guests: Option<bool>,
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
    
    info!("Using boot parameter: {}", boot_param);
    
    // Use the correct API path format for Proxmox
    let path = format!("/api2/json/nodes/{}/qemu/{}/config", node, vmid);
    info!("Using API path: {}", path);
    
    // Need to use URL-encoded form data for Proxmox API rather than JSON
    // This is critical for the VM configuration APIs to work properly
    let _params_map = vec![("boot", boot_param.as_str())];
    
    // First, try to make the request directly - API tokens may already be set up correctly
    info!("Sending PUT request to set boot order");
    
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
                        warn!("Proxmox API error response for boot order change");
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

/// Create a ProxmoxApiClient with proper TLS settings.
/// When `skip_tls_verify` is true, uses `TlsOptions::Insecure` to accept self-signed certs.
fn create_proxmox_client(host_uri: Uri, skip_tls_verify: bool) -> Result<ProxmoxApiClient, String> {
    if skip_tls_verify {
        ProxmoxApiClient::with_options(
            host_uri,
            TlsOptions::Insecure,
            proxmox_http::HttpOptions::default(),
        ).map_err(|e| format!("Failed to create Proxmox client: {}", e))
    } else {
        Ok(ProxmoxApiClient::new(host_uri))
    }
}

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
    let import_guests = request.import_guests.unwrap_or(false);

    // Same connection process as before - authenticate with provided credentials
    let result = authenticate_with_proxmox(state.store.as_ref(), &host, port as i32, &username, &password, skip_tls_verify).await;
    
    match result {
        Ok(_) => {
            info!("Successfully authenticated with Proxmox API");

            // Create specialized API tokens with minimal permissions
            info!("Creating specialized API tokens with minimal permissions");

            let token_request = ProxmoxTokensCreateRequest {
                host: host.clone(),
                port: port as i32,
                username: username.clone(),
                password: password.clone(),
                skip_tls_verify,
            };

            let tokens_result = generate_proxmox_tokens_with_credentials(&token_request).await;

            match tokens_result {
                Ok(token_set) => {
                    match save_proxmox_tokens(&state, token_set).await {
                        Ok(_) => {
                            info!("Successfully created and saved specialized Proxmox API tokens");

                            // Import guests if requested
                            let mut import_result = None;
                            if import_guests {
                                info!("Import guests requested, starting discovery...");
                                match connect_to_proxmox(&state, "sync").await {
                                    Ok(client) => {
                                        let cluster_name = host.clone();
                                        match discover_and_register_proxmox_vms(&client, &cluster_name, &state).await {
                                            Ok((registered, failed, _)) => {
                                                info!("Guest import complete: {} registered, {} failed", registered, failed);
                                                import_result = Some(json!({
                                                    "imported": registered,
                                                    "failed": failed,
                                                }));
                                            }
                                            Err(e) => {
                                                warn!("Guest import failed: {:?}", e);
                                                import_result = Some(json!({
                                                    "error": format!("Import failed: {:?}", e),
                                                }));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Could not connect for guest import: {}", e);
                                        import_result = Some(json!({
                                            "error": format!("Could not connect for import: {}", e),
                                        }));
                                    }
                                }
                            }

                            let mut response = json!({
                                "success": true,
                                "message": "Successfully connected to Proxmox and created API tokens",
                                "tokens_created": true,
                                "tokens_saved": true
                            });
                            if let Some(ir) = import_result {
                                response.as_object_mut().unwrap().insert("import_result".to_string(), ir);
                            }
                            (StatusCode::OK, Json(response))
                        },
                        Err(e) => {
                            warn!("Created tokens but failed to save them: {}", e);
                            (StatusCode::OK, Json(json!({
                                "success": true,
                                "message": format!("Connected to Proxmox and created tokens, but failed to save: {}", e),
                                "tokens_created": true,
                                "tokens_saved": false
                            })))
                        }
                    }
                },
                Err(e) => {
                    warn!("Connected to Proxmox but failed to create API tokens: {}", e);

                    let error_message = if e.contains("Parameter verification failed") || e.contains("privileges") || e.contains("privs") {
                        format!("Failed to create API tokens: {}. Check Proxmox version and permissions.", e)
                    } else if e.contains("permission") || e.contains("unauthorized") || e.contains("access") {
                        format!("Failed to create API tokens: {}. Account needs administrative privileges.", e)
                    } else {
                        format!("Failed to create API tokens: {}", e)
                    };

                    (StatusCode::OK, Json(json!({
                        "success": true,
                        "message": format!("Connected to Proxmox but failed to create tokens: {}", e),
                        "tokens_created": false,
                        "token_error": error_message
                    })))
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
    store: &dyn crate::store::v1::Store,
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
    
    let client = create_proxmox_client(host_uri, skip_tls_verify)?;

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
            match update_proxmox_connection_settings_in_store(
                store, host, port as i32, username, skip_tls_verify
            ).await {
                Ok(_) => info!("Proxmox connection settings saved to Store (without storing password)"),
                Err(e) => warn!("Failed to save Proxmox settings to Store: {}", e),
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
    info!("Starting token creation process");
    
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
    
    let client = create_proxmox_client(host_uri, *skip_tls_verify)?;

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
                info!("Creating or checking for role: {}", role_name);
                
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
                ("DragonflySync", "VM.Audit,Sys.Audit"),
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
            info!("Creating VM creation token...");
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
            
            info!("Creating VM power token...");
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
            
            info!("Creating VM config token...");
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
            
            info!("Creating VM sync token...");
            let sync_token = match create_token_with_role(
                &client, 
                &user_part, 
                "dragonfly-sync", 
                "Dragonfly automation token for VM.Audit Sys.Audit",
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

/// Associative identity lookup: find an existing machine that matches ANY identity
/// anchor from the new machine. Anchors are checked in priority order:
///
/// 1. **Proxmox source** (cluster + node + vmid/ctid/node_name) — strongest, never changes
/// 2. **MAC address** — strong, but can change if NIC is replaced/regenerated
///
/// If ANY anchor matches, it's the same machine. This is associative, not hash-based.
fn find_existing_machine<'a>(
    existing_machines: &'a [dragonfly_common::Machine],
    new_machine: &dragonfly_common::Machine,
) -> Option<&'a dragonfly_common::Machine> {
    use dragonfly_common::MachineSource;

    // Priority 1: Match by Proxmox source tuple (strongest anchor)
    match &new_machine.metadata.source {
        MachineSource::Proxmox { cluster, node, vmid } => {
            if let Some(m) = existing_machines.iter().find(|m| {
                matches!(&m.metadata.source, MachineSource::Proxmox { cluster: c, node: n, vmid: v }
                    if c == cluster && n == node && v == vmid)
            }) {
                return Some(m);
            }
        }
        MachineSource::ProxmoxLxc { cluster, node, ctid } => {
            if let Some(m) = existing_machines.iter().find(|m| {
                matches!(&m.metadata.source, MachineSource::ProxmoxLxc { cluster: c, node: n, ctid: ct }
                    if c == cluster && n == node && ct == ctid)
            }) {
                return Some(m);
            }
        }
        MachineSource::ProxmoxNode { cluster, node } => {
            if let Some(m) = existing_machines.iter().find(|m| {
                matches!(&m.metadata.source, MachineSource::ProxmoxNode { cluster: c, node: n }
                    if c == cluster && n == node)
            }) {
                return Some(m);
            }
        }
        _ => {}
    }

    // Priority 2: Match by ANY MAC address (associative — any NIC could PXE boot)
    for new_mac in &new_machine.identity.all_macs {
        if new_mac.is_empty() || new_mac == "unknown" {
            continue;
        }
        for existing in existing_machines.iter() {
            if existing.identity.all_macs.iter().any(|m| m == new_mac) {
                return Some(existing);
            }
        }
    }

    None
}

/// Merge a newly-discovered machine into an existing one, preserving user-configured
/// fields while updating hardware/status from the fresh Proxmox data.
fn merge_into_existing(existing: &dragonfly_common::Machine, new_machine: &mut dragonfly_common::Machine) {
    // Keep the existing UUID — this IS the machine
    new_machine.id = existing.id;

    // Preserve user-configured fields
    new_machine.config.memorable_name = existing.config.memorable_name.clone();
    if existing.config.os_choice.is_some() {
        new_machine.config.os_choice = existing.config.os_choice.clone();
    }
    if existing.config.hostname.is_some() && new_machine.config.hostname.is_none() {
        new_machine.config.hostname = existing.config.hostname.clone();
    }

    // Merge tags: keep existing user tags, add new Proxmox-imported ones
    for tag in &existing.config.tags {
        if !new_machine.config.tags.contains(tag) {
            new_machine.config.tags.push(tag.clone());
        }
    }

    // Preserve timestamps, pending state, BMC, network config
    new_machine.metadata.created_at = existing.metadata.created_at;
    new_machine.config.pending_apply = existing.config.pending_apply;
    new_machine.config.pending_fields = existing.config.pending_fields.clone();
    new_machine.config.pending_snapshot = existing.config.pending_snapshot.clone();
    if existing.config.bmc.is_some() {
        new_machine.config.bmc = existing.config.bmc.clone();
    }
    new_machine.config.network_mode = existing.config.network_mode.clone();
    new_machine.config.static_ipv4 = existing.config.static_ipv4.clone();
    new_machine.config.static_ipv6 = existing.config.static_ipv6.clone();
    if !existing.config.nameservers.is_empty() {
        new_machine.config.nameservers = existing.config.nameservers.clone();
    }
    new_machine.config.domain = existing.config.domain.clone();
    new_machine.config.network_id = existing.config.network_id;
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
    
    // Load all existing machines ONCE for associative dedup during import
    let existing_machines = state.store.list_machines().await
        .unwrap_or_default();
    info!("Loaded {} existing machines for dedup", existing_machines.len());

    // Fetch cluster status to get node IPs (the /nodes/{node}/status endpoint
    // does NOT include an IP field — /cluster/status does)
    let mut node_ip_map = std::collections::HashMap::<String, String>::new();
    if let Ok(cluster_status_resp) = client.get("/api2/json/cluster/status").await {
        if let Ok(cluster_val) = serde_json::from_slice::<serde_json::Value>(&cluster_status_resp.body) {
            if let Some(entries) = cluster_val.get("data").and_then(|d| d.as_array()) {
                for entry in entries {
                    if entry.get("type").and_then(|t| t.as_str()) == Some("node") {
                        if let (Some(name), Some(ip)) = (
                            entry.get("name").and_then(|n| n.as_str()),
                            entry.get("ip").and_then(|i| i.as_str()),
                        ) {
                            info!("Cluster status: node '{}' has IP {}", name, ip);
                            node_ip_map.insert(name.to_string(), ip.to_string());
                        }
                    }
                }
            }
        }
    }

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
        
        // --- Gather host node hardware data ---

        // IP from /cluster/status (already fetched above)
        let host_ip = node_ip_map.get(node_name).cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        // CPU, RAM, PVE version from /nodes/{node}/status
        let node_status_path = format!("/api2/json/nodes/{}/status", node_name);
        let mut host_hostname = node_name.to_string();
        let mut host_cpu_model = None;
        let mut host_cpu_cores = None;
        let mut host_cpu_threads = None;
        let mut host_ram_bytes = None;

        if let Ok(resp) = client.get(&node_status_path).await {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                if let Some(data) = val.get("data") {
                    // PVE version → hostname
                    if let Some(ver) = data.get("pveversion").and_then(|v| v.as_str()) {
                        host_hostname = format!("{} (PVE {})", node_name, ver);
                    }
                    // CPU info: { "model": "...", "cpus": N, "cores": N, "sockets": N }
                    if let Some(cpuinfo) = data.get("cpuinfo") {
                        host_cpu_model = cpuinfo.get("model").and_then(|m| m.as_str()).map(String::from);
                        host_cpu_cores = cpuinfo.get("cores").and_then(|c| c.as_u64()).map(|c| c as u32);
                        host_cpu_threads = cpuinfo.get("cpus").and_then(|c| c.as_u64()).map(|c| c as u32);
                    }
                    // Memory: { "total": bytes, "used": bytes, "free": bytes }
                    if let Some(meminfo) = data.get("memory") {
                        host_ram_bytes = meminfo.get("total").and_then(|t| t.as_u64());
                    }
                }
            }
        }

        // Collect ALL physical NICs from /nodes/{node}/network
        // Exclude virtual interfaces (tap, veth, fwbr, fwpr, fwln, docker, virbr, lo)
        let node_net_path = format!("/api2/json/nodes/{}/network", node_name);
        let mut physical_nics: Vec<dragonfly_common::NetworkInterface> = Vec::new();

        if let Ok(resp) = client.get(&node_net_path).await {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                if let Some(ifaces) = val.get("data").and_then(|d| d.as_array()) {
                    for iface in ifaces {
                        let name = iface.get("iface").and_then(|n| n.as_str()).unwrap_or("");
                        let itype = iface.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        let hwaddr = iface.get("hwaddr").and_then(|h| h.as_str()).unwrap_or("");
                        let active = iface.get("active").and_then(|a| a.as_u64()).unwrap_or(0) == 1;

                        // Skip interfaces without a valid MAC
                        if hwaddr.len() != 17 || !hwaddr.contains(':') {
                            continue;
                        }

                        // Skip virtual/container/VM interfaces
                        let is_virtual = name.starts_with("tap")
                            || name.starts_with("veth")
                            || name.starts_with("fwbr")
                            || name.starts_with("fwpr")
                            || name.starts_with("fwln")
                            || name.starts_with("docker")
                            || name.starts_with("br-")
                            || name.starts_with("virbr")
                            || name == "lo";
                        if is_virtual {
                            continue;
                        }

                        // Accept physical NICs (eth), bonds, and bridges (vmbr)
                        let is_physical = itype == "eth" || itype == "bond"
                            || itype == "bridge" || name.starts_with("en");
                        if !is_physical {
                            continue;
                        }

                        info!("Node '{}': found NIC {} (type={}, hwaddr={}, active={})",
                              node_name, name, itype, hwaddr, active);

                        physical_nics.push(dragonfly_common::NetworkInterface {
                            name: name.to_string(),
                            mac: hwaddr.to_lowercase(),
                            speed_mbps: None, // Proxmox API doesn't expose link speed
                        });
                    }
                }
            }
        }

        if physical_nics.is_empty() {
            warn!("No physical NICs found for node '{}', skipping registration", node_name);
        } else {
            info!("Node '{}': {} physical NICs, IP={}, CPU={:?}, RAM={:?}",
                  node_name, physical_nics.len(), host_ip,
                  host_cpu_model, host_ram_bytes);

            // Build identity from ALL physical MACs (any could PXE boot)
            let all_macs: Vec<String> = physical_nics.iter().map(|n| n.mac.clone()).collect();
            let primary_mac = all_macs[0].clone();
            let identity = dragonfly_common::MachineIdentity::new(
                primary_mac.clone(),
                all_macs,
                None, None, None,
            );

            let now = chrono::Utc::now();
            let mut machine = dragonfly_common::Machine {
                id: dragonfly_common::new_machine_id(),
                identity,
                status: dragonfly_common::MachineStatus {
                    state: dragonfly_common::MachineState::ExistingOs {
                        os_name: "Proxmox VE".to_string(),
                    },
                    last_seen: Some(now),
                    current_ip: Some(host_ip.clone()),
                    current_workflow: None,
                    last_workflow_result: None,
                },
                hardware: dragonfly_common::HardwareInfo {
                    cpu_model: host_cpu_model,
                    cpu_cores: host_cpu_cores,
                    cpu_threads: host_cpu_threads,
                    memory_bytes: host_ram_bytes,
                    disks: Vec::new(),
                    gpus: Vec::new(),
                    network_interfaces: physical_nics,
                    is_virtual: false,
                    virt_platform: None,
                },
                config: {
                    let mut cfg = dragonfly_common::MachineConfig::with_mac(&primary_mac);
                    cfg.hostname = Some(host_hostname.clone());
                    cfg
                },
                metadata: dragonfly_common::MachineMetadata {
                    created_at: now,
                    updated_at: now,
                    labels: std::collections::HashMap::new(),
                    source: dragonfly_common::MachineSource::ProxmoxNode {
                        cluster: cluster_name.to_string(),
                        node: node_name.to_string(),
                    },
                },
            };

            // Associative dedup
            if let Some(existing) = find_existing_machine(&existing_machines, &machine) {
                info!("Found existing machine {} for node '{}', updating", existing.id, node_name);
                merge_into_existing(existing, &mut machine);
            }

            let machine_id = machine.id;
            match state.store.put_machine(&machine).await {
                Ok(()) => {
                    info!("Registered Proxmox host node '{}' as machine {} ({} NICs)",
                          node_name, machine_id, machine.hardware.network_interfaces.len());
                    registered_machines += 1;
                }
                Err(e) => {
                    error!("Failed to register Proxmox host node '{}': {}", node_name, e);
                    failed_registrations += 1;
                }
            }
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
                disks: Vec::new(),
                nameservers: Vec::new(),
                cpu_model: Some("Proxmox Virtual CPU".to_string()),
                cpu_cores: Some(vm_cpu_cores),
                total_ram_bytes: Some(vm_mem_bytes),
                proxmox_vmid: Some(vmid),
                proxmox_node: Some(node_name.to_string()),
                proxmox_cluster: Some(cluster_name.to_string()),
                proxmox_type: Some("vm".to_string()),
            };

            // Create v1 Machine from register request
            let mut machine = machine_from_register_request(&register_request);

            // Import tags from Proxmox (semicolon-separated string)
            if let Some(tags_str) = config_data.get("tags").and_then(|t| t.as_str()) {
                machine.config.tags = tags_str.split(';')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                if !machine.config.tags.is_empty() {
                    info!("Imported {} tags for VM {}: {:?}", machine.config.tags.len(), vmid, machine.config.tags);
                }
            }

            // Set the machine state based on VM status
            use dragonfly_common::MachineState;
            machine.status.state = match status {
                "running" => MachineState::ExistingOs { os_name: "Unknown".to_string() },
                "stopped" => MachineState::Offline,
                _ => MachineState::ExistingOs { os_name: "Unknown".to_string() },
            };

            // Associative dedup: match by Proxmox source tuple or MAC
            if let Some(existing) = find_existing_machine(&existing_machines, &machine) {
                info!("Found existing machine {} for VM {} ({}), updating", existing.id, vmid, name);
                merge_into_existing(existing, &mut machine);
            }

            let machine_id = machine.id;
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

        // --- Fetch and Register LXC containers for this node ---
        info!("Processing LXC containers for node: {}", node_name);

        let lxc_path = format!("/api2/json/nodes/{}/lxc", node_name);
        let lxc_response = match client.get(&lxc_path).await {
            Ok(response) => Some(response),
            Err(e) => {
                warn!("Failed to fetch LXC containers for node {}: {}", node_name, e);
                None
            }
        };

        if let Some(lxc_resp) = lxc_response {
            let lxc_value: serde_json::Value = match serde_json::from_slice(&lxc_resp.body) {
                Ok(value) => value,
                Err(e) => {
                    warn!("Failed to parse LXC response for node {}: {}", node_name, e);
                    serde_json::Value::Null
                }
            };

            if let Some(lxc_data) = lxc_value.get("data").and_then(|d| d.as_array()) {
                info!("Found {} LXC containers on node {}", lxc_data.len(), node_name);

                for ct in lxc_data {
                    let ctid = match ct.get("vmid").and_then(|id| id.as_u64()).map(|id| id as u32) {
                        Some(id) => id,
                        None => { continue; }
                    };

                    let ct_name = ct.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                    let ct_status = ct.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");

                    // Get container config for MAC address and resources
                    let ct_config_path = format!("/api2/json/nodes/{}/lxc/{}/config", node_name, ctid);
                    let ct_config = match client.get(&ct_config_path).await {
                        Ok(resp) => serde_json::from_slice::<serde_json::Value>(&resp.body).ok(),
                        Err(e) => {
                            warn!("Failed to fetch LXC {} config: {}", ctid, e);
                            None
                        }
                    };

                    // Extract MAC from LXC net config (format: "name=eth0,bridge=vmbr0,hwaddr=XX:XX:XX:XX:XX:XX,...")
                    let mut ct_mac = None;
                    let mut ct_mem_bytes: u64 = 0;
                    let mut ct_cpu_cores: u32 = 0;

                    if let Some(config_val) = &ct_config {
                        if let Some(config_data) = config_val.get("data") {
                            // Extract MAC from net0..net7
                            for i in 0..8 {
                                let net_key = format!("net{}", i);
                                if let Some(net_cfg) = config_data.get(&net_key).and_then(|n| n.as_str()) {
                                    // LXC net config: "name=eth0,bridge=vmbr0,hwaddr=AA:BB:CC:DD:EE:FF,..."
                                    for part in net_cfg.split(',') {
                                        if let Some(mac) = part.strip_prefix("hwaddr=") {
                                            if mac.len() == 17 && mac.contains(':') {
                                                ct_mac = Some(mac.to_lowercase());
                                                break;
                                            }
                                        }
                                    }
                                    if ct_mac.is_some() { break; }
                                }
                            }

                            // Memory (LXC uses megabytes in "memory" field)
                            if let Some(mem_mb) = config_data.get("memory").and_then(|m| m.as_u64()) {
                                ct_mem_bytes = mem_mb * 1024 * 1024;
                            }

                            // CPU cores
                            if let Some(cores) = config_data.get("cores").and_then(|c| c.as_u64()) {
                                ct_cpu_cores = cores as u32;
                            }
                        }
                    }

                    let mac_address = match ct_mac {
                        Some(mac) => mac,
                        None => {
                            warn!("No MAC found for LXC container {}, skipping", ctid);
                            continue;
                        }
                    };

                    // Try to get IP from container status if running
                    let mut ct_ip = "Unknown".to_string();
                    if ct_status == "running" {
                        let ct_ifaces_path = format!("/api2/json/nodes/{}/lxc/{}/interfaces", node_name, ctid);
                        if let Ok(ifaces_resp) = client.get(&ct_ifaces_path).await {
                            if let Ok(ifaces_val) = serde_json::from_slice::<serde_json::Value>(&ifaces_resp.body) {
                                if let Some(ifaces) = ifaces_val.get("data").and_then(|d| d.as_array()) {
                                    for iface in ifaces {
                                        let iface_name = iface.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                        if iface_name == "lo" { continue; }
                                        if let Some(inet) = iface.get("inet").and_then(|i| i.as_str()) {
                                            // Format: "10.7.1.50/24"
                                            if let Some(ip) = inet.split('/').next() {
                                                if !ip.starts_with("127.") {
                                                    ct_ip = ip.to_string();
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    discovered_machines.push(DiscoveredProxmox {
                        host: format!("{}-lxc-{}", node_name, ctid),
                        port: 0,
                        hostname: Some(ct_name.to_string()),
                        mac_address: Some(mac_address.clone()),
                        machine_type: "proxmox-lxc".to_string(),
                        vmid: Some(ctid),
                        parent_host: Some(node_name.to_string()),
                    });

                    info!("Processing LXC container {} (ID: {}, Status: {}, IP: {})", ct_name, ctid, ct_status, ct_ip);

                    let register_request = RegisterRequest {
                        mac_address,
                        ip_address: ct_ip,
                        hostname: Some(ct_name.to_string()),
                        disks: Vec::new(),
                        nameservers: Vec::new(),
                        cpu_model: Some("Proxmox LXC Container".to_string()),
                        cpu_cores: Some(ct_cpu_cores),
                        total_ram_bytes: Some(ct_mem_bytes),
                        proxmox_vmid: Some(ctid),
                        proxmox_node: Some(node_name.to_string()),
                        proxmox_cluster: Some(cluster_name.to_string()),
                        proxmox_type: Some("lxc".to_string()),
                    };

                    let mut machine = machine_from_register_request(&register_request);

                    // Import tags from Proxmox LXC config (semicolon-separated string)
                    if let Some(config_val) = &ct_config {
                        if let Some(config_data) = config_val.get("data") {
                            if let Some(tags_str) = config_data.get("tags").and_then(|t| t.as_str()) {
                                machine.config.tags = tags_str.split(';')
                                    .map(|t| t.trim().to_string())
                                    .filter(|t| !t.is_empty())
                                    .collect();
                                if !machine.config.tags.is_empty() {
                                    info!("Imported {} tags for LXC {}: {:?}", machine.config.tags.len(), ctid, machine.config.tags);
                                }
                            }
                        }
                    }

                    use dragonfly_common::MachineState;
                    machine.status.state = match ct_status {
                        "running" => MachineState::ExistingOs { os_name: "Unknown".to_string() },
                        "stopped" => MachineState::Offline,
                        _ => MachineState::ExistingOs { os_name: "Unknown".to_string() },
                    };

                    // Associative dedup: match by Proxmox source tuple or MAC
                    if let Some(existing) = find_existing_machine(&existing_machines, &machine) {
                        info!("Found existing machine {} for LXC {} ({}), updating", existing.id, ctid, ct_name);
                        merge_into_existing(existing, &mut machine);
                    }

                    let machine_id = machine.id;
                    match state.store.put_machine(&machine).await {
                        Ok(()) => {
                            info!("Successfully registered Proxmox LXC {} as machine {}", ctid, machine_id);
                            registered_machines += 1;
                        },
                        Err(e) => {
                            error!("Failed to register Proxmox LXC {}: {}", ctid, e);
                            failed_registrations += 1;
                        }
                    }
                }
            }
        }
    }

    // Return success with a summary
    info!("Proxmox guest discovery and registration complete: {} successful, {} failed",
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
                        // Check Store as a last resort
                        match get_proxmox_settings_from_store(state_clone.store.as_ref()).await {
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
        
        let host_url = format!("https://{}:{}", host, port);
        let base_uri = host_url.parse::<Uri>()
            .context(format!("Invalid Proxmox URL: {}", host_url))?;

        // Parse the API token to extract user and token parts
        // Format: user@realm!tokenname=token_value
        if let Some(equals_pos) = token.find('=') {
            let token_id = &token[..equals_pos];
            let token_value = &token[equals_pos + 1..];

            // Create client with proper TLS settings and authenticate
            let client = create_proxmox_client(base_uri, skip_tls_verify)
                .map_err(|e| anyhow::anyhow!(e))?;
            client.set_authentication(ProxmoxToken {
                userid: token_id.to_string(),
                prefix: "PVEAPIToken".to_string(),
                value: token_value.to_string(),
                perl_compat: true,
            });

            info!("Successfully initialized Proxmox client with in-memory API token for {} operations", token_type);
            return Ok(client);
        }
    }
    
    // If not in memory, try to get settings from the Store
    let db_settings = match get_proxmox_settings_from_store(state.store.as_ref()).await {
        Ok(Some(settings)) => {
            info!("Found Proxmox settings in Store for host {}", settings.host);
            Some(settings)
        },
        Ok(None) => {
            info!("No Proxmox settings found in Store, checking in-memory settings");
            None
        },
        Err(e) => {
            warn!("Error loading Proxmox settings from Store: {}", e);
            None
        }
    };
    
    // If we have settings in the database, try using the appropriate API token
    if let Some(settings) = db_settings {
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
                    // Format: user@realm!tokenname=token_value
                    if let Some(equals_pos) = api_token.find('=') {
                        let token_id = &api_token[..equals_pos];
                        let token_value = &api_token[equals_pos + 1..];

                        // Create client with proper TLS settings and authenticate
                        let client = create_proxmox_client(base_uri, settings.skip_tls_verify)
                            .map_err(|e| anyhow::anyhow!(e))?;
                        client.set_authentication(ProxmoxToken {
                            userid: token_id.to_string(),
                            prefix: "PVEAPIToken".to_string(),
                            value: token_value.to_string(),
                            perl_compat: true,
                        });

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
    
    // Update Store with encrypted tokens
    update_proxmox_tokens_in_store(
        state.store.as_ref(),
        encrypted_create_token,
        encrypted_power_token,
        encrypted_config_token,
        encrypted_sync_token,
    ).await?;

    // Also update connection settings
    update_proxmox_connection_settings_in_store(
        state.store.as_ref(),
        &token_set.connection_info.host,
        token_set.connection_info.port,
        &token_set.connection_info.username,
        token_set.connection_info.skip_tls_verify,
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
    
    // Get Proxmox settings from the Store
    let settings = match get_proxmox_settings_from_store(state.store.as_ref()).await {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            info!("No Proxmox settings found in Store, skipping token loading");
            return Ok(());
        },
        Err(e) => {
            warn!("Error loading Proxmox settings from Store: {}", e);
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
    info!("Creating token {}/{}", user, token_name);
    
    // Set up token creation params
    let token_params = serde_json::json!({
        "comment": description,
        "expire": "0",  // No expiration
        "privsep": "1"  // Privilege separation enabled
    });
    
    let token_path = format!("/api2/json/access/users/{}/token/{}", user, token_name);
    info!("Creating API token: {}/{}", user, token_name);
    
    // Create the token
    match client.post(&token_path, &token_params).await {
        Ok(response) => {
            if response.status == 200 {
                let body_str = String::from_utf8_lossy(&response.body);
                
                match serde_json::from_str::<serde_json::Value>(&body_str) {
                    Ok(json) => {
                        // Extract the token from the response
                        match json.get("data").and_then(|d| d.get("value")).and_then(|v| v.as_str()) {
                            Some(token_value) => {
                                let full_token_id = format!("{}!{}", user, token_name);
                                let full_token = format!("{}={}", full_token_id, token_value);
                                
                                // Set the ACL (permissions) for this token
                                info!("Setting ACL for token {} with role {}", token_name, role_name);
                                let acl_params = serde_json::json!({
                                    "path": "/",
                                    "propagate": "1",
                                    "roles": role_name,
                                    "tokens": full_token_id
                                });
                                
                                match client.put("/api2/json/access/acl", &acl_params).await {
                                    Ok(acl_response) => {
                                        let acl_body_str = String::from_utf8_lossy(&acl_response.body);
                                        
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
                                                                "DragonflySync" => "VM.Audit,Sys.Audit",
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
                                                                    info!("ACL retry response status for {}", role_name);
                                                                    
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

/// Sync tags from a Dragonfly machine to Proxmox.
/// Called when tags are updated in Dragonfly to push the change back to Proxmox.
pub async fn sync_tags_to_proxmox(
    state: &AppState,
    machine: &dragonfly_common::machine::Machine,
) {
    use dragonfly_common::MachineSource;

    let (api_type, node, id) = match &machine.metadata.source {
        MachineSource::Proxmox { node, vmid, .. } => ("qemu", node.clone(), *vmid),
        MachineSource::ProxmoxLxc { node, ctid, .. } => ("lxc", node.clone(), *ctid),
        _ => return, // Not a Proxmox guest, nothing to sync
    };

    let tags_str = machine.config.tags.join(";");
    let path = format!("/api2/json/nodes/{}/{}/{}/config", node, api_type, id);

    match connect_to_proxmox(state, "config").await {
        Ok(client) => {
            let body = json!({ "tags": tags_str });
            match client.put(&path, &body).await {
                Ok(resp) => {
                    if resp.status >= 200 && resp.status < 300 {
                        info!("Synced tags to Proxmox {} {}: {:?}", api_type, id, machine.config.tags);
                    } else {
                        warn!("Proxmox returned {} when syncing tags for {} {}", resp.status, api_type, id);
                    }
                }
                Err(e) => {
                    warn!("Failed to sync tags to Proxmox for {} {}: {}", api_type, id, e);
                }
            }
        }
        Err(e) => {
            warn!("Could not connect to Proxmox to sync tags: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_common::{Machine, MachineIdentity, MachineSource};

    fn make_vm(mac: &str, cluster: &str, node: &str, vmid: u32) -> Machine {
        let identity = MachineIdentity::from_mac(mac);
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::Proxmox {
            cluster: cluster.to_string(),
            node: node.to_string(),
            vmid,
        };
        m
    }

    fn make_lxc(mac: &str, cluster: &str, node: &str, ctid: u32) -> Machine {
        let identity = MachineIdentity::from_mac(mac);
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::ProxmoxLxc {
            cluster: cluster.to_string(),
            node: node.to_string(),
            ctid,
        };
        m
    }

    fn make_node(mac: &str, cluster: &str, node: &str) -> Machine {
        let identity = MachineIdentity::from_mac(mac);
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::ProxmoxNode {
            cluster: cluster.to_string(),
            node: node.to_string(),
        };
        m
    }

    /// Make a node with multiple NICs (realistic bare-metal host)
    fn make_multi_nic_node(macs: &[&str], cluster: &str, node: &str) -> Machine {
        let all_macs: Vec<String> = macs.iter().map(|m| m.to_string()).collect();
        let identity = MachineIdentity::new(
            all_macs[0].clone(),
            all_macs,
            None, None, None,
        );
        let mut m = Machine::new(identity);
        m.metadata.source = MachineSource::ProxmoxNode {
            cluster: cluster.to_string(),
            node: node.to_string(),
        };
        m
    }

    #[test]
    fn test_dedup_matches_node_by_any_nic_mac() {
        // Existing node registered with 4 NICs
        let existing = vec![make_multi_nic_node(
            &["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03", "aa:bb:cc:00:00:04"],
            "cluster1", "bee",
        )];

        // New import only sees NIC #3 (e.g. different bridge config exposed different MACs)
        let new = make_node("aa:bb:cc:00:00:03", "cluster1", "bee");
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some(), "Should match when ANY MAC in all_macs overlaps");
    }

    #[test]
    fn test_dedup_matches_pxe_boot_agent_to_node_by_mac() {
        // Node was imported from Proxmox with multiple NICs
        let existing = vec![make_multi_nic_node(
            &["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"],
            "cluster1", "bee",
        )];

        // Agent PXE-booted on NIC #2 (different source type, but MAC matches)
        let identity = MachineIdentity::from_mac("aa:bb:cc:00:00:02");
        let agent_machine = Machine::new(identity);
        let found = find_existing_machine(&existing, &agent_machine);
        assert!(found.is_some(), "PXE boot on any NIC should find the existing node");
    }

    #[test]
    fn test_dedup_matches_vm_by_source() {
        let existing = vec![make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, existing[0].id);
    }

    #[test]
    fn test_dedup_matches_vm_even_with_different_mac() {
        // VM got its NIC regenerated — different MAC, same source tuple
        let existing = vec![make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("ff:ff:ff:ff:ff:ff", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some(), "Should match by Proxmox source even when MAC differs");
        assert_eq!(found.unwrap().id, existing[0].id);
    }

    #[test]
    fn test_dedup_no_match_different_vmid() {
        let existing = vec![make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("aa:bb:cc:dd:ee:02", "cluster1", "node1", 200);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_none(), "Different VMID = different machine");
    }

    #[test]
    fn test_dedup_matches_lxc_by_source() {
        let existing = vec![make_lxc("aa:bb:cc:dd:ee:01", "cluster1", "node1", 300)];
        let new = make_lxc("aa:bb:cc:dd:ee:01", "cluster1", "node1", 300);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some());
    }

    #[test]
    fn test_dedup_matches_node_by_source() {
        let existing = vec![make_node("aa:bb:cc:dd:ee:01", "cluster1", "bee")];
        let new = make_node("ff:ff:ff:ff:ff:ff", "cluster1", "bee");
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some(), "Should match node by cluster+node_name");
    }

    #[test]
    fn test_dedup_falls_back_to_mac() {
        // Agent-registered machine (no Proxmox source) matched by MAC
        let identity = MachineIdentity::from_mac("aa:bb:cc:dd:ee:01");
        let agent_machine = Machine::new(identity);
        let existing = vec![agent_machine];

        let new = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        assert!(found.is_some(), "Should fall back to MAC match when source doesn't match");
    }

    #[test]
    fn test_dedup_vm_does_not_match_lxc_same_id() {
        // VM 100 and LXC 100 are different machines
        let existing = vec![make_lxc("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100)];
        let new = make_vm("aa:bb:cc:dd:ee:02", "cluster1", "node1", 100);
        let found = find_existing_machine(&existing, &new);
        // Source types differ (Proxmox vs ProxmoxLxc), and MACs differ → no match
        assert!(found.is_none(), "VM and LXC with same numeric ID are different machines");
    }

    #[test]
    fn test_merge_preserves_user_fields() {
        let mut existing = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        existing.config.memorable_name = "my-cool-server".to_string();
        existing.config.os_choice = Some("debian-12".to_string());
        existing.config.tags = vec!["production".to_string(), "web".to_string()];

        let mut new = make_vm("aa:bb:cc:dd:ee:01", "cluster1", "node1", 100);
        new.config.tags = vec!["proxmox-imported".to_string()];
        new.hardware.cpu_cores = Some(8); // Updated hardware from Proxmox

        merge_into_existing(&existing, &mut new);

        assert_eq!(new.id, existing.id, "UUID must be preserved");
        assert_eq!(new.config.memorable_name, "my-cool-server", "User-set name must be preserved");
        assert_eq!(new.config.os_choice, Some("debian-12".to_string()), "User-set OS must be preserved");
        assert!(new.config.tags.contains(&"production".to_string()), "Existing tags must be kept");
        assert!(new.config.tags.contains(&"web".to_string()), "Existing tags must be kept");
        assert!(new.config.tags.contains(&"proxmox-imported".to_string()), "New tags must be added");
        assert_eq!(new.hardware.cpu_cores, Some(8), "Fresh hardware data must be used");
    }
}