use anyhow::Context;
use axum::{Json, extract::State, http::{StatusCode, Uri}, response::IntoResponse};
use proxmox_client::{
    Client as ProxmoxApiClient, HttpApiClient, TlsOptions, Token as ProxmoxToken,
};
use serde_json::json;
use tracing::{error, info, warn};

use super::discovery::connect_proxmox_discover;
use super::settings::{
    get_proxmox_settings_from_store, update_proxmox_connection_settings_in_store,
};
use super::tokens::{create_token_with_role, save_proxmox_tokens};
use super::types::{ProxmoxConnectRequest, ProxmoxConnectionInfo, ProxmoxTokenSet, ProxmoxTokensCreateRequest};

/// Create a ProxmoxApiClient with proper TLS settings.
pub(super) fn create_proxmox_client(
    host_uri: Uri,
    skip_tls_verify: bool,
) -> Result<ProxmoxApiClient, String> {
    if skip_tls_verify {
        ProxmoxApiClient::with_options(
            host_uri,
            TlsOptions::Insecure,
            proxmox_http::HttpOptions::default(),
        )
        .map_err(|e| format!("Failed to create Proxmox client: {}", e))
    } else {
        Ok(ProxmoxApiClient::new(host_uri))
    }
}

/// Authenticate with Proxmox using credentials (does not create tokens).
pub(super) async fn authenticate_with_proxmox(
    store: &dyn crate::store::v1::Store,
    host: &str,
    port: i32,
    username: &str,
    password: &str,
    skip_tls_verify: bool,
) -> Result<(), String> {
    let host_url = format!("https://{}:{}", host, port);
    let host_uri = match host_url.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => return Err(format!("Invalid Proxmox URL: {}", e)),
    };

    let client = create_proxmox_client(host_uri, skip_tls_verify)?;

    let login_builder =
        proxmox_login::Login::new(&host_url, username.to_string(), password.to_string());

    match client.login(login_builder).await {
        Ok(None) => {
            info!("Successfully authenticated with Proxmox API");

            match update_proxmox_connection_settings_in_store(
                store,
                host,
                port,
                username,
                skip_tls_verify,
            )
            .await
            {
                Ok(_) => {
                    info!("Proxmox connection settings saved to Store (without storing password)")
                }
                Err(e) => warn!("Failed to save Proxmox settings to Store: {}", e),
            }

            Ok(())
        }
        Ok(Some(_)) => {
            error!("Proxmox login requires Two-Factor Authentication, which is not supported");
            Err("Proxmox authentication requires 2FA which is not supported".to_string())
        }
        Err(e) => {
            error!("Proxmox authentication failed: {}", e);
            Err(format!("Proxmox authentication failed: {}", e))
        }
    }
}

/// Create specialized API tokens with credentials (authenticate + create tokens in one step).
pub async fn generate_proxmox_tokens_with_credentials(
    request: &ProxmoxTokensCreateRequest,
) -> Result<ProxmoxTokenSet, String> {
    info!("Starting token creation process");

    let ProxmoxTokensCreateRequest {
        host,
        port,
        username,
        password,
        skip_tls_verify,
    } = request;

    let host_url = format!("https://{}:{}", host, port);
    let host_uri = match host_url.parse::<Uri>() {
        Ok(uri) => uri,
        Err(e) => return Err(format!("Invalid Proxmox URL: {}", e)),
    };

    let client = create_proxmox_client(host_uri, *skip_tls_verify)?;

    let login_builder =
        proxmox_login::Login::new(&host_url, username.to_string(), password.to_string());

    match client.login(login_builder).await {
        Ok(None) => {
            info!("Successfully authenticated with Proxmox API for token creation");

            // Create custom roles for Dragonfly operations
            info!("Creating custom roles for Dragonfly operations");

            let roles_to_create = [
                (
                    "DragonflyCreate",
                    "Custom role for Dragonfly VM/LXC creation operations",
                ),
                (
                    "DragonflyVMConfig",
                    "Custom role for Dragonfly VM configuration operations",
                ),
                (
                    "DragonflySync",
                    "Custom role for Dragonfly synchronization operations",
                ),
            ];

            for (role_name, _role_description) in roles_to_create.iter() {
                info!("Creating or checking for role: {}", role_name);

                let role_check_path = format!("/api2/json/access/roles/{}", role_name);
                match client.get(&role_check_path).await {
                    Ok(response) => {
                        if response.status == 200 {
                            info!("Role {} already exists, skipping creation", role_name);
                        } else {
                            let role_create_path = "/api2/json/access/roles";
                            let role_params = json!({
                                "roleid": role_name.to_string(),
                                "privs": ""
                            });

                            match client.post(role_create_path, &role_params).await {
                                Ok(response) => {
                                    if response.status == 200 {
                                        info!("Created role {} successfully", role_name);
                                    } else {
                                        warn!(
                                            "Failed to create role {}: Status {}",
                                            role_name, response.status
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!("Error creating role {}: {}", role_name, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error checking if role {} exists: {}", role_name, e);

                        let error_msg = e.to_string();
                        if error_msg.contains("does not exist")
                            || error_msg.contains("404")
                            || error_msg.contains("500")
                        {
                            info!("Role {} doesn't exist, creating it now", role_name);

                            let role_create_path = "/api2/json/access/roles";
                            let role_params = json!({
                                "roleid": role_name.to_string(),
                                "privs": ""
                            });

                            match client.post(role_create_path, &role_params).await {
                                Ok(response) => {
                                    if response.status == 200 {
                                        info!("Created role {} successfully", role_name);
                                    } else {
                                        warn!(
                                            "Failed to create role {}: Status {}",
                                            role_name, response.status
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!("Error creating role {}: {}", role_name, e);
                                }
                            }
                        }
                    }
                }
            }

            // Update roles with proper permissions
            let role_permissions = [
                ("DragonflyCreate", "VM.Allocate,VM.Config.Options,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Config.Network,VM.Config.HWType,VM.PowerMgmt,VM.Console,Datastore.AllocateSpace,Datastore.Audit,SDN.Use,Sys.Audit"),
                ("DragonflyVMConfig", "VM.Config.Options,VM.Config.Disk"),
                (
                    "DragonflySync",
                    "VM.Audit,Sys.Audit,Sys.Modify,SDN.Audit,VM.Config.Options,Datastore.Audit",
                ),
            ];

            for (role_name, permissions) in role_permissions.iter() {
                info!(
                    "Setting permissions for role {}: {}",
                    role_name, permissions
                );

                let update_path = format!("/api2/json/access/roles/{}", role_name);
                let params = json!({
                    "privs": permissions.to_string()
                });

                match client.put(&update_path, &params).await {
                    Ok(response) => {
                        if response.status == 200 {
                            info!("Successfully updated permissions for role {}", role_name);
                        } else {
                            warn!(
                                "Failed to update permissions for role {}: Status {}",
                                role_name, response.status
                            );

                            let response_body = String::from_utf8_lossy(&response.body);
                            if response_body.contains("does not exist") {
                                info!(
                                    "Role {} doesn't exist when updating permissions, creating it now",
                                    role_name
                                );

                                let role_create_path = "/api2/json/access/roles";
                                let role_create_params = json!({
                                    "roleid": role_name.to_string(),
                                    "privs": permissions.to_string()
                                });

                                match client.post(role_create_path, &role_create_params).await {
                                    Ok(create_response) => {
                                        if create_response.status == 200 {
                                            info!(
                                                "Created role {} successfully with permissions",
                                                role_name
                                            );
                                        } else {
                                            warn!(
                                                "Failed to create role {} with permissions: Status {}",
                                                role_name, create_response.status
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Error creating role {} with permissions: {}",
                                            role_name, e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error updating permissions for role {}: {}", role_name, e);

                        let error_msg = e.to_string();
                        if error_msg.contains("does not exist")
                            || error_msg.contains("role not found")
                        {
                            info!(
                                "Role {} doesn't exist when updating permissions, creating it now",
                                role_name
                            );

                            let role_create_path = "/api2/json/access/roles";
                            let role_create_params = json!({
                                "roleid": role_name.to_string(),
                                "privs": permissions.to_string()
                            });

                            match client.post(role_create_path, &role_create_params).await {
                                Ok(create_response) => {
                                    if create_response.status == 200 {
                                        info!(
                                            "Created role {} successfully with permissions",
                                            role_name
                                        );
                                    } else {
                                        warn!(
                                            "Failed to create role {} with permissions: Status {}",
                                            role_name, create_response.status
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Error creating role {} with permissions: {}",
                                        role_name, e
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Create tokens with the custom roles
            let user_part = if username.contains('@') {
                username.to_string()
            } else {
                format!("{}@pam", username)
            };

            info!("Creating VM creation token...");
            let create_token = match create_token_with_role(
                &client,
                &user_part,
                "dragonfly-create",
                "Dragonfly automation token for VM.Create",
                "DragonflyCreate",
            )
            .await
            {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM creation token: {}", e)),
            };

            info!("Creating VM power token...");
            let power_token = match create_token_with_role(
                &client,
                &user_part,
                "dragonfly-power",
                "Dragonfly automation token for VM.PowerMgmt",
                "PVEVMUser",
            )
            .await
            {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM power token: {}", e)),
            };

            info!("Creating VM config token...");
            let config_token = match create_token_with_role(
                &client,
                &user_part,
                "dragonfly-config",
                "Dragonfly automation token for VM.Config.Options",
                "DragonflyVMConfig",
            )
            .await
            {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM config token: {}", e)),
            };

            info!("Creating VM sync token...");
            let sync_token = match create_token_with_role(
                &client,
                &user_part,
                "dragonfly-sync",
                "Dragonfly automation token for VM.Audit Sys.Audit",
                "DragonflySync",
            )
            .await
            {
                Ok(token) => token,
                Err(e) => return Err(format!("Failed to create VM sync token: {}", e)),
            };

            info!("Created tokens for VM operations with appropriate permissions");

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
                },
            })
        }
        Ok(Some(_)) => {
            Err("Proxmox authentication requires 2FA which is not supported".to_string())
        }
        Err(e) => Err(format!("Failed to authenticate with Proxmox: {}", e)),
    }
}

/// Connect to Proxmox API using stored tokens.
pub async fn connect_to_proxmox(
    state: &crate::AppState,
    token_type: &str,
) -> Result<ProxmoxApiClient, anyhow::Error> {
    use crate::encryption::decrypt_string;

    info!(
        "Connecting to Proxmox API for operation type: {}",
        token_type
    );

    let token_key = format!("proxmox_vm_{}_token", token_type);
    let in_memory_token = {
        let tokens = state.tokens.lock().await;
        tokens.get(&token_key).cloned()
    };

    if let Some(token) = in_memory_token {
        info!("Using in-memory token for {} operations", token_type);

        let settings = state.settings.lock().await.clone();
        let host = settings
            .proxmox_host
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Proxmox host not configured"))?;
        let port = settings.proxmox_port.unwrap_or(8006);
        let skip_tls_verify = settings.proxmox_skip_tls_verify.unwrap_or(false);

        let host_url = format!("https://{}:{}", host, port);
        let base_uri = host_url
            .parse::<Uri>()
            .context(format!("Invalid Proxmox URL: {}", host_url))?;

        if let Some(equals_pos) = token.find('=') {
            let token_id = &token[..equals_pos];
            let token_value = &token[equals_pos + 1..];

            let client =
                create_proxmox_client(base_uri, skip_tls_verify).map_err(|e| anyhow::anyhow!(e))?;
            client.set_authentication(ProxmoxToken {
                userid: token_id.to_string(),
                prefix: "PVEAPIToken".to_string(),
                value: token_value.to_string(),
                perl_compat: true,
            });

            info!(
                "Successfully initialized Proxmox client with in-memory API token for {} operations",
                token_type
            );
            return Ok(client);
        }
    }

    let db_settings = match get_proxmox_settings_from_store(state.store.as_ref()).await {
        Ok(Some(settings)) => {
            info!("Found Proxmox settings in Store for host {}", settings.host);
            Some(settings)
        }
        Ok(None) => {
            info!("No Proxmox settings found in Store, checking in-memory settings");
            None
        }
        Err(e) => {
            warn!("Error loading Proxmox settings from Store: {}", e);
            None
        }
    };

    if let Some(settings) = db_settings {
        let host_url = format!("https://{}:{}", settings.host, settings.port);
        let base_uri = host_url
            .parse::<Uri>()
            .context(format!("Invalid Proxmox URL: {}", host_url))?;

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
            match decrypt_string(&encrypted_token) {
                Ok(api_token) => {
                    info!(
                        "Using API token from database for {} operations",
                        token_type
                    );

                    let mut tokens = state.tokens.lock().await;
                    tokens.insert(token_key, api_token.clone());
                    drop(tokens);

                    if let Some(equals_pos) = api_token.find('=') {
                        let token_id = &api_token[..equals_pos];
                        let token_value = &api_token[equals_pos + 1..];

                        let client = create_proxmox_client(base_uri, settings.skip_tls_verify)
                            .map_err(|e| anyhow::anyhow!(e))?;
                        client.set_authentication(ProxmoxToken {
                            userid: token_id.to_string(),
                            prefix: "PVEAPIToken".to_string(),
                            value: token_value.to_string(),
                            perl_compat: true,
                        });

                        info!(
                            "Successfully initialized Proxmox client with API token for {} operations",
                            token_type
                        );
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
            warn!(
                "No API token found for {} operations, and no fallback authentication method available",
                token_type
            );
            return Err(anyhow::anyhow!(
                "No API token found for {} operations. Please go to Settings and reconnect to Proxmox to create the required API tokens.",
                token_type
            ));
        }
    }

    let settings = state.settings.lock().await;

    if settings.proxmox_host.is_some() {
        return Err(anyhow::anyhow!(
            "Proxmox is configured but API tokens are not set up. Please go to Settings and reconnect to Proxmox to create API tokens."
        ));
    }

    Err(anyhow::anyhow!(
        "Proxmox is not configured. Please set up a connection to Proxmox first."
    ))
}

/// Handler for connecting to Proxmox: authenticate, create tokens, then discover.
pub async fn connect_proxmox_handler(
    State(state): State<crate::AppState>,
    Json(request): Json<ProxmoxConnectRequest>,
) -> impl IntoResponse {
    let host = request.host.clone();
    let port = match request.port {
        Some(p) => p,
        None => 8006, // Default Proxmox port
    };

    let username = request.username.clone();
    let password = request.password.clone();

    let skip_tls_verify = request.skip_tls_verify.unwrap_or(false);
    let import_guests = request.import_guests.unwrap_or(false);

    // Check if we already have valid tokens for this host — reuse them if so
    let existing_tokens_valid = {
        let settings = state.settings.lock().await;
        let same_host = settings.proxmox_host.as_deref() == Some(&host)
            && settings.proxmox_port == Some(port as u16);
        drop(settings);

        if same_host {
            match connect_to_proxmox(&state, "sync").await {
                Ok(client) => match client.get("/api2/json/version").await {
                    Ok(_) => {
                        info!("Existing Proxmox tokens for {} are still valid, reusing", host);
                        true
                    }
                    Err(e) => {
                        info!("Existing tokens failed validation ({}), will recreate", e);
                        false
                    }
                },
                Err(_) => false,
            }
        } else {
            false
        }
    };

    if existing_tokens_valid {
        info!("Existing tokens valid but will re-authenticate to update roles/permissions");
    }

    // Full flow: authenticate with provided credentials, create tokens, then discover
    let result = authenticate_with_proxmox(
        state.store.as_ref(),
        &host,
        port as i32,
        &username,
        &password,
        skip_tls_verify,
    )
    .await;

    match result {
        Ok(_) => {
            info!("Successfully authenticated with Proxmox API");

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
                            connect_proxmox_discover(&state, &host, import_guests, false).await
                        }
                        Err(e) => {
                            warn!("Created tokens but failed to save them: {}", e);
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "success": true,
                                    "message": format!("Connected to Proxmox and created tokens, but failed to save: {}", e),
                                    "tokens_created": true,
                                    "tokens_saved": false
                                })),
                            )
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Connected to Proxmox but failed to create API tokens: {}",
                        e
                    );

                    let error_message = if e.contains("Parameter verification failed")
                        || e.contains("privileges")
                        || e.contains("privs")
                    {
                        format!(
                            "Failed to create API tokens: {}. Check Proxmox version and permissions.",
                            e
                        )
                    } else if e.contains("permission")
                        || e.contains("unauthorized")
                        || e.contains("access")
                    {
                        format!(
                            "Failed to create API tokens: {}. Account needs administrative privileges.",
                            e
                        )
                    } else {
                        format!("Failed to create API tokens: {}", e)
                    };

                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "message": format!("Connected to Proxmox but failed to create tokens: {}", e),
                            "tokens_created": false,
                            "token_error": error_message
                        })),
                    )
                }
            }
        }
        Err(e) => {
            error!("Failed to connect to Proxmox: {}", e);

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "message": format!("Failed to connect to Proxmox: {}", e)
                })),
            )
        }
    }
}
