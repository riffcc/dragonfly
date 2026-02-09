use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use proxmox_client::{Client as ProxmoxApiClient, HttpApiClient};
use serde_json::json;
use tracing::{error, info, warn};

use super::client::generate_proxmox_tokens_with_credentials;
use super::settings::{
    get_proxmox_settings_from_store, update_proxmox_connection_settings_in_store,
    update_proxmox_tokens_in_store,
};
use super::types::{ProxmoxTokenSet, ProxmoxTokensCreateRequest};

/// Handler to create Proxmox API tokens.
pub async fn create_proxmox_tokens_handler(
    State(state): State<crate::AppState>,
    Json(request): Json<ProxmoxTokensCreateRequest>,
) -> impl IntoResponse {
    let tokens_result = generate_proxmox_tokens_with_credentials(&request).await;

    match tokens_result {
        Ok(token_set) => match save_proxmox_tokens(&state, token_set).await {
            Ok(_) => {
                info!("Successfully created and saved specialized Proxmox API tokens");

                (
                    StatusCode::OK,
                    Json(json!({
                        "success": true,
                        "message": "Successfully created and saved specialized Proxmox API tokens",
                        "tokens_created": true,
                        "tokens_saved": true
                    })),
                )
            }
            Err(e) => {
                warn!("Successfully created tokens but failed to save them: {}", e);

                (
                    StatusCode::OK,
                    Json(json!({
                        "success": true,
                        "message": format!("Successfully created Proxmox API tokens but failed to save them: {}", e),
                        "tokens_created": true,
                        "tokens_saved": false
                    })),
                )
            }
        },
        Err(e) => {
            error!("Failed to create Proxmox API tokens: {}", e);

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "message": format!("Failed to create Proxmox API tokens: {}", e)
                })),
            )
        }
    }
}

/// Saves Proxmox API tokens to the database for future use.
pub async fn save_proxmox_tokens(
    state: &crate::AppState,
    token_set: ProxmoxTokenSet,
) -> Result<(), anyhow::Error> {
    info!("Saving Proxmox tokens to database");

    use crate::encryption::encrypt_string;

    let encrypted_create_token = encrypt_string(&token_set.create_token)?;
    let encrypted_power_token = encrypt_string(&token_set.power_token)?;
    let encrypted_config_token = encrypt_string(&token_set.config_token)?;
    let encrypted_sync_token = encrypt_string(&token_set.sync_token)?;

    update_proxmox_tokens_in_store(
        state.store.as_ref(),
        encrypted_create_token,
        encrypted_power_token,
        encrypted_config_token,
        encrypted_sync_token,
    )
    .await?;

    update_proxmox_connection_settings_in_store(
        state.store.as_ref(),
        &token_set.connection_info.host,
        token_set.connection_info.port,
        &token_set.connection_info.username,
        token_set.connection_info.skip_tls_verify,
    )
    .await?;

    let mut tokens = state.tokens.lock().await;
    tokens.insert(
        "proxmox_vm_create_token".to_string(),
        token_set.create_token,
    );
    tokens.insert("proxmox_vm_power_token".to_string(), token_set.power_token);
    tokens.insert(
        "proxmox_vm_config_token".to_string(),
        token_set.config_token,
    );
    tokens.insert("proxmox_vm_sync_token".to_string(), token_set.sync_token);
    drop(tokens);

    let mut settings = state.settings.lock().await;
    settings.proxmox_host = Some(token_set.connection_info.host.clone());
    settings.proxmox_port = Some(token_set.connection_info.port as u16);
    settings.proxmox_username = Some(token_set.connection_info.username.clone());
    settings.proxmox_skip_tls_verify = Some(token_set.connection_info.skip_tls_verify);
    drop(settings);

    Ok(())
}

/// Loads Proxmox API tokens from the database and populates the in-memory token store.
pub async fn load_proxmox_tokens_to_memory(state: &crate::AppState) -> Result<(), anyhow::Error> {
    use crate::encryption::decrypt_string;

    info!("Loading Proxmox API tokens from database to memory...");

    let settings = match get_proxmox_settings_from_store(state.store.as_ref()).await {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            info!("No Proxmox settings found in Store, skipping token loading");
            return Ok(());
        }
        Err(e) => {
            warn!("Error loading Proxmox settings from Store: {}", e);
            return Err(anyhow::anyhow!("Failed to load Proxmox settings: {}", e));
        }
    };

    let token_map = [
        ("proxmox_vm_create_token", settings.vm_create_token),
        ("proxmox_vm_power_token", settings.vm_power_token),
        ("proxmox_vm_config_token", settings.vm_config_token),
        ("proxmox_vm_sync_token", settings.vm_sync_token),
    ];

    let mut tokens_loaded = 0;
    let mut tokens = state.tokens.lock().await;

    for (token_key, encrypted_token_opt) in token_map {
        if let Some(encrypted_token) = encrypted_token_opt {
            match decrypt_string(&encrypted_token) {
                Ok(decrypted_token) => {
                    tokens.insert(token_key.to_string(), decrypted_token);
                    tokens_loaded += 1;
                }
                Err(e) => {
                    warn!("Failed to decrypt {} from database: {}", token_key, e);
                }
            }
        }
    }

    drop(tokens);

    {
        let mut app_settings = state.settings.lock().await;
        if app_settings.proxmox_host.is_none() {
            app_settings.proxmox_host = Some(settings.host.clone());
            app_settings.proxmox_port = Some(settings.port as u16);
            app_settings.proxmox_username = Some(settings.username.clone());
            app_settings.proxmox_skip_tls_verify = Some(settings.skip_tls_verify);
            info!(
                "Restored Proxmox connection settings from DB: {}:{}",
                settings.host, settings.port
            );
        }
    }

    info!(
        "Loaded {} Proxmox API tokens from database to memory",
        tokens_loaded
    );
    Ok(())
}

/// Create a single API token with a specific role assignment.
pub(super) async fn create_token_with_role(
    client: &ProxmoxApiClient,
    user: &str,
    token_name: &str,
    description: &str,
    role_name: &str,
) -> Result<String, String> {
    info!("Creating token {}/{}", user, token_name);

    let token_params = json!({
        "comment": description,
        "expire": "0",
        "privsep": "1"
    });

    let token_path = format!("/api2/json/access/users/{}/token/{}", user, token_name);
    info!("Creating API token: {}/{}", user, token_name);

    // Delete existing token if it exists (idempotent recreation)
    let _ = client.delete(&token_path).await;

    match client.post(&token_path, &token_params).await {
        Ok(response) => {
            if response.status == 200 {
                let body_str = String::from_utf8_lossy(&response.body);

                match serde_json::from_str::<serde_json::Value>(&body_str) {
                    Ok(json_val) => {
                        match json_val
                            .get("data")
                            .and_then(|d| d.get("value"))
                            .and_then(|v| v.as_str())
                        {
                            Some(token_value) => {
                                let full_token_id = format!("{}!{}", user, token_name);
                                let full_token = format!("{}={}", full_token_id, token_value);

                                info!(
                                    "Setting ACL for token {} with role {}",
                                    token_name, role_name
                                );
                                let acl_params = json!({
                                    "path": "/",
                                    "propagate": "1",
                                    "roles": role_name,
                                    "tokens": full_token_id
                                });

                                match client.put("/api2/json/access/acl", &acl_params).await {
                                    Ok(acl_response) => {
                                        if acl_response.status == 200 {
                                            Ok(full_token)
                                        } else {
                                            // Try fallback: create role then retry, or use standard role
                                            try_acl_with_fallback(
                                                client,
                                                &acl_params,
                                                &full_token,
                                                &full_token_id,
                                                role_name,
                                            )
                                            .await
                                        }
                                    }
                                    Err(e) => {
                                        Err(format!("Failed to set ACL for token: {}", e))
                                    }
                                }
                            }
                            None => Err("Token value not found in response".to_string()),
                        }
                    }
                    Err(e) => Err(format!("Failed to parse token response: {}", e)),
                }
            } else {
                Err(format!(
                    "Failed to create token: Status {}",
                    response.status
                ))
            }
        }
        Err(e) => Err(format!("Error creating token: {}", e)),
    }
}

/// Try to set ACL with role creation fallback and standard role fallback.
async fn try_acl_with_fallback(
    client: &ProxmoxApiClient,
    acl_params: &serde_json::Value,
    full_token: &str,
    full_token_id: &str,
    role_name: &str,
) -> Result<String, String> {
    info!(
        "ACL with role {} failed, attempting to create role and retry",
        role_name
    );

    // Try to create the role
    let role_create_path = "/api2/json/access/roles";
    let permissions = match role_name {
        "DragonflyCreate" => "VM.Allocate,VM.Config.Options,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Config.Network,VM.Config.HWType,VM.PowerMgmt,VM.Console,Datastore.AllocateSpace,Datastore.Audit,SDN.Use,Sys.Audit",
        "DragonflyVMConfig" => "VM.Config.Options,VM.Config.Disk",
        "DragonflySync" => "VM.Audit,Sys.Audit,Sys.Modify,SDN.Audit,VM.Config.Options,Datastore.Audit",
        _ => "",
    };

    let role_create_params = json!({
        "roleid": role_name.to_string(),
        "privs": permissions
    });

    if let Ok(create_response) = client.post(role_create_path, &role_create_params).await {
        if create_response.status == 200 {
            info!("Created role {} successfully with permissions", role_name);

            if !permissions.is_empty() {
                let update_path = format!("/api2/json/access/roles/{}", role_name);
                let perm_params = json!({ "privs": permissions });
                match client.put(&update_path, &perm_params).await {
                    Ok(_) => info!("Set permissions for new role {}", role_name),
                    Err(e) => warn!(
                        "Failed to set permissions for new role {}: {}",
                        role_name, e
                    ),
                }
            }

            // Retry ACL
            if let Ok(retry_response) =
                client.put("/api2/json/access/acl", acl_params).await
            {
                if retry_response.status == 200 {
                    return Ok(full_token.to_string());
                }
            }
        }
    }

    // Fallback to standard role
    let fallback_role = match role_name {
        "DragonflyCreate" => "PVEVMAdmin",
        "DragonflyVMConfig" => "PVEVMUser",
        "DragonflySync" => "PVEAuditor",
        _ => "PVEVMUser",
    };

    info!("Falling back to standard role: {}", fallback_role);
    let fallback_params = json!({
        "path": "/",
        "propagate": "1",
        "roles": fallback_role,
        "tokens": full_token_id
    });

    match client
        .put("/api2/json/access/acl", &fallback_params)
        .await
    {
        Ok(fallback_response) => {
            if fallback_response.status == 200 {
                info!("Successfully set ACL with fallback role");
                Ok(full_token.to_string())
            } else {
                Err(format!(
                    "Failed to set ACL with fallback role: Status {}",
                    fallback_response.status
                ))
            }
        }
        Err(e) => Err(format!("Error setting ACL with fallback role: {}", e)),
    }
}
