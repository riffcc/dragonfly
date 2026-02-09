use super::types::ProxmoxSettings;

pub(super) const PROXMOX_SETTINGS_KEY: &str = "proxmox_settings";

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
pub(super) async fn get_proxmox_settings_from_store(
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
pub(super) async fn put_proxmox_settings_to_store(
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
pub(super) async fn update_proxmox_connection_settings_in_store(
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
pub(super) async fn update_proxmox_tokens_in_store(
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
