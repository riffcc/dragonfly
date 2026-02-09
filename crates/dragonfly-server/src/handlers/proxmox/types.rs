use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Debug, Clone)]
pub struct DiscoveredProxmox {
    pub host: String,
    pub port: u16,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub machine_type: String,
    pub vmid: Option<u32>,
    pub parent_host: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ProxmoxDiscoverResponse {
    pub machines: Vec<DiscoveredProxmox>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct ProxmoxConnectRequest {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: String,
    pub vm_selection_option: Option<String>,
    pub skip_tls_verify: Option<bool>,
    pub import_guests: Option<bool>,
}

#[derive(Serialize, Debug)]
pub struct ProxmoxConnectResponse {
    pub message: String,
    pub suggest_disable_tls_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_vms: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_vms: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machines: Option<Vec<DiscoveredProxmox>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ProxmoxTokensCreateRequest {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub skip_tls_verify: bool,
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
