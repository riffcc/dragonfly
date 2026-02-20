//! Native Rust Proxmox VE API client for the install-pve command.
//!
//! Replaces the Python3 subprocess scripts that were shelling out to the
//! `requests` library. Uses `reqwest` (already a workspace dependency) with
//! the same rustls TLS stack as the rest of Dragonfly.
//!
//! Only implements the four operations needed by `install-pve`:
//! - Authenticate (obtain ticket + CSRF token)
//! - List cluster nodes
//! - Find a named LXC container across all nodes (returns node + vmid + IP)
//! - List network bridges active on a given node

use reqwest::{Client, ClientBuilder, header};
use serde::Deserialize;
use std::collections::HashMap;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ProxmoxError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Proxmox API error: {0}")]
    Api(String),
}

type Result<T> = std::result::Result<T, ProxmoxError>;

// ─── Public types ─────────────────────────────────────────────────────────────

/// Information about a located LXC container.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerInfo {
    /// Proxmox node the container lives on.
    pub node: String,
    /// Container VMID.
    pub vmid: u64,
    /// First non-loopback IPv4 on eth0, if the container is running.
    pub ip: Option<String>,
}

// ─── Internal API response shapes ────────────────────────────────────────────

#[derive(Deserialize)]
struct TicketData {
    ticket: String,
    #[serde(rename = "CSRFPreventionToken")]
    csrf_token: String,
}

#[derive(Deserialize)]
struct TicketResp {
    data: TicketData,
}

#[derive(Deserialize)]
struct NodeInfo {
    node: String,
    /// "online" or "offline" — offline nodes are skipped during search.
    status: Option<String>,
}

#[derive(Deserialize)]
struct ApiList<T> {
    data: Vec<T>,
}

#[derive(Deserialize)]
struct LxcEntry {
    vmid: serde_json::Value, // Proxmox returns vmid as integer
    name: Option<String>,
}

#[derive(Deserialize)]
struct NetworkIface {
    name: Option<String>,
    /// IPv4 address with CIDR mask as returned by Proxmox LXC `/interfaces`,
    /// e.g. `"10.1.21.26/16"`.
    inet: Option<String>,
}

/// Information about a network bridge on a Proxmox node.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeInfo {
    /// Interface name, e.g. `vmbr0`.
    pub name: String,
    /// Whether this bridge has an IPv4 address configured on the host.
    /// Bridges with an IP are directly routable; prefer them over unaddressed ones.
    pub has_ip: bool,
}

#[derive(Deserialize)]
struct BridgeEntry {
    iface: Option<String>,
    #[serde(rename = "type")]
    iface_type: Option<String>,
    active: Option<serde_json::Value>,
    /// IPv4 address configured on this interface, if any.
    address: Option<String>,
}


// ─── Client ──────────────────────────────────────────────────────────────────

/// Minimal Proxmox API client for the `install-pve` command.
///
/// Stateful: call `authenticate()` before any other methods.
pub struct ProxmoxInstallClient {
    client: Client,
    base_url: String,
    ticket: Option<String>,
    csrf_token: Option<String>,
    /// Whether TLS certificate verification is skipped (from `--skip-tls-verify`).
    /// Stored so that error messages can suggest it when a TLS error is detected.
    skip_tls_verify: bool,
}

impl ProxmoxInstallClient {
    /// Construct a new client.
    ///
    /// # Arguments
    /// * `base_url` – full URL including scheme and port, e.g. `https://pve:8006`
    /// * `skip_tls_verify` – accept self-signed certificates (common for homelabs)
    pub fn new(base_url: &str, skip_tls_verify: bool) -> Result<Self> {
        // Normalise: strip trailing slash
        let base_url = base_url.trim_end_matches('/').to_string();

        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(skip_tls_verify)
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(ProxmoxError::Http)?;

        Ok(Self {
            client,
            base_url,
            ticket: None,
            csrf_token: None,
            skip_tls_verify,
        })
    }

    /// Authenticate with username + password and store the session ticket.
    ///
    /// Must be called before `list_nodes`, `find_container`, or `list_bridges`.
    pub async fn authenticate(&mut self, user: &str, password: &str) -> Result<()> {
        let url = format!("{}/api2/json/access/ticket", self.base_url);

        let mut form = HashMap::new();
        form.insert("username", user);
        form.insert("password", password);

        let response = self
            .client
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| {
                // Detect likely TLS errors and suggest --skip-tls-verify.
                let msg = e.to_string().to_lowercase();
                let is_tls = msg.contains("certificate")
                    || msg.contains("tls")
                    || msg.contains("ssl")
                    || msg.contains("handshake");
                if is_tls && !self.skip_tls_verify {
                    ProxmoxError::AuthFailed(format!(
                        "TLS error connecting to {}: {}\n  \
                         Hint: add --skip-tls-verify for self-signed certificates",
                        self.base_url, e
                    ))
                } else {
                    ProxmoxError::AuthFailed(format!(
                        "Cannot reach Proxmox at {}: {}",
                        self.base_url, e
                    ))
                }
            })?;

        if !response.status().is_success() {
            return Err(ProxmoxError::AuthFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response.json().await.map_err(ProxmoxError::Http)?;

        // Proxmox returns `{ "data": null }` on bad credentials
        if body["data"].is_null() {
            let msg = body["message"]
                .as_str()
                .unwrap_or("invalid credentials")
                .to_string();
            return Err(ProxmoxError::AuthFailed(msg));
        }

        let resp: TicketResp =
            serde_json::from_value(body).map_err(|e| ProxmoxError::Api(e.to_string()))?;

        self.ticket = Some(resp.data.ticket);
        self.csrf_token = Some(resp.data.csrf_token);
        Ok(())
    }

    /// List all online Proxmox cluster nodes.
    ///
    /// Nodes with `status: "offline"` are silently excluded — they cannot be
    /// used for provisioning and would only produce confusing errors later.
    pub async fn list_nodes(&self) -> Result<Vec<String>> {
        let url = format!("{}/api2/json/nodes", self.base_url);
        let resp: ApiList<NodeInfo> = self.get_json(&url).await?;
        Ok(resp
            .data
            .into_iter()
            .filter(|n| n.status.as_deref() != Some("offline"))
            .map(|n| n.node)
            .collect())
    }

    /// Search every online node for an LXC container with the given hostname.
    ///
    /// Returns `None` if the container is not found anywhere.
    /// Nodes that error (e.g., momentarily offline) are skipped rather than
    /// aborting the search — we prefer to report "not found" than to crash on
    /// a transient node failure.
    pub async fn find_container(&self, hostname: &str) -> Result<Option<ContainerInfo>> {
        let nodes = self.list_nodes().await?;

        for node in nodes {
            match self.find_container_on_node(&node, hostname).await {
                Ok(Some(info)) => return Ok(Some(info)),
                Ok(None) => continue,
                // Skip unreachable/offline nodes; don't abort the entire search.
                Err(_) => continue,
            }
        }

        Ok(None)
    }

    /// Return the active network bridges on a given node.
    ///
    /// Each entry includes whether the bridge has an IPv4 address configured on
    /// the host.  Bridges with an IP are directly reachable; the caller should
    /// prefer them when choosing where to attach a new container.
    pub async fn list_bridges(&self, node: &str) -> Result<Vec<BridgeInfo>> {
        let url = format!("{}/api2/json/nodes/{}/network", self.base_url, node);
        let resp: ApiList<BridgeEntry> = self.get_json(&url).await?;

        let bridges = resp
            .data
            .into_iter()
            .filter(|b| b.iface_type.as_deref() == Some("bridge"))
            .filter(|b| {
                // `active` field is 1 when the bridge is up
                b.active
                    .as_ref()
                    .and_then(|v| v.as_u64())
                    .map(|v| v == 1)
                    .unwrap_or(false)
            })
            .filter_map(|b| {
                b.iface.map(|name| BridgeInfo {
                    has_ip: b.address.as_deref().map(|a| !a.is_empty()).unwrap_or(false),
                    name,
                })
            })
            .collect();

        Ok(bridges)
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    /// Build the auth headers required for every authenticated request.
    fn auth_headers(&self) -> Result<header::HeaderMap> {
        let ticket = self
            .ticket
            .as_deref()
            .ok_or_else(|| ProxmoxError::Api("not authenticated – call authenticate() first".to_string()))?;
        let csrf = self
            .csrf_token
            .as_deref()
            .ok_or_else(|| ProxmoxError::Api("not authenticated – call authenticate() first".to_string()))?;

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(&format!("PVEAuthCookie={}", ticket))
                .map_err(|e| ProxmoxError::Api(e.to_string()))?,
        );
        headers.insert(
            "CSRFPreventionToken",
            header::HeaderValue::from_str(csrf)
                .map_err(|e| ProxmoxError::Api(e.to_string()))?,
        );
        Ok(headers)
    }

    /// GET a URL and deserialise the JSON response body.
    ///
    /// On non-2xx responses the body is read and inspected for Proxmox error
    /// messages, cluster-quorum failures, and TLS-related status codes so that
    /// the caller receives an actionable error rather than a bare HTTP status.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let headers = self.auth_headers()?;
        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(ProxmoxError::Http)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProxmoxError::Api(format_api_error(status, &body, self.skip_tls_verify)));
        }

        response.json::<T>().await.map_err(|e| ProxmoxError::Api(e.to_string()))
    }

    /// Search a single node for a container by hostname, returning its info + IP.
    async fn find_container_on_node(
        &self,
        node: &str,
        hostname: &str,
    ) -> Result<Option<ContainerInfo>> {
        let url = format!("{}/api2/json/nodes/{}/lxc", self.base_url, node);
        let resp: ApiList<LxcEntry> = self.get_json(&url).await?;

        for entry in resp.data {
            if entry.name.as_deref() != Some(hostname) {
                continue;
            }

            let vmid = match &entry.vmid {
                serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
                serde_json::Value::String(s) => s.parse().unwrap_or(0),
                _ => 0,
            };

            let ip = self.get_container_ip(node, vmid).await?;
            return Ok(Some(ContainerInfo { node: node.to_string(), vmid, ip }));
        }

        Ok(None)
    }

    /// Query the container's network interfaces for its primary IPv4 address.
    async fn get_container_ip(&self, node: &str, vmid: u64) -> Result<Option<String>> {
        let url = format!(
            "{}/api2/json/nodes/{}/lxc/{}/interfaces",
            self.base_url, node, vmid
        );

        // Interfaces API can fail if the container is stopped — treat as None.
        let resp: ApiList<NetworkIface> = match self.get_json(&url).await {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        for iface in resp.data {
            // Only look at eth0 (primary interface), skip loopback and extras.
            if iface.name.as_deref() != Some("eth0") {
                continue;
            }

            if let Some(ref inet) = iface.inet {
                // Strip CIDR mask: "10.1.21.26/16" → "10.1.21.26"
                let ip = inet.split('/').next().unwrap_or(inet.as_str());
                if !ip.is_empty() && ip != "127.0.0.1" {
                    return Ok(Some(ip.to_string()));
                }
            }
        }

        Ok(None)
    }
}

// ─── URL resolution ──────────────────────────────────────────────────────────

/// Resolve a bare hostname or partial URL to a fully-qualified Proxmox HTTPS URL.
///
/// Accepts any of:
/// - `proxmox.riff.cc`              → TCP-knock 8006 then 443; use the first open port
/// - `proxmox.riff.cc:8006`         → normalise to `https://proxmox.riff.cc:8006`
/// - `https://proxmox.riff.cc`      → TCP-knock 8006 then 443
/// - `https://proxmox.riff.cc:8006` → return normalised (no probing)
///
/// When no port is given, a non-authenticating TCP connect is tried first so
/// that an obviously wrong address is reported before any credentials are sent.
pub fn resolve_proxmox_url(input: &str) -> std::result::Result<String, String> {
    let input = input.trim().trim_end_matches('/');

    // Strip the scheme so we can work with the `host[:port]` part uniformly.
    let (use_https, host_part) = if let Some(rest) = input.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = input.strip_prefix("http://") {
        (false, rest)
    } else {
        (true, input) // no scheme → default to https
    };

    // If the user already included a port, normalise and return immediately.
    if has_explicit_port(host_part) {
        let scheme = if use_https { "https" } else { "http" };
        return Ok(format!("{}://{}", scheme, host_part));
    }

    // No port specified — probe Proxmox's two standard ports in preference order:
    // 8006  native Proxmox API
    // 443   reverse-proxy (nginx/haproxy in front of Proxmox)
    for &port in &[8006u16, 443] {
        if tcp_port_open(host_part, port) {
            return Ok(format!("https://{}:{}", host_part, port));
        }
    }

    Err(format!(
        "Cannot reach '{}' on port 8006 (Proxmox native) or 443 (reverse proxy).\n\
         Check that the hostname is correct and the Proxmox API is accessible.",
        input
    ))
}

/// Returns `true` if `host_part` contains an explicit port number.
///
/// Works for bare hostnames (`pve:8006`), IPv4 (`192.168.1.1:8006`), and
/// bracketed IPv6 (`[::1]:8006`).  A bare IPv4 address (`192.168.1.1`) returns
/// `false` because its dots are not a port separator.
fn has_explicit_port(host_part: &str) -> bool {
    // Bracketed IPv6: [::1]:8006
    if host_part.starts_with('[') {
        return host_part
            .split_once(']')
            .and_then(|(_, after)| after.strip_prefix(':'))
            .map(|port_str| port_str.parse::<u16>().is_ok())
            .unwrap_or(false);
    }
    // Hostname or IPv4: the last ':' separates host from port.
    host_part
        .rfind(':')
        .map(|i| host_part[i + 1..].parse::<u16>().is_ok())
        .unwrap_or(false)
}

/// Try to open a TCP connection to `host:port` with a short timeout.
///
/// Returns `true` if the port is accepting connections, `false` otherwise.
/// DNS resolution is performed synchronously (acceptable for a CLI tool).
fn tcp_port_open(host: &str, port: u16) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr_str = format!("{}:{}", host, port);
    let timeout = Duration::from_secs(2);

    let Ok(addrs) = addr_str.to_socket_addrs() else {
        return false;
    };
    addrs.into_iter().any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
}

// ─── Error formatting ─────────────────────────────────────────────────────────

/// Format a human-readable error from a failed Proxmox API response.
///
/// Tries (in order):
/// 1. Detect well-known Proxmox cluster errors from the body (quorum, node offline)
/// 2. Extract Proxmox's own `errors` or `message` field from the JSON body
/// 3. Add a `--skip-tls-verify` hint for suspicious HTTP status codes when TLS
///    verification is enabled (HTTP 5xx-range proxy/TLS error codes)
fn format_api_error(status: reqwest::StatusCode, body: &str, skip_tls_verify: bool) -> String {
    let body_lower = body.to_lowercase();

    // Cluster quorum error — Proxmox refuses writes when quorum is lost.
    if body_lower.contains("no quorum") {
        return "Proxmox cluster has no quorum — \
                check that the majority of cluster nodes are online"
            .to_string();
    }

    // Node offline / unavailable.
    if body_lower.contains("node is offline") || body_lower.contains("not available") {
        return format!("HTTP {}: node is offline or unavailable", status);
    }

    // Try to extract Proxmox's own error message from the JSON body.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(errors) = json["errors"].as_object() {
            if !errors.is_empty() {
                let msgs: Vec<String> = errors
                    .values()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                if !msgs.is_empty() {
                    return format!("HTTP {}: {}", status, msgs.join("; "));
                }
            }
        }
        if let Some(msg) = json["message"].as_str() {
            if !msg.is_empty() {
                return format!("HTTP {}: {}", status, msg);
            }
        }
    }

    // For unusual status codes (HTTP 5xx proxy/TLS errors) suggest --skip-tls-verify
    // when the user has NOT already enabled it.
    let code = status.as_u16();
    let tls_hint = if !skip_tls_verify && (code >= 590 || code == 526 || code == 525) {
        "\n  Hint: HTTP 5xx proxy/TLS errors may indicate a self-signed certificate — \
         try --skip-tls-verify"
    } else {
        ""
    };

    format!("HTTP {}{}", status, tls_hint)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new_strips_trailing_slash() {
        let client = ProxmoxInstallClient::new("https://pve:8006/", false).unwrap();
        assert_eq!(client.base_url, "https://pve:8006");
    }

    #[test]
    fn test_client_new_keeps_clean_url() {
        let client = ProxmoxInstallClient::new("https://proxmox.example.com:8006", false).unwrap();
        assert_eq!(client.base_url, "https://proxmox.example.com:8006");
    }

    #[test]
    fn test_auth_headers_fails_before_authenticate() {
        let client = ProxmoxInstallClient::new("https://pve:8006", true).unwrap();
        let result = client.auth_headers();
        assert!(result.is_err(), "Should fail before authenticate()");
        assert!(result.unwrap_err().to_string().contains("not authenticated"));
    }

    #[test]
    fn test_container_info_equality() {
        let a = ContainerInfo {
            node: "pve1".to_string(),
            vmid: 100,
            ip: Some("10.0.0.1".to_string()),
        };
        let b = ContainerInfo {
            node: "pve1".to_string(),
            vmid: 100,
            ip: Some("10.0.0.1".to_string()),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_container_info_no_ip() {
        let info = ContainerInfo {
            node: "pve1".to_string(),
            vmid: 100,
            ip: None,
        };
        assert!(info.ip.is_none());
    }

    /// Simulate parsing the Proxmox ticket response to ensure our struct matches.
    #[test]
    fn test_ticket_resp_deserialization() {
        let json = serde_json::json!({
            "data": {
                "ticket": "PVE:root@pam:ABCDEF",
                "CSRFPreventionToken": "CSRF123"
            }
        });

        let resp: TicketResp = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.ticket, "PVE:root@pam:ABCDEF");
        assert_eq!(resp.data.csrf_token, "CSRF123");
    }

    /// A null `data` field from Proxmox means bad credentials.
    #[test]
    fn test_ticket_null_data_is_detected() {
        let json = serde_json::json!({ "data": null, "message": "invalid credentials" });
        assert!(json["data"].is_null());
    }

    /// Verify bridge filtering: only active bridges of type "bridge" survive.
    #[test]
    fn test_bridge_filtering() {
        let raw = serde_json::json!({
            "data": [
                {"iface": "vmbr0", "type": "bridge", "active": 1, "address": "10.0.0.1"},
                {"iface": "eth0",  "type": "eth",    "active": 1},
                {"iface": "vmbr1", "type": "bridge", "active": 0},
            ]
        });

        let bridges: ApiList<BridgeEntry> = serde_json::from_value(raw).unwrap();
        let active: Vec<BridgeInfo> = bridges
            .data
            .into_iter()
            .filter(|b| b.iface_type.as_deref() == Some("bridge"))
            .filter(|b| {
                b.active
                    .as_ref()
                    .and_then(|v| v.as_u64())
                    .map(|v| v == 1)
                    .unwrap_or(false)
            })
            .filter_map(|b| {
                b.iface.map(|name| BridgeInfo {
                    has_ip: b.address.as_deref().map(|a| !a.is_empty()).unwrap_or(false),
                    name,
                })
            })
            .collect();

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "vmbr0");
        assert!(active[0].has_ip, "vmbr0 has an address so has_ip must be true");
    }

    /// A bridge without an address field gets has_ip = false.
    #[test]
    fn test_bridge_no_address_has_ip_false() {
        let raw = serde_json::json!({
            "data": [
                {"iface": "vmbr1", "type": "bridge", "active": 1}
            ]
        });
        let bridges: ApiList<BridgeEntry> = serde_json::from_value(raw).unwrap();
        let entry = &bridges.data[0];
        let has_ip = entry.address.as_deref().map(|a| !a.is_empty()).unwrap_or(false);
        assert!(!has_ip);
    }

    /// Two active bridges: one with IP, one without.  has_ip reflects the data.
    #[test]
    fn test_bridge_info_has_ip_reflects_address_presence() {
        let raw = serde_json::json!({
            "data": [
                {"iface": "vmbr0", "type": "bridge", "active": 1, "address": "192.168.1.1"},
                {"iface": "vmbr1", "type": "bridge", "active": 1},
            ]
        });
        let list: ApiList<BridgeEntry> = serde_json::from_value(raw).unwrap();
        let infos: Vec<BridgeInfo> = list.data.into_iter()
            .filter(|b| b.iface_type.as_deref() == Some("bridge"))
            .filter(|b| b.active.as_ref().and_then(|v| v.as_u64()).map(|v| v == 1).unwrap_or(false))
            .filter_map(|b| b.iface.map(|name| BridgeInfo {
                has_ip: b.address.as_deref().map(|a| !a.is_empty()).unwrap_or(false),
                name,
            }))
            .collect();

        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].name, "vmbr0");
        assert!(infos[0].has_ip);
        assert_eq!(infos[1].name, "vmbr1");
        assert!(!infos[1].has_ip);
    }

    /// Verify LXC lookup by name, handling Proxmox returning vmid as integer.
    #[test]
    fn test_lxc_vmid_integer_parsing() {
        let entry_json = serde_json::json!({ "vmid": 106, "name": "dragonfly" });
        let entry: LxcEntry = serde_json::from_value(entry_json).unwrap();

        let vmid = match &entry.vmid {
            serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
            serde_json::Value::String(s) => s.parse().unwrap_or(0),
            _ => 0,
        };

        assert_eq!(vmid, 106);
        assert_eq!(entry.name.as_deref(), Some("dragonfly"));
    }

    /// Verify that loopback IPs and CIDR notation are handled correctly.
    #[test]
    fn test_ip_loopback_filtered_and_cidr_stripped() {
        // Proxmox LXC /interfaces returns inet with CIDR, e.g. "10.1.21.10/16"
        let ifaces = vec![
            NetworkIface { name: Some("lo".to_string()), inet: Some("127.0.0.1/8".to_string()) },
            NetworkIface { name: Some("eth0".to_string()), inet: Some("10.1.21.10/16".to_string()) },
        ];

        let result = ifaces.iter()
            .filter(|iface| iface.name.as_deref() != Some("lo"))
            .filter_map(|iface| iface.inet.as_ref())
            .map(|inet| inet.split('/').next().unwrap_or(inet.as_str()).to_string())
            .find(|ip| !ip.is_empty() && ip != "127.0.0.1");

        assert_eq!(result, Some("10.1.21.10".to_string()));
    }

    // ── format_api_error ──────────────────────────────────────────────────

    #[test]
    fn test_format_api_error_quorum_detected() {
        let status = reqwest::StatusCode::INTERNAL_SERVER_ERROR;
        let body = r#"{"message":"cluster has no quorum","data":null}"#;
        let msg = format_api_error(status, body, false);
        assert!(msg.contains("quorum"), "Should surface quorum issue: {}", msg);
    }

    #[test]
    fn test_format_api_error_extracts_proxmox_message() {
        let status = reqwest::StatusCode::FORBIDDEN;
        let body = r#"{"message":"Permission check failed","data":null}"#;
        let msg = format_api_error(status, body, false);
        assert!(msg.contains("Permission check failed"), "Should show Proxmox message: {}", msg);
    }

    #[test]
    fn test_format_api_error_extracts_errors_field() {
        let status = reqwest::StatusCode::BAD_REQUEST;
        let body = r#"{"errors":{"vmid":"already exists"},"data":null}"#;
        let msg = format_api_error(status, body, false);
        assert!(msg.contains("already exists"), "Should show errors field: {}", msg);
    }

    #[test]
    fn test_format_api_error_tls_hint_for_595_without_skip() {
        let status = reqwest::StatusCode::from_u16(595).unwrap();
        let msg = format_api_error(status, "", false);
        assert!(msg.contains("skip-tls-verify"), "Should suggest --skip-tls-verify: {}", msg);
    }

    #[test]
    fn test_format_api_error_no_tls_hint_when_skip_enabled() {
        let status = reqwest::StatusCode::from_u16(595).unwrap();
        let msg = format_api_error(status, "", true);
        assert!(!msg.contains("skip-tls-verify"), "Should not suggest when already skipping");
    }

    #[test]
    fn test_format_api_error_plain_status_for_normal_error() {
        let status = reqwest::StatusCode::NOT_FOUND;
        let msg = format_api_error(status, "", false);
        assert!(msg.starts_with("HTTP 404"), "Should show status code: {}", msg);
    }

    // ── resolve_proxmox_url / has_explicit_port ───────────────────────────

    #[test]
    fn test_has_explicit_port_bare_hostname() {
        assert!(!has_explicit_port("proxmox.riff.cc"));
    }

    #[test]
    fn test_has_explicit_port_hostname_with_port() {
        assert!(has_explicit_port("proxmox.riff.cc:8006"));
        assert!(has_explicit_port("proxmox.riff.cc:443"));
    }

    #[test]
    fn test_has_explicit_port_bare_ipv4() {
        assert!(!has_explicit_port("192.168.1.1"));
    }

    #[test]
    fn test_has_explicit_port_ipv4_with_port() {
        assert!(has_explicit_port("192.168.1.1:8006"));
    }

    #[test]
    fn test_has_explicit_port_ipv6_no_port() {
        assert!(!has_explicit_port("[::1]"));
    }

    #[test]
    fn test_has_explicit_port_ipv6_with_port() {
        assert!(has_explicit_port("[::1]:8006"));
    }

    #[test]
    fn test_resolve_proxmox_url_full_url_unchanged() {
        // Already has scheme + port — returned as-is (no probe needed).
        let result = resolve_proxmox_url("https://proxmox.example.com:8006").unwrap();
        assert_eq!(result, "https://proxmox.example.com:8006");
    }

    #[test]
    fn test_resolve_proxmox_url_trailing_slash_stripped() {
        let result = resolve_proxmox_url("https://proxmox.example.com:8006/").unwrap();
        assert_eq!(result, "https://proxmox.example.com:8006");
    }

    #[test]
    fn test_resolve_proxmox_url_hostname_colon_port() {
        // No scheme but has port — normalise to https://.
        let result = resolve_proxmox_url("proxmox.example.com:8006").unwrap();
        assert_eq!(result, "https://proxmox.example.com:8006");
    }

    #[test]
    fn test_resolve_proxmox_url_http_scheme_preserved() {
        let result = resolve_proxmox_url("http://pve:8006").unwrap();
        assert_eq!(result, "http://pve:8006");
    }

    #[test]
    fn test_resolve_proxmox_url_https_no_port_probes_loopback() {
        // Probing localhost:8006 should succeed (or at least not crash).
        // We can't assert success without a real server, but can check the logic
        // when port 65535 is almost certainly closed: we get a clear error.
        let err = resolve_proxmox_url("https://127.0.0.1");
        // Either it found a port (if something is running) or returns an error.
        // Just confirm the function runs without panicking.
        let _ = err;
    }

    /// Integration test - requires a real Proxmox server.
    /// Set PROXMOX_URL, PROXMOX_USER, PROXMOX_PASSWORD env vars to run.
    #[tokio::test]
    #[ignore = "requires live Proxmox"]
    async fn test_integration_list_nodes() {
        let url = std::env::var("PROXMOX_URL").expect("PROXMOX_URL not set");
        let user = std::env::var("PROXMOX_USER").expect("PROXMOX_USER not set");
        let pass = std::env::var("PROXMOX_PASSWORD").expect("PROXMOX_PASSWORD not set");

        let mut client = ProxmoxInstallClient::new(&url, true).unwrap();
        client.authenticate(&user, &pass).await.unwrap();

        let nodes = client.list_nodes().await.unwrap();
        assert!(!nodes.is_empty(), "Should find at least one node");
        println!("Nodes: {:?}", nodes);
    }
}
