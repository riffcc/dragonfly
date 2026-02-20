//! MCP (Model Context Protocol) server for Dragonfly.
//!
//! Exposes Dragonfly's entire API as a **single MCP tool** with action-based
//! dispatch. This keeps the MCP tool list minimal (one entry) while providing
//! full coverage via `action` + `params`.
//!
//! Communicates over stdio (JSON-RPC). Logging goes to stderr.

use clap::Parser;
use reqwest::Client;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

/// CLI arguments for the `mcp` subcommand.
#[derive(Parser, Debug)]
pub struct McpArgs {
    /// Dragonfly server URL
    #[arg(long, env = "DRAGONFLY_URL", default_value = "http://localhost:3000")]
    pub url: String,

    /// API token for Bearer authentication
    #[arg(long, env = "DRAGONFLY_TOKEN", default_value = "")]
    pub token: String,
}

/// Shared HTTP client for the Dragonfly REST API.
struct ApiClient {
    http: Client,
    base_url: String,
    token: String,
}

impl ApiClient {
    fn new(base_url: String, token: String) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/api{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        req
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }

    fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::PUT, path)
    }

    fn patch(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::PATCH, path)
    }

    fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::DELETE, path)
    }
}

/// The Dragonfly MCP server — one tool to rule them all.
#[derive(Clone)]
pub struct DragonflyMcp {
    api: Arc<ApiClient>,
    tool_router: ToolRouter<DragonflyMcp>,
}

// ─── Single tool parameter ─────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DragonflyParams {
    /// The action to perform. Use "help" for a full manual.
    #[schemars(description = "Action to perform. Examples: help, machines.list, machines.get, networks.list, dhcp.leases, settings.get, tags.list. Use 'help' for the full manual.")]
    pub action: String,

    /// Action-specific parameters as a JSON object. See 'help' for details.
    #[schemars(description = "Action parameters (JSON object). Required fields depend on the action — use 'help' for details.")]
    pub params: Option<Value>,
}

// ─── Help text ──────────────────────────────────────────────────────

const HELP_TEXT: &str = r#"# Dragonfly MCP — Action Reference

## Machines
  machines.list      {detail?, page?, per_page?}
      detail: "simple" (id/hostname/ip/status/tags, ~50 tok/machine, default 80/page)
              "standard" (default — + cpu/ram/os/proxmox, ~150 tok, 25/page)
              "full" (everything incl disks/interfaces/gpus, ~400 tok, 10/page)
      Pages calibrated to ~4k tokens. Max per_page ~20k tokens worth.
  machines.get        {id}               — Get machine details
  machines.register   {body}             — Register a new machine (POST body)
  machines.update     {id, body}         — Update machine fields (PATCH body)
  machines.delete     {id}               — Delete a machine
  machines.assign-os  {id, os}           — Assign OS template for provisioning
  machines.reimage    {id}               — Wipe and reinstall (DANGEROUS)
  machines.abort-reimage {id}            — Cancel a pending reimage
  machines.power      {id, action}       — BMC power: on, off, reset, cycle
  machines.set-hostname {id, hostname}   — Set machine hostname
  machines.status     {id}               — Get machine status and progress
  machines.tags       {id}               — Get tags for a machine
  machines.set-tags   {id, tags}         — Set tags (array of strings)

## Networks
  networks.list                          — List all networks
  networks.get        {id}               — Get network details
  networks.create     {body}             — Create a network (POST body)
  networks.update     {id, body}         — Update network (PATCH body)
  networks.delete     {id}               — Delete a network

## DHCP
  dhcp.leases                            — List all active DHCP leases
  dhcp.release        {mac}              — Release a DHCP lease by MAC

## DNS
  dns.zones                              — List all DNS zones
  dns.records         {zone}             — List records in a zone
  dns.create-record   {zone, body}       — Create a DNS record
  dns.update-record   {zone, id, body}   — Update a DNS record
  dns.delete-record   {zone, id}         — Delete a DNS record

## Templates
  templates.list                         — List available OS templates
  templates.get       {name}             — Get template details
  templates.toggle    {name}             — Enable/disable a template

## Settings
  settings.get                           — Get all settings
  settings.update     {body}             — Update settings (PUT body)
  settings.mode                          — Get deployment mode

## Tags
  tags.list                              — List all tags
  tags.create         {body}             — Create a tag
  tags.delete         {name}             — Delete a tag
  tags.machines       {name}             — List machines with a tag

## Credentials
  credentials.list                       — List stored credentials
  credentials.add     {body}             — Add a credential
  credentials.rotate  {id}               — Rotate a credential
  credentials.delete  {id}               — Delete a credential

## Cluster
  cluster.status                         — Get cluster status

## Tokens
  tokens.list                            — List API tokens (metadata only)
  tokens.create       {body}             — Create an API token
  tokens.rotate       {id}               — Rotate: revoke old, create new with same name
  tokens.revoke       {id}               — Revoke an API token

## Parameter Notes
- {id} = UUID string
- {body} = JSON object passed directly as the request body
- {os} = template name, e.g. "debian-12", "ubuntu-24.04"
- {action} = power action string: "on", "off", "reset", "cycle"
- {mac} = MAC address string, e.g. "aa:bb:cc:dd:ee:ff"
- {zone} = DNS zone name, e.g. "example.com"
- {name} = resource name string
- {tags} = array of tag name strings
"#;

// ─── Tool implementation ────────────────────────────────────────────

#[tool_router]
impl DragonflyMcp {
    pub fn new(api: Arc<ApiClient>) -> Self {
        Self {
            api,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Dragonfly bare metal management. One tool for everything: machines, networks, DHCP, DNS, templates, settings, tags, credentials, cluster, tokens. Use action='help' for the full manual.")]
    async fn dragonfly(
        &self,
        Parameters(p): Parameters<DragonflyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let params = p.params.unwrap_or(Value::Null);
        self.dispatch(&p.action, &params).await
    }
}

impl DragonflyMcp {
    /// Central action dispatcher.
    async fn dispatch(&self, action: &str, params: &Value) -> Result<CallToolResult, ErrorData> {
        match action {
            "help" => Ok(CallToolResult::success(vec![Content::text(HELP_TEXT)])),

            // ── Machines ────────────────────────────────────────
            "machines.list" => {
                let detail = params.get("detail").and_then(|v| v.as_str());
                let page = u64_param_opt(params, "page");
                let per_page = u64_param_opt(params, "per_page");
                let mut qparams = Vec::new();
                if let Some(d) = detail {
                    qparams.push(format!("detail={d}"));
                }
                if let Some(p) = page {
                    qparams.push(format!("page={p}"));
                }
                if let Some(pp) = per_page {
                    qparams.push(format!("per_page={pp}"));
                }
                let path = if qparams.is_empty() {
                    "/machines".to_string()
                } else {
                    format!("/machines?{}", qparams.join("&"))
                };
                self.api_get(&path).await
            }
            "machines.get" => {
                let id = str_param(params, "id")?;
                self.api_get(&format!("/machines/{id}")).await
            }
            "machines.register" => {
                let body = obj_param(params, "body")?;
                self.api_post_json("/machines", &body).await
            }
            "machines.update" => {
                let id = str_param(params, "id")?;
                let body = obj_param(params, "body")?;
                self.api_patch_json(&format!("/machines/{id}"), &body).await
            }
            "machines.delete" => {
                let id = str_param(params, "id")?;
                self.api_delete(&format!("/machines/{id}")).await
            }
            "machines.assign-os" => {
                let id = str_param(params, "id")?;
                let os = str_param(params, "os")?;
                self.api_post_json(
                    &format!("/machines/{id}/os"),
                    &serde_json::json!({"os": os}),
                )
                .await
            }
            "machines.reimage" => {
                let id = str_param(params, "id")?;
                self.api_post_empty(&format!("/machines/{id}/reimage")).await
            }
            "machines.abort-reimage" => {
                let id = str_param(params, "id")?;
                self.api_post_empty(&format!("/machines/{id}/abort-reimage"))
                    .await
            }
            "machines.power" => {
                let id = str_param(params, "id")?;
                let power_action = str_param(params, "action")?;
                self.api_post_json(
                    &format!("/machines/{id}/bmc/power-action"),
                    &serde_json::json!({"action": power_action}),
                )
                .await
            }
            "machines.set-hostname" => {
                let id = str_param(params, "id")?;
                let hostname = str_param(params, "hostname")?;
                self.api_put_json(
                    &format!("/machines/{id}/hostname"),
                    &serde_json::json!({"hostname": hostname}),
                )
                .await
            }
            "machines.status" => {
                let id = str_param(params, "id")?;
                self.api_get(&format!("/machines/{id}/status-and-progress"))
                    .await
            }
            "machines.tags" => {
                let id = str_param(params, "id")?;
                self.api_get(&format!("/machines/{id}/tags")).await
            }
            "machines.set-tags" => {
                let id = str_param(params, "id")?;
                let tags = params
                    .get("tags")
                    .ok_or_else(|| missing_param("tags"))?
                    .clone();
                self.api_put_json(&format!("/machines/{id}/tags"), &tags)
                    .await
            }

            // ── Networks ────────────────────────────────────────
            "networks.list" => self.api_get("/networks").await,
            "networks.get" => {
                let id = str_param(params, "id")?;
                self.api_get(&format!("/networks/{id}")).await
            }
            "networks.create" => {
                let body = obj_param(params, "body")?;
                self.api_post_json("/networks", &body).await
            }
            "networks.update" => {
                let id = str_param(params, "id")?;
                let body = obj_param(params, "body")?;
                self.api_patch_json(&format!("/networks/{id}"), &body).await
            }
            "networks.delete" => {
                let id = str_param(params, "id")?;
                self.api_delete(&format!("/networks/{id}")).await
            }

            // ── DHCP ────────────────────────────────────────────
            "dhcp.leases" => self.api_get("/dhcp/leases").await,
            "dhcp.release" => {
                let mac = str_param(params, "mac")?;
                self.api_delete(&format!("/dhcp/leases/{mac}")).await
            }

            // ── DNS ─────────────────────────────────────────────
            "dns.zones" => self.api_get("/dns/zones").await,
            "dns.records" => {
                let zone = str_param(params, "zone")?;
                self.api_get(&format!("/dns/zones/{zone}/records")).await
            }
            "dns.create-record" => {
                let zone = str_param(params, "zone")?;
                let body = obj_param(params, "body")?;
                self.api_post_json(&format!("/dns/zones/{zone}/records"), &body)
                    .await
            }
            "dns.update-record" => {
                let zone = str_param(params, "zone")?;
                let id = str_param(params, "id")?;
                let body = obj_param(params, "body")?;
                self.api_put_json(&format!("/dns/zones/{zone}/records/{id}"), &body)
                    .await
            }
            "dns.delete-record" => {
                let zone = str_param(params, "zone")?;
                let id = str_param(params, "id")?;
                self.api_delete(&format!("/dns/zones/{zone}/records/{id}"))
                    .await
            }

            // ── Templates ───────────────────────────────────────
            "templates.list" => self.api_get("/templates").await,
            "templates.get" => {
                let name = str_param(params, "name")?;
                self.api_get(&format!("/templates/{name}")).await
            }
            "templates.toggle" => {
                let name = str_param(params, "name")?;
                self.api_post_empty(&format!("/templates/{name}/toggle"))
                    .await
            }

            // ── Settings ────────────────────────────────────────
            "settings.get" => self.api_get("/settings").await,
            "settings.update" => {
                let body = obj_param(params, "body")?;
                self.api_put_json("/settings", &body).await
            }
            "settings.mode" => self.api_get("/settings/mode").await,

            // ── Tags ────────────────────────────────────────────
            "tags.list" => self.api_get("/tags").await,
            "tags.create" => {
                let body = obj_param(params, "body")?;
                self.api_post_json("/tags", &body).await
            }
            "tags.delete" => {
                let name = str_param(params, "name")?;
                self.api_delete(&format!("/tags/{name}")).await
            }
            "tags.machines" => {
                let name = str_param(params, "name")?;
                self.api_get(&format!("/tags/{name}/machines")).await
            }

            // ── Credentials ─────────────────────────────────────
            "credentials.list" => self.api_get("/credentials").await,
            "credentials.add" => {
                let body = obj_param(params, "body")?;
                self.api_post_json("/credentials/add", &body).await
            }
            "credentials.rotate" => {
                let id = str_param(params, "id")?;
                self.api_post_empty(&format!("/credentials/{id}/rotate"))
                    .await
            }
            "credentials.delete" => {
                let id = str_param(params, "id")?;
                self.api_delete(&format!("/credentials/{id}")).await
            }

            // ── Cluster ─────────────────────────────────────────
            "cluster.status" => self.api_get("/cluster/status").await,

            // ── Tokens ──────────────────────────────────────────
            "tokens.list" => self.api_get("/tokens").await,
            "tokens.create" => {
                let body = obj_param(params, "body")?;
                self.api_post_json("/tokens", &body).await
            }
            "tokens.rotate" => {
                let id = str_param(params, "id")?;
                self.api_post_empty(&format!("/tokens/{id}/rotate")).await
            }
            "tokens.revoke" => {
                let id = str_param(params, "id")?;
                self.api_delete(&format!("/tokens/{id}")).await
            }

            _ => Err(ErrorData::invalid_params(
                format!("Unknown action: \"{action}\". Use action=\"help\" for available actions."),
                None,
            )),
        }
    }

    // ── HTTP helpers ────────────────────────────────────────────────

    async fn api_get(&self, path: &str) -> Result<CallToolResult, ErrorData> {
        let resp = self.api.get(path).send().await.map_err(api_err)?;
        let body = resp.text().await.map_err(api_err)?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }

    async fn api_post_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<CallToolResult, ErrorData> {
        let resp = self
            .api
            .post(path)
            .json(body)
            .send()
            .await
            .map_err(api_err)?;
        let text = resp.text().await.map_err(api_err)?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    async fn api_post_empty(&self, path: &str) -> Result<CallToolResult, ErrorData> {
        let resp = self.api.post(path).send().await.map_err(api_err)?;
        let body = resp.text().await.map_err(api_err)?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }

    async fn api_put_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<CallToolResult, ErrorData> {
        let resp = self
            .api
            .put(path)
            .json(body)
            .send()
            .await
            .map_err(api_err)?;
        let text = resp.text().await.map_err(api_err)?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    async fn api_patch_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<CallToolResult, ErrorData> {
        let resp = self
            .api
            .patch(path)
            .json(body)
            .send()
            .await
            .map_err(api_err)?;
        let text = resp.text().await.map_err(api_err)?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    async fn api_delete(&self, path: &str) -> Result<CallToolResult, ErrorData> {
        let resp = self.api.delete(path).send().await.map_err(api_err)?;
        let body = resp.text().await.map_err(api_err)?;
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }
}

// ─── Param extraction helpers ───────────────────────────────────────

/// Extract an optional u64 from a JSON value that could be a number or a string.
fn u64_param_opt(params: &Value, key: &str) -> Option<u64> {
    params.get(key).and_then(|v| {
        v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}

fn str_param(params: &Value, key: &str) -> Result<String, ErrorData> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| missing_param(key))
}

fn obj_param(params: &Value, key: &str) -> Result<Value, ErrorData> {
    // If key is "body" and the params IS the body (no wrapper), use it directly.
    match params.get(key) {
        Some(v) if v.is_object() || v.is_array() => Ok(v.clone()),
        _ if key == "body" && params.is_object() && !params.as_object().unwrap().is_empty() => {
            // The caller passed the body fields directly in params — use the whole thing.
            Ok(params.clone())
        }
        _ => Err(missing_param(key)),
    }
}

fn missing_param(key: &str) -> ErrorData {
    ErrorData::invalid_params(
        format!("Missing required parameter: \"{key}\". Use action=\"help\" for usage."),
        None,
    )
}

/// Convert a reqwest error into an MCP ErrorData.
fn api_err(e: impl std::fmt::Display) -> ErrorData {
    ErrorData::internal_error(format!("Dragonfly API error: {e}"), None)
}

// ─── ServerHandler trait ────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for DragonflyMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "dragonfly".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("Dragonfly".to_string()),
                description: Some("Bare metal infrastructure management".to_string()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "Dragonfly bare metal management. Single tool with action-based dispatch. \
                 Call with action=\"help\" for the full manual of available actions."
                    .to_string(),
            ),
        }
    }
}

// ─── Entry point ────────────────────────────────────────────────────

pub async fn run_mcp(args: McpArgs) -> color_eyre::eyre::Result<()> {
    let api = Arc::new(ApiClient::new(args.url, args.token));
    let server = DragonflyMcp::new(api);

    let service = server
        .serve(stdio())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("MCP serve error: {e}"))?;

    service
        .waiting()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("MCP service error: {e}"))?;

    Ok(())
}
