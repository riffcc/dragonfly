//! High Availability management for Dragonfly
//!
//! Manages the rqlite distributed database lifecycle:
//! - Download rqlite binary from GitHub releases
//! - Start/stop rqlite as a managed child process
//! - Migrate data from standalone SQLite → rqlite
//! - Query cluster status and health
//!
//! The HA flag file at `/var/lib/dragonfly/ha.enabled` controls whether
//! Dragonfly starts in HA mode or standalone SQLite mode.

use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::store::v1::{RqliteStore, SqliteStore, Store};

/// rqlite version to download
const RQLITE_VERSION: &str = "8.36.6";

/// Base directory for Dragonfly data
const DATA_DIR: &str = "/var/lib/dragonfly";

/// HA flag file — presence means HA mode is enabled.
/// Contents: empty for local rqlite, or a URL for remote cluster.
pub const HA_FLAG_FILE: &str = "/var/lib/dragonfly/ha.enabled";

/// rqlite binary location
const RQLITE_BIN: &str = "/var/lib/dragonfly/bin/rqlited";

/// rqlite data directory
const RQLITE_DATA_DIR: &str = "/var/lib/dragonfly/rqlite-data";

/// Default rqlite HTTP API port
const RQLITE_HTTP_PORT: u16 = 4001;

/// Default rqlite Raft port
const RQLITE_RAFT_PORT: u16 = 4002;

/// HA cluster state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaStatus {
    pub enabled: bool,
    pub node_id: Option<String>,
    pub http_addr: Option<String>,
    pub raft_addr: Option<String>,
    pub leader: Option<String>,
    pub nodes: Vec<ClusterNode>,
    pub rqlite_running: bool,
}

/// A node in the HA cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub id: String,
    pub addr: String,
    pub is_leader: bool,
    pub is_self: bool,
}

/// Managed rqlite process
pub struct HaManager {
    process: Mutex<Option<Child>>,
    node_id: String,
    http_port: u16,
    raft_port: u16,
}

impl HaManager {
    /// Create a new HA manager
    pub fn new(node_id: String) -> Self {
        Self {
            process: Mutex::new(None),
            node_id,
            http_port: RQLITE_HTTP_PORT,
            raft_port: RQLITE_RAFT_PORT,
        }
    }

    /// Check if HA mode is enabled (flag file exists)
    pub fn is_ha_enabled() -> bool {
        Path::new(HA_FLAG_FILE).exists()
    }

    /// Get the rqlite HTTP URL for this node
    pub fn rqlite_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }

    /// Download the rqlite binary if not already present
    pub async fn ensure_rqlite_binary() -> Result<()> {
        if Path::new(RQLITE_BIN).exists() {
            info!("rqlite binary already present at {}", RQLITE_BIN);
            return Ok(());
        }

        info!("Downloading rqlite v{}...", RQLITE_VERSION);

        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "amd64"
        };

        let tarball_name = format!("rqlite-v{}-linux-{}.tar.gz", RQLITE_VERSION, arch);
        let url = format!(
            "https://github.com/rqlite/rqlite/releases/download/v{}/{}",
            RQLITE_VERSION, tarball_name
        );

        let client = Client::new();
        let resp = client
            .get(&url)
            .send()
            .await
            .context("Failed to download rqlite")?;

        if !resp.status().is_success() {
            bail!("rqlite download failed: HTTP {}", resp.status());
        }

        let bytes = resp.bytes().await.context("Failed to read rqlite tarball")?;

        // Extract rqlited from tarball
        let decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(decoder);

        let bin_dir = PathBuf::from(DATA_DIR).join("bin");
        fs::create_dir_all(&bin_dir).await?;

        let expected_entry = format!(
            "rqlite-v{}-linux-{}/rqlited",
            RQLITE_VERSION, arch
        );

        let mut found = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().to_string();
            if path == expected_entry {
                let dest = PathBuf::from(RQLITE_BIN);
                let mut file = std::fs::File::create(&dest)?;
                std::io::copy(&mut entry, &mut file)?;
                // Make executable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
                }
                found = true;
                break;
            }
        }

        if !found {
            bail!("rqlited binary not found in tarball (looked for {})", expected_entry);
        }

        info!("rqlite v{} installed at {}", RQLITE_VERSION, RQLITE_BIN);
        Ok(())
    }

    /// Start the rqlite process
    pub async fn start(&self, join_addr: Option<&str>) -> Result<()> {
        let mut proc = self.process.lock().await;
        if proc.is_some() {
            info!("rqlite already running");
            return Ok(());
        }

        // Ensure data directory exists
        fs::create_dir_all(RQLITE_DATA_DIR).await?;

        let http_addr = format!("0.0.0.0:{}", self.http_port);
        let raft_addr = format!("0.0.0.0:{}", self.raft_port);

        let mut cmd = Command::new(RQLITE_BIN);
        cmd.arg("-node-id").arg(&self.node_id)
            .arg("-http-addr").arg(&http_addr)
            .arg("-raft-addr").arg(&raft_addr)
            .arg(RQLITE_DATA_DIR);

        if let Some(join) = join_addr {
            cmd.arg("-join").arg(join);
        }

        let child = cmd
            .kill_on_drop(true)
            .spawn()
            .context("Failed to start rqlite")?;

        info!(
            "rqlite started (node={}, http={}, raft={})",
            self.node_id, http_addr, raft_addr
        );

        *proc = Some(child);

        // Wait for rqlite to become ready
        let client = Client::new();
        let ready_url = format!("{}/readyz", self.rqlite_url());
        for i in 0..50 {
            match client.get(&ready_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!("rqlite ready after {}ms", i * 100);
                    return Ok(());
                }
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }

        warn!("rqlite did not become ready within 5 seconds, but process is running");
        Ok(())
    }

    /// Stop the rqlite process
    pub async fn stop(&self) -> Result<()> {
        let mut proc = self.process.lock().await;
        if let Some(mut child) = proc.take() {
            child.kill().await.context("Failed to kill rqlite")?;
            info!("rqlite process stopped");
        }
        Ok(())
    }

    /// Check if rqlite process is running
    pub async fn is_running(&self) -> bool {
        let mut proc = self.process.lock().await;
        match proc.as_mut() {
            Some(child) => child.try_wait().ok().flatten().is_none(),
            None => false,
        }
    }

    /// Get HA cluster status
    pub async fn status(&self) -> HaStatus {
        let enabled = Self::is_ha_enabled();
        let running = self.is_running().await;

        let mut status = HaStatus {
            enabled,
            node_id: Some(self.node_id.clone()),
            http_addr: Some(format!("127.0.0.1:{}", self.http_port)),
            raft_addr: Some(format!("127.0.0.1:{}", self.raft_port)),
            leader: None,
            nodes: Vec::new(),
            rqlite_running: running,
        };

        if running {
            // Try to get cluster info from rqlite
            let client = Client::new();
            let status_url = format!("{}/status", self.rqlite_url());
            if let Ok(resp) = client.get(&status_url).send().await {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    // Extract leader from status
                    if let Some(store) = data.get("store") {
                        if let Some(leader) = store.get("leader").and_then(|l| l.get("addr")) {
                            status.leader = leader.as_str().map(String::from);
                        }

                        // Extract nodes
                        if let Some(nodes) = store.get("metadata").and_then(|m| m.as_object()) {
                            for (node_id, meta) in nodes {
                                let addr = meta
                                    .get("api_addr")
                                    .and_then(|a| a.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                let is_leader = status.leader.as_deref() == Some(&addr);
                                status.nodes.push(ClusterNode {
                                    id: node_id.clone(),
                                    addr,
                                    is_leader,
                                    is_self: node_id == &self.node_id,
                                });
                            }
                        }
                    }
                }
            }
        }

        status
    }

    /// Enable HA mode: download rqlite, start it, migrate data from SQLite
    pub async fn enable_ha(
        &self,
        sqlite_store: &SqliteStore,
    ) -> Result<Arc<dyn Store>> {
        info!("Enabling High Availability mode...");

        // Step 1: Download rqlite binary
        Self::ensure_rqlite_binary().await?;

        // Step 2: Start rqlite (single node initially)
        self.start(None).await?;

        // Step 3: Connect to rqlite
        let rqlite_store = RqliteStore::open(&self.rqlite_url()).await
            .context("Failed to connect to rqlite store")?;

        // Step 4: Migrate data from SQLite
        migrate_sqlite_to_rqlite(sqlite_store, &rqlite_store).await?;

        // Step 5: Write HA flag file
        fs::write(HA_FLAG_FILE, self.node_id.as_bytes()).await?;

        info!("High Availability mode enabled successfully");
        Ok(Arc::new(rqlite_store))
    }

    /// Disable HA mode: migrate data back to SQLite, stop rqlite
    pub async fn disable_ha(
        &self,
        rqlite_store: &RqliteStore,
        sqlite_path: &str,
    ) -> Result<Arc<dyn Store>> {
        info!("Disabling High Availability mode...");

        // Step 1: Open/create SQLite store
        let sqlite_store = SqliteStore::open(sqlite_path).await
            .map_err(|e| anyhow::anyhow!("Failed to open SQLite: {}", e))?;

        // Step 2: Migrate data from rqlite → SQLite
        migrate_rqlite_to_sqlite(rqlite_store, &sqlite_store).await?;

        // Step 3: Stop rqlite
        self.stop().await?;

        // Step 4: Remove HA flag file
        let _ = fs::remove_file(HA_FLAG_FILE).await;

        info!("High Availability mode disabled, back to standalone SQLite");
        Ok(Arc::new(sqlite_store))
    }
}

/// Migrate all data from SQLite store to rqlite store
pub async fn migrate_sqlite_to_rqlite(
    src: &SqliteStore,
    dst: &RqliteStore,
) -> Result<()> {
    info!("Migrating data from SQLite to rqlite...");

    // Migrate settings
    let settings = src.list_settings("").await
        .map_err(|e| anyhow::anyhow!("Failed to list settings: {}", e))?;
    for (key, value) in &settings {
        dst.put_setting(key, value).await
            .map_err(|e| anyhow::anyhow!("Failed to put setting: {}", e))?;
    }
    info!("Migrated {} settings", settings.len());

    // Migrate templates
    let templates = src.list_templates().await
        .map_err(|e| anyhow::anyhow!("Failed to list templates: {}", e))?;
    for template in &templates {
        dst.put_template(template).await
            .map_err(|e| anyhow::anyhow!("Failed to put template: {}", e))?;
    }
    info!("Migrated {} templates", templates.len());

    // Migrate networks
    let networks = src.list_networks().await
        .map_err(|e| anyhow::anyhow!("Failed to list networks: {}", e))?;
    for network in &networks {
        dst.put_network(network).await
            .map_err(|e| anyhow::anyhow!("Failed to put network: {}", e))?;
    }
    info!("Migrated {} networks", networks.len());

    // Migrate users
    let users = src.list_users().await
        .map_err(|e| anyhow::anyhow!("Failed to list users: {}", e))?;
    for user in &users {
        dst.put_user(user).await
            .map_err(|e| anyhow::anyhow!("Failed to put user: {}", e))?;
    }
    info!("Migrated {} users", users.len());

    // Migrate machines (includes tags)
    let machines = src.list_machines().await
        .map_err(|e| anyhow::anyhow!("Failed to list machines: {}", e))?;
    for machine in &machines {
        dst.put_machine(machine).await
            .map_err(|e| anyhow::anyhow!("Failed to put machine: {}", e))?;
    }
    info!("Migrated {} machines", machines.len());

    // Migrate standalone tags (not attached to any machine)
    let tags = src.list_all_tags().await
        .map_err(|e| anyhow::anyhow!("Failed to list tags: {}", e))?;
    for tag in &tags {
        let _ = dst.create_tag(tag).await;
    }
    info!("Migrated {} tags", tags.len());

    // Migrate workflows
    let workflows = src.list_workflows().await
        .map_err(|e| anyhow::anyhow!("Failed to list workflows: {}", e))?;
    for workflow in &workflows {
        dst.put_workflow(workflow).await
            .map_err(|e| anyhow::anyhow!("Failed to put workflow: {}", e))?;
    }
    info!("Migrated {} workflows", workflows.len());

    info!("Migration complete!");
    Ok(())
}

/// Read the rqlite cluster URL from the HA flag file.
///
/// Returns `None` if the file doesn't exist or is empty (local rqlite).
/// Returns `Some(url)` if the file contains a remote cluster URL.
pub fn read_ha_url() -> Option<String> {
    let content = std::fs::read_to_string(HA_FLAG_FILE).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() || !trimmed.starts_with("http") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Enable HA mode with a remote rqlite cluster (deployed via LXCs).
///
/// This is called by the cluster orchestrator after rqlite is running.
/// It migrates data from the current SQLite store to the remote rqlite cluster,
/// then writes the cluster URL to the HA flag file.
pub async fn enable_ha_remote(
    _state: &crate::AppState,
    rqlite_url: &str,
) -> anyhow::Result<()> {
    info!("Enabling HA with remote rqlite cluster at {}", rqlite_url);

    // Connect to the remote rqlite cluster
    let rqlite_store = RqliteStore::open(rqlite_url).await
        .map_err(|e| anyhow::anyhow!("Failed to connect to rqlite: {}", e))?;

    // Open a read connection to the current SQLite store for migration
    let sqlite_path = "/var/lib/dragonfly/dragonfly.sqlite3";
    let sqlite_store = SqliteStore::open(sqlite_path).await
        .map_err(|e| anyhow::anyhow!("Failed to open SQLite: {}", e))?;

    // Migrate data
    migrate_sqlite_to_rqlite(&sqlite_store, &rqlite_store).await?;

    // Write the remote URL to the HA flag file
    fs::write(HA_FLAG_FILE, rqlite_url.as_bytes()).await?;

    info!("HA mode enabled with remote cluster at {}", rqlite_url);
    Ok(())
}

/// Migrate all data from rqlite store back to SQLite store
pub async fn migrate_rqlite_to_sqlite(
    src: &RqliteStore,
    dst: &SqliteStore,
) -> Result<()> {
    info!("Migrating data from rqlite to SQLite...");

    // Settings
    let settings = src.list_settings("").await
        .map_err(|e| anyhow::anyhow!("Failed to list settings: {}", e))?;
    for (key, value) in &settings {
        dst.put_setting(key, value).await
            .map_err(|e| anyhow::anyhow!("Failed to put setting: {}", e))?;
    }

    // Templates
    let templates = src.list_templates().await
        .map_err(|e| anyhow::anyhow!("Failed to list templates: {}", e))?;
    for template in &templates {
        dst.put_template(template).await
            .map_err(|e| anyhow::anyhow!("Failed to put template: {}", e))?;
    }

    // Networks
    let networks = src.list_networks().await
        .map_err(|e| anyhow::anyhow!("Failed to list networks: {}", e))?;
    for network in &networks {
        dst.put_network(network).await
            .map_err(|e| anyhow::anyhow!("Failed to put network: {}", e))?;
    }

    // Users
    let users = src.list_users().await
        .map_err(|e| anyhow::anyhow!("Failed to list users: {}", e))?;
    for user in &users {
        dst.put_user(user).await
            .map_err(|e| anyhow::anyhow!("Failed to put user: {}", e))?;
    }

    // Machines
    let machines = src.list_machines().await
        .map_err(|e| anyhow::anyhow!("Failed to list machines: {}", e))?;
    for machine in &machines {
        dst.put_machine(machine).await
            .map_err(|e| anyhow::anyhow!("Failed to put machine: {}", e))?;
    }

    // Tags
    let tags = src.list_all_tags().await
        .map_err(|e| anyhow::anyhow!("Failed to list tags: {}", e))?;
    for tag in &tags {
        let _ = dst.create_tag(tag).await;
    }

    // Workflows
    let workflows = src.list_workflows().await
        .map_err(|e| anyhow::anyhow!("Failed to list workflows: {}", e))?;
    for workflow in &workflows {
        dst.put_workflow(workflow).await
            .map_err(|e| anyhow::anyhow!("Failed to put workflow: {}", e))?;
    }

    info!("Migration to SQLite complete!");
    Ok(())
}
