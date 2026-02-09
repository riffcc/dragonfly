//! rqlite distributed storage backend
//!
//! Uses `rqlite-rs` crate for automatic failover, connection pooling,
//! and cluster management. Same schema as SQLiteStore but with TEXT
//! instead of BLOB for UUID columns (cleaner HTTP transport).

use super::{Result, Store, StoreError, User};
use async_trait::async_trait;
use dragonfly_common::{DnsRecord, DnsRecordSource, DnsRecordType, Machine, MachineState, Network, normalize_mac};
use dragonfly_crd::{Template, Workflow};
use rqlite_rs::prelude::*;
use rqlite_rs::query::RqliteQuery;
use rqlite_rs::error::RequestError;
use serde::Serialize;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

/// rqlite storage backend implementing the Store trait.
///
/// Connects to a running rqlite cluster via rqlite-rs. Uses the same schema
/// as SqliteStore but with TEXT IDs instead of BLOB for clean HTTP transport.
pub struct RqliteStore {
    client: RqliteClient,
    base_url: String,
}

impl RqliteStore {
    /// Connect to a running rqlite instance and create tables if needed.
    pub async fn open(base_url: &str) -> Result<Self> {
        let clean_url = base_url.trim_end_matches('/');

        // Extract host:port from URL (rqlite-rs wants "host:port", not "http://host:port")
        let known_host = clean_url
            .strip_prefix("http://")
            .or_else(|| clean_url.strip_prefix("https://"))
            .unwrap_or(clean_url);

        let client = RqliteClientBuilder::new()
            .known_host(known_host)
            .build()
            .map_err(|e| StoreError::Database(format!("rqlite client build error: {}", e)))?;

        let store = Self {
            client,
            base_url: clean_url.to_string(),
        };
        store.create_tables().await?;
        info!("rqlite store connected at {}", store.base_url);
        Ok(store)
    }

    /// Return the base URL of the rqlite node
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn to_json<T: Serialize>(value: &T) -> Result<String> {
        serde_json::to_string(value).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
        serde_json::from_str(json).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    /// Create all tables (same schema as SQLite but TEXT for IDs)
    async fn create_tables(&self) -> Result<()> {
        let stmts: Vec<&str> = vec![
            "CREATE TABLE IF NOT EXISTS machines (id TEXT PRIMARY KEY, primary_mac TEXT, identity_hash TEXT, current_ip TEXT, state TEXT, data TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_machines_mac ON machines(primary_mac)",
            "CREATE INDEX IF NOT EXISTS idx_machines_identity ON machines(identity_hash)",
            "CREATE INDEX IF NOT EXISTS idx_machines_ip ON machines(current_ip)",
            "CREATE INDEX IF NOT EXISTS idx_machines_state ON machines(state)",
            "CREATE TABLE IF NOT EXISTS machine_tags (machine_id TEXT NOT NULL, tag TEXT NOT NULL, PRIMARY KEY (machine_id, tag))",
            "CREATE INDEX IF NOT EXISTS idx_machine_tags_tag ON machine_tags(tag)",
            "CREATE TABLE IF NOT EXISTS tags (name TEXT PRIMARY KEY, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS templates (name TEXT PRIMARY KEY, data TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS workflows (id TEXT PRIMARY KEY, machine_id TEXT, data TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_workflows_machine ON workflows(machine_id)",
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS networks (id TEXT PRIMARY KEY, data TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT, data TEXT NOT NULL)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE TABLE IF NOT EXISTS dns_records (id TEXT PRIMARY KEY, zone TEXT NOT NULL, name TEXT NOT NULL, rtype TEXT NOT NULL, rdata TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 3600, source TEXT NOT NULL, machine_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_dns_zone_name ON dns_records(zone, name)",
            "CREATE INDEX IF NOT EXISTS idx_dns_machine ON dns_records(machine_id)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_unique ON dns_records(zone, name, rtype, rdata)",
        ];

        // Use transaction for atomicity
        self.client
            .transaction(stmts)
            .await
            .map_err(|e| StoreError::Database(format!("rqlite table creation error: {}", e)))?;

        info!("rqlite tables initialized");
        Ok(())
    }

    /// Check if the rqlite node is ready
    pub async fn is_ready(&self) -> bool {
        self.client.ready().await
    }

    /// Fetch a single optional data column from a query
    async fn fetch_one_data<Q>(&self, q: Q) -> Result<Option<String>>
    where
        Q: TryInto<RqliteQuery>,
        RequestError: From<Q::Error>,
    {
        let rows = self.client.fetch(q).await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        match rows.first() {
            Some(row) => {
                let data: String = row.get("data")
                    .map_err(|e| StoreError::Database(format!("rqlite column error: {}", e)))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    fn dns_record_from_rqlite_row(row: &rqlite_rs::Row) -> Result<DnsRecord> {
        let id_str: String = row.get("id")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let id = Uuid::parse_str(&id_str)
            .map_err(|e| StoreError::Serialization(format!("Invalid UUID: {}", e)))?;

        let zone: String = row.get("zone")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let name: String = row.get("name")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let rtype_str: String = row.get("rtype")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let rdata: String = row.get("rdata")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let ttl: i64 = row.get("ttl")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let source_str: String = row.get("source")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let machine_id_str: String = row.get("machine_id")
            .unwrap_or_default();
        let created_str: String = row.get("created_at")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
        let updated_str: String = row.get("updated_at")
            .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;

        let rtype = DnsRecordType::from_str_loose(&rtype_str)
            .ok_or_else(|| StoreError::Serialization(format!("Unknown DNS record type: {}", rtype_str)))?;
        let source = DnsRecordSource::from_str_loose(&source_str)
            .ok_or_else(|| StoreError::Serialization(format!("Unknown DNS record source: {}", source_str)))?;

        let machine_id = if machine_id_str.is_empty() {
            None
        } else {
            Uuid::parse_str(&machine_id_str).ok()
        };

        let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        Ok(DnsRecord {
            id,
            zone,
            name,
            rtype,
            rdata,
            ttl: ttl as u32,
            source,
            machine_id,
            created_at,
            updated_at,
        })
    }

    /// Fetch all "data" columns from a query
    async fn fetch_all_data<Q>(&self, q: Q) -> Result<Vec<String>>
    where
        Q: TryInto<RqliteQuery>,
        RequestError: From<Q::Error>,
    {
        let rows = self.client.fetch(q).await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        let mut results = Vec::with_capacity(rows.len());
        for row in &rows {
            let data: String = row.get("data")
                .map_err(|e| StoreError::Database(format!("rqlite column error: {}", e)))?;
            results.push(data);
        }
        Ok(results)
    }
}

#[async_trait]
impl Store for RqliteStore {
    // === Machine Operations ===

    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>> {
        let q = rqlite_rs::query!(
            "SELECT data FROM machines WHERE id = ?",
            id.to_string()
        );

        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>> {
        let q = rqlite_rs::query!(
            "SELECT data FROM machines WHERE identity_hash = ?",
            identity_hash.to_string()
        );

        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn get_machine_by_mac(&self, mac: &str) -> Result<Option<Machine>> {
        let normalized = normalize_mac(mac);
        let q = rqlite_rs::query!(
            "SELECT data FROM machines WHERE primary_mac = ?",
            normalized
        );

        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn get_machine_by_ip(&self, ip: &str) -> Result<Option<Machine>> {
        let q = rqlite_rs::query!(
            "SELECT data FROM machines WHERE current_ip = ?",
            ip.to_string()
        );

        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn put_machine(&self, machine: &Machine) -> Result<()> {
        let id = machine.id.to_string();
        let json = Self::to_json(machine)?;
        let primary_mac = machine.identity.primary_mac.clone();
        let identity_hash = machine.identity.identity_hash.clone();
        let current_ip = machine.status.current_ip.clone();
        let state = machine.status.state.as_str().to_string();

        // Upsert machine
        let upsert = rqlite_rs::query!(
            "INSERT INTO machines (id, primary_mac, identity_hash, current_ip, state, data) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET primary_mac = excluded.primary_mac, identity_hash = excluded.identity_hash, current_ip = excluded.current_ip, state = excluded.state, data = excluded.data",
            id.clone(), primary_mac, identity_hash, current_ip, state, json
        );
        self.client.exec(upsert).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;

        // Get old tags
        let old_q = rqlite_rs::query!(
            "SELECT tag FROM machine_tags WHERE machine_id = ?",
            id.clone()
        );
        let old_rows = self.client.fetch(old_q).await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        let old_tags: Vec<String> = old_rows.iter()
            .filter_map(|r| r.get::<String>("tag").ok())
            .collect();

        // Delete old tags
        let del = rqlite_rs::query!(
            "DELETE FROM machine_tags WHERE machine_id = ?",
            id.clone()
        );
        self.client.exec(del).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;

        // Insert new tags
        let now = chrono::Utc::now().to_rfc3339();
        for tag in &machine.config.tags {
            let ins = rqlite_rs::query!(
                "INSERT INTO machine_tags (machine_id, tag) VALUES (?, ?)",
                id.clone(), tag.clone()
            );
            self.client.exec(ins).await
                .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;

            let tag_ins = rqlite_rs::query!(
                "INSERT OR IGNORE INTO tags (name, created_at) VALUES (?, ?)",
                tag.clone(), now.clone()
            );
            self.client.exec(tag_ins).await
                .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        }

        // Clean up orphaned tags
        let new_tags: std::collections::HashSet<&String> = machine.config.tags.iter().collect();
        for old_tag in &old_tags {
            if new_tags.contains(old_tag) {
                continue;
            }
            let cnt_q = rqlite_rs::query!(
                "SELECT COUNT(*) as cnt FROM machine_tags WHERE tag = ?",
                old_tag.clone()
            );
            let rows = self.client.fetch(cnt_q).await
                .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
            let count: i64 = rows.first()
                .and_then(|r| r.get::<i64>("cnt").ok())
                .unwrap_or(0);
            if count == 0 {
                let del_tag = rqlite_rs::query!(
                    "DELETE FROM tags WHERE name = ?",
                    old_tag.clone()
                );
                self.client.exec(del_tag).await
                    .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
            }
        }

        Ok(())
    }

    async fn list_machines(&self) -> Result<Vec<Machine>> {
        let jsons = self.fetch_all_data("SELECT data FROM machines").await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn list_machines_by_tag(&self, tag: &str) -> Result<Vec<Machine>> {
        let q = rqlite_rs::query!(
            "SELECT m.data FROM machines m INNER JOIN machine_tags mt ON m.id = mt.machine_id WHERE mt.tag = ?",
            tag.to_string()
        );
        let jsons = self.fetch_all_data(q).await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn list_machines_by_state(&self, state: &MachineState) -> Result<Vec<Machine>> {
        let q = rqlite_rs::query!(
            "SELECT data FROM machines WHERE state = ?",
            state.as_str().to_string()
        );
        let jsons = self.fetch_all_data(q).await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn delete_machine(&self, id: Uuid) -> Result<bool> {
        let id_str = id.to_string();

        // Get tags before deleting
        let tag_q = rqlite_rs::query!(
            "SELECT tag FROM machine_tags WHERE machine_id = ?",
            id_str.clone()
        );
        let tag_rows = self.client.fetch(tag_q).await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        let tags: Vec<String> = tag_rows.iter()
            .filter_map(|r| r.get::<String>("tag").ok())
            .collect();

        // Delete machine_tags and machine
        let del_tags = rqlite_rs::query!(
            "DELETE FROM machine_tags WHERE machine_id = ?",
            id_str.clone()
        );
        self.client.exec(del_tags).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;

        let del_machine = rqlite_rs::query!(
            "DELETE FROM machines WHERE id = ?",
            id_str
        );
        let result = self.client.exec(del_machine).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;

        // Clean up orphaned tags
        for tag in &tags {
            let cnt_q = rqlite_rs::query!(
                "SELECT COUNT(*) as cnt FROM machine_tags WHERE tag = ?",
                tag.clone()
            );
            let rows = self.client.fetch(cnt_q).await
                .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
            let count: i64 = rows.first()
                .and_then(|r| r.get::<i64>("cnt").ok())
                .unwrap_or(0);
            if count == 0 {
                let del_tag = rqlite_rs::query!(
                    "DELETE FROM tags WHERE name = ?",
                    tag.clone()
                );
                self.client.exec(del_tag).await
                    .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
            }
        }

        Ok(result.changed())
    }

    // === Tag Operations ===

    async fn create_tag(&self, name: &str) -> Result<bool> {
        let now = chrono::Utc::now().to_rfc3339();
        let q = rqlite_rs::query!(
            "INSERT OR IGNORE INTO tags (name, created_at) VALUES (?, ?)",
            name.to_string(), now
        );
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(result.changed())
    }

    async fn list_all_tags(&self) -> Result<Vec<String>> {
        let rows = self.client.fetch("SELECT name FROM tags ORDER BY name").await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        Ok(rows.iter().filter_map(|r| r.get::<String>("name").ok()).collect())
    }

    async fn delete_tag(&self, tag: &str) -> Result<bool> {
        let del_standalone = rqlite_rs::query!("DELETE FROM tags WHERE name = ?", tag.to_string());
        let r1 = self.client.exec(del_standalone).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;

        let del_machine_tags = rqlite_rs::query!("DELETE FROM machine_tags WHERE tag = ?", tag.to_string());
        let r2 = self.client.exec(del_machine_tags).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;

        if r2.changed() {
            // Update JSON data for affected machines
            let rows = self.client.fetch("SELECT id, data FROM machines").await
                .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;

            for row in &rows {
                let id: String = row.get("id")
                    .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
                let json: String = row.get("data")
                    .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
                if let Ok(mut machine) = Self::from_json::<Machine>(&json) {
                    if machine.config.tags.contains(&tag.to_string()) {
                        machine.config.tags.retain(|t| t != tag);
                        if let Ok(updated_json) = Self::to_json(&machine) {
                            let upd = rqlite_rs::query!(
                                "UPDATE machines SET data = ? WHERE id = ?",
                                updated_json, id
                            );
                            self.client.exec(upd).await
                                .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
                        }
                    }
                }
            }
        }

        Ok(r1.changed() || r2.changed())
    }

    // === Template Operations ===

    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        let q = rqlite_rs::query!("SELECT data FROM templates WHERE name = ?", name.to_string());
        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn put_template(&self, template: &Template) -> Result<()> {
        let json = Self::to_json(template)?;
        let q = rqlite_rs::query!(
            "INSERT INTO templates (name, data) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET data = excluded.data",
            template.metadata.name.clone(), json
        );
        self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(())
    }

    async fn list_templates(&self) -> Result<Vec<Template>> {
        let jsons = self.fetch_all_data("SELECT data FROM templates").await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn delete_template(&self, name: &str) -> Result<bool> {
        let q = rqlite_rs::query!("DELETE FROM templates WHERE name = ?", name.to_string());
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(result.changed())
    }

    // === Workflow Operations ===

    async fn get_workflow(&self, id: Uuid) -> Result<Option<Workflow>> {
        let q = rqlite_rs::query!("SELECT data FROM workflows WHERE id = ?", id.to_string());
        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn get_workflows_for_machine(&self, machine_id: Uuid) -> Result<Vec<Workflow>> {
        let q = rqlite_rs::query!("SELECT data FROM workflows WHERE machine_id = ?", machine_id.to_string());
        let jsons = self.fetch_all_data(q).await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn put_workflow(&self, workflow: &Workflow) -> Result<()> {
        let workflow_id = Uuid::parse_str(&workflow.metadata.name)
            .map_err(|e| StoreError::InvalidData(format!("Invalid workflow UUID: {}", e)))?;
        let machine_id = Uuid::parse_str(&workflow.spec.hardware_ref).map_err(|e| {
            StoreError::InvalidData(format!("Invalid machine UUID in workflow: {}", e))
        })?;
        let json = Self::to_json(workflow)?;
        let q = rqlite_rs::query!(
            "INSERT INTO workflows (id, machine_id, data) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET machine_id = excluded.machine_id, data = excluded.data",
            workflow_id.to_string(), machine_id.to_string(), json
        );
        self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(())
    }

    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        let jsons = self.fetch_all_data("SELECT data FROM workflows").await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn delete_workflow(&self, id: Uuid) -> Result<bool> {
        let q = rqlite_rs::query!("DELETE FROM workflows WHERE id = ?", id.to_string());
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(result.changed())
    }

    // === Settings Operations ===

    async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let q = rqlite_rs::query!("SELECT value FROM settings WHERE key = ?", key.to_string());
        let rows = self.client.fetch(q).await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        match rows.first() {
            Some(row) => Ok(Some(row.get::<String>("value")
                .map_err(|e| StoreError::Database(format!("column error: {}", e)))?)),
            None => Ok(None),
        }
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        let q = rqlite_rs::query!(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            key.to_string(), value.to_string()
        );
        self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(())
    }

    async fn delete_setting(&self, key: &str) -> Result<bool> {
        let q = rqlite_rs::query!("DELETE FROM settings WHERE key = ?", key.to_string());
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(result.changed())
    }

    async fn list_settings(&self, prefix: &str) -> Result<HashMap<String, String>> {
        let pattern = format!("{}%", prefix);
        let q = rqlite_rs::query!("SELECT key, value FROM settings WHERE key LIKE ?", pattern);
        let rows = self.client.fetch(q).await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        let mut settings = HashMap::new();
        for row in &rows {
            let key: String = row.get("key")
                .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
            let value: String = row.get("value")
                .map_err(|e| StoreError::Database(format!("column error: {}", e)))?;
            settings.insert(key, value);
        }
        Ok(settings)
    }

    // === Network Operations ===

    async fn get_network(&self, id: Uuid) -> Result<Option<Network>> {
        let q = rqlite_rs::query!("SELECT data FROM networks WHERE id = ?", id.to_string());
        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn put_network(&self, network: &Network) -> Result<()> {
        let json = Self::to_json(network)?;
        let q = rqlite_rs::query!(
            "INSERT INTO networks (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data",
            network.id.to_string(), json
        );
        self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(())
    }

    async fn list_networks(&self) -> Result<Vec<Network>> {
        let jsons = self.fetch_all_data("SELECT data FROM networks").await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn delete_network(&self, id: Uuid) -> Result<bool> {
        let q = rqlite_rs::query!("DELETE FROM networks WHERE id = ?", id.to_string());
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(result.changed())
    }

    // === User Operations ===

    async fn get_user(&self, id: Uuid) -> Result<Option<User>> {
        let q = rqlite_rs::query!("SELECT data FROM users WHERE id = ?", id.to_string());
        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let q = rqlite_rs::query!("SELECT data FROM users WHERE username = ?", username.to_string());
        match self.fetch_one_data(q).await? {
            Some(json) => Ok(Some(Self::from_json(&json)?)),
            None => Ok(None),
        }
    }

    async fn put_user(&self, user: &User) -> Result<()> {
        let json = Self::to_json(user)?;
        let q = rqlite_rs::query!(
            "INSERT INTO users (id, username, data) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET username = excluded.username, data = excluded.data",
            user.id.to_string(), user.username.clone(), json
        );
        self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        let jsons = self.fetch_all_data("SELECT data FROM users ORDER BY json_extract(data, '$.created_at')").await?;
        jsons.iter().map(|j| Self::from_json(j)).collect()
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool> {
        let q = rqlite_rs::query!("DELETE FROM users WHERE id = ?", id.to_string());
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(result.changed())
    }

    // === DNS Record Operations ===

    async fn list_dns_records(&self, zone: &str) -> Result<Vec<DnsRecord>> {
        let q = rqlite_rs::query!(
            "SELECT id, zone, name, rtype, rdata, ttl, source, machine_id, created_at, updated_at FROM dns_records WHERE zone = ? ORDER BY name, rtype",
            zone.to_string()
        );
        let rows = self.client.fetch(q).await
            .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;
        rows.iter().map(Self::dns_record_from_rqlite_row).collect()
    }

    async fn get_dns_records(
        &self,
        zone: &str,
        name: &str,
        rtype: Option<DnsRecordType>,
    ) -> Result<Vec<DnsRecord>> {
        let rows = if let Some(rt) = rtype {
            let q = rqlite_rs::query!(
                "SELECT id, zone, name, rtype, rdata, ttl, source, machine_id, created_at, updated_at FROM dns_records WHERE zone = ? AND name = ? AND rtype = ?",
                zone.to_string(), name.to_string(), rt.as_str().to_string()
            );
            self.client.fetch(q).await
        } else {
            let q = rqlite_rs::query!(
                "SELECT id, zone, name, rtype, rdata, ttl, source, machine_id, created_at, updated_at FROM dns_records WHERE zone = ? AND name = ?",
                zone.to_string(), name.to_string()
            );
            self.client.fetch(q).await
        }
        .map_err(|e| StoreError::Database(format!("rqlite query error: {}", e)))?;

        rows.iter().map(Self::dns_record_from_rqlite_row).collect()
    }

    async fn put_dns_record(&self, record: &DnsRecord) -> Result<()> {
        let machine_id_str = record.machine_id.map(|m| m.to_string()).unwrap_or_default();
        let created = record.created_at.to_rfc3339();
        let updated = record.updated_at.to_rfc3339();

        let q = rqlite_rs::query!(
            "INSERT INTO dns_records (id, zone, name, rtype, rdata, ttl, source, machine_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET zone = excluded.zone, name = excluded.name, rtype = excluded.rtype, rdata = excluded.rdata, ttl = excluded.ttl, source = excluded.source, machine_id = excluded.machine_id, updated_at = excluded.updated_at",
            record.id.to_string(), record.zone.clone(), record.name.clone(),
            record.rtype.as_str().to_string(), record.rdata.clone(),
            record.ttl as i64, record.source.as_str().to_string(),
            machine_id_str, created, updated
        );
        self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(())
    }

    async fn delete_dns_record(&self, id: Uuid) -> Result<bool> {
        let q = rqlite_rs::query!("DELETE FROM dns_records WHERE id = ?", id.to_string());
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(result.changed())
    }

    async fn delete_dns_records_by_machine(&self, machine_id: Uuid) -> Result<u64> {
        let q = rqlite_rs::query!("DELETE FROM dns_records WHERE machine_id = ?", machine_id.to_string());
        let result = self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(if result.changed() { 1 } else { 0 })
    }

    async fn upsert_dns_record(
        &self,
        zone: &str,
        name: &str,
        rtype: DnsRecordType,
        rdata: &str,
        ttl: u32,
        source: DnsRecordSource,
        machine_id: Option<Uuid>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let new_id = Uuid::now_v7().to_string();
        let machine_id_str = machine_id.map(|m| m.to_string()).unwrap_or_default();

        let q = rqlite_rs::query!(
            "INSERT INTO dns_records (id, zone, name, rtype, rdata, ttl, source, machine_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(zone, name, rtype, rdata) DO UPDATE SET ttl = excluded.ttl, source = excluded.source, machine_id = excluded.machine_id, updated_at = excluded.updated_at",
            new_id, zone.to_string(), name.to_string(),
            rtype.as_str().to_string(), rdata.to_string(),
            ttl as i64, source.as_str().to_string(),
            machine_id_str, now.clone(), now
        );
        self.client.exec(q).await
            .map_err(|e| StoreError::Database(format!("rqlite exec error: {}", e)))?;
        Ok(())
    }
}
