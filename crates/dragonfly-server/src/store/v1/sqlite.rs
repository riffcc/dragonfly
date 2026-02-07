//! SQLite storage backend for v0.1.0 schema
//!
//! Persistent storage using SQLite with WAL mode for concurrent reads
//! and fast serialized writes. Entities stored as JSON blobs with
//! indexed lookup columns.

use super::{Result, Store, StoreError, User};
use async_trait::async_trait;
use dragonfly_common::{Machine, MachineState, Network, normalize_mac};
use dragonfly_crd::{Template, Workflow};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use tracing::info;
use uuid::Uuid;

/// SQLite storage backend implementing the v0.1.0 schema.
///
/// Uses WAL journal mode for concurrent reads with fast serialized writes.
/// All complex entities are stored as JSON with indexed lookup columns.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Get a reference to the underlying SQLite connection pool.
    /// Used for session stores and other components that need raw pool access.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Open or create a SQLite database at the given path.
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path_str))
            .map_err(|e| StoreError::Database(e.to_string()))?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let store = Self { pool };
        store.create_tables().await?;
        info!("SQLite store opened at {}", path_str);
        Ok(store)
    }

    async fn create_tables(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS machines (
                id BLOB PRIMARY KEY,
                primary_mac TEXT,
                identity_hash TEXT,
                current_ip TEXT,
                state TEXT,
                data TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_machines_mac ON machines(primary_mac)")
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_machines_identity ON machines(identity_hash)")
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_machines_ip ON machines(current_ip)")
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_machines_state ON machines(state)")
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS machine_tags (
                machine_id BLOB NOT NULL,
                tag TEXT NOT NULL,
                PRIMARY KEY (machine_id, tag)
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_machine_tags_tag ON machine_tags(tag)")
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tags (
                name TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS templates (
                name TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS workflows (
                id BLOB PRIMARY KEY,
                machine_id BLOB,
                data TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflows_machine ON workflows(machine_id)")
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS networks (
                id BLOB PRIMARY KEY,
                data TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id BLOB PRIMARY KEY,
                username TEXT,
                data TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
        serde_json::to_string(value).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
        serde_json::from_str(json).map_err(|e| StoreError::Serialization(e.to_string()))
    }
}

#[async_trait]
impl Store for SqliteStore {
    // === Machine Operations ===

    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>> {
        let id_bytes = id.as_bytes().to_vec();
        let row = sqlx::query("SELECT data FROM machines WHERE id = ?")
            .bind(&id_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>> {
        let row = sqlx::query("SELECT data FROM machines WHERE identity_hash = ?")
            .bind(identity_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn get_machine_by_mac(&self, mac: &str) -> Result<Option<Machine>> {
        let normalized = normalize_mac(mac);
        let row = sqlx::query("SELECT data FROM machines WHERE primary_mac = ?")
            .bind(&normalized)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn get_machine_by_ip(&self, ip: &str) -> Result<Option<Machine>> {
        let row = sqlx::query("SELECT data FROM machines WHERE current_ip = ?")
            .bind(ip)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn put_machine(&self, machine: &Machine) -> Result<()> {
        let id_bytes = machine.id.as_bytes().to_vec();
        let json = Self::to_json(machine)?;
        let primary_mac = machine.identity.primary_mac.clone();
        let identity_hash = machine.identity.identity_hash.clone();
        let current_ip = machine.status.current_ip.clone();
        let state = machine.status.state.as_str().to_string();

        // Upsert machine
        sqlx::query(
            "INSERT INTO machines (id, primary_mac, identity_hash, current_ip, state, data) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
             primary_mac = excluded.primary_mac, \
             identity_hash = excluded.identity_hash, \
             current_ip = excluded.current_ip, \
             state = excluded.state, \
             data = excluded.data",
        )
        .bind(&id_bytes)
        .bind(&primary_mac)
        .bind(&identity_hash)
        .bind(&current_ip)
        .bind(&state)
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        // Get old tags for this machine before replacing
        let old_tag_rows = sqlx::query("SELECT tag FROM machine_tags WHERE machine_id = ?")
            .bind(&id_bytes)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let old_tags: Vec<String> = old_tag_rows.iter().map(|r| r.get("tag")).collect();

        // Rebuild machine_tags
        sqlx::query("DELETE FROM machine_tags WHERE machine_id = ?")
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now = chrono::Utc::now().to_rfc3339();
        for tag in &machine.config.tags {
            sqlx::query("INSERT INTO machine_tags (machine_id, tag) VALUES (?, ?)")
                .bind(&id_bytes)
                .bind(tag)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

            // Ensure tag exists in tags table
            sqlx::query("INSERT OR IGNORE INTO tags (name, created_at) VALUES (?, ?)")
                .bind(tag)
                .bind(&now)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        // Clean up orphaned tags: old tags that no machine has anymore
        let new_tags: std::collections::HashSet<&String> = machine.config.tags.iter().collect();
        for old_tag in &old_tags {
            if new_tags.contains(old_tag) {
                continue;
            }
            let count_row = sqlx::query("SELECT COUNT(*) as cnt FROM machine_tags WHERE tag = ?")
                .bind(old_tag)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let count: i64 = count_row.get("cnt");
            if count == 0 {
                sqlx::query("DELETE FROM tags WHERE name = ?")
                    .bind(old_tag)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn list_machines(&self) -> Result<Vec<Machine>> {
        let rows = sqlx::query("SELECT data FROM machines")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut machines = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            machines.push(Self::from_json(&json)?);
        }
        Ok(machines)
    }

    async fn list_machines_by_tag(&self, tag: &str) -> Result<Vec<Machine>> {
        let rows = sqlx::query(
            "SELECT m.data FROM machines m \
             INNER JOIN machine_tags mt ON m.id = mt.machine_id \
             WHERE mt.tag = ?",
        )
        .bind(tag)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut machines = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            machines.push(Self::from_json(&json)?);
        }
        Ok(machines)
    }

    async fn list_machines_by_state(&self, state: &MachineState) -> Result<Vec<Machine>> {
        let state_str = state.as_str();
        let rows = sqlx::query("SELECT data FROM machines WHERE state = ?")
            .bind(state_str)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut machines = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            machines.push(Self::from_json(&json)?);
        }
        Ok(machines)
    }

    async fn delete_machine(&self, id: Uuid) -> Result<bool> {
        let id_bytes = id.as_bytes().to_vec();

        // Get this machine's tags before deleting
        let tag_rows = sqlx::query("SELECT tag FROM machine_tags WHERE machine_id = ?")
            .bind(&id_bytes)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let tags: Vec<String> = tag_rows.iter().map(|r| r.get("tag")).collect();

        // Delete machine_tags
        sqlx::query("DELETE FROM machine_tags WHERE machine_id = ?")
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let result = sqlx::query("DELETE FROM machines WHERE id = ?")
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Clean up orphaned tags from this machine
        for tag in &tags {
            let count_row = sqlx::query("SELECT COUNT(*) as cnt FROM machine_tags WHERE tag = ?")
                .bind(tag)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let count: i64 = count_row.get("cnt");
            if count == 0 {
                sqlx::query("DELETE FROM tags WHERE name = ?")
                    .bind(tag)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
        }

        Ok(result.rows_affected() > 0)
    }

    // === Tag Operations ===

    async fn create_tag(&self, name: &str) -> Result<bool> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query("INSERT OR IGNORE INTO tags (name, created_at) VALUES (?, ?)")
            .bind(name)
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_all_tags(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT name FROM tags ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(rows.iter().map(|r| r.get("name")).collect())
    }

    async fn delete_tag(&self, tag: &str) -> Result<bool> {
        // Remove from standalone tags table
        let standalone_result = sqlx::query("DELETE FROM tags WHERE name = ?")
            .bind(tag)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Remove from machine_tags
        let machine_tags_result = sqlx::query("DELETE FROM machine_tags WHERE tag = ?")
            .bind(tag)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let anything_deleted =
            standalone_result.rows_affected() > 0 || machine_tags_result.rows_affected() > 0;

        if machine_tags_result.rows_affected() > 0 {
            // Also update the JSON data for affected machines
            let rows = sqlx::query("SELECT id, data FROM machines")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

            for row in rows {
                let json: String = row.get("data");
                if let Ok(mut machine) = Self::from_json::<Machine>(&json) {
                    if machine.config.tags.contains(&tag.to_string()) {
                        machine.config.tags.retain(|t| t != tag);
                        let updated_json = Self::to_json(&machine)?;
                        let id_bytes: Vec<u8> = row.get("id");
                        sqlx::query("UPDATE machines SET data = ? WHERE id = ?")
                            .bind(&updated_json)
                            .bind(&id_bytes)
                            .execute(&self.pool)
                            .await
                            .map_err(|e| StoreError::Database(e.to_string()))?;
                    }
                }
            }
        }

        Ok(anything_deleted)
    }

    // === Template Operations ===

    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        let row = sqlx::query("SELECT data FROM templates WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn put_template(&self, template: &Template) -> Result<()> {
        let json = Self::to_json(template)?;
        sqlx::query(
            "INSERT INTO templates (name, data) VALUES (?, ?) \
             ON CONFLICT(name) DO UPDATE SET data = excluded.data",
        )
        .bind(&template.metadata.name)
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn list_templates(&self) -> Result<Vec<Template>> {
        let rows = sqlx::query("SELECT data FROM templates")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut templates = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            templates.push(Self::from_json(&json)?);
        }
        Ok(templates)
    }

    async fn delete_template(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM templates WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    // === Workflow Operations ===

    async fn get_workflow(&self, id: Uuid) -> Result<Option<Workflow>> {
        let id_bytes = id.as_bytes().to_vec();
        let row = sqlx::query("SELECT data FROM workflows WHERE id = ?")
            .bind(&id_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn get_workflows_for_machine(&self, machine_id: Uuid) -> Result<Vec<Workflow>> {
        let machine_id_bytes = machine_id.as_bytes().to_vec();
        let rows = sqlx::query("SELECT data FROM workflows WHERE machine_id = ?")
            .bind(&machine_id_bytes)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut workflows = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            workflows.push(Self::from_json(&json)?);
        }
        Ok(workflows)
    }

    async fn put_workflow(&self, workflow: &Workflow) -> Result<()> {
        let workflow_id = Uuid::parse_str(&workflow.metadata.name)
            .map_err(|e| StoreError::InvalidData(format!("Invalid workflow UUID: {}", e)))?;
        let machine_id = Uuid::parse_str(&workflow.spec.hardware_ref).map_err(|e| {
            StoreError::InvalidData(format!("Invalid machine UUID in workflow: {}", e))
        })?;

        let wf_id_bytes = workflow_id.as_bytes().to_vec();
        let machine_id_bytes = machine_id.as_bytes().to_vec();
        let json = Self::to_json(workflow)?;

        sqlx::query(
            "INSERT INTO workflows (id, machine_id, data) VALUES (?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET machine_id = excluded.machine_id, data = excluded.data",
        )
        .bind(&wf_id_bytes)
        .bind(&machine_id_bytes)
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        let rows = sqlx::query("SELECT data FROM workflows")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut workflows = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            workflows.push(Self::from_json(&json)?);
        }
        Ok(workflows)
    }

    async fn delete_workflow(&self, id: Uuid) -> Result<bool> {
        let id_bytes = id.as_bytes().to_vec();
        let result = sqlx::query("DELETE FROM workflows WHERE id = ?")
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    // === Settings Operations ===

    async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(row.map(|r| r.get("value")))
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_setting(&self, key: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM settings WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_settings(&self, prefix: &str) -> Result<HashMap<String, String>> {
        let pattern = format!("{}%", prefix);
        let rows = sqlx::query("SELECT key, value FROM settings WHERE key LIKE ?")
            .bind(&pattern)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut settings = HashMap::new();
        for row in rows {
            let key: String = row.get("key");
            let value: String = row.get("value");
            settings.insert(key, value);
        }
        Ok(settings)
    }

    // === Network Operations ===

    async fn get_network(&self, id: Uuid) -> Result<Option<Network>> {
        let id_bytes = id.as_bytes().to_vec();
        let row = sqlx::query("SELECT data FROM networks WHERE id = ?")
            .bind(&id_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn put_network(&self, network: &Network) -> Result<()> {
        let id_bytes = network.id.as_bytes().to_vec();
        let json = Self::to_json(network)?;

        sqlx::query(
            "INSERT INTO networks (id, data) VALUES (?, ?) \
             ON CONFLICT(id) DO UPDATE SET data = excluded.data",
        )
        .bind(&id_bytes)
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn list_networks(&self) -> Result<Vec<Network>> {
        let rows = sqlx::query("SELECT data FROM networks")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut networks = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            networks.push(Self::from_json(&json)?);
        }
        Ok(networks)
    }

    async fn delete_network(&self, id: Uuid) -> Result<bool> {
        let id_bytes = id.as_bytes().to_vec();
        let result = sqlx::query("DELETE FROM networks WHERE id = ?")
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    // === User Operations ===

    async fn get_user(&self, id: Uuid) -> Result<Option<User>> {
        let id_bytes = id.as_bytes().to_vec();
        let row = sqlx::query("SELECT data FROM users WHERE id = ?")
            .bind(&id_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query("SELECT data FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match row {
            Some(row) => {
                let json: String = row.get("data");
                Ok(Some(Self::from_json(&json)?))
            }
            None => Ok(None),
        }
    }

    async fn put_user(&self, user: &User) -> Result<()> {
        let id_bytes = user.id.as_bytes().to_vec();
        let json = Self::to_json(user)?;

        sqlx::query(
            "INSERT INTO users (id, username, data) VALUES (?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET username = excluded.username, data = excluded.data",
        )
        .bind(&id_bytes)
        .bind(&user.username)
        .bind(&json)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        let rows =
            sqlx::query("SELECT data FROM users ORDER BY json_extract(data, '$.created_at')")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut users = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            users.push(Self::from_json(&json)?);
        }
        Ok(users)
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool> {
        let id_bytes = id.as_bytes().to_vec();
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(&id_bytes)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }
}
