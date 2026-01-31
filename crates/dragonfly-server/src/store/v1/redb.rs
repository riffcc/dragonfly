//! ReDB storage backend for v0.1.0 schema
//!
//! Persistent storage using ReDB embedded database.
//! Uses JSON serialization for complex types.
//!
//! ## Table Structure
//!
//! ```text
//! machines          : UUID (bytes) -> Machine (JSON)
//! machines_by_mac   : MAC (string) -> UUID (bytes)
//! machines_by_identity : identity_hash (string) -> UUID (bytes)
//! machines_by_tag   : (tag, UUID) -> ()
//! machines_by_state : (state, UUID) -> ()
//!
//! templates         : name (string) -> Template (JSON)
//! workflows         : UUID (bytes) -> Workflow (JSON)
//! workflows_by_machine : (machine_id, workflow_id) -> ()
//!
//! settings          : key (string) -> value (string)
//! ```

use super::{Result, Store, StoreError};
use crate::store::types::{normalize_mac, Machine, MachineState};
use async_trait::async_trait;
use dragonfly_crd::{Template, Workflow};
use redb::{Database, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

// Table definitions
const MACHINES: TableDefinition<&[u8; 16], &str> = TableDefinition::new("machines_v1");
const MACHINES_BY_MAC: TableDefinition<&str, &[u8; 16]> = TableDefinition::new("machines_by_mac_v1");
const MACHINES_BY_IP: TableDefinition<&str, &[u8; 16]> = TableDefinition::new("machines_by_ip_v1");
const MACHINES_BY_IDENTITY: TableDefinition<&str, &[u8; 16]> = TableDefinition::new("machines_by_identity_v1");
const MACHINES_BY_TAG: MultimapTableDefinition<&str, &[u8; 16]> = MultimapTableDefinition::new("machines_by_tag_v1");
const MACHINES_BY_STATE: MultimapTableDefinition<&str, &[u8; 16]> = MultimapTableDefinition::new("machines_by_state_v1");

const TEMPLATES: TableDefinition<&str, &str> = TableDefinition::new("templates_v1");

const WORKFLOWS: TableDefinition<&[u8; 16], &str> = TableDefinition::new("workflows_v1");
const WORKFLOWS_BY_MACHINE: MultimapTableDefinition<&[u8; 16], &[u8; 16]> = MultimapTableDefinition::new("workflows_by_machine_v1");

const SETTINGS: TableDefinition<&str, &str> = TableDefinition::new("settings_v1");

/// ReDB storage backend implementing the v0.1.0 schema.
pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    /// Open or create a ReDB database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::create(path).map_err(|e| StoreError::Database(e.to_string()))?;

        // Create all tables on first open
        let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
        {
            let _ = write_txn.open_table(MACHINES);
            let _ = write_txn.open_table(MACHINES_BY_MAC);
            let _ = write_txn.open_table(MACHINES_BY_IP);
            let _ = write_txn.open_table(MACHINES_BY_IDENTITY);
            let _ = write_txn.open_multimap_table(MACHINES_BY_TAG);
            let _ = write_txn.open_multimap_table(MACHINES_BY_STATE);
            let _ = write_txn.open_table(TEMPLATES);
            let _ = write_txn.open_table(WORKFLOWS);
            let _ = write_txn.open_multimap_table(WORKFLOWS_BY_MACHINE);
            let _ = write_txn.open_table(SETTINGS);
        }
        write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Helper to convert UUID to fixed byte array for storage
    fn uuid_to_bytes(id: Uuid) -> [u8; 16] {
        *id.as_bytes()
    }

    /// Helper to convert byte array back to UUID
    fn bytes_to_uuid(bytes: &[u8; 16]) -> Uuid {
        Uuid::from_bytes(*bytes)
    }

    /// Serialize a value to JSON
    fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
        serde_json::to_string(value).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    /// Deserialize a value from JSON
    fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
        serde_json::from_str(json).map_err(|e| StoreError::Serialization(e.to_string()))
    }
}

#[async_trait]
impl Store for RedbStore {
    // === Machine Operations ===

    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>> {
        let db = Arc::clone(&self.db);
        let id_bytes = Self::uuid_to_bytes(id);

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;

            match table.get(&id_bytes) {
                Ok(Some(access)) => {
                    let json = access.value();
                    let machine: Machine = Self::from_json(json)?;
                    Ok(Some(machine))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(StoreError::Database(e.to_string())),
            }
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>> {
        let db = Arc::clone(&self.db);
        let identity_hash = identity_hash.to_string();

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;

            // Look up UUID by identity hash
            let index = read_txn
                .open_table(MACHINES_BY_IDENTITY)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            let id_bytes = match index.get(identity_hash.as_str()) {
                Ok(Some(access)) => *access.value(),
                Ok(None) => return Ok(None),
                Err(e) => return Err(StoreError::Database(e.to_string())),
            };

            // Get the machine
            let table = read_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;
            match table.get(&id_bytes) {
                Ok(Some(access)) => {
                    let machine: Machine = Self::from_json(access.value())?;
                    Ok(Some(machine))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(StoreError::Database(e.to_string())),
            }
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn get_machine_by_mac(&self, mac: &str) -> Result<Option<Machine>> {
        let db = Arc::clone(&self.db);
        let normalized = normalize_mac(mac);

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;

            // Look up UUID by MAC
            let index = read_txn
                .open_table(MACHINES_BY_MAC)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            let id_bytes = match index.get(normalized.as_str()) {
                Ok(Some(access)) => *access.value(),
                Ok(None) => return Ok(None),
                Err(e) => return Err(StoreError::Database(e.to_string())),
            };

            // Get the machine
            let table = read_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;
            match table.get(&id_bytes) {
                Ok(Some(access)) => {
                    let machine: Machine = Self::from_json(access.value())?;
                    Ok(Some(machine))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(StoreError::Database(e.to_string())),
            }
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn get_machine_by_ip(&self, ip: &str) -> Result<Option<Machine>> {
        let db = Arc::clone(&self.db);
        let ip = ip.to_string();

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;

            // Look up UUID by IP
            let index = read_txn
                .open_table(MACHINES_BY_IP)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            let id_bytes = match index.get(ip.as_str()) {
                Ok(Some(access)) => *access.value(),
                Ok(None) => return Ok(None),
                Err(e) => return Err(StoreError::Database(e.to_string())),
            };

            // Get the machine
            let table = read_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;
            match table.get(&id_bytes) {
                Ok(Some(access)) => {
                    let machine: Machine = Self::from_json(access.value())?;
                    Ok(Some(machine))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(StoreError::Database(e.to_string())),
            }
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn put_machine(&self, machine: &Machine) -> Result<()> {
        let db = Arc::clone(&self.db);
        let machine = machine.clone();

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
            let id_bytes = Self::uuid_to_bytes(machine.id);

            // Check for existing machine to clean up old indices
            {
                let table = write_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;
                if let Ok(Some(access)) = table.get(&id_bytes) {
                    let old_machine: Machine = Self::from_json(access.value())?;

                    // Clean up old MAC index
                    let mut mac_index = write_txn
                        .open_table(MACHINES_BY_MAC)
                        .map_err(|e| StoreError::Database(e.to_string()))?;
                    let _ = mac_index.remove(old_machine.identity.primary_mac.as_str());

                    // Clean up old IP index
                    if let Some(ref old_ip) = old_machine.status.current_ip {
                        let mut ip_index = write_txn
                            .open_table(MACHINES_BY_IP)
                            .map_err(|e| StoreError::Database(e.to_string()))?;
                        let _ = ip_index.remove(old_ip.as_str());
                    }

                    // Clean up old identity index
                    let mut identity_index = write_txn
                        .open_table(MACHINES_BY_IDENTITY)
                        .map_err(|e| StoreError::Database(e.to_string()))?;
                    let _ = identity_index.remove(old_machine.identity.identity_hash.as_str());

                    // Clean up old tag indices
                    let mut tag_table = write_txn
                        .open_multimap_table(MACHINES_BY_TAG)
                        .map_err(|e| StoreError::Database(e.to_string()))?;
                    for tag in &old_machine.config.tags {
                        let _ = tag_table.remove(tag.as_str(), &id_bytes);
                    }

                    // Clean up old state index
                    let mut state_table = write_txn
                        .open_multimap_table(MACHINES_BY_STATE)
                        .map_err(|e| StoreError::Database(e.to_string()))?;
                    let _ = state_table.remove(old_machine.status.state.as_str(), &id_bytes);
                }
            }

            // Insert the machine
            {
                let mut table = write_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;
                let json = Self::to_json(&machine)?;
                table
                    .insert(&id_bytes, json.as_str())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            // Update MAC index
            {
                let mut index = write_txn
                    .open_table(MACHINES_BY_MAC)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                index
                    .insert(machine.identity.primary_mac.as_str(), &id_bytes)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            // Update IP index (if IP is known)
            if let Some(ref ip) = machine.status.current_ip {
                let mut index = write_txn
                    .open_table(MACHINES_BY_IP)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                index
                    .insert(ip.as_str(), &id_bytes)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            // Update identity index
            {
                let mut index = write_txn
                    .open_table(MACHINES_BY_IDENTITY)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                index
                    .insert(machine.identity.identity_hash.as_str(), &id_bytes)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            // Update tag indices
            {
                let mut table = write_txn
                    .open_multimap_table(MACHINES_BY_TAG)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                for tag in &machine.config.tags {
                    table
                        .insert(tag.as_str(), &id_bytes)
                        .map_err(|e| StoreError::Database(e.to_string()))?;
                }
            }

            // Update state index
            {
                let mut table = write_txn
                    .open_multimap_table(MACHINES_BY_STATE)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                table
                    .insert(machine.status.state.as_str(), &id_bytes)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn list_machines(&self) -> Result<Vec<Machine>> {
        let db = Arc::clone(&self.db);

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;

            let mut machines = Vec::new();
            for entry in table.iter().map_err(|e| StoreError::Database(e.to_string()))? {
                let (_, value) = entry.map_err(|e| StoreError::Database(e.to_string()))?;
                let machine: Machine = Self::from_json(value.value())?;
                machines.push(machine);
            }

            Ok(machines)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn list_machines_by_tag(&self, tag: &str) -> Result<Vec<Machine>> {
        let db = Arc::clone(&self.db);
        let tag = tag.to_string();

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let tag_table = read_txn
                .open_multimap_table(MACHINES_BY_TAG)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let machines_table = read_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;

            let mut machines = Vec::new();
            if let Ok(values) = tag_table.get(tag.as_str()) {
                for entry in values {
                    let entry_guard = entry.map_err(|e| StoreError::Database(e.to_string()))?;
                    let id_bytes = entry_guard.value();
                    if let Ok(Some(access)) = machines_table.get(&id_bytes) {
                        let machine: Machine = Self::from_json(access.value())?;
                        machines.push(machine);
                    }
                }
            }

            Ok(machines)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn list_machines_by_state(&self, state: &MachineState) -> Result<Vec<Machine>> {
        let db = Arc::clone(&self.db);
        let state_key = state.as_str().to_string();

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let state_table = read_txn
                .open_multimap_table(MACHINES_BY_STATE)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let machines_table = read_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;

            let mut machines = Vec::new();
            if let Ok(values) = state_table.get(state_key.as_str()) {
                for entry in values {
                    let entry_guard = entry.map_err(|e| StoreError::Database(e.to_string()))?;
                    let id_bytes = entry_guard.value();
                    if let Ok(Some(access)) = machines_table.get(&id_bytes) {
                        let machine: Machine = Self::from_json(access.value())?;
                        machines.push(machine);
                    }
                }
            }

            Ok(machines)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn delete_machine(&self, id: Uuid) -> Result<bool> {
        let db = Arc::clone(&self.db);
        let id_bytes = Self::uuid_to_bytes(id);

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;

            // Get existing machine for index cleanup
            let machine: Option<Machine> = {
                let table = write_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;
                match table.get(&id_bytes) {
                    Ok(Some(access)) => Some(Self::from_json(access.value())?),
                    Ok(None) => None,
                    Err(e) => return Err(StoreError::Database(e.to_string())),
                }
            };

            let Some(machine) = machine else {
                return Ok(false);
            };

            // Remove from MAC index
            {
                let mut index = write_txn
                    .open_table(MACHINES_BY_MAC)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                let _ = index.remove(machine.identity.primary_mac.as_str());
            }

            // Remove from IP index
            if let Some(ref ip) = machine.status.current_ip {
                let mut index = write_txn
                    .open_table(MACHINES_BY_IP)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                let _ = index.remove(ip.as_str());
            }

            // Remove from identity index
            {
                let mut index = write_txn
                    .open_table(MACHINES_BY_IDENTITY)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                let _ = index.remove(machine.identity.identity_hash.as_str());
            }

            // Remove from tag indices
            {
                let mut table = write_txn
                    .open_multimap_table(MACHINES_BY_TAG)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                for tag in &machine.config.tags {
                    let _ = table.remove(tag.as_str(), &id_bytes);
                }
            }

            // Remove from state index
            {
                let mut table = write_txn
                    .open_multimap_table(MACHINES_BY_STATE)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                let _ = table.remove(machine.status.state.as_str(), &id_bytes);
            }

            // Remove from main table
            {
                let mut table = write_txn.open_table(MACHINES).map_err(|e| StoreError::Database(e.to_string()))?;
                table.remove(&id_bytes).map_err(|e| StoreError::Database(e.to_string()))?;
            }

            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(true)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    // === Template Operations ===

    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        let db = Arc::clone(&self.db);
        let name = name.to_string();

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(TEMPLATES).map_err(|e| StoreError::Database(e.to_string()))?;

            match table.get(name.as_str()) {
                Ok(Some(access)) => {
                    let template: Template = Self::from_json(access.value())?;
                    Ok(Some(template))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(StoreError::Database(e.to_string())),
            }
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn put_template(&self, template: &Template) -> Result<()> {
        let db = Arc::clone(&self.db);
        let template = template.clone();

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
            {
                let mut table = write_txn.open_table(TEMPLATES).map_err(|e| StoreError::Database(e.to_string()))?;
                let json = Self::to_json(&template)?;
                table
                    .insert(template.metadata.name.as_str(), json.as_str())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn list_templates(&self) -> Result<Vec<Template>> {
        let db = Arc::clone(&self.db);

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(TEMPLATES).map_err(|e| StoreError::Database(e.to_string()))?;

            let mut templates = Vec::new();
            for entry in table.iter().map_err(|e| StoreError::Database(e.to_string()))? {
                let (_, value) = entry.map_err(|e| StoreError::Database(e.to_string()))?;
                let template: Template = Self::from_json(value.value())?;
                templates.push(template);
            }

            Ok(templates)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn delete_template(&self, name: &str) -> Result<bool> {
        let db = Arc::clone(&self.db);
        let name = name.to_string();

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
            let deleted = {
                let mut table = write_txn.open_table(TEMPLATES).map_err(|e| StoreError::Database(e.to_string()))?;
                table
                    .remove(name.as_str())
                    .map_err(|e| StoreError::Database(e.to_string()))?
                    .is_some()
            };
            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(deleted)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    // === Workflow Operations ===

    async fn get_workflow(&self, id: Uuid) -> Result<Option<Workflow>> {
        let db = Arc::clone(&self.db);
        let id_bytes = Self::uuid_to_bytes(id);

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(WORKFLOWS).map_err(|e| StoreError::Database(e.to_string()))?;

            match table.get(&id_bytes) {
                Ok(Some(access)) => {
                    let workflow: Workflow = Self::from_json(access.value())?;
                    Ok(Some(workflow))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(StoreError::Database(e.to_string())),
            }
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn get_workflows_for_machine(&self, machine_id: Uuid) -> Result<Vec<Workflow>> {
        let db = Arc::clone(&self.db);
        let machine_id_bytes = Self::uuid_to_bytes(machine_id);

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let index = read_txn
                .open_multimap_table(WORKFLOWS_BY_MACHINE)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let workflows_table = read_txn.open_table(WORKFLOWS).map_err(|e| StoreError::Database(e.to_string()))?;

            let mut workflows = Vec::new();
            if let Ok(values) = index.get(&machine_id_bytes) {
                for entry in values {
                    let entry_guard = entry.map_err(|e| StoreError::Database(e.to_string()))?;
                    let wf_id_bytes = entry_guard.value();
                    if let Ok(Some(access)) = workflows_table.get(&wf_id_bytes) {
                        let workflow: Workflow = Self::from_json(access.value())?;
                        workflows.push(workflow);
                    }
                }
            }

            Ok(workflows)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn put_workflow(&self, workflow: &Workflow) -> Result<()> {
        let db = Arc::clone(&self.db);
        let workflow = workflow.clone();

        // Parse workflow ID and machine ID from the workflow
        let workflow_id = Uuid::parse_str(&workflow.metadata.name)
            .map_err(|e| StoreError::InvalidData(format!("Invalid workflow UUID: {}", e)))?;
        let machine_id = Uuid::parse_str(&workflow.spec.hardware_ref)
            .map_err(|e| StoreError::InvalidData(format!("Invalid machine UUID in workflow: {}", e)))?;

        let wf_id_bytes = Self::uuid_to_bytes(workflow_id);
        let machine_id_bytes = Self::uuid_to_bytes(machine_id);

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;

            // Insert workflow
            {
                let mut table = write_txn.open_table(WORKFLOWS).map_err(|e| StoreError::Database(e.to_string()))?;
                let json = Self::to_json(&workflow)?;
                table
                    .insert(&wf_id_bytes, json.as_str())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            // Update machine index
            {
                let mut index = write_txn
                    .open_multimap_table(WORKFLOWS_BY_MACHINE)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                index
                    .insert(&machine_id_bytes, &wf_id_bytes)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        let db = Arc::clone(&self.db);

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(WORKFLOWS).map_err(|e| StoreError::Database(e.to_string()))?;

            let mut workflows = Vec::new();
            for entry in table.iter().map_err(|e| StoreError::Database(e.to_string()))? {
                let (_, value) = entry.map_err(|e| StoreError::Database(e.to_string()))?;
                let workflow: Workflow = Self::from_json(value.value())?;
                workflows.push(workflow);
            }

            Ok(workflows)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn delete_workflow(&self, id: Uuid) -> Result<bool> {
        let db = Arc::clone(&self.db);
        let id_bytes = Self::uuid_to_bytes(id);

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;

            // Get workflow for machine index cleanup
            let workflow: Option<Workflow> = {
                let table = write_txn.open_table(WORKFLOWS).map_err(|e| StoreError::Database(e.to_string()))?;
                match table.get(&id_bytes) {
                    Ok(Some(access)) => Some(Self::from_json(access.value())?),
                    Ok(None) => None,
                    Err(e) => return Err(StoreError::Database(e.to_string())),
                }
            };

            let Some(workflow) = workflow else {
                return Ok(false);
            };

            // Remove from machine index
            if let Ok(machine_id) = Uuid::parse_str(&workflow.spec.hardware_ref) {
                let machine_id_bytes = Self::uuid_to_bytes(machine_id);
                let mut index = write_txn
                    .open_multimap_table(WORKFLOWS_BY_MACHINE)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                let _ = index.remove(&machine_id_bytes, &id_bytes);
            }

            // Remove from main table
            {
                let mut table = write_txn.open_table(WORKFLOWS).map_err(|e| StoreError::Database(e.to_string()))?;
                table.remove(&id_bytes).map_err(|e| StoreError::Database(e.to_string()))?;
            }

            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(true)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    // === Settings Operations ===

    async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let db = Arc::clone(&self.db);
        let key = key.to_string();

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(SETTINGS).map_err(|e| StoreError::Database(e.to_string()))?;

            match table.get(key.as_str()) {
                Ok(Some(access)) => Ok(Some(access.value().to_string())),
                Ok(None) => Ok(None),
                Err(e) => Err(StoreError::Database(e.to_string())),
            }
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        let db = Arc::clone(&self.db);
        let key = key.to_string();
        let value = value.to_string();

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
            {
                let mut table = write_txn.open_table(SETTINGS).map_err(|e| StoreError::Database(e.to_string()))?;
                table
                    .insert(key.as_str(), value.as_str())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn delete_setting(&self, key: &str) -> Result<bool> {
        let db = Arc::clone(&self.db);
        let key = key.to_string();

        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
            let deleted = {
                let mut table = write_txn.open_table(SETTINGS).map_err(|e| StoreError::Database(e.to_string()))?;
                table
                    .remove(key.as_str())
                    .map_err(|e| StoreError::Database(e.to_string()))?
                    .is_some()
            };
            write_txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(deleted)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }

    async fn list_settings(&self, prefix: &str) -> Result<HashMap<String, String>> {
        let db = Arc::clone(&self.db);
        let prefix = prefix.to_string();

        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = read_txn.open_table(SETTINGS).map_err(|e| StoreError::Database(e.to_string()))?;

            let mut settings: HashMap<String, String> = HashMap::new();
            for entry in table.iter().map_err(|e| StoreError::Database(e.to_string()))? {
                let (key, value) = entry.map_err(|e: redb::StorageError| StoreError::Database(e.to_string()))?;
                let key_str: &str = key.value();
                if key_str.starts_with(&prefix) {
                    settings.insert(key_str.to_string(), value.value().to_string());
                }
            }

            Ok(settings)
        })
        .await
        .map_err(|e| StoreError::Database(format!("Task join error: {}", e)))?
    }
}
