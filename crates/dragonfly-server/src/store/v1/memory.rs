//! In-memory storage backend for v0.1.0 schema
//!
//! Simple storage for testing and development.
//! Uses RwLock for thread-safe access with minimal contention.

use super::{Result, Store, StoreError};
use async_trait::async_trait;
use dragonfly_common::{normalize_mac, Machine, MachineState};
use dragonfly_crd::{Template, Workflow};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use uuid::Uuid;

/// In-memory storage backend implementing the v0.1.0 schema.
///
/// Maintains indices for efficient lookups:
/// - By UUID (primary key)
/// - By identity hash (for re-identification)
/// - By MAC address (legacy compatibility)
/// - By tag (for grouping)
/// - By state (for filtering)
pub struct MemoryStore {
    // Primary storage
    machines: RwLock<HashMap<Uuid, Machine>>,
    templates: RwLock<HashMap<String, Template>>,
    workflows: RwLock<HashMap<Uuid, Workflow>>,
    settings: RwLock<HashMap<String, String>>,

    // Machine indices
    /// identity_hash -> machine UUID
    identity_index: RwLock<HashMap<String, Uuid>>,
    /// MAC address (normalized) -> machine UUID
    mac_index: RwLock<HashMap<String, Uuid>>,
    /// IP address -> machine UUID
    ip_index: RwLock<HashMap<String, Uuid>>,
    /// tag -> set of machine UUIDs
    tag_index: RwLock<HashMap<String, HashSet<Uuid>>>,
    /// state key -> set of machine UUIDs
    state_index: RwLock<HashMap<String, HashSet<Uuid>>>,

    // Workflow indices
    /// machine_id -> set of workflow UUIDs
    workflow_by_machine: RwLock<HashMap<Uuid, HashSet<Uuid>>>,
}

impl MemoryStore {
    /// Create a new empty memory store
    pub fn new() -> Self {
        Self {
            machines: RwLock::new(HashMap::new()),
            templates: RwLock::new(HashMap::new()),
            workflows: RwLock::new(HashMap::new()),
            settings: RwLock::new(HashMap::new()),
            identity_index: RwLock::new(HashMap::new()),
            mac_index: RwLock::new(HashMap::new()),
            ip_index: RwLock::new(HashMap::new()),
            tag_index: RwLock::new(HashMap::new()),
            state_index: RwLock::new(HashMap::new()),
            workflow_by_machine: RwLock::new(HashMap::new()),
        }
    }

    /// Helper to acquire write lock with error conversion
    fn write_lock<T>(lock: &RwLock<T>) -> Result<std::sync::RwLockWriteGuard<'_, T>> {
        lock.write()
            .map_err(|e| StoreError::Lock(format!("write lock poisoned: {}", e)))
    }

    /// Helper to acquire read lock with error conversion
    fn read_lock<T>(lock: &RwLock<T>) -> Result<std::sync::RwLockReadGuard<'_, T>> {
        lock.read()
            .map_err(|e| StoreError::Lock(format!("read lock poisoned: {}", e)))
    }

    /// Update all machine indices when storing a machine
    fn update_machine_indices(&self, machine: &Machine) -> Result<()> {
        let id = machine.id;

        // Identity index
        {
            let mut index = Self::write_lock(&self.identity_index)?;
            index.insert(machine.identity.identity_hash.clone(), id);
        }

        // MAC index (primary MAC only)
        {
            let mut index = Self::write_lock(&self.mac_index)?;
            index.insert(machine.identity.primary_mac.clone(), id);
        }

        // IP index (if IP is known)
        if let Some(ref ip) = machine.status.current_ip {
            let mut index = Self::write_lock(&self.ip_index)?;
            index.insert(ip.clone(), id);
        }

        // Tag index
        {
            let mut index = Self::write_lock(&self.tag_index)?;
            for tag in &machine.config.tags {
                index.entry(tag.clone()).or_default().insert(id);
            }
        }

        // State index
        {
            let mut index = Self::write_lock(&self.state_index)?;
            let state_key = machine.status.state.as_str().to_string();
            index.entry(state_key).or_default().insert(id);
        }

        Ok(())
    }

    /// Remove machine from all indices
    fn remove_machine_from_indices(&self, machine: &Machine) -> Result<()> {
        let id = machine.id;

        // Identity index
        {
            let mut index = Self::write_lock(&self.identity_index)?;
            index.remove(&machine.identity.identity_hash);
        }

        // MAC index
        {
            let mut index = Self::write_lock(&self.mac_index)?;
            index.remove(&machine.identity.primary_mac);
        }

        // IP index
        if let Some(ref ip) = machine.status.current_ip {
            let mut index = Self::write_lock(&self.ip_index)?;
            index.remove(ip);
        }

        // Tag index - remove from all tags
        {
            let mut index = Self::write_lock(&self.tag_index)?;
            for tag in &machine.config.tags {
                if let Some(set) = index.get_mut(tag) {
                    set.remove(&id);
                    if set.is_empty() {
                        index.remove(tag);
                    }
                }
            }
        }

        // State index
        {
            let mut index = Self::write_lock(&self.state_index)?;
            let state_key = machine.status.state.as_str().to_string();
            if let Some(set) = index.get_mut(&state_key) {
                set.remove(&id);
                if set.is_empty() {
                    index.remove(&state_key);
                }
            }
        }

        Ok(())
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Store for MemoryStore {
    // === Machine Operations ===

    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>> {
        let guard = Self::read_lock(&self.machines)?;
        Ok(guard.get(&id).cloned())
    }

    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>> {
        let index = Self::read_lock(&self.identity_index)?;
        if let Some(&id) = index.get(identity_hash) {
            drop(index); // Release index lock before acquiring machines lock
            let guard = Self::read_lock(&self.machines)?;
            Ok(guard.get(&id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_machine_by_mac(&self, mac: &str) -> Result<Option<Machine>> {
        let normalized = normalize_mac(mac);
        let index = Self::read_lock(&self.mac_index)?;
        if let Some(&id) = index.get(&normalized) {
            drop(index); // Release index lock before acquiring machines lock
            let guard = Self::read_lock(&self.machines)?;
            Ok(guard.get(&id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_machine_by_ip(&self, ip: &str) -> Result<Option<Machine>> {
        let index = Self::read_lock(&self.ip_index)?;
        if let Some(&id) = index.get(ip) {
            drop(index); // Release index lock before acquiring machines lock
            let guard = Self::read_lock(&self.machines)?;
            Ok(guard.get(&id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn put_machine(&self, machine: &Machine) -> Result<()> {
        // If updating existing machine, remove old index entries first
        let existing = {
            let guard = Self::read_lock(&self.machines)?;
            guard.get(&machine.id).cloned()
        };

        if let Some(ref existing) = existing {
            self.remove_machine_from_indices(existing)?;
        }

        // Insert/update the machine
        {
            let mut guard = Self::write_lock(&self.machines)?;
            guard.insert(machine.id, machine.clone());
        }

        // Update indices
        self.update_machine_indices(machine)?;

        Ok(())
    }

    async fn list_machines(&self) -> Result<Vec<Machine>> {
        let guard = Self::read_lock(&self.machines)?;
        Ok(guard.values().cloned().collect())
    }

    async fn list_machines_by_tag(&self, tag: &str) -> Result<Vec<Machine>> {
        let tag_index = Self::read_lock(&self.tag_index)?;
        let ids: Vec<Uuid> = tag_index
            .get(tag)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        drop(tag_index);

        let machines = Self::read_lock(&self.machines)?;
        Ok(ids
            .iter()
            .filter_map(|id| machines.get(id).cloned())
            .collect())
    }

    async fn list_machines_by_state(&self, state: &MachineState) -> Result<Vec<Machine>> {
        let state_key = state.as_str().to_string();
        let state_index = Self::read_lock(&self.state_index)?;
        let ids: Vec<Uuid> = state_index
            .get(&state_key)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        drop(state_index);

        let machines = Self::read_lock(&self.machines)?;
        Ok(ids
            .iter()
            .filter_map(|id| machines.get(id).cloned())
            .collect())
    }

    async fn delete_machine(&self, id: Uuid) -> Result<bool> {
        // Get the machine first to clean up indices
        let machine = {
            let guard = Self::read_lock(&self.machines)?;
            guard.get(&id).cloned()
        };

        if let Some(machine) = machine {
            // Remove from indices
            self.remove_machine_from_indices(&machine)?;

            // Remove from primary storage
            let mut guard = Self::write_lock(&self.machines)?;
            guard.remove(&id);

            Ok(true)
        } else {
            Ok(false)
        }
    }

    // === Template Operations ===

    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        let guard = Self::read_lock(&self.templates)?;
        Ok(guard.get(name).cloned())
    }

    async fn put_template(&self, template: &Template) -> Result<()> {
        let name = template.metadata.name.clone();
        let mut guard = Self::write_lock(&self.templates)?;
        guard.insert(name, template.clone());
        Ok(())
    }

    async fn list_templates(&self) -> Result<Vec<Template>> {
        let guard = Self::read_lock(&self.templates)?;
        Ok(guard.values().cloned().collect())
    }

    async fn delete_template(&self, name: &str) -> Result<bool> {
        let mut guard = Self::write_lock(&self.templates)?;
        Ok(guard.remove(name).is_some())
    }

    // === Workflow Operations ===

    async fn get_workflow(&self, id: Uuid) -> Result<Option<Workflow>> {
        let guard = Self::read_lock(&self.workflows)?;
        Ok(guard.get(&id).cloned())
    }

    async fn get_workflows_for_machine(&self, machine_id: Uuid) -> Result<Vec<Workflow>> {
        let index = Self::read_lock(&self.workflow_by_machine)?;
        let ids: Vec<Uuid> = index
            .get(&machine_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        drop(index);

        let workflows = Self::read_lock(&self.workflows)?;
        Ok(ids
            .iter()
            .filter_map(|id| workflows.get(id).cloned())
            .collect())
    }

    async fn put_workflow(&self, workflow: &Workflow) -> Result<()> {
        // Parse workflow name as UUID (workflows use UUIDv7 as name in v0.1.0)
        let id = Uuid::parse_str(&workflow.metadata.name)
            .map_err(|e| StoreError::InvalidData(format!("Invalid workflow UUID: {}", e)))?;

        // Parse machine reference as UUID
        let machine_id = Uuid::parse_str(&workflow.spec.hardware_ref)
            .map_err(|e| StoreError::InvalidData(format!("Invalid machine UUID in workflow: {}", e)))?;

        // Insert workflow
        {
            let mut guard = Self::write_lock(&self.workflows)?;
            guard.insert(id, workflow.clone());
        }

        // Update machine index
        {
            let mut index = Self::write_lock(&self.workflow_by_machine)?;
            index.entry(machine_id).or_default().insert(id);
        }

        Ok(())
    }

    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        let guard = Self::read_lock(&self.workflows)?;
        Ok(guard.values().cloned().collect())
    }

    async fn delete_workflow(&self, id: Uuid) -> Result<bool> {
        // Get workflow to find machine reference for index cleanup
        let workflow = {
            let guard = Self::read_lock(&self.workflows)?;
            guard.get(&id).cloned()
        };

        if let Some(workflow) = workflow {
            // Remove from machine index
            if let Ok(machine_id) = Uuid::parse_str(&workflow.spec.hardware_ref) {
                let mut index = Self::write_lock(&self.workflow_by_machine)?;
                if let Some(set) = index.get_mut(&machine_id) {
                    set.remove(&id);
                    if set.is_empty() {
                        index.remove(&machine_id);
                    }
                }
            }

            // Remove from primary storage
            let mut guard = Self::write_lock(&self.workflows)?;
            guard.remove(&id);

            Ok(true)
        } else {
            Ok(false)
        }
    }

    // === Settings Operations ===

    async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let guard = Self::read_lock(&self.settings)?;
        Ok(guard.get(key).cloned())
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        let mut guard = Self::write_lock(&self.settings)?;
        guard.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn delete_setting(&self, key: &str) -> Result<bool> {
        let mut guard = Self::write_lock(&self.settings)?;
        Ok(guard.remove(key).is_some())
    }

    async fn list_settings(&self, prefix: &str) -> Result<HashMap<String, String>> {
        let guard = Self::read_lock(&self.settings)?;
        Ok(guard
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}
