//! In-memory storage backend for v0.1.0 schema
//!
//! Simple storage for testing and development.
//! Uses RwLock for thread-safe access with minimal contention.

use super::{Result, Store, StoreError, User};
use async_trait::async_trait;
use dragonfly_common::{DnsRecord, DnsRecordSource, DnsRecordType, Machine, MachineState, Network, normalize_mac};
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
    networks: RwLock<HashMap<Uuid, Network>>,
    users: RwLock<HashMap<Uuid, User>>,
    standalone_tags: RwLock<HashSet<String>>,
    dns_records: RwLock<HashMap<Uuid, DnsRecord>>,

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

    // User indices
    /// username -> user UUID
    users_by_username: RwLock<HashMap<String, Uuid>>,
}

impl MemoryStore {
    /// Create a new empty memory store
    pub fn new() -> Self {
        Self {
            machines: RwLock::new(HashMap::new()),
            templates: RwLock::new(HashMap::new()),
            workflows: RwLock::new(HashMap::new()),
            settings: RwLock::new(HashMap::new()),
            networks: RwLock::new(HashMap::new()),
            users: RwLock::new(HashMap::new()),
            standalone_tags: RwLock::new(HashSet::new()),
            dns_records: RwLock::new(HashMap::new()),
            identity_index: RwLock::new(HashMap::new()),
            mac_index: RwLock::new(HashMap::new()),
            ip_index: RwLock::new(HashMap::new()),
            tag_index: RwLock::new(HashMap::new()),
            state_index: RwLock::new(HashMap::new()),
            workflow_by_machine: RwLock::new(HashMap::new()),
            users_by_username: RwLock::new(HashMap::new()),
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
        // Collect old tags before updating
        let old_tags: Vec<String> = {
            let guard = Self::read_lock(&self.machines)?;
            guard
                .get(&machine.id)
                .map(|m| m.config.tags.clone())
                .unwrap_or_default()
        };

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

        // Sync standalone_tags: ensure new tags exist
        {
            let mut tags = Self::write_lock(&self.standalone_tags)?;
            for tag in &machine.config.tags {
                tags.insert(tag.clone());
            }
        }

        // Clean up orphaned tags that were on this machine but no longer on any machine
        let new_tags: HashSet<&String> = machine.config.tags.iter().collect();
        for old_tag in &old_tags {
            if new_tags.contains(old_tag) {
                continue;
            }
            // Check if any other machine still has this tag
            let tag_index = Self::read_lock(&self.tag_index)?;
            let still_used = tag_index.get(old_tag).map_or(false, |s| !s.is_empty());
            drop(tag_index);
            if !still_used {
                let mut tags = Self::write_lock(&self.standalone_tags)?;
                tags.remove(old_tag);
            }
        }

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
        let machine = {
            let guard = Self::read_lock(&self.machines)?;
            guard.get(&id).cloned()
        };

        if let Some(machine) = machine {
            let machine_tags = machine.config.tags.clone();

            // Remove from indices
            self.remove_machine_from_indices(&machine)?;

            // Remove from primary storage
            {
                let mut guard = Self::write_lock(&self.machines)?;
                guard.remove(&id);
            }

            // Clean up orphaned tags from this machine
            let tag_index = Self::read_lock(&self.tag_index)?;
            let orphans: Vec<String> = machine_tags
                .iter()
                .filter(|t| tag_index.get(*t).map_or(true, |s| s.is_empty()))
                .cloned()
                .collect();
            drop(tag_index);

            if !orphans.is_empty() {
                let mut tags = Self::write_lock(&self.standalone_tags)?;
                for orphan in orphans {
                    tags.remove(&orphan);
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    // === Tag Operations ===

    async fn create_tag(&self, name: &str) -> Result<bool> {
        let mut tags = Self::write_lock(&self.standalone_tags)?;
        Ok(tags.insert(name.to_string()))
    }

    async fn list_all_tags(&self) -> Result<Vec<String>> {
        let tags = Self::read_lock(&self.standalone_tags)?;
        let mut sorted: Vec<String> = tags.iter().cloned().collect();
        sorted.sort();
        Ok(sorted)
    }

    async fn delete_tag(&self, tag: &str) -> Result<bool> {
        let mut standalone = Self::write_lock(&self.standalone_tags)?;
        let removed_standalone = standalone.remove(tag);
        drop(standalone);

        let mut machines = Self::write_lock(&self.machines)?;
        let mut removed_from_machines = false;
        for machine in machines.values_mut() {
            if machine.config.tags.contains(&tag.to_string()) {
                machine.config.tags.retain(|t| t != tag);
                removed_from_machines = true;
            }
        }

        // Also clean tag_index
        {
            let mut tag_index = Self::write_lock(&self.tag_index)?;
            tag_index.remove(tag);
        }

        Ok(removed_standalone || removed_from_machines)
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
        let machine_id = Uuid::parse_str(&workflow.spec.hardware_ref).map_err(|e| {
            StoreError::InvalidData(format!("Invalid machine UUID in workflow: {}", e))
        })?;

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

    // === Network Operations ===

    async fn get_network(&self, id: Uuid) -> Result<Option<Network>> {
        let guard = Self::read_lock(&self.networks)?;
        Ok(guard.get(&id).cloned())
    }

    async fn put_network(&self, network: &Network) -> Result<()> {
        let mut guard = Self::write_lock(&self.networks)?;
        guard.insert(network.id, network.clone());
        Ok(())
    }

    async fn list_networks(&self) -> Result<Vec<Network>> {
        let guard = Self::read_lock(&self.networks)?;
        Ok(guard.values().cloned().collect())
    }

    async fn delete_network(&self, id: Uuid) -> Result<bool> {
        let mut guard = Self::write_lock(&self.networks)?;
        Ok(guard.remove(&id).is_some())
    }

    // === User Operations ===

    async fn get_user(&self, id: Uuid) -> Result<Option<User>> {
        let guard = Self::read_lock(&self.users)?;
        Ok(guard.get(&id).cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let index = Self::read_lock(&self.users_by_username)?;
        if let Some(&id) = index.get(username) {
            drop(index); // Release index lock before acquiring users lock
            let guard = Self::read_lock(&self.users)?;
            Ok(guard.get(&id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn put_user(&self, user: &User) -> Result<()> {
        // If updating existing user with changed username, remove old index
        let old_username = {
            let guard = Self::read_lock(&self.users)?;
            guard.get(&user.id).and_then(|existing| {
                if existing.username != user.username {
                    Some(existing.username.clone())
                } else {
                    None
                }
            })
        };

        if let Some(old) = old_username {
            let mut index = Self::write_lock(&self.users_by_username)?;
            index.remove(&old);
        }

        // Insert/update the user
        {
            let mut guard = Self::write_lock(&self.users)?;
            guard.insert(user.id, user.clone());
        }

        // Update username index
        {
            let mut index = Self::write_lock(&self.users_by_username)?;
            index.insert(user.username.clone(), user.id);
        }

        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        let guard = Self::read_lock(&self.users)?;
        let mut users: Vec<User> = guard.values().cloned().collect();
        // Sort by created_at for consistent ordering
        users.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(users)
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool> {
        // Get the user first to clean up index
        let user = {
            let guard = Self::read_lock(&self.users)?;
            guard.get(&id).cloned()
        };

        if let Some(user) = user {
            // Remove from username index
            {
                let mut index = Self::write_lock(&self.users_by_username)?;
                index.remove(&user.username);
            }

            // Remove from primary storage
            {
                let mut guard = Self::write_lock(&self.users)?;
                guard.remove(&id);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    // === DNS Record Operations ===

    async fn list_dns_records(&self, zone: &str) -> Result<Vec<DnsRecord>> {
        let guard = Self::read_lock(&self.dns_records)?;
        let mut records: Vec<DnsRecord> = guard
            .values()
            .filter(|r| r.zone == zone)
            .cloned()
            .collect();
        records.sort_by(|a, b| (&a.name, &a.rtype).partial_cmp(&(&b.name, &b.rtype)).unwrap_or(std::cmp::Ordering::Equal));
        Ok(records)
    }

    async fn get_dns_records(
        &self,
        zone: &str,
        name: &str,
        rtype: Option<DnsRecordType>,
    ) -> Result<Vec<DnsRecord>> {
        let guard = Self::read_lock(&self.dns_records)?;
        Ok(guard
            .values()
            .filter(|r| {
                r.zone == zone
                    && r.name == name
                    && rtype.map_or(true, |rt| r.rtype == rt)
            })
            .cloned()
            .collect())
    }

    async fn put_dns_record(&self, record: &DnsRecord) -> Result<()> {
        let mut guard = Self::write_lock(&self.dns_records)?;
        guard.insert(record.id, record.clone());
        Ok(())
    }

    async fn delete_dns_record(&self, id: Uuid) -> Result<bool> {
        let mut guard = Self::write_lock(&self.dns_records)?;
        Ok(guard.remove(&id).is_some())
    }

    async fn delete_dns_records_by_machine(&self, machine_id: Uuid) -> Result<u64> {
        let mut guard = Self::write_lock(&self.dns_records)?;
        let to_remove: Vec<Uuid> = guard
            .values()
            .filter(|r| r.machine_id == Some(machine_id))
            .map(|r| r.id)
            .collect();
        let count = to_remove.len() as u64;
        for id in to_remove {
            guard.remove(&id);
        }
        Ok(count)
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
        let mut guard = Self::write_lock(&self.dns_records)?;
        let now = chrono::Utc::now();

        // Find existing record by (zone, name, rtype, rdata)
        let existing_id = guard
            .values()
            .find(|r| r.zone == zone && r.name == name && r.rtype == rtype && r.rdata == rdata)
            .map(|r| r.id);

        if let Some(id) = existing_id {
            if let Some(record) = guard.get_mut(&id) {
                record.ttl = ttl;
                record.source = source;
                record.machine_id = machine_id;
                record.updated_at = now;
            }
        } else {
            let record = DnsRecord {
                id: uuid::Uuid::now_v7(),
                zone: zone.to_string(),
                name: name.to_string(),
                rtype,
                rdata: rdata.to_string(),
                ttl,
                source,
                machine_id,
                created_at: now,
                updated_at: now,
            };
            guard.insert(record.id, record);
        }

        Ok(())
    }
}
