//! Tests for the v0.1.0 Store trait
//!
//! These tests are written against the Store trait, so they can be run
//! against any implementation (MemoryStore, SqliteStore, EtcdStore).

use super::*;
use dragonfly_common::{
    BmcConfig, BmcType, Disk, HardwareInfo, Machine, MachineConfig, MachineIdentity,
    MachineMetadata, MachineSource, MachineState, MachineStatus, NetworkInterface,
    WorkflowResult,
};
use chrono::Utc;
use dragonfly_crd::{ActionStep, Image2DiskConfig, Template, Workflow};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Create a memory store for testing
fn create_memory_store() -> Arc<dyn Store> {
    Arc::new(MemoryStore::new())
}

/// Create a SQLite store for testing (uses tempdir)
async fn create_sqlite_store() -> Arc<dyn Store> {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.db");
    // Note: we leak the tempdir to keep the file around for the test
    std::mem::forget(tmp);
    Arc::new(SqliteStore::open(&path).await.unwrap())
}

/// Create a test store instance (default: memory)
fn create_test_store() -> Arc<dyn Store> {
    create_memory_store()
}

/// Create a test machine with the given MAC
fn test_machine(mac: &str) -> Machine {
    Machine::new(MachineIdentity::from_mac(mac))
}

/// Create a test machine with multiple MACs
fn test_machine_full(primary_mac: &str, all_macs: Vec<&str>, smbios_uuid: Option<&str>) -> Machine {
    let identity = MachineIdentity::new(
        primary_mac.to_string(),
        all_macs.iter().map(|s| s.to_string()).collect(),
        smbios_uuid.map(|s| s.to_string()),
        None,
        None,
    );
    Machine::new(identity)
}

// ============================================================================
// Machine CRUD Tests
// ============================================================================

#[tokio::test]
async fn test_machine_put_and_get() {
    let store = create_test_store();
    let machine = test_machine("00:11:22:33:44:55");
    let id = machine.id;

    // Put
    store.put_machine(&machine).await.unwrap();

    // Get by UUID
    let retrieved = store.get_machine(id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, id);
    assert_eq!(retrieved.identity.primary_mac, "00:11:22:33:44:55");
}

#[tokio::test]
async fn test_machine_get_not_found() {
    let store = create_test_store();
    let result = store.get_machine(Uuid::now_v7()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_machine_get_by_identity() {
    let store = create_test_store();
    let machine = test_machine_full(
        "00:11:22:33:44:55",
        vec!["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"],
        Some("smbios-uuid-123"),
    );
    let identity_hash = machine.identity.identity_hash.clone();

    store.put_machine(&machine).await.unwrap();

    // Get by identity hash
    let retrieved = store.get_machine_by_identity(&identity_hash).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, machine.id);
}

#[tokio::test]
async fn test_machine_get_by_mac() {
    let store = create_test_store();
    let machine = test_machine("00:11:22:33:44:55");
    let id = machine.id;

    store.put_machine(&machine).await.unwrap();

    // Get by MAC (exact)
    let retrieved = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, id);

    // Get by MAC (normalized from dashes)
    let retrieved = store.get_machine_by_mac("00-11-22-33-44-55").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, id);

    // Get by MAC (uppercase)
    let retrieved = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap();
    assert!(retrieved.is_some());
}

#[tokio::test]
async fn test_machine_update() {
    let store = create_test_store();
    let mut machine = test_machine("00:11:22:33:44:55");
    let id = machine.id;

    store.put_machine(&machine).await.unwrap();

    // Update the machine
    machine.config.hostname = Some("new-hostname".to_string());
    machine.status.state = MachineState::ReadyToInstall;
    store.put_machine(&machine).await.unwrap();

    // Verify update
    let retrieved = store.get_machine(id).await.unwrap().unwrap();
    assert_eq!(retrieved.config.hostname, Some("new-hostname".to_string()));
    assert_eq!(retrieved.status.state, MachineState::ReadyToInstall);
}

#[tokio::test]
async fn test_machine_delete() {
    let store = create_test_store();
    let machine = test_machine("00:11:22:33:44:55");
    let id = machine.id;
    let identity_hash = machine.identity.identity_hash.clone();

    store.put_machine(&machine).await.unwrap();

    // Delete
    let deleted = store.delete_machine(id).await.unwrap();
    assert!(deleted);

    // Verify deleted
    assert!(store.get_machine(id).await.unwrap().is_none());
    assert!(store.get_machine_by_identity(&identity_hash).await.unwrap().is_none());
    assert!(store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap().is_none());
}

#[tokio::test]
async fn test_machine_delete_not_found() {
    let store = create_test_store();
    let deleted = store.delete_machine(Uuid::now_v7()).await.unwrap();
    assert!(!deleted);
}

#[tokio::test]
async fn test_machine_list() {
    let store = create_test_store();

    // Empty list
    let machines = store.list_machines().await.unwrap();
    assert!(machines.is_empty());

    // Add machines
    let m1 = test_machine("00:11:22:33:44:55");
    let m2 = test_machine("aa:bb:cc:dd:ee:ff");
    store.put_machine(&m1).await.unwrap();
    store.put_machine(&m2).await.unwrap();

    let machines = store.list_machines().await.unwrap();
    assert_eq!(machines.len(), 2);
}

// ============================================================================
// Machine Index Tests
// ============================================================================

#[tokio::test]
async fn test_machine_list_by_tag() {
    let store = create_test_store();

    let mut m1 = test_machine("00:11:22:33:44:55");
    m1.config.tags = vec!["production".to_string(), "web".to_string()];

    let mut m2 = test_machine("aa:bb:cc:dd:ee:ff");
    m2.config.tags = vec!["production".to_string(), "database".to_string()];

    let mut m3 = test_machine("11:22:33:44:55:66");
    m3.config.tags = vec!["staging".to_string()];

    store.put_machine(&m1).await.unwrap();
    store.put_machine(&m2).await.unwrap();
    store.put_machine(&m3).await.unwrap();

    // List by tag
    let production = store.list_machines_by_tag("production").await.unwrap();
    assert_eq!(production.len(), 2);

    let web = store.list_machines_by_tag("web").await.unwrap();
    assert_eq!(web.len(), 1);
    assert_eq!(web[0].id, m1.id);

    let staging = store.list_machines_by_tag("staging").await.unwrap();
    assert_eq!(staging.len(), 1);

    let nonexistent = store.list_machines_by_tag("nonexistent").await.unwrap();
    assert!(nonexistent.is_empty());
}

#[tokio::test]
async fn test_machine_list_by_state() {
    let store = create_test_store();

    let mut m1 = test_machine("00:11:22:33:44:55");
    m1.status.state = MachineState::Discovered;

    let mut m2 = test_machine("aa:bb:cc:dd:ee:ff");
    m2.status.state = MachineState::ReadyToInstall;

    let mut m3 = test_machine("11:22:33:44:55:66");
    m3.status.state = MachineState::ReadyToInstall;

    let mut m4 = test_machine("22:33:44:55:66:77");
    m4.status.state = MachineState::Failed {
        message: "test error".to_string(),
    };

    store.put_machine(&m1).await.unwrap();
    store.put_machine(&m2).await.unwrap();
    store.put_machine(&m3).await.unwrap();
    store.put_machine(&m4).await.unwrap();

    let discovered = store.list_machines_by_state(&MachineState::Discovered).await.unwrap();
    assert_eq!(discovered.len(), 1);

    let ready = store.list_machines_by_state(&MachineState::ReadyToInstall).await.unwrap();
    assert_eq!(ready.len(), 2);

    let failed = store
        .list_machines_by_state(&MachineState::Failed {
            message: String::new(),
        })
        .await
        .unwrap();
    assert_eq!(failed.len(), 1);
}

#[tokio::test]
async fn test_machine_index_update_on_state_change() {
    let store = create_test_store();

    let mut machine = test_machine("00:11:22:33:44:55");
    machine.status.state = MachineState::Discovered;
    store.put_machine(&machine).await.unwrap();

    // Verify in discovered state
    let discovered = store.list_machines_by_state(&MachineState::Discovered).await.unwrap();
    assert_eq!(discovered.len(), 1);

    // Change state
    machine.status.state = MachineState::Installing;
    store.put_machine(&machine).await.unwrap();

    // Verify moved to new state
    let discovered = store.list_machines_by_state(&MachineState::Discovered).await.unwrap();
    assert!(discovered.is_empty());

    let installing = store.list_machines_by_state(&MachineState::Installing).await.unwrap();
    assert_eq!(installing.len(), 1);
}

// ============================================================================
// Machine Re-identification Tests
// ============================================================================

#[tokio::test]
async fn test_machine_reidentification_by_hash() {
    let store = create_test_store();

    // First registration
    let machine = test_machine_full(
        "00:11:22:33:44:55",
        vec!["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"],
        Some("smbios-uuid-abc"),
    );
    let original_id = machine.id;
    let identity_hash = machine.identity.identity_hash.clone();

    store.put_machine(&machine).await.unwrap();

    // Simulate machine returning after reboot/reimaging
    // Same identity sources should produce same hash
    let returning_identity = MachineIdentity::new(
        "00:11:22:33:44:55".to_string(),
        vec!["00:11:22:33:44:55".to_string(), "aa:bb:cc:dd:ee:ff".to_string()],
        Some("smbios-uuid-abc".to_string()),
        None,
        None,
    );

    assert_eq!(returning_identity.identity_hash, identity_hash);

    // Should find the existing machine
    let found = store.get_machine_by_identity(&returning_identity.identity_hash).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, original_id);
}

#[tokio::test]
async fn test_machine_reidentification_primary_mac_changed() {
    let store = create_test_store();

    // First registration with two NICs
    let machine = test_machine_full(
        "00:11:22:33:44:55",
        vec!["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"],
        Some("smbios-uuid-xyz"),
    );
    let original_hash = machine.identity.identity_hash.clone();
    store.put_machine(&machine).await.unwrap();

    // Second registration - primary NIC changed, but same identity sources
    // (Same MACs, just different primary)
    let new_identity = MachineIdentity::new(
        "aa:bb:cc:dd:ee:ff".to_string(), // Different primary
        vec!["00:11:22:33:44:55".to_string(), "aa:bb:cc:dd:ee:ff".to_string()],
        Some("smbios-uuid-xyz".to_string()),
        None,
        None,
    );

    // Hash should be the same (MAC order doesn't matter)
    assert_eq!(new_identity.identity_hash, original_hash);

    // Should find by identity hash even though primary MAC changed
    let found = store.get_machine_by_identity(&new_identity.identity_hash).await.unwrap();
    assert!(found.is_some());
}

// ============================================================================
// Template Tests
// ============================================================================

#[tokio::test]
async fn test_template_crud() {
    let store = create_test_store();

    let template = Template::new("debian-13").with_action(ActionStep::Image2disk(Image2DiskConfig {
        url: "http://example.com/debian.raw".to_string(),
        disk: "auto".to_string(),
        checksum: None,
        timeout: Some(1800),
    }));

    // Put
    store.put_template(&template).await.unwrap();

    // Get
    let retrieved = store.get_template("debian-13").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().metadata.name, "debian-13");

    // List
    let templates = store.list_templates().await.unwrap();
    assert_eq!(templates.len(), 1);

    // Delete
    let deleted = store.delete_template("debian-13").await.unwrap();
    assert!(deleted);
    assert!(store.get_template("debian-13").await.unwrap().is_none());
}

#[tokio::test]
async fn test_template_update() {
    let store = create_test_store();

    let mut template = Template::new("ubuntu-2404");
    store.put_template(&template).await.unwrap();

    // Update
    template = template.with_action(ActionStep::Image2disk(Image2DiskConfig {
        url: "http://example.com/ubuntu.raw".to_string(),
        disk: "/dev/sda".to_string(),
        checksum: Some("sha256:abc123".to_string()),
        timeout: None,
    }));
    store.put_template(&template).await.unwrap();

    // Verify update
    let retrieved = store.get_template("ubuntu-2404").await.unwrap().unwrap();
    assert_eq!(retrieved.spec.actions.len(), 1);
}

// ============================================================================
// Workflow Tests
// ============================================================================

#[tokio::test]
async fn test_workflow_crud() {
    let store = create_test_store();

    // Create a machine first
    let machine = test_machine("00:11:22:33:44:55");
    let machine_id = machine.id;
    store.put_machine(&machine).await.unwrap();

    // Create workflow with UUIDv7 as name
    let workflow_id = Uuid::now_v7();
    let mut workflow = Workflow::new(&workflow_id.to_string(), &machine_id.to_string(), "debian-13");

    // Put
    store.put_workflow(&workflow).await.unwrap();

    // Get
    let retrieved = store.get_workflow(workflow_id).await.unwrap();
    assert!(retrieved.is_some());

    // Get by machine
    let for_machine = store.get_workflows_for_machine(machine_id).await.unwrap();
    assert_eq!(for_machine.len(), 1);

    // List
    let all = store.list_workflows().await.unwrap();
    assert_eq!(all.len(), 1);

    // Delete
    let deleted = store.delete_workflow(workflow_id).await.unwrap();
    assert!(deleted);
    assert!(store.get_workflow(workflow_id).await.unwrap().is_none());
    assert!(store.get_workflows_for_machine(machine_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_workflow_multiple_per_machine() {
    let store = create_test_store();

    let machine = test_machine("00:11:22:33:44:55");
    let machine_id = machine.id;
    store.put_machine(&machine).await.unwrap();

    // Create multiple workflows for same machine
    let wf1_id = Uuid::now_v7();
    let wf2_id = Uuid::now_v7();

    let wf1 = Workflow::new(&wf1_id.to_string(), &machine_id.to_string(), "debian-13");
    let wf2 = Workflow::new(&wf2_id.to_string(), &machine_id.to_string(), "ubuntu-2404");

    store.put_workflow(&wf1).await.unwrap();
    store.put_workflow(&wf2).await.unwrap();

    let for_machine = store.get_workflows_for_machine(machine_id).await.unwrap();
    assert_eq!(for_machine.len(), 2);
}

// ============================================================================
// Settings Tests
// ============================================================================

#[tokio::test]
async fn test_settings_crud() {
    let store = create_test_store();

    // Put
    store.put_setting("app.mode", "production").await.unwrap();

    // Get
    let value = store.get_setting("app.mode").await.unwrap();
    assert_eq!(value, Some("production".to_string()));

    // Get not found
    let missing = store.get_setting("nonexistent").await.unwrap();
    assert!(missing.is_none());

    // Update
    store.put_setting("app.mode", "development").await.unwrap();
    let value = store.get_setting("app.mode").await.unwrap();
    assert_eq!(value, Some("development".to_string()));

    // Delete
    let deleted = store.delete_setting("app.mode").await.unwrap();
    assert!(deleted);
    assert!(store.get_setting("app.mode").await.unwrap().is_none());
}

#[tokio::test]
async fn test_default_os_setting_roundtrip() {
    let store = create_test_store();

    // Save default_os exactly as the UI does
    let os_choice = "debian-13";
    store.put_setting("default_os", os_choice).await.unwrap();

    // Read it back exactly as settings_page does
    let default_os = store.get_setting("default_os").await
        .ok().flatten();

    // Verify it's Some("debian-13")
    assert_eq!(default_os, Some("debian-13".to_string()));

    // Verify the comparison logic used in the template works
    assert_eq!(default_os.as_deref(), Some("debian-13"));
    assert!(default_os.as_deref() == Some("debian-13"));
    assert!(!(default_os.is_none()));
}

#[tokio::test]
async fn test_settings_list_by_prefix() {
    let store = create_test_store();

    store.put_setting("proxmox.api_url", "https://pve.local:8006").await.unwrap();
    store.put_setting("proxmox.username", "root@pam").await.unwrap();
    store.put_setting("app.mode", "production").await.unwrap();
    store.put_setting("app.debug", "false").await.unwrap();

    // List by prefix
    let proxmox = store.list_settings("proxmox.").await.unwrap();
    assert_eq!(proxmox.len(), 2);
    assert!(proxmox.contains_key("proxmox.api_url"));
    assert!(proxmox.contains_key("proxmox.username"));

    let app = store.list_settings("app.").await.unwrap();
    assert_eq!(app.len(), 2);

    // Empty prefix returns all
    let all = store.list_settings("").await.unwrap();
    assert_eq!(all.len(), 4);

    // No matches
    let none = store.list_settings("nonexistent.").await.unwrap();
    assert!(none.is_empty());
}

// ============================================================================
// Concurrency Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_machine_operations() {
    let store = create_test_store();

    // Spawn multiple tasks to create machines concurrently
    let mut handles = Vec::new();
    for i in 0..10 {
        let store_clone = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            let mac = format!("00:11:22:33:44:{:02x}", i);
            let machine = test_machine(&mac);
            store_clone.put_machine(&machine).await.unwrap();
            machine.id
        });
        handles.push(handle);
    }

    // Wait for all
    let ids: Vec<Uuid> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Verify all created
    let machines = store.list_machines().await.unwrap();
    assert_eq!(machines.len(), 10);

    // Verify each can be retrieved
    for id in ids {
        assert!(store.get_machine(id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn test_concurrent_read_write() {
    let store = create_test_store();
    let machine = test_machine("00:11:22:33:44:55");
    let id = machine.id;
    store.put_machine(&machine).await.unwrap();

    // Spawn readers and writers concurrently
    let mut handles = Vec::new();

    // Readers
    for _ in 0..5 {
        let store_clone = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let _ = store_clone.get_machine(id).await;
            }
        }));
    }

    // Writers (updating state)
    for i in 0..3 {
        let store_clone = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            for j in 0..50 {
                if let Some(mut m) = store_clone.get_machine(id).await.unwrap() {
                    m.config.hostname = Some(format!("host-{}-{}", i, j));
                    let _ = store_clone.put_machine(&m).await;
                }
            }
        }));
    }

    // Wait for all
    for handle in handles {
        handle.await.unwrap();
    }

    // Machine should still exist and be retrievable
    let final_machine = store.get_machine(id).await.unwrap();
    assert!(final_machine.is_some());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_machine_with_full_hardware_info() {
    let store = create_test_store();

    let mut machine = test_machine("00:11:22:33:44:55");
    machine.hardware = HardwareInfo {
        cpu_model: Some("Intel Xeon E5-2690 v4".to_string()),
        cpu_cores: Some(28),
        cpu_threads: Some(56),
        memory_bytes: Some(128 * 1024 * 1024 * 1024), // 128GB
        disks: vec![
            Disk {
                device: "/dev/sda".to_string(),
                size_bytes: 500 * 1000 * 1000 * 1000,
                model: Some("Samsung 970 EVO".to_string()),
                serial: Some("S1234567890".to_string()),
            },
            Disk {
                device: "/dev/nvme0n1".to_string(),
                size_bytes: 2 * 1000 * 1000 * 1000 * 1000,
                model: Some("Intel P4510".to_string()),
                serial: None,
            },
        ],
        network_interfaces: vec![
            NetworkInterface {
                name: "eth0".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                speed_mbps: Some(10000),
                interface_type: Default::default(),
                members: Vec::new(),
                ip_address: None,
                active: None,
                bond_mode: None,
                mtu: None,
            },
            NetworkInterface {
                name: "eth1".to_string(),
                mac: "00:11:22:33:44:56".to_string(),
                speed_mbps: Some(25000),
                interface_type: Default::default(),
                members: Vec::new(),
                ip_address: None,
                active: None,
                bond_mode: None,
                mtu: None,
            },
        ],
        gpus: vec![],
        is_virtual: false,
        virt_platform: None,
    };

    store.put_machine(&machine).await.unwrap();

    let retrieved = store.get_machine(machine.id).await.unwrap().unwrap();
    assert_eq!(retrieved.hardware.cpu_cores, Some(28));
    assert_eq!(retrieved.hardware.disks.len(), 2);
    assert_eq!(retrieved.hardware.network_interfaces.len(), 2);
    assert!(!retrieved.hardware.is_virtual);
}

#[tokio::test]
async fn test_machine_with_bmc() {
    let store = create_test_store();

    let mut machine = test_machine("00:11:22:33:44:55");
    machine.config.bmc = Some(BmcConfig {
        address: "192.168.1.100".to_string(),
        username: "admin".to_string(),
        password_encrypted: "encrypted:abc123".to_string(),
        bmc_type: BmcType::Ipmi,
    });

    store.put_machine(&machine).await.unwrap();

    let retrieved = store.get_machine(machine.id).await.unwrap().unwrap();
    assert!(retrieved.config.bmc.is_some());
    let bmc = retrieved.config.bmc.unwrap();
    assert_eq!(bmc.address, "192.168.1.100");
    assert_eq!(bmc.bmc_type, BmcType::Ipmi);
}

#[tokio::test]
async fn test_machine_from_proxmox() {
    let store = create_test_store();

    let identity = MachineIdentity::from_mac("aa:bb:cc:dd:ee:ff");
    let machine = Machine::from_proxmox(
        identity,
        "main-cluster".to_string(),
        "pve-node1".to_string(),
        100,
    );

    store.put_machine(&machine).await.unwrap();

    let retrieved = store.get_machine(machine.id).await.unwrap().unwrap();
    assert!(retrieved.hardware.is_virtual);
    assert_eq!(retrieved.hardware.virt_platform, Some("proxmox".to_string()));

    if let MachineSource::Proxmox { cluster, node, vmid } = &retrieved.metadata.source {
        assert_eq!(cluster, "main-cluster");
        assert_eq!(node, "pve-node1");
        assert_eq!(*vmid, 100);
    } else {
        panic!("Expected Proxmox source");
    }
}

#[tokio::test]
async fn test_machine_labels() {
    let store = create_test_store();

    let mut machine = test_machine("00:11:22:33:44:55");
    machine.metadata.labels.insert("env".to_string(), "production".to_string());
    machine.metadata.labels.insert("role".to_string(), "web-server".to_string());
    machine.metadata.labels.insert("team".to_string(), "platform".to_string());

    store.put_machine(&machine).await.unwrap();

    let retrieved = store.get_machine(machine.id).await.unwrap().unwrap();
    assert_eq!(retrieved.metadata.labels.len(), 3);
    assert_eq!(retrieved.metadata.labels.get("env"), Some(&"production".to_string()));
}

#[tokio::test]
async fn test_machine_workflow_result() {
    let store = create_test_store();

    let mut machine = test_machine("00:11:22:33:44:55");
    machine.status.last_workflow_result = Some(WorkflowResult::Success {
        completed_at: Utc::now(),
    });

    store.put_machine(&machine).await.unwrap();

    let retrieved = store.get_machine(machine.id).await.unwrap().unwrap();
    assert!(matches!(
        retrieved.status.last_workflow_result,
        Some(WorkflowResult::Success { .. })
    ));

    // Update with failure
    machine.status.last_workflow_result = Some(WorkflowResult::Failed {
        error: "Disk write failed".to_string(),
        failed_at: Utc::now(),
    });
    store.put_machine(&machine).await.unwrap();

    let retrieved = store.get_machine(machine.id).await.unwrap().unwrap();
    if let Some(WorkflowResult::Failed { error, .. }) = &retrieved.status.last_workflow_result {
        assert_eq!(error, "Disk write failed");
    } else {
        panic!("Expected Failed workflow result");
    }
}

// ============================================================================
// SQLite-Specific Tests
// ============================================================================
// These tests verify that SqliteStore behaves identically to MemoryStore

#[tokio::test]
async fn test_sqlite_machine_crud() {
    let store = create_sqlite_store().await;
    let machine = test_machine("00:11:22:33:44:55");
    let id = machine.id;

    // Put
    store.put_machine(&machine).await.unwrap();

    // Get by UUID
    let retrieved = store.get_machine(id).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, id);

    // Get by MAC
    let by_mac = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap();
    assert!(by_mac.is_some());

    // Get by identity
    let by_identity = store
        .get_machine_by_identity(&machine.identity.identity_hash)
        .await
        .unwrap();
    assert!(by_identity.is_some());

    // List
    let all = store.list_machines().await.unwrap();
    assert_eq!(all.len(), 1);

    // Delete
    let deleted = store.delete_machine(id).await.unwrap();
    assert!(deleted);
    assert!(store.get_machine(id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_sqlite_machine_indices() {
    let store = create_sqlite_store().await;

    let mut m1 = test_machine("00:11:22:33:44:55");
    m1.config.tags = vec!["production".to_string(), "web".to_string()];
    m1.status.state = MachineState::ReadyToInstall;

    let mut m2 = test_machine("aa:bb:cc:dd:ee:ff");
    m2.config.tags = vec!["staging".to_string()];
    m2.status.state = MachineState::Discovered;

    store.put_machine(&m1).await.unwrap();
    store.put_machine(&m2).await.unwrap();

    // Tag index
    let production = store.list_machines_by_tag("production").await.unwrap();
    assert_eq!(production.len(), 1);

    // State index
    let ready_to_install = store.list_machines_by_state(&MachineState::ReadyToInstall).await.unwrap();
    assert_eq!(ready_to_install.len(), 1);
    assert_eq!(ready_to_install[0].id, m1.id);
}

#[tokio::test]
async fn test_sqlite_template_crud() {
    let store = create_sqlite_store().await;

    let template = Template::new("debian-13").with_action(ActionStep::Image2disk(Image2DiskConfig {
        url: "http://example.com/debian.raw".to_string(),
        disk: "auto".to_string(),
        checksum: None,
        timeout: Some(1800),
    }));

    store.put_template(&template).await.unwrap();

    let retrieved = store.get_template("debian-13").await.unwrap();
    assert!(retrieved.is_some());

    let all = store.list_templates().await.unwrap();
    assert_eq!(all.len(), 1);

    let deleted = store.delete_template("debian-13").await.unwrap();
    assert!(deleted);
}

#[tokio::test]
async fn test_sqlite_workflow_crud() {
    let store = create_sqlite_store().await;

    let machine = test_machine("00:11:22:33:44:55");
    let machine_id = machine.id;
    store.put_machine(&machine).await.unwrap();

    let workflow_id = Uuid::now_v7();
    let workflow = Workflow::new(&workflow_id.to_string(), &machine_id.to_string(), "debian-13");

    store.put_workflow(&workflow).await.unwrap();

    let retrieved = store.get_workflow(workflow_id).await.unwrap();
    assert!(retrieved.is_some());

    let for_machine = store.get_workflows_for_machine(machine_id).await.unwrap();
    assert_eq!(for_machine.len(), 1);

    let deleted = store.delete_workflow(workflow_id).await.unwrap();
    assert!(deleted);
}

#[tokio::test]
async fn test_sqlite_settings_crud() {
    let store = create_sqlite_store().await;

    store.put_setting("proxmox.api_url", "https://pve.local:8006").await.unwrap();
    store.put_setting("proxmox.username", "root@pam").await.unwrap();
    store.put_setting("app.mode", "production").await.unwrap();

    let value = store.get_setting("proxmox.api_url").await.unwrap();
    assert_eq!(value, Some("https://pve.local:8006".to_string()));

    let proxmox = store.list_settings("proxmox.").await.unwrap();
    assert_eq!(proxmox.len(), 2);

    let deleted = store.delete_setting("app.mode").await.unwrap();
    assert!(deleted);
}

#[tokio::test]
async fn test_sqlite_machine_update_preserves_indices() {
    let store = create_sqlite_store().await;

    let mut machine = test_machine("00:11:22:33:44:55");
    machine.config.tags = vec!["production".to_string()];
    machine.status.state = MachineState::Discovered;
    store.put_machine(&machine).await.unwrap();

    // Verify initial state
    let discovered = store.list_machines_by_state(&MachineState::Discovered).await.unwrap();
    assert_eq!(discovered.len(), 1);

    // Update state
    machine.status.state = MachineState::Installing;
    machine.config.tags = vec!["staging".to_string()]; // Change tags too
    store.put_machine(&machine).await.unwrap();

    // Old indices should be cleaned up
    let discovered = store.list_machines_by_state(&MachineState::Discovered).await.unwrap();
    assert!(discovered.is_empty());
    let production = store.list_machines_by_tag("production").await.unwrap();
    assert!(production.is_empty());

    // New indices should be populated
    let installing = store.list_machines_by_state(&MachineState::Installing).await.unwrap();
    assert_eq!(installing.len(), 1);
    let staging = store.list_machines_by_tag("staging").await.unwrap();
    assert_eq!(staging.len(), 1);
}
