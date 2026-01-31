//! Store contract tests - TDD specification for Dragonfly v0.1.0 data layer
//!
//! These tests define the expected behavior of ANY DragonflyStore implementation.
//! Write tests first, then implement to make them pass.
//!
//! # Identity Model
//!
//! - Machine ID is a UUIDv7, generated ONCE at first registration
//! - Associated identifiers (MAC, SMBIOS UUID, machine-id) help find/recognize the machine
//! - Any associated identifier can be used for lookup
//! - New identifiers can be associated later (e.g., agent reports machine-id post-install)

use super::*;
use chrono::Utc;
use std::sync::Arc;

/// Helper to create a test store - will test both Memory and ReDB
async fn create_test_stores() -> Vec<(&'static str, Arc<dyn DragonflyStore>)> {
    let mut stores: Vec<(&'static str, Arc<dyn DragonflyStore>)> = vec![
        ("memory", Arc::new(MemoryStore::new())),
    ];

    // Add ReDB store with temp directory
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let redb_path = tmp.path().join("test.redb");
    // Leak the tempdir so it lives for the test duration
    let _tmp = Box::leak(Box::new(tmp));
    if let Ok(store) = RedbStore::open(&redb_path) {
        stores.push(("redb", Arc::new(store)));
    }

    stores
}

// =============================================================================
// MACHINE IDENTITY TESTS
// =============================================================================

#[tokio::test]
async fn test_machine_register_generates_uuidv7() {
    for (name, store) in create_test_stores().await {
        let mac = "aa:bb:cc:dd:ee:ff";
        let machine_id = store.register_machine_by_mac(mac, "192.168.1.100").await
            .expect(&format!("{}: register should succeed", name));

        // Should be a valid UUIDv7 (version 7, variant 1)
        assert_eq!(machine_id.get_version_num(), 7, "{}: should be UUIDv7", name);

        // Fetch it back - ID should match
        let machine = store.get_machine(&machine_id).await.unwrap().unwrap();
        assert_eq!(machine.id, machine_id, "{}: stored ID should match", name);
    }
}

#[tokio::test]
async fn test_machine_register_same_mac_returns_same_id() {
    for (name, store) in create_test_stores().await {
        let mac = "11:22:33:44:55:66";

        // First registration
        let id1 = store.register_machine_by_mac(mac, "10.0.0.1").await.unwrap();

        // Same MAC registers again (reboot, new IP)
        let id2 = store.register_machine_by_mac(mac, "10.0.0.2").await.unwrap();

        // SAME machine ID - the UUIDv7 is stable
        assert_eq!(id1, id2, "{}: same MAC should return same machine ID", name);

        // IP should be updated on the interface
        let machine = store.get_machine(&id1).await.unwrap().unwrap();
        let primary = machine.interfaces.iter().find(|i| i.is_primary).unwrap();
        assert_eq!(primary.ip, Some("10.0.0.2".to_string()), "{}: IP should update", name);
    }
}

#[tokio::test]
async fn test_machine_register_with_smbios_uuid() {
    for (name, store) in create_test_stores().await {
        let mac = "aa:00:bb:11:cc:22";
        let smbios = Uuid::new_v4(); // Pretend this came from hardware

        // Register with SMBIOS UUID
        let id = store.register_machine(RegisterRequest {
            smbios_uuid: Some(smbios),
            machine_id: None,
            mac_address: mac.to_string(),
            ip_address: "10.0.0.1".to_string(),
        }).await.expect(&format!("{}: register should succeed", name));

        // Machine should have SMBIOS stored
        let machine = store.get_machine(&id).await.unwrap().unwrap();
        assert_eq!(machine.smbios_uuid, Some(smbios), "{}: SMBIOS should be stored", name);

        // Should be findable by SMBIOS
        let found = store.get_machine_by_smbios(&smbios).await.unwrap();
        assert!(found.is_some(), "{}: should find by SMBIOS", name);
        assert_eq!(found.unwrap().id, id);
    }
}

#[tokio::test]
async fn test_machine_smbios_takes_precedence_over_mac() {
    for (name, store) in create_test_stores().await {
        let smbios = Uuid::new_v4();
        let mac1 = "dd:dd:dd:dd:dd:01";
        let mac2 = "dd:dd:dd:dd:dd:02"; // Different MAC, same SMBIOS

        // Register with MAC1
        let id1 = store.register_machine(RegisterRequest {
            smbios_uuid: Some(smbios),
            machine_id: None,
            mac_address: mac1.to_string(),
            ip_address: "10.0.0.1".to_string(),
        }).await.unwrap();

        // Register with MAC2 but SAME SMBIOS (NIC was replaced)
        let id2 = store.register_machine(RegisterRequest {
            smbios_uuid: Some(smbios),
            machine_id: None,
            mac_address: mac2.to_string(),
            ip_address: "10.0.0.2".to_string(),
        }).await.unwrap();

        // Should be the SAME machine (SMBIOS matched)
        assert_eq!(id1, id2, "{}: same SMBIOS should return same machine", name);

        // Machine should now have BOTH MACs
        let machine = store.get_machine(&id1).await.unwrap().unwrap();
        let macs: Vec<_> = machine.interfaces.iter().map(|i| i.mac.as_str()).collect();
        assert!(macs.contains(&mac1), "{}: should have first MAC", name);
        assert!(macs.contains(&mac2), "{}: should have second MAC", name);
    }
}

#[tokio::test]
async fn test_machine_associate_machine_id_post_install() {
    for (name, store) in create_test_stores().await {
        let mac = "ee:ee:ee:ee:ee:ee";

        // Initial registration during PXE (no machine-id yet)
        let id = store.register_machine_by_mac(mac, "10.0.0.1").await.unwrap();

        let machine = store.get_machine(&id).await.unwrap().unwrap();
        assert!(machine.machine_id.is_none(), "{}: initially no machine-id", name);

        // Agent checks in post-install with machine-id
        let os_machine_id = "a1b2c3d4e5f6";
        store.associate_machine_id(&id, os_machine_id).await
            .expect(&format!("{}: associate should succeed", name));

        // Now should be findable by machine-id
        let found = store.get_machine_by_machine_id(os_machine_id).await.unwrap();
        assert!(found.is_some(), "{}: should find by machine-id", name);
        assert_eq!(found.unwrap().id, id);

        // Machine record should have it stored
        let machine = store.get_machine(&id).await.unwrap().unwrap();
        assert_eq!(machine.machine_id, Some(os_machine_id.to_string()));
    }
}

// =============================================================================
// MACHINE LOOKUP TESTS
// =============================================================================

#[tokio::test]
async fn test_machine_lookup_by_mac_normalizes() {
    for (name, store) in create_test_stores().await {
        let mac = "de:ad:be:ef:00:01";
        let id = store.register_machine_by_mac(mac, "1.2.3.4").await.unwrap();

        // Exact match
        assert!(store.get_machine_by_mac("de:ad:be:ef:00:01").await.unwrap().is_some());

        // Uppercase
        assert!(store.get_machine_by_mac("DE:AD:BE:EF:00:01").await.unwrap().is_some(),
            "{}: should find with uppercase", name);

        // Dashes instead of colons
        assert!(store.get_machine_by_mac("de-ad-be-ef-00-01").await.unwrap().is_some(),
            "{}: should find with dashes", name);

        // No separators
        assert!(store.get_machine_by_mac("deadbeef0001").await.unwrap().is_some(),
            "{}: should find without separators", name);

        // Unknown
        assert!(store.get_machine_by_mac("ff:ff:ff:ff:ff:ff").await.unwrap().is_none());
    }
}

#[tokio::test]
async fn test_machine_lookup_by_ip() {
    for (name, store) in create_test_stores().await {
        let id = store.register_machine_by_mac("aa:aa:aa:aa:aa:aa", "192.168.50.100").await.unwrap();

        let found = store.get_machine_by_ip("192.168.50.100").await.unwrap();
        assert!(found.is_some(), "{}: should find by IP", name);
        assert_eq!(found.unwrap().id, id);

        // Unknown IP
        assert!(store.get_machine_by_ip("10.10.10.10").await.unwrap().is_none());
    }
}

#[tokio::test]
async fn test_machine_list_all() {
    for (name, store) in create_test_stores().await {
        assert!(store.list_machines().await.unwrap().is_empty());

        store.register_machine_by_mac("01:01:01:01:01:01", "1.1.1.1").await.unwrap();
        store.register_machine_by_mac("02:02:02:02:02:02", "2.2.2.2").await.unwrap();
        store.register_machine_by_mac("03:03:03:03:03:03", "3.3.3.3").await.unwrap();

        let all = store.list_machines().await.unwrap();
        assert_eq!(all.len(), 3, "{}: should have 3 machines", name);
    }
}

// =============================================================================
// MACHINE DELETE TESTS
// =============================================================================

#[tokio::test]
async fn test_machine_delete_removes_all_indexes() {
    for (name, store) in create_test_stores().await {
        let smbios = Uuid::new_v4();
        let mac = "bb:bb:bb:bb:bb:bb";
        let ip = "5.5.5.5";

        let id = store.register_machine(RegisterRequest {
            smbios_uuid: Some(smbios),
            machine_id: None,
            mac_address: mac.to_string(),
            ip_address: ip.to_string(),
        }).await.unwrap();

        // Associate machine-id too
        store.associate_machine_id(&id, "test-machine-id").await.unwrap();

        // Verify all lookups work
        assert!(store.get_machine(&id).await.unwrap().is_some());
        assert!(store.get_machine_by_mac(mac).await.unwrap().is_some());
        assert!(store.get_machine_by_ip(ip).await.unwrap().is_some());
        assert!(store.get_machine_by_smbios(&smbios).await.unwrap().is_some());
        assert!(store.get_machine_by_machine_id("test-machine-id").await.unwrap().is_some());

        // Delete
        let deleted = store.delete_machine(&id).await.unwrap();
        assert!(deleted, "{}: should return true", name);

        // ALL lookups should fail
        assert!(store.get_machine(&id).await.unwrap().is_none(),
            "{}: ID lookup should fail", name);
        assert!(store.get_machine_by_mac(mac).await.unwrap().is_none(),
            "{}: MAC lookup should fail", name);
        assert!(store.get_machine_by_ip(ip).await.unwrap().is_none(),
            "{}: IP lookup should fail", name);
        assert!(store.get_machine_by_smbios(&smbios).await.unwrap().is_none(),
            "{}: SMBIOS lookup should fail", name);
        assert!(store.get_machine_by_machine_id("test-machine-id").await.unwrap().is_none(),
            "{}: machine-id lookup should fail", name);

        // Delete again should return false
        assert!(!store.delete_machine(&id).await.unwrap());
    }
}

// =============================================================================
// MEMORABLE NAME TESTS
// =============================================================================

#[tokio::test]
async fn test_memorable_name_from_primary_mac() {
    for (name, store) in create_test_stores().await {
        let mac = "00:11:22:33:44:55";
        let id = store.register_machine_by_mac(mac, "1.2.3.4").await.unwrap();

        let machine = store.get_machine(&id).await.unwrap().unwrap();

        // Memorable name should be generated from MAC
        let expected = dragonfly_common::mac_to_words::mac_to_words_safe(mac);
        assert_eq!(machine.memorable_name, expected,
            "{}: memorable name should match mac_to_words", name);

        // Name defaults to memorable name
        assert_eq!(machine.name, machine.memorable_name,
            "{}: name should default to memorable_name", name);
    }
}

#[tokio::test]
async fn test_memorable_name_stable_across_registrations() {
    for (name, store) in create_test_stores().await {
        let mac = "aa:bb:cc:dd:ee:ff";

        let id = store.register_machine_by_mac(mac, "1.1.1.1").await.unwrap();
        let name1 = store.get_machine(&id).await.unwrap().unwrap().memorable_name;

        // Re-register (reboot)
        store.register_machine_by_mac(mac, "2.2.2.2").await.unwrap();
        let name2 = store.get_machine(&id).await.unwrap().unwrap().memorable_name;

        assert_eq!(name1, name2, "{}: memorable name should be stable", name);
    }
}

#[tokio::test]
async fn test_name_can_be_renamed() {
    for (name, store) in create_test_stores().await {
        let id = store.register_machine_by_mac("ff:ee:dd:cc:bb:aa", "1.1.1.1").await.unwrap();

        // Rename
        store.rename_machine(&id, "prod-database-01").await
            .expect(&format!("{}: rename should succeed", name));

        let machine = store.get_machine(&id).await.unwrap().unwrap();
        assert_eq!(machine.name, "prod-database-01");
        // Memorable name unchanged
        assert_ne!(machine.memorable_name, "prod-database-01");
    }
}

// =============================================================================
// MACHINE STATUS TESTS
// =============================================================================

#[tokio::test]
async fn test_machine_initial_status_is_discovered() {
    for (name, store) in create_test_stores().await {
        let id = store.register_machine_by_mac("cc:cc:cc:cc:cc:cc", "6.6.6.6").await.unwrap();
        let machine = store.get_machine(&id).await.unwrap().unwrap();

        assert_eq!(machine.status, MachineStatus::Discovered,
            "{}: initial status should be Discovered", name);
    }
}

#[tokio::test]
async fn test_machine_status_transitions() {
    for (name, store) in create_test_stores().await {
        let id = store.register_machine_by_mac("dd:dd:dd:dd:dd:dd", "7.7.7.7").await.unwrap();

        // Discovered -> Pending (template assigned)
        store.update_machine_status(&id, MachineStatus::Pending).await.unwrap();
        assert_eq!(store.get_machine(&id).await.unwrap().unwrap().status, MachineStatus::Pending);

        // Pending -> Installing
        store.update_machine_status(&id, MachineStatus::Installing).await.unwrap();
        assert_eq!(store.get_machine(&id).await.unwrap().unwrap().status, MachineStatus::Installing);

        // Installing -> Ready
        store.update_machine_status(&id, MachineStatus::Ready).await.unwrap();
        assert_eq!(store.get_machine(&id).await.unwrap().unwrap().status, MachineStatus::Ready);
    }
}

#[tokio::test]
async fn test_machine_filter_by_status() {
    for (name, store) in create_test_stores().await {
        let id1 = store.register_machine_by_mac("e1:e1:e1:e1:e1:e1", "1.0.0.1").await.unwrap();
        let id2 = store.register_machine_by_mac("e2:e2:e2:e2:e2:e2", "1.0.0.2").await.unwrap();
        let id3 = store.register_machine_by_mac("e3:e3:e3:e3:e3:e3", "1.0.0.3").await.unwrap();

        store.update_machine_status(&id2, MachineStatus::Installing).await.unwrap();
        store.update_machine_status(&id3, MachineStatus::Ready).await.unwrap();

        let discovered = store.get_machines_by_status(MachineStatus::Discovered).await.unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].id, id1);

        let installing = store.get_machines_by_status(MachineStatus::Installing).await.unwrap();
        assert_eq!(installing.len(), 1);
        assert_eq!(installing[0].id, id2);
    }
}

// =============================================================================
// MULTI-INTERFACE TESTS
// =============================================================================

#[tokio::test]
async fn test_machine_add_interface() {
    for (name, store) in create_test_stores().await {
        let mac1 = "f1:f1:f1:f1:f1:f1";
        let mac2 = "f2:f2:f2:f2:f2:f2";

        let id = store.register_machine_by_mac(mac1, "10.0.0.1").await.unwrap();

        // Add second interface
        store.add_machine_interface(&id, mac2, Some("10.0.0.2")).await
            .expect(&format!("{}: add interface should succeed", name));

        let machine = store.get_machine(&id).await.unwrap().unwrap();
        assert_eq!(machine.interfaces.len(), 2, "{}: should have 2 interfaces", name);

        // Both MACs find the same machine
        assert_eq!(store.get_machine_by_mac(mac1).await.unwrap().unwrap().id, id);
        assert_eq!(store.get_machine_by_mac(mac2).await.unwrap().unwrap().id, id);
    }
}

#[tokio::test]
async fn test_machine_remove_interface() {
    for (name, store) in create_test_stores().await {
        let mac1 = "a1:a1:a1:a1:a1:a1";
        let mac2 = "a2:a2:a2:a2:a2:a2";

        let id = store.register_machine_by_mac(mac1, "10.0.0.1").await.unwrap();
        store.add_machine_interface(&id, mac2, Some("10.0.0.2")).await.unwrap();

        // Remove second interface
        store.remove_machine_interface(&id, mac2).await.unwrap();

        let machine = store.get_machine(&id).await.unwrap().unwrap();
        assert_eq!(machine.interfaces.len(), 1);

        // Second MAC no longer finds it
        assert!(store.get_machine_by_mac(mac2).await.unwrap().is_none());
        // First still works
        assert!(store.get_machine_by_mac(mac1).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn test_machine_cannot_remove_primary_interface() {
    for (name, store) in create_test_stores().await {
        let mac = "b1:b1:b1:b1:b1:b1";
        let id = store.register_machine_by_mac(mac, "10.0.0.1").await.unwrap();

        // Try to remove primary (only) interface - should fail
        let result = store.remove_machine_interface(&id, mac).await;
        assert!(result.is_err(), "{}: should not allow removing primary interface", name);
    }
}

// =============================================================================
// TAG TESTS
// =============================================================================

#[tokio::test]
async fn test_tag_crud() {
    for (name, store) in create_test_stores().await {
        // Create
        assert!(store.create_tag("production").await.unwrap());
        assert!(store.create_tag("database").await.unwrap());

        // Duplicate returns false
        assert!(!store.create_tag("production").await.unwrap());

        // List
        let tags = store.list_tags().await.unwrap();
        assert_eq!(tags.len(), 2);

        // Delete
        assert!(store.delete_tag("production").await.unwrap());
        assert_eq!(store.list_tags().await.unwrap().len(), 1);

        // Delete non-existent
        assert!(!store.delete_tag("nonexistent").await.unwrap());
    }
}

#[tokio::test]
async fn test_machine_tags() {
    for (name, store) in create_test_stores().await {
        let id = store.register_machine_by_mac("c1:c1:c1:c1:c1:c1", "1.1.1.1").await.unwrap();

        // Initially empty
        assert!(store.get_machine_tags(&id).await.unwrap().is_empty());

        // Set tags
        store.set_machine_tags(&id, &["web", "prod"]).await.unwrap();
        let tags = store.get_machine_tags(&id).await.unwrap();
        assert_eq!(tags.len(), 2);

        // Tags auto-created
        let all_tags = store.list_tags().await.unwrap();
        assert!(all_tags.contains(&"web".to_string()));

        // Find by tag
        let web_machines = store.get_machines_by_tag("web").await.unwrap();
        assert_eq!(web_machines.len(), 1);
        assert_eq!(web_machines[0].id, id);

        // Replace tags
        store.set_machine_tags(&id, &["staging"]).await.unwrap();
        assert_eq!(store.get_machine_tags(&id).await.unwrap(), vec!["staging"]);

        // Old tag no longer finds it
        assert!(store.get_machines_by_tag("web").await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn test_delete_tag_removes_from_machines() {
    for (name, store) in create_test_stores().await {
        let id1 = store.register_machine_by_mac("d1:d1:d1:d1:d1:d1", "1.1.1.1").await.unwrap();
        let id2 = store.register_machine_by_mac("d2:d2:d2:d2:d2:d2", "2.2.2.2").await.unwrap();

        store.set_machine_tags(&id1, &["shared"]).await.unwrap();
        store.set_machine_tags(&id2, &["shared", "other"]).await.unwrap();

        // Delete shared tag globally
        store.delete_tag("shared").await.unwrap();

        // Removed from both machines
        assert!(store.get_machine_tags(&id1).await.unwrap().is_empty());
        assert_eq!(store.get_machine_tags(&id2).await.unwrap(), vec!["other"]);
    }
}

// =============================================================================
// SETTINGS TESTS
// =============================================================================

#[tokio::test]
async fn test_settings_crud() {
    for (name, store) in create_test_stores().await {
        // Non-existent
        assert!(store.get_setting("nonexistent").await.unwrap().is_none());

        // Set
        store.put_setting("default_template", "ubuntu-2404").await.unwrap();
        assert_eq!(store.get_setting("default_template").await.unwrap(), Some("ubuntu-2404".to_string()));

        // Update
        store.put_setting("default_template", "debian-13").await.unwrap();
        assert_eq!(store.get_setting("default_template").await.unwrap(), Some("debian-13".to_string()));

        // Delete
        store.delete_setting("default_template").await.unwrap();
        assert!(store.get_setting("default_template").await.unwrap().is_none());
    }
}

#[tokio::test]
async fn test_schema_version_present() {
    for (name, store) in create_test_stores().await {
        let version = store.get_setting("schema_version").await.unwrap();
        assert_eq!(version, Some("0.1.0".to_string()),
            "{}: schema_version should be 0.1.0", name);
    }
}

// =============================================================================
// TEMPLATE TESTS
// =============================================================================

#[tokio::test]
async fn test_template_crud() {
    for (name, store) in create_test_stores().await {
        let template = Template {
            name: "ubuntu-2404".to_string(),
            actions: vec![
                Action::Image2Disk {
                    url: "https://example.com/ubuntu.raw".to_string(),
                    disk: "auto".to_string(),
                    checksum: Some("sha256:abc123".to_string()),
                    timeout_secs: 1800,
                },
                Action::Reboot,
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        store.put_template(&template).await.unwrap();

        let fetched = store.get_template("ubuntu-2404").await.unwrap().unwrap();
        assert_eq!(fetched.name, "ubuntu-2404");
        assert_eq!(fetched.actions.len(), 2);

        assert_eq!(store.list_templates().await.unwrap().len(), 1);

        store.delete_template("ubuntu-2404").await.unwrap();
        assert!(store.get_template("ubuntu-2404").await.unwrap().is_none());
    }
}

// =============================================================================
// ADMIN CREDENTIALS TESTS
// =============================================================================

#[tokio::test]
async fn test_admin_credentials() {
    for (name, store) in create_test_stores().await {
        // Initially none
        assert!(store.get_admin_credentials().await.unwrap().is_none());

        // Save
        let creds = AdminCredentials {
            username: "admin".to_string(),
            password_hash: "$argon2id$v=19$...".to_string(),
        };
        store.save_admin_credentials(&creds).await.unwrap();

        let fetched = store.get_admin_credentials().await.unwrap().unwrap();
        assert_eq!(fetched.username, "admin");
        assert_eq!(fetched.password_hash, "$argon2id$v=19$...");

        // Update
        let new_creds = AdminCredentials {
            username: "admin".to_string(),
            password_hash: "$argon2id$v=19$NEW".to_string(),
        };
        store.save_admin_credentials(&new_creds).await.unwrap();

        let fetched = store.get_admin_credentials().await.unwrap().unwrap();
        assert_eq!(fetched.password_hash, "$argon2id$v=19$NEW");
    }
}

// =============================================================================
// PROXMOX INTEGRATION TESTS
// =============================================================================

#[tokio::test]
async fn test_proxmox_machines() {
    for (name, store) in create_test_stores().await {
        // Regular machine
        let id1 = store.register_machine_by_mac("p1:p1:p1:p1:p1:p1", "1.1.1.1").await.unwrap();

        // Proxmox VM
        let id2 = store.register_machine_by_mac("p2:p2:p2:p2:p2:p2", "2.2.2.2").await.unwrap();
        store.set_machine_proxmox(&id2, ProxmoxInfo {
            cluster: "main".to_string(),
            node: Some("pve1".to_string()),
            vmid: Some(100),
            is_host: false,
        }).await.unwrap();

        // Proxmox host
        let id3 = store.register_machine_by_mac("p3:p3:p3:p3:p3:p3", "3.3.3.3").await.unwrap();
        store.set_machine_proxmox(&id3, ProxmoxInfo {
            cluster: "main".to_string(),
            node: Some("pve1".to_string()),
            vmid: None,
            is_host: true,
        }).await.unwrap();

        // List Proxmox machines only
        let proxmox = store.get_proxmox_machines().await.unwrap();
        assert_eq!(proxmox.len(), 2, "{}: should have 2 proxmox machines", name);

        // Both should be there, not the regular machine
        let ids: Vec<_> = proxmox.iter().map(|m| m.id).collect();
        assert!(!ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert!(ids.contains(&id3));
    }
}
