//! Test helpers for dragonfly-server integration tests
//!
//! Provides utilities for creating test instances of the server.

use crate::auth::Settings;
use crate::event_manager::EventManager;
use crate::image_cache::ImageCache;
use crate::store::v1::MemoryStore;
use crate::{AppState, TemplateEnv};
use minijinja::Environment;
use std::collections::HashMap;
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::{Mutex, watch};

/// Create a minimal AppState for testing
///
/// Uses in-memory store and minimal configuration suitable for API tests.
pub async fn create_test_app_state() -> AppState {
    // Create shutdown channels
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    // Create event manager (it creates its own broadcast channel internally)
    let event_manager = Arc::new(EventManager::new());

    // Create in-memory v1 store
    let store: Arc<dyn crate::store::v1::Store> = Arc::new(MemoryStore::new());

    // Create minimal settings
    let settings = Settings::default();

    // Create a minimal Jinja environment for testing
    let env = Environment::new();
    let template_env = TemplateEnv::Static(Arc::new(env));

    // Create image cache (use temp dir for tests)
    let cache_dir = std::env::temp_dir().join("dragonfly-test-cache");
    let image_cache = Arc::new(ImageCache::new(cache_dir, "http://localhost:3000"));

    AppState {
        settings: Arc::new(Mutex::new(settings)),
        event_manager,
        setup_mode: false,
        first_run: true,
        shutdown_tx,
        shutdown_rx,
        template_env,
        is_installed: false,
        is_demo_mode: true,
        is_installation_server: false,
        client_ip: Arc::new(Mutex::new(None)),
        tokens: Arc::new(Mutex::new(HashMap::new())),
        provisioning: None,
        store,
        network_services_started: Arc::new(AtomicBool::new(false)),
        image_cache,
    }
}

/// Create a test router with API routes
pub async fn create_test_api_router() -> axum::Router {
    let app_state = create_test_app_state().await;
    crate::api::api_router().with_state(app_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_create_test_app_state() {
        let _state = create_test_app_state().await;
        // If we get here without panicking, the state was created successfully
    }

    #[tokio::test]
    async fn test_settings_api_get() {
        let app = create_test_api_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Fresh state should have no mode set
        assert!(json["deployment_mode"].is_null());
        assert_eq!(json["setup_completed"], false);
    }

    #[tokio::test]
    async fn test_settings_api_set_mode() {
        let app = create_test_api_router().await;

        // Set mode to simple (not flight, to avoid triggering network services)
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/settings/mode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"mode": "simple"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["mode"], "simple");

        // Verify mode was set
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings/mode")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["mode"], "simple");
    }

    #[tokio::test]
    async fn test_settings_api_invalid_mode() {
        let app = create_test_api_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/settings/mode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"mode": "invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "INVALID_MODE");
    }

    #[tokio::test]
    async fn test_settings_api_update_default_os() {
        let app = create_test_api_router().await;

        // Set default_os
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/settings")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"default_os": "debian-13"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], true);

        // Verify
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["default_os"], "debian-13");
    }

    #[tokio::test]
    async fn test_settings_api_update_both() {
        let app = create_test_api_router().await;

        // Set both mode and default_os
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/settings")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"deployment_mode": "simple", "default_os": "debian-13"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify both were set
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["deployment_mode"], "simple");
        assert_eq!(json["default_os"], "debian-13");
    }

    #[tokio::test]
    async fn test_all_valid_modes() {
        for mode in ["simple", "flight", "swarm"] {
            let app = create_test_api_router().await;

            let body = format!(r#"{{"mode": "{}"}}"#, mode);
            let response = app
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/settings/mode")
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Mode '{}' should be valid",
                mode
            );
        }
    }

    /// Test that template substitution uses hostname from machine when machine_id is provided
    #[tokio::test]
    async fn test_template_uses_hostname_substitution() {
        use dragonfly_common::{Machine, MachineIdentity};
        use dragonfly_crd::{
            ActionStep, ObjectMeta, Template, TemplateSpec, TypeMeta, WritefileConfig,
        };

        let state = create_test_app_state().await;

        // Create a machine with a user-set hostname
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let mut machine = Machine::new(identity);
        machine.config.hostname = Some("vm1".to_string()); // User-set hostname
        let machine_id = machine.id;

        // Store the machine
        state.store.put_machine(&machine.into()).await.unwrap();

        // Create a template with {{ friendly_name }} in a writefile action
        let template = Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-template"),
            spec: TemplateSpec {
                actions: vec![ActionStep::Writefile(WritefileConfig {
                    path: "/etc/cloud/cloud.cfg.d/99-hostname.cfg".to_string(),
                    partition: Some(1),
                    fs_type: None,
                    content: Some("local-hostname: {{ friendly_name }}".to_string()),
                    content_b64: None,
                    mode: None,
                    uid: None,
                    gid: None,
                    timeout: None,
                })],
                timeout: None,
                version: None,
            },
        };

        // Store the template
        state.store.put_template(&template).await.unwrap();

        // Build the router with our state
        let app = crate::api::api_router().with_state(state);

        // Request the template with machine_id
        let uri = format!("/templates/test-template?machine_id={}", machine_id);
        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Template request should succeed"
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let returned_template: Template = serde_json::from_slice(&body).unwrap();

        // Verify the hostname was substituted
        if let ActionStep::Writefile(cfg) = &returned_template.spec.actions[0] {
            let content = cfg.content.as_ref().expect("Content should be present");
            assert!(
                content.contains("local-hostname: vm1"),
                "Template should substitute hostname 'vm1' but got: {}",
                content
            );
            assert!(
                !content.contains("{{ friendly_name }}"),
                "Template should NOT contain raw template variable: {}",
                content
            );
        } else {
            panic!("Expected Writefile action");
        }
    }

    /// Test that memorable_name is used when hostname is not set
    #[tokio::test]
    async fn test_template_falls_back_to_memorable_name() {
        use dragonfly_common::{Machine, MachineIdentity};
        use dragonfly_crd::{
            ActionStep, ObjectMeta, Template, TemplateSpec, TypeMeta, WritefileConfig,
        };

        let state = create_test_app_state().await;

        // Create a machine WITHOUT a user-set hostname
        let identity = MachineIdentity::from_mac("00:11:22:33:44:66");
        let machine = Machine::new(identity);
        let machine_id = machine.id;
        let memorable_name = machine.config.memorable_name.clone();

        // Store the machine
        state.store.put_machine(&machine.into()).await.unwrap();

        // Create a template with {{ friendly_name }}
        let template = Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-template-fallback"),
            spec: TemplateSpec {
                actions: vec![ActionStep::Writefile(WritefileConfig {
                    path: "/etc/cloud/cloud.cfg.d/99-hostname.cfg".to_string(),
                    partition: Some(1),
                    fs_type: None,
                    content: Some("local-hostname: {{ friendly_name }}".to_string()),
                    content_b64: None,
                    mode: None,
                    uid: None,
                    gid: None,
                    timeout: None,
                })],
                timeout: None,
                version: None,
            },
        };

        // Store the template
        state.store.put_template(&template).await.unwrap();

        // Build the router with our state
        let app = crate::api::api_router().with_state(state);

        // Request the template with machine_id
        let uri = format!(
            "/templates/test-template-fallback?machine_id={}",
            machine_id
        );
        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Template request should succeed"
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let returned_template: Template = serde_json::from_slice(&body).unwrap();

        // Verify the memorable_name was substituted
        if let ActionStep::Writefile(cfg) = &returned_template.spec.actions[0] {
            let content = cfg.content.as_ref().expect("Content should be present");
            assert!(
                content.contains(&format!("local-hostname: {}", memorable_name)),
                "Template should substitute memorable_name '{}' but got: {}",
                memorable_name,
                content
            );
            assert!(
                !content.contains("{{ friendly_name }}"),
                "Template should NOT contain raw template variable: {}",
                content
            );
        } else {
            panic!("Expected Writefile action");
        }
    }

    /// Test that direct SSH keys and GitHub/GitLab subscriptions are substituted into templates
    #[tokio::test]
    async fn test_template_ssh_keys_and_subscriptions() {
        use dragonfly_crd::{
            ActionStep, ObjectMeta, Template, TemplateSpec, TypeMeta, WritefileConfig,
        };

        let state = create_test_app_state().await;

        // Store direct SSH keys
        state.store.put_setting("ssh_keys",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest1 wings@tealc\nssh-rsa AAAAB3NzaC1yc2EAAAAtest2 admin@server"
        ).await.unwrap();

        // Store GitHub + GitLab subscriptions
        let subs = serde_json::json!([
            { "type": "github", "value": "torvalds", "label": "torvalds@github", "url": "https://github.com/torvalds.keys" },
            { "type": "gitlab", "value": "linus", "label": "linus@gitlab", "url": "https://gitlab.com/linus.keys" }
        ]);
        state
            .store
            .put_setting("ssh_key_subscriptions", &subs.to_string())
            .await
            .unwrap();

        // Create template with both placeholders
        let template = Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-ssh-combined"),
            spec: TemplateSpec {
                actions: vec![
                    ActionStep::Writefile(WritefileConfig {
                        path: "/etc/cloud/cloud.cfg.d/99-users.cfg".to_string(),
                        partition: Some(1),
                        fs_type: None,
                        content: Some(
                            "ssh_authorized_keys: {{ ssh_authorized_keys }}\nssh_import_id: {{ ssh_import_id }}".to_string()
                        ),
                        content_b64: None,
                        mode: None,
                        uid: None,
                        gid: None,
                        timeout: None,
                    }),
                ],
                timeout: None,
                version: None,
            },
        };
        state.store.put_template(&template).await.unwrap();

        let app = crate::api::api_router().with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/templates/test-ssh-combined")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let returned: Template = serde_json::from_slice(&body).unwrap();

        if let ActionStep::Writefile(cfg) = &returned.spec.actions[0] {
            let content = cfg.content.as_ref().expect("Content should be present");

            // Direct keys should be in ssh_authorized_keys
            assert!(
                content.contains("wings@tealc"),
                "Should contain first direct key comment: {}",
                content
            );
            assert!(
                content.contains("admin@server"),
                "Should contain second direct key comment: {}",
                content
            );

            // GitHub/GitLab subscriptions should be in ssh_import_id
            assert!(
                content.contains("gh:torvalds"),
                "Should contain GitHub import_id: {}",
                content
            );
            assert!(
                content.contains("gl:linus"),
                "Should contain GitLab import_id: {}",
                content
            );

            // Raw template variables should be gone
            assert!(
                !content.contains("{{ ssh_authorized_keys }}"),
                "Should not contain raw placeholder: {}",
                content
            );
            assert!(
                !content.contains("{{ ssh_import_id }}"),
                "Should not contain raw placeholder: {}",
                content
            );
        } else {
            panic!("Expected Writefile action");
        }
    }

    /// Test that URL subscription keys are fetched and added to ssh_authorized_keys during provisioning
    #[tokio::test]
    async fn test_template_ssh_url_subscription_resolved() {
        use axum::{Router, routing::get};
        use dragonfly_crd::{
            ActionStep, ObjectMeta, Template, TemplateSpec, TypeMeta, WritefileConfig,
        };
        use tokio::net::TcpListener;

        // Start a local mock server that serves SSH keys
        let mock_keys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImock1 alice@laptop\nssh-rsa AAAAB3NzaC1yc2EAAAAmock2 bob@desktop";
        let mock_keys_owned = mock_keys.to_string();
        let mock_app = Router::new().route(
            "/keys.txt",
            get(move || {
                let keys = mock_keys_owned.clone();
                async move { keys }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock_app).await.unwrap() });

        let state = create_test_app_state().await;

        // Store a URL subscription pointing to the mock server
        let mock_url = format!("http://127.0.0.1:{}/keys.txt", addr.port());
        let subs = serde_json::json!([
            { "type": "url", "value": &mock_url, "label": "test-keys", "url": &mock_url }
        ]);
        state
            .store
            .put_setting("ssh_key_subscriptions", &subs.to_string())
            .await
            .unwrap();

        // Also add a direct key to verify both coexist
        state
            .store
            .put_setting(
                "ssh_keys",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIdirect wings@forge",
            )
            .await
            .unwrap();

        let template = Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-url-sub"),
            spec: TemplateSpec {
                actions: vec![ActionStep::Writefile(WritefileConfig {
                    path: "/etc/cloud/cloud.cfg.d/99-users.cfg".to_string(),
                    partition: Some(1),
                    fs_type: None,
                    content: Some("ssh_authorized_keys: {{ ssh_authorized_keys }}".to_string()),
                    content_b64: None,
                    mode: None,
                    uid: None,
                    gid: None,
                    timeout: None,
                })],
                timeout: None,
                version: None,
            },
        };
        state.store.put_template(&template).await.unwrap();

        let app = crate::api::api_router().with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/templates/test-url-sub")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let returned: Template = serde_json::from_slice(&body).unwrap();

        if let ActionStep::Writefile(cfg) = &returned.spec.actions[0] {
            let content = cfg.content.as_ref().expect("Content should be present");

            // URL subscription keys should be fetched and included
            assert!(
                content.contains("alice@laptop"),
                "Should contain key from URL subscription: {}",
                content
            );
            assert!(
                content.contains("bob@desktop"),
                "Should contain second key from URL subscription: {}",
                content
            );

            // Direct key should also be present
            assert!(
                content.contains("wings@forge"),
                "Should contain direct key: {}",
                content
            );
        } else {
            panic!("Expected Writefile action");
        }
    }

    /// Test that unreachable URL subscriptions are gracefully skipped without breaking provisioning
    #[tokio::test]
    async fn test_template_ssh_url_subscription_unreachable_gracefully_skipped() {
        use dragonfly_crd::{
            ActionStep, ObjectMeta, Template, TemplateSpec, TypeMeta, WritefileConfig,
        };

        let state = create_test_app_state().await;

        // Store a URL subscription pointing to an unreachable host
        let subs = serde_json::json!([
            { "type": "url", "value": "http://127.0.0.1:1/nonexistent.keys", "label": "unreachable", "url": "http://127.0.0.1:1/nonexistent.keys" }
        ]);
        state
            .store
            .put_setting("ssh_key_subscriptions", &subs.to_string())
            .await
            .unwrap();

        // Add a direct key that should still work
        state
            .store
            .put_setting(
                "ssh_keys",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsurvive wings@resilient",
            )
            .await
            .unwrap();

        let template = Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-unreachable"),
            spec: TemplateSpec {
                actions: vec![ActionStep::Writefile(WritefileConfig {
                    path: "/etc/cloud/cloud.cfg.d/99-users.cfg".to_string(),
                    partition: Some(1),
                    fs_type: None,
                    content: Some("ssh_authorized_keys: {{ ssh_authorized_keys }}".to_string()),
                    content_b64: None,
                    mode: None,
                    uid: None,
                    gid: None,
                    timeout: None,
                })],
                timeout: None,
                version: None,
            },
        };
        state.store.put_template(&template).await.unwrap();

        let app = crate::api::api_router().with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/templates/test-unreachable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should succeed despite unreachable URL
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let returned: Template = serde_json::from_slice(&body).unwrap();

        if let ActionStep::Writefile(cfg) = &returned.spec.actions[0] {
            let content = cfg.content.as_ref().expect("Content should be present");

            // Direct key should survive despite URL subscription failure
            assert!(
                content.contains("wings@resilient"),
                "Direct key should survive URL failure: {}",
                content
            );

            // Template variable should be substituted (not left raw)
            assert!(
                !content.contains("{{ ssh_authorized_keys }}"),
                "Should not contain raw placeholder: {}",
                content
            );
        } else {
            panic!("Expected Writefile action");
        }
    }

    // =============================================================================
    // Agent self-service endpoint tests
    // =============================================================================

    /// Test POST /api/agent/request-install assigns OS and flags for reimage
    #[tokio::test]
    async fn test_agent_request_install() {
        use dragonfly_common::{Machine, MachineIdentity};
        use dragonfly_crd::{ObjectMeta, Template, TemplateSpec, TypeMeta};

        let state = create_test_app_state().await;

        // Create a machine
        let identity = MachineIdentity::from_mac("AA:BB:CC:DD:EE:01");
        let machine = Machine::new(identity);
        let machine_id = machine.id.to_string();
        state.store.put_machine(&machine.into()).await.unwrap();

        // Create a template
        let template = Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("debian-13"),
            spec: TemplateSpec {
                actions: vec![],
                timeout: None,
                version: None,
            },
        };
        state.store.put_template(&template).await.unwrap();

        let app = crate::api::api_router().with_state(state.clone());

        let body = serde_json::json!({
            "machine_id": machine_id,
            "mac": "AA:BB:CC:DD:EE:01",
            "template_name": "debian-13"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/request-install")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["success"], true);

        // Verify machine was updated
        let machine_uuid = uuid::Uuid::parse_str(&machine_id).unwrap();
        let updated = state
            .store
            .get_machine(machine_uuid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.config.os_choice.as_deref(), Some("debian-13"));
        assert!(updated.config.reimage_requested);
    }

    /// Test POST /api/agent/request-install rejects mismatched MAC
    #[tokio::test]
    async fn test_agent_request_install_mac_mismatch() {
        use dragonfly_common::{Machine, MachineIdentity};

        let state = create_test_app_state().await;

        let identity = MachineIdentity::from_mac("AA:BB:CC:DD:EE:02");
        let machine = Machine::new(identity);
        let machine_id = machine.id.to_string();
        state.store.put_machine(&machine.into()).await.unwrap();

        let app = crate::api::api_router().with_state(state);

        let body = serde_json::json!({
            "machine_id": machine_id,
            "mac": "FF:FF:FF:FF:FF:FF",
            "template_name": "debian-13"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/request-install")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Test POST /api/agent/remove deletes the machine
    #[tokio::test]
    async fn test_agent_remove() {
        use dragonfly_common::{Machine, MachineIdentity};

        let state = create_test_app_state().await;

        let identity = MachineIdentity::from_mac("AA:BB:CC:DD:EE:03");
        let machine = Machine::new(identity);
        let machine_id = machine.id.to_string();
        state.store.put_machine(&machine.into()).await.unwrap();

        let app = crate::api::api_router().with_state(state.clone());

        let body = serde_json::json!({
            "machine_id": machine_id,
            "mac": "AA:BB:CC:DD:EE:03"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/remove")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["success"], true);

        // Verify machine was deleted
        let machine_uuid = uuid::Uuid::parse_str(&machine_id).unwrap();
        let result = state.store.get_machine(machine_uuid).await.unwrap();
        assert!(result.is_none());
    }

    /// Test GET /api/agent/diagnostics returns availability
    #[tokio::test]
    async fn test_agent_boot_mode_memtest() {
        use dragonfly_common::{Machine, MachineIdentity};

        let state = create_test_app_state().await;

        let identity = MachineIdentity::from_mac("AA:BB:CC:DD:EE:04");
        let machine = Machine::new(identity);
        let machine_id = machine.id.to_string();
        state.store.put_machine(&machine.into()).await.unwrap();

        let app = crate::api::api_router().with_state(state.clone());

        let body = serde_json::json!({
            "machine_id": machine_id,
            "mac": "AA:BB:CC:DD:EE:04",
            "mode": "memtest"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/boot-mode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify boot-mode tag was added
        let machine_uuid = uuid::Uuid::parse_str(&machine_id).unwrap();
        let updated = state
            .store
            .get_machine(machine_uuid)
            .await
            .unwrap()
            .unwrap();
        assert!(updated.config.tags.iter().any(|t| t == "boot-mode:memtest"));
    }

    /// Test POST /api/agent/boot-mode with rescue mode
    #[tokio::test]
    async fn test_agent_boot_mode_rescue() {
        use dragonfly_common::{Machine, MachineIdentity};

        let state = create_test_app_state().await;

        let identity = MachineIdentity::from_mac("AA:BB:CC:DD:EE:05");
        let machine = Machine::new(identity);
        let machine_id = machine.id.to_string();
        state.store.put_machine(&machine.into()).await.unwrap();

        let app = crate::api::api_router().with_state(state.clone());

        let body = serde_json::json!({
            "machine_id": machine_id,
            "mac": "AA:BB:CC:DD:EE:05",
            "mode": "rescue"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/boot-mode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let machine_uuid = uuid::Uuid::parse_str(&machine_id).unwrap();
        let updated = state
            .store
            .get_machine(machine_uuid)
            .await
            .unwrap()
            .unwrap();
        assert!(updated.config.tags.iter().any(|t| t == "boot-mode:rescue"));
    }

    /// Test POST /api/agent/boot-mode with invalid mode
    #[tokio::test]
    async fn test_agent_boot_mode_invalid() {
        use dragonfly_common::{Machine, MachineIdentity};

        let state = create_test_app_state().await;

        let identity = MachineIdentity::from_mac("AA:BB:CC:DD:EE:06");
        let machine = Machine::new(identity);
        let machine_id = machine.id.to_string();
        state.store.put_machine(&machine.into()).await.unwrap();

        let app = crate::api::api_router().with_state(state);

        let body = serde_json::json!({
            "machine_id": machine_id,
            "mac": "AA:BB:CC:DD:EE:06",
            "mode": "bogus"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agent/boot-mode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Test GET /api/agent/isos returns empty list when no ISOs
    #[tokio::test]
    async fn test_agent_list_isos_empty() {
        let state = create_test_app_state().await;
        let app = crate::api::api_router().with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agent/isos")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        // Agent endpoint returns a plain JSON array
        assert!(json.is_array(), "Expected JSON array, got: {}", json);
    }

    /// Test that duplicate SSH keys (same type+data, different comments) are deduplicated
    #[tokio::test]
    async fn test_template_ssh_keys_deduplicated() {
        use dragonfly_crd::{
            ActionStep, ObjectMeta, Template, TemplateSpec, TypeMeta, WritefileConfig,
        };

        let state = create_test_app_state().await;

        // Store keys with same type+base64 but different comments
        state
            .store
            .put_setting(
                "ssh_keys",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest1 wings@tealc\n\
             ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest1 wings@desktop\n\
             ssh-rsa AAAAB3NzaC1yc2EAAAAtest2 admin@server",
            )
            .await
            .unwrap();

        let template = Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-dedup"),
            spec: TemplateSpec {
                actions: vec![ActionStep::Writefile(WritefileConfig {
                    path: "/etc/cloud/cloud.cfg.d/99-users.cfg".to_string(),
                    partition: Some(1),
                    fs_type: None,
                    content: Some("ssh_authorized_keys: {{ ssh_authorized_keys }}".to_string()),
                    content_b64: None,
                    mode: None,
                    uid: None,
                    gid: None,
                    timeout: None,
                })],
                timeout: None,
                version: None,
            },
        };
        state.store.put_template(&template).await.unwrap();

        let app = crate::api::api_router().with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/templates/test-dedup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let returned: Template = serde_json::from_slice(&body).unwrap();

        if let ActionStep::Writefile(cfg) = &returned.spec.actions[0] {
            let content = cfg.content.as_ref().expect("Content should be present");

            // First occurrence (wings@tealc) should be kept
            assert!(
                content.contains("wings@tealc"),
                "Should keep first occurrence: {}",
                content
            );

            // Duplicate (wings@desktop, same key data) should be removed
            assert!(
                !content.contains("wings@desktop"),
                "Should deduplicate same key with different comment: {}",
                content
            );

            // Unique key should still be present
            assert!(
                content.contains("admin@server"),
                "Should keep unique key: {}",
                content
            );
        } else {
            panic!("Expected Writefile action");
        }
    }
}
