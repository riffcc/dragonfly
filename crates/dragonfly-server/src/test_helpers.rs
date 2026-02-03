//! Test helpers for dragonfly-server integration tests
//!
//! Provides utilities for creating test instances of the server.

use crate::{AppState, TemplateEnv};
use crate::auth::Settings;
use crate::event_manager::EventManager;
use crate::image_cache::ImageCache;
use crate::store::v1::MemoryStore;
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

    // Create in-memory SQLite pool for tests
    let dbpool = sqlx::SqlitePool::connect(":memory:")
        .await
        .expect("Failed to create in-memory SQLite pool");

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
        dbpool,
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
                    .body(Body::from(r#"{"deployment_mode": "simple", "default_os": "debian-13"}"#))
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
        use dragonfly_crd::{Template, ActionStep, WritefileConfig, ObjectMeta, TypeMeta, TemplateSpec};
        use dragonfly_common::{Machine, MachineIdentity};

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
                actions: vec![
                    ActionStep::Writefile(WritefileConfig {
                        path: "/etc/cloud/cloud.cfg.d/99-hostname.cfg".to_string(),
                        partition: Some(1),
                        fs_type: None,
                        content: Some("local-hostname: {{ friendly_name }}".to_string()),
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

        // Store the template
        state.store.put_template(&template).await.unwrap();

        // Build the router with our state
        let app = crate::api::api_router().with_state(state);

        // Request the template with machine_id
        let uri = format!("/templates/test-template?machine_id={}", machine_id);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "Template request should succeed");

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
        use dragonfly_crd::{Template, ActionStep, WritefileConfig, ObjectMeta, TypeMeta, TemplateSpec};
        use dragonfly_common::{Machine, MachineIdentity};

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
                actions: vec![
                    ActionStep::Writefile(WritefileConfig {
                        path: "/etc/cloud/cloud.cfg.d/99-hostname.cfg".to_string(),
                        partition: Some(1),
                        fs_type: None,
                        content: Some("local-hostname: {{ friendly_name }}".to_string()),
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

        // Store the template
        state.store.put_template(&template).await.unwrap();

        // Build the router with our state
        let app = crate::api::api_router().with_state(state);

        // Request the template with machine_id
        let uri = format!("/templates/test-template-fallback?machine_id={}", machine_id);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "Template request should succeed");

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
}
