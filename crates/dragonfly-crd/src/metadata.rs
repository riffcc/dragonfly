//! Common metadata types for CRDs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Kubernetes-style object metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Resource name (required)
    pub name: String,

    /// Namespace (optional, defaults to "default")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Unique identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<Uuid>,

    /// Resource version for optimistic concurrency
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,

    /// Labels for organizing resources
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,

    /// Annotations for storing arbitrary metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,

    /// Creation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl ObjectMeta {
    /// Create new metadata with just a name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: None,
            uid: None,
            resource_version: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
        }
    }

    /// Create new metadata with name and namespace
    pub fn with_namespace(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: Some(namespace.into()),
            uid: None,
            resource_version: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
        }
    }

    /// Add a label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Add an annotation
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }
}

impl Default for ObjectMeta {
    fn default() -> Self {
        Self {
            name: String::new(),
            namespace: None,
            uid: None,
            resource_version: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
        }
    }
}

/// Type metadata for CRD objects
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TypeMeta {
    /// API version (e.g., "dragonfly.computer/v1")
    pub api_version: String,

    /// Kind (e.g., "Hardware", "Workflow", "Template")
    pub kind: String,
}

impl TypeMeta {
    /// Create type metadata for Hardware
    pub fn hardware() -> Self {
        Self {
            api_version: crate::API_VERSION.to_string(),
            kind: "Hardware".to_string(),
        }
    }

    /// Create type metadata for Workflow
    pub fn workflow() -> Self {
        Self {
            api_version: crate::API_VERSION.to_string(),
            kind: "Workflow".to_string(),
        }
    }

    /// Create type metadata for Template
    pub fn template() -> Self {
        Self {
            api_version: crate::API_VERSION.to_string(),
            kind: "Template".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_meta_new() {
        let meta = ObjectMeta::new("test-machine");
        assert_eq!(meta.name, "test-machine");
        assert!(meta.namespace.is_none());
        assert!(meta.labels.is_empty());
    }

    #[test]
    fn test_object_meta_with_namespace() {
        let meta = ObjectMeta::with_namespace("test-machine", "production");
        assert_eq!(meta.name, "test-machine");
        assert_eq!(meta.namespace, Some("production".to_string()));
    }

    #[test]
    fn test_object_meta_with_labels() {
        let meta = ObjectMeta::new("test")
            .with_label("env", "prod")
            .with_label("tier", "frontend");

        assert_eq!(meta.labels.get("env"), Some(&"prod".to_string()));
        assert_eq!(meta.labels.get("tier"), Some(&"frontend".to_string()));
    }

    #[test]
    fn test_type_meta_hardware() {
        let meta = TypeMeta::hardware();
        assert_eq!(meta.api_version, "dragonfly.computer/v1");
        assert_eq!(meta.kind, "Hardware");
    }

    #[test]
    fn test_object_meta_serialization() {
        let meta = ObjectMeta::with_namespace("my-server", "default").with_label("app", "web");

        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ObjectMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(meta, parsed);
    }
}
