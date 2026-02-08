//! OS Template Management
//!
//! Templates use a layered system:
//! 1. **Built-in templates** are compiled into the binary and always available
//! 2. **User overrides** from `/var/lib/dragonfly/os-templates/` layer on top
//!
//! Updating Dragonfly automatically updates built-in templates.
//! User customizations in the override directory are never lost.
//!
//! Templates use `{{ server }}` as a placeholder for the Dragonfly server address,
//! which is substituted at workflow execution time based on the machine's context.

use anyhow::{Result, anyhow};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{info, warn};

use crate::store::v1::Store;
use dragonfly_crd::Template;

/// Built-in templates compiled into the binary
const BUILTIN_TEMPLATES: &[(&str, &str)] = &[
    ("debian-12", include_str!("../../../os-templates/debian-12.yml")),
    ("debian-13", include_str!("../../../os-templates/debian-13.yml")),
    ("proxmox", include_str!("../../../os-templates/proxmox.yml")),
    ("rocky-10", include_str!("../../../os-templates/rocky-10.yml")),
    ("ubuntu-2204", include_str!("../../../os-templates/ubuntu-2204.yml")),
    ("ubuntu-2404", include_str!("../../../os-templates/ubuntu-2404.yml")),
];

/// User override directory
const USER_TEMPLATE_DIR: &str = "/var/lib/dragonfly/os-templates";

/// Additional override directories (local dev)
const DEV_TEMPLATE_DIRS: &[&str] = &["os-templates"];

/// Initialize OS templates: load built-ins, then overlay user overrides
pub async fn init_os_templates(store: Arc<dyn Store>) -> Result<()> {
    info!("Initializing OS templates...");

    // Layer 1: Load built-in templates (always available)
    for (name, yaml) in BUILTIN_TEMPLATES {
        match parse_and_validate(yaml) {
            Ok(template) => {
                if let Err(e) = store.put_template(&template).await {
                    warn!("Failed to store built-in template '{}': {}", name, e);
                } else {
                    info!("Loaded built-in template '{}'", name);
                }
            }
            Err(e) => {
                warn!("Built-in template '{}' failed validation: {}", name, e);
            }
        }
    }

    // Layer 2: Overlay user overrides from disk (last write wins)
    let override_dirs = std::iter::once(USER_TEMPLATE_DIR)
        .chain(DEV_TEMPLATE_DIRS.iter().copied());

    for dir_path in override_dirs {
        let dir = Path::new(dir_path);
        if let Ok(count) = load_overrides_from_dir(store.clone(), dir).await {
            if count > 0 {
                info!("Loaded {} user template override(s) from {}", count, dir_path);
            }
        }
    }

    info!("OS templates initialization complete");
    Ok(())
}

/// Parse and validate a YAML template string
fn parse_and_validate(yaml: &str) -> Result<Template> {
    let template: Template = serde_yaml::from_str(yaml)
        .map_err(|e| anyhow!("Failed to parse template YAML: {}", e))?;
    template
        .validate()
        .map_err(|e| anyhow!("Template validation failed: {}", e))?;
    Ok(template)
}

/// Load template overrides from a directory, returning the count loaded
async fn load_overrides_from_dir(store: Arc<dyn Store>, dir: &Path) -> Result<usize> {
    let mut entries = fs::read_dir(dir).await?;
    let mut count = 0;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }

        let template_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let content = fs::read_to_string(&path).await?;
        match parse_and_validate(&content) {
            Ok(template) => {
                if let Err(e) = store.put_template(&template).await {
                    warn!("Failed to store override template '{}': {}", template_name, e);
                } else {
                    info!("Loaded template override '{}' from {}", template_name, path.display());
                    count += 1;
                }
            }
            Err(e) => {
                warn!("Failed to load template from {:?}: {}", path, e);
            }
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_templates_parse() {
        for (name, yaml) in BUILTIN_TEMPLATES {
            let result = parse_and_validate(yaml);
            assert!(result.is_ok(), "Built-in template '{}' failed to parse: {:?}", name, result.err());
            let template = result.unwrap();
            assert_eq!(template.metadata.name, *name);
        }
    }

    #[test]
    fn test_builtin_template_count() {
        assert!(BUILTIN_TEMPLATES.len() >= 6, "Should have at least 6 built-in templates");
    }

    #[test]
    fn test_user_template_dir() {
        assert_eq!(USER_TEMPLATE_DIR, "/var/lib/dragonfly/os-templates");
    }
}
