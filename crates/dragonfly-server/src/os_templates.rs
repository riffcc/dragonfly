//! OS Template Management
//!
//! This module handles loading and managing OS templates for provisioning.
//! Templates are loaded from YAML files in /opt/dragonfly/templates/ and stored
//! in the configured storage backend (ReDB, K8s, etc.) via the DragonflyStore trait.
//!
//! The file system is the source of truth - templates are always loaded from files
//! on startup, allowing updates without database wipes.
//!
//! Templates use `{{ server }}` as a placeholder for the Dragonfly server address,
//! which is substituted at workflow execution time based on the machine's context.

use anyhow::{anyhow, Result};
use tracing::{info, error, warn, debug};
use std::path::Path;
use tokio::fs;
use std::sync::Arc;

use crate::store::DragonflyStore;
use dragonfly_crd::Template;

/// Primary template directory (installed by `dragonfly install`)
const TEMPLATE_DIR: &str = "/var/lib/dragonfly/os-templates";

/// Fallback template directory for development
const FALLBACK_TEMPLATE_DIRS: &[&str] = &[
    "os-templates",
];

/// Initialize the OS templates using the provided store
///
/// Templates are always loaded from files, making the file system the source of truth.
/// This allows updating templates without wiping the database.
pub async fn init_os_templates(store: Arc<dyn DragonflyStore>) -> Result<()> {
    info!("Initializing OS templates from files...");

    // Find the template directory
    let template_dir = find_template_dir().await;

    if let Some(dir) = &template_dir {
        info!("Loading templates from: {}", dir.display());
        load_templates_from_dir(store.clone(), dir).await?;
    } else {
        warn!("No template directory found. Templates will be downloaded on demand.");
        // Fall back to downloading default templates
        for template_name in &["ubuntu-2204", "ubuntu-2404", "debian-12", "debian-13"] {
            if let Err(e) = install_template_if_missing(store.clone(), template_name).await {
                warn!("Failed to install {} template: {}", template_name, e);
            }
        }
    }

    info!("OS templates initialization complete");
    Ok(())
}

/// Find the template directory to use
async fn find_template_dir() -> Option<std::path::PathBuf> {
    // Check primary location first
    let primary = Path::new(TEMPLATE_DIR);
    if primary.exists() {
        return Some(primary.to_path_buf());
    }

    // Check fallback locations
    for fallback in FALLBACK_TEMPLATE_DIRS {
        let path = Path::new(fallback);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

/// Load all templates from a directory
async fn load_templates_from_dir(store: Arc<dyn DragonflyStore>, dir: &Path) -> Result<()> {
    let mut entries = fs::read_dir(dir).await
        .map_err(|e| anyhow!("Failed to read template directory: {}", e))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        // Only process .yml files
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }

        let template_name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        match load_template_from_path(&path).await {
            Ok(template) => {
                // Always update the template in the store (file is source of truth)
                if let Err(e) = store.put_template(&template).await {
                    warn!("Failed to store template '{}': {}", template_name, e);
                } else {
                    info!("Loaded template '{}' from {}", template_name, path.display());
                }
            }
            Err(e) => {
                warn!("Failed to load template from {:?}: {}", path, e);
            }
        }
    }

    Ok(())
}

/// Load and validate a template from a file path
async fn load_template_from_path(path: &Path) -> Result<Template> {
    let content = fs::read_to_string(path).await
        .map_err(|e| anyhow!("Failed to read template file: {}", e))?;

    let template: Template = serde_yaml::from_str(&content)
        .map_err(|e| anyhow!("Failed to parse template YAML: {}", e))?;

    template.validate()
        .map_err(|e| anyhow!("Template validation failed: {}", e))?;

    Ok(template)
}

/// Install a template if it doesn't exist (fallback for when no template dir exists)
async fn install_template_if_missing(store: Arc<dyn DragonflyStore>, template_name: &str) -> Result<()> {
    // Check if template already exists in store
    match store.get_template(template_name).await {
        Ok(Some(_)) => {
            debug!("Template '{}' already exists in store, skipping", template_name);
            Ok(())
        },
        Ok(None) => {
            info!("Template '{}' not found in store, downloading...", template_name);
            install_template_from_download(store, template_name).await
        },
        Err(e) => {
            error!("Error checking for template '{}': {}", template_name, e);
            Err(anyhow!("Error checking for template: {}", e))
        }
    }
}

/// Download and install a template from GitHub
async fn install_template_from_download(store: Arc<dyn DragonflyStore>, template_name: &str) -> Result<()> {
    info!("Downloading template '{}' from GitHub...", template_name);
    let yaml_content = download_template(template_name).await?;

    // Parse YAML to Template
    let template: Template = serde_yaml::from_str(&yaml_content)
        .map_err(|e| {
            error!("Failed to parse template '{}': {}", template_name, e);
            anyhow!("Failed to parse template YAML: {}", e)
        })?;

    // Validate the template
    if let Err(e) = template.validate() {
        error!("Template '{}' validation failed: {}", template_name, e);
        return Err(anyhow!("Template validation failed: {}", e));
    }

    // Store the template
    store.put_template(&template).await
        .map_err(|e| {
            error!("Failed to store template '{}': {}", template_name, e);
            anyhow!("Failed to store template: {}", e)
        })?;

    info!("Successfully installed template '{}'", template_name);
    Ok(())
}

/// Download a template from GitHub
async fn download_template(template_name: &str) -> Result<String> {
    // Try native-provisioning branch first, then main
    let urls = [
        format!(
            "https://raw.githubusercontent.com/Zorlin/dragonfly/refs/heads/native-provisioning/os-templates/{}.yml",
            template_name
        ),
        format!(
            "https://raw.githubusercontent.com/Zorlin/dragonfly/refs/heads/main/os-templates/{}.yml",
            template_name
        ),
    ];

    for url in &urls {
        debug!("Trying to download template from: {}", url);

        match reqwest::get(url).await {
            Ok(response) if response.status().is_success() => {
                let content = response.text().await
                    .map_err(|e| anyhow!("Failed to read response: {}", e))?;

                // Try to save locally for future use
                save_template_locally(template_name, &content).await;

                return Ok(content);
            },
            Ok(response) => {
                debug!("Got {} from {}", response.status(), url);
            },
            Err(e) => {
                debug!("Failed to fetch {}: {}", url, e);
            }
        }
    }

    Err(anyhow!("Failed to download template '{}' from any source", template_name))
}

/// Save a downloaded template locally for future use
async fn save_template_locally(template_name: &str, content: &str) {
    let path = Path::new("/var/lib/dragonfly/os-templates").join(format!("{}.yml", template_name));

    // Create directory if needed
    if let Some(parent) = path.parent()
        && !parent.exists()
            && let Err(e) = fs::create_dir_all(parent).await {
                debug!("Failed to create template directory: {}", e);
                return;
            }

    // Save the file
    if let Err(e) = fs::write(&path, content).await {
        debug!("Failed to save template locally: {}", e);
    } else {
        debug!("Saved template to {:?}", path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_dir_constant() {
        // Verify primary template directory is set correctly
        assert_eq!(TEMPLATE_DIR, "/var/lib/dragonfly/os-templates");
    }

    #[test]
    fn test_fallback_dirs() {
        // Verify fallback directory for development is configured
        assert!(FALLBACK_TEMPLATE_DIRS.contains(&"os-templates"));
    }
}
