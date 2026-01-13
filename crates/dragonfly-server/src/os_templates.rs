//! OS Template Management
//!
//! This module handles loading and managing OS templates for provisioning.
//! Templates are loaded from YAML files and stored in the configured
//! storage backend (ReDB, K8s, etc.) via the DragonflyStore trait.
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

/// Default templates to install
const DEFAULT_TEMPLATES: &[&str] = &[
    "ubuntu-2204",
    "ubuntu-2404",
    "debian-12",
    "debian-13",
];

/// Initialize the OS templates using the provided store
pub async fn init_os_templates(store: Arc<dyn DragonflyStore>) -> Result<()> {
    info!("Initializing OS templates...");

    for template_name in DEFAULT_TEMPLATES {
        if let Err(e) = install_template(store.clone(), template_name).await {
            warn!("Failed to install {} template: {}", template_name, e);
            // Continue with other templates even if one fails
        }
    }

    info!("OS templates initialization complete");
    Ok(())
}

/// Check if a template exists in the store, and install it if it doesn't
async fn install_template(store: Arc<dyn DragonflyStore>, template_name: &str) -> Result<()> {
    // Check if template already exists in store
    match store.get_template(template_name).await {
        Ok(Some(_)) => {
            debug!("Template '{}' already exists in store, skipping", template_name);
            Ok(())
        },
        Ok(None) => {
            info!("Template '{}' not found in store, installing...", template_name);
            install_template_from_file(store, template_name).await
        },
        Err(e) => {
            error!("Error checking for template '{}': {}", template_name, e);
            Err(anyhow!("Error checking for template: {}", e))
        }
    }
}

/// Install a template from a YAML file into the store
async fn install_template_from_file(store: Arc<dyn DragonflyStore>, template_name: &str) -> Result<()> {
    // Try multiple locations for template files
    let template_paths = [
        Path::new("/var/lib/dragonfly/os-templates").join(format!("{}.yml", template_name)),
        Path::new("os-templates").join(format!("{}.yml", template_name)),
    ];

    let mut template_yaml = None;

    for path in &template_paths {
        if path.exists() {
            debug!("Found template at: {:?}", path);
            match fs::read_to_string(path).await {
                Ok(content) => {
                    template_yaml = Some(content);
                    break;
                },
                Err(e) => {
                    warn!("Failed to read template from {:?}: {}", path, e);
                }
            }
        }
    }

    // If not found locally, try downloading from GitHub
    let yaml_content = match template_yaml {
        Some(content) => content,
        None => {
            info!("Template '{}' not found locally, downloading from GitHub...", template_name);
            download_template(template_name).await?
        }
    };

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
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent).await {
                debug!("Failed to create template directory: {}", e);
                return;
            }
        }
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
    fn test_default_templates() {
        // Verify all default templates are defined
        assert!(DEFAULT_TEMPLATES.contains(&"ubuntu-2204"));
        assert!(DEFAULT_TEMPLATES.contains(&"ubuntu-2404"));
        assert!(DEFAULT_TEMPLATES.contains(&"debian-12"));
        assert!(DEFAULT_TEMPLATES.contains(&"debian-13"));
    }
}
