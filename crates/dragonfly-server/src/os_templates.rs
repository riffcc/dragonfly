use anyhow::{anyhow, Result};
use kube::{
    api::{Api, PostParams},
    Client, Error as KubeError, core::DynamicObject,
};
use serde_yaml;
use tracing::{info, error, warn};
use std::path::Path;
use tokio::fs;
use std::env;
use url::Url;
use std::collections::HashMap;
use reqwest;

/// Initialize the OS templates in Kubernetes
pub async fn init_os_templates() -> Result<()> {
    info!("Initializing OS templates...");
    
    // Get Tinkerbell client
    let client = match crate::tinkerbell::get_client().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Skipping OS template initialization: {}", e);
            return Err(anyhow!("Failed to get Kubernetes client: {}", e));
        }
    };
    
    // Get the bare base URL (without port) for template substitution
    let base_url_bare = get_base_url_without_port()?;
    
    // Check and install ubuntu-2204 template
    if let Err(e) = install_template(client, "ubuntu-2204", &base_url_bare).await {
        error!("Failed to install ubuntu-2204 template: {}", e);
        return Err(anyhow!("Failed to install ubuntu-2204 template: {}", e));
    }

    // Check and install debian-12 template
    if let Err(e) = install_template(client, "debian-12", &base_url_bare).await {
        error!("Failed to install debian-12 template: {}", e);
        return Err(anyhow!("Failed to install debian-12 template: {}", e));
    }

    // Check and install debian-13 template
    if let Err(e) = install_template(client, "debian-13", &base_url_bare).await {
        error!("Failed to install debian-13 template: {}", e);
        return Err(anyhow!("Failed to install debian-13 template: {}", e));
    }

    info!("OS templates initialization complete");
    Ok(())
}

/// Extract base URL without port from DRAGONFLY_BASE_URL environment variable
fn get_base_url_without_port() -> Result<String> {
    // Read required base URL from environment variable
    let base_url = match env::var("DRAGONFLY_BASE_URL") {
        Ok(url) => url,
        Err(_) => {
            // If DRAGONFLY_BASE_URL is not set, try DRAGONFLY_BASE_URL_BARE
            match env::var("DRAGONFLY_BASE_URL_BARE") {
                Ok(url) => url,
                Err(_) => {
                    // If not set, default to localhost for development
                    warn!("Neither DRAGONFLY_BASE_URL nor DRAGONFLY_BASE_URL_BARE set, using localhost as base URL for templates");
                    "localhost".to_string()
                }
            }
        }
    };
    
    // Parse the URL to extract just the hostname without port
    let base_url_bare = if base_url.contains("://") {
        // Full URL with scheme
        match Url::parse(&base_url) {
            Ok(parsed_url) => {
                parsed_url.host_str().unwrap_or("localhost").to_string()
            },
            Err(_) => {
                // Fall back to simple splitting if URL parsing fails
                base_url.split(':').next().unwrap_or("localhost").to_string()
            }
        }
    } else if base_url.contains(':') {
        // Just hostname:port without scheme
        base_url.split(':').next().unwrap_or("localhost").to_string()
    } else {
        // Just hostname without port
        base_url
    };
    
    info!("Using base URL without port for templates: {}", base_url_bare);
    Ok(base_url_bare)
}

/// Check if a template exists in Kubernetes, and install it if it doesn't
async fn install_template(client: &Client, template_name: &str, base_url_bare: &str) -> Result<()> {
    // Create the API resource for Template CRD
    let template_api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Template".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "templates".to_string(),
    };
    
    let template_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), "tink", &template_api_resource);
    
    // Check if template already exists
    match template_api.get(template_name).await {
        Ok(_) => {
            info!("Template '{}' already exists in Tinkerbell, skipping installation", template_name);
            Ok(())
        },
        Err(KubeError::Api(ae)) if ae.code == 404 => {
            info!("Template '{}' not found in Tinkerbell, installing...", template_name);
            install_template_from_file(client, template_name, base_url_bare).await
        },
        Err(e) => {
            error!("Error checking for template '{}': {}", template_name, e);
            Err(anyhow!("Error checking for template: {}", e))
        }
    }
}

/// Install a template from a YAML file
async fn install_template_from_file(client: &Client, template_name: &str, base_url_bare: &str) -> Result<()> {
    // Determine file paths
    let os_templates_dir = Path::new("/var/lib/dragonfly/os-templates");
    let fallback_dir = Path::new("os-templates");
    
    let template_path = if os_templates_dir.exists() {
        os_templates_dir.join(format!("{}.yml", template_name))
    } else {
        fallback_dir.join(format!("{}.yml", template_name))
    };
    
    info!("Loading template from: {:?}", template_path);
    
    // Try to read the template file locally first
    let template_yaml = match fs::read_to_string(&template_path).await {
        Ok(content) => content,
        Err(e) => {
            // If file doesn't exist locally, try downloading from GitHub
            info!("Tried to load template from {:?}: {}", template_path, e);
            info!("Attempting to download template from GitHub...");
            
            // Construct GitHub URL for the template
            let github_url = format!(
                "https://raw.githubusercontent.com/Zorlin/dragonfly/refs/heads/main/os-templates/{}.yml",
                template_name
            );
            
            match download_template_from_github(&github_url).await {
                Ok(content) => {
                    info!("Successfully downloaded template from GitHub");
                    content
                },
                Err(e) => {
                    error!("Failed to download template from GitHub: {}", e);
                    return Err(anyhow!("Failed to read template file: {}", e));
                }
            }
        }
    };
    
    // Fix metadata_urls to work with the correct port
    let template_yaml = fix_metadata_urls(&template_yaml, base_url_bare);
    
    // Parse YAML to get the DynamicObject
    let dynamic_obj: DynamicObject = match serde_yaml::from_str(&template_yaml) {
        Ok(obj) => obj,
        Err(e) => {
            error!("Failed to parse template YAML: {}", e);
            return Err(anyhow!("Failed to parse template YAML: {}", e));
        }
    };
    
    // Create the API resource for Template CRD
    let template_api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Template".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "templates".to_string(),
    };
    
    let template_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), "tink", &template_api_resource);
    
    // Create the template
    match template_api.create(&PostParams::default(), &dynamic_obj).await {
        Ok(_) => {
            info!("Successfully created template '{}'", template_name);
            Ok(())
        },
        Err(e) => {
            error!("Failed to create template '{}': {}", template_name, e);
            Err(anyhow!("Failed to create template: {}", e))
        }
    }
}

/// Download a template from GitHub
async fn download_template_from_github(url: &str) -> Result<String> {
    info!("Downloading template from: {}", url);
    
    let response = reqwest::get(url).await
        .map_err(|e| anyhow!("Failed to send request to GitHub: {}", e))?;
    
    if !response.status().is_success() {
        return Err(anyhow!("Failed to download template, status: {}", response.status()));
    }
    
    let content = response.text().await
        .map_err(|e| anyhow!("Failed to read response body: {}", e))?;
    
    // Extract template name from the URL to use for saving
    let template_name = url.split('/').last().unwrap_or("unknown.yml");
    
    // Try to save the template to the filesystem for future use
    save_template_to_filesystem(template_name, &content).await?;
    
    Ok(content)
}

/// Save a downloaded template to the filesystem
async fn save_template_to_filesystem(template_name: &str, content: &str) -> Result<()> {
    // Create directory structure if it doesn't exist
    let fallback_dir = Path::new("os-templates");
    if !fallback_dir.exists() {
        match fs::create_dir_all(fallback_dir).await {
            Ok(_) => info!("Created directory: {:?}", fallback_dir),
            Err(e) => {
                warn!("Failed to create directory {:?}: {}", fallback_dir, e);
                return Ok(());  // Continue even if we can't save the template
            }
        }
    }
    
    // Save the template file
    let template_path = fallback_dir.join(template_name);
    match fs::write(&template_path, content).await {
        Ok(_) => {
            info!("Saved template to: {:?}", template_path);
            Ok(())
        },
        Err(e) => {
            warn!("Failed to save template to {:?}: {}", template_path, e);
            Ok(())  // Continue even if we can't save the template
        }
    }
}

/// Fix the metadata_urls in the template YAML to work with the correct port
fn fix_metadata_urls(yaml: &str, base_url_bare: &str) -> String {
    // Replace both {{ base_url }} and {{ base_url_bare }} with the actual base_url_bare value
    // to ensure the port will be correctly appended
    let replacement_vars = HashMap::from([
        // Use the same base_url_bare for both placeholders
        ("base_url".to_string(), base_url_bare.to_string()),
        ("base_url_bare".to_string(), base_url_bare.to_string()),
    ]);
    
    let mut result = yaml.to_string();
    for (key, value) in replacement_vars {
        // Ensure the value used for replacement doesn't have surrounding braces
        let clean_value = value.trim_start_matches('{').trim_end_matches('}');
        // Replace the template placeholder (e.g., "{{ base_url_bare }}") with the cleaned value
        result = result.replace(&format!("{{{{ {} }}}}", key), clean_value);
    }
    
    result
}

/// Helper function for unit tests to parse a URL without accessing environment variables
fn parse_url_to_bare(url: &str) -> String {
    if url.contains("://") {
        // Full URL with scheme
        match Url::parse(url) {
            Ok(parsed_url) => {
                parsed_url.host_str().unwrap_or("localhost").to_string()
            },
            Err(_) => {
                // Fall back to simple splitting if URL parsing fails
                url.split(':').next().unwrap_or("localhost").to_string()
            }
        }
    } else if url.contains(':') {
        // Just hostname:port without scheme
        url.split(':').next().unwrap_or("localhost").to_string()
    } else {
        // Just hostname without port
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_parsing() {
        // Test cases for different URL formats
        let test_cases = vec![
            // Full URLs with scheme
            ("http://example.com:3000", "example.com"),
            ("https://server.domain.com:8443", "server.domain.com"),
            ("http://192.168.1.1:8080", "192.168.1.1"),
            
            // Hostname:port format
            ("example.com:3000", "example.com"),
            ("192.168.1.1:8080", "192.168.1.1"),
            
            // Just hostname
            ("example.com", "example.com"),
            ("192.168.1.1", "192.168.1.1"),
            
            // Edge cases
            ("localhost", "localhost"),
            ("localhost:3000", "localhost"),
        ];
        
        for (input, expected) in test_cases {
            let result = parse_url_to_bare(input);
            assert_eq!(result, expected, "Failed parsing URL: {}", input);
        }
    }
} 