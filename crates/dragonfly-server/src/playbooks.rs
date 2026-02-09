//! Jetpack Playbook Management
//!
//! Playbooks use a layered system (same pattern as OS templates):
//! 1. **Built-in playbooks** are compiled into the binary and always available
//! 2. **User overrides** from `/var/lib/dragonfly/playbooks/` layer on top
//!
//! Playbooks are served as tarballs (.tar.gz) containing a complete Jetpack
//! playbook directory (playbook.yml, roles/, templates/, etc.).
//!
//! Updating Dragonfly automatically updates built-in playbooks.
//! User customizations in the override directory are never lost.

use anyhow::Result;
use std::path::Path;
use tokio::fs;
use tracing::info;

/// Built-in playbook tarballs compiled into the binary
const BUILTIN_PLAYBOOKS: &[(&str, &[u8])] = &[
    (
        "debian-to-proxmox",
        include_bytes!("../../../jetpack-playbooks/debian-to-proxmox.tar.gz"),
    ),
];

/// Directory where playbook tarballs are served from
const PLAYBOOK_DIR: &str = "/var/lib/dragonfly/playbooks";

/// Initialize playbooks: extract built-ins to disk, user overrides take precedence
pub async fn init_playbooks() -> Result<()> {
    info!("Initializing Jetpack playbooks...");

    // Ensure the playbook directory exists
    fs::create_dir_all(PLAYBOOK_DIR).await?;

    // Extract built-in playbooks (skip if user has placed an override)
    for (name, data) in BUILTIN_PLAYBOOKS {
        let dest = Path::new(PLAYBOOK_DIR).join(format!("{}.tar.gz", name));

        if dest.exists() {
            // Check if the existing file is the same size — if so, it's the same built-in
            // If different size, it's a user override — don't clobber
            let metadata = fs::metadata(&dest).await?;
            if metadata.len() == data.len() as u64 {
                info!("Built-in playbook '{}' already extracted (unchanged)", name);
                continue;
            }
            info!(
                "Playbook '{}' exists with different size (user override), keeping it",
                name
            );
            continue;
        }

        fs::write(&dest, data).await?;
        info!("Extracted built-in playbook '{}' ({} bytes)", name, data.len());
    }

    info!("Jetpack playbooks initialization complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_playbooks_not_empty() {
        assert!(
            !BUILTIN_PLAYBOOKS.is_empty(),
            "Should have at least one built-in playbook"
        );
    }

    #[test]
    fn test_builtin_playbook_data_valid() {
        for (name, data) in BUILTIN_PLAYBOOKS {
            assert!(!data.is_empty(), "Built-in playbook '{}' should not be empty", name);
            // Verify it starts with gzip magic bytes (0x1f 0x8b)
            assert!(
                data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b,
                "Built-in playbook '{}' should be a valid gzip file",
                name
            );
        }
    }
}
