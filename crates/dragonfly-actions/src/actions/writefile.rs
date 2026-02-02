//! Write file action
//!
//! Writes content to files on the target filesystem. Supports:
//! - Direct content writing
//! - Base64-encoded content
//! - Directory creation
//! - Permission setting
//! - Automatic partition mounting when DEST_DISK is a block device

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use base64::Engine;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs;
use tokio::process::Command;

/// Native file writing action
///
/// Environment variables:
/// - `DEST_PATH` (required): Target file path
/// - `CONTENTS` (optional): File contents (plain text)
/// - `CONTENTS_B64` (optional): Base64-encoded contents
/// - `MODE` (optional): File permissions in octal (e.g., "0644")
/// - `UID` (optional): Owner user ID
/// - `GID` (optional): Owner group ID
/// - `DEST_DISK` (optional): Block device to mount (e.g., /dev/sda2)
/// - `FS_TYPE` (optional): Filesystem type (default: ext4)
/// - `CREATE_DIRS` (optional): Create parent directories if missing ("true"/"false")
pub struct WriteFileAction;

/// Mount point for partition operations
const MOUNT_POINT: &str = "/mnt/dragonfly";

lazy_static::lazy_static! {
    /// Track whether we've mounted a partition to avoid redundant mounts
    static ref MOUNTED: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
}

#[async_trait]
impl Action for WriteFileAction {
    fn name(&self) -> &str {
        "writefile"
    }

    fn description(&self) -> &str {
        "Write content to a file on the target filesystem"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec!["DEST_PATH"]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["CONTENTS", "CONTENTS_B64", "MODE", "UID", "GID", "CREATE_DIRS", "DEST_DISK", "FS_TYPE"]
    }

    fn validate(&self, ctx: &ActionContext) -> Result<()> {
        ctx.env("DEST_PATH")
            .ok_or_else(|| ActionError::MissingEnvVar("DEST_PATH".to_string()))?;

        // Must have either CONTENTS or CONTENTS_B64
        if ctx.env("CONTENTS").is_none() && ctx.env("CONTENTS_B64").is_none() {
            return Err(ActionError::ValidationFailed(
                "Either CONTENTS or CONTENTS_B64 must be set".to_string(),
            ));
        }

        // Validate MODE if present
        if let Some(mode) = ctx.env("MODE") {
            u32::from_str_radix(mode.trim_start_matches('0'), 8).map_err(|_| {
                ActionError::ValidationFailed(format!("Invalid octal mode: {}", mode))
            })?;
        }

        Ok(())
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let dest_path = ctx.env("DEST_PATH").unwrap();
        let reporter = ctx.progress_reporter();

        // Check if we need to mount a partition first
        let needs_mount = ctx.env("DEST_DISK").is_some();
        let mount_point = if needs_mount {
            // Mount the partition and use mount point for file operations
            let disk = ctx.env("DEST_DISK").unwrap();
            reporter.report(Progress::new(
                self.name(),
                5,
                format!("Mounting partition {}", disk),
            ));

            // Check if already mounted and determine what action to take
            let mount_action = {
                let mounted_guard = MOUNTED.lock().unwrap();
                match mounted_guard.as_ref() {
                    Some(current) if current == &disk => {
                        drop(mounted_guard);
                        None // Already mounted
                    }
                    Some(_) => {
                        drop(mounted_guard);
                        Some(true) // Need to unmount and remount
                    }
                    None => {
                        drop(mounted_guard);
                        Some(false) // Need to mount
                    }
                }
            };

            // Execute the mount action (if any)
            if let Some(action) = mount_action {
                if action {
                    // Different disk mounted, unmount first
                    do_unmount().await?;
                }
                do_mount(&disk).await?;
                let mut guard = MOUNTED.lock().unwrap();
                *guard = Some(disk.to_string());
                drop(guard);
            }

            Some(MOUNT_POINT)
        } else {
            None
        };

        reporter.report(Progress::new(
            self.name(),
            10,
            format!("Writing to {}", dest_path),
        ));

        // Decode content
        let content = if let Some(b64) = ctx.env("CONTENTS_B64") {
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| {
                    ActionError::ValidationFailed(format!("Invalid base64 content: {}", e))
                })?
        } else if let Some(plain) = ctx.env("CONTENTS") {
            plain.as_bytes().to_vec()
        } else {
            return Err(ActionError::ValidationFailed(
                "No content provided".to_string(),
            ));
        };

        if ctx.is_dry_run() {
            return Ok(ActionResult::success(format!(
                "DRY RUN: Would write {} bytes to {}",
                content.len(),
                dest_path
            )));
        }

        // Prepend mount point if we're writing to a mounted partition
        let actual_path = if let Some(mnt) = mount_point {
            Path::new(mnt).join(&dest_path.strip_prefix('/').unwrap_or(&dest_path))
        } else {
            Path::new(dest_path).to_path_buf()
        };

        // Create parent directories if requested
        let create_dirs = ctx.env("CREATE_DIRS").map(|v| v == "true").unwrap_or(true);
        let path = &actual_path;

        if create_dirs {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    reporter.report(Progress::new(
                        self.name(),
                        30,
                        format!("Creating directory {}", parent.display()),
                    ));
                    fs::create_dir_all(parent).await.map_err(|e| {
                        ActionError::ExecutionFailed(format!(
                            "Failed to create directory {}: {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
            }
        }

        // Write the file
        reporter.report(Progress::new(
            self.name(),
            50,
            format!("Writing {} bytes", content.len()),
        ));

        fs::write(&actual_path, &content).await.map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to write file {}: {}", actual_path.display(), e))
        })?;

        // Set permissions if specified
        if let Some(mode_str) = ctx.env("MODE") {
            let mode = u32::from_str_radix(mode_str.trim_start_matches('0'), 8).unwrap();
            reporter.report(Progress::new(
                self.name(),
                70,
                format!("Setting permissions to {:o}", mode),
            ));

            let permissions = std::fs::Permissions::from_mode(mode);
            fs::set_permissions(&actual_path, permissions).await.map_err(|e| {
                ActionError::ExecutionFailed(format!(
                    "Failed to set permissions on {}: {}",
                    actual_path.display(), e
                ))
            })?;
        }

        // Set ownership if specified
        if let (Some(uid_str), Some(gid_str)) = (ctx.env("UID"), ctx.env("GID")) {
            let uid: u32 = uid_str.parse().map_err(|_| {
                ActionError::ValidationFailed(format!("Invalid UID: {}", uid_str))
            })?;
            let gid: u32 = gid_str.parse().map_err(|_| {
                ActionError::ValidationFailed(format!("Invalid GID: {}", gid_str))
            })?;

            reporter.report(Progress::new(
                self.name(),
                90,
                format!("Setting ownership to {}:{}", uid, gid),
            ));

            std::os::unix::fs::chown(&actual_path, Some(uid), Some(gid)).map_err(|e| {
                ActionError::ExecutionFailed(format!(
                    "Failed to set ownership on {}: {}",
                    actual_path.display(), e
                ))
            })?;
        }

        reporter.report(Progress::completed(self.name()));

        Ok(ActionResult::success(format!(
            "Successfully wrote {} bytes to {}",
            content.len(),
            dest_path
        ))
        .with_output("bytes_written", content.len())
        .with_output("path", dest_path))
    }
}

/// Detect filesystem type by reading magic bytes from block device
///
/// Returns the filesystem type string (e.g., "ext4", "xfs", "btrfs")
/// or None if unknown/unreadable.
fn detect_filesystem(device: &str) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = match std::fs::File::open(device) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("Failed to open {} for fs detection: {}", device, e);
            return None;
        }
    };

    let mut buf = [0u8; 8];

    // Check for ext2/3/4: magic 0xEF53 at offset 1080 (0x438)
    if file.seek(SeekFrom::Start(0x438)).is_ok() && file.read_exact(&mut buf[..2]).is_ok() {
        if buf[0] == 0x53 && buf[1] == 0xEF {
            tracing::debug!("Detected ext2/3/4 filesystem on {}", device);
            return Some("ext4".to_string()); // ext4 is backward compatible
        }
    }

    // Check for XFS: magic "XFSB" at offset 0
    if file.seek(SeekFrom::Start(0)).is_ok() && file.read_exact(&mut buf[..4]).is_ok() {
        if &buf[..4] == b"XFSB" {
            tracing::debug!("Detected XFS filesystem on {}", device);
            return Some("xfs".to_string());
        }
    }

    // Check for btrfs: magic "_BHRfS_M" at offset 0x10040
    if file.seek(SeekFrom::Start(0x10040)).is_ok() && file.read_exact(&mut buf).is_ok() {
        if &buf == b"_BHRfS_M" {
            tracing::debug!("Detected btrfs filesystem on {}", device);
            return Some("btrfs".to_string());
        }
    }

    // Check for FAT32: Look for FAT signature
    if file.seek(SeekFrom::Start(0x52)).is_ok() && file.read_exact(&mut buf).is_ok() {
        if &buf[..5] == b"FAT32" {
            tracing::debug!("Detected FAT32 filesystem on {}", device);
            return Some("vfat".to_string());
        }
    }

    // Check for FAT16/FAT12
    if file.seek(SeekFrom::Start(0x36)).is_ok() && file.read_exact(&mut buf).is_ok() {
        if &buf[..3] == b"FAT" {
            tracing::debug!("Detected FAT filesystem on {}", device);
            return Some("vfat".to_string());
        }
    }

    tracing::warn!("Could not detect filesystem type on {}", device);
    None
}

/// Mount a partition to the dragonfly mount point
async fn do_mount(disk: &str) -> Result<()> {
    // Create mount point if it doesn't exist
    if !Path::new(MOUNT_POINT).exists() {
        fs::create_dir_all(MOUNT_POINT).await.map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to create mount point {}: {}", MOUNT_POINT, e))
        })?;
    }

    // Detect filesystem type
    let fs_type = detect_filesystem(disk);

    // Build mount command with filesystem type if detected
    // Explicitly request rw mode to get a clear error if fs can't be mounted rw
    let output = if let Some(ref fstype) = fs_type {
        tracing::info!("Mounting {} as {} to {} (rw)", disk, fstype, MOUNT_POINT);
        Command::new("mount")
            .args(["-t", fstype, "-o", "rw", disk, MOUNT_POINT])
            .output()
            .await
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to execute mount: {}", e)))?
    } else {
        tracing::info!("Mounting {} to {} (auto-detect fs, rw)", disk, MOUNT_POINT);
        Command::new("mount")
            .args(["-o", "rw", disk, MOUNT_POINT])
            .output()
            .await
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to execute mount: {}", e)))?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Failed to mount {} to {}: {}",
            disk, MOUNT_POINT, stderr
        )));
    }

    tracing::info!("Mounted {} to {}", disk, MOUNT_POINT);
    Ok(())
}

/// Unmount the dragonfly mount point
async fn do_unmount() -> Result<()> {
    let output = Command::new("umount")
        .arg(MOUNT_POINT)
        .output()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to execute umount: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Failed to unmount {}: {}",
            MOUNT_POINT, stderr
        )));
    }

    tracing::info!("Unmounted {}", MOUNT_POINT);
    Ok(())
}

/// Clean up any mounted partitions
///
/// This function should be called after workflow completion to ensure
/// partitions are properly unmounted. It's safe to call multiple times.
pub async fn cleanup_mount() {
    let needs_unmount = {
        let mounted_guard = MOUNTED.lock().unwrap();
        mounted_guard.is_some()
    };

    if needs_unmount {
        if let Err(e) = do_unmount().await {
            tracing::warn!("Failed to unmount during cleanup: {}", e);
        } else {
            let mut guard = MOUNTED.lock().unwrap();
            *guard = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use dragonfly_crd::{Hardware, HardwareSpec, ObjectMeta, TypeMeta, Workflow};
    use tempfile::tempdir;

    fn test_context() -> ActionContext {
        let hardware = Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test"),
            spec: HardwareSpec::default(),
            status: None,
        };
        let workflow = Workflow::new("test", "test", "test");
        ActionContext::new(hardware, workflow)
    }

    #[test]
    fn test_validation_missing_path() {
        let action = WriteFileAction;
        let ctx = test_context().with_env("CONTENTS", "hello");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DEST_PATH"));
    }

    #[test]
    fn test_validation_missing_content() {
        let action = WriteFileAction;
        let ctx = test_context().with_env("DEST_PATH", "/tmp/test.txt");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CONTENTS"));
    }

    #[test]
    fn test_validation_invalid_mode() {
        let action = WriteFileAction;
        let ctx = test_context()
            .with_env("DEST_PATH", "/tmp/test.txt")
            .with_env("CONTENTS", "hello")
            .with_env("MODE", "999"); // Invalid octal

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("octal"));
    }

    #[test]
    fn test_validation_success() {
        let action = WriteFileAction;
        let ctx = test_context()
            .with_env("DEST_PATH", "/tmp/test.txt")
            .with_env("CONTENTS", "hello world")
            .with_env("MODE", "0644");

        assert!(action.validate(&ctx).is_ok());
    }

    #[tokio::test]
    async fn test_write_plain_content() {
        let action = WriteFileAction;
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("test.txt");

        let ctx = test_context()
            .with_env("DEST_PATH", file_path.to_str().unwrap())
            .with_env("CONTENTS", "Hello, World!");

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[tokio::test]
    async fn test_write_base64_content() {
        let action = WriteFileAction;
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("test.txt");

        let encoded = base64::engine::general_purpose::STANDARD.encode("Hello, Base64!");

        let ctx = test_context()
            .with_env("DEST_PATH", file_path.to_str().unwrap())
            .with_env("CONTENTS_B64", &encoded);

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Hello, Base64!");
    }

    #[tokio::test]
    async fn test_write_with_permissions() {
        let action = WriteFileAction;
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("script.sh");

        let ctx = test_context()
            .with_env("DEST_PATH", file_path.to_str().unwrap())
            .with_env("CONTENTS", "#!/bin/sh\necho hello")
            .with_env("MODE", "0755");

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());

        let metadata = std::fs::metadata(&file_path).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[tokio::test]
    async fn test_write_creates_directories() {
        let action = WriteFileAction;
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("a/b/c/test.txt");

        let ctx = test_context()
            .with_env("DEST_PATH", file_path.to_str().unwrap())
            .with_env("CONTENTS", "nested file")
            .with_env("CREATE_DIRS", "true");

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
        assert!(file_path.exists());
    }

    #[tokio::test]
    async fn test_dry_run() {
        let action = WriteFileAction;
        let ctx = test_context()
            .with_env("DEST_PATH", "/this/path/should/not/exist.txt")
            .with_env("CONTENTS", "test")
            .with_dry_run(true);

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
        assert!(result.message.contains("DRY RUN"));
        assert!(!Path::new("/this/path/should/not/exist.txt").exists());
    }
}
