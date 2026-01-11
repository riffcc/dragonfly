//! Write file action
//!
//! Writes content to files on the target filesystem. Supports:
//! - Direct content writing
//! - Base64-encoded content
//! - Directory creation
//! - Permission setting

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use base64::Engine;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs;

/// Native file writing action
///
/// Environment variables:
/// - `DEST_PATH` (required): Target file path
/// - `CONTENTS` (optional): File contents (plain text)
/// - `CONTENTS_B64` (optional): Base64-encoded contents
/// - `MODE` (optional): File permissions in octal (e.g., "0644")
/// - `UID` (optional): Owner user ID
/// - `GID` (optional): Owner group ID
/// - `CREATE_DIRS` (optional): Create parent directories if missing ("true"/"false")
pub struct WriteFileAction;

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
        vec!["CONTENTS", "CONTENTS_B64", "MODE", "UID", "GID", "CREATE_DIRS"]
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

        // Create parent directories if requested
        let create_dirs = ctx.env("CREATE_DIRS").map(|v| v == "true").unwrap_or(true);
        let path = Path::new(dest_path);

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

        fs::write(dest_path, &content).await.map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to write file {}: {}", dest_path, e))
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
            fs::set_permissions(dest_path, permissions).await.map_err(|e| {
                ActionError::ExecutionFailed(format!(
                    "Failed to set permissions on {}: {}",
                    dest_path, e
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

            std::os::unix::fs::chown(dest_path, Some(uid), Some(gid)).map_err(|e| {
                ActionError::ExecutionFailed(format!(
                    "Failed to set ownership on {}: {}",
                    dest_path, e
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
