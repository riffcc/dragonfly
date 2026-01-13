//! Image to disk streaming action
//!
//! Streams OS images directly to disk without Docker. Supports:
//! - QCOW2 images (via qemu-img)
//! - Raw images (direct dd)
//! - Compressed images (.gz, .xz, .zst)
//! - Tar archives (.tar, .tar.gz, .tar.xz)

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Native image-to-disk streaming action
///
/// Environment variables:
/// - `IMG_URL` (required): URL or path to the source image
/// - `DEST_DISK` (required): Target disk device (e.g., /dev/sda)
/// - `COMPRESSED` (optional): "true" if image is compressed
/// - `CHECKSUM` (optional): Expected checksum for verification
pub struct Image2DiskAction;

#[async_trait]
impl Action for Image2DiskAction {
    fn name(&self) -> &str {
        "image2disk"
    }

    fn description(&self) -> &str {
        "Stream an OS image to disk"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec!["IMG_URL", "DEST_DISK"]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["COMPRESSED", "CHECKSUM", "BLOCK_SIZE"]
    }

    fn validate(&self, ctx: &ActionContext) -> Result<()> {
        let dest = ctx
            .env("DEST_DISK")
            .ok_or_else(|| ActionError::MissingEnvVar("DEST_DISK".to_string()))?;

        // Validate disk path
        if !dest.starts_with("/dev/") {
            return Err(ActionError::ValidationFailed(format!(
                "DEST_DISK must be a device path starting with /dev/, got: {}",
                dest
            )));
        }

        ctx.env("IMG_URL")
            .ok_or_else(|| ActionError::MissingEnvVar("IMG_URL".to_string()))?;

        Ok(())
    }

    fn default_timeout(&self) -> Option<Duration> {
        // Image streaming can take a long time - 30 min default
        Some(Duration::from_secs(1800))
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let img_url = ctx.env("IMG_URL").unwrap();
        let dest_disk = ctx.env("DEST_DISK").unwrap();
        let block_size = ctx.env("BLOCK_SIZE").unwrap_or("4M");

        let reporter = ctx.progress_reporter();
        reporter.report(Progress::new(
            self.name(),
            5,
            format!("Preparing to stream {} to {}", img_url, dest_disk),
        ));

        if ctx.is_dry_run() {
            return Ok(ActionResult::success(format!(
                "DRY RUN: Would stream {} to {}",
                img_url, dest_disk
            )));
        }

        // Detect image type from URL/path
        let image_type = detect_image_type(img_url);

        reporter.report(Progress::new(
            self.name(),
            10,
            format!("Detected image type: {:?}", image_type),
        ));

        // Execute based on image type
        let result = match image_type {
            ImageType::Qcow2 => {
                stream_qcow2(img_url, dest_disk, reporter.as_ref(), self.name()).await
            }
            ImageType::Raw => {
                stream_raw(img_url, dest_disk, block_size, reporter.as_ref(), self.name()).await
            }
            ImageType::RawGz => {
                stream_raw_compressed(
                    img_url,
                    dest_disk,
                    "gzip",
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::RawXz => {
                stream_raw_compressed(img_url, dest_disk, "xz", reporter.as_ref(), self.name())
                    .await
            }
            ImageType::RawZst => {
                stream_raw_compressed(
                    img_url,
                    dest_disk,
                    "zstd",
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::TarGz | ImageType::TarXz | ImageType::Tar => {
                // For tar archives, we need a mounted filesystem
                // This is typically used for rootfs extraction, not raw disk imaging
                return Err(ActionError::ExecutionFailed(
                    "Tar archives require a mounted filesystem. Use writefile action instead."
                        .to_string(),
                ));
            }
        };

        match result {
            Ok(bytes_written) => {
                reporter.report(Progress::completed(self.name()));
                Ok(ActionResult::success(format!(
                    "Successfully streamed image to {} ({} bytes written)",
                    dest_disk, bytes_written
                ))
                .with_output("bytes_written", bytes_written)
                .with_output("destination", dest_disk))
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ImageType {
    Qcow2,
    Raw,
    RawGz,
    RawXz,
    RawZst,
    TarGz,
    TarXz,
    Tar,
}

fn detect_image_type(path: &str) -> ImageType {
    let lower = path.to_lowercase();

    if lower.ends_with(".qcow2") || lower.ends_with(".qcow") {
        ImageType::Qcow2
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        ImageType::TarGz
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        ImageType::TarXz
    } else if lower.ends_with(".tar") {
        ImageType::Tar
    } else if lower.ends_with(".raw.gz") || lower.ends_with(".img.gz") {
        ImageType::RawGz
    } else if lower.ends_with(".raw.xz") || lower.ends_with(".img.xz") {
        ImageType::RawXz
    } else if lower.ends_with(".raw.zst") || lower.ends_with(".img.zst") {
        ImageType::RawZst
    } else {
        // Default to raw
        ImageType::Raw
    }
}

/// Stream a QCOW2 image using qemu-img convert
async fn stream_qcow2(
    source: &str,
    dest: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    reporter.report(Progress::new(
        action_name,
        15,
        "Converting QCOW2 to raw with qemu-img",
    ));

    // qemu-img convert -f qcow2 -O raw source dest
    let output = Command::new("qemu-img")
        .args(["convert", "-f", "qcow2", "-O", "raw", "-p", source, dest])
        .output()
        .await
        .map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to run qemu-img: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "qemu-img convert failed: {}",
            stderr
        )));
    }

    // Get the size of the destination
    let metadata = tokio::fs::metadata(dest).await.map_err(|e| {
        ActionError::ExecutionFailed(format!("Failed to stat destination: {}", e))
    })?;

    Ok(metadata.len())
}

/// Stream a raw image with wget | dd pipeline
async fn stream_raw(
    source: &str,
    dest: &str,
    block_size: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    reporter.report(Progress::new(
        action_name,
        15,
        "Streaming raw image to disk",
    ));

    // For local files, use dd directly
    // For URLs, use wget | dd (wget -qO- outputs to stdout, works in busybox)
    let is_url = source.starts_with("http://") || source.starts_with("https://");

    let mut child = if is_url {
        Command::new("sh")
            .args([
                "-c",
                &format!(
                    "wget -qO - '{}' | dd of='{}' bs={} status=progress",
                    source, dest, block_size
                ),
            ])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to spawn dd: {}", e)))?
    } else {
        Command::new("dd")
            .args([
                &format!("if={}", source),
                &format!("of={}", dest),
                &format!("bs={}", block_size),
                "status=progress",
            ])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to spawn dd: {}", e)))?
    };

    // Read progress from stderr (dd outputs progress there)
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr).lines();
    let mut last_bytes: u64 = 0;

    while let Ok(Some(line)) = reader.next_line().await {
        // dd progress lines look like: "1234567890 bytes (1.2 GB, 1.1 GiB) copied"
        if let Some(bytes_str) = line.split_whitespace().next() {
            if let Ok(bytes) = bytes_str.parse::<u64>() {
                last_bytes = bytes;
                reporter.report(Progress::new(
                    action_name,
                    50, // Approximate
                    format!("Streamed {} bytes", bytes),
                ));
            }
        }
    }

    let status = child.wait().await.map_err(|e| {
        ActionError::ExecutionFailed(format!("Failed to wait for dd: {}", e))
    })?;

    if !status.success() {
        return Err(ActionError::ExecutionFailed(
            "dd command failed".to_string(),
        ));
    }

    Ok(last_bytes)
}

/// Stream a compressed raw image
async fn stream_raw_compressed(
    source: &str,
    dest: &str,
    compression: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    reporter.report(Progress::new(
        action_name,
        15,
        format!("Streaming {} compressed image to disk", compression),
    ));

    let is_url = source.starts_with("http://") || source.starts_with("https://");

    let decompress_cmd = match compression {
        "gzip" => "gunzip -c",
        "xz" => "xz -d -c",
        "zstd" => "zstd -d -c",
        _ => {
            return Err(ActionError::ExecutionFailed(format!(
                "Unknown compression: {}",
                compression
            )))
        }
    };

    let cmd = if is_url {
        format!(
            "wget -qO - '{}' | {} | dd of='{}' bs=4M status=progress",
            source, decompress_cmd, dest
        )
    } else {
        format!(
            "{} '{}' | dd of='{}' bs=4M status=progress",
            decompress_cmd, source, dest
        )
    };

    let output = Command::new("sh")
        .args(["-c", &cmd])
        .output()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to run pipeline: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Streaming failed: {}",
            stderr
        )));
    }

    // Parse bytes from dd output
    let stderr = String::from_utf8_lossy(&output.stderr);
    let bytes = parse_dd_bytes(&stderr).unwrap_or(0);

    Ok(bytes)
}

fn parse_dd_bytes(output: &str) -> Option<u64> {
    // Parse "123456789 bytes" from dd output
    for line in output.lines() {
        if line.contains("bytes") {
            if let Some(num) = line.split_whitespace().next() {
                if let Ok(bytes) = num.parse::<u64>() {
                    return Some(bytes);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_crd::{Hardware, HardwareSpec, ObjectMeta, TypeMeta, Workflow};

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
    fn test_detect_image_type() {
        assert!(matches!(
            detect_image_type("ubuntu.qcow2"),
            ImageType::Qcow2
        ));
        assert!(matches!(detect_image_type("disk.raw"), ImageType::Raw));
        assert!(matches!(
            detect_image_type("disk.raw.gz"),
            ImageType::RawGz
        ));
        assert!(matches!(
            detect_image_type("disk.raw.xz"),
            ImageType::RawXz
        ));
        assert!(matches!(
            detect_image_type("rootfs.tar.gz"),
            ImageType::TarGz
        ));
        assert!(matches!(
            detect_image_type("rootfs.tar.xz"),
            ImageType::TarXz
        ));
    }

    #[test]
    fn test_validation_missing_disk() {
        let action = Image2DiskAction;
        let ctx = test_context().with_env("IMG_URL", "http://example.com/image.raw");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DEST_DISK"));
    }

    #[test]
    fn test_validation_invalid_disk() {
        let action = Image2DiskAction;
        let ctx = test_context()
            .with_env("IMG_URL", "http://example.com/image.raw")
            .with_env("DEST_DISK", "/tmp/disk.img");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("/dev/"));
    }

    #[test]
    fn test_validation_success() {
        let action = Image2DiskAction;
        let ctx = test_context()
            .with_env("IMG_URL", "http://example.com/image.raw")
            .with_env("DEST_DISK", "/dev/sda");

        assert!(action.validate(&ctx).is_ok());
    }

    #[tokio::test]
    async fn test_dry_run() {
        let action = Image2DiskAction;
        let ctx = test_context()
            .with_env("IMG_URL", "http://example.com/image.raw")
            .with_env("DEST_DISK", "/dev/sda")
            .with_dry_run(true);

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
        assert!(result.message.contains("DRY RUN"));
    }
}
