//! Image to disk streaming action
//!
//! Streams OS images directly to disk using native Rust. Supports:
//! - QCOW2 images (via qemu-img - requires external tool)
//! - Raw images (native streaming)
//! - Compressed images (.gz, .xz, .zst) with native decompression
//! - Tar archives (.tar.xz, .tar.gz) with streaming extraction
//!
//! All operations stream directly to disk without buffering entire files in memory,
//! making this suitable for memory-constrained environments like Alpine ramdisks.

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_compression::tokio::bufread::{GzipDecoder, XzDecoder, ZstdDecoder};
use async_trait::async_trait;
use futures::StreamExt;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader};
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
            ImageType::Raw => stream_raw(img_url, dest_disk, reporter.as_ref(), self.name()).await,
            ImageType::RawGz => {
                stream_compressed(
                    img_url,
                    dest_disk,
                    Compression::Gzip,
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::RawXz => {
                stream_compressed(
                    img_url,
                    dest_disk,
                    Compression::Xz,
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::RawZst => {
                stream_compressed(
                    img_url,
                    dest_disk,
                    Compression::Zstd,
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::TarGz => {
                stream_tar_compressed(
                    img_url,
                    dest_disk,
                    Compression::Gzip,
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::TarXz => {
                stream_tar_compressed(
                    img_url,
                    dest_disk,
                    Compression::Xz,
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::TarZst => {
                stream_tar_compressed(
                    img_url,
                    dest_disk,
                    Compression::Zstd,
                    reporter.as_ref(),
                    self.name(),
                )
                .await
            }
            ImageType::Tar => stream_tar(img_url, dest_disk, reporter.as_ref(), self.name()).await,
        };

        match result {
            Ok(bytes_written) => {
                // Run partprobe to make kernel re-read partition table
                // This is critical because the partition table changed during imaging
                reporter.report(Progress::new(
                    self.name(),
                    95,
                    "Re-reading partition table with partprobe",
                ));

                if let Err(e) = Command::new("partprobe")
                    .arg(&dest_disk)
                    .output()
                    .await
                    .map_err(|e| {
                        ActionError::ExecutionFailed(format!("Failed to run partprobe: {}", e))
                    })
                {
                    // Log warning but don't fail - partprobe may fail harmlessly
                    tracing::warn!("partprobe failed (non-critical): {}", e);
                }

                // On Alpine/mdev systems, refresh device nodes after partition table change
                if let Err(e) = Command::new("mdev").arg("-s").output().await {
                    tracing::debug!("mdev -s not available (not Alpine?): {}", e);
                }

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
    TarZst,
    Tar,
}

#[derive(Debug, Clone, Copy)]
enum Compression {
    Gzip,
    Xz,
    Zstd,
}

fn detect_image_type(path: &str) -> ImageType {
    let lower = path.to_lowercase();

    if lower.ends_with(".qcow2") || lower.ends_with(".qcow") {
        ImageType::Qcow2
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        ImageType::TarGz
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        ImageType::TarXz
    } else if lower.ends_with(".tar.zst") || lower.ends_with(".tzst") {
        ImageType::TarZst
    } else if lower.ends_with(".tar") {
        ImageType::Tar
    } else if lower.ends_with(".raw.gz") || lower.ends_with(".img.gz") || lower.ends_with(".gz") {
        ImageType::RawGz
    } else if lower.ends_with(".raw.xz") || lower.ends_with(".img.xz") || lower.ends_with(".xz") {
        ImageType::RawXz
    } else if lower.ends_with(".raw.zst") || lower.ends_with(".img.zst") || lower.ends_with(".zst")
    {
        ImageType::RawZst
    } else {
        // Default to raw
        ImageType::Raw
    }
}

/// Stream a QCOW2 image using qemu-img convert (requires external tool)
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
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to run qemu-img: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "qemu-img convert failed: {}",
            stderr
        )));
    }

    // Get the size of the destination
    let metadata = tokio::fs::metadata(dest)
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to stat destination: {}", e)))?;

    Ok(metadata.len())
}

/// Stream a raw image using native Rust
async fn stream_raw(
    source: &str,
    dest: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    reporter.report(Progress::new(
        action_name,
        15,
        "Streaming raw image to disk (native)",
    ));

    let is_url = source.starts_with("http://") || source.starts_with("https://");

    if is_url {
        stream_from_url(source, dest, None, reporter, action_name).await
    } else {
        stream_from_file(source, dest, reporter, action_name).await
    }
}

/// Stream a compressed raw image using native Rust decompression
async fn stream_compressed(
    source: &str,
    dest: &str,
    compression: Compression,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    reporter.report(Progress::new(
        action_name,
        15,
        format!(
            "Streaming {:?} compressed image to disk (native)",
            compression
        ),
    ));

    let is_url = source.starts_with("http://") || source.starts_with("https://");

    if is_url {
        stream_from_url(source, dest, Some(compression), reporter, action_name).await
    } else {
        stream_compressed_file(source, dest, compression, reporter, action_name).await
    }
}

/// Stream from HTTP URL to disk with optional decompression
async fn stream_from_url(
    url: &str,
    dest: &str,
    compression: Option<Compression>,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    // Create HTTP client and start download
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(ActionError::ExecutionFailed(format!(
            "HTTP error: {}",
            response.status()
        )));
    }

    // Get content length for progress reporting
    let total_size = response.content_length();

    reporter.report(Progress::new(
        action_name,
        20,
        format!(
            "Downloading {} ({})",
            url,
            total_size
                .map(|s| format_bytes(s))
                .unwrap_or_else(|| "unknown size".to_string())
        ),
    ));

    // Open destination device for writing
    let mut dest_file = OpenOptions::new()
        .write(true)
        .open(dest)
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to open {}: {}", dest, e)))?;

    // Convert response body to async reader
    let stream = response.bytes_stream();
    let stream_reader = tokio_util::io::StreamReader::new(
        stream.map(|result| result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))),
    );
    let buffered = BufReader::new(stream_reader);

    // Apply decompression if needed and write to disk
    let bytes_written = match compression {
        Some(Compression::Gzip) => {
            let decoder = GzipDecoder::new(buffered);
            write_to_disk(decoder, &mut dest_file, total_size, reporter, action_name).await?
        }
        Some(Compression::Xz) => {
            let decoder = XzDecoder::new(buffered);
            write_to_disk(decoder, &mut dest_file, total_size, reporter, action_name).await?
        }
        Some(Compression::Zstd) => {
            let decoder = ZstdDecoder::new(buffered);
            write_to_disk(decoder, &mut dest_file, total_size, reporter, action_name).await?
        }
        None => write_to_disk(buffered, &mut dest_file, total_size, reporter, action_name).await?,
    };

    // Sync to ensure all data is written
    dest_file
        .sync_all()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to sync disk: {}", e)))?;

    Ok(bytes_written)
}

/// Stream from local file to disk
async fn stream_from_file(
    source: &str,
    dest: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    let source_file = tokio::fs::File::open(source)
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to open source: {}", e)))?;

    let total_size = source_file.metadata().await.ok().map(|m| m.len());
    let buffered = BufReader::new(source_file);

    let mut dest_file = OpenOptions::new()
        .write(true)
        .open(dest)
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to open {}: {}", dest, e)))?;

    let bytes_written =
        write_to_disk(buffered, &mut dest_file, total_size, reporter, action_name).await?;

    dest_file
        .sync_all()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to sync disk: {}", e)))?;

    Ok(bytes_written)
}

/// Stream from compressed local file to disk
async fn stream_compressed_file(
    source: &str,
    dest: &str,
    compression: Compression,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    let source_file = tokio::fs::File::open(source)
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to open source: {}", e)))?;

    let total_size = source_file.metadata().await.ok().map(|m| m.len());
    let buffered = BufReader::new(source_file);

    let mut dest_file = OpenOptions::new()
        .write(true)
        .open(dest)
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to open {}: {}", dest, e)))?;

    let bytes_written = match compression {
        Compression::Gzip => {
            let decoder = GzipDecoder::new(buffered);
            write_to_disk(decoder, &mut dest_file, total_size, reporter, action_name).await?
        }
        Compression::Xz => {
            let decoder = XzDecoder::new(buffered);
            write_to_disk(decoder, &mut dest_file, total_size, reporter, action_name).await?
        }
        Compression::Zstd => {
            let decoder = ZstdDecoder::new(buffered);
            write_to_disk(decoder, &mut dest_file, total_size, reporter, action_name).await?
        }
    };

    dest_file
        .sync_all()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to sync disk: {}", e)))?;

    Ok(bytes_written)
}

/// Write from an async reader to disk with progress reporting
async fn write_to_disk<R: AsyncRead + Unpin>(
    mut reader: R,
    dest: &mut tokio::fs::File,
    total_size: Option<u64>,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    use tokio::io::AsyncReadExt;

    // Use 4MB buffer for efficient disk writes
    let mut buffer = vec![0u8; 4 * 1024 * 1024];
    let mut bytes_written: u64 = 0;
    let mut last_report = std::time::Instant::now();
    let start_time = std::time::Instant::now();

    loop {
        let n = reader
            .read(&mut buffer)
            .await
            .map_err(|e| ActionError::ExecutionFailed(format!("Read error: {}", e)))?;

        if n == 0 {
            break;
        }

        dest.write_all(&buffer[..n])
            .await
            .map_err(|e| ActionError::ExecutionFailed(format!("Write error: {}", e)))?;

        bytes_written += n as u64;

        // Report progress every 500ms to avoid flooding
        if last_report.elapsed() > Duration::from_millis(500) {
            let elapsed = start_time.elapsed();
            let speed = if elapsed.as_secs() > 0 {
                bytes_written / elapsed.as_secs()
            } else {
                bytes_written
            };

            // Calculate ETA if we know total size
            let eta = total_size.and_then(|total| {
                if speed > 0 && bytes_written < total {
                    let remaining = total - bytes_written;
                    Some(Duration::from_secs(remaining / speed))
                } else {
                    None
                }
            });

            let progress = if let Some(total) = total_size {
                Progress::new(
                    action_name,
                    0, // will be calculated by with_bytes
                    format!(
                        "{} @ {}/s",
                        format_bytes(bytes_written),
                        format_bytes(speed)
                    ),
                )
                .with_bytes(bytes_written, total)
            } else {
                // No total size known - report raw bytes
                Progress::new(
                    action_name,
                    50, // Unknown progress
                    format!(
                        "{} @ {}/s",
                        format_bytes(bytes_written),
                        format_bytes(speed)
                    ),
                )
            };

            let progress = if let Some(eta) = eta {
                progress.with_eta(eta)
            } else {
                progress
            };

            reporter.report(progress);
            last_report = std::time::Instant::now();
        }
    }

    // Final progress report
    let elapsed = start_time.elapsed();
    let avg_speed = if elapsed.as_secs() > 0 {
        bytes_written / elapsed.as_secs()
    } else {
        bytes_written
    };

    reporter.report(Progress::new(
        action_name,
        95,
        format!(
            "Syncing {} (avg {}/s, took {:.1}s)",
            format_bytes(bytes_written),
            format_bytes(avg_speed),
            elapsed.as_secs_f64()
        ),
    ));

    Ok(bytes_written)
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Stream a tar archive with compression, extracting the disk image directly to disk
async fn stream_tar_compressed(
    source: &str,
    dest: &str,
    compression: Compression,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    reporter.report(Progress::new(
        action_name,
        15,
        format!("Streaming {:?} compressed tar archive to disk", compression),
    ));

    let is_url = source.starts_with("http://") || source.starts_with("https://");

    if is_url {
        stream_tar_from_url(source, dest, Some(compression), reporter, action_name).await
    } else {
        stream_tar_from_file(source, dest, Some(compression), reporter, action_name).await
    }
}

/// Stream an uncompressed tar archive, extracting the disk image directly to disk
async fn stream_tar(
    source: &str,
    dest: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    reporter.report(Progress::new(
        action_name,
        15,
        "Streaming tar archive to disk",
    ));

    let is_url = source.starts_with("http://") || source.starts_with("https://");

    if is_url {
        stream_tar_from_url(source, dest, None, reporter, action_name).await
    } else {
        stream_tar_from_file(source, dest, None, reporter, action_name).await
    }
}

/// Stream tar from URL, extract disk image, and write to disk
async fn stream_tar_from_url(
    url: &str,
    dest: &str,
    compression: Option<Compression>,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    use tokio_tar::Archive;

    // Create HTTP client and start download
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(ActionError::ExecutionFailed(format!(
            "HTTP error: {}",
            response.status()
        )));
    }

    let total_size = response.content_length();

    reporter.report(Progress::new(
        action_name,
        20,
        format!(
            "Downloading tar archive {} ({})",
            url,
            total_size
                .map(|s| format_bytes(s))
                .unwrap_or_else(|| "unknown size".to_string())
        ),
    ));

    // Convert response body to async reader
    let stream = response.bytes_stream();
    let stream_reader = tokio_util::io::StreamReader::new(
        stream.map(|result| result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))),
    );
    let buffered = BufReader::new(stream_reader);

    // Apply decompression and create tar archive reader
    let bytes_written = match compression {
        Some(Compression::Gzip) => {
            let decoder = GzipDecoder::new(buffered);
            extract_disk_from_tar(decoder, dest, reporter, action_name).await?
        }
        Some(Compression::Xz) => {
            let decoder = XzDecoder::new(buffered);
            extract_disk_from_tar(decoder, dest, reporter, action_name).await?
        }
        Some(Compression::Zstd) => {
            let decoder = ZstdDecoder::new(buffered);
            extract_disk_from_tar(decoder, dest, reporter, action_name).await?
        }
        None => extract_disk_from_tar(buffered, dest, reporter, action_name).await?,
    };

    Ok(bytes_written)
}

/// Stream tar from local file
async fn stream_tar_from_file(
    source: &str,
    dest: &str,
    compression: Option<Compression>,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    let source_file = tokio::fs::File::open(source)
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to open source: {}", e)))?;

    let buffered = BufReader::new(source_file);

    let bytes_written = match compression {
        Some(Compression::Gzip) => {
            let decoder = GzipDecoder::new(buffered);
            extract_disk_from_tar(decoder, dest, reporter, action_name).await?
        }
        Some(Compression::Xz) => {
            let decoder = XzDecoder::new(buffered);
            extract_disk_from_tar(decoder, dest, reporter, action_name).await?
        }
        Some(Compression::Zstd) => {
            let decoder = ZstdDecoder::new(buffered);
            extract_disk_from_tar(decoder, dest, reporter, action_name).await?
        }
        None => extract_disk_from_tar(buffered, dest, reporter, action_name).await?,
    };

    Ok(bytes_written)
}

/// Extract disk image from tar archive and write directly to disk
///
/// Looks for files ending in .raw, .img, or the largest file in the archive
async fn extract_disk_from_tar<R: AsyncRead + Unpin>(
    reader: R,
    dest: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<u64> {
    use tokio::io::AsyncReadExt;
    use tokio_tar::Archive;

    let mut archive = Archive::new(reader);
    let mut entries = archive
        .entries()
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to read tar entries: {}", e)))?;

    reporter.report(Progress::new(
        action_name,
        30,
        "Scanning tar archive for disk image",
    ));

    // Find the disk image entry (look for .raw, .img, or largest file)
    while let Some(entry) = entries.next().await {
        let mut entry = entry.map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to read tar entry: {}", e))
        })?;

        let path = entry.path().map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to get entry path: {}", e))
        })?;

        let path_str = path.to_string_lossy().to_string();
        let is_disk_image = path_str.ends_with(".raw")
            || path_str.ends_with(".img")
            || path_str.ends_with(".qcow2");

        if is_disk_image {
            reporter.report(Progress::new(
                action_name,
                35,
                format!("Found disk image: {}", path_str),
            ));

            // Open destination device
            let mut dest_file = OpenOptions::new()
                .write(true)
                .open(dest)
                .await
                .map_err(|e| {
                    ActionError::ExecutionFailed(format!("Failed to open {}: {}", dest, e))
                })?;

            // Stream the entry directly to disk
            let entry_size = entry.header().size().ok();
            let bytes_written =
                write_to_disk(entry, &mut dest_file, entry_size, reporter, action_name).await?;

            dest_file
                .sync_all()
                .await
                .map_err(|e| ActionError::ExecutionFailed(format!("Failed to sync disk: {}", e)))?;

            return Ok(bytes_written);
        }
    }

    Err(ActionError::ExecutionFailed(
        "No disk image found in tar archive (expected .raw, .img, or .qcow2 file)".to_string(),
    ))
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
        assert!(matches!(detect_image_type("disk.raw.gz"), ImageType::RawGz));
        assert!(matches!(detect_image_type("disk.raw.xz"), ImageType::RawXz));
        assert!(matches!(
            detect_image_type("rootfs.tar.gz"),
            ImageType::TarGz
        ));
        assert!(matches!(
            detect_image_type("rootfs.tar.xz"),
            ImageType::TarXz
        ));
        assert!(matches!(
            detect_image_type("ubuntu-2404.raw.tar.zst"),
            ImageType::TarZst
        ));
        // Test .gz alone (common cloud image format)
        assert!(matches!(
            detect_image_type("debian-12-generic-amd64.qcow2.gz"),
            ImageType::RawGz
        ));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 bytes");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1536 * 1024 * 1024), "1.50 GB");
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
