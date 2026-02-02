//! Image Cache Service
//!
//! JIT conversion of QCOW2 images to raw format for streaming to agents.
//! When a template references a QCOW2 image (like Ubuntu cloud images),
//! we download, convert to raw, compress, and cache it server-side.
//!
//! This offloads the heavy conversion work from memory-constrained agents
//! to the server, which has more resources.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Known QCOW2 image sources that need conversion
/// Maps URL patterns to cache names
const QCOW2_SOURCES: &[(&str, &str)] = &[
    // Ubuntu cloud images - direct QCOW2 .img files
    ("cloud-images.ubuntu.com/noble", "ubuntu-2404"),
    ("cloud-images.ubuntu.com/jammy", "ubuntu-2204"),
    ("cloud-images.ubuntu.com/focal", "ubuntu-2004"),
];

/// Image cache service
pub struct ImageCache {
    /// Cache directory
    cache_dir: PathBuf,
    /// In-progress conversions (to avoid duplicate work)
    in_progress: Arc<RwLock<HashMap<String, tokio::sync::watch::Receiver<ConversionStatus>>>>,
    /// Server base URL for rewriting
    server_url: String,
}

#[derive(Clone, Debug)]
pub enum ConversionStatus {
    InProgress,
    Complete,
    Failed(String),
}

impl ImageCache {
    /// Create a new image cache
    pub fn new(cache_dir: impl Into<PathBuf>, server_url: impl Into<String>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            in_progress: Arc::new(RwLock::new(HashMap::new())),
            server_url: server_url.into(),
        }
    }

    /// Initialize the cache directory
    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.cache_dir).await?;
        info!(cache_dir = %self.cache_dir.display(), "Image cache initialized");
        Ok(())
    }

    /// Check if a URL needs QCOW2 conversion
    pub fn needs_conversion(&self, url: &str) -> Option<&'static str> {
        for (pattern, cache_name) in QCOW2_SOURCES {
            if url.contains(pattern) {
                return Some(cache_name);
            }
        }
        None
    }

    /// Get the cached image path for a cache name
    fn cached_path(&self, cache_name: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.raw.tar.zst", cache_name))
    }

    /// Check if an image is cached
    pub async fn is_cached(&self, cache_name: &str) -> bool {
        let path = self.cached_path(cache_name);
        path.exists()
    }

    /// Get the URL for a cached image
    pub fn cached_url(&self, cache_name: &str) -> String {
        format!("{}/images/{}.raw.tar.zst", self.server_url, cache_name)
    }

    /// Ensure an image is cached, converting if necessary
    ///
    /// This blocks until the image is ready. If conversion is already
    /// in progress by another request, we wait for it.
    pub async fn ensure_cached(&self, url: &str, cache_name: &str) -> Result<String> {
        // Check if already cached
        if self.is_cached(cache_name).await {
            info!(cache_name = %cache_name, "Image already cached");
            return Ok(self.cached_url(cache_name));
        }

        // Check if conversion is in progress
        {
            let in_progress = self.in_progress.read().await;
            if let Some(receiver) = in_progress.get(cache_name) {
                let mut receiver = receiver.clone();
                drop(in_progress);

                info!(cache_name = %cache_name, "Waiting for in-progress conversion");

                // Wait for conversion to complete
                loop {
                    let status = receiver.borrow().clone();
                    match status {
                        ConversionStatus::Complete => {
                            return Ok(self.cached_url(cache_name));
                        }
                        ConversionStatus::Failed(err) => {
                            return Err(anyhow!("Conversion failed: {}", err));
                        }
                        ConversionStatus::InProgress => {
                            if receiver.changed().await.is_err() {
                                return Err(anyhow!("Conversion channel closed"));
                            }
                        }
                    }
                }
            }
        }

        // Start conversion
        let (tx, rx) = tokio::sync::watch::channel(ConversionStatus::InProgress);
        {
            let mut in_progress = self.in_progress.write().await;
            in_progress.insert(cache_name.to_string(), rx);
        }

        info!(cache_name = %cache_name, url = %url, "Starting image conversion");

        // Do the conversion
        let result = self.convert_image(url, cache_name).await;

        // Update status and remove from in-progress
        {
            let mut in_progress = self.in_progress.write().await;
            in_progress.remove(cache_name);
        }

        match result {
            Ok(()) => {
                let _ = tx.send(ConversionStatus::Complete);
                info!(cache_name = %cache_name, "Image conversion complete");
                Ok(self.cached_url(cache_name))
            }
            Err(e) => {
                let _ = tx.send(ConversionStatus::Failed(e.to_string()));
                error!(cache_name = %cache_name, error = %e, "Image conversion failed");
                Err(e)
            }
        }
    }

    /// Convert an image: download QCOW2, convert to raw, compress
    async fn convert_image(&self, url: &str, cache_name: &str) -> Result<()> {
        let temp_qcow2 = self.cache_dir.join(format!("{}.qcow2.tmp", cache_name));
        let temp_raw = self.cache_dir.join(format!("{}.raw.tmp", cache_name));
        let final_path = self.cached_path(cache_name);

        // Step 1: Download QCOW2 image
        info!(url = %url, "Downloading QCOW2 image");
        self.download_file(url, &temp_qcow2).await?;

        // Step 2: Convert QCOW2 to raw
        info!("Converting QCOW2 to raw");
        self.convert_qcow2_to_raw(&temp_qcow2, &temp_raw).await?;
        let _ = fs::remove_file(&temp_qcow2).await;

        // Step 3: Compress raw to tar.zst
        info!("Compressing raw image to tar.zst");
        self.compress_to_tar_zst(&temp_raw, &final_path, cache_name).await?;

        // Clean up temp raw
        let _ = fs::remove_file(&temp_raw).await;

        Ok(())
    }

    /// Download a file directly to disk
    async fn download_file(&self, url: &str, output: &Path) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        use futures::StreamExt;

        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error: {}", response.status()));
        }

        let content_length = response.content_length();
        info!(content_length = ?content_length, "Download started");

        let mut file = fs::File::create(output).await?;
        let mut stream = response.bytes_stream();
        let mut downloaded: u64 = 0;
        let mut last_report = std::time::Instant::now();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| anyhow!("Download error: {}", e))?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;

            if last_report.elapsed() > std::time::Duration::from_secs(5) {
                let pct = content_length.map(|t| (downloaded * 100) / t).unwrap_or(0);
                info!(downloaded = downloaded, percent = pct, "Download progress");
                last_report = std::time::Instant::now();
            }
        }

        file.sync_all().await?;
        info!(bytes = downloaded, "Download complete");
        Ok(())
    }

    #[allow(dead_code)]
    /// Download a tar.gz and extract the disk image file inside (legacy, for tar.gz sources)
    async fn download_and_extract_image(&self, url: &str, output: &Path) -> Result<()> {
        use async_compression::tokio::bufread::GzipDecoder;
        use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio_tar::Archive;
        use futures::StreamExt;

        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error: {}", response.status()));
        }

        let content_length = response.content_length();
        info!(content_length = ?content_length, "Download started");

        // Stream response -> gzip decoder -> tar archive
        let stream = response.bytes_stream();
        let stream_reader = tokio_util::io::StreamReader::new(
            stream.map(|result| result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
        );
        let buffered = BufReader::new(stream_reader);
        let decoder = GzipDecoder::new(buffered);
        let mut archive = Archive::new(decoder);

        let mut entries = archive.entries()?;

        while let Some(entry) = entries.next().await {
            let mut entry = entry?;
            let path = entry.path()?;
            let path_str = path.to_string_lossy();

            // Look for .img or .qcow2 file
            if path_str.ends_with(".img") || path_str.ends_with(".qcow2") {
                info!(file = %path_str, "Found disk image in archive");

                let mut output_file = fs::File::create(output).await?;
                let mut buffer = vec![0u8; 4 * 1024 * 1024];
                let mut total = 0u64;

                loop {
                    let n = entry.read(&mut buffer).await?;
                    if n == 0 {
                        break;
                    }
                    output_file.write_all(&buffer[..n]).await?;
                    total += n as u64;
                }

                output_file.sync_all().await?;
                info!(bytes = total, "Extracted disk image");
                return Ok(());
            }
        }

        Err(anyhow!("No .img or .qcow2 file found in archive"))
    }

    /// Convert QCOW2 to raw using qemu-img (battle-tested, handles all QCOW2 variants)
    async fn convert_qcow2_to_raw(&self, input: &Path, output: &Path) -> Result<()> {
        use tokio::process::Command;

        info!(input = %input.display(), output = %output.display(), "Converting QCOW2 to raw with qemu-img");

        let result = Command::new("qemu-img")
            .args(["convert", "-f", "qcow2", "-O", "raw", "-p"])
            .arg(input)
            .arg(output)
            .output()
            .await
            .map_err(|e| anyhow!("Failed to run qemu-img: {}", e))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(anyhow!("qemu-img convert failed: {}", stderr));
        }

        let output_size = fs::metadata(output).await?.len();
        info!(output_size = output_size, "QCOW2 conversion complete");

        Ok(())
    }

    /// Compress raw image to tar.zst
    async fn compress_to_tar_zst(&self, input: &Path, output: &Path, name: &str) -> Result<()> {
        use async_compression::tokio::write::ZstdEncoder;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let input_file = fs::File::open(input).await?;
        let input_size = input_file.metadata().await?.len();

        let output_file = fs::File::create(output).await?;
        let encoder = ZstdEncoder::with_quality(output_file, async_compression::Level::Default);

        // Create tar archive with the raw file inside
        let mut builder = tokio_tar::Builder::new(encoder);

        // Add the raw file to tar
        let mut header = tokio_tar::Header::new_gnu();
        header.set_path(format!("{}.raw", name))?;
        header.set_size(input_size);
        header.set_mode(0o644);
        header.set_mtime(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs());
        header.set_cksum();

        let input_file = fs::File::open(input).await?;
        builder.append(&header, input_file).await?;

        let mut encoder = builder.into_inner().await?;
        encoder.shutdown().await?;

        let output_size = fs::metadata(output).await?.len();
        let ratio = (output_size as f64 / input_size as f64) * 100.0;
        info!(
            input_size = input_size,
            output_size = output_size,
            ratio = format!("{:.1}%", ratio),
            "Compression complete"
        );

        Ok(())
    }

    /// Get the cache directory for serving files
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

/// Rewrite template URLs to use cached images where available
pub async fn rewrite_template_urls(
    template: &mut dragonfly_crd::Template,
    cache: &ImageCache,
) -> Result<()> {
    for action in &mut template.spec.actions {
        if let dragonfly_crd::ActionStep::Image2disk(cfg) = action {
            if let Some(cache_name) = cache.needs_conversion(&cfg.url) {
                info!(
                    original_url = %cfg.url,
                    cache_name = %cache_name,
                    "URL needs QCOW2 conversion"
                );

                // Ensure image is cached (blocks if conversion needed)
                let cached_url = cache.ensure_cached(&cfg.url, cache_name).await?;

                info!(
                    original_url = %cfg.url,
                    cached_url = %cached_url,
                    "Rewrote URL to cached image"
                );

                cfg.url = cached_url;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_conversion() {
        let cache = ImageCache::new("/tmp/cache", "http://localhost:8080");

        // Ubuntu URLs should need conversion
        assert_eq!(
            cache.needs_conversion("https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.tar.gz"),
            Some("ubuntu-2404")
        );
        assert_eq!(
            cache.needs_conversion("https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.tar.gz"),
            Some("ubuntu-2204")
        );

        // Debian URLs should not need conversion (they provide raw)
        assert_eq!(
            cache.needs_conversion("https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.tar.xz"),
            None
        );
    }

    #[test]
    fn test_cached_url() {
        let cache = ImageCache::new("/tmp/cache", "http://dragonfly.local:8080");
        assert_eq!(
            cache.cached_url("ubuntu-2404"),
            "http://dragonfly.local:8080/images/ubuntu-2404.raw.tar.zst"
        );
    }
}
