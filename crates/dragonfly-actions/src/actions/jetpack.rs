//! Jetpack action
//!
//! Downloads the Jetpack binary and runs it in pull mode with `--url`,
//! letting Jetpack handle playbook download/extraction (single files, tarballs, git repos).
//! If a chroot is active (via the chroot action), Jetpack runs inside it with
//! `--chroot <path>`.
//!
//! This action is Dragonfly-agnostic: the playbook URL can point to any
//! HTTPS endpoint, tarball, or git repository, and the Jetpack binary can be
//! sourced from any URL (defaults to the latest GitHub release).
//!
//! Template usage:
//! ```yaml
//! - action: jetpack
//!   url: "https://dragonfly.example.com/playbooks/debian-to-proxmox.tar.gz"
//!   timeout: 3600
//! ```

use crate::actions::chroot::chroot_path;
use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use tokio::process::Command;
use tracing::{debug, error, info};

/// Default Jetpack binary download URL (latest stable release from GitHub).
const DEFAULT_JETPACK_URL: &str =
    "https://github.com/riffcc/jetpack/releases/latest/download/jetpack-x86_64";

/// Where to store the downloaded Jetpack binary.
const JETPACK_BIN_PATH: &str = "/tmp/jetpack-bin";

pub struct JetpackAction;

#[async_trait]
impl Action for JetpackAction {
    fn name(&self) -> &str {
        "jetpack"
    }

    fn description(&self) -> &str {
        "Run Jetpack in pull mode, optionally inside a chroot"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec!["PLAYBOOK_URL"]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["JETPACK_BINARY_URL"]
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let reporter = ctx.progress_reporter();
        let playbook_url = ctx
            .env("PLAYBOOK_URL")
            .ok_or_else(|| ActionError::MissingEnvVar("PLAYBOOK_URL".to_string()))?
            .to_string();
        let binary_url = ctx
            .env("JETPACK_BINARY_URL")
            .unwrap_or(DEFAULT_JETPACK_URL)
            .to_string();

        // Step 1: Download Jetpack binary
        reporter.report(Progress::new("jetpack", 5, "Downloading Jetpack binary"));
        download_file(&binary_url, JETPACK_BIN_PATH).await?;
        make_executable(JETPACK_BIN_PATH).await?;
        info!(url = %binary_url, dest = %JETPACK_BIN_PATH, "Jetpack binary downloaded");

        // Step 2: Run Jetpack in pull mode with --url
        // Jetpack handles download, extraction (tarballs), and playbook discovery
        reporter.report(Progress::new("jetpack", 20, "Running Jetpack pull mode"));

        let chroot = chroot_path();
        let mut cmd = Command::new(JETPACK_BIN_PATH);
        cmd.arg("pull").arg("--url").arg(&playbook_url);

        if let Some(ref cp) = chroot {
            cmd.arg("--chroot").arg(cp);
            info!(chroot = %cp, url = %playbook_url, "Running Jetpack inside chroot");
        } else {
            info!(url = %playbook_url, "Running Jetpack locally (no chroot)");
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| ActionError::ExecutionFailed(format!("jetpack execution failed: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !stdout.is_empty() {
            debug!(stdout = %stdout, "Jetpack stdout");
        }
        if !stderr.is_empty() {
            debug!(stderr = %stderr, "Jetpack stderr");
        }

        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            error!(
                code = code,
                stdout = %stdout,
                stderr = %stderr,
                "Jetpack failed"
            );
            return Err(ActionError::ExecutionFailed(format!(
                "jetpack exited with code {}: {}",
                code,
                stderr.trim()
            )));
        }

        reporter.report(Progress::completed("jetpack"));
        info!("Jetpack pull mode completed successfully");

        Ok(ActionResult::success("Jetpack playbook executed successfully")
            .with_output("playbook_url", &playbook_url)
            .with_output("chroot", chroot.as_deref().unwrap_or("none")))
    }

    fn validate(&self, ctx: &ActionContext) -> Result<()> {
        if ctx.env("PLAYBOOK_URL").is_none() {
            return Err(ActionError::MissingEnvVar("PLAYBOOK_URL".to_string()));
        }
        Ok(())
    }
}

/// Download a file from a URL using curl.
async fn download_file(url: &str, dest: &str) -> Result<()> {
    let status = Command::new("curl")
        .arg("-sfL")
        .arg("--connect-timeout")
        .arg("30")
        .arg("--retry")
        .arg("3")
        .arg("-o")
        .arg(dest)
        .arg(url)
        .status()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("curl failed: {}", e)))?;

    if !status.success() {
        return Err(ActionError::ExecutionFailed(format!(
            "download failed ({}): {}",
            status.code().unwrap_or(-1),
            url
        )));
    }

    Ok(())
}

/// Make a file executable (chmod +x).
async fn make_executable(path: &str) -> Result<()> {
    let status = Command::new("chmod")
        .arg("+x")
        .arg(path)
        .status()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("chmod failed: {}", e)))?;

    if !status.success() {
        return Err(ActionError::ExecutionFailed(format!(
            "chmod +x {} failed",
            path
        )));
    }

    Ok(())
}
