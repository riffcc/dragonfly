//! Development mode command
//!
//! Sets up and runs Dragonfly with hot-reloading templates for development.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

const DATA_DIR: &str = "/var/lib/dragonfly";

/// Find the project root by looking for Cargo.toml
fn find_project_root() -> Result<PathBuf> {
    let mut current = std::env::current_dir()?;

    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            // Verify it's the dragonfly project
            let content = std::fs::read_to_string(&cargo_toml)?;
            if content.contains("name = \"dragonfly\"") || content.contains("dragonfly-server") {
                return Ok(current);
            }
        }

        if !current.pop() {
            bail!("Could not find Dragonfly project root. Run from within the dragonfly source directory.");
        }
    }
}

/// Ensure a directory exists
fn ensure_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
    }
    Ok(())
}

/// Create a symlink, removing existing target if needed
fn symlink(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() || dst.is_symlink() {
        if dst.is_symlink() {
            std::fs::remove_file(dst)?;
        } else if dst.is_dir() {
            std::fs::remove_dir_all(dst)?;
        } else {
            std::fs::remove_file(dst)?;
        }
    }

    #[cfg(unix)]
    std::os::unix::fs::symlink(src, dst)
        .with_context(|| format!("Failed to symlink {} -> {}", src.display(), dst.display()))?;

    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(src, dst)
        .with_context(|| format!("Failed to symlink {} -> {}", src.display(), dst.display()))?;

    Ok(())
}

/// Set up development environment symlinks
fn setup_dev_environment(project_root: &Path) -> Result<()> {
    let server_crate = project_root.join("crates/dragonfly-server");
    let templates_src = server_crate.join("templates");
    let static_src = server_crate.join("static");

    // Verify source directories exist
    if !templates_src.exists() {
        bail!("Templates directory not found at {}", templates_src.display());
    }
    if !static_src.exists() {
        bail!("Static directory not found at {}", static_src.display());
    }

    // Create data directory if it doesn't exist
    ensure_dir(Path::new(DATA_DIR))?;

    // Set up /opt/dragonfly/templates symlink (preferred path for templates)
    let opt_dragonfly = Path::new("/opt/dragonfly");
    ensure_dir(opt_dragonfly)?;
    let opt_templates = opt_dragonfly.join("templates");
    info!("Symlinking {} -> {}", templates_src.display(), opt_templates.display());
    symlink(&templates_src, &opt_templates)?;

    // Set up relative paths for debug mode (relative to DATA_DIR working directory)
    let data_crates = PathBuf::from(DATA_DIR).join("crates/dragonfly-server");
    ensure_dir(&data_crates)?;

    let data_templates = data_crates.join("templates");
    info!("Symlinking {} -> {}", templates_src.display(), data_templates.display());
    symlink(&templates_src, &data_templates)?;

    let data_static = data_crates.join("static");
    info!("Symlinking {} -> {}", static_src.display(), data_static.display());
    symlink(&static_src, &data_static)?;

    Ok(())
}

/// Run the development server
pub async fn run_dev() -> Result<()> {
    println!("🐉 Dragonfly Development Mode");
    println!();

    // Find project root
    let project_root = find_project_root()?;
    println!("  Project root: {}", project_root.display());

    // Check if we're running from a debug build
    let is_debug = cfg!(debug_assertions);
    if !is_debug {
        println!();
        println!("⚠️  Warning: Running a release build. Hot reload is only available in debug builds.");
        println!("   Build with 'cargo build' (not --release) for hot reload.");
        println!();
    }

    // Set up symlinks
    println!("  Setting up development environment...");
    setup_dev_environment(&project_root)?;
    println!("  ✓ Symlinks configured for hot reload");
    println!();

    // Check for existing dragonfly processes
    let port_check = Command::new("lsof")
        .args(["-i", ":3000", "-sTCP:LISTEN"])
        .output();

    if let Ok(output) = port_check {
        if output.status.success() && !output.stdout.is_empty() {
            println!("⚠️  Port 3000 is already in use. Stop the existing server first:");
            println!("   systemctl stop dragonfly  # if running as service");
            println!("   pkill dragonfly           # if running manually");
            bail!("Port 3000 already in use");
        }
    }

    println!("  Starting server with hot reload...");
    println!("  Templates: {}/crates/dragonfly-server/templates", project_root.display());
    println!("  Static:    {}/crates/dragonfly-server/static", project_root.display());
    println!();
    println!("  Edit templates and refresh browser - changes apply immediately!");
    println!();

    // Change to data directory (for database paths)
    std::env::set_current_dir(DATA_DIR)
        .with_context(|| format!("Failed to change to data directory: {}", DATA_DIR))?;

    // Run the server
    dragonfly_server::run().await?;

    Ok(())
}
