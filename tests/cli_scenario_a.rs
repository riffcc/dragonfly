use assert_cmd::prelude::*;
use std::process::Command;
use std::path::Path;
use color_eyre::Result;

const DRAGONFLY_CONFIG: &str = "/var/lib/dragonfly/config.toml";

#[test]
fn test_dragonfly_status_output() -> Result<()> {
    // Run the dragonfly command with no arguments
    let mut cmd = Command::cargo_bin("dragonfly")?;
    let output = cmd.output().expect("Failed to execute dragonfly command");

    // Command should succeed
    assert!(output.status.success(), "Dragonfly command failed. Stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    println!("-- Dragonfly stdout --\n{}\n-- End Dragonfly stdout --", stdout_str);

    // Check for appropriate status message based on config existence
    let is_installed = Path::new(DRAGONFLY_CONFIG).exists();

    if is_installed {
        assert!(stdout_str.contains("Status: Installed"), "Missing 'Status: Installed' message");
        assert!(stdout_str.contains("Config:"), "Missing config path");
    } else {
        assert!(stdout_str.contains("Status: Not installed"), "Missing 'Status: Not installed' message");
        assert!(stdout_str.contains("dragonfly install") || stdout_str.contains("dragonfly demo"),
            "Missing install/demo hint");
    }

    // Always check for help text
    assert!(stdout_str.contains("Usage: dragonfly [OPTIONS] [COMMAND]"), "Missing usage text");
    assert!(stdout_str.contains("serve"), "Missing serve command");
    assert!(stdout_str.contains("demo"), "Missing demo command");
    assert!(stdout_str.contains("install"), "Missing install command");

    Ok(())
}
