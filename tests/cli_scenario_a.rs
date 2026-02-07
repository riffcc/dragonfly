use assert_cmd::prelude::*;
use color_eyre::Result;
use std::path::Path;
use std::process::Command;

const DRAGONFLY_CONFIG: &str = "/var/lib/dragonfly/config.toml";

#[test]
fn test_dragonfly_status_output() -> Result<()> {
    let mut cmd = Command::cargo_bin("dragonfly")?;
    let output = cmd.output().expect("Failed to execute dragonfly command");

    assert!(
        output.status.success(),
        "Dragonfly command failed. Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);

    // Header is always present
    assert!(
        stdout_str.contains("Dragonfly Status"),
        "Missing status header"
    );

    let is_installed = Path::new(DRAGONFLY_CONFIG).exists();

    if is_installed {
        assert!(
            stdout_str.contains("Installation: ✓ Installed"),
            "Missing installation status"
        );
    } else {
        assert!(
            stdout_str.contains("Installation: ✗ Not installed"),
            "Missing installation status"
        );
        assert!(
            stdout_str.contains("dragonfly install") || stdout_str.contains("dragonfly demo"),
            "Missing install/demo hint"
        );
    }

    Ok(())
}
