//! Jetpack playbook builder for the Dragonfly-on-LXC install flow.
//!
//! Produces the inline YAML that Jetpack executes on the newly-provisioned
//! container after the `proxmox_lxc` provisioner brings it up.
//!
//! The playbook performs every step that `dragonfly install` would perform,
//! but expressed as explicit Jetpack tasks so we don't need the binary to
//! bootstrap itself:
//!
//! 1. Create all required directories under `/var/lib/dragonfly` and `/opt/dragonfly`
//! 2. Upload the Dragonfly binary via `!copy`
//! 3. Upload web static assets via `!copy recursive: true`
//! 4. Optionally upload OS templates via `!copy recursive: true`
//! 5. Write `/var/lib/dragonfly/config.toml` (detects container IP at runtime)
//! 6. Write `/etc/systemd/system/dragonfly.service`
//! 7. `systemctl daemon-reload && systemctl enable --now dragonfly`
//! 8. Verify the service is active

/// Configuration for the Dragonfly install playbook.
#[derive(Debug, Clone)]
pub struct InstallPlaybookConfig {
    /// Absolute path to the Dragonfly binary on the LOCAL machine.
    /// Jetpack's `!copy` module transfers this to the container.
    /// Static web assets are compiled into the binary — no separate upload needed.
    pub local_binary_path: String,

    /// Optional absolute path to an OS templates directory on the LOCAL machine.
    /// If present, the directory is uploaded recursively.
    pub os_templates_path: Option<String>,
}

/// Build the inline Jetpack YAML that installs Dragonfly on the container.
///
/// The resulting YAML is passed to `jetpack::api::run_inline`.
/// Paths are single-quoted in YAML; callers must validate them with
/// `validate_local_path` first.
pub fn build_install_playbook(config: &InstallPlaybookConfig) -> String {
    let os_templates_task = match &config.os_templates_path {
        Some(path) => format!(
            r#"
    - !copy
      name: Uploading OS templates
      src: '{os_tmpl}'
      dest: /var/lib/dragonfly/os-templates
      recursive: true
"#,
            os_tmpl = path,
        ),
        None => String::new(),
    };

    // NOTE on format!() escaping:
    //   {{  →  literal {      }}  →  literal }
    //   ${{IP}}  →  ${IP}  (shell variable in the heredoc)
    //   {{print $1}}  →  {print $1}  (awk program)
    format!(
        r#"
- name: Install Dragonfly on LXC container
  groups:
    - containers
  tasks:
    - !shell
      name: Checking Dragonfly directories
      cmd: mkdir -p /var/lib/dragonfly/data /var/lib/dragonfly/tftp/mage /var/lib/dragonfly/templates /var/lib/dragonfly/os-templates && chmod 755 /var/lib/dragonfly

    - !copy
      name: Uploading Dragonfly binary
      src: '{binary}'
      dest: /usr/local/bin/dragonfly
      attributes:
        mode: '0o755'
{os_templates_task}
    - !shell
      name: Writing Dragonfly config
      cmd: |
        IP=$(hostname -I | awk '{{print $1}}')
        cat << EOF > /var/lib/dragonfly/config.toml
        [server]
        port = 3000
        base_url = "http://${{IP}}:3000"

        [paths]
        data_dir = "/var/lib/dragonfly/data"
        tftp_dir = "/var/lib/dragonfly/tftp"
        EOF

    - !shell
      name: Installing and starting Dragonfly service
      cmd: |
        cat << 'EOF' > /etc/systemd/system/dragonfly.service
        [Unit]
        Description=Dragonfly Bare Metal Management
        After=network.target

        [Service]
        Type=simple
        ExecStart=/usr/local/bin/dragonfly serve
        Restart=always
        RestartSec=5
        WorkingDirectory=/var/lib/dragonfly
        SyslogIdentifier=dragonfly
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
        EOF
        systemctl daemon-reload && systemctl enable dragonfly && systemctl start dragonfly

    - !fetch
      name: Retrieving initial admin password
      src: /var/lib/dragonfly/initial_password.txt
"#,
        binary = config.local_binary_path,
        os_templates_task = os_templates_task,
    )
}

/// Build the inline Jetpack YAML for an idempotent Dragonfly update.
///
/// Copies the new binary (and optionally OS templates), then restarts the
/// service and verifies it is active.  Static web assets are compiled into the
/// binary — no separate upload is required.
///
/// The service file is (re-)written on every update so that the update flow
/// also works correctly on a fresh container where install previously failed
/// before the service was registered.
///
/// The resulting YAML is passed to `jetpack::api::run_inline`.
pub fn build_update_playbook(config: &InstallPlaybookConfig) -> String {
    let os_templates_task = match &config.os_templates_path {
        Some(path) => format!(
            r#"
    - !copy
      name: Uploading OS templates
      src: '{os_tmpl}'
      dest: /var/lib/dragonfly/os-templates
      recursive: true
"#,
            os_tmpl = path,
        ),
        None => String::new(),
    };

    format!(
        r#"
- name: Update Dragonfly on LXC container
  groups:
    - containers
  tasks:
    - !shell
      name: Checking Dragonfly directories
      cmd: mkdir -p /var/lib/dragonfly/data /var/lib/dragonfly/tftp/mage /var/lib/dragonfly/os-templates

    - !copy
      name: Updating Dragonfly binary
      src: '{binary}'
      dest: /usr/local/bin/dragonfly
      attributes:
        mode: '0o755'
{os_templates_task}
    - !shell
      name: Installing and starting Dragonfly service
      cmd: |
        cat << 'EOF' > /etc/systemd/system/dragonfly.service
        [Unit]
        Description=Dragonfly Bare Metal Management
        After=network.target

        [Service]
        Type=simple
        ExecStart=/usr/local/bin/dragonfly serve
        Restart=always
        RestartSec=5
        WorkingDirectory=/var/lib/dragonfly
        SyslogIdentifier=dragonfly
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
        EOF
        systemctl daemon-reload && systemctl enable dragonfly && systemctl restart dragonfly && systemctl start dragonfly

    - !fetch
      name: Retrieving initial admin password
      src: /var/lib/dragonfly/initial_password.txt
"#,
        binary = config.local_binary_path,
        os_templates_task = os_templates_task,
    )
}

/// Validate that a local file/directory path is safe to embed in single-quoted YAML.
///
/// Returns `Err` with a human-readable message if the path would break the
/// YAML single-quoted string.
pub fn validate_local_path(label: &str, path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{} path must not be empty", label));
    }
    if path.contains('\'') {
        return Err(format!(
            "{} path '{}' contains a single-quote character which cannot \
             be safely embedded in YAML. Rename or move the file/directory.",
            label, path
        ));
    }
    Ok(())
}

/// Validate the binary path (convenience wrapper around `validate_local_path`).
pub fn validate_binary_path(path: &str) -> Result<(), String> {
    validate_local_path("Binary", path)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(binary: &str) -> InstallPlaybookConfig {
        InstallPlaybookConfig {
            local_binary_path: binary.to_string(),
            os_templates_path: None,
        }
    }

    fn make_config_with_templates(binary: &str, tmpl: &str) -> InstallPlaybookConfig {
        InstallPlaybookConfig {
            local_binary_path: binary.to_string(),
            os_templates_path: Some(tmpl.to_string()),
        }
    }

    // ── Structural checks ──────────────────────────────────────────────────

    #[test]
    fn test_playbook_targets_containers_group() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(
            yaml.contains("groups:\n    - containers"),
            "Play must target the 'containers' group, not 'all'"
        );
    }

    #[test]
    fn test_playbook_contains_mkdir_task() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("mkdir -p /var/lib/dragonfly"), "Must create Dragonfly directories");
        assert!(yaml.contains("Checking Dragonfly directories"), "Directory task must have correct name");
    }

    #[test]
    fn test_playbook_contains_binary_copy_task() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("!copy"), "Must have a copy task");
        assert!(yaml.contains("src: '/usr/local/bin/dragonfly'"), "Must reference the binary path");
        assert!(yaml.contains("dest: /usr/local/bin/dragonfly"), "Binary must go to the production path");
        assert!(yaml.contains("Uploading Dragonfly binary"), "Binary copy task must have correct name");
    }

    #[test]
    fn test_playbook_binary_mode_is_set() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("mode: '0o755'"), "Binary must be marked executable");
    }

    #[test]
    fn test_playbook_no_static_assets_copy() {
        // Static assets are compiled into the binary — no copy task should exist.
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(
            !yaml.contains("Upload web static assets"),
            "Static assets are embedded in the binary, no copy task needed"
        );
        assert!(
            !yaml.contains("/opt/dragonfly/static"),
            "No reference to /opt/dragonfly/static — assets are served from binary"
        );
    }

    #[test]
    fn test_playbook_no_os_templates_when_none() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(
            !yaml.contains("Uploading OS templates"),
            "No OS templates upload task when os_templates_path is None"
        );
    }

    #[test]
    fn test_playbook_includes_os_templates_when_some() {
        let yaml = build_install_playbook(&make_config_with_templates(
            "/usr/local/bin/dragonfly",
            "/tmp/os-templates",
        ));
        assert!(yaml.contains("/tmp/os-templates"), "Must reference the OS templates path");
        assert!(
            yaml.contains("Uploading OS templates"),
            "Must have an OS templates upload task"
        );
    }

    #[test]
    fn test_playbook_contains_config_write() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("Writing Dragonfly config"), "Must have a config-writing task");
        assert!(yaml.contains("config.toml"), "Config task must reference config.toml");
        assert!(yaml.contains("hostname -I"), "Config must detect container IP at runtime");
    }

    #[test]
    fn test_playbook_contains_systemd_service() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("dragonfly.service"), "Must write the systemd service file");
        assert!(yaml.contains("ExecStart=/usr/local/bin/dragonfly serve"), "Service must start the serve command");
        assert!(yaml.contains("WantedBy=multi-user.target"), "Service must enable on multi-user target");
        assert!(yaml.contains("Installing and starting Dragonfly service"), "Service task must have correct name");
        assert!(yaml.contains("SyslogIdentifier=dragonfly"), "Service must set syslog identifier for log filtering");
        assert!(yaml.contains("StandardOutput=journal"), "Service must route stdout to journal");
        assert!(yaml.contains("StandardError=journal"), "Service must route stderr to journal");
    }

    #[test]
    fn test_playbook_enables_service() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("systemctl enable dragonfly"), "Must enable the service");
        assert!(yaml.contains("systemctl start dragonfly"), "Must start the service");
    }

    #[test]
    fn test_playbook_starts_service() {
        // systemctl start blocks until the unit is in a stable (active/failed) state —
        // no sleep required, and it's idempotent on an already-running service.
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("systemctl start dragonfly"), "Must start (and wait for) the service");
    }

    #[test]
    fn test_playbook_no_self_install_invocation() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(
            !yaml.contains("dragonfly install"),
            "Playbook must not call 'dragonfly install' — steps are explicit"
        );
    }

    // ── build_update_playbook ──────────────────────────────────────────────

    #[test]
    fn test_update_playbook_targets_containers_group() {
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(
            yaml.contains("groups:\n    - containers"),
            "Update play must target the 'containers' group"
        );
    }

    #[test]
    fn test_update_playbook_copies_binary() {
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("src: '/usr/local/bin/dragonfly'"), "Must reference the binary path");
        assert!(yaml.contains("dest: /usr/local/bin/dragonfly"), "Binary must go to the production path");
        assert!(yaml.contains("mode: '0o755'"), "Binary must be marked executable");
        assert!(yaml.contains("Updating Dragonfly binary"), "Binary copy task must have correct name");
    }

    #[test]
    fn test_update_playbook_no_static_assets_copy() {
        // Static assets are compiled into the binary — no copy task should exist.
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(
            !yaml.contains("Upload web static assets"),
            "Static assets are embedded in the binary, no copy task needed"
        );
    }

    #[test]
    fn test_update_playbook_installs_service_file() {
        // Update must write the service file so it works on a fresh container.
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("dragonfly.service"), "Must write the systemd service file");
        assert!(yaml.contains("ExecStart=/usr/local/bin/dragonfly serve"), "Service must start the serve command");
        assert!(yaml.contains("systemctl daemon-reload"), "Must reload systemd after writing service");
        assert!(yaml.contains("Installing and starting Dragonfly service"), "Service task must have correct name");
        assert!(yaml.contains("SyslogIdentifier=dragonfly"), "Service must set syslog identifier for log filtering");
        assert!(yaml.contains("StandardOutput=journal"), "Service must route stdout to journal");
        assert!(yaml.contains("StandardError=journal"), "Service must route stderr to journal");
    }

    #[test]
    fn test_update_playbook_restarts_service() {
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("systemctl restart dragonfly"), "Must restart the service");
    }

    #[test]
    fn test_update_playbook_starts_service() {
        // systemctl start blocks until the unit is stable — no sleep needed.
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("systemctl start dragonfly"), "Must start (and wait for) the service");
    }

    #[test]
    fn test_update_playbook_ensures_directories() {
        // Update creates directories idempotently so it works on fresh containers too.
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("mkdir -p"), "Update must ensure directories exist");
        assert!(yaml.contains("Checking Dragonfly directories"), "Directory task must have correct name");
    }

    #[test]
    fn test_update_playbook_no_os_templates_when_none() {
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(
            !yaml.contains("Uploading OS templates"),
            "No OS templates task when os_templates_path is None"
        );
    }

    #[test]
    fn test_update_playbook_includes_os_templates_when_some() {
        let yaml = build_update_playbook(&make_config_with_templates(
            "/usr/local/bin/dragonfly",
            "/tmp/os-templates",
        ));
        assert!(yaml.contains("/tmp/os-templates"), "Must reference OS templates path");
        assert!(yaml.contains("Uploading OS templates"), "Must have an OS templates upload task");
    }

    #[test]
    fn test_update_playbook_is_valid_yaml() {
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&yaml);
        assert!(parsed.is_ok(), "Generated update YAML must be valid: {:?}", parsed.err());
    }

    #[test]
    fn test_update_playbook_enables_restarts_and_starts_service() {
        // Update: enable (idempotent) → restart (picks up new binary) → start (blocks until stable).
        let yaml = build_update_playbook(&make_config("/usr/local/bin/dragonfly"));
        assert!(yaml.contains("systemctl enable dragonfly"), "Update must enable the service");
        assert!(yaml.contains("systemctl restart dragonfly"), "Update must restart the service");
        assert!(yaml.contains("systemctl start dragonfly"), "Update must wait for stable start");
    }

    // ── validate_local_path ────────────────────────────────────────────────

    #[test]
    fn test_validate_path_ok() {
        assert!(validate_local_path("Binary", "/usr/local/bin/dragonfly").is_ok());
        assert!(validate_local_path("Static", "/tmp/dragonfly-static").is_ok());
    }

    #[test]
    fn test_validate_path_empty() {
        let result = validate_local_path("Binary", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must not be empty"));
    }

    #[test]
    fn test_validate_path_single_quote() {
        let result = validate_local_path("Binary", "/tmp/it's-a-binary");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("single-quote"));
    }

    #[test]
    fn test_validate_binary_path_delegates_correctly() {
        assert!(validate_binary_path("/usr/local/bin/dragonfly").is_ok());
        let err = validate_binary_path("").unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    // ── YAML validity ──────────────────────────────────────────────────────

    #[test]
    fn test_playbook_is_valid_yaml() {
        let yaml = build_install_playbook(&make_config("/usr/local/bin/dragonfly"));
        let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&yaml);
        assert!(parsed.is_ok(), "Generated YAML must be valid: {:?}", parsed.err());
    }

    #[test]
    fn test_playbook_with_templates_is_valid_yaml() {
        let config = make_config_with_templates("/usr/local/bin/dragonfly", "/tmp/os-templates");
        let yaml = build_install_playbook(&config);
        let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&yaml);
        assert!(parsed.is_ok(), "Generated YAML with OS templates must be valid: {:?}", parsed.err());
    }
}
