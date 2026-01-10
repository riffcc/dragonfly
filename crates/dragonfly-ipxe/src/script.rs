//! iPXE script generation
//!
//! This module generates iPXE boot scripts. The SERVER decides what script
//! to return based on hardware state - the client never chooses.
//!
//! # Boot Flow
//!
//! ```text
//! PXE → DHCP → iPXE binary → GET /boot/${mac} → Server decides → Script
//! ```
//!
//! # Script Types
//!
//! - **Local boot**: Machine has existing OS, boot from disk
//! - **Discovery**: Boot into Mage, agent checks in and waits for user
//! - **Imaging**: Boot into Mage, agent checks in and proceeds automatically
//! - **Menu**: Optional interactive menu (only when explicitly enabled)
//!
//! Discovery and imaging use the same Mage image - only the mode parameter
//! differs. The agent reads `dragonfly.mode` and either waits (discovery)
//! or proceeds with the assigned workflow (imaging).

use crate::error::Result;
use dragonfly_crd::Hardware;

/// Configuration for iPXE script generation
#[derive(Debug, Clone)]
pub struct IpxeConfig {
    /// Base URL for fetching resources (e.g., http://192.168.1.1:8080)
    pub base_url: String,

    /// Mage kernel URL
    pub mage_kernel_url: Option<String>,

    /// Mage initramfs URL
    pub mage_initramfs_url: Option<String>,

    /// Default kernel parameters
    pub kernel_params: Vec<String>,

    /// Console configuration (e.g., "ttyS0,115200")
    pub console: Option<String>,

    /// Enable verbose boot logging
    pub verbose: bool,
}

impl Default for IpxeConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            kernel_params: Vec::new(),
            console: None,
            verbose: false,
            mage_kernel_url: None,
            mage_initramfs_url: None,
        }
    }
}

impl IpxeConfig {
    /// Create a new config with base URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Default::default()
        }
    }

    /// Set console configuration
    pub fn with_console(mut self, console: impl Into<String>) -> Self {
        self.console = Some(console.into());
        self
    }

    /// Add kernel parameter
    pub fn with_kernel_param(mut self, param: impl Into<String>) -> Self {
        self.kernel_params.push(param.into());
        self
    }

    /// Enable verbose boot
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set Mage kernel URL
    pub fn with_mage_kernel(mut self, url: impl Into<String>) -> Self {
        self.mage_kernel_url = Some(url.into());
        self
    }

    /// Set Mage initramfs URL
    pub fn with_mage_initramfs(mut self, url: impl Into<String>) -> Self {
        self.mage_initramfs_url = Some(url.into());
        self
    }

    fn mage_kernel(&self) -> String {
        self.mage_kernel_url
            .clone()
            .unwrap_or_else(|| format!("{}/mage/vmlinuz", self.base_url))
    }

    fn mage_initramfs(&self) -> String {
        self.mage_initramfs_url
            .clone()
            .unwrap_or_else(|| format!("{}/mage/initramfs", self.base_url))
    }
}

/// iPXE script generator
///
/// The server uses this to generate the appropriate script based on
/// hardware state. The client never chooses - it just executes.
#[derive(Debug, Clone)]
pub struct IpxeScriptGenerator {
    config: IpxeConfig,
}

impl IpxeScriptGenerator {
    /// Create a new script generator
    pub fn new(config: IpxeConfig) -> Self {
        Self { config }
    }

    /// Generate the initial chainload script
    ///
    /// This is what iPXE fetches first - it just chains to the server
    /// to get the real boot script based on MAC address.
    pub fn chainload_script(&self) -> String {
        format!(
            r#"#!ipxe
# Dragonfly Boot - fetches appropriate script from server
chain {}/boot/${{mac}}
"#,
            self.config.base_url
        )
    }

    /// Generate chainload script with optional menu on keypress
    ///
    /// If user holds Ctrl during the timeout, show interactive menu.
    /// Otherwise, proceed with server-decided boot.
    pub fn chainload_script_with_menu_option(&self, timeout_secs: u8) -> String {
        format!(
            r#"#!ipxe
# Dragonfly Boot - hold Ctrl for menu
echo Dragonfly - press Ctrl for boot menu...
iseq ${{keypress}} 0x03 && goto menu ||
sleep {timeout} || goto auto

:auto
chain {base}/boot/${{mac}}

:menu
chain {base}/boot/${{mac}}?menu=1
"#,
            timeout = timeout_secs,
            base = self.config.base_url
        )
    }

    /// Generate local boot script
    ///
    /// Boots from local disk. Server returns this when:
    /// - Machine is known
    /// - Has existing OS
    /// - Not scheduled for reinstall
    pub fn local_boot_script(&self) -> String {
        r#"#!ipxe
# Dragonfly - Local Boot
echo Booting from local disk...

# UEFI boot
iseq ${platform} efi && sanboot --no-describe --drive 0x80 ||

# BIOS fallback
sanboot --drive 0x80 ||

# Failed
echo Boot failed
shell
"#
        .to_string()
    }

    /// Generate discovery script
    ///
    /// Boots into Mage environment for registration. Server returns this when:
    /// - Machine is unknown (MAC not in database)
    /// - Interactive mode is configured
    ///
    /// Same image as imaging mode - agent checks in then waits for user action.
    pub fn discovery_script(&self, hardware: Option<&Hardware>) -> Result<String> {
        let kernel = self.config.mage_kernel();
        let initramfs = self.config.mage_initramfs();
        let params = self.kernel_params(hardware, "discovery");

        Ok(format!(
            r#"#!ipxe
# Dragonfly - Discovery Mode
echo Booting into discovery mode...
echo MAC: ${{mac}}

kernel {kernel} {params}
initrd {initramfs}
boot
"#
        ))
    }

    /// Generate imaging script
    ///
    /// Boots into Mage environment for auto-provisioning. Server returns this when:
    /// - Machine is unknown OR scheduled for imaging
    /// - Automatic mode is configured
    /// - No existing bootloader detected (or reinstall forced)
    ///
    /// Same image as discovery mode - agent checks in then proceeds automatically.
    pub fn imaging_script(&self, hardware: Option<&Hardware>, workflow_id: &str) -> Result<String> {
        let kernel = self.config.mage_kernel();
        let initramfs = self.config.mage_initramfs();
        let params = self.kernel_params(hardware, "imaging");

        Ok(format!(
            r#"#!ipxe
# Dragonfly - Imaging Mode
echo Booting into imaging mode...
echo MAC: ${{mac}}
echo Workflow: {workflow_id}

kernel {kernel} {params} dragonfly.workflow={workflow_id}
initrd {initramfs}
boot
"#
        ))
    }

    /// Generate interactive menu script
    ///
    /// Only returned when menu is explicitly requested (keypress or server config).
    pub fn menu_script(&self, hardware: Option<&Hardware>) -> Result<String> {
        let hw_name = hardware
            .map(|h| h.metadata.name.as_str())
            .unwrap_or("Unknown");

        Ok(format!(
            r#"#!ipxe
# Dragonfly - Boot Menu
menu Dragonfly Boot Menu - {hw_name}
item --gap -- MAC: ${{mac}}
item --gap --
item local     Boot from local disk
item discovery Discovery mode (register with server)
item imaging   Imaging mode (reinstall)
item shell     iPXE shell
choose --default local --timeout 30000 target && goto ${{target}} || goto local

:local
echo Booting from local disk...
sanboot --drive 0x80 || goto failed

:discovery
echo Booting into discovery mode...
chain {base}/boot/${{mac}}?mode=discovery || goto failed

:imaging
echo Booting into imaging mode...
chain {base}/boot/${{mac}}?mode=imaging || goto failed

:shell
echo Entering iPXE shell...
shell

:failed
echo Boot failed
shell
"#,
            base = self.config.base_url
        ))
    }

    /// Build kernel parameters string
    fn kernel_params(&self, hardware: Option<&Hardware>, mode: &str) -> String {
        let mut params = self.config.kernel_params.clone();

        // Console
        if let Some(ref console) = self.config.console {
            params.push(format!("console={}", console));
        }

        // Verbose logging
        if self.config.verbose {
            params.push("loglevel=7".to_string());
        }

        // Dragonfly parameters
        params.push(format!("dragonfly.url={}", self.config.base_url));
        params.push(format!("dragonfly.mode={}", mode));
        params.push("dragonfly.mac=${mac}".to_string());

        // Hardware ID if known
        if let Some(hw) = hardware {
            params.push(format!("dragonfly.hardware={}", hw.metadata.name));
        }

        params.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_crd::{HardwareSpec, ObjectMeta, TypeMeta};

    fn test_config() -> IpxeConfig {
        IpxeConfig::new("http://192.168.1.1:8080")
            .with_mage_kernel("http://192.168.1.1:8080/mage/vmlinuz")
            .with_mage_initramfs("http://192.168.1.1:8080/mage/initramfs")
    }

    fn test_hardware() -> Hardware {
        Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test-machine"),
            spec: HardwareSpec::default(),
            status: None,
        }
    }

    #[test]
    fn test_chainload_script() {
        let gen = IpxeScriptGenerator::new(test_config());
        let script = gen.chainload_script();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("chain http://192.168.1.1:8080/boot/${mac}"));
        // No menu, no choices
        assert!(!script.contains("menu"));
    }

    #[test]
    fn test_chainload_with_menu_option() {
        let gen = IpxeScriptGenerator::new(test_config());
        let script = gen.chainload_script_with_menu_option(3);

        assert!(script.contains("press Ctrl for boot menu"));
        assert!(script.contains("sleep 3"));
        assert!(script.contains("?menu=1"));
    }

    #[test]
    fn test_local_boot_script() {
        let gen = IpxeScriptGenerator::new(test_config());
        let script = gen.local_boot_script();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Local Boot"));
        assert!(script.contains("sanboot"));
        // No menu
        assert!(!script.contains("menu"));
    }

    #[test]
    fn test_discovery_script() {
        let gen = IpxeScriptGenerator::new(test_config());
        let script = gen.discovery_script(None).unwrap();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Discovery Mode"));
        assert!(script.contains("kernel http://192.168.1.1:8080/mage/vmlinuz"));
        assert!(script.contains("dragonfly.mode=discovery"));
        // No menu
        assert!(!script.contains("menu"));
    }

    #[test]
    fn test_imaging_script() {
        let gen = IpxeScriptGenerator::new(test_config());
        let hw = test_hardware();
        let script = gen.imaging_script(Some(&hw), "workflow-123").unwrap();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Imaging Mode"));
        assert!(script.contains("dragonfly.workflow=workflow-123"));
        assert!(script.contains("dragonfly.hardware=test-machine"));
        // No menu
        assert!(!script.contains("menu"));
    }

    #[test]
    fn test_menu_script() {
        let gen = IpxeScriptGenerator::new(test_config());
        let hw = test_hardware();
        let script = gen.menu_script(Some(&hw)).unwrap();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Boot Menu"));
        assert!(script.contains("test-machine"));
        // Menu items
        assert!(script.contains("item local"));
        assert!(script.contains("item discovery"));
        assert!(script.contains("item imaging"));
    }

    #[test]
    fn test_kernel_params() {
        let config = test_config()
            .with_console("ttyS0,115200")
            .with_kernel_param("quiet")
            .with_verbose(true);

        let gen = IpxeScriptGenerator::new(config);
        let params = gen.kernel_params(None, "discovery");

        assert!(params.contains("quiet"));
        assert!(params.contains("console=ttyS0,115200"));
        assert!(params.contains("loglevel=7"));
        assert!(params.contains("dragonfly.mode=discovery"));
    }

    #[test]
    fn test_config_builder() {
        let config = IpxeConfig::new("http://10.0.0.1")
            .with_console("tty0")
            .with_kernel_param("nosplash")
            .with_verbose(true)
            .with_mage_kernel("http://10.0.0.1/kernel")
            .with_mage_initramfs("http://10.0.0.1/initramfs");

        assert_eq!(config.base_url, "http://10.0.0.1");
        assert_eq!(config.console, Some("tty0".to_string()));
        assert!(config.verbose);
        assert_eq!(config.mage_kernel(), "http://10.0.0.1/kernel");
    }
}
