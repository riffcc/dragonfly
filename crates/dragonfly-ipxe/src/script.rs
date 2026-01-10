//! iPXE script generation
//!
//! This module provides utilities for generating iPXE boot scripts
//! for different boot scenarios.

use crate::error::{IpxeError, Result};
use dragonfly_crd::Hardware;

/// Boot mode for iPXE scripts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// Discovery boot - machine registers with server
    Discovery,
    /// Provisioning boot - run workflow to install OS
    Provisioning,
    /// Local boot - boot from local disk
    LocalBoot,
    /// Hook boot - boot into Dragonfly hook environment
    Hook,
}

/// Configuration for iPXE script generation
#[derive(Debug, Clone)]
pub struct IpxeConfig {
    /// Base URL for fetching resources (e.g., http://192.168.1.1:8080)
    pub base_url: String,

    /// Default kernel parameters
    pub kernel_params: Vec<String>,

    /// Console configuration (e.g., "ttyS0,115200")
    pub console: Option<String>,

    /// Enable verbose boot
    pub verbose: bool,

    /// Hook kernel URL (for provisioning boot)
    pub hook_kernel_url: Option<String>,

    /// Hook initramfs URL
    pub hook_initramfs_url: Option<String>,

    /// Custom script header
    pub script_header: Option<String>,
}

impl Default for IpxeConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            kernel_params: Vec::new(),
            console: None,
            verbose: false,
            hook_kernel_url: None,
            hook_initramfs_url: None,
            script_header: None,
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

    /// Set hook kernel URL
    pub fn with_hook_kernel(mut self, url: impl Into<String>) -> Self {
        self.hook_kernel_url = Some(url.into());
        self
    }

    /// Set hook initramfs URL
    pub fn with_hook_initramfs(mut self, url: impl Into<String>) -> Self {
        self.hook_initramfs_url = Some(url.into());
        self
    }

    /// Set custom script header
    pub fn with_script_header(mut self, header: impl Into<String>) -> Self {
        self.script_header = Some(header.into());
        self
    }
}

/// iPXE script generator
#[derive(Debug, Clone)]
pub struct IpxeScriptGenerator {
    config: IpxeConfig,
}

impl IpxeScriptGenerator {
    /// Create a new script generator
    pub fn new(config: IpxeConfig) -> Self {
        Self { config }
    }

    /// Generate an iPXE script for the given boot mode and hardware
    pub fn generate(&self, mode: BootMode, hardware: Option<&Hardware>) -> Result<String> {
        match mode {
            BootMode::Discovery => self.generate_discovery_script(),
            BootMode::Provisioning => self.generate_provisioning_script(hardware),
            BootMode::LocalBoot => self.generate_local_boot_script(),
            BootMode::Hook => self.generate_hook_script(hardware),
        }
    }

    /// Generate discovery script (machine registers with server)
    fn generate_discovery_script(&self) -> Result<String> {
        let mut script = self.script_header();

        script.push_str(&format!(
            r#"
echo Dragonfly Discovery Boot
echo MAC: ${{mac}}
echo

# Report to server for registration
chain {}/boot/register?mac=${{mac}}
"#,
            self.config.base_url
        ));

        Ok(script)
    }

    /// Generate provisioning script (boot into hook environment)
    fn generate_provisioning_script(&self, hardware: Option<&Hardware>) -> Result<String> {
        let kernel_url = self
            .config
            .hook_kernel_url
            .as_ref()
            .map(|u| u.clone())
            .or_else(|| Some(format!("{}/hook/vmlinuz", self.config.base_url)))
            .ok_or_else(|| IpxeError::MissingConfig("hook_kernel_url".to_string()))?;

        let initramfs_url = self
            .config
            .hook_initramfs_url
            .as_ref()
            .map(|u| u.clone())
            .or_else(|| Some(format!("{}/hook/initramfs", self.config.base_url)))
            .ok_or_else(|| IpxeError::MissingConfig("hook_initramfs_url".to_string()))?;

        let mut script = self.script_header();

        script.push_str(&format!(
            r#"
echo Dragonfly Provisioning Boot
echo MAC: ${{mac}}
"#
        ));

        if let Some(hw) = hardware {
            script.push_str(&format!("echo Hardware: {}\n", hw.metadata.name));
        }

        script.push_str(&format!(
            r#"echo

echo Loading kernel...
kernel {} {}
echo Loading initramfs...
initrd {}
echo Booting...
boot
"#,
            kernel_url,
            self.kernel_params_string(hardware),
            initramfs_url
        ));

        Ok(script)
    }

    /// Generate local boot script
    fn generate_local_boot_script(&self) -> Result<String> {
        let mut script = self.script_header();

        script.push_str(
            r#"
echo Dragonfly Local Boot
echo Booting from local disk...
echo

# Try UEFI boot first
iseq ${platform} efi && goto uefi_boot || goto bios_boot

:uefi_boot
echo Attempting UEFI boot...
sanboot --no-describe --drive 0x80 || goto boot_failed
exit

:bios_boot
echo Attempting BIOS boot...
sanboot --drive 0x80 || goto boot_failed
exit

:boot_failed
echo Local boot failed
shell
"#,
        );

        Ok(script)
    }

    /// Generate hook script (boot into Dragonfly hook environment)
    fn generate_hook_script(&self, hardware: Option<&Hardware>) -> Result<String> {
        let kernel_url = self
            .config
            .hook_kernel_url
            .as_ref()
            .map(|u| u.clone())
            .or_else(|| Some(format!("{}/hook/vmlinuz", self.config.base_url)))
            .ok_or_else(|| IpxeError::MissingConfig("hook_kernel_url".to_string()))?;

        let initramfs_url = self
            .config
            .hook_initramfs_url
            .as_ref()
            .map(|u| u.clone())
            .or_else(|| Some(format!("{}/hook/initramfs", self.config.base_url)))
            .ok_or_else(|| IpxeError::MissingConfig("hook_initramfs_url".to_string()))?;

        let mut script = self.script_header();

        script.push_str(&format!(
            r#"
echo Dragonfly Hook Environment
echo MAC: ${{mac}}
"#
        ));

        if let Some(hw) = hardware {
            script.push_str(&format!("echo Hardware: {}\n", hw.metadata.name));
        }

        // Get facility code from hardware metadata if available
        let facility_code = hardware
            .and_then(|hw| hw.spec.metadata.as_ref())
            .map(|m| m.instance.id.as_str())
            .unwrap_or("unknown");

        script.push_str(&format!(
            r#"echo

echo Loading hook kernel...
kernel {} {} facility={}
echo Loading hook initramfs...
initrd {}
echo Booting into hook environment...
boot
"#,
            kernel_url,
            self.kernel_params_string(hardware),
            facility_code,
            initramfs_url
        ));

        Ok(script)
    }

    /// Build the kernel parameters string
    fn kernel_params_string(&self, hardware: Option<&Hardware>) -> String {
        let mut params = self.config.kernel_params.clone();

        // Add console if configured
        if let Some(ref console) = self.config.console {
            params.push(format!("console={}", console));
        }

        // Add verbose flag
        if self.config.verbose {
            params.push("loglevel=7".to_string());
        }

        // Add server URL
        params.push(format!("dragonfly.url={}", self.config.base_url));

        // Add MAC address placeholder
        params.push("dragonfly.mac=${mac}".to_string());

        // Add hardware ID if available
        if let Some(hw) = hardware {
            params.push(format!("dragonfly.hardware={}", hw.metadata.name));
        }

        params.join(" ")
    }

    /// Generate script header
    fn script_header(&self) -> String {
        let mut header = String::from("#!ipxe\n");

        if let Some(ref custom_header) = self.config.script_header {
            header.push_str(custom_header);
            header.push('\n');
        }

        header.push_str("\n# Generated by Dragonfly\n");
        header
    }
}

/// Generate a chainload script that fetches the actual boot script from server
pub fn chainload_script(base_url: &str) -> String {
    format!(
        r#"#!ipxe

# Dragonfly Chainload Script
# Fetches boot script from server based on MAC address

echo Dragonfly PXE Boot
echo MAC: ${{mac}}
echo

chain {}/boot/${{mac}}
"#,
        base_url
    )
}

/// Generate an auto-registration script for unknown machines
pub fn auto_register_script(base_url: &str) -> String {
    format!(
        r#"#!ipxe

# Dragonfly Auto-Registration Script
# Registers unknown machines with the server

echo Dragonfly Auto-Registration
echo MAC: ${{mac}}
echo UUID: ${{uuid}}
echo Manufacturer: ${{manufacturer}}
echo Product: ${{product}}
echo Serial: ${{serial}}
echo

# Send hardware info to server
chain {}/boot/register?mac=${{mac}}&uuid=${{uuid}}&manufacturer=${{manufacturer}}&product=${{product}}&serial=${{serial}}
"#,
        base_url
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_crd::{HardwareSpec, ObjectMeta, TypeMeta};

    fn test_hardware() -> Hardware {
        Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test-machine"),
            spec: HardwareSpec::default(),
            status: None,
        }
    }

    #[test]
    fn test_ipxe_config_builder() {
        let config = IpxeConfig::new("http://192.168.1.1:8080")
            .with_console("ttyS0,115200")
            .with_kernel_param("quiet")
            .with_verbose(true);

        assert_eq!(config.base_url, "http://192.168.1.1:8080");
        assert_eq!(config.console, Some("ttyS0,115200".to_string()));
        assert_eq!(config.kernel_params, vec!["quiet"]);
        assert!(config.verbose);
    }

    #[test]
    fn test_generate_discovery_script() {
        let config = IpxeConfig::new("http://192.168.1.1:8080");
        let generator = IpxeScriptGenerator::new(config);

        let script = generator.generate(BootMode::Discovery, None).unwrap();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Discovery Boot"));
        assert!(script.contains("${mac}"));
        assert!(script.contains("chain http://192.168.1.1:8080/boot/register"));
    }

    #[test]
    fn test_generate_provisioning_script() {
        let config = IpxeConfig::new("http://192.168.1.1:8080")
            .with_hook_kernel("http://192.168.1.1:8080/hook/vmlinuz")
            .with_hook_initramfs("http://192.168.1.1:8080/hook/initramfs");

        let generator = IpxeScriptGenerator::new(config);
        let hw = test_hardware();

        let script = generator
            .generate(BootMode::Provisioning, Some(&hw))
            .unwrap();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Provisioning Boot"));
        assert!(script.contains("kernel http://192.168.1.1:8080/hook/vmlinuz"));
        assert!(script.contains("initrd http://192.168.1.1:8080/hook/initramfs"));
        assert!(script.contains("dragonfly.hardware=test-machine"));
    }

    #[test]
    fn test_generate_local_boot_script() {
        let config = IpxeConfig::new("http://192.168.1.1:8080");
        let generator = IpxeScriptGenerator::new(config);

        let script = generator.generate(BootMode::LocalBoot, None).unwrap();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Local Boot"));
        assert!(script.contains("sanboot"));
        assert!(script.contains("uefi_boot"));
        assert!(script.contains("bios_boot"));
    }

    #[test]
    fn test_generate_hook_script() {
        let config = IpxeConfig::new("http://192.168.1.1:8080")
            .with_console("ttyS0,115200")
            .with_verbose(true);

        let generator = IpxeScriptGenerator::new(config);
        let hw = test_hardware();

        let script = generator.generate(BootMode::Hook, Some(&hw)).unwrap();

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Hook Environment"));
        assert!(script.contains("console=ttyS0,115200"));
        assert!(script.contains("loglevel=7"));
        assert!(script.contains("dragonfly.url=http://192.168.1.1:8080"));
    }

    #[test]
    fn test_chainload_script() {
        let script = chainload_script("http://192.168.1.1:8080");

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("chain http://192.168.1.1:8080/boot/${mac}"));
    }

    #[test]
    fn test_auto_register_script() {
        let script = auto_register_script("http://192.168.1.1:8080");

        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("Auto-Registration"));
        assert!(script.contains("${uuid}"));
        assert!(script.contains("${manufacturer}"));
        assert!(script.contains("${serial}"));
    }

    #[test]
    fn test_kernel_params_string() {
        let config = IpxeConfig::new("http://192.168.1.1:8080")
            .with_console("tty0")
            .with_kernel_param("quiet")
            .with_kernel_param("splash")
            .with_verbose(true);

        let generator = IpxeScriptGenerator::new(config);
        let params = generator.kernel_params_string(None);

        assert!(params.contains("quiet"));
        assert!(params.contains("splash"));
        assert!(params.contains("console=tty0"));
        assert!(params.contains("loglevel=7"));
        assert!(params.contains("dragonfly.url=http://192.168.1.1:8080"));
    }

    #[test]
    fn test_boot_mode_enum() {
        assert_eq!(BootMode::Discovery, BootMode::Discovery);
        assert_ne!(BootMode::Discovery, BootMode::Provisioning);
        assert_ne!(BootMode::LocalBoot, BootMode::Hook);
    }
}
