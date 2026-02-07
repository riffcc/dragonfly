//! DHCP server configuration
//!
//! This module provides configuration types for the DHCP server
//! including server mode, network settings, and PXE options.

use std::net::Ipv4Addr;

/// DHCP server operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DhcpMode {
    /// Full DHCP server with IP assignment
    ///
    /// Acts as a complete DHCP server, assigning IP addresses
    /// from configured pools or static reservations.
    #[default]
    Reservation,

    /// Proxy DHCP mode (works alongside existing DHCP)
    ///
    /// Only responds with PXE boot options, does not assign IPs.
    /// Use when another DHCP server handles IP assignment.
    Proxy,

    /// Auto-proxy mode
    ///
    /// Behaves like Proxy mode but also handles unknown machines
    /// by providing basic PXE options for discovery boot.
    AutoProxy,
}

/// DHCP server configuration
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Server operating mode
    pub mode: DhcpMode,

    /// Interface to bind to (e.g., "eth0")
    /// If None, binds to all interfaces
    pub interface: Option<String>,

    /// IP address to bind socket to (use 0.0.0.0 for all interfaces)
    pub bind_ip: Ipv4Addr,

    /// Server IP address (used in DHCP responses for boot URLs)
    /// Must be a routable IP that clients can reach
    pub server_ip: Ipv4Addr,

    /// Subnet mask
    pub subnet_mask: Ipv4Addr,

    /// Default gateway
    pub gateway: Option<Ipv4Addr>,

    /// DNS servers
    pub dns_servers: Vec<Ipv4Addr>,

    /// Default lease time in seconds
    pub lease_time: u32,

    /// TFTP server IP (for PXE boot)
    pub tftp_server: Option<Ipv4Addr>,

    /// Boot filename (iPXE binary)
    pub boot_filename: Option<String>,

    /// iPXE script URL (for chainloading)
    pub ipxe_script_url: Option<String>,

    /// HTTP server port for iPXE scripts
    pub http_port: u16,

    /// Enable UEFI support
    pub uefi_support: bool,

    /// Pool range start (for Full/Reservation mode with dynamic allocation)
    pub pool_range_start: Option<Ipv4Addr>,

    /// Pool range end (inclusive)
    pub pool_range_end: Option<Ipv4Addr>,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            mode: DhcpMode::Reservation,
            interface: None,
            bind_ip: Ipv4Addr::new(0, 0, 0, 0),
            server_ip: Ipv4Addr::new(0, 0, 0, 0),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: None,
            dns_servers: Vec::new(),
            lease_time: 86400, // 24 hours
            tftp_server: None,
            boot_filename: None,
            ipxe_script_url: None,
            http_port: 8080,
            uefi_support: true,
            pool_range_start: None,
            pool_range_end: None,
        }
    }
}

impl DhcpConfig {
    /// Create a new DHCP config with server IP
    ///
    /// bind_ip: IP to bind socket to (0.0.0.0 for all interfaces)
    /// server_ip: IP to use in DHCP responses (must be routable)
    pub fn new(server_ip: Ipv4Addr) -> Self {
        Self {
            bind_ip: Ipv4Addr::new(0, 0, 0, 0), // Always bind to all interfaces
            server_ip,
            tftp_server: Some(server_ip), // Default TFTP to same server
            ..Default::default()
        }
    }

    /// Set the operating mode
    pub fn with_mode(mut self, mode: DhcpMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the interface to bind to
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Set the subnet mask
    pub fn with_subnet_mask(mut self, mask: Ipv4Addr) -> Self {
        self.subnet_mask = mask;
        self
    }

    /// Set the gateway
    pub fn with_gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Add a DNS server
    pub fn with_dns_server(mut self, dns: Ipv4Addr) -> Self {
        self.dns_servers.push(dns);
        self
    }

    /// Set the lease time
    pub fn with_lease_time(mut self, seconds: u32) -> Self {
        self.lease_time = seconds;
        self
    }

    /// Set the TFTP server
    pub fn with_tftp_server(mut self, server: Ipv4Addr) -> Self {
        self.tftp_server = Some(server);
        self
    }

    /// Set the boot filename
    pub fn with_boot_filename(mut self, filename: impl Into<String>) -> Self {
        self.boot_filename = Some(filename.into());
        self
    }

    /// Set the iPXE script URL
    pub fn with_ipxe_script_url(mut self, url: impl Into<String>) -> Self {
        self.ipxe_script_url = Some(url.into());
        self
    }

    /// Set the HTTP port
    pub fn with_http_port(mut self, port: u16) -> Self {
        self.http_port = port;
        self
    }

    /// Enable or disable UEFI support
    pub fn with_uefi_support(mut self, enabled: bool) -> Self {
        self.uefi_support = enabled;
        self
    }

    /// Set the IP pool range for dynamic allocation in Reservation/Full mode
    pub fn with_pool_range(mut self, start: Ipv4Addr, end: Ipv4Addr) -> Self {
        self.pool_range_start = Some(start);
        self.pool_range_end = Some(end);
        self
    }

    /// Get the appropriate boot filename based on architecture
    pub fn boot_file_for_arch(&self, is_uefi: bool, arch: Option<&str>) -> &str {
        if let Some(ref filename) = self.boot_filename {
            return filename;
        }

        // Default iPXE binaries
        match (is_uefi, arch) {
            (true, Some("x86_64")) => "ipxe.efi",
            (true, Some("aarch64")) => "arm64-efi/snp.efi",
            (true, None) => "ipxe.efi",
            (true, Some(_)) => "ipxe.efi", // Unknown UEFI arch, default to x86_64
            (false, _) => "undionly.kpxe",
        }
    }
}

/// PXE boot options to staple to DHCP responses
#[derive(Debug, Clone, Default)]
pub struct PxeOptions {
    /// TFTP server IP (option 66)
    pub tftp_server: Option<Ipv4Addr>,

    /// Boot filename (option 67)
    pub boot_filename: Option<String>,

    /// Vendor class identifier (option 60)
    pub vendor_class: Option<String>,

    /// Boot server discovery (option 43)
    pub boot_servers: Vec<Ipv4Addr>,
}

impl PxeOptions {
    /// Create PXE options from DHCP config
    pub fn from_config(config: &DhcpConfig, is_uefi: bool, arch: Option<&str>) -> Self {
        Self {
            tftp_server: config.tftp_server,
            boot_filename: Some(config.boot_file_for_arch(is_uefi, arch).to_string()),
            vendor_class: Some("PXEClient".to_string()),
            boot_servers: config.tftp_server.into_iter().collect(),
        }
    }

    /// Check if any PXE options are set
    pub fn is_empty(&self) -> bool {
        self.tftp_server.is_none()
            && self.boot_filename.is_none()
            && self.vendor_class.is_none()
            && self.boot_servers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_mode_default() {
        assert_eq!(DhcpMode::default(), DhcpMode::Reservation);
    }

    #[test]
    fn test_dhcp_config_new() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1));

        assert_eq!(config.server_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.tftp_server, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(config.mode, DhcpMode::Reservation);
        assert_eq!(config.lease_time, 86400);
    }

    #[test]
    fn test_dhcp_config_builder() {
        let config = DhcpConfig::new(Ipv4Addr::new(10, 0, 0, 1))
            .with_mode(DhcpMode::Proxy)
            .with_interface("eth0")
            .with_subnet_mask(Ipv4Addr::new(255, 255, 0, 0))
            .with_gateway(Ipv4Addr::new(10, 0, 0, 254))
            .with_dns_server(Ipv4Addr::new(8, 8, 8, 8))
            .with_dns_server(Ipv4Addr::new(8, 8, 4, 4))
            .with_lease_time(3600)
            .with_boot_filename("custom.ipxe")
            .with_ipxe_script_url("http://10.0.0.1:8080/boot.ipxe")
            .with_http_port(9090);

        assert_eq!(config.mode, DhcpMode::Proxy);
        assert_eq!(config.interface, Some("eth0".to_string()));
        assert_eq!(config.subnet_mask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(config.gateway, Some(Ipv4Addr::new(10, 0, 0, 254)));
        assert_eq!(config.dns_servers.len(), 2);
        assert_eq!(config.lease_time, 3600);
        assert_eq!(config.boot_filename, Some("custom.ipxe".to_string()));
        assert_eq!(config.http_port, 9090);
    }

    #[test]
    fn test_boot_file_for_arch() {
        let config = DhcpConfig::default();

        // UEFI x86_64
        assert_eq!(config.boot_file_for_arch(true, Some("x86_64")), "ipxe.efi");
        assert_eq!(config.boot_file_for_arch(true, None), "ipxe.efi");

        // UEFI ARM64
        assert_eq!(
            config.boot_file_for_arch(true, Some("aarch64")),
            "arm64-efi/snp.efi"
        );

        // Legacy BIOS
        assert_eq!(config.boot_file_for_arch(false, None), "undionly.kpxe");
        assert_eq!(
            config.boot_file_for_arch(false, Some("x86_64")),
            "undionly.kpxe"
        );

        // Custom filename overrides all
        let config = DhcpConfig::default().with_boot_filename("custom.pxe");
        assert_eq!(
            config.boot_file_for_arch(true, Some("x86_64")),
            "custom.pxe"
        );
        assert_eq!(config.boot_file_for_arch(false, None), "custom.pxe");
    }

    #[test]
    fn test_pxe_options_from_config() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1));
        let pxe = PxeOptions::from_config(&config, true, Some("x86_64"));

        assert_eq!(pxe.tftp_server, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(pxe.boot_filename, Some("ipxe.efi".to_string()));
        assert_eq!(pxe.vendor_class, Some("PXEClient".to_string()));
        assert!(!pxe.is_empty());
    }

    #[test]
    fn test_pxe_options_empty() {
        let pxe = PxeOptions::default();
        assert!(pxe.is_empty());
    }
}
