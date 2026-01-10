//! Common types for BMC operations

use std::net::IpAddr;

/// Power state of a machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// Machine is powered on
    On,
    /// Machine is powered off
    Off,
    /// Power state is unknown
    Unknown,
}

impl std::fmt::Display for PowerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PowerState::On => write!(f, "on"),
            PowerState::Off => write!(f, "off"),
            PowerState::Unknown => write!(f, "unknown"),
        }
    }
}

/// Boot device selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootDevice {
    /// Boot from network (PXE)
    Pxe,
    /// Boot from local disk
    Disk,
    /// Boot from CD/DVD
    Cdrom,
    /// Boot from BIOS setup
    BiosSetup,
    /// No override (use default)
    None,
}

impl std::fmt::Display for BootDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootDevice::Pxe => write!(f, "pxe"),
            BootDevice::Disk => write!(f, "disk"),
            BootDevice::Cdrom => write!(f, "cdrom"),
            BootDevice::BiosSetup => write!(f, "bios"),
            BootDevice::None => write!(f, "none"),
        }
    }
}

/// BMC protocol to use
#[derive(Debug, Clone)]
pub enum BmcProtocol {
    /// IPMI over LAN
    Ipmi(IpmiConfig),
    /// Redfish REST API
    Redfish(RedfishConfig),
    /// Wake-on-LAN (power on only)
    WakeOnLan(WolConfig),
}

/// IPMI connection configuration
#[derive(Debug, Clone)]
pub struct IpmiConfig {
    /// BMC IP address
    pub address: IpAddr,
    /// BMC port (default 623)
    pub port: u16,
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

impl IpmiConfig {
    /// Create new IPMI config
    pub fn new(address: IpAddr, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            address,
            port: 623,
            username: username.into(),
            password: password.into(),
        }
    }

    /// Set custom port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

/// Redfish REST API configuration
#[derive(Debug, Clone)]
pub struct RedfishConfig {
    /// Base URL (e.g., https://bmc.example.com)
    pub base_url: String,
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// Skip TLS verification (for self-signed certs)
    pub insecure: bool,
}

impl RedfishConfig {
    /// Create new Redfish config
    pub fn new(
        base_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            username: username.into(),
            password: password.into(),
            insecure: false,
        }
    }

    /// Allow insecure TLS (self-signed certs)
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }
}

/// Wake-on-LAN configuration
#[derive(Debug, Clone)]
pub struct WolConfig {
    /// Target MAC address
    pub mac_address: [u8; 6],
    /// Broadcast address (default 255.255.255.255)
    pub broadcast_address: IpAddr,
    /// Port (default 9)
    pub port: u16,
}

impl WolConfig {
    /// Create new WoL config from MAC address
    pub fn new(mac_address: [u8; 6]) -> Self {
        Self {
            mac_address,
            broadcast_address: IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            port: 9,
        }
    }

    /// Parse MAC address from string (e.g., "aa:bb:cc:dd:ee:ff")
    pub fn from_mac_string(mac: &str) -> Option<Self> {
        let parts: Vec<&str> = mac.split(':').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut addr = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            addr[i] = u8::from_str_radix(part, 16).ok()?;
        }

        Some(Self::new(addr))
    }

    /// Set custom broadcast address
    pub fn with_broadcast(mut self, addr: IpAddr) -> Self {
        self.broadcast_address = addr;
        self
    }

    /// Set custom port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Get MAC address as string
    pub fn mac_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac_address[0],
            self.mac_address[1],
            self.mac_address[2],
            self.mac_address[3],
            self.mac_address[4],
            self.mac_address[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_power_state_display() {
        assert_eq!(PowerState::On.to_string(), "on");
        assert_eq!(PowerState::Off.to_string(), "off");
        assert_eq!(PowerState::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_boot_device_display() {
        assert_eq!(BootDevice::Pxe.to_string(), "pxe");
        assert_eq!(BootDevice::Disk.to_string(), "disk");
        assert_eq!(BootDevice::Cdrom.to_string(), "cdrom");
    }

    #[test]
    fn test_ipmi_config() {
        let config = IpmiConfig::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "admin",
            "password",
        );

        assert_eq!(config.port, 623);
        assert_eq!(config.username, "admin");

        let config = config.with_port(6230);
        assert_eq!(config.port, 6230);
    }

    #[test]
    fn test_redfish_config() {
        let config = RedfishConfig::new("https://bmc.local", "admin", "password");

        assert!(!config.insecure);
        assert_eq!(config.base_url, "https://bmc.local");

        let config = config.with_insecure(true);
        assert!(config.insecure);
    }

    #[test]
    fn test_wol_config_from_mac() {
        let config = WolConfig::from_mac_string("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(config.mac_address, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(config.mac_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_wol_config_invalid_mac() {
        assert!(WolConfig::from_mac_string("invalid").is_none());
        assert!(WolConfig::from_mac_string("aa:bb:cc").is_none());
        assert!(WolConfig::from_mac_string("aa:bb:cc:dd:ee:gg").is_none());
    }

    #[test]
    fn test_wol_config_builder() {
        let config = WolConfig::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .with_broadcast(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)))
            .with_port(7);

        assert_eq!(
            config.broadcast_address,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(config.port, 7);
    }
}
