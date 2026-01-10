//! IPMI protocol implementation
//!
//! IPMI (Intelligent Platform Management Interface) is the most common
//! BMC protocol for server hardware. This module provides IPMI over LAN
//! support for power management.
//!
//! Note: Full IPMI implementation requires the `ipmitool` binary or a
//! native Rust IPMI library. This module provides the structure for
//! integration with external tools.

use async_trait::async_trait;

use crate::controller::{BmcController, BmcOperation};
use crate::error::{BmcError, Result};
use crate::types::{BootDevice, IpmiConfig, PowerState};

/// IPMI controller using external ipmitool
#[derive(Debug)]
pub struct IpmiController {
    config: IpmiConfig,
}

impl IpmiController {
    /// Create a new IPMI controller
    pub fn new(config: IpmiConfig) -> Self {
        Self { config }
    }

    /// Get the BMC address
    pub fn address(&self) -> &std::net::IpAddr {
        &self.config.address
    }

    /// Build ipmitool command args
    fn base_args(&self) -> Vec<String> {
        vec![
            "-I".to_string(),
            "lanplus".to_string(),
            "-H".to_string(),
            self.config.address.to_string(),
            "-p".to_string(),
            self.config.port.to_string(),
            "-U".to_string(),
            self.config.username.clone(),
            "-P".to_string(),
            self.config.password.clone(),
        ]
    }

    /// Execute ipmitool command (stub - would shell out to ipmitool)
    async fn execute_ipmi(&self, command: &[&str]) -> Result<String> {
        let mut args = self.base_args();
        args.extend(command.iter().map(|s| s.to_string()));

        // In a real implementation, this would execute:
        // ipmitool -I lanplus -H <addr> -p <port> -U <user> -P <pass> <command>
        //
        // For now, return an error indicating the stub status
        Err(BmcError::Unsupported(format!(
            "IPMI stub: would execute 'ipmitool {}'",
            args.join(" ")
        )))
    }
}

#[async_trait]
impl BmcController for IpmiController {
    async fn power_on(&self) -> Result<()> {
        self.execute_ipmi(&["chassis", "power", "on"]).await?;
        Ok(())
    }

    async fn power_off(&self) -> Result<()> {
        self.execute_ipmi(&["chassis", "power", "off"]).await?;
        Ok(())
    }

    async fn power_cycle(&self) -> Result<()> {
        self.execute_ipmi(&["chassis", "power", "cycle"]).await?;
        Ok(())
    }

    async fn soft_shutdown(&self) -> Result<()> {
        self.execute_ipmi(&["chassis", "power", "soft"]).await?;
        Ok(())
    }

    async fn get_power_state(&self) -> Result<PowerState> {
        let output = self.execute_ipmi(&["chassis", "power", "status"]).await?;

        if output.contains("is on") {
            Ok(PowerState::On)
        } else if output.contains("is off") {
            Ok(PowerState::Off)
        } else {
            Ok(PowerState::Unknown)
        }
    }

    async fn set_boot_device(&self, device: BootDevice) -> Result<()> {
        let device_arg = match device {
            BootDevice::Pxe => "pxe",
            BootDevice::Disk => "disk",
            BootDevice::Cdrom => "cdrom",
            BootDevice::BiosSetup => "bios",
            BootDevice::None => "none",
        };

        self.execute_ipmi(&["chassis", "bootdev", device_arg])
            .await?;
        Ok(())
    }

    async fn set_persistent_boot_device(&self, device: BootDevice) -> Result<()> {
        let device_arg = match device {
            BootDevice::Pxe => "pxe",
            BootDevice::Disk => "disk",
            BootDevice::Cdrom => "cdrom",
            BootDevice::BiosSetup => "bios",
            BootDevice::None => "none",
        };

        self.execute_ipmi(&["chassis", "bootdev", device_arg, "options=persistent"])
            .await?;
        Ok(())
    }

    fn supports_operation(&self, _op: BmcOperation) -> bool {
        // IPMI supports all operations
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config() -> IpmiConfig {
        IpmiConfig::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "admin",
            "password",
        )
    }

    #[test]
    fn test_ipmi_controller_creation() {
        let controller = IpmiController::new(test_config());
        assert_eq!(
            controller.address(),
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn test_base_args() {
        let controller = IpmiController::new(test_config());
        let args = controller.base_args();

        assert!(args.contains(&"lanplus".to_string()));
        assert!(args.contains(&"192.168.1.100".to_string()));
        assert!(args.contains(&"admin".to_string()));
    }

    #[test]
    fn test_supports_all_operations() {
        let controller = IpmiController::new(test_config());

        assert!(controller.supports_operation(BmcOperation::PowerOn));
        assert!(controller.supports_operation(BmcOperation::PowerOff));
        assert!(controller.supports_operation(BmcOperation::SetBootDevice));
    }

    // Note: Actual IPMI operations are stubs and will return errors
    // Real integration tests would require actual BMC hardware or emulation
}
