//! Wake-on-LAN implementation
//!
//! Wake-on-LAN is a simple protocol that sends a "magic packet" to wake
//! a machine from a powered-off state. It only supports power_on().

use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use crate::controller::{BmcController, BmcOperation};
use crate::error::{BmcError, Result};
use crate::types::{BootDevice, PowerState, WolConfig};

/// Wake-on-LAN controller
///
/// Only supports power_on() - other operations return Unsupported.
#[derive(Debug)]
pub struct WolController {
    config: WolConfig,
}

impl WolController {
    /// Create a new Wake-on-LAN controller
    pub fn new(config: WolConfig) -> Self {
        Self { config }
    }

    /// Create from MAC address string
    pub fn from_mac(mac: &str) -> Result<Self> {
        let config = WolConfig::from_mac_string(mac)
            .ok_or_else(|| BmcError::InvalidConfig(format!("invalid MAC address: {}", mac)))?;
        Ok(Self::new(config))
    }

    /// Build the magic packet
    ///
    /// Magic packet format:
    /// - 6 bytes of 0xFF
    /// - Target MAC repeated 16 times (96 bytes)
    /// - Total: 102 bytes
    fn build_magic_packet(&self) -> [u8; 102] {
        let mut packet = [0u8; 102];

        // 6 bytes of 0xFF
        for byte in packet.iter_mut().take(6) {
            *byte = 0xFF;
        }

        // MAC address repeated 16 times
        for i in 0..16 {
            let offset = 6 + (i * 6);
            packet[offset..offset + 6].copy_from_slice(&self.config.mac_address);
        }

        packet
    }

    /// Get the target MAC address
    pub fn mac_address(&self) -> &[u8; 6] {
        &self.config.mac_address
    }
}

#[async_trait]
impl BmcController for WolController {
    async fn power_on(&self) -> Result<()> {
        let packet = self.build_magic_packet();

        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| BmcError::NetworkError(e.to_string()))?;

        // Enable broadcast
        socket
            .set_broadcast(true)
            .map_err(|e| BmcError::NetworkError(e.to_string()))?;

        let target = SocketAddr::new(self.config.broadcast_address, self.config.port);

        socket
            .send_to(&packet, target)
            .await
            .map_err(|e| BmcError::NetworkError(e.to_string()))?;

        Ok(())
    }

    async fn power_off(&self) -> Result<()> {
        Err(BmcError::Unsupported(
            "Wake-on-LAN does not support power off".to_string(),
        ))
    }

    async fn power_cycle(&self) -> Result<()> {
        Err(BmcError::Unsupported(
            "Wake-on-LAN does not support power cycle".to_string(),
        ))
    }

    async fn soft_shutdown(&self) -> Result<()> {
        Err(BmcError::Unsupported(
            "Wake-on-LAN does not support soft shutdown".to_string(),
        ))
    }

    async fn get_power_state(&self) -> Result<PowerState> {
        // WoL can't query state
        Ok(PowerState::Unknown)
    }

    async fn set_boot_device(&self, _device: BootDevice) -> Result<()> {
        Err(BmcError::Unsupported(
            "Wake-on-LAN does not support setting boot device".to_string(),
        ))
    }

    async fn set_persistent_boot_device(&self, _device: BootDevice) -> Result<()> {
        Err(BmcError::Unsupported(
            "Wake-on-LAN does not support setting boot device".to_string(),
        ))
    }

    fn supports_operation(&self, op: BmcOperation) -> bool {
        matches!(op, BmcOperation::PowerOn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wol_from_mac() {
        let controller = WolController::from_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(
            controller.mac_address(),
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn test_wol_from_invalid_mac() {
        let result = WolController::from_mac("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_magic_packet_format() {
        let controller = WolController::from_mac("11:22:33:44:55:66").unwrap();
        let packet = controller.build_magic_packet();

        // Check length
        assert_eq!(packet.len(), 102);

        // Check first 6 bytes are 0xFF
        assert_eq!(&packet[0..6], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Check MAC is repeated 16 times
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        for i in 0..16 {
            let offset = 6 + (i * 6);
            assert_eq!(&packet[offset..offset + 6], &mac);
        }
    }

    #[test]
    fn test_supports_operation() {
        let controller = WolController::from_mac("aa:bb:cc:dd:ee:ff").unwrap();

        assert!(controller.supports_operation(BmcOperation::PowerOn));
        assert!(!controller.supports_operation(BmcOperation::PowerOff));
        assert!(!controller.supports_operation(BmcOperation::SetBootDevice));
    }

    #[tokio::test]
    async fn test_unsupported_operations() {
        let controller = WolController::from_mac("aa:bb:cc:dd:ee:ff").unwrap();

        assert!(controller.power_off().await.is_err());
        assert!(controller.power_cycle().await.is_err());
        assert!(controller.soft_shutdown().await.is_err());
        assert!(controller.set_boot_device(BootDevice::Pxe).await.is_err());
    }

    #[tokio::test]
    async fn test_get_power_state_unknown() {
        let controller = WolController::from_mac("aa:bb:cc:dd:ee:ff").unwrap();

        let state = controller.get_power_state().await.unwrap();
        assert_eq!(state, PowerState::Unknown);
    }
}
