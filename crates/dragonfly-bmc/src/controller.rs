//! BMC controller trait and implementations

use async_trait::async_trait;

use crate::error::Result;
use crate::types::{BootDevice, PowerState};

/// Trait for BMC power management operations
///
/// Implementations handle the protocol-specific details (IPMI, Redfish, WoL).
#[async_trait]
pub trait BmcController: Send + Sync {
    /// Power on the machine
    async fn power_on(&self) -> Result<()>;

    /// Power off the machine (hard shutdown)
    async fn power_off(&self) -> Result<()>;

    /// Power cycle the machine (off then on)
    async fn power_cycle(&self) -> Result<()>;

    /// Soft shutdown (ACPI shutdown signal)
    async fn soft_shutdown(&self) -> Result<()>;

    /// Get current power state
    async fn get_power_state(&self) -> Result<PowerState>;

    /// Set next boot device
    ///
    /// This sets the boot device for the next boot only (one-time).
    async fn set_boot_device(&self, device: BootDevice) -> Result<()>;

    /// Set persistent boot device
    ///
    /// This sets the boot device permanently until changed.
    async fn set_persistent_boot_device(&self, device: BootDevice) -> Result<()>;

    /// Check if the controller supports a specific operation
    fn supports_operation(&self, op: BmcOperation) -> bool;
}

/// BMC operations for capability checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BmcOperation {
    /// Power on
    PowerOn,
    /// Power off
    PowerOff,
    /// Power cycle
    PowerCycle,
    /// Soft shutdown
    SoftShutdown,
    /// Get power state
    GetPowerState,
    /// Set boot device (one-time)
    SetBootDevice,
    /// Set boot device (persistent)
    SetPersistentBootDevice,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock controller for testing
    struct MockBmcController {
        power_state: std::sync::atomic::AtomicU8,
    }

    impl MockBmcController {
        fn new(initial_state: PowerState) -> Self {
            let state = match initial_state {
                PowerState::On => 1,
                PowerState::Off => 0,
                PowerState::Unknown => 2,
            };
            Self {
                power_state: std::sync::atomic::AtomicU8::new(state),
            }
        }
    }

    #[async_trait]
    impl BmcController for MockBmcController {
        async fn power_on(&self) -> Result<()> {
            self.power_state
                .store(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn power_off(&self) -> Result<()> {
            self.power_state
                .store(0, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn power_cycle(&self) -> Result<()> {
            self.power_off().await?;
            self.power_on().await
        }

        async fn soft_shutdown(&self) -> Result<()> {
            self.power_off().await
        }

        async fn get_power_state(&self) -> Result<PowerState> {
            match self.power_state.load(std::sync::atomic::Ordering::SeqCst) {
                0 => Ok(PowerState::Off),
                1 => Ok(PowerState::On),
                _ => Ok(PowerState::Unknown),
            }
        }

        async fn set_boot_device(&self, _device: BootDevice) -> Result<()> {
            Ok(())
        }

        async fn set_persistent_boot_device(&self, _device: BootDevice) -> Result<()> {
            Ok(())
        }

        fn supports_operation(&self, _op: BmcOperation) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_mock_power_on() {
        let controller = MockBmcController::new(PowerState::Off);

        assert_eq!(controller.get_power_state().await.unwrap(), PowerState::Off);

        controller.power_on().await.unwrap();
        assert_eq!(controller.get_power_state().await.unwrap(), PowerState::On);
    }

    #[tokio::test]
    async fn test_mock_power_off() {
        let controller = MockBmcController::new(PowerState::On);

        assert_eq!(controller.get_power_state().await.unwrap(), PowerState::On);

        controller.power_off().await.unwrap();
        assert_eq!(controller.get_power_state().await.unwrap(), PowerState::Off);
    }

    #[tokio::test]
    async fn test_mock_power_cycle() {
        let controller = MockBmcController::new(PowerState::On);

        controller.power_cycle().await.unwrap();
        assert_eq!(controller.get_power_state().await.unwrap(), PowerState::On);
    }

    #[tokio::test]
    async fn test_mock_set_boot_device() {
        let controller = MockBmcController::new(PowerState::Off);

        controller.set_boot_device(BootDevice::Pxe).await.unwrap();
        controller
            .set_persistent_boot_device(BootDevice::Disk)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_supports_operation() {
        let controller = MockBmcController::new(PowerState::Off);

        assert!(controller.supports_operation(BmcOperation::PowerOn));
        assert!(controller.supports_operation(BmcOperation::SetBootDevice));
    }
}
