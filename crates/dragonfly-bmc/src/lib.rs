//! Dragonfly BMC Control
//!
//! This crate provides BMC (Baseboard Management Controller) integration
//! for power management and boot device control.
//!
//! # Supported Protocols
//!
//! - **IPMI**: Traditional BMC protocol, widely supported on server hardware
//! - **Redfish**: Modern REST-based protocol for newer hardware
//! - **Wake-on-LAN**: Simple power-on only (no other operations)
//!
//! # Example
//!
//! ```
//! use dragonfly_bmc::{WolController, BmcController};
//!
//! # async fn example() -> dragonfly_bmc::error::Result<()> {
//! // Wake-on-LAN for simple power-on
//! let controller = WolController::from_mac("aa:bb:cc:dd:ee:ff")?;
//!
//! // Check what operations are supported
//! use dragonfly_bmc::BmcOperation;
//! assert!(controller.supports_operation(BmcOperation::PowerOn));
//! assert!(!controller.supports_operation(BmcOperation::PowerOff));
//!
//! // Power on the machine
//! controller.power_on().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # IPMI Example
//!
//! ```no_run
//! use dragonfly_bmc::{IpmiController, IpmiConfig, BmcController, BootDevice};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! # async fn example() -> dragonfly_bmc::error::Result<()> {
//! let config = IpmiConfig::new(
//!     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
//!     "admin",
//!     "password",
//! );
//!
//! let controller = IpmiController::new(config);
//!
//! // Set PXE boot for next reboot
//! controller.set_boot_device(BootDevice::Pxe).await?;
//!
//! // Power cycle to apply
//! controller.power_cycle().await?;
//! # Ok(())
//! # }
//! ```

pub mod controller;
pub mod error;
pub mod ipmi;
pub mod redfish;
pub mod types;
pub mod wol;

pub use controller::{BmcController, BmcOperation};
pub use error::{BmcError, Result};
pub use ipmi::IpmiController;
pub use redfish::RedfishController;
pub use types::{BootDevice, BmcProtocol, IpmiConfig, PowerState, RedfishConfig, WolConfig};
pub use wol::WolController;
