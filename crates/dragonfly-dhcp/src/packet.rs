//! DHCP packet handling
//!
//! This module provides utilities for parsing and building DHCP packets
//! with PXE boot options.

use crate::config::PxeOptions;
use crate::error::{DhcpError, Result};
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Encodable};
use std::net::Ipv4Addr;

/// Client architecture types (RFC 4578)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientArch {
    /// Intel x86 BIOS
    IntelX86Bios = 0,
    /// EFI x86
    EfiX86 = 6,
    /// EFI x86_64
    EfiX64 = 7,
    /// EFI ARM32
    EfiArm32 = 10,
    /// EFI ARM64
    EfiArm64 = 11,
    /// Unknown architecture
    Unknown = 255,
}

impl From<u16> for ClientArch {
    fn from(value: u16) -> Self {
        match value {
            0 => ClientArch::IntelX86Bios,
            6 => ClientArch::EfiX86,
            7 => ClientArch::EfiX64,
            10 => ClientArch::EfiArm32,
            11 => ClientArch::EfiArm64,
            _ => ClientArch::Unknown,
        }
    }
}

impl ClientArch {
    /// Check if this is a UEFI architecture
    pub fn is_uefi(&self) -> bool {
        matches!(
            self,
            ClientArch::EfiX86 | ClientArch::EfiX64 | ClientArch::EfiArm32 | ClientArch::EfiArm64
        )
    }

    /// Get the Rust architecture string
    pub fn arch_string(&self) -> Option<&'static str> {
        match self {
            ClientArch::IntelX86Bios | ClientArch::EfiX86 => Some("x86"),
            ClientArch::EfiX64 => Some("x86_64"),
            ClientArch::EfiArm32 => Some("arm"),
            ClientArch::EfiArm64 => Some("aarch64"),
            ClientArch::Unknown => None,
        }
    }
}

/// Parsed DHCP request with extracted information
#[derive(Debug, Clone)]
pub struct DhcpRequest {
    /// Original message
    pub message: Message,

    /// Message type (DISCOVER, REQUEST, etc.)
    pub message_type: MessageType,

    /// Client MAC address
    pub mac_address: String,

    /// Client architecture (from option 93)
    pub client_arch: Option<ClientArch>,

    /// Requested IP address (from option 50)
    pub requested_ip: Option<Ipv4Addr>,

    /// Is this an iPXE client? (checks user-class option)
    pub is_ipxe: bool,

    /// Transaction ID
    pub xid: u32,

    /// Client IP (ciaddr)
    pub client_ip: Ipv4Addr,

    /// Gateway IP (giaddr) for relayed requests
    pub relay_ip: Ipv4Addr,
}

impl DhcpRequest {
    /// Parse a DHCP request from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let message =
            Message::from_bytes(data).map_err(|e| DhcpError::ParseError(e.to_string()))?;

        // Extract message type
        let message_type = message
            .opts()
            .get(OptionCode::MessageType)
            .and_then(|opt| {
                if let DhcpOption::MessageType(mt) = opt {
                    Some(mt.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| DhcpError::ParseError("missing message type".to_string()))?;

        // Extract MAC address
        let mac_bytes = message.chaddr();
        let mac_address = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
        );

        // Extract client architecture (option 93)
        let client_arch = message
            .opts()
            .get(OptionCode::ClientSystemArchitecture)
            .and_then(|opt| {
                if let DhcpOption::ClientSystemArchitecture(arch) = opt {
                    Some(ClientArch::from(u16::from(*arch)))
                } else {
                    None
                }
            });

        // Extract requested IP (option 50)
        let requested_ip = message
            .opts()
            .get(OptionCode::RequestedIpAddress)
            .and_then(|opt| {
                if let DhcpOption::RequestedIpAddress(ip) = opt {
                    Some(ip.clone())
                } else {
                    None
                }
            });

        // Check if iPXE client (option 77 user-class contains "iPXE")
        let is_ipxe = message
            .opts()
            .get(OptionCode::UserClass)
            .map(|opt| {
                if let DhcpOption::UserClass(user_class) = opt {
                    String::from_utf8_lossy(user_class).contains("iPXE")
                } else {
                    false
                }
            })
            .unwrap_or(false);

        Ok(Self {
            xid: message.xid(),
            client_ip: message.ciaddr(),
            relay_ip: message.giaddr(),
            message,
            message_type,
            mac_address,
            client_arch,
            requested_ip,
            is_ipxe,
        })
    }

    /// Check if this is a PXE boot request
    pub fn is_pxe_request(&self) -> bool {
        // Check vendor class option 60 for "PXEClient"
        self.message
            .opts()
            .get(OptionCode::ClassIdentifier)
            .map(|opt| {
                if let DhcpOption::ClassIdentifier(class) = opt {
                    String::from_utf8_lossy(class).starts_with("PXEClient")
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }
}

/// DHCP response builder
pub struct DhcpResponseBuilder {
    request: DhcpRequest,
    message_type: MessageType,
    server_ip: Ipv4Addr,
    offered_ip: Option<Ipv4Addr>,
    subnet_mask: Option<Ipv4Addr>,
    gateway: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
    lease_time: Option<u32>,
    pxe_options: Option<PxeOptions>,
}

impl DhcpResponseBuilder {
    /// Create a new response builder
    pub fn new(request: DhcpRequest, message_type: MessageType, server_ip: Ipv4Addr) -> Self {
        Self {
            request,
            message_type,
            server_ip,
            offered_ip: None,
            subnet_mask: None,
            gateway: None,
            dns_servers: Vec::new(),
            lease_time: None,
            pxe_options: None,
        }
    }

    /// Set the offered IP address
    pub fn with_offered_ip(mut self, ip: Ipv4Addr) -> Self {
        self.offered_ip = Some(ip);
        self
    }

    /// Set the subnet mask
    pub fn with_subnet_mask(mut self, mask: Ipv4Addr) -> Self {
        self.subnet_mask = Some(mask);
        self
    }

    /// Set the gateway
    pub fn with_gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Set DNS servers
    pub fn with_dns_servers(mut self, servers: Vec<Ipv4Addr>) -> Self {
        self.dns_servers = servers;
        self
    }

    /// Set the lease time
    pub fn with_lease_time(mut self, seconds: u32) -> Self {
        self.lease_time = Some(seconds);
        self
    }

    /// Set PXE options
    pub fn with_pxe_options(mut self, options: PxeOptions) -> Self {
        self.pxe_options = Some(options);
        self
    }

    /// Build the response message
    pub fn build(self) -> Result<Message> {
        let mut response = Message::default();

        // Set basic fields
        response.set_opcode(Opcode::BootReply);
        response.set_xid(self.request.xid);
        response.set_flags(self.request.message.flags());
        response.set_chaddr(self.request.message.chaddr());
        response.set_giaddr(self.request.relay_ip);

        // Set yiaddr (your IP address)
        if let Some(ip) = self.offered_ip {
            response.set_yiaddr(ip);
        }

        // Set siaddr (server IP)
        response.set_siaddr(self.server_ip);

        // Add message type
        response
            .opts_mut()
            .insert(DhcpOption::MessageType(self.message_type));

        // Add server identifier
        response
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(self.server_ip));

        // Add subnet mask
        if let Some(mask) = self.subnet_mask {
            response.opts_mut().insert(DhcpOption::SubnetMask(mask));
        }

        // Add gateway (router)
        if let Some(gateway) = self.gateway {
            response
                .opts_mut()
                .insert(DhcpOption::Router(vec![gateway]));
        }

        // Add DNS servers
        if !self.dns_servers.is_empty() {
            response
                .opts_mut()
                .insert(DhcpOption::DomainNameServer(self.dns_servers));
        }

        // Add lease time
        if let Some(lease_time) = self.lease_time {
            response
                .opts_mut()
                .insert(DhcpOption::AddressLeaseTime(lease_time));
        }

        // Add PXE options
        if let Some(pxe) = self.pxe_options {
            // TFTP server (option 66)
            if let Some(tftp) = pxe.tftp_server {
                response.set_siaddr(tftp);
                // Also set as string for some clients
                response
                    .opts_mut()
                    .insert(DhcpOption::TFTPServerName(tftp.to_string().into_bytes()));
            }

            // Boot filename (option 67)
            if let Some(filename) = pxe.boot_filename {
                response.set_fname_str(&filename);
                response
                    .opts_mut()
                    .insert(DhcpOption::BootfileName(filename.into_bytes()));
            }

            // Vendor class
            if let Some(vendor) = pxe.vendor_class {
                response
                    .opts_mut()
                    .insert(DhcpOption::ClassIdentifier(vendor.into_bytes()));
            }

            // PXE vendor options (Option 43) — tells PXE ROM to skip Boot Server
            // Discovery and use the filename from DHCP directly. Required for VMware
            // and other PXE ROMs that default to discovery mode without this.
            // Format: sub-option 6 (PXE_DISCOVERY_CONTROL) = 0x08, then END (0xFF)
            response
                .opts_mut()
                .insert(DhcpOption::VendorExtensions(vec![
                    0x06, 0x01, 0x08, // Sub-option 6, length 1, value 8 (skip discovery)
                    0xFF,             // END
                ]));
        }

        Ok(response)
    }

    /// Build and encode the response to bytes
    pub fn build_bytes(self) -> Result<Vec<u8>> {
        let message = self.build()?;
        message
            .to_vec()
            .map_err(|e| DhcpError::EncodeError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_message(msg: &Message) -> Vec<u8> {
        msg.to_vec().unwrap()
    }

    #[test]
    fn test_client_arch_from_u16() {
        assert_eq!(ClientArch::from(0), ClientArch::IntelX86Bios);
        assert_eq!(ClientArch::from(7), ClientArch::EfiX64);
        assert_eq!(ClientArch::from(11), ClientArch::EfiArm64);
        assert_eq!(ClientArch::from(999), ClientArch::Unknown);
    }

    #[test]
    fn test_client_arch_is_uefi() {
        assert!(!ClientArch::IntelX86Bios.is_uefi());
        assert!(ClientArch::EfiX64.is_uefi());
        assert!(ClientArch::EfiArm64.is_uefi());
        assert!(!ClientArch::Unknown.is_uefi());
    }

    #[test]
    fn test_client_arch_string() {
        assert_eq!(ClientArch::IntelX86Bios.arch_string(), Some("x86"));
        assert_eq!(ClientArch::EfiX64.arch_string(), Some("x86_64"));
        assert_eq!(ClientArch::EfiArm64.arch_string(), Some("aarch64"));
        assert_eq!(ClientArch::Unknown.arch_string(), None);
    }

    #[test]
    fn test_build_offer_response() {
        // Create a minimal DHCP discover message for testing
        let mut discover = Message::default();
        discover.set_opcode(Opcode::BootRequest);
        discover.set_xid(0x12345678);
        discover.set_chaddr(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        discover
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));

        let bytes = encode_message(&discover);
        let request = DhcpRequest::parse(&bytes).unwrap();

        assert_eq!(request.message_type, MessageType::Discover);
        assert_eq!(request.mac_address, "00:11:22:33:44:55");
        assert_eq!(request.xid, 0x12345678);

        // Build offer response
        let response =
            DhcpResponseBuilder::new(request, MessageType::Offer, Ipv4Addr::new(192, 168, 1, 1))
                .with_offered_ip(Ipv4Addr::new(192, 168, 1, 100))
                .with_subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
                .with_gateway(Ipv4Addr::new(192, 168, 1, 1))
                .with_lease_time(86400)
                .build()
                .unwrap();

        assert_eq!(response.opcode(), Opcode::BootReply);
        assert_eq!(response.xid(), 0x12345678);
        assert_eq!(response.yiaddr(), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_build_response_with_pxe() {
        let mut discover = Message::default();
        discover.set_opcode(Opcode::BootRequest);
        discover.set_xid(0xAABBCCDD);
        discover.set_chaddr(&[
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        discover
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        discover.opts_mut().insert(DhcpOption::ClassIdentifier(
            b"PXEClient:Arch:00007".to_vec(),
        ));

        let bytes = encode_message(&discover);
        let request = DhcpRequest::parse(&bytes).unwrap();

        assert!(request.is_pxe_request());

        let pxe_opts = PxeOptions {
            tftp_server: Some(Ipv4Addr::new(192, 168, 1, 1)),
            boot_filename: Some("ipxe.efi".to_string()),
            vendor_class: Some("PXEClient".to_string()),
            boot_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
        };

        let response =
            DhcpResponseBuilder::new(request, MessageType::Offer, Ipv4Addr::new(192, 168, 1, 1))
                .with_offered_ip(Ipv4Addr::new(192, 168, 1, 100))
                .with_pxe_options(pxe_opts)
                .build()
                .unwrap();

        // Verify PXE options are set
        assert_eq!(response.siaddr(), Ipv4Addr::new(192, 168, 1, 1));
    }
}
