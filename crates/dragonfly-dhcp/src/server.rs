//! DHCP server implementation
//!
//! This module provides the main DHCP server that handles client requests
//! and provides PXE boot options for bare metal provisioning.

use crate::config::{DhcpConfig, DhcpMode, PxeOptions};
use crate::error::{DhcpError, Result};
use crate::packet::{DhcpRequest, DhcpResponseBuilder};
use async_trait::async_trait;
use dhcproto::v4::MessageType;
use dragonfly_crd::Hardware;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Trait for looking up hardware information
#[async_trait]
pub trait HardwareLookup: Send + Sync {
    /// Look up hardware by MAC address
    async fn get_hardware_by_mac(&self, mac: &str) -> Option<Hardware>;
}

/// Event emitted by the DHCP server
#[derive(Debug, Clone)]
pub enum DhcpEvent {
    /// Server started
    Started { bind_addr: SocketAddr },
    /// Received a DHCP request
    Request {
        mac: String,
        message_type: String,
        is_pxe: bool,
    },
    /// Sent a DHCP response
    Response {
        mac: String,
        message_type: String,
        offered_ip: Option<Ipv4Addr>,
    },
    /// Error occurred
    Error { mac: Option<String>, error: String },
    /// Server stopped
    Stopped,
}

/// DHCP server
pub struct DhcpServer {
    config: DhcpConfig,
    hardware_lookup: Arc<dyn HardwareLookup>,
    event_sender: broadcast::Sender<DhcpEvent>,
}

impl DhcpServer {
    /// Create a new DHCP server
    pub fn new(config: DhcpConfig, hardware_lookup: Arc<dyn HardwareLookup>) -> Self {
        let (event_sender, _) = broadcast::channel(1024);
        Self {
            config,
            hardware_lookup,
            event_sender,
        }
    }

    /// Subscribe to server events
    pub fn subscribe(&self) -> broadcast::Receiver<DhcpEvent> {
        self.event_sender.subscribe()
    }

    /// Run the DHCP server
    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let bind_addr = SocketAddrV4::new(self.config.server_ip, 67);

        // Create and bind socket
        let socket = self.create_socket(bind_addr).await?;

        info!(addr = %bind_addr, mode = ?self.config.mode, "DHCP server started");
        let _ = self.event_sender.send(DhcpEvent::Started {
            bind_addr: bind_addr.into(),
        });

        let mut buf = [0u8; 1500];
        let mut shutdown = shutdown;

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            if let Err(e) = self.handle_packet(&socket, &buf[..len], src).await {
                                error!(error = %e, "Error handling DHCP packet");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving packet");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("DHCP server shutting down");
                        let _ = self.event_sender.send(DhcpEvent::Stopped);
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Create and configure the UDP socket
    async fn create_socket(&self, bind_addr: SocketAddrV4) -> Result<UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| DhcpError::BindFailed {
            addr: bind_addr.into(),
            source: e,
        })?;

        // Allow address reuse
        socket.set_reuse_address(true).ok();

        // Set broadcast option
        socket.set_broadcast(true).ok();

        // Bind to address
        socket
            .bind(&bind_addr.into())
            .map_err(|e| DhcpError::BindFailed {
                addr: bind_addr.into(),
                source: e,
            })?;

        // Set non-blocking for tokio
        socket.set_nonblocking(true).map_err(|e| DhcpError::BindFailed {
            addr: bind_addr.into(),
            source: e,
        })?;

        // Convert to tokio socket
        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket).map_err(|e| DhcpError::BindFailed {
            addr: bind_addr.into(),
            source: e,
        })
    }

    /// Handle an incoming DHCP packet
    async fn handle_packet(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        _src: SocketAddr,
    ) -> Result<()> {
        // Parse the request
        let request = match DhcpRequest::parse(data) {
            Ok(req) => req,
            Err(e) => {
                debug!(error = %e, "Failed to parse DHCP packet");
                return Ok(());
            }
        };

        debug!(
            mac = %request.mac_address,
            msg_type = ?request.message_type,
            is_pxe = request.is_pxe_request(),
            "Received DHCP request"
        );

        // Emit request event
        let _ = self.event_sender.send(DhcpEvent::Request {
            mac: request.mac_address.clone(),
            message_type: format!("{:?}", request.message_type),
            is_pxe: request.is_pxe_request(),
        });

        // Look up hardware
        let hardware = self
            .hardware_lookup
            .get_hardware_by_mac(&request.mac_address)
            .await;

        // Handle based on mode and message type
        let response = match self.config.mode {
            DhcpMode::Reservation => {
                self.handle_reservation_mode(&request, hardware.as_ref()).await?
            }
            DhcpMode::Proxy => {
                self.handle_proxy_mode(&request, hardware.as_ref()).await?
            }
            DhcpMode::AutoProxy => {
                self.handle_auto_proxy_mode(&request, hardware.as_ref()).await?
            }
        };

        // Send response if we have one
        if let Some((response_bytes, offered_ip, msg_type)) = response {
            // Determine destination address
            let dest = if request.relay_ip != Ipv4Addr::UNSPECIFIED {
                // Relayed request - send to relay agent
                SocketAddr::new(request.relay_ip.into(), 67)
            } else if request.client_ip != Ipv4Addr::UNSPECIFIED {
                // Client has IP - send unicast
                SocketAddr::new(request.client_ip.into(), 68)
            } else {
                // Broadcast
                SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68)
            };

            socket.send_to(&response_bytes, dest).await?;

            info!(
                mac = %request.mac_address,
                msg_type = %msg_type,
                offered_ip = ?offered_ip,
                dest = %dest,
                "Sent DHCP response"
            );

            let _ = self.event_sender.send(DhcpEvent::Response {
                mac: request.mac_address,
                message_type: msg_type,
                offered_ip,
            });
        }

        Ok(())
    }

    /// Handle request in Reservation mode (full DHCP server)
    async fn handle_reservation_mode(
        &self,
        request: &DhcpRequest,
        hardware: Option<&Hardware>,
    ) -> Result<Option<(Vec<u8>, Option<Ipv4Addr>, String)>> {
        let hardware = match hardware {
            Some(hw) => hw,
            None => {
                debug!(mac = %request.mac_address, "No hardware record found, ignoring");
                return Ok(None);
            }
        };

        // Get configured IP for this hardware
        let offered_ip = hardware
            .spec
            .interfaces
            .first()
            .and_then(|iface| iface.dhcp.as_ref())
            .and_then(|dhcp| dhcp.ip.as_ref())
            .and_then(|ip| ip.address.parse().ok());

        let offered_ip = match offered_ip {
            Some(ip) => ip,
            None => {
                warn!(mac = %request.mac_address, "No IP configured for hardware");
                return Ok(None);
            }
        };

        match request.message_type {
            MessageType::Discover => {
                let response = self.build_offer(request, offered_ip, hardware)?;
                Ok(Some((response, Some(offered_ip), "OFFER".to_string())))
            }
            MessageType::Request => {
                // Verify requested IP matches
                if let Some(requested) = request.requested_ip {
                    if requested != offered_ip {
                        // Send NAK
                        let response = self.build_nak(request)?;
                        return Ok(Some((response, None, "NAK".to_string())));
                    }
                }
                let response = self.build_ack(request, offered_ip, hardware)?;
                Ok(Some((response, Some(offered_ip), "ACK".to_string())))
            }
            _ => Ok(None),
        }
    }

    /// Handle request in Proxy mode (PXE only, no IP assignment)
    async fn handle_proxy_mode(
        &self,
        request: &DhcpRequest,
        hardware: Option<&Hardware>,
    ) -> Result<Option<(Vec<u8>, Option<Ipv4Addr>, String)>> {
        // Only respond to PXE requests
        if !request.is_pxe_request() {
            return Ok(None);
        }

        // Only respond if we have hardware record
        let hardware = match hardware {
            Some(hw) => hw,
            None => {
                debug!(mac = %request.mac_address, "No hardware record for PXE request");
                return Ok(None);
            }
        };

        // Check if netboot is allowed
        if !hardware.allows_pxe() {
            debug!(mac = %request.mac_address, "PXE not allowed for hardware");
            return Ok(None);
        }

        match request.message_type {
            MessageType::Discover | MessageType::Request => {
                let response = self.build_proxy_offer(request, Some(hardware))?;
                Ok(Some((response, None, "PROXY_OFFER".to_string())))
            }
            _ => Ok(None),
        }
    }

    /// Handle request in AutoProxy mode
    async fn handle_auto_proxy_mode(
        &self,
        request: &DhcpRequest,
        hardware: Option<&Hardware>,
    ) -> Result<Option<(Vec<u8>, Option<Ipv4Addr>, String)>> {
        // Only respond to PXE requests
        if !request.is_pxe_request() {
            return Ok(None);
        }

        // If we have hardware, check if PXE is allowed
        if let Some(hw) = hardware {
            if !hw.allows_pxe() {
                debug!(mac = %request.mac_address, "PXE not allowed for hardware");
                return Ok(None);
            }
        }

        // In auto-proxy, we respond even without hardware record
        // (for discovery boot)
        match request.message_type {
            MessageType::Discover | MessageType::Request => {
                let response = self.build_proxy_offer(request, hardware)?;
                Ok(Some((response, None, "PROXY_OFFER".to_string())))
            }
            _ => Ok(None),
        }
    }

    /// Build a DHCP OFFER response
    fn build_offer(
        &self,
        request: &DhcpRequest,
        offered_ip: Ipv4Addr,
        hardware: &Hardware,
    ) -> Result<Vec<u8>> {
        let is_uefi = request.client_arch.map(|a| a.is_uefi()).unwrap_or(false);
        let arch = request.client_arch.and_then(|a| a.arch_string());

        let mut builder = DhcpResponseBuilder::new(
            request.clone(),
            MessageType::Offer,
            self.config.server_ip,
        )
        .with_offered_ip(offered_ip)
        .with_subnet_mask(self.config.subnet_mask)
        .with_lease_time(self.config.lease_time);

        // Add gateway
        if let Some(gateway) = self.config.gateway {
            builder = builder.with_gateway(gateway);
        } else if let Some(gw) = self.get_hardware_gateway(hardware) {
            builder = builder.with_gateway(gw);
        }

        // Add DNS servers
        if !self.config.dns_servers.is_empty() {
            builder = builder.with_dns_servers(self.config.dns_servers.clone());
        }

        // Add PXE options if this is a PXE request and allowed
        if request.is_pxe_request() && hardware.allows_pxe() {
            let pxe = if request.is_ipxe {
                // iPXE client - send boot script URL
                let script_url = self.config.ipxe_script_url.clone().unwrap_or_else(|| {
                    format!(
                        "http://{}:{}/boot/${{mac}}",
                        self.config.server_ip,
                        self.config.http_port
                    )
                });
                PxeOptions {
                    tftp_server: None,
                    boot_filename: Some(script_url),
                    vendor_class: Some("PXEClient".to_string()),
                    boot_servers: vec![],
                }
            } else {
                // Standard PXE client - send iPXE binary
                PxeOptions::from_config(&self.config, is_uefi, arch)
            };
            builder = builder.with_pxe_options(pxe);
        }

        builder.build_bytes()
    }

    /// Build a DHCP ACK response
    fn build_ack(
        &self,
        request: &DhcpRequest,
        offered_ip: Ipv4Addr,
        hardware: &Hardware,
    ) -> Result<Vec<u8>> {
        let is_uefi = request.client_arch.map(|a| a.is_uefi()).unwrap_or(false);
        let arch = request.client_arch.and_then(|a| a.arch_string());

        let mut builder = DhcpResponseBuilder::new(
            request.clone(),
            MessageType::Ack,
            self.config.server_ip,
        )
        .with_offered_ip(offered_ip)
        .with_subnet_mask(self.config.subnet_mask)
        .with_lease_time(self.config.lease_time);

        if let Some(gateway) = self.config.gateway {
            builder = builder.with_gateway(gateway);
        } else if let Some(gw) = self.get_hardware_gateway(hardware) {
            builder = builder.with_gateway(gw);
        }

        if !self.config.dns_servers.is_empty() {
            builder = builder.with_dns_servers(self.config.dns_servers.clone());
        }

        // Add PXE options if this is a PXE request and allowed
        if request.is_pxe_request() && hardware.allows_pxe() {
            let pxe = if request.is_ipxe {
                // iPXE client - send boot script URL
                let script_url = self.config.ipxe_script_url.clone().unwrap_or_else(|| {
                    format!(
                        "http://{}:{}/boot/${{mac}}",
                        self.config.server_ip,
                        self.config.http_port
                    )
                });
                PxeOptions {
                    tftp_server: None,
                    boot_filename: Some(script_url),
                    vendor_class: Some("PXEClient".to_string()),
                    boot_servers: vec![],
                }
            } else {
                // Standard PXE client - send iPXE binary
                PxeOptions::from_config(&self.config, is_uefi, arch)
            };
            builder = builder.with_pxe_options(pxe);
        }

        builder.build_bytes()
    }

    /// Build a DHCP NAK response
    fn build_nak(&self, request: &DhcpRequest) -> Result<Vec<u8>> {
        DhcpResponseBuilder::new(request.clone(), MessageType::Nak, self.config.server_ip)
            .build_bytes()
    }

    /// Build a proxy DHCP offer (PXE options only)
    fn build_proxy_offer(
        &self,
        request: &DhcpRequest,
        _hardware: Option<&Hardware>,
    ) -> Result<Vec<u8>> {
        let is_uefi = request.client_arch.map(|a| a.is_uefi()).unwrap_or(false);
        let arch = request.client_arch.and_then(|a| a.arch_string());

        info!(
            mac = %request.mac_address,
            is_ipxe = %request.is_ipxe,
            is_uefi = %is_uefi,
            arch = ?arch,
            "Building PROXY_OFFER"
        );

        // If this is an iPXE client, send the boot script URL instead of iPXE binary
        let pxe = if request.is_ipxe {
            if let Some(ref script_url) = self.config.ipxe_script_url {
                info!(
                    mac = %request.mac_address,
                    script_url = %script_url,
                    "iPXE client: sending configured boot script URL"
                );
                PxeOptions {
                    tftp_server: None,
                    boot_filename: Some(script_url.clone()),
                    vendor_class: Some("PXEClient".to_string()),
                    boot_servers: vec![],
                }
            } else {
                // No script URL configured, use default based on server URL
                let script_url = format!(
                    "http://{}:{}/boot/${{mac}}",
                    self.config.server_ip,
                    self.config.http_port
                );
                info!(
                    mac = %request.mac_address,
                    script_url = %script_url,
                    "iPXE client: sending default boot script URL"
                );
                PxeOptions {
                    tftp_server: None,
                    boot_filename: Some(script_url),
                    vendor_class: Some("PXEClient".to_string()),
                    boot_servers: vec![],
                }
            }
        } else {
            // Standard PXE client - send iPXE binary via TFTP
            let pxe = PxeOptions::from_config(&self.config, is_uefi, arch);
            info!(
                mac = %request.mac_address,
                tftp_server = ?pxe.tftp_server,
                boot_filename = ?pxe.boot_filename,
                "PXE client: sending iPXE binary via TFTP"
            );
            pxe
        };

        DhcpResponseBuilder::new(request.clone(), MessageType::Offer, self.config.server_ip)
            .with_pxe_options(pxe)
            .build_bytes()
    }

    /// Get gateway from hardware config
    fn get_hardware_gateway(&self, hardware: &Hardware) -> Option<Ipv4Addr> {
        hardware
            .spec
            .interfaces
            .first()
            .and_then(|iface| iface.dhcp.as_ref())
            .and_then(|dhcp| dhcp.ip.as_ref())
            .and_then(|ip| ip.gateway.as_ref())
            .and_then(|gw| gw.parse().ok())
    }
}

impl std::fmt::Debug for DhcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpServer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_crd::{DhcpSpec, HardwareSpec, InterfaceSpec, IpSpec, NetbootSpec, ObjectMeta, TypeMeta};
    use std::collections::HashMap;
    use std::sync::RwLock;

    struct MockHardwareLookup {
        hardware: RwLock<HashMap<String, Hardware>>,
    }

    impl MockHardwareLookup {
        fn new() -> Self {
            Self {
                hardware: RwLock::new(HashMap::new()),
            }
        }

        fn add_hardware(&self, mac: &str, hardware: Hardware) {
            self.hardware
                .write()
                .unwrap()
                .insert(mac.to_lowercase(), hardware);
        }
    }

    #[async_trait]
    impl HardwareLookup for MockHardwareLookup {
        async fn get_hardware_by_mac(&self, mac: &str) -> Option<Hardware> {
            self.hardware.read().unwrap().get(&mac.to_lowercase()).cloned()
        }
    }

    fn test_hardware(mac: &str, ip: &str, allow_pxe: bool) -> Hardware {
        Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new(format!("machine-{}", mac.replace(':', "-"))),
            spec: HardwareSpec {
                interfaces: vec![InterfaceSpec {
                    dhcp: Some(DhcpSpec {
                        mac: mac.to_string(),
                        hostname: Some("test-host".to_string()),
                        ip: Some(IpSpec {
                            address: ip.to_string(),
                            gateway: Some("192.168.1.1".to_string()),
                            netmask: Some("255.255.255.0".to_string()),
                        }),
                        arch: None,
                        lease_time: None,
                        name_servers: Vec::new(),
                        uefi: None,
                    }),
                    netboot: Some(NetbootSpec {
                        allow_pxe: Some(allow_pxe),
                        allow_workflow: Some(true),
                    }),
                }],
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn test_dhcp_server_new() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1));
        let lookup = Arc::new(MockHardwareLookup::new());
        let server = DhcpServer::new(config, lookup);

        assert_eq!(server.config.server_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_dhcp_server_subscribe() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1));
        let lookup = Arc::new(MockHardwareLookup::new());
        let server = DhcpServer::new(config, lookup);

        let _receiver = server.subscribe();
        // Just verify subscription works
    }

    #[tokio::test]
    async fn test_hardware_lookup() {
        let lookup = MockHardwareLookup::new();
        let hw = test_hardware("00:11:22:33:44:55", "192.168.1.100", true);
        lookup.add_hardware("00:11:22:33:44:55", hw);

        let found = lookup.get_hardware_by_mac("00:11:22:33:44:55").await;
        assert!(found.is_some());

        let found = lookup.get_hardware_by_mac("00:11:22:33:44:55").await.unwrap();
        assert_eq!(found.metadata.name, "machine-00-11-22-33-44-55");

        // Case insensitive
        let found = lookup.get_hardware_by_mac("00:11:22:33:44:55").await;
        assert!(found.is_some());

        // Not found
        let not_found = lookup.get_hardware_by_mac("ff:ff:ff:ff:ff:ff").await;
        assert!(not_found.is_none());
    }

    #[test]
    fn test_dhcp_modes() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1))
            .with_mode(DhcpMode::Proxy);
        assert_eq!(config.mode, DhcpMode::Proxy);

        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1))
            .with_mode(DhcpMode::AutoProxy);
        assert_eq!(config.mode, DhcpMode::AutoProxy);
    }
}
