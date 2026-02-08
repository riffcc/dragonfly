//! DHCP server implementation
//!
//! This module provides the main DHCP server that handles client requests
//! and provides PXE boot options for bare metal provisioning.

use crate::config::{DhcpConfig, DhcpMode, PxeOptions};
use crate::error::{DhcpError, Result};
use crate::packet::{DhcpRequest, DhcpResponseBuilder};
use async_trait::async_trait;
use dhcproto::v4::MessageType;
use dragonfly_common::Machine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

/// Trait for looking up machines by MAC address
#[async_trait]
pub trait MachineLookup: Send + Sync {
    /// Look up machine by MAC address
    async fn get_machine_by_mac(&self, mac: &str) -> Option<Machine>;
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

/// Public lease information for API/UI consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub mac: String,
    pub ip: Ipv4Addr,
    pub remaining_secs: u64,
}

/// A single DHCP lease entry
struct LeaseEntry {
    ip: Ipv4Addr,
    expires_at: Instant,
}

/// In-memory lease table for pool allocation
pub struct LeaseTable {
    /// MAC address → lease mapping
    leases: HashMap<String, LeaseEntry>,
    /// Reverse lookup: IP → MAC address
    ip_to_mac: HashMap<Ipv4Addr, String>,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            ip_to_mac: HashMap::new(),
        }
    }

    /// List all active (non-expired) leases
    pub fn active_leases(&self) -> Vec<LeaseInfo> {
        let now = Instant::now();
        self.leases
            .iter()
            .filter(|(_, entry)| entry.expires_at > now)
            .map(|(mac, entry)| LeaseInfo {
                mac: mac.clone(),
                ip: entry.ip,
                remaining_secs: (entry.expires_at - now).as_secs(),
            })
            .collect()
    }

    /// Remove a specific lease by MAC address. Returns true if found and removed.
    pub fn remove_lease(&mut self, mac: &str) -> bool {
        if let Some(entry) = self.leases.remove(mac) {
            self.ip_to_mac.remove(&entry.ip);
            info!(mac = %mac, ip = %entry.ip, "Lease terminated");
            true
        } else {
            false
        }
    }

    /// Remove expired leases
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired_macs: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(mac, _)| mac.clone())
            .collect();

        for mac in expired_macs {
            if let Some(entry) = self.leases.remove(&mac) {
                self.ip_to_mac.remove(&entry.ip);
                debug!(mac = %mac, ip = %entry.ip, "Expired lease removed");
            }
        }
    }

    /// Allocate an IP from the pool range for the given MAC
    fn allocate(&mut self, mac: &str, start: Ipv4Addr, end: Ipv4Addr, lease_time: u32) -> Option<Ipv4Addr> {
        // If this MAC already has a valid lease, return its existing IP
        if let Some(entry) = self.leases.get(mac) {
            if entry.expires_at > Instant::now() {
                return Some(entry.ip);
            }
        }

        // Clean up expired leases before allocating
        self.cleanup_expired();

        // Iterate through the range and find the first available IP
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        for ip_u32 in start_u32..=end_u32 {
            let candidate = Ipv4Addr::from(ip_u32);
            if !self.ip_to_mac.contains_key(&candidate) {
                let expires_at = Instant::now() + std::time::Duration::from_secs(lease_time as u64);
                let entry = LeaseEntry { ip: candidate, expires_at };

                // Remove any old lease for this MAC
                if let Some(old) = self.leases.remove(mac) {
                    self.ip_to_mac.remove(&old.ip);
                }

                self.ip_to_mac.insert(candidate, mac.to_string());
                self.leases.insert(mac.to_string(), entry);
                info!(mac = %mac, ip = %candidate, "Pool lease allocated");
                return Some(candidate);
            }
        }

        warn!(mac = %mac, "Pool exhausted, no IPs available in range {}–{}", start, end);
        None
    }

    /// Renew an existing lease (extend expiry)
    fn renew(&mut self, mac: &str, lease_time: u32) -> Option<Ipv4Addr> {
        if let Some(entry) = self.leases.get_mut(mac) {
            entry.expires_at = Instant::now() + std::time::Duration::from_secs(lease_time as u64);
            Some(entry.ip)
        } else {
            None
        }
    }
}

/// DHCP server
pub struct DhcpServer {
    config: DhcpConfig,
    machine_lookup: Arc<dyn MachineLookup>,
    event_sender: broadcast::Sender<DhcpEvent>,
    lease_table: Arc<RwLock<LeaseTable>>,
}

impl DhcpServer {
    /// Create a new DHCP server with its own internal lease table
    pub fn new(config: DhcpConfig, machine_lookup: Arc<dyn MachineLookup>) -> Self {
        Self::with_lease_table(config, machine_lookup, Arc::new(RwLock::new(LeaseTable::new())))
    }

    /// Create a DHCP server with a shared external lease table
    pub fn with_lease_table(
        config: DhcpConfig,
        machine_lookup: Arc<dyn MachineLookup>,
        lease_table: Arc<RwLock<LeaseTable>>,
    ) -> Self {
        let (event_sender, _) = broadcast::channel(1024);
        Self {
            config,
            machine_lookup,
            event_sender,
            lease_table,
        }
    }

    /// Get a reference to the shared lease table
    pub fn lease_table(&self) -> &Arc<RwLock<LeaseTable>> {
        &self.lease_table
    }

    /// Subscribe to server events
    pub fn subscribe(&self) -> broadcast::Receiver<DhcpEvent> {
        self.event_sender.subscribe()
    }

    /// Run the DHCP server
    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let bind_addr = SocketAddrV4::new(self.config.bind_ip, 67);

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
        socket
            .set_nonblocking(true)
            .map_err(|e| DhcpError::BindFailed {
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
    async fn handle_packet(&self, socket: &UdpSocket, data: &[u8], _src: SocketAddr) -> Result<()> {
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
            is_ipxe = request.is_ipxe,
            is_http_boot = request.is_http_boot,
            "Received DHCP request"
        );

        // Emit request event
        let _ = self.event_sender.send(DhcpEvent::Request {
            mac: request.mac_address.clone(),
            message_type: format!("{:?}", request.message_type),
            is_pxe: request.is_boot_request(),
        });

        // Look up machine
        let machine = self
            .machine_lookup
            .get_machine_by_mac(&request.mac_address)
            .await;

        // Handle based on mode and message type
        let response = match self.config.mode {
            DhcpMode::Reservation => {
                self.handle_reservation_mode(&request, machine.as_ref())
                    .await?
            }
            DhcpMode::Proxy => self.handle_proxy_mode(&request, machine.as_ref()).await?,
            DhcpMode::AutoProxy => {
                self.handle_auto_proxy_mode(&request, machine.as_ref())
                    .await?
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
    ///
    /// Priority: machine reservation first, then pool allocation if configured.
    async fn handle_reservation_mode(
        &self,
        request: &DhcpRequest,
        machine: Option<&Machine>,
    ) -> Result<Option<(Vec<u8>, Option<Ipv4Addr>, String)>> {
        // Try machine reservation first
        if let Some(m) = machine {
            if let Some(reserved_ip) = m.dhcp_ip().and_then(|dhcp| dhcp.address.parse::<Ipv4Addr>().ok()) {
                return match request.message_type {
                    MessageType::Discover => {
                        let response = self.build_offer(request, reserved_ip, m)?;
                        Ok(Some((response, Some(reserved_ip), "OFFER".to_string())))
                    }
                    MessageType::Request => {
                        if let Some(requested) = request.requested_ip {
                            if requested != reserved_ip {
                                let response = self.build_nak(request)?;
                                return Ok(Some((response, None, "NAK".to_string())));
                            }
                        }
                        let response = self.build_ack(request, reserved_ip, m)?;
                        Ok(Some((response, Some(reserved_ip), "ACK".to_string())))
                    }
                    _ => Ok(None),
                };
            }
        }

        // No machine reservation — try pool allocation if configured
        let (pool_start, pool_end) = match (self.config.pool_range_start, self.config.pool_range_end) {
            (Some(s), Some(e)) => (s, e),
            _ => {
                debug!(mac = %request.mac_address, "No reservation and no pool configured, ignoring");
                return Ok(None);
            }
        };

        match request.message_type {
            MessageType::Discover => {
                let offered_ip = {
                    let mut table = self.lease_table.write().await;
                    table.allocate(&request.mac_address, pool_start, pool_end, self.config.lease_time)
                };
                match offered_ip {
                    Some(ip) => {
                        let response = self.build_pool_offer(request, ip)?;
                        Ok(Some((response, Some(ip), "OFFER".to_string())))
                    }
                    None => Ok(None),
                }
            }
            MessageType::Request => {
                // Try to renew existing lease, or allocate new one
                let ip = {
                    let mut table = self.lease_table.write().await;
                    table.renew(&request.mac_address, self.config.lease_time)
                        .or_else(|| {
                            // Blocking: we already hold the lock in the outer scope,
                            // but renew returned None so we need to allocate
                            None
                        })
                };

                let ip = match ip {
                    Some(ip) => ip,
                    None => {
                        // Try fresh allocation
                        let mut table = self.lease_table.write().await;
                        match table.allocate(&request.mac_address, pool_start, pool_end, self.config.lease_time) {
                            Some(ip) => ip,
                            None => return Ok(None),
                        }
                    }
                };

                // Verify requested IP matches if specified
                if let Some(requested) = request.requested_ip {
                    if requested != ip {
                        let response = self.build_nak(request)?;
                        return Ok(Some((response, None, "NAK".to_string())));
                    }
                }

                let response = self.build_pool_ack(request, ip)?;
                Ok(Some((response, Some(ip), "ACK".to_string())))
            }
            _ => Ok(None),
        }
    }

    /// Handle request in Proxy mode (PXE only, no IP assignment)
    async fn handle_proxy_mode(
        &self,
        request: &DhcpRequest,
        machine: Option<&Machine>,
    ) -> Result<Option<(Vec<u8>, Option<Ipv4Addr>, String)>> {
        // Only respond to boot requests (PXE or HTTP Boot)
        if !request.is_boot_request() {
            return Ok(None);
        }

        // Only respond if we have machine record
        let machine = match machine {
            Some(m) => m,
            None => {
                debug!(mac = %request.mac_address, "No machine record for PXE request");
                return Ok(None);
            }
        };

        // Check if netboot is allowed
        if !machine.allows_pxe() {
            debug!(mac = %request.mac_address, "PXE not allowed for machine");
            return Ok(None);
        }

        match request.message_type {
            MessageType::Discover | MessageType::Request => {
                let response = self.build_proxy_offer(request, Some(machine))?;
                Ok(Some((response, None, "PROXY_OFFER".to_string())))
            }
            _ => Ok(None),
        }
    }

    /// Handle request in AutoProxy mode
    async fn handle_auto_proxy_mode(
        &self,
        request: &DhcpRequest,
        machine: Option<&Machine>,
    ) -> Result<Option<(Vec<u8>, Option<Ipv4Addr>, String)>> {
        // Only respond to boot requests (PXE or HTTP Boot)
        if !request.is_boot_request() {
            return Ok(None);
        }

        // If we have machine, check if PXE is allowed
        if let Some(m) = machine {
            if !m.allows_pxe() {
                debug!(mac = %request.mac_address, "PXE not allowed for machine");
                return Ok(None);
            }
        }

        // In auto-proxy, we respond even without machine record
        // (for discovery boot)
        match request.message_type {
            MessageType::Discover | MessageType::Request => {
                let response = self.build_proxy_offer(request, machine)?;
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
        machine: &Machine,
    ) -> Result<Vec<u8>> {
        let mut builder =
            DhcpResponseBuilder::new(request.clone(), MessageType::Offer, self.config.server_ip)
                .with_offered_ip(offered_ip)
                .with_subnet_mask(self.config.subnet_mask)
                .with_lease_time(self.config.lease_time);

        // Add gateway
        if let Some(gateway) = self.config.gateway {
            builder = builder.with_gateway(gateway);
        } else if let Some(gw) = self.get_machine_gateway(machine) {
            builder = builder.with_gateway(gw);
        }

        // Add DNS servers
        if !self.config.dns_servers.is_empty() {
            builder = builder.with_dns_servers(self.config.dns_servers.clone());
        }

        // Add PXE/HTTP Boot options if allowed
        // In Full mode, always include boot options — some PXE ROMs (VMware)
        // drop Option 60 on REQUEST after sending it on DISCOVER, so we can't
        // gate on is_pxe_request() alone.
        if machine.allows_pxe() || request.is_http_boot {
            builder = builder.with_pxe_options(self.build_boot_options(request));
        }

        builder.build_bytes()
    }

    /// Build a DHCP ACK response
    fn build_ack(
        &self,
        request: &DhcpRequest,
        offered_ip: Ipv4Addr,
        machine: &Machine,
    ) -> Result<Vec<u8>> {
        let mut builder =
            DhcpResponseBuilder::new(request.clone(), MessageType::Ack, self.config.server_ip)
                .with_offered_ip(offered_ip)
                .with_subnet_mask(self.config.subnet_mask)
                .with_lease_time(self.config.lease_time);

        if let Some(gateway) = self.config.gateway {
            builder = builder.with_gateway(gateway);
        } else if let Some(gw) = self.get_machine_gateway(machine) {
            builder = builder.with_gateway(gw);
        }

        if !self.config.dns_servers.is_empty() {
            builder = builder.with_dns_servers(self.config.dns_servers.clone());
        }

        // Always include boot options in Full mode (see build_offer comment)
        if machine.allows_pxe() || request.is_http_boot {
            builder = builder.with_pxe_options(self.build_boot_options(request));
        }

        builder.build_bytes()
    }

    /// Build a DHCP NAK response
    fn build_nak(&self, request: &DhcpRequest) -> Result<Vec<u8>> {
        DhcpResponseBuilder::new(request.clone(), MessageType::Nak, self.config.server_ip)
            .build_bytes()
    }

    /// Build a DHCP OFFER for a pool-allocated IP (no machine record needed)
    fn build_pool_offer(&self, request: &DhcpRequest, offered_ip: Ipv4Addr) -> Result<Vec<u8>> {
        let mut builder =
            DhcpResponseBuilder::new(request.clone(), MessageType::Offer, self.config.server_ip)
                .with_offered_ip(offered_ip)
                .with_subnet_mask(self.config.subnet_mask)
                .with_lease_time(self.config.lease_time);

        if let Some(gateway) = self.config.gateway {
            builder = builder.with_gateway(gateway);
        }
        if !self.config.dns_servers.is_empty() {
            builder = builder.with_dns_servers(self.config.dns_servers.clone());
        }

        // Always include boot options in Full mode for pool clients —
        // non-PXE clients simply ignore Option 66/67, and some PXE ROMs
        // (VMware) drop Option 60 on REQUEST after sending it on DISCOVER.
        builder = builder.with_pxe_options(self.build_boot_options(request));

        builder.build_bytes()
    }

    /// Build a DHCP ACK for a pool-allocated IP (no machine record needed)
    fn build_pool_ack(&self, request: &DhcpRequest, offered_ip: Ipv4Addr) -> Result<Vec<u8>> {
        let mut builder =
            DhcpResponseBuilder::new(request.clone(), MessageType::Ack, self.config.server_ip)
                .with_offered_ip(offered_ip)
                .with_subnet_mask(self.config.subnet_mask)
                .with_lease_time(self.config.lease_time);

        if let Some(gateway) = self.config.gateway {
            builder = builder.with_gateway(gateway);
        }
        if !self.config.dns_servers.is_empty() {
            builder = builder.with_dns_servers(self.config.dns_servers.clone());
        }

        // Always include boot options (see build_pool_offer comment)
        builder = builder.with_pxe_options(self.build_boot_options(request));

        builder.build_bytes()
    }

    /// Build a proxy DHCP offer (boot options only)
    fn build_proxy_offer(
        &self,
        request: &DhcpRequest,
        _machine: Option<&Machine>,
    ) -> Result<Vec<u8>> {
        let pxe = self.build_boot_options(request);

        info!(
            mac = %request.mac_address,
            is_ipxe = %request.is_ipxe,
            is_http_boot = %request.is_http_boot,
            boot_filename = ?pxe.boot_filename,
            vendor_class = ?pxe.vendor_class,
            "Building PROXY_OFFER"
        );

        DhcpResponseBuilder::new(request.clone(), MessageType::Offer, self.config.server_ip)
            .with_pxe_options(pxe)
            .build_bytes()
    }

    /// Build appropriate PXE/HTTP Boot options based on client type.
    ///
    /// Three client types:
    /// - iPXE client → HTTP URL for boot script (per-MAC)
    /// - HTTP Boot client → HTTP URL for ipxe.efi binary (chainload into iPXE)
    /// - Standard PXE client → TFTP filename for iPXE binary
    fn build_boot_options(&self, request: &DhcpRequest) -> PxeOptions {
        let is_uefi = request.client_arch.map(|a| a.is_uefi()).unwrap_or(false);
        let arch = request.client_arch.and_then(|a| a.arch_string());

        if request.is_ipxe {
            // iPXE client: send boot script URL
            let script_url = self.config.ipxe_script_url.clone().unwrap_or_else(|| {
                format!(
                    "http://{}:{}/boot/${{mac}}",
                    self.config.server_ip, self.config.http_port
                )
            });
            PxeOptions {
                tftp_server: None,
                boot_filename: Some(script_url),
                vendor_class: Some("PXEClient".to_string()),
                boot_servers: vec![],
            }
        } else if request.is_http_boot {
            // UEFI HTTP Boot: serve ipxe.efi via HTTP URL
            // The firmware downloads ipxe.efi over HTTP, then iPXE takes over
            let ipxe_url = format!(
                "http://{}:{}/boot/ipxe.efi",
                self.config.server_ip, self.config.http_port
            );
            info!(
                mac = %request.mac_address,
                url = %ipxe_url,
                "HTTP Boot client: sending iPXE EFI URL"
            );
            PxeOptions {
                tftp_server: None,
                boot_filename: Some(ipxe_url),
                vendor_class: Some("HTTPClient".to_string()),
                boot_servers: vec![],
            }
        } else {
            // Standard PXE client: TFTP filename
            PxeOptions::from_config(&self.config, is_uefi, arch)
        }
    }

    /// Get gateway from machine config
    fn get_machine_gateway(&self, machine: &Machine) -> Option<Ipv4Addr> {
        machine
            .dhcp_ip()
            .and_then(|dhcp| dhcp.gateway.as_ref())
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
    use dragonfly_common::{DhcpReservation, MachineIdentity, NetbootConfig};

    struct MockMachineLookup {
        machines: std::sync::RwLock<HashMap<String, Machine>>,
    }

    impl MockMachineLookup {
        fn new() -> Self {
            Self {
                machines: std::sync::RwLock::new(HashMap::new()),
            }
        }

        fn add_machine(&self, mac: &str, machine: Machine) {
            self.machines
                .write()
                .unwrap()
                .insert(mac.to_lowercase(), machine);
        }
    }

    #[async_trait]
    impl MachineLookup for MockMachineLookup {
        async fn get_machine_by_mac(&self, mac: &str) -> Option<Machine> {
            self.machines
                .read()
                .unwrap()
                .get(&mac.to_lowercase())
                .cloned()
        }
    }

    fn test_machine(mac: &str, ip: &str, allow_pxe: bool) -> Machine {
        let identity = MachineIdentity::from_mac(mac);
        let mut machine = Machine::new(identity);
        machine.config.netboot = NetbootConfig {
            allow_pxe,
            allow_workflow: true,
            dhcp_ip: Some(DhcpReservation {
                address: ip.to_string(),
                gateway: Some("192.168.1.1".to_string()),
                netmask: Some("255.255.255.0".to_string()),
            }),
        };
        machine
    }

    #[test]
    fn test_dhcp_server_new() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1));
        let lookup = Arc::new(MockMachineLookup::new());
        let server = DhcpServer::new(config, lookup);

        assert_eq!(server.config.server_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_dhcp_server_subscribe() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1));
        let lookup = Arc::new(MockMachineLookup::new());
        let server = DhcpServer::new(config, lookup);

        let _receiver = server.subscribe();
        // Just verify subscription works
    }

    #[tokio::test]
    async fn test_machine_lookup() {
        let lookup = MockMachineLookup::new();
        let machine = test_machine("00:11:22:33:44:55", "192.168.1.100", true);
        lookup.add_machine("00:11:22:33:44:55", machine);

        let found = lookup.get_machine_by_mac("00:11:22:33:44:55").await;
        assert!(found.is_some());

        let found = lookup
            .get_machine_by_mac("00:11:22:33:44:55")
            .await
            .unwrap();
        assert_eq!(found.primary_mac(), "00:11:22:33:44:55");

        // Case insensitive
        let found = lookup.get_machine_by_mac("00:11:22:33:44:55").await;
        assert!(found.is_some());

        // Not found
        let not_found = lookup.get_machine_by_mac("ff:ff:ff:ff:ff:ff").await;
        assert!(not_found.is_none());
    }

    #[test]
    fn test_dhcp_modes() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1)).with_mode(DhcpMode::Proxy);
        assert_eq!(config.mode, DhcpMode::Proxy);

        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1)).with_mode(DhcpMode::AutoProxy);
        assert_eq!(config.mode, DhcpMode::AutoProxy);
    }

    #[test]
    fn test_pool_allocation_basic() {
        let mut table = LeaseTable::new();
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end = Ipv4Addr::new(10, 0, 0, 105);

        // First allocation gets first IP
        let ip = table.allocate("aa:bb:cc:dd:ee:01", start, end, 3600);
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 100)));

        // Second client gets next IP
        let ip = table.allocate("aa:bb:cc:dd:ee:02", start, end, 3600);
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 101)));

        // Same MAC returns same IP (existing lease)
        let ip = table.allocate("aa:bb:cc:dd:ee:01", start, end, 3600);
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 100)));
    }

    #[test]
    fn test_pool_allocation_exhaustion() {
        let mut table = LeaseTable::new();
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end = Ipv4Addr::new(10, 0, 0, 101); // Only 2 IPs

        let ip1 = table.allocate("aa:bb:cc:dd:ee:01", start, end, 3600);
        assert!(ip1.is_some());

        let ip2 = table.allocate("aa:bb:cc:dd:ee:02", start, end, 3600);
        assert!(ip2.is_some());

        // Pool exhausted
        let ip3 = table.allocate("aa:bb:cc:dd:ee:03", start, end, 3600);
        assert!(ip3.is_none());
    }

    #[test]
    fn test_pool_renew() {
        let mut table = LeaseTable::new();
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end = Ipv4Addr::new(10, 0, 0, 105);

        // Allocate
        let ip = table.allocate("aa:bb:cc:dd:ee:01", start, end, 3600);
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 100)));

        // Renew returns same IP
        let renewed = table.renew("aa:bb:cc:dd:ee:01", 7200);
        assert_eq!(renewed, Some(Ipv4Addr::new(10, 0, 0, 100)));

        // Unknown MAC renew returns None
        let unknown = table.renew("ff:ff:ff:ff:ff:ff", 3600);
        assert!(unknown.is_none());
    }

    #[test]
    fn test_pool_config_builder() {
        let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1))
            .with_mode(DhcpMode::Reservation)
            .with_pool_range(Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 200));

        assert_eq!(config.pool_range_start, Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(config.pool_range_end, Some(Ipv4Addr::new(192, 168, 1, 200)));
    }
}
