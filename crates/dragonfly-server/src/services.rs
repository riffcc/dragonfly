//! Network Services Runner
//!
//! This module manages the network services required for bare metal provisioning:
//! - DHCP server for PXE boot
//! - TFTP server for iPXE binaries
//! - Metadata service integration for cloud-init
//!
//! All services are optional and can be enabled/disabled via configuration.

use crate::store::v1::Store;
use async_trait::async_trait;
use bytes::Bytes;
use dragonfly_common::dns::{DnsProvider, DnsRecord, DnsRecordType};
use dragonfly_common::Machine;
use dragonfly_dhcp::{DhcpConfig, DhcpEvent, DhcpMode, DhcpServer, LeaseTable, MachineLookup, NetworkReservation};
use dragonfly_dns::{DnsServer, DnsStore, ZoneConfig};
use dragonfly_tftp::{FileProvider, TftpEvent, TftpServer};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

/// Configuration for network services
#[derive(Debug, Clone)]
pub struct ServicesConfig {
    /// DHCP server configuration (None = disabled)
    pub dhcp: Option<DhcpServiceConfig>,
    /// TFTP server configuration (None = disabled)
    pub tftp: Option<TftpServiceConfig>,
    /// Server IP address (used for DHCP next-server and TFTP bind)
    pub server_ip: Ipv4Addr,
    /// HTTP port for boot script URLs (must match the main server port)
    pub http_port: u16,
}

impl Default for ServicesConfig {
    fn default() -> Self {
        Self {
            dhcp: None,
            tftp: None,
            server_ip: Ipv4Addr::new(0, 0, 0, 0),
            http_port: 3000,
        }
    }
}

/// DHCP service configuration
#[derive(Debug, Clone)]
pub struct DhcpServiceConfig {
    /// Operating mode
    pub mode: DhcpMode,
    /// Boot filename for BIOS systems
    pub boot_filename_bios: String,
    /// Boot filename for UEFI systems
    pub boot_filename_uefi: String,
    /// HTTP boot URL (for UEFI HTTP boot)
    pub http_boot_url: Option<String>,
    /// Pool range start (for Full/Reservation mode)
    pub pool_range_start: Option<Ipv4Addr>,
    /// Pool range end (for Full/Reservation mode)
    pub pool_range_end: Option<Ipv4Addr>,
    /// Subnet mask override
    pub subnet_mask: Option<Ipv4Addr>,
    /// Gateway override
    pub gateway: Option<Ipv4Addr>,
    /// DNS servers
    pub dns_servers: Vec<Ipv4Addr>,
}

impl Default for DhcpServiceConfig {
    fn default() -> Self {
        Self {
            mode: DhcpMode::Proxy,
            boot_filename_bios: "undionly.kpxe".to_string(),
            boot_filename_uefi: "ipxe.efi".to_string(),
            http_boot_url: None,
            pool_range_start: None,
            pool_range_end: None,
            subnet_mask: None,
            gateway: None,
            dns_servers: Vec::new(),
        }
    }
}

/// TFTP service configuration
#[derive(Debug, Clone)]
pub struct TftpServiceConfig {
    /// Directory containing boot files
    pub boot_dir: PathBuf,
}

impl Default for TftpServiceConfig {
    fn default() -> Self {
        Self {
            boot_dir: PathBuf::from("/var/lib/dragonfly/tftp"),
        }
    }
}

/// Network services runner
///
/// Manages the lifecycle of DHCP and TFTP servers.
pub struct ServiceRunner {
    config: ServicesConfig,
    store: Arc<dyn Store>,
    lease_table: Option<Arc<tokio::sync::RwLock<LeaseTable>>>,
}

impl ServiceRunner {
    /// Create a new service runner
    pub fn new(config: ServicesConfig, store: Arc<dyn Store>) -> Self {
        Self {
            config,
            store,
            lease_table: None,
        }
    }

    /// Create a service runner with a shared lease table
    pub fn with_lease_table(
        config: ServicesConfig,
        store: Arc<dyn Store>,
        lease_table: Arc<tokio::sync::RwLock<LeaseTable>>,
    ) -> Self {
        Self {
            config,
            store,
            lease_table: Some(lease_table),
        }
    }

    /// Start all configured services
    ///
    /// Returns handles for monitoring service events.
    pub async fn start(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> Result<ServiceHandles, ServiceError> {
        let mut handles = ServiceHandles::default();

        // Start DHCP if configured
        if let Some(ref dhcp_config) = self.config.dhcp {
            let dhcp_shutdown = shutdown.clone();
            let (dhcp_server, dhcp_handle) = self.start_dhcp(dhcp_config, dhcp_shutdown).await?;

            // Wire DHCP → DNS sync: lease events automatically create DNS records
            let dns_events = dhcp_server.subscribe();
            crate::dns_sync::spawn_dhcp_dns_sync(self.store.clone(), dns_events);

            handles.dhcp = Some(ServiceHandle {
                events: dhcp_server.subscribe(),
                join_handle: dhcp_handle,
            });
        }

        // Start TFTP if configured
        if let Some(ref tftp_config) = self.config.tftp {
            let tftp_shutdown = shutdown.clone();
            let (tftp_server, tftp_handle) = self.start_tftp(tftp_config, tftp_shutdown).await?;
            handles.tftp = Some(ServiceHandle {
                events: tftp_server.subscribe(),
                join_handle: tftp_handle,
            });
        }

        // Start DNS if any network has dns_provider: Internal
        self.start_dns().await;

        Ok(handles)
    }

    /// Start the DNS server if any network has internal DNS enabled.
    ///
    /// Queries the store for networks with dns_provider=Internal and a configured
    /// domain. Each such network becomes a DNS zone served by hickory-server.
    async fn start_dns(&self) {
        let networks = match self.store.list_networks().await {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "Failed to list networks for DNS startup");
                return;
            }
        };

        let internal_zones: Vec<ZoneConfig> = networks
            .iter()
            .filter(|n| n.dns_provider == DnsProvider::Internal)
            .filter_map(|n| {
                n.domain.as_ref().map(|domain| ZoneConfig {
                    origin: domain.clone(),
                })
            })
            .collect();

        if internal_zones.is_empty() {
            debug!("No networks with internal DNS provider — DNS server not starting");
            return;
        }

        // Collect upstream DNS servers from all networks
        let upstreams: Vec<SocketAddr> = networks
            .iter()
            .flat_map(|n| &n.dns_servers)
            .filter_map(|s| {
                s.parse::<Ipv4Addr>()
                    .ok()
                    .map(|ip| SocketAddr::new(ip.into(), 53))
            })
            .collect();

        // Server hostname for SOA/NS records
        let server_hostname = self
            .store
            .get_setting("server_hostname")
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "dragonfly.local".to_string());

        let zone_count = internal_zones.len();
        let zone_names: Vec<_> = internal_zones.iter().map(|z| z.origin.clone()).collect();

        // Bridge the Store to DnsStore
        let dns_store: Arc<dyn DnsStore> = Arc::new(StoreDnsLookup::new(self.store.clone()));

        let bind_addr: SocketAddr = "0.0.0.0:53".parse().unwrap();

        tokio::spawn(async move {
            info!(
                zones = ?zone_names,
                count = zone_count,
                "Starting DNS server"
            );
            if let Err(e) = DnsServer::start(
                bind_addr,
                internal_zones,
                dns_store,
                upstreams,
                server_hostname,
            )
            .await
            {
                error!(error = %e, "DNS server error");
            }
        });
    }

    /// Start DHCP server
    async fn start_dhcp(
        &self,
        config: &DhcpServiceConfig,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(Arc<DhcpServer>, tokio::task::JoinHandle<()>), ServiceError> {
        // Use auto-detected IP if server_ip is 0.0.0.0 (bind all)
        let actual_ip = if self.config.server_ip == Ipv4Addr::new(0, 0, 0, 0) {
            crate::mode::detect_server_ip()
                .and_then(|ip| ip.parse().ok())
                .unwrap_or(self.config.server_ip)
        } else {
            self.config.server_ip
        };

        info!(bind_ip = %self.config.server_ip, actual_ip = %actual_ip, "DHCP using detected server IP");

        let mut dhcp_config = DhcpConfig::new(actual_ip)
            .with_mode(config.mode.clone())
            .with_tftp_server(actual_ip)
            .with_http_port(self.config.http_port);

        // Apply optional Full mode configuration
        if let (Some(start), Some(end)) = (config.pool_range_start, config.pool_range_end) {
            dhcp_config = dhcp_config.with_pool_range(start, end);
        }
        if let Some(mask) = config.subnet_mask {
            dhcp_config = dhcp_config.with_subnet_mask(mask);
        }
        if let Some(gw) = config.gateway {
            dhcp_config = dhcp_config.with_gateway(gw);
        }
        for dns in &config.dns_servers {
            dhcp_config = dhcp_config.with_dns_server(*dns);
        }

        // Create machine lookup wrapper
        let lookup = StoreMachineLookup::new(self.store.clone());

        let server = Arc::new(if let Some(ref lt) = self.lease_table {
            DhcpServer::with_lease_table(dhcp_config, Arc::new(lookup), lt.clone())
        } else {
            DhcpServer::new(dhcp_config, Arc::new(lookup))
        });
        let server_clone = server.clone();

        info!(
            ip = %actual_ip,
            mode = ?config.mode,
            "Starting DHCP server"
        );

        let handle = tokio::spawn(async move {
            if let Err(e) = server_clone.run(shutdown).await {
                error!(error = %e, "DHCP server error");
            }
        });

        Ok((server, handle))
    }

    /// Start TFTP server
    async fn start_tftp(
        &self,
        config: &TftpServiceConfig,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(Arc<TftpServer>, tokio::task::JoinHandle<()>), ServiceError> {
        // Create file provider
        let provider = DirectoryFileProvider::new(config.boot_dir.clone());

        let server = Arc::new(TftpServer::new(self.config.server_ip, Arc::new(provider)));
        let server_clone = server.clone();

        info!(
            ip = %self.config.server_ip,
            dir = %config.boot_dir.display(),
            "Starting TFTP server"
        );

        let handle = tokio::spawn(async move {
            if let Err(e) = server_clone.run(shutdown).await {
                error!(error = %e, "TFTP server error");
            }
        });

        Ok((server, handle))
    }
}

/// Handles to running services
#[derive(Default)]
pub struct ServiceHandles {
    pub dhcp: Option<ServiceHandle<DhcpEvent>>,
    pub tftp: Option<ServiceHandle<TftpEvent>>,
}

/// Handle to a single service
pub struct ServiceHandle<E> {
    pub events: tokio::sync::broadcast::Receiver<E>,
    pub join_handle: tokio::task::JoinHandle<()>,
}

/// Machine lookup implementation using v1 Store
struct StoreMachineLookup {
    store: Arc<dyn Store>,
}

impl StoreMachineLookup {
    fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl MachineLookup for StoreMachineLookup {
    async fn get_machine_by_mac(&self, mac: &str) -> Option<Machine> {
        match self.store.get_machine_by_mac(mac).await {
            Ok(m) => m,
            Err(e) => {
                warn!(mac = %mac, error = %e, "Failed to lookup machine");
                None
            }
        }
    }

    async fn get_network_reservation(&self, mac: &str) -> Option<NetworkReservation> {
        let normalized = dragonfly_common::normalize_mac(mac);
        let networks = match self.store.list_networks().await {
            Ok(n) => n,
            Err(e) => {
                warn!(mac = %mac, error = %e, "Failed to list networks for reservation lookup");
                return None;
            }
        };

        for network in &networks {
            for res in &network.reservations {
                if dragonfly_common::normalize_mac(&res.mac) == normalized {
                    let ip = match res.ip.parse::<std::net::Ipv4Addr>() {
                        Ok(ip) => ip,
                        Err(_) => continue,
                    };
                    let gateway = network
                        .gateway
                        .as_ref()
                        .and_then(|gw| gw.parse::<std::net::Ipv4Addr>().ok());
                    return Some(NetworkReservation {
                        ip,
                        gateway,
                        hostname: res.hostname.clone(),
                    });
                }
            }
        }
        None
    }
}

/// Bridge from the dragonfly-server Store trait to dragonfly-dns DnsStore trait.
///
/// Keeps dragonfly-dns loosely coupled — it only knows about DnsStore,
/// never about the full Store type.
struct StoreDnsLookup {
    store: Arc<dyn Store>,
}

impl StoreDnsLookup {
    fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DnsStore for StoreDnsLookup {
    async fn list_dns_records(&self, zone: &str) -> anyhow::Result<Vec<DnsRecord>> {
        self.store
            .list_dns_records(zone)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    async fn get_dns_records(
        &self,
        zone: &str,
        name: &str,
        rtype: Option<DnsRecordType>,
    ) -> anyhow::Result<Vec<DnsRecord>> {
        self.store
            .get_dns_records(zone, name, rtype)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    }
}

/// File provider that serves files from a directory
struct DirectoryFileProvider {
    root: PathBuf,
}

impl DirectoryFileProvider {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

#[async_trait]
impl FileProvider for DirectoryFileProvider {
    async fn get_file(&self, path: &str) -> Option<Bytes> {
        // Security: prevent path traversal
        let path = path.trim_start_matches('/');
        if path.contains("..") {
            warn!(path = %path, "Blocked path traversal attempt");
            return None;
        }

        let full_path = self.root.join(path);
        debug!(path = %full_path.display(), "TFTP file request");

        match tokio::fs::read(&full_path).await {
            Ok(contents) => Some(Bytes::from(contents)),
            Err(e) => {
                debug!(path = %full_path.display(), error = %e, "File not found");
                None
            }
        }
    }

    async fn get_file_size(&self, path: &str) -> Option<u64> {
        let path = path.trim_start_matches('/');
        if path.contains("..") {
            return None;
        }

        let full_path = self.root.join(path);
        match tokio::fs::metadata(&full_path).await {
            Ok(meta) => Some(meta.len()),
            Err(_) => None,
        }
    }
}

/// In-memory file provider for testing or embedded files
pub struct MemoryFileProvider {
    files: HashMap<String, Bytes>,
}

impl MemoryFileProvider {
    /// Create empty provider
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    /// Add a file
    pub fn add_file(&mut self, path: impl Into<String>, contents: impl Into<Bytes>) {
        self.files.insert(path.into(), contents.into());
    }
}

impl Default for MemoryFileProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FileProvider for MemoryFileProvider {
    async fn get_file(&self, path: &str) -> Option<Bytes> {
        let path = path.trim_start_matches('/');
        self.files.get(path).cloned()
    }

    async fn get_file_size(&self, path: &str) -> Option<u64> {
        let path = path.trim_start_matches('/');
        self.files.get(path).map(|b| b.len() as u64)
    }
}

/// Service runner errors
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("DHCP error: {0}")]
    Dhcp(String),

    #[error("TFTP error: {0}")]
    Tftp(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::v1::MemoryStore;
    use dragonfly_common::MachineIdentity;

    #[tokio::test]
    async fn test_memory_file_provider() {
        let mut provider = MemoryFileProvider::new();
        provider.add_file("ipxe.efi", vec![0u8; 1024]);
        provider.add_file("undionly.kpxe", vec![1u8; 512]);

        assert_eq!(provider.get_file_size("ipxe.efi").await, Some(1024));
        assert_eq!(provider.get_file_size("undionly.kpxe").await, Some(512));
        assert_eq!(provider.get_file_size("nonexistent").await, None);

        let contents = provider.get_file("ipxe.efi").await.unwrap();
        assert_eq!(contents.len(), 1024);
    }

    #[tokio::test]
    async fn test_memory_file_provider_path_normalization() {
        let mut provider = MemoryFileProvider::new();
        provider.add_file("boot/ipxe.efi", vec![0u8; 100]);

        // Should work with leading slash
        assert!(provider.get_file("/boot/ipxe.efi").await.is_some());
        // Should work without leading slash
        assert!(provider.get_file("boot/ipxe.efi").await.is_some());
    }

    #[tokio::test]
    async fn test_directory_file_provider_path_traversal() {
        let provider = DirectoryFileProvider::new(PathBuf::from("/tmp"));

        // Should block path traversal
        assert!(provider.get_file("../etc/passwd").await.is_none());
        assert!(provider.get_file("foo/../../../etc/passwd").await.is_none());
    }

    #[tokio::test]
    async fn test_store_machine_lookup() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Add machine
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let machine = Machine::new(identity);
        store.put_machine(&machine).await.unwrap();

        let lookup = StoreMachineLookup::new(store);

        // Should find by MAC
        let found = lookup.get_machine_by_mac("00:11:22:33:44:55").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().primary_mac(), "00:11:22:33:44:55");

        // Should not find unknown MAC
        let not_found = lookup.get_machine_by_mac("ff:ff:ff:ff:ff:ff").await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_services_config_default() {
        let config = ServicesConfig::default();

        assert!(config.dhcp.is_none());
        assert!(config.tftp.is_none());
        assert_eq!(config.server_ip, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[tokio::test]
    async fn test_dhcp_config_default() {
        let config = DhcpServiceConfig::default();

        assert!(matches!(config.mode, DhcpMode::Proxy));
        assert_eq!(config.boot_filename_uefi, "ipxe.efi");
        assert_eq!(config.boot_filename_bios, "undionly.kpxe");
    }
}
