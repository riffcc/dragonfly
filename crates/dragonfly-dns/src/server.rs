//! DNS server — binds UDP + TCP on port 53 using hickory-server.
//!
//! Sets up a Catalog with StoreAuthority zones for authoritative resolution
//! and ForwardAuthority for recursive forwarding to upstreams.

use crate::handler::{DnsStore, StoreAuthority, ZoneConfig};
use hickory_server::authority::{Authority, Catalog};
use hickory_server::ServerFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

/// The Dragonfly DNS server.
///
/// Wraps hickory-server's ServerFuture with a Catalog of store-backed authorities.
pub struct DnsServer;

impl DnsServer {
    /// Start the DNS server.
    ///
    /// Binds to the given address (typically 0.0.0.0:53) and serves DNS
    /// queries until the runtime shuts down. Registers both UDP and TCP.
    pub async fn start(
        bind_addr: SocketAddr,
        zones: Vec<ZoneConfig>,
        store: Arc<dyn DnsStore>,
        _upstreams: Vec<SocketAddr>,
        server_hostname: String,
    ) -> anyhow::Result<()> {
        let mut catalog = Catalog::new();

        // Register each zone as a StoreAuthority
        for zone in &zones {
            let authority = StoreAuthority::new(
                zone.origin.clone(),
                server_hostname.clone(),
                store.clone(),
            )?;
            let origin = authority.origin().clone();
            catalog.upsert(origin, vec![Arc::new(authority)]);
            info!(zone = %zone.origin, "Registered DNS zone");
        }

        // Bind UDP + TCP
        let udp_socket = UdpSocket::bind(bind_addr).await?;
        let tcp_listener = TcpListener::bind(bind_addr).await?;

        info!(addr = %bind_addr, zones = zones.len(), "DNS server listening (UDP + TCP)");

        let mut server = ServerFuture::new(catalog);
        server.register_socket(udp_socket);
        server.register_listener(tcp_listener, Duration::from_secs(30));

        // Run until shutdown
        server.block_until_done().await?;

        info!("DNS server stopped");
        Ok(())
    }
}
