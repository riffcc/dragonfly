//! Dragonfly DNS — integrated authoritative + recursive DNS server.
//!
//! Uses hickory-server for the full DNS protocol stack (UDP, TCP, EDNS,
//! truncation handling) backed by the Dragonfly Store for zone data.
//! Unknown zones are forwarded to upstream resolvers.

pub mod handler;
pub mod provider;
pub mod server;

pub use handler::{DnsStore, StoreAuthority, ZoneConfig};
pub use provider::{DnsProviderBackend, ExternalProvider, InternalProvider};
pub use server::DnsServer;
