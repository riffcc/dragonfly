//! DNS provider backends — abstraction over internal/external DNS management.
//!
//! Each network can use a different DNS provider:
//! - Internal: Records served by Dragonfly's built-in hickory DNS server
//! - External: Records tracked in store for awareness but not served
//! - Gravity: Future API integration with Pi-hole/Gravity

use async_trait::async_trait;
use dragonfly_common::dns::{DnsRecord, DnsRecordType};

/// Backend for DNS record management.
///
/// Different providers handle record lifecycle differently:
/// - InternalProvider writes to the store (records served by hickory)
/// - ExternalProvider is a no-op (records exist in store for tracking only)
#[async_trait]
pub trait DnsProviderBackend: Send + Sync {
    /// Create or update a DNS record.
    async fn create_record(&self, record: &DnsRecord) -> anyhow::Result<()>;

    /// Delete a DNS record by zone, name, and type.
    async fn delete_record(
        &self,
        zone: &str,
        name: &str,
        rtype: DnsRecordType,
    ) -> anyhow::Result<()>;
}

/// Internal DNS provider — records stored in Dragonfly's store and served by hickory.
///
/// This is the default provider. Writing a record to the store makes it
/// immediately resolvable via the DNS server (no cache, direct store queries).
pub struct InternalProvider;

#[async_trait]
impl DnsProviderBackend for InternalProvider {
    async fn create_record(&self, _record: &DnsRecord) -> anyhow::Result<()> {
        // Records are written directly to the store by the caller.
        // The StoreAuthority queries the store on every lookup, so records
        // are immediately available without any provider-side action.
        Ok(())
    }

    async fn delete_record(
        &self,
        _zone: &str,
        _name: &str,
        _rtype: DnsRecordType,
    ) -> anyhow::Result<()> {
        // Records are deleted from the store by the caller.
        // Same reasoning as create — the StoreAuthority always reads fresh.
        Ok(())
    }
}

/// External DNS provider — records tracked but not served by Dragonfly.
///
/// Used for networks where DNS is managed externally (e.g. by a cloud provider
/// or existing infrastructure). Records are stored for awareness/audit but
/// Dragonfly doesn't serve them.
pub struct ExternalProvider;

#[async_trait]
impl DnsProviderBackend for ExternalProvider {
    async fn create_record(&self, _record: &DnsRecord) -> anyhow::Result<()> {
        // No-op: external DNS is managed outside Dragonfly
        Ok(())
    }

    async fn delete_record(
        &self,
        _zone: &str,
        _name: &str,
        _rtype: DnsRecordType,
    ) -> anyhow::Result<()> {
        // No-op: external DNS is managed outside Dragonfly
        Ok(())
    }
}
