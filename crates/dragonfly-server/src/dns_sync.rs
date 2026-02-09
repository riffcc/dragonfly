//! DNS synchronisation for all machine lifecycle events.
//!
//! Provides `sync_machine_dns` — the universal DNS hook that any subsystem can
//! call when a machine gets an IP. Also subscribes to DHCP lease events and
//! automatically creates forward (A) and reverse (PTR) DNS records.
//!
//! Records are idempotent — repeated calls just update the existing record.

use crate::store::v1::Store;
use dragonfly_common::dns::{
    DnsProvider, DnsRecordSource, DnsRecordType, reverse_name_v4, reverse_zone_from_subnet,
};
use dragonfly_common::machine::Machine;
use dragonfly_dhcp::DhcpEvent;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Given a machine with an IP and hostname, write DNS records to the appropriate zone.
///
/// Safe to call from anywhere: DHCP, Proxmox discovery, sync, provisioning, cluster deploy.
/// Idempotent — repeated calls for the same machine just update existing records.
///
/// Returns `Ok(())` silently when:
/// - Machine has no IP or IP is "Unknown"
/// - No network matches the IP
/// - Network doesn't use internal DNS
/// - Network has no domain configured
pub async fn sync_machine_dns(
    store: &Arc<dyn Store>,
    machine: &Machine,
    source: DnsRecordSource,
) -> anyhow::Result<()> {
    // Get current IP — bail if missing or placeholder
    let ip_str = match &machine.status.current_ip {
        Some(ip) if ip != "Unknown" && !ip.is_empty() => ip.clone(),
        _ => {
            debug!(machine_id = %machine.id, "Machine has no IP — skipping DNS sync");
            return Ok(());
        }
    };

    let ip: Ipv4Addr = ip_str.parse().map_err(|e| {
        anyhow::anyhow!("Invalid IP '{}' for machine {}: {}", ip_str, machine.id, e)
    })?;

    // Determine hostname: user-set > reported > memorable_name > MAC-derived
    let hostname = machine
        .config
        .hostname
        .as_deref()
        .or(machine.config.reported_hostname.as_deref())
        .unwrap_or(&machine.config.memorable_name);

    write_dns_records(
        store,
        ip,
        hostname,
        &machine.identity.primary_mac,
        Some(machine.id),
        source,
    )
    .await
}

/// Core DNS record writer shared by all sync paths.
///
/// Finds the network containing `ip`, checks for internal DNS + domain,
/// and writes forward A + reverse PTR records.
async fn write_dns_records(
    store: &Arc<dyn Store>,
    ip: Ipv4Addr,
    hostname: &str,
    mac: &str,
    machine_id: Option<Uuid>,
    source: DnsRecordSource,
) -> anyhow::Result<()> {
    let networks = store
        .list_networks()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let network = match networks.iter().find(|n| ip_in_subnet(ip, &n.subnet)) {
        Some(n) => n,
        None => {
            debug!(ip = %ip, "No network found for IP — skipping DNS sync");
            return Ok(());
        }
    };

    if network.dns_provider != DnsProvider::Internal {
        debug!(
            ip = %ip,
            network = %network.name,
            provider = %network.dns_provider,
            "Network DNS provider is not internal — skipping"
        );
        return Ok(());
    }

    let zone = match &network.domain {
        Some(d) => d.clone(),
        None => {
            debug!(
                ip = %ip,
                network = %network.name,
                "Network has no domain configured — skipping DNS sync"
            );
            return Ok(());
        }
    };

    // Determine final name: prefer explicit hostname, fall back to reservation, then MAC
    let name = if !hostname.is_empty() {
        hostname.to_string()
    } else {
        let from_reservation = network
            .reservations
            .iter()
            .find(|r| r.mac.eq_ignore_ascii_case(mac))
            .and_then(|r| r.hostname.clone());

        from_reservation.unwrap_or_else(|| mac.replace(':', "-"))
    };

    let ip_str = ip.to_string();

    // Write forward A record
    store
        .upsert_dns_record(
            &zone,
            &name,
            DnsRecordType::A,
            &ip_str,
            3600,
            source.clone(),
            machine_id,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    info!(
        name = %name,
        zone = %zone,
        ip = %ip_str,
        source = %source,
        "DNS: A record synced"
    );

    // Write reverse PTR record
    let reverse_fqdn = reverse_name_v4(ip);
    let reverse_zone = reverse_zone_from_subnet(&network.subnet);

    if let Some(rev_zone) = reverse_zone {
        let ptr_name = ip.octets()[3].to_string();
        let ptr_target = format!("{}.{}.", name, zone);

        store
            .upsert_dns_record(
                &rev_zone,
                &ptr_name,
                DnsRecordType::PTR,
                &ptr_target,
                3600,
                source.clone(),
                machine_id,
            )
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        info!(
            ptr = %reverse_fqdn,
            target = %ptr_target,
            source = %source,
            "DNS: PTR record synced"
        );
    }

    Ok(())
}

/// Spawn a task that listens for DHCP lease events and writes DNS records.
///
/// This is the glue between the DHCP server and the DNS store. Every OFFER/ACK
/// with a valid IP triggers:
/// 1. Forward A record: `hostname.zone → IP`
/// 2. Reverse PTR record: `x.y.z.w.in-addr.arpa → hostname.zone.`
///
/// Records are only created for networks that have:
/// - `dns_provider == Internal`
/// - A configured `domain` (the DNS zone)
pub fn spawn_dhcp_dns_sync(store: Arc<dyn Store>, mut events: broadcast::Receiver<DhcpEvent>) {
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(DhcpEvent::Response {
                    mac,
                    message_type,
                    offered_ip: Some(ip),
                    machine_id,
                    hostname,
                }) => {
                    // Only act on OFFER and ACK (not NAK, not PROXY_OFFER)
                    if message_type != "OFFER" && message_type != "ACK" {
                        continue;
                    }

                    debug!(
                        mac = %mac,
                        ip = %ip,
                        hostname = ?hostname,
                        machine_id = ?machine_id,
                        "DHCP lease event — checking DNS sync"
                    );

                    // Determine hostname for the DHCP path
                    let host = hostname.as_deref().unwrap_or("");

                    if let Err(e) = write_dns_records(
                        &store,
                        ip,
                        host,
                        &mac,
                        machine_id,
                        DnsRecordSource::Dhcp,
                    )
                    .await
                    {
                        error!(
                            mac = %mac,
                            ip = %ip,
                            error = %e,
                            "Failed to sync DNS record from DHCP lease"
                        );
                    }
                }
                Ok(DhcpEvent::Stopped) => {
                    info!("DHCP server stopped — DNS sync shutting down");
                    break;
                }
                Ok(_) => {} // Ignore other events
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "DNS sync lagged behind DHCP events");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    debug!("DHCP event channel closed — DNS sync shutting down");
                    break;
                }
            }
        }
    });
}

/// Check if an IPv4 address falls within a CIDR subnet.
///
/// Supports `a.b.c.d/N` notation. Returns false on parse failure.
fn ip_in_subnet(ip: Ipv4Addr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network_ip: Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let prefix_len: u32 = match parts[1].parse() {
        Ok(p) if p <= 32 => p,
        _ => return false,
    };

    if prefix_len == 0 {
        return true;
    }

    let mask = !0u32 << (32 - prefix_len);
    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(network_ip);

    (ip_u32 & mask) == (net_u32 & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_subnet() {
        assert!(ip_in_subnet(
            "10.7.2.50".parse().unwrap(),
            "10.7.2.0/24"
        ));
        assert!(ip_in_subnet(
            "10.7.2.1".parse().unwrap(),
            "10.7.2.0/24"
        ));
        assert!(ip_in_subnet(
            "10.7.2.254".parse().unwrap(),
            "10.7.2.0/24"
        ));
        assert!(!ip_in_subnet(
            "10.7.3.1".parse().unwrap(),
            "10.7.2.0/24"
        ));
        assert!(!ip_in_subnet(
            "192.168.1.1".parse().unwrap(),
            "10.7.2.0/24"
        ));
    }

    #[test]
    fn test_ip_in_subnet_various_masks() {
        assert!(ip_in_subnet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.0/8"
        ));
        assert!(ip_in_subnet(
            "10.255.255.255".parse().unwrap(),
            "10.0.0.0/8"
        ));
        assert!(!ip_in_subnet(
            "11.0.0.1".parse().unwrap(),
            "10.0.0.0/8"
        ));

        assert!(ip_in_subnet(
            "192.168.1.100".parse().unwrap(),
            "192.168.0.0/16"
        ));
        assert!(!ip_in_subnet(
            "192.169.0.1".parse().unwrap(),
            "192.168.0.0/16"
        ));
    }

    #[test]
    fn test_ip_in_subnet_edge_cases() {
        // /32 — single host
        assert!(ip_in_subnet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.1/32"
        ));
        assert!(!ip_in_subnet(
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1/32"
        ));

        // /0 — everything matches
        assert!(ip_in_subnet(
            "1.2.3.4".parse().unwrap(),
            "0.0.0.0/0"
        ));

        // Bad CIDR
        assert!(!ip_in_subnet("10.0.0.1".parse().unwrap(), "garbage"));
        assert!(!ip_in_subnet("10.0.0.1".parse().unwrap(), "10.0.0.0"));
        assert!(!ip_in_subnet("10.0.0.1".parse().unwrap(), "10.0.0.0/33"));
    }
}
