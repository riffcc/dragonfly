//! Store-backed DNS authority — resolves queries from the Dragonfly store.
//!
//! Implements hickory-server's Authority trait backed by the Dragonfly store.
//! Every DNS query hits the store directly (no caching layer) ensuring records
//! are always fresh. The store is local SQLite so latency is sub-millisecond.

use async_trait::async_trait;
use dragonfly_common::dns::{DnsRecord, DnsRecordType};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, PTR, SOA, TXT};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordSet, RecordType};
use hickory_server::authority::{
    AuthLookup, Authority, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
    UpdateResult, ZoneType,
};
use hickory_server::server::{Request, RequestInfo};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, warn};

/// Trait abstracting DNS record storage, matching the Store trait's DNS methods.
///
/// This allows the DNS server to query records without depending on the full
/// Store type (keeping dragonfly-dns loosely coupled from dragonfly-server).
#[async_trait]
pub trait DnsStore: Send + Sync {
    async fn list_dns_records(&self, zone: &str) -> anyhow::Result<Vec<DnsRecord>>;
    async fn get_dns_records(
        &self,
        zone: &str,
        name: &str,
        rtype: Option<DnsRecordType>,
    ) -> anyhow::Result<Vec<DnsRecord>>;
}

/// Configuration for a DNS zone.
#[derive(Debug, Clone)]
pub struct ZoneConfig {
    /// Zone origin (e.g. "lon.riff.cc")
    pub origin: String,
}

/// A hickory-server Authority backed by the Dragonfly Store.
///
/// Queries the store on every lookup — no caching, always fresh data.
/// SOA and NS records are auto-generated from zone configuration.
pub struct StoreAuthority {
    /// Zone origin as a LowerName (for hickory Authority trait)
    lower_origin: LowerName,
    /// Zone origin as a Name (for building records)
    name_origin: Name,
    /// Zone origin as a plain string (no trailing dot)
    zone_origin: String,
    /// Our server's hostname for NS/SOA records
    server_hostname: String,
    /// The backing store
    store: Arc<dyn DnsStore>,
}

impl StoreAuthority {
    pub fn new(
        zone_origin: String,
        server_hostname: String,
        store: Arc<dyn DnsStore>,
    ) -> anyhow::Result<Self> {
        let name_origin = Name::from_str(&format!("{}.", zone_origin))?;
        let lower_origin = LowerName::from(&name_origin);
        Ok(Self {
            lower_origin,
            name_origin,
            zone_origin,
            server_hostname,
            store,
        })
    }

    /// Get the origin as a Name (for building records).
    pub fn origin_name(&self) -> &Name {
        &self.name_origin
    }

    /// Get the relative name within the zone (e.g. "web-01" from "web-01.lon.riff.cc.")
    fn relative_name(&self, qname: &LowerName) -> String {
        let qname_str = qname.to_string();
        let qname_clean = qname_str.trim_end_matches('.').to_lowercase();
        let origin_clean = self.zone_origin.to_lowercase();

        if qname_clean == origin_clean {
            "@".to_string()
        } else if let Some(prefix) = qname_clean.strip_suffix(&format!(".{}", origin_clean)) {
            prefix.to_string()
        } else {
            qname_clean
        }
    }

    /// Map hickory RecordType to our DnsRecordType.
    fn map_record_type(rtype: RecordType) -> Option<DnsRecordType> {
        match rtype {
            RecordType::A => Some(DnsRecordType::A),
            RecordType::AAAA => Some(DnsRecordType::AAAA),
            RecordType::PTR => Some(DnsRecordType::PTR),
            RecordType::CNAME => Some(DnsRecordType::CNAME),
            RecordType::NS => Some(DnsRecordType::NS),
            RecordType::SOA => Some(DnsRecordType::SOA),
            RecordType::TXT => Some(DnsRecordType::TXT),
            RecordType::ANY => None,
            _ => None,
        }
    }

    /// Convert a DnsRecord from our store to a hickory Record.
    fn to_hickory_record(&self, record: &DnsRecord) -> Option<Record> {
        let fqdn = if record.name == "@" {
            format!("{}.", self.zone_origin)
        } else {
            format!("{}.{}.", record.name, self.zone_origin)
        };
        let name = Name::from_str(&fqdn).ok()?;

        let rdata = match record.rtype {
            DnsRecordType::A => {
                let ip: Ipv4Addr = record.rdata.parse().ok()?;
                RData::A(A(ip))
            }
            DnsRecordType::AAAA => {
                let ip: Ipv6Addr = record.rdata.parse().ok()?;
                RData::AAAA(AAAA(ip))
            }
            DnsRecordType::CNAME => {
                let target = Name::from_str(&ensure_trailing_dot(&record.rdata)).ok()?;
                RData::CNAME(CNAME(target))
            }
            DnsRecordType::PTR => {
                let target = Name::from_str(&ensure_trailing_dot(&record.rdata)).ok()?;
                RData::PTR(PTR(target))
            }
            DnsRecordType::NS => {
                let target = Name::from_str(&ensure_trailing_dot(&record.rdata)).ok()?;
                RData::NS(NS(target))
            }
            DnsRecordType::TXT => RData::TXT(TXT::new(vec![record.rdata.clone()])),
            DnsRecordType::SOA | DnsRecordType::SRV => return None,
        };

        Some(Record::from_rdata(name, record.ttl, rdata))
    }

    /// Build a synthetic SOA record for this zone.
    fn build_soa_record(&self) -> Record {
        let mname = Name::from_str(&format!("{}.", self.server_hostname))
            .unwrap_or_else(|_| Name::from_str("ns1.dragonfly.local.").unwrap());
        let rname = Name::from_str("hostmaster.dragonfly.local.").unwrap();
        let serial = chrono::Utc::now().timestamp() as u32;

        let soa = SOA::new(
            mname,
            rname,
            serial,
            86400,   // refresh
            7200,    // retry
            3600000, // expire
            300,     // minimum TTL
        );

        Record::from_rdata(self.name_origin.clone(), 3600, RData::SOA(soa))
    }

    /// Build a synthetic NS record for this zone.
    fn build_ns_record(&self) -> Record {
        let ns_name = Name::from_str(&format!("{}.", self.server_hostname))
            .unwrap_or_else(|_| Name::from_str("ns1.dragonfly.local.").unwrap());
        Record::from_rdata(self.name_origin.clone(), 3600, RData::NS(NS(ns_name)))
    }

    /// Build LookupRecords from a RecordSet.
    fn make_lookup(rs: RecordSet) -> LookupRecords {
        LookupRecords::new(LookupOptions::default(), Arc::new(rs))
    }

    /// Query the store and build a LookupControlFlow from the results.
    async fn store_lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
    ) -> LookupControlFlow<AuthLookup> {
        let relative = self.relative_name(name);
        let our_rtype = Self::map_record_type(rtype);

        debug!(
            zone = %self.zone_origin,
            name = %relative,
            rtype = %rtype,
            "Store lookup"
        );

        // SOA queries → return synthetic SOA
        if rtype == RecordType::SOA {
            let soa = self.build_soa_record();
            let mut rs = RecordSet::new(self.name_origin.clone(), RecordType::SOA, 0);
            rs.insert(soa, 0);
            return LookupControlFlow::Break(Ok(AuthLookup::answers(
                Self::make_lookup(rs),
                None,
            )));
        }

        // NS queries for zone apex
        if rtype == RecordType::NS && (relative == "@" || relative.is_empty()) {
            let ns = self.build_ns_record();
            let mut rs = RecordSet::new(self.name_origin.clone(), RecordType::NS, 0);
            rs.insert(ns, 0);
            return LookupControlFlow::Break(Ok(AuthLookup::answers(
                Self::make_lookup(rs),
                None,
            )));
        }

        // Query the store
        let records = match self
            .store
            .get_dns_records(&self.zone_origin, &relative, our_rtype)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Store query failed");
                return LookupControlFlow::Break(Err(LookupError::from(
                    hickory_proto::op::ResponseCode::ServFail,
                )));
            }
        };

        if records.is_empty() {
            return LookupControlFlow::Break(Ok(AuthLookup::Empty));
        }

        // Convert to hickory records and build a RecordSet
        let record_name: Name = name.into();
        let mut rs = RecordSet::new(record_name, rtype, 0);
        for record in &records {
            if let Some(rr) = self.to_hickory_record(record) {
                rs.insert(rr, 0);
            }
        }

        if rs.is_empty() {
            LookupControlFlow::Break(Ok(AuthLookup::Empty))
        } else {
            LookupControlFlow::Break(Ok(AuthLookup::answers(Self::make_lookup(rs), None)))
        }
    }
}

#[async_trait]
impl Authority for StoreAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &Request) -> UpdateResult<bool> {
        Ok(false)
    }

    fn origin(&self) -> &LowerName {
        &self.lower_origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.store_lookup(name, rtype).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let name = request_info.query.name();
        let rtype = request_info.query.query_type();
        self.lookup(name, rtype, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Break(Ok(AuthLookup::Empty))
    }
}

/// Ensure a domain name has a trailing dot.
fn ensure_trailing_dot(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relative_name() {
        let authority = StoreAuthority::new(
            "lon.riff.cc".to_string(),
            "dragonfly.local".to_string(),
            Arc::new(MockStore),
        )
        .unwrap();

        let name = Name::from_str("web-01.lon.riff.cc.").unwrap();
        assert_eq!(authority.relative_name(&LowerName::from(&name)), "web-01");

        let name = Name::from_str("lon.riff.cc.").unwrap();
        assert_eq!(authority.relative_name(&LowerName::from(&name)), "@");

        let name = Name::from_str("deep.sub.lon.riff.cc.").unwrap();
        assert_eq!(
            authority.relative_name(&LowerName::from(&name)),
            "deep.sub"
        );
    }

    #[test]
    fn test_ensure_trailing_dot() {
        assert_eq!(ensure_trailing_dot("example.com"), "example.com.");
        assert_eq!(ensure_trailing_dot("example.com."), "example.com.");
    }

    struct MockStore;

    #[async_trait]
    impl DnsStore for MockStore {
        async fn list_dns_records(&self, _zone: &str) -> anyhow::Result<Vec<DnsRecord>> {
            Ok(vec![])
        }
        async fn get_dns_records(
            &self,
            _zone: &str,
            _name: &str,
            _rtype: Option<DnsRecordType>,
        ) -> anyhow::Result<Vec<DnsRecord>> {
            Ok(vec![])
        }
    }
}
