//! ASN-keyed IP-range index built once from a GeoLite2-ASN MMDB.
//!
//! `IP-ASN` / `SRC-IP-ASN` matching uses the retained range tries directly,
//! so rule matching does not perform MMDB decoding or heap allocation.

use ipnet::{Ipv4Net, Ipv6Net};
use maxminddb::PathElement;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use crate::ip_set::{IpRangeSet, IpRangeSetBuilder};

/// Per-ASN IPv4 + IPv6 range set, shared by every rule naming the ASN.
pub type AsnRanges = Arc<IpRangeSet>;

#[derive(Default)]
pub struct AsnIndex {
    by_asn: HashMap<u32, AsnRanges>,
}

impl AsnIndex {
    pub fn build<S: AsRef<[u8]>>(
        reader: &maxminddb::Reader<S>,
        allowed: &HashSet<u32>,
    ) -> Result<Self, String> {
        if allowed.is_empty() {
            return Ok(Self::default());
        }

        let allowed_asns: Vec<u32> = allowed.iter().copied().collect();
        if allowed_asns.len() > u16::MAX as usize {
            return Err(format!(
                "ASN allowlist has {} entries, exceeds {}",
                allowed_asns.len(),
                u16::MAX
            ));
        }
        let mut buckets: Vec<IpRangeSetBuilder> = (0..allowed_asns.len())
            .map(|_| IpRangeSetBuilder::new())
            .collect();

        let iter = reader
            .networks(Default::default())
            .map_err(|e| format!("failed to iterate ASN networks: {e}"))?;
        let path = [PathElement::Key("autonomous_system_number")];
        let mut offset_cache: HashMap<usize, Option<u16>> = HashMap::new();

        for result in iter {
            let Ok(lookup) = result else {
                continue;
            };
            let Some(offset) = lookup.offset() else {
                continue;
            };

            let bucket_idx = match offset_cache.get(&offset) {
                Some(&cached) => cached,
                None => {
                    let resolved = match lookup.decode_path::<u32>(&path) {
                        Ok(Some(asn)) => allowed_asns
                            .iter()
                            .position(|candidate| *candidate == asn)
                            .map(|idx| idx as u16),
                        _ => None,
                    };
                    offset_cache.insert(offset, resolved);
                    resolved
                }
            };
            let Some(bucket_idx) = bucket_idx else {
                continue;
            };

            let Ok(net) = lookup.network() else {
                continue;
            };
            let prefix = net.prefix();
            let bucket = &mut buckets[bucket_idx as usize];
            match net.network() {
                IpAddr::V4(v4) => {
                    if let Ok(net4) = Ipv4Net::new(v4, prefix) {
                        bucket.add_v4(net4);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(net6) = Ipv6Net::new(v6, prefix) {
                        bucket.add_v6(net6);
                    }
                }
            }
        }

        let mut by_asn = HashMap::with_capacity(allowed_asns.len());
        for (asn, bucket) in allowed_asns.into_iter().zip(buckets) {
            if bucket.is_empty() {
                continue;
            }
            by_asn.insert(asn, Arc::new(bucket.build()));
        }

        Ok(Self { by_asn })
    }

    pub fn ranges_for(&self, asn: u32) -> AsnRanges {
        self.by_asn
            .get(&asn)
            .map_or_else(|| Arc::new(IpRangeSet::default()), Arc::clone)
    }

    pub fn asn_count(&self) -> usize {
        self.by_asn.len()
    }
}

impl std::fmt::Debug for AsnIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsnIndex")
            .field("asns", &self.by_asn.len())
            .finish()
    }
}
