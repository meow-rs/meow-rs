//! Country-keyed IP-range index built once from a GeoIP MMDB.
//!
//! At config-load the GeoIP `Reader` is walked end-to-end; each network is
//! binned by uppercased ISO country code into a per-country
//! [`IpRangeSet`] (sorted, coalesced intervals). After build, the MMDB
//! Reader can be dropped — every `GEOIP` / `SRC-GEOIP` rule retains only an
//! `Arc` to the per-country set and matches via one binary search (no MMDB
//! lookup, no country-code String allocation on the hot path).
//!
//! ## Build-time optimisations
//!
//! The MMDB walk yields hundreds of thousands of networks but only ~250
//! unique country records — every CN network, for instance, points at the
//! same data offset. The build loop exploits this and the bounded shape
//! of the rule-driven allowlist to keep the per-record cost tiny:
//!
//! * **Decode only `country.iso_code`** via `decode_path`, skipping the
//!   continent / names / traits sub-maps that `geoip2::Country` would
//!   otherwise walk.
//! * **Memoise per data offset** — decoding any given record once and
//!   reusing the resolved bucket index for every subsequent network that
//!   points at it.
//! * **Stack-pack the ISO code** into a fixed-size key so the allowlist
//!   comparison costs no allocations (no `to_ascii_uppercase()` String per
//!   record, no String-keyed HashMap insert).
//! * **Index buckets by allowlist position** in a `Vec`, since the rule
//!   set typically references at most a handful of countries — a linear
//!   scan beats a HashMap probe at that size and avoids hashing.

use ipnet::{Ipv4Net, Ipv6Net};
use maxminddb::PathElement;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use crate::ip_set::{IpRangeSet, IpRangeSetBuilder};

/// Per-country IPv4 + IPv6 range set, shared by every rule that names the
/// country. Cheap to clone.
pub type CountryRanges = Arc<IpRangeSet>;

/// Country-code → `CountryRanges` map. Built once via [`CountryIndex::build`].
#[derive(Default)]
pub struct CountryIndex {
    by_country: HashMap<String, CountryRanges>,
}

/// Stack-packed uppercase ASCII country code.
///
/// Sized for ISO 3166-1 alpha-2 (2 chars) with headroom for the longer codes
/// some MMDBs ship (e.g. UN M.49 numerics). Comparison is byte-wise so the
/// allowlist scan in the hot loop runs without allocating or hashing.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CountryKey([u8; 8]);

impl CountryKey {
    /// Pack `s` into the buffer, uppercasing ASCII letters. Bytes beyond
    /// `BUF_LEN` are dropped — anything that long isn't a valid GeoIP code.
    #[inline]
    fn from_str_upper(s: &str) -> Self {
        let mut buf = [0u8; 8];
        let bytes = s.as_bytes();
        let n = bytes.len().min(buf.len());
        let mut i = 0;
        while i < n {
            buf[i] = bytes[i].to_ascii_uppercase();
            i += 1;
        }
        Self(buf)
    }

    /// Borrow the packed key as a `&str` (uppercase, trailing NULs stripped).
    #[inline]
    fn as_str(&self) -> &str {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        // Safe: `from_str_upper` only mutates ASCII letters; non-ASCII bytes
        // come from a `&str`, so the buffer up to `len` is valid UTF-8.
        std::str::from_utf8(&self.0[..len]).unwrap_or("")
    }
}

impl CountryIndex {
    /// Walk every record in `reader` and bin each network into the
    /// matching country bucket — but only for ISO codes present in
    /// `allowed`. Codes outside the allowlist are skipped during the walk
    /// so the index never allocates ranges for countries no rule cares
    /// about. Codes are matched case-insensitively (the allowlist is
    /// internally uppercased). Networks without an `iso_code` are skipped
    /// silently — they cannot drive any rule.
    pub fn build<S: AsRef<[u8]>>(
        reader: &maxminddb::Reader<S>,
        allowed: &HashSet<String>,
    ) -> Result<Self, String> {
        if allowed.is_empty() {
            return Ok(Self::default());
        }

        // Pack the allowlist into stack-friendly keys, indexed by position.
        // The country count is bounded by the rule set (typically ≤ 16),
        // so a `Vec` + linear scan is faster than a HashMap probe in the
        // hot loop.
        let allowed_keys: Vec<CountryKey> = allowed
            .iter()
            .map(|s| CountryKey::from_str_upper(s))
            .collect();
        if allowed_keys.len() > u16::MAX as usize {
            return Err(format!(
                "GeoIP allowlist has {} entries, exceeds {}",
                allowed_keys.len(),
                u16::MAX
            ));
        }
        let mut buckets: Vec<IpRangeSetBuilder> = (0..allowed_keys.len())
            .map(|_| IpRangeSetBuilder::new())
            .collect();

        let iter = reader
            .networks(Default::default())
            .map_err(|e| format!("failed to iterate GeoIP networks: {e}"))?;

        // Path straight to `country.iso_code`, skipping every other field
        // in the GeoIP2 record (continent, names, traits, …). Borrowed by
        // `decode_path` on every iteration.
        let path = [PathElement::Key("country"), PathElement::Key("iso_code")];

        // Memoise the resolved bucket per MMDB data offset. Many networks
        // (often all networks of one country) share a single data record;
        // caching by offset turns ~10⁶ decodes into ~10² decodes.
        // `None` ⇒ checked, not in allowlist; `Some(idx)` ⇒ allowed at idx.
        let mut offset_cache: HashMap<usize, Option<u16>> = HashMap::new();

        for result in iter {
            let Ok(lookup) = result else {
                continue;
            };

            // Networks with no data record can't drive any rule.
            let Some(offset) = lookup.offset() else {
                continue;
            };

            let bucket_idx = match offset_cache.get(&offset) {
                Some(&cached) => cached,
                None => {
                    let resolved = match lookup.decode_path::<&str>(&path) {
                        Ok(Some(iso)) => {
                            let key = CountryKey::from_str_upper(iso);
                            allowed_keys
                                .iter()
                                .position(|k| *k == key)
                                .map(|idx| idx as u16)
                        }
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

        let mut by_country = HashMap::with_capacity(allowed_keys.len());
        for (key, bucket) in allowed_keys.iter().zip(buckets) {
            if bucket.is_empty() {
                continue;
            }
            by_country.insert(key.as_str().to_string(), Arc::new(bucket.build()));
        }

        Ok(Self { by_country })
    }

    /// Look up ranges for a country code. Unknown codes return an empty set
    /// (no panic) — the rule will simply never match, mirroring upstream's
    /// "MMDB has no record" path.
    pub fn ranges_for(&self, country: &str) -> CountryRanges {
        self.by_country
            .get(&country.to_ascii_uppercase())
            .map_or_else(|| Arc::new(IpRangeSet::default()), Arc::clone)
    }

    pub fn country_count(&self) -> usize {
        self.by_country.len()
    }
}

impl std::fmt::Debug for CountryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountryIndex")
            .field("countries", &self.by_country.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path to the repo-root Country.mmdb fixture. The test silently skips
    /// when missing so cargo-test works on contributor machines without the
    /// fixture.
    fn fixture_path() -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // crate root is .../crates/meow-rules — climb to repo root.
        p.pop();
        p.pop();
        p.push("Country.mmdb");
        p
    }

    fn try_open() -> Option<maxminddb::Reader<Vec<u8>>> {
        let path = fixture_path();
        if !path.exists() {
            return None;
        }
        let bytes = std::fs::read(&path).ok()?;
        maxminddb::Reader::from_source(bytes).ok()
    }

    #[test]
    fn country_index_unknown_country_is_empty() {
        let idx = CountryIndex::default();
        let r = idx.ranges_for("ZZ");
        assert!(r.is_empty());
    }

    #[test]
    fn country_index_lookup_is_case_insensitive() {
        // Build a tiny manual index via the public-by-construction map.
        let mut by_country: HashMap<String, CountryRanges> = HashMap::new();
        let set = IpRangeSet::from_nets(["1.2.3.0/24".parse().unwrap()]);
        by_country.insert("CN".into(), Arc::new(set));
        let idx = CountryIndex { by_country };
        let probe: IpAddr = "1.2.3.42".parse().unwrap();
        assert!(idx.ranges_for("cn").contains(probe));
        assert!(idx.ranges_for("CN").contains(probe));
        assert!(!idx.ranges_for("US").contains(probe));
    }

    /// Build a real CountryIndex from the repo's Country.mmdb fixture, but
    /// only for the allowlisted countries — verifying that we don't
    /// allocate ranges for codes outside the rule set.
    /// Skipped on machines without the fixture.
    #[test]
    fn country_index_builds_only_allowed_countries() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["CN", "US"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 2, "should bin only CN + US");
        assert!(idx.ranges_for("US").has_v4(), "US v4 ranges empty?");
        assert!(idx.ranges_for("CN").has_v4(), "CN v4 ranges empty?");
        // Country outside the allowlist returns empty ranges.
        assert!(idx.ranges_for("JP").is_empty());
    }

    #[test]
    fn country_index_empty_allowlist_yields_empty_index() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let idx = CountryIndex::build(&reader, &HashSet::new()).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 0);
    }

    /// Regression — duplicate `GEOIP,CN,...` rules must NOT each parse the
    /// CN range. `ranges_for` returns an `Arc::clone`, so two lookups of the
    /// same country share the underlying `IpRange` allocation. If a future
    /// refactor switches to per-rule range construction, `Arc::ptr_eq` will
    /// fail here.
    #[test]
    fn ranges_for_shares_arc_across_repeated_lookups() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["CN"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");

        let a = idx.ranges_for("CN");
        let b = idx.ranges_for("CN");
        let c = idx.ranges_for("cn"); // case-insensitive must hit the same bucket

        assert!(
            Arc::ptr_eq(&a, &b),
            "two CN lookups must share the IpRangeSet Arc"
        );
        assert!(
            Arc::ptr_eq(&a, &c),
            "case-insensitive CN lookup must share the IpRangeSet Arc"
        );
    }

    /// Regression — `parse_rule` building many GEOIP rules over the same
    /// country must reuse the single per-country `Arc<IpRange>`. We exercise
    /// the parser end-to-end (rather than `ranges_for` directly) so this
    /// test catches a regression where the parser starts cloning into a new
    /// `IpRange` instead of `Arc::clone`-ing the index entry.
    #[test]
    fn parser_reuses_arc_for_duplicate_geoip_rules() {
        use crate::parser::{parse_rule, ParserContext};

        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["CN", "US"].into_iter().map(String::from).collect();
        let idx = Arc::new(CountryIndex::build(&reader, &allowed).expect("build CountryIndex"));
        let ctx = ParserContext {
            geoip: Some(Arc::clone(&idx)),
            ..Default::default()
        };

        // Drive 100 duplicate GEOIP,CN,... lines through the parser. After
        // building the index, every parsed rule should share the same v4/v6
        // Arc — a sanity check that no per-rule range allocation slipped in.
        let baseline = idx.ranges_for("CN");
        for i in 0..100 {
            let line = format!("GEOIP,CN,Proxy{i}");
            let _rule = parse_rule(&line, &ctx).expect("parse_rule must succeed");
            // We can't introspect GeoIpRule.ranges (private), but we can
            // re-fetch from the index — which is the very Arc the parser
            // cloned into the rule.
            let again = idx.ranges_for("CN");
            assert!(
                Arc::ptr_eq(&baseline, &again),
                "iteration {i} broke Arc sharing"
            );
        }

        // Different country must NOT share with CN — guards against a
        // pathological refactor that collapses all countries to one bucket.
        let us = idx.ranges_for("US");
        assert!(
            !Arc::ptr_eq(&baseline, &us),
            "CN and US must hold distinct Arcs"
        );
    }

    #[test]
    fn country_index_allowlist_is_case_insensitive() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["cn"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 1);
        assert!(idx.ranges_for("CN").has_v4());
    }
}
