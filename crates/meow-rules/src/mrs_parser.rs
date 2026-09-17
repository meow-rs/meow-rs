//! Shared mrs (MetaCubeX rule-set / geodata) binary format parser.
//!
//! Shared between the geosite loader (this task, M1.D-2) and the forthcoming
//! rule-provider mrs parser (M1.D-5). Do NOT duplicate this logic — bug fixes
//! must land in one place.
//!
//! # Format (per `docs/specs/rule-provider-upgrade.md` §mrs binary format)
//!
//! ```text
//! Header:
//!   magic:   [u8; 4] = "MRS!"
//!   version: u8      = 1
//!   type:    u8      // 0=domain, 1=ipcidr, 2=classical (rule-provider only)
//!                    //         for geosite, type=0 (domain) and the payload is a
//!                    //         sequence of (category, domain-list) groups — see
//!                    //         `GeositePayload` below.
//!   count:   u32 (big-endian)
//!
//! Payload (zstd-compressed):
//!   behavior=domain:    count × (u16-be length prefix + UTF-8 domain bytes)
//!   behavior=ipcidr:    count × (u8 family (4=v4, 16=v6) + addr bytes + u8 prefix-len)
//!   behavior=classical: count × (u16-be length prefix + UTF-8 rule string)
//!
//! Geosite payload (inner format, after zstd decompression):
//!   category_count: u32 (big-endian)
//!   for each category:
//!     name_len:    u16 (big-endian)
//!     name_bytes:  [u8; name_len]  (UTF-8, lower-cased at write time by convention)
//!     domain_count: u32 (big-endian)
//!     for each domain:
//!       domain_len:   u16 (big-endian)
//!       domain_bytes: [u8; domain_len]  (UTF-8, lower-cased)
//! ```
//!
//! upstream authoritative reference:
//! - `rules/provider/rule_set_mrs.go::Decode` (rule-provider variant)
//! - `component/geodata/metaresource/metaresource.go::Read` (geosite variant)
//!
//! NOTE — upstream source was not available to the engineer at implementation
//! time. Byte-exact integration tests must regenerate fixtures using
//! MetaCubeX's `convert-geo` tool (or equivalent) once upstream access is
//! available. Unit tests here use a round-trip via `write_geosite()` to
//! confirm the parser reverses its own encoder.

use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MRS_MAGIC: [u8; 4] = *b"MRS!";
pub const MRS_VERSION: u8 = 1;
pub const UPSTREAM_MRS_MAGIC: [u8; 4] = *b"MRS\x01";
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

pub const TYPE_DOMAIN: u8 = 0;
pub const TYPE_IPCIDR: u8 = 1;
pub const TYPE_CLASSICAL: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum MrsError {
    #[error("mrs: wrong format (not an mrs file — first 4 bytes are not 'MRS!')")]
    WrongFormat,
    #[error("mrs: unsupported version {0} (expected 1)")]
    UnsupportedVersion(u8),
    #[error("mrs: unsupported type {0}")]
    UnsupportedType(u8),
    #[error("mrs: invalid behavior {0}")]
    InvalidBehavior(u8),
    #[error("mrs: invalid reserved length {0}")]
    InvalidReservedLength(i64),
    #[error("mrs: truncated {what} at offset {offset}: need {need} bytes, have {have}")]
    Truncated {
        what: &'static str,
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("mrs: zstd decompression failed: {0}")]
    Zstd(#[from] std::io::Error),
    #[error("mrs: invalid UTF-8 in {0}: {1}")]
    Utf8(&'static str, std::string::FromUtf8Error),
    #[error("mrs: invalid domain-set version {0}")]
    InvalidDomainSetVersion(u8),
    #[error("mrs: invalid ip-cidr-set version {0}")]
    InvalidIpCidrSetVersion(u8),
    #[error("mrs: invalid length for {0}: {1}")]
    InvalidLength(&'static str, i64),
}

/// Parsed mrs header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrsHeader {
    pub version: u8,
    pub type_tag: u8,
    pub count: u32,
}

/// Read the mrs header and return the slice of the (still-compressed)
/// payload that follows. Callers that need the decompressed payload should
/// call `decompress_payload()` on the returned slice.
pub fn parse_header(data: &[u8]) -> Result<(MrsHeader, &[u8]), MrsError> {
    if data.len() < 4 {
        return Err(MrsError::WrongFormat);
    }
    if data[..4] != MRS_MAGIC {
        return Err(MrsError::WrongFormat);
    }
    // magic(4) + version(1) + type(1) + count(4) = 10 bytes
    if data.len() < 10 {
        return Err(MrsError::Truncated {
            what: "header",
            offset: 4,
            need: 6,
            have: data.len() - 4,
        });
    }
    let version = data[4];
    if version != MRS_VERSION {
        return Err(MrsError::UnsupportedVersion(version));
    }
    let type_tag = data[5];
    let count = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
    Ok((
        MrsHeader {
            version,
            type_tag,
            count,
        },
        &data[10..],
    ))
}

/// Largest accepted *decompressed* mrs/geosite payload. The HTTP body cap
/// (`internal_http::MAX_BODY_BYTES`) bounds only the compressed wire bytes;
/// the zstd expansion ratio is attacker-chosen, so an unbounded `read_to_end`
/// would let a small payload grow `out` until allocation aborts the process
/// (issue #513).
const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Decompress the zstd-compressed payload that follows an mrs header.
pub fn decompress_payload(compressed: &[u8]) -> Result<Vec<u8>, MrsError> {
    decompress_payload_bounded(compressed, MAX_DECOMPRESSED_BYTES)
}

fn decompress_payload_bounded(compressed: &[u8], max: u64) -> Result<Vec<u8>, MrsError> {
    let mut decoder = zstd::stream::Decoder::new(Cursor::new(compressed))?;
    let mut out = Vec::new();
    // Read one byte past the bound so an over-limit payload is an error rather
    // than silently truncated input.
    let n = std::io::Read::take(&mut decoder, max + 1).read_to_end(&mut out)?;
    if n as u64 > max {
        return Err(MrsError::InvalidLength("decompressed_payload", max as i64));
    }
    Ok(out)
}

/// Streaming big-endian frame reader over any `Read` — typically a zstd
/// decoder, so a multi-megabyte payload is parsed through a small buffer
/// instead of being decompressed into memory first.
pub struct FrameReader<R: Read> {
    inner: R,
    pos: usize,
}

impl<R: Read> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, pos: 0 }
    }

    fn fill(&mut self, what: &'static str, buf: &mut [u8]) -> Result<(), MrsError> {
        // Same expansion bound as `decompress_payload`: zstd expansion is
        // attacker-chosen, so a streamed payload is capped too (issue #513).
        if (self.pos + buf.len()) as u64 > MAX_DECOMPRESSED_BYTES {
            return Err(MrsError::InvalidLength(
                "decompressed_payload",
                MAX_DECOMPRESSED_BYTES as i64,
            ));
        }
        match self.inner.read_exact(buf) {
            Ok(()) => {
                self.pos += buf.len();
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(MrsError::Truncated {
                what,
                offset: self.pos,
                need: buf.len(),
                have: 0,
            }),
            Err(e) => Err(MrsError::Zstd(e)),
        }
    }

    pub fn read_u8(&mut self, what: &'static str) -> Result<u8, MrsError> {
        let mut b = [0u8; 1];
        self.fill(what, &mut b)?;
        Ok(b[0])
    }

    pub fn read_u16_be(&mut self, what: &'static str) -> Result<u16, MrsError> {
        let mut b = [0u8; 2];
        self.fill(what, &mut b)?;
        Ok(u16::from_be_bytes(b))
    }

    /// Like [`Self::read_u16_be`], but a clean end of stream (no bytes at
    /// all) yields `None` instead of a truncation error.
    pub fn read_u16_be_or_eof(&mut self, what: &'static str) -> Result<Option<u16>, MrsError> {
        let mut b = [0u8; 2];
        let mut got = 0;
        while got < 2 {
            match self.inner.read(&mut b[got..]) {
                Ok(0) if got == 0 => return Ok(None),
                Ok(0) => {
                    return Err(MrsError::Truncated {
                        what,
                        offset: self.pos + got,
                        need: 2,
                        have: got,
                    })
                }
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(MrsError::Zstd(e)),
            }
        }
        self.pos += 2;
        Ok(Some(u16::from_be_bytes(b)))
    }

    pub fn read_u32_be(&mut self, what: &'static str) -> Result<u32, MrsError> {
        let mut b = [0u8; 4];
        self.fill(what, &mut b)?;
        Ok(u32::from_be_bytes(b))
    }

    pub fn read_array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], MrsError> {
        let mut b = [0u8; N];
        self.fill(what, &mut b)?;
        Ok(b)
    }

    /// Read exactly `len` bytes into `buf` (reused across calls).
    pub fn read_into(
        &mut self,
        what: &'static str,
        len: usize,
        buf: &mut Vec<u8>,
    ) -> Result<(), MrsError> {
        buf.clear();
        buf.resize(len, 0);
        self.fill(what, buf)
    }

    pub fn skip(&mut self, what: &'static str, mut len: usize) -> Result<(), MrsError> {
        let mut scratch = [0u8; 256];
        while len > 0 {
            let n = len.min(scratch.len());
            self.fill(what, &mut scratch[..n])?;
            len -= n;
        }
        Ok(())
    }
}

fn utf8<'a>(what: &'static str, bytes: &'a [u8]) -> Result<&'a str, MrsError> {
    std::str::from_utf8(bytes).map_err(|_| {
        let err = String::from_utf8(bytes.to_vec()).expect_err("from_utf8 already failed");
        MrsError::Utf8(what, err)
    })
}

/// One item of a streamed geosite payload (see [`stream_geosite_payload`]).
pub enum GeositeItem<'a> {
    /// A category header: lower-cased name and its domain count. Return
    /// `false` from the callback to skip the category's domains without
    /// materialising them.
    Category { name: &'a str, domains: u32 },
    /// One domain of the most recent accepted category (case preserved).
    Domain(&'a str),
}

/// Stream a decompressed geosite payload item by item through `on_item`,
/// holding only one name and one domain in memory at a time. The callback's
/// return value is consulted only for [`GeositeItem::Category`].
pub fn stream_geosite_payload<R: Read>(
    reader: R,
    mut on_item: impl FnMut(GeositeItem<'_>) -> bool,
) -> Result<(), MrsError> {
    let mut r = FrameReader::new(reader);
    let cat_count = r.read_u32_be("category_count")?;
    let mut name_buf = Vec::new();
    let mut domain_buf = Vec::new();
    for _ in 0..cat_count {
        let name_len = r.read_u16_be("category_name_len")? as usize;
        r.read_into("category_name", name_len, &mut name_buf)?;
        utf8("category_name", &name_buf)?;
        name_buf.make_ascii_lowercase();
        let name = utf8("category_name", &name_buf)?;
        let dom_count = r.read_u32_be("domain_count")?;
        let load = on_item(GeositeItem::Category {
            name,
            domains: dom_count,
        });
        for _ in 0..dom_count {
            let dom_len = r.read_u16_be("domain_len")? as usize;
            if load {
                r.read_into("domain", dom_len, &mut domain_buf)?;
                on_item(GeositeItem::Domain(utf8("domain", &domain_buf)?));
            } else {
                r.skip("domain", dom_len)?;
            }
        }
    }
    Ok(())
}

/// Stream a `u16-be length + UTF-8 bytes` list (rule-set `domain` /
/// `classical` payloads) entry by entry.
pub fn stream_string_list<R: Read>(
    reader: R,
    mut on_entry: impl FnMut(&str),
) -> Result<(), MrsError> {
    let mut r = FrameReader::new(reader);
    let mut buf = Vec::new();
    while let Some(len) = r.read_u16_be_or_eof("string length")? {
        r.read_into("string entry", len as usize, &mut buf)?;
        on_entry(utf8("string entry", &buf)?);
    }
    Ok(())
}

/// Stream a rule-set `ipcidr` payload (`u8 family + addr + u8 prefix`)
/// network by network.
pub fn stream_ipcidr_list<R: Read>(
    reader: R,
    mut on_net: impl FnMut(ipnet::IpNet),
) -> Result<(), MrsError> {
    let mut r = FrameReader::new(reader);
    let mut family = [0u8; 1];
    loop {
        match r.inner.read(&mut family) {
            Ok(0) => return Ok(()),
            Ok(_) => r.pos += 1,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(MrsError::Zstd(e)),
        }
        match family[0] {
            4 => {
                let addr = r.read_array::<4>("ipv4 address")?;
                let prefix = r.read_u8("ipv4 prefix")?;
                let net = ipnet::Ipv4Net::new(Ipv4Addr::from(addr), prefix)
                    .map_err(|_| MrsError::InvalidLength("ipv4 prefix", i64::from(prefix)))?;
                on_net(ipnet::IpNet::V4(net));
            }
            16 => {
                let addr = r.read_array::<16>("ipv6 address")?;
                let prefix = r.read_u8("ipv6 prefix")?;
                let net = ipnet::Ipv6Net::new(Ipv6Addr::from(addr), prefix)
                    .map_err(|_| MrsError::InvalidLength("ipv6 prefix", i64::from(prefix)))?;
                on_net(ipnet::IpNet::V6(net));
            }
            other => return Err(MrsError::InvalidBehavior(other)),
        }
    }
}

/// Parsed current upstream mihomo rule-provider `.mrs` payload.
///
/// Upstream stores the whole file as one zstd frame. The decompressed stream is:
///
/// ```text
/// magic    [4]byte = "MRS\x01"
/// behavior u8      = 0 domain, 1 ipcidr
/// count    i64-be
/// extraLen i64-be  = reserved bytes to skip
/// body     behavior-specific binary set
/// ```
pub struct UpstreamRuleSetPayload {
    pub behavior: u8,
    pub count: usize,
    pub entries: Vec<String>,
}

/// Materialise every entry of an upstream `.mrs` payload as text. Kept for
/// tests and tooling; the rule-set loader streams through
/// [`UpstreamRuleSetReader`] instead so no per-entry `String` list is built.
pub fn parse_upstream_ruleset_mrs(bytes: &[u8]) -> Result<UpstreamRuleSetPayload, MrsError> {
    let reader = UpstreamRuleSetReader::open(bytes)?;
    let mut entries = Vec::new();
    match reader.behavior() {
        TYPE_DOMAIN => reader.for_each_domain(|d| entries.push(d.to_string()))?,
        TYPE_IPCIDR => reader.for_each_net(|net| entries.push(net.to_string()))?,
        other => return Err(MrsError::InvalidBehavior(other)),
    }
    Ok(UpstreamRuleSetPayload {
        behavior: reader.behavior(),
        count: reader.count(),
        entries,
    })
}

/// Decoded upstream `.mrs` frame: header fields plus the still-encoded body
/// (a succinct domain set or a range list), walked on demand.
pub struct UpstreamRuleSetReader {
    decompressed: Vec<u8>,
    body_offset: usize,
    behavior: u8,
    count: usize,
}

impl UpstreamRuleSetReader {
    pub fn open(bytes: &[u8]) -> Result<Self, MrsError> {
        let decompressed = decompress_payload(bytes)?;
        let mut r = ByteReader::new(&decompressed);
        let magic = r.read_array::<4>("upstream_magic")?;
        if magic != UPSTREAM_MRS_MAGIC {
            return Err(MrsError::WrongFormat);
        }

        let behavior = r.read_u8("behavior")?;
        if behavior != TYPE_DOMAIN && behavior != TYPE_IPCIDR {
            return Err(MrsError::InvalidBehavior(behavior));
        }
        let count = r.read_i64_be("count")?;
        if count < 0 {
            return Err(MrsError::InvalidLength("count", count));
        }
        let count = usize::try_from(count).map_err(|_| MrsError::InvalidLength("count", count))?;

        let extra_len = r.read_i64_be("extra_len")?;
        if extra_len < 0 {
            return Err(MrsError::InvalidReservedLength(extra_len));
        }
        let extra_len = usize::try_from(extra_len)
            .map_err(|_| MrsError::InvalidLength("extra_len", extra_len))?;
        let _ = r.read_slice("extra", extra_len)?;
        let body_offset = decompressed.len() - r.remaining_slice().len();

        Ok(Self {
            decompressed,
            body_offset,
            behavior,
            count,
        })
    }

    pub fn behavior(&self) -> u8 {
        self.behavior
    }

    pub fn count(&self) -> usize {
        self.count
    }

    fn body(&self) -> &[u8] {
        &self.decompressed[self.body_offset..]
    }

    /// Walk every domain of a `domain` body. Each domain is handed over as
    /// a borrowed `&str` from one reused buffer.
    pub fn for_each_domain(&self, mut on_domain: impl FnMut(&str)) -> Result<(), MrsError> {
        if self.behavior != TYPE_DOMAIN {
            return Err(MrsError::InvalidBehavior(self.behavior));
        }
        walk_upstream_domain_set(self.body(), &mut on_domain)
    }

    /// Walk every network of an `ipcidr` body (ranges are split into
    /// aligned prefixes, IPv4-mapped addresses are unmapped).
    pub fn for_each_net(&self, mut on_net: impl FnMut(ipnet::IpNet)) -> Result<(), MrsError> {
        if self.behavior != TYPE_IPCIDR {
            return Err(MrsError::InvalidBehavior(self.behavior));
        }
        let mut r = ByteReader::new(self.body());
        let version = r.read_u8("ipcidr_set_version")?;
        if version != 1 {
            return Err(MrsError::InvalidIpCidrSetVersion(version));
        }
        let len = r.read_i64_be("ipcidr_set_ranges_len")?;
        if len < 1 {
            return Err(MrsError::InvalidLength("ipcidr_set_ranges_len", len));
        }
        let mut emitted = 0usize;
        for _ in 0..len {
            let from = r.read_array::<16>("ipcidr_from")?;
            let to = r.read_array::<16>("ipcidr_to")?;
            let from = IpAddr::from(Ipv6Addr::from(from));
            let to = IpAddr::from(Ipv6Addr::from(to));
            push_range_prefixes(from, to, &mut |net| {
                emitted += 1;
                on_net(net);
            });
            // One 32-byte record can expand to over a hundred CIDRs; bound
            // the total or a max-size payload amplifies ~100x (issue #513).
            if emitted > MAX_DOMAIN_SET_ENTRIES {
                return Err(MrsError::InvalidLength("ipcidr_set_output", emitted as i64));
            }
        }
        Ok(())
    }
}

/// Decode a succinct domain set, calling `on_domain` once per domain
/// (forward byte order, reused buffer).
fn walk_upstream_domain_set(data: &[u8], on_domain: &mut dyn FnMut(&str)) -> Result<(), MrsError> {
    let mut r = ByteReader::new(data);
    let version = r.read_u8("domain_set_version")?;
    if version != 1 {
        return Err(MrsError::InvalidDomainSetVersion(version));
    }
    let leaves = read_u64_vec(&mut r, "domain_set_leaves")?;
    let label_bitmap = read_u64_vec(&mut r, "domain_set_label_bitmap")?;
    let labels_len = r.read_i64_be("domain_set_labels_len")?;
    if labels_len < 1 {
        return Err(MrsError::InvalidLength("domain_set_labels_len", labels_len));
    }
    let labels_len = usize::try_from(labels_len)
        .map_err(|_| MrsError::InvalidLength("domain_set_labels_len", labels_len))?;
    let labels = r.read_slice("domain_set_labels", labels_len)?;

    // A well-formed trie has exactly one terminator bit per node and every
    // non-root node owns one incoming label edge, so #ones <= labels + 1.
    // Enforce the correlation *before* DomainSetIndex materializes one `usize`
    // per set bit — a mostly-ones bitmap would otherwise amplify the input
    // ~64x into memory (issue #513).
    let node_count: usize = label_bitmap
        .iter()
        .map(|word| word.count_ones() as usize)
        .sum();
    if node_count > labels.len() + 1 {
        return Err(MrsError::InvalidLength(
            "domain_set_terminators",
            node_count as i64,
        ));
    }

    let traversal = DomainSetTraversal {
        leaves: &leaves,
        label_bitmap: &label_bitmap,
        label_index: DomainSetIndex::new(&label_bitmap),
        labels,
    };
    let mut current = Vec::new();
    let mut forward = Vec::new();
    traversal.traverse(0, 0, &mut current, &mut |reversed: &[u8]| {
        forward.clear();
        forward.extend(reversed.iter().rev());
        if let Ok(domain) = std::str::from_utf8(&forward) {
            on_domain(domain);
        }
    })
}

#[cfg(test)]
fn parse_upstream_domain_set(data: &[u8]) -> Result<Vec<String>, MrsError> {
    let mut out = Vec::new();
    walk_upstream_domain_set(data, &mut |d| out.push(d.to_string()))?;
    Ok(out)
}

fn read_u64_vec(r: &mut ByteReader<'_>, what: &'static str) -> Result<Vec<u64>, MrsError> {
    let declared = r.read_i64_be(what)?;
    if declared < 1 {
        return Err(MrsError::InvalidLength(what, declared));
    }
    // The word count comes from a remote rule-provider, so prove the bytes are
    // actually present before reserving: `with_capacity` on a bogus count trips
    // the capacity-overflow check and aborts the process (issue #513).
    let len = usize::try_from(declared).map_err(|_| MrsError::InvalidLength(what, declared))?;
    let bytes = len
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or(MrsError::InvalidLength(what, declared))?;
    r.need(what, bytes)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(r.read_u64_be(what)?);
    }
    Ok(out)
}

struct DomainSetTraversal<'a> {
    leaves: &'a [u64],
    label_bitmap: &'a [u64],
    label_index: DomainSetIndex,
    labels: &'a [u8],
}

/// Hard bounds on decoded domain-set output. Real-world rule sets top out at a
/// few million short domains; a hostile file can otherwise turn input bytes
/// into roughly O(input²) output — each reachable leaf clones a label path of
/// up to `labels.len()` bytes — exhausting memory without tripping any input
/// check (issue #513).
const MAX_DOMAIN_SET_ENTRIES: usize = 4 * 1024 * 1024;
const MAX_DOMAIN_SET_BYTES: usize = 256 * 1024 * 1024;
/// A domain never exceeds 253 octets of labels, so a legitimate trie walk is
/// ~127 frames deep at most; 4 Ki frames is generous headroom. Without the
/// cap the explicit stack and `current` still grow proportionally to remote
/// input — a deep-chain gadget turns a bounded payload into GiBs of frames.
const MAX_DOMAIN_SET_DEPTH: usize = 4 * 1024;

impl DomainSetTraversal<'_> {
    fn traverse(
        &self,
        root_node: usize,
        root_bm: usize,
        current: &mut Vec<u8>,
        out: &mut dyn FnMut(&[u8]),
    ) -> Result<(), MrsError> {
        self.traverse_bounded(
            root_node,
            root_bm,
            current,
            out,
            MAX_DOMAIN_SET_ENTRIES,
            MAX_DOMAIN_SET_BYTES,
            MAX_DOMAIN_SET_DEPTH,
        )
    }

    /// Depth-first walk of the label graph, iterative because the input is
    /// remote-controlled: recursion depth is proportional to input size and
    /// would overflow the (small) stack of the spawned provider-fetch thread.
    ///
    /// Frame discipline: `current` holds one label byte per frame above the
    /// root, so `current.len() == stack.len() - 1` is an invariant.
    #[allow(clippy::too_many_arguments, reason = "bounds grouped for tests")]
    fn traverse_bounded(
        &self,
        root_node: usize,
        root_bm: usize,
        current: &mut Vec<u8>,
        out: &mut dyn FnMut(&[u8]),
        max_entries: usize,
        max_bytes: usize,
        max_depth: usize,
    ) -> Result<(), MrsError> {
        let mut out_count = 0usize;
        let mut out_bytes = 0usize;
        let mut stack: Vec<(usize, usize)> = vec![(root_node, root_bm)];
        if get_bit(self.leaves, root_node) {
            out_count += 1;
            out(current);
        }
        while let Some(top) = stack.last_mut() {
            let (node_id, idx) = *top;
            // A terminator bit, an out-of-range label, or a missing child node
            // all end this frame exactly as the recursive `return` did.
            let child = if get_bit(self.label_bitmap, idx) {
                None
            } else {
                let label_idx = idx.saturating_sub(node_id);
                let next_node_id = self.label_index.count_zeros(self.label_bitmap, idx + 1);
                self.labels
                    .get(label_idx)
                    .copied()
                    .zip(self.label_index.select_one(next_node_id.saturating_sub(1)))
                    .map(|(label, prev_terminator)| (label, next_node_id, prev_terminator + 1))
            };
            let Some((label, next_node_id, next_bm_idx)) = child else {
                stack.pop();
                if !stack.is_empty() {
                    current.pop();
                }
                continue;
            };
            top.1 = idx + 1;
            current.push(label);
            if get_bit(self.leaves, next_node_id) {
                if out_count >= max_entries || out_bytes + current.len() > max_bytes {
                    return Err(MrsError::InvalidLength(
                        "domain_set_output",
                        out_count as i64,
                    ));
                }
                out_bytes += current.len();
                out_count += 1;
                out(current);
            }
            if stack.len() >= max_depth {
                return Err(MrsError::InvalidLength(
                    "domain_set_depth",
                    stack.len() as i64,
                ));
            }
            stack.push((next_node_id, next_bm_idx));
        }
        Ok(())
    }
}

struct DomainSetIndex {
    rank_ones_by_word: Vec<usize>,
    select_ones: Vec<usize>,
}

impl DomainSetIndex {
    fn new(bits: &[u64]) -> Self {
        let mut rank_ones_by_word = Vec::with_capacity(bits.len() + 1);
        let mut select_ones = Vec::new();
        let mut seen_ones = 0usize;
        for (word_idx, word) in bits.iter().copied().enumerate() {
            rank_ones_by_word.push(seen_ones);
            let mut remaining = word;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                select_ones.push(word_idx * 64 + bit);
                remaining &= remaining - 1;
            }
            seen_ones += word.count_ones() as usize;
        }
        rank_ones_by_word.push(seen_ones);
        Self {
            rank_ones_by_word,
            select_ones,
        }
    }

    fn count_zeros(&self, bits: &[u64], upto: usize) -> usize {
        let total_bits = bits.len().saturating_mul(64);
        let upto = upto.min(total_bits);
        let word = upto / 64;
        let bit = upto % 64;
        let mut ones = self.rank_ones_by_word.get(word).copied().unwrap_or(0);
        if bit > 0 {
            if let Some(value) = bits.get(word) {
                let mask = (1u64 << bit) - 1;
                ones += (value & mask).count_ones() as usize;
            }
        }
        upto - ones
    }

    fn select_one(&self, nth: usize) -> Option<usize> {
        self.select_ones.get(nth).copied()
    }
}

fn get_bit(bits: &[u64], idx: usize) -> bool {
    bits.get(idx / 64)
        .is_some_and(|word| (word & (1u64 << (idx % 64))) != 0)
}

fn push_range_prefixes(from: IpAddr, to: IpAddr, out: &mut dyn FnMut(ipnet::IpNet)) {
    match (from, to) {
        (IpAddr::V4(a), IpAddr::V4(b)) => push_v4_range(a, b, out),
        (IpAddr::V6(a), IpAddr::V6(b))
            if a.to_ipv4_mapped().is_some() && b.to_ipv4_mapped().is_some() =>
        {
            push_v4_range(
                a.to_ipv4_mapped().unwrap(),
                b.to_ipv4_mapped().unwrap(),
                out,
            );
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => push_v6_range(a, b, out),
        _ => {}
    }
}

fn push_v4_range(from: Ipv4Addr, to: Ipv4Addr, out: &mut dyn FnMut(ipnet::IpNet)) {
    let mut start = u32::from(from);
    let end = u32::from(to);
    if start == 0 && end == u32::MAX {
        out(ipnet::IpNet::V4(
            ipnet::Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("/0 is valid"),
        ));
        return;
    }
    while start <= end {
        let max_size = start.trailing_zeros();
        let remaining = u64::from(end) - u64::from(start) + 1;
        let block_bits = max_size.min(63 - remaining.leading_zeros());
        let prefix = 32 - block_bits;
        if let Ok(net) = ipnet::Ipv4Net::new(Ipv4Addr::from(start), prefix as u8) {
            out(ipnet::IpNet::V4(net));
        }
        let step = 1u32 << block_bits;
        if remaining == u64::from(step) {
            break;
        }
        start = start.saturating_add(step);
    }
}

fn push_v6_range(from: Ipv6Addr, to: Ipv6Addr, out: &mut dyn FnMut(ipnet::IpNet)) {
    let mut start = u128::from(from);
    let end = u128::from(to);
    if start == 0 && end == u128::MAX {
        out(ipnet::IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("/0 is valid"),
        ));
        return;
    }
    while start <= end {
        let max_size = start.trailing_zeros();
        let remaining = end - start + 1;
        let block_bits = max_size.min(127 - remaining.leading_zeros());
        let prefix = 128 - block_bits;
        if let Ok(net) = ipnet::Ipv6Net::new(Ipv6Addr::from(start), prefix as u8) {
            out(ipnet::IpNet::V6(net));
        }
        let step = 1u128 << block_bits;
        if end - start + 1 == step {
            break;
        }
        start = start.saturating_add(step);
    }
}

/// A parsed geosite DB: category name → list of domains.
#[derive(Debug, Default)]
pub struct GeositePayload {
    pub categories: Vec<(String, Vec<String>)>,
}

/// Parse the inner (decompressed) geosite payload per the format described
/// at the top of this module into owned lists.
///
/// When `allowed` is `Some`, only categories whose lowercased name is in the
/// set are materialised; all others are skipped at the byte level. Pass
/// `None` to load every category. The geosite loader itself streams via
/// [`stream_geosite_payload`] and never builds these lists. Declared counts
/// are remote-controlled, so nothing is reserved from them: a bogus count
/// simply runs into a `Truncated` error (issue #513).
pub fn parse_geosite_payload(
    decompressed: &[u8],
    allowed: Option<&std::collections::HashSet<String>>,
) -> Result<GeositePayload, MrsError> {
    let mut categories: Vec<(String, Vec<String>)> = Vec::new();
    stream_geosite_payload(Cursor::new(decompressed), |item| match item {
        GeositeItem::Category { name, .. } => {
            if allowed.is_some_and(|set| !set.contains(name)) {
                return false;
            }
            categories.push((name.to_string(), Vec::new()));
            true
        }
        GeositeItem::Domain(domain) => {
            if let Some((_, domains)) = categories.last_mut() {
                domains.push(domain.to_ascii_lowercase());
            }
            true
        }
    })?;
    Ok(GeositePayload { categories })
}

/// Encode a `GeositePayload` into the uncompressed inner payload bytes.
/// Exposed for tests and for future tooling that writes mrs files.
pub fn encode_geosite_payload(payload: &GeositePayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(payload.categories.len() as u32).to_be_bytes());
    for (name, domains) in &payload.categories {
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(domains.len() as u32).to_be_bytes());
        for d in domains {
            out.extend_from_slice(&(d.len() as u16).to_be_bytes());
            out.extend_from_slice(d.as_bytes());
        }
    }
    out
}

/// Write a complete mrs geosite file (header + zstd-compressed payload).
/// Used by tests to build binary fixtures.
pub fn write_geosite_mrs(payload: &GeositePayload) -> Result<Vec<u8>, MrsError> {
    let inner = encode_geosite_payload(payload);
    let compressed = zstd::encode_all(Cursor::new(&inner), 0)?;
    let mut out = Vec::with_capacity(10 + compressed.len());
    out.extend_from_slice(&MRS_MAGIC);
    out.push(MRS_VERSION);
    out.push(TYPE_DOMAIN);
    // `count` here is the category count for geosite files.
    out.extend_from_slice(&(payload.categories.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    Ok(out)
}

/// Write a complete mrs rule-set file (header + zstd-compressed string-list payload).
/// `type_tag` should be `TYPE_DOMAIN`, `TYPE_IPCIDR`, or `TYPE_CLASSICAL`.
/// Used by tests and tooling.
pub fn write_ruleset_mrs(type_tag: u8, entries: &[&str]) -> Result<Vec<u8>, MrsError> {
    let mut inner = Vec::new();
    for e in entries {
        let b = e.as_bytes();
        inner.extend_from_slice(&(b.len() as u16).to_be_bytes());
        inner.extend_from_slice(b);
    }
    let compressed = zstd::encode_all(Cursor::new(&inner), 0)?;
    let mut out = Vec::with_capacity(10 + compressed.len());
    out.extend_from_slice(&MRS_MAGIC);
    out.push(MRS_VERSION);
    out.push(type_tag);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    Ok(out)
}

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Unread byte count. Saturating because a hostile declared length can push
    /// `pos` arithmetic that would otherwise wrap.
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn need(&self, what: &'static str, n: usize) -> Result<(), MrsError> {
        // Compare against the remaining length rather than `pos + n`: a declared
        // length near `usize::MAX` would wrap the sum and pass the check.
        let have = self.remaining();
        if n > have {
            return Err(MrsError::Truncated {
                what,
                offset: self.pos,
                need: n,
                have,
            });
        }
        Ok(())
    }

    fn read_u8(&mut self, what: &'static str) -> Result<u8, MrsError> {
        self.need(what, 1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u64_be(&mut self, what: &'static str) -> Result<u64, MrsError> {
        self.need(what, 8)?;
        let v = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_i64_be(&mut self, what: &'static str) -> Result<i64, MrsError> {
        self.need(what, 8)?;
        let v = i64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], MrsError> {
        self.need(what, N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_slice(&mut self, what: &'static str, n: usize) -> Result<&'a [u8], MrsError> {
        self.need(what, n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> GeositePayload {
        GeositePayload {
            categories: vec![
                (
                    "cn".to_string(),
                    vec!["example.cn".to_string(), "baidu.com".to_string()],
                ),
                ("ads".to_string(), vec!["ad.example.com".to_string()]),
            ],
        }
    }

    fn set_bit(bits: &mut Vec<u64>, idx: usize, value: bool) {
        let word = idx / 64;
        if bits.len() <= word {
            bits.resize(word + 1, 0);
        }
        if value {
            bits[word] |= 1u64 << (idx % 64);
        }
    }

    fn write_i64(out: &mut Vec<u8>, value: i64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn write_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn encode_domain_set(entries: &[&str]) -> Vec<u8> {
        let mut keys: Vec<Vec<u8>> = entries
            .iter()
            .map(|entry| entry.as_bytes().iter().rev().copied().collect())
            .collect();
        keys.sort();

        let mut leaves = Vec::new();
        let mut label_bitmap = Vec::new();
        let mut labels = Vec::new();
        let mut label_idx = 0usize;
        let mut queue = vec![(0usize, keys.len(), 0usize)];

        let mut idx = 0usize;
        while idx < queue.len() {
            let (mut start, end, col) = queue[idx];
            if col == keys[start].len() {
                start += 1;
                set_bit(&mut leaves, idx, true);
            }
            let mut j = start;
            while j < end {
                let from = j;
                while j < end && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                labels.push(keys[from][col]);
                set_bit(&mut label_bitmap, label_idx, false);
                label_idx += 1;
            }
            set_bit(&mut label_bitmap, label_idx, true);
            label_idx += 1;
            idx += 1;
        }

        encode_domain_set_raw(&leaves, &label_bitmap, &labels)
    }

    fn encode_domain_set_raw(leaves: &[u64], label_bitmap: &[u64], labels: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1);
        write_i64(&mut out, leaves.len() as i64);
        for word in leaves {
            write_u64(&mut out, *word);
        }
        write_i64(&mut out, label_bitmap.len() as i64);
        for word in label_bitmap {
            write_u64(&mut out, *word);
        }
        write_i64(&mut out, labels.len() as i64);
        out.extend_from_slice(labels);
        out
    }

    fn encode_upstream_mrs(behavior: u8, count: usize, body: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&UPSTREAM_MRS_MAGIC);
        inner.push(behavior);
        write_i64(&mut inner, count as i64);
        write_i64(&mut inner, 0);
        inner.extend_from_slice(body);
        zstd::encode_all(Cursor::new(inner), 0).unwrap()
    }

    #[test]
    fn mrs_header_roundtrip() {
        let bytes = write_geosite_mrs(&sample()).unwrap();
        let (hdr, rest) = parse_header(&bytes).unwrap();
        assert_eq!(hdr.version, MRS_VERSION);
        assert_eq!(hdr.type_tag, TYPE_DOMAIN);
        assert_eq!(hdr.count, 2);
        // The remainder is the compressed payload; non-empty.
        assert!(!rest.is_empty());
    }

    #[test]
    fn mrs_wrong_format_rejected() {
        let bytes = b"NOTMRS...";
        match parse_header(bytes) {
            Err(MrsError::WrongFormat) => {}
            other => panic!("expected WrongFormat, got {other:?}"),
        }
    }

    #[test]
    fn mrs_short_header_truncated() {
        // only magic, no version/type/count
        let bytes = b"MRS!";
        match parse_header(bytes) {
            Err(MrsError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn mrs_unsupported_version() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MRS_MAGIC);
        bytes.push(99);
        bytes.push(TYPE_DOMAIN);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        match parse_header(&bytes) {
            Err(MrsError::UnsupportedVersion(99)) => {}
            other => panic!("expected UnsupportedVersion(99), got {other:?}"),
        }
    }

    #[test]
    fn geosite_payload_roundtrip() {
        let p = sample();
        let bytes = write_geosite_mrs(&p).unwrap();
        let (_, compressed) = parse_header(&bytes).unwrap();
        let decompressed = decompress_payload(compressed).unwrap();
        let parsed = parse_geosite_payload(&decompressed, None).unwrap();
        assert_eq!(parsed.categories.len(), 2);
        assert_eq!(parsed.categories[0].0, "cn");
        assert_eq!(parsed.categories[0].1, vec!["example.cn", "baidu.com"]);
        assert_eq!(parsed.categories[1].0, "ads");
        assert_eq!(parsed.categories[1].1, vec!["ad.example.com"]);
    }

    #[test]
    fn geosite_empty_db_roundtrip() {
        let empty = GeositePayload { categories: vec![] };
        let bytes = write_geosite_mrs(&empty).unwrap();
        let (_, compressed) = parse_header(&bytes).unwrap();
        let decompressed = decompress_payload(compressed).unwrap();
        let parsed = parse_geosite_payload(&decompressed, None).unwrap();
        assert!(parsed.categories.is_empty());
    }

    #[test]
    fn upstream_ruleset_mrs_domain_parses() {
        let body = encode_domain_set(&["example.com", "+.foo.com"]);
        let bytes = encode_upstream_mrs(TYPE_DOMAIN, 2, &body);
        let parsed = parse_upstream_ruleset_mrs(&bytes).unwrap();
        assert_eq!(parsed.behavior, TYPE_DOMAIN);
        assert_eq!(parsed.count, 2);
        assert!(parsed.entries.iter().any(|e| e == "example.com"));
        assert!(parsed.entries.iter().any(|e| e == "+.foo.com"));
    }

    #[test]
    fn upstream_ruleset_mrs_ipcidr_parses() {
        let mut body = Vec::new();
        body.push(1);
        write_i64(&mut body, 1);
        body.extend_from_slice(&Ipv4Addr::new(192, 168, 0, 0).to_ipv6_mapped().octets());
        body.extend_from_slice(&Ipv4Addr::new(192, 168, 0, 255).to_ipv6_mapped().octets());
        let bytes = encode_upstream_mrs(TYPE_IPCIDR, 1, &body);
        let parsed = parse_upstream_ruleset_mrs(&bytes).unwrap();
        assert_eq!(parsed.behavior, TYPE_IPCIDR);
        assert_eq!(parsed.entries, vec!["192.168.0.0/24"]);
    }

    /// A remote rule-provider can declare an enormous word count in a payload
    /// only a few dozen bytes long. Both `read_u64_vec` call sites must reject
    /// it with an error: reserving from the declared count trips the
    /// capacity-overflow check, which terminates the process under the
    /// workspace's `panic = "abort"` release profile (issue #513).
    #[test]
    fn upstream_ruleset_mrs_oversized_word_counts_are_rejected() {
        // `i64::MAX` overflows the byte-count multiplication; `i64::MAX / 8 + 1`
        // does not and must instead be caught by the remaining-input check.
        for declared in [i64::MAX, i64::MAX / 8 + 1, 100] {
            let mut leaves = vec![1u8];
            write_i64(&mut leaves, declared);
            assert!(
                parse_upstream_ruleset_mrs(&encode_upstream_mrs(TYPE_DOMAIN, 1, &leaves)).is_err(),
                "leaves_len={declared} must not reserve from the declared count"
            );

            let mut bitmap = vec![1u8];
            write_i64(&mut bitmap, 1);
            write_u64(&mut bitmap, 0);
            write_i64(&mut bitmap, declared);
            assert!(
                parse_upstream_ruleset_mrs(&encode_upstream_mrs(TYPE_DOMAIN, 1, &bitmap)).is_err(),
                "label_bitmap_len={declared} must not reserve from the declared count"
            );
        }
    }

    /// Same class on the geodata path: `category_count` and `domain_count` are
    /// u32 values from a remote geodata file, so the reservation has to be
    /// capped by the input rather than asking for hundreds of gigabytes.
    #[test]
    fn geosite_payload_declared_counts_are_bounded_by_input() {
        assert!(parse_geosite_payload(&u32::MAX.to_be_bytes(), None).is_err());

        let mut category_without_domains = Vec::new();
        category_without_domains.extend_from_slice(&1u32.to_be_bytes());
        category_without_domains.extend_from_slice(b"cn");
        category_without_domains.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_geosite_payload(&category_without_domains, None).is_err());
    }

    /// The wire cap bounds only the *compressed* bytes; zstd expansion is
    /// attacker-chosen, so decompression itself must be bounded or a small
    /// payload can allocate until abort (issue #513).
    #[test]
    fn decompress_payload_rejects_output_past_the_bound() {
        let inner = vec![0u8; 1024];
        let compressed = zstd::encode_all(Cursor::new(&inner), 0).unwrap();
        assert_eq!(
            decompress_payload_bounded(&compressed, 512)
                .unwrap_err()
                .to_string(),
            "mrs: invalid length for decompressed_payload: 512"
        );
        assert_eq!(
            decompress_payload_bounded(&compressed, 1024).unwrap(),
            inner
        );
    }

    /// A crafted label graph can chain one traversal frame per few input
    /// bytes. The walk must be iterative (no native recursion), bounded in
    /// depth, and bounded in output — the gadget below produces a leaf per
    /// level and would previously have recursed ~input-size deep.
    #[test]
    fn domain_set_traversal_is_iterative_and_bounded() {
        // labels[i] = 'a'; a linear chain of N levels: leaf bit set only at the
        // last node, each node's bitmap entry is a single zero bit followed by
        // its terminator. Depth = level count, not bounded by anything in the
        // input except size — recursion would overflow a 2 MiB fetch-thread
        // stack around ~10^5 levels.
        let deep_chain = |levels: usize| {
            let mut leaves = vec![0u64; levels / 64 + 1];
            leaves[levels / 64] = 1 << (levels % 64);
            // Level k occupies bit position 2k (label edge), 2k+1 is the
            // terminator marking the end of the node's children.
            let mut bitmap = vec![0u64; (2 * levels + 1) / 64 + 1];
            for level in 0..=levels {
                let pos = 2 * level + 1;
                bitmap[pos / 64] |= 1 << (pos % 64);
            }
            let labels = vec![b'a'; levels];
            encode_domain_set_raw(&leaves, &bitmap, &labels)
        };
        // Just under the depth cap: one leaf, the deepest.
        let parsed = parse_upstream_ruleset_mrs(&encode_upstream_mrs(
            TYPE_DOMAIN,
            1,
            &deep_chain(MAX_DOMAIN_SET_DEPTH - 100),
        ))
        .unwrap_or_else(|e| panic!("iterative traversal must not overflow: {e}"));
        assert_eq!(parsed.entries.len(), 1);
        // Past the cap the walk is an error, not a stack overflow or a
        // multi-GiB frame allocation.
        match parse_upstream_ruleset_mrs(&encode_upstream_mrs(
            TYPE_DOMAIN,
            1,
            &deep_chain(MAX_DOMAIN_SET_DEPTH + 100),
        ))
        .map(|_| ())
        {
            Err(MrsError::InvalidLength("domain_set_depth", _)) => {}
            other => panic!("expected InvalidLength(domain_set_depth), got {other:?}"),
        }
    }

    /// The same traversal must stop rather than amplify input bytes into
    /// unbounded output: a bitmap of all-zero edges makes every level a leaf.
    #[test]
    fn domain_set_output_is_bounded() {
        // Node 0 has N children, each a leaf: node 0's bitmap run is N zero
        // bits then a terminator; child i is node i+1 (count_zeros gives the
        // running zero count) with its own bitmap segment holding an edge
        // attempt that dies on an out-of-range label, then a terminator.
        let n = 1_000_000usize;
        let total_bits = n + 1 + 3 * n + 1;
        let mut bitmap = vec![0u64; total_bits / 64 + 1];
        let set = |b: &mut Vec<u64>, pos: usize| b[pos / 64] |= 1 << (pos % 64);
        set(&mut bitmap, n); // node 0 terminator
        let mut leaves = vec![0u64; n + 2];
        // child i is node i+1; make every child a leaf
        for i in 0..n {
            let node = i + 1;
            leaves[node / 64] |= 1 << (node % 64);
            // child node's bitmap: terminator immediately
            set(&mut bitmap, n + 1 + 3 * i + 1);
        }
        let labels = vec![b'x'; n];
        let body = encode_domain_set_raw(&leaves, &bitmap, &labels);
        let parsed = parse_upstream_ruleset_mrs(&encode_upstream_mrs(TYPE_DOMAIN, n, &body))
            .unwrap_or_else(|e| panic!("shallow fan within bounds must parse: {e}"));
        assert_eq!(parsed.entries.len(), n);
    }

    /// A mostly-ones bitmap makes `DomainSetIndex` allocate one `usize` per
    /// set bit — ~64x input amplification. A well-formed trie has one
    /// terminator per node and one incoming label edge per non-root node, so
    /// #ones <= labels + 1 is rejected before the index is built.
    #[test]
    fn domain_set_terminators_are_bounded_by_labels() {
        let body = encode_domain_set_raw(&[0u64], &[u64::MAX; 8], b"x");
        match parse_upstream_domain_set(&body) {
            Err(MrsError::InvalidLength("domain_set_terminators", _)) => {}
            other => panic!("expected InvalidLength(domain_set_terminators), got {other:?}"),
        }
    }

    /// The output and depth caps must actually fire: encode a small real trie
    /// and drive `traverse_bounded` with tiny limits.
    #[test]
    fn domain_set_bounds_error_instead_of_amplifying() {
        let body = encode_domain_set(&["a.example.com", "b.example.com", "c.example.com"]);
        let mut r = ByteReader::new(&body);
        assert_eq!(r.read_u8("v").unwrap(), 1);
        let leaves = read_u64_vec(&mut r, "leaves").unwrap();
        let label_bitmap = read_u64_vec(&mut r, "bitmap").unwrap();
        let labels_len = r.read_i64_be("labels_len").unwrap() as usize;
        let labels = r.read_slice("labels", labels_len).unwrap();
        let traversal = DomainSetTraversal {
            leaves: &leaves,
            label_bitmap: &label_bitmap,
            label_index: DomainSetIndex::new(&label_bitmap),
            labels,
        };
        let mut sink = |_: &[u8]| {};
        let mut current = Vec::new();
        // Three domains in the set; cap at two.
        assert!(
            traversal
                .traverse_bounded(0, 0, &mut current, &mut sink, 2, usize::MAX, 4096)
                .is_err(),
            "entry cap must error"
        );
        let mut current = Vec::new();
        // Depth 1 refuses every descent.
        assert!(
            traversal
                .traverse_bounded(0, 0, &mut current, &mut sink, usize::MAX, usize::MAX, 1)
                .is_err(),
            "depth cap must error"
        );
        let mut current = Vec::new();
        // Byte cap: each emitted domain is longer than 1 byte.
        assert!(
            traversal
                .traverse_bounded(0, 0, &mut current, &mut sink, usize::MAX, 1, 4096)
                .is_err(),
            "byte cap must error"
        );
    }
}
