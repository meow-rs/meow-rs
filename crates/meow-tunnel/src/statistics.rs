// M2 layout change (ADR-0011 T2):
//   id: String (24 B heap) → Uuid (16 B inline, −8 B)
//   metadata: Metadata (272 B inline) → Arc<Metadata> (8 B thin-ptr, −264 B)
//     Closing a connection drops a refcount, not a 272 B drop chain.
//   rule: String → SmolStr (inline ≤23 B, heap-backed above that, −8 B)
//   rule_payload: String → SmolStr (same)
//     ADR-0008 HP-3: previously these were `Arc<str>`, which always allocates
//     on construction. SmolStr inlines the common cases (`Direct`, `DOMAIN`,
//     `example.com`, `192.168.0.0/16`, …) — zero heap touches per connection
//     for the rule-match record.
//   chains: Vec<String> (24 B struct, heap elems) → Vec<Arc<str>> (24 B struct,
//     ref-counted elems — no per-element allocation for proxy names)
// Public JSON shape: Uuid serialises as hyphenated string via the `serde`
// feature; SmolStr / Arc<str> / Vec<Arc<str>> all serialise as string/array.
// Arc<Metadata> serialises transparently as the inner `Metadata` under the
// mihomo-compatible `metadata` key (issue #241).
// Breaking change permitted by ADR-0009.

use dashmap::DashMap;
use meow_common::atomic::{AtomicI, Int};
use meow_common::conn_notes::ConnNotes;
pub use meow_common::traffic::ProxyTraffic;
use meow_common::traffic::ProxyTrafficSource;
use meow_common::Metadata;
use parking_lot::Mutex;
use serde::Serialize;
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

/// Hot-path rule-match counters. Keys are `&'static str` to avoid per-call
/// allocation since `increment` is called on every proxied connection.
pub struct RuleMatchCounters {
    inner: DashMap<(&'static str, &'static str), u64>,
}

impl RuleMatchCounters {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// `rule_type` and `action` MUST be `'static` literals (e.g. "DOMAIN", "PROXY").
    pub fn increment(&self, rule_type: &'static str, action: &'static str) {
        *self.inner.entry((rule_type, action)).or_insert(0) += 1;
    }

    pub fn snapshot(&self) -> Vec<((&'static str, &'static str), u64)> {
        self.inner.iter().map(|e| (*e.key(), *e.value())).collect()
    }
}

impl Default for RuleMatchCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Live per-connection byte counters, shared between the relay closures and
/// the `/connections` serializer. `Arc`-owned by the relay's `ConnectionGuard`
/// so the hot loop bumps the atomics directly — no per-chunk DashMap lookup
/// (measured −8..10% on bulk throughput when the lookup was per-chunk).
/// The single `Arc::new` happens once per connection inside
/// [`Statistics::track_connection`], which is setup-path, not steady-state
/// (ADR-0008 §3 scopes the zero-alloc rule to per-iteration counts).
#[derive(Debug, Default)]
pub struct ConnCounters {
    pub upload: AtomicI,
    pub download: AtomicI,
    // Stored in the existing Arc so cancellation adds no setup allocation.
    closed: AtomicBool,
    close_notify: tokio::sync::Notify,
    /// The connection's notes when the tunnel records them (see
    /// `Tunnel::set_connection_notes`). Kept here, not on `ConnectionInfo`,
    /// so the info struct keeps its size and the list JSON its shape; only
    /// `GET /connections/{id}` serializes them.
    notes: Option<ConnNotes>,
    /// The leaf proxy's totals (`chains[0]`), bumped alongside these.
    proxy: Option<Arc<ProxyTraffic>>,
}

impl ConnCounters {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.close_notify.notify_waiters();
    }

    pub(crate) async fn closed(&self) {
        // Register before checking the flag: closing before the first poll or
        // between the check and await must not lose the wakeup.
        let notified = self.close_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.closed.load(Ordering::Acquire) {
            notified.await;
        }
    }

    pub fn upload_bytes(&self) -> Int {
        self.upload.load(Ordering::Relaxed)
    }

    pub fn download_bytes(&self) -> Int {
        self.download.load(Ordering::Relaxed)
    }

    pub fn notes(&self) -> Option<&ConnNotes> {
        self.notes.as_ref()
    }
}

// Serialises as `"upload": N, "download": N` so the flattened field keeps the
// exact mihomo connection JSON shape the plain i64 fields produced.
impl Serialize for ConnCounters {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ConnCounters", 2)?;
        s.serialize_field("upload", &self.upload_bytes())?;
        s.serialize_field("download", &self.download_bytes())?;
        s.end()
    }
}

#[derive(Serialize, Clone)]
pub struct ConnectionInfo {
    /// 16 B inline UUID; serialises as `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`.
    pub id: Uuid,
    /// 8 B thin-ptr; refcount drop on close instead of 272 B drop chain.
    /// Serialised as the mihomo-compatible `metadata` object (host, IPs, ports,
    /// network, type, …) so panels can show `host:port` as the connection title
    /// (issue #241). The `Arc` wrapper is transparent to serde — it serialises
    /// the inner `Metadata`. Struct size is unchanged (still an 8 B thin-ptr);
    /// only the `/connections` JSON payload grows.
    pub metadata: Arc<Metadata>,
    /// 8 B thin-ptr (was two inline `i64`s, −8 B). Flattened so the JSON keeps
    /// the top-level `upload`/`download` fields.
    #[serde(flatten)]
    pub counters: Arc<ConnCounters>,
    pub start: SmolStr,
    /// Proxy chain; ref-counted so proxy-name strings are shared across entries.
    pub chains: SmallVec<[Arc<str>; 1]>,
    /// Rule type that matched this connection (e.g. `"DOMAIN-SUFFIX"`).
    /// `SmolStr` so common short names inline (no heap on the connection
    /// hot path).
    pub rule: SmolStr,
    /// Rule payload (e.g. the domain pattern). Config-derived, low-cardinality.
    /// Renamed so the derived JSON matches the REST API's camelCase field.
    #[serde(rename = "rulePayload")]
    pub rule_payload: SmolStr,
}

/// Values exposed by the mihomo `/traffic` stream, captured together under
/// one lock so a reader never mixes rates and totals from different sampling
/// ticks (issue #338). Totals are the cumulative counters as observed at the
/// last tick; rates are the delta between consecutive observations (issue
/// #357) — derived from one counter, so `rate <= total` holds by construction
/// and no interleaving can publish an impossible pair (issue #340).
#[derive(Default, Clone, Copy)]
struct TrafficSnapshot {
    upload_rate: Int,
    download_rate: Int,
    upload_total: Int,
    download_total: Int,
}

pub struct Statistics {
    /// Cumulative relay byte totals. The only global counters the relay hot
    /// path touches (one relaxed `fetch_add` per direction per chunk). The
    /// sampler derives per-interval rates as deltas of consecutive
    /// observations and never writes these counters, so no relay increment
    /// can land on the wrong side of a `swap(0)`-style reset (issue #357).
    upload_total: AtomicI,
    download_total: AtomicI,
    traffic: Mutex<TrafficSnapshot>,
    /// Keyed by `Uuid` (16 B Copy) — formerly `String`, which heap-allocated a
    /// 36-byte hyphenated representation per insert.  REST handlers parse the
    /// query path back into a `Uuid` at lookup time.
    pub connections: DashMap<Uuid, ConnectionInfo>,
    /// Headless flows still need cancellation on a cold config reload, but
    /// never need the metadata and serialization fields used by the API.
    headless_connections: OnceLock<DashMap<usize, Arc<ConnCounters>>>,
    /// Connections that recorded notes, kept after they close so a client
    /// can still read why a short-lived or failed flow went where it did.
    /// Newest last, at most [`RECENTLY_CLOSED_CAPACITY`]. Flows without
    /// notes never enter it, so it stays empty unless notes are on.
    recently_closed: Mutex<VecDeque<ClosedConnection>>,
    pub rule_match: Arc<RuleMatchCounters>,
    /// Per proxy, created on its first flow and kept for the tunnel's life,
    /// so a proxy a reload removed still shows what it carried. Empty while
    /// headless, which keeps only the totals.
    proxy_traffic: DashMap<Arc<str>, Arc<ProxyTraffic>>,
}

/// How many closed connections with notes [`Statistics`] keeps.
pub const RECENTLY_CLOSED_CAPACITY: usize = 256;

/// A connection that has left the live table, with the time it did.
#[derive(Clone)]
struct ClosedConnection {
    info: ConnectionInfo,
    end: SmolStr,
}

/// One connection as `GET /connections/{id}` shows it: the `/connections`
/// entry plus its notes, and for a closed one, when it closed.
#[derive(Clone, Serialize)]
pub struct ConnectionDetail {
    #[serde(flatten)]
    pub info: ConnectionInfo,
    pub closed: bool,
    /// RFC 3339 time the connection left the live table; closed ones only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<SmolStr>,
    /// Empty when the connection records no notes.
    pub notes: NotesField,
}

/// The `notes` array of a [`ConnectionDetail`], read at serialization time
/// so a live connection's latest notes are included.
#[derive(Clone)]
pub struct NotesField(Option<ConnNotes>);

impl NotesField {
    pub fn get(&self) -> Option<&ConnNotes> {
        self.0.as_ref()
    }
}

impl Serialize for NotesField {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(notes) => notes.serialize(serializer),
            None => serializer.collect_seq(std::iter::empty::<()>()),
        }
    }
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            upload_total: AtomicI::new(0),
            download_total: AtomicI::new(0),
            traffic: Mutex::new(TrafficSnapshot::default()),
            connections: DashMap::new(),
            headless_connections: OnceLock::new(),
            recently_closed: Mutex::new(VecDeque::new()),
            rule_match: Arc::new(RuleMatchCounters::new()),
            proxy_traffic: DashMap::new(),
        }
    }

    pub fn add_upload(&self, n: Int) {
        self.upload_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_download(&self, n: Int) {
        self.download_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Per-chunk relay accounting: relaxed atomic adds (the connection, its
    /// proxy, the totals), no map lookup.
    /// Callers obtain the `ConnCounters` once at connection setup via
    /// [`Self::connection_counters`] (or `ConnectionGuard::counters`).
    pub fn record_upload(&self, counters: &ConnCounters, n: Int) {
        counters.upload.fetch_add(n, Ordering::Relaxed);
        self.record_packet_upload(counters.proxy.as_deref(), n);
    }

    /// See [`Self::record_upload`].
    pub fn record_download(&self, counters: &ConnCounters, n: Int) {
        counters.download.fetch_add(n, Ordering::Relaxed);
        self.record_packet_download(counters.proxy.as_deref(), n);
    }

    /// Count `n` bytes sent through `proxy` by a flow without connection
    /// counters (UDP): the totals and the proxy's, when it has them.
    pub fn record_packet_upload(&self, proxy: Option<&ProxyTraffic>, n: Int) {
        if let Some(proxy) = proxy {
            proxy.add_upload(n);
        }
        self.add_upload(n);
    }

    /// See [`Self::record_packet_upload`].
    pub fn record_packet_download(&self, proxy: Option<&ProxyTraffic>, n: Int) {
        if let Some(proxy) = proxy {
            proxy.add_download(n);
        }
        self.add_download(n);
    }

    /// `proxy`'s totals, created on its first flow; `None` while headless.
    /// Setup path (once per connection or UDP flow), never per chunk: a
    /// proxy seen before costs a lookup and a refcount, no allocation.
    pub fn proxy_counters(&self, proxy: &str) -> Option<Arc<ProxyTraffic>> {
        if self.is_headless() {
            return None;
        }
        if let Some(entry) = self.proxy_traffic.get(proxy) {
            return Some(Arc::clone(entry.value()));
        }
        let entry = self.proxy_traffic.entry(Arc::from(proxy)).or_default();
        Some(Arc::clone(entry.value()))
    }

    /// Every proxy that carried a flow, with its `(upload, download)` bytes
    /// so far, by name. Live connections count as far as they have got.
    pub fn proxy_traffic(&self) -> BTreeMap<Arc<str>, (Int, Int)> {
        self.proxy_traffic
            .iter()
            .map(|entry| {
                let traffic = entry.value();
                (
                    Arc::clone(entry.key()),
                    (traffic.upload_bytes(), traffic.download_bytes()),
                )
            })
            .collect()
    }

    /// One-time (per connection) handle to the live byte counters of a
    /// tracked connection. Setup-path only — never call per chunk.
    pub fn connection_counters(&self, id: Uuid) -> Option<Arc<ConnCounters>> {
        self.connections
            .get(&id)
            .map(|entry| Arc::clone(&entry.counters))
    }

    /// Roll the cumulative counters into the values exposed by the mihomo
    /// `/traffic` stream. All four values are published under one lock so
    /// `traffic_snapshot` readers see a mutually consistent set; rates are the
    /// delta between consecutive observations of the same counter, so they can
    /// never disagree with the totals (issue #340). The hot path stays
    /// lock-free — the once-per-second ticker plus API readers are the only
    /// contenders. Delta sampling means the ticker only loads the counters
    /// (issue #357): there is no reset for a concurrent relay `fetch_add` to
    /// race against, so an increment lands in exactly one interval — this one
    /// if the load observed it, the next one otherwise.
    pub fn sample_traffic(&self) {
        let mut snap = self.traffic.lock();
        let upload = self.upload_total.load(Ordering::Relaxed);
        let download = self.download_total.load(Ordering::Relaxed);
        snap.upload_rate = upload - snap.upload_total;
        snap.download_rate = download - snap.download_total;
        snap.upload_total = upload;
        snap.download_total = download;
    }

    /// `(upload_rate, download_rate, upload_total, download_total)` as of the
    /// last `sample_traffic` tick. Totals lag the live counters by up to one
    /// tick, in exchange for being consistent with the rates.
    pub fn traffic_snapshot(&self) -> (Int, Int, Int, Int) {
        let snap = *self.traffic.lock();
        (
            snap.upload_rate,
            snap.download_rate,
            snap.upload_total,
            snap.download_total,
        )
    }

    pub fn track_connection(
        &self,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
    ) -> Uuid {
        self.track_connection_with_counters(metadata, rule, rule_payload, chains, None)
            .0
    }

    pub(crate) fn track_connection_with_counters(
        &self,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
        notes: Option<ConnNotes>,
    ) -> (Uuid, Arc<ConnCounters>) {
        let uuid = Uuid::new_v4();
        let counters = Arc::new(ConnCounters {
            notes,
            proxy: chains.first().and_then(|leaf| self.proxy_counters(leaf)),
            ..ConnCounters::default()
        });
        let info = ConnectionInfo {
            id: uuid,
            metadata: Arc::new(metadata),
            counters: Arc::clone(&counters),
            start: chrono_now(),
            chains,
            rule,
            rule_payload,
        };
        self.connections.insert(uuid, info);
        (uuid, counters)
    }

    /// Select the lighter connection registry before listeners start. The
    /// default remains full tracking for embedders and API consumers.
    pub fn set_headless(&self) {
        assert!(self.connections.is_empty());
        assert!(self.headless_connections.set(DashMap::new()).is_ok());
    }

    /// Whether [`Self::set_headless`] dropped the API-visible registry.
    pub fn is_headless(&self) -> bool {
        self.headless_connections.get().is_some()
    }

    pub(crate) fn begin_headless_connection(&self) -> Option<Arc<ConnCounters>> {
        let connections = self.headless_connections.get()?;
        let counters = Arc::new(ConnCounters::default());
        // The guard pins this allocation until after its Drop unregisters it.
        // Even after a reload drains the map, a stale guard keeps its address
        // from being reused by a new connection. The address is only a private
        // map key, never dereferenced, and has no cumulative ID limit on 32-bit.
        connections.insert(Arc::as_ptr(&counters).addr(), Arc::clone(&counters));
        Some(counters)
    }

    pub(crate) fn close_headless_connection(&self, counters: &Arc<ConnCounters>) {
        // Borrow the owning Arc so the key cannot outlive its allocation.
        let key = Arc::as_ptr(counters).addr();
        if let Some((_, counters)) = self
            .headless_connections
            .get()
            .and_then(|connections| connections.remove(&key))
        {
            counters.close();
        }
    }

    /// Signal the owner to drop its dial/relay future and remove the entry.
    pub fn close_connection(&self, id: Uuid) {
        if let Some((_, info)) = self.connections.remove(&id) {
            info.counters.close();
            self.remember_closed(info);
        }
    }

    /// File a connection that left the live table into the recently-closed
    /// ring, if it recorded notes. The notes stay shared with the
    /// connection task, so a close reason noted after removal (an API
    /// close, a reload) still shows up.
    fn remember_closed(&self, info: ConnectionInfo) {
        if info.counters.notes.is_none() {
            return;
        }
        let closed = ClosedConnection {
            info,
            end: chrono_now(),
        };
        let mut ring = self.recently_closed.lock();
        if ring.len() == RECENTLY_CLOSED_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(closed);
    }

    /// Closed connections that recorded notes, newest first.
    pub fn recently_closed(&self) -> Vec<ConnectionDetail> {
        self.recently_closed
            .lock()
            .iter()
            .rev()
            .map(|closed| ConnectionDetail {
                info: closed.info.clone(),
                closed: true,
                end: Some(closed.end.clone()),
                notes: NotesField(closed.info.counters.notes.clone()),
            })
            .collect()
    }

    /// A live or recently closed connection by id, with its notes.
    /// `None` once a closed connection has aged out of the ring, and for
    /// closed connections that recorded no notes.
    pub fn connection_detail(&self, id: Uuid) -> Option<ConnectionDetail> {
        if let Some(entry) = self.connections.get(&id) {
            let info = entry.value().clone();
            drop(entry);
            let notes = NotesField(info.counters.notes.clone());
            return Some(ConnectionDetail {
                info,
                closed: false,
                end: None,
                notes,
            });
        }
        let ring = self.recently_closed.lock();
        let closed = ring.iter().rev().find(|closed| closed.info.id == id)?;
        Some(ConnectionDetail {
            info: closed.info.clone(),
            closed: true,
            end: Some(closed.end.clone()),
            notes: NotesField(closed.info.counters.notes.clone()),
        })
    }

    /// Live cumulative `(upload, download)` totals, read straight from the
    /// hot-path counters. Each counter is a single monotonic atomic — no
    /// lock, no split between sampled and unsampled parts — so the values are
    /// exact and monotonic per direction.
    pub fn snapshot(&self) -> (Int, Int) {
        (
            self.upload_total.load(Ordering::Relaxed),
            self.download_total.load(Ordering::Relaxed),
        )
    }

    /// Number of API-tracked connections. Headless cancellation handles are
    /// excluded, so this can return zero while headless TCP flows are live.
    pub fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn active_connections(&self) -> Vec<ConnectionInfo> {
        self.connections.iter().map(|e| e.value().clone()).collect()
    }

    /// Borrow-serializing view over the active-connections table.
    ///
    /// Serialises each entry in place while iterating the DashMap — no
    /// per-call `Vec` clone, no intermediate `serde_json::Value` tree.
    /// Shard read locks are held per entry during serialization, the same
    /// window the clone in [`Self::active_connections`] holds them.
    pub fn active_connections_view(&self) -> ActiveConnectionsView<'_> {
        ActiveConnectionsView(self)
    }

    pub fn close_all_connections(&self) {
        self.close_all_connections_counted();
    }

    /// Request closure of all tracked TCP connections and remove their entries.
    /// Returns the number of closure requests, not completed socket teardowns.
    pub fn close_all_connections_counted(&self) -> usize {
        let mut closed = 0;
        // Signal and remove under the same shard lock. A separate iteration
        // followed by clear could erase newly inserted, unsignalled entries.
        let mut noted = Vec::new();
        self.connections.retain(|_, info| {
            info.counters.close();
            closed += 1;
            if info.counters.notes.is_some() {
                noted.push(info.clone());
            }
            false
        });
        for info in noted {
            self.remember_closed(info);
        }
        if let Some(connections) = self.headless_connections.get() {
            connections.retain(|_, counters| {
                counters.close();
                closed += 1;
                false
            });
        }
        closed
    }
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}

/// `dialer-proxy` front hops count into the same per-proxy totals, never
/// into the tunnel totals: the connection they carry is already counted
/// there once.
impl ProxyTrafficSource for Statistics {
    fn proxy_counters(&self, proxy: &str) -> Option<Arc<ProxyTraffic>> {
        Statistics::proxy_counters(self, proxy)
    }
}

/// See [`Statistics::active_connections_view`].
pub struct ActiveConnectionsView<'a>(&'a Statistics);

impl Serialize for ActiveConnectionsView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.connections.iter().map(EntryRef))
    }
}

/// Wraps a DashMap entry guard so `collect_seq` can serialize the borrowed
/// `ConnectionInfo` without cloning it out of the map.
struct EntryRef<'a>(dashmap::mapref::multiple::RefMulti<'a, Uuid, ConnectionInfo>);

impl Serialize for EntryRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.value().serialize(serializer)
    }
}

fn chrono_now() -> SmolStr {
    use time::format_description::well_known::Rfc3339;

    // Seconds precision is sufficient for mihomo's connection API and keeps
    // the 20-byte RFC 3339 value inline in `SmolStr`. Formatting into a stack
    // buffer also avoids allocating an intermediate `String` on this hot path.
    let now = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let mut buffer = TimestampBuffer::default();
    if now.format_into(&mut buffer, &Rfc3339).is_ok() {
        if let Ok(value) = std::str::from_utf8(&buffer.bytes[..buffer.len]) {
            return SmolStr::new(value);
        }
    }

    SmolStr::new_static("1970-01-01T00:00:00Z")
}

#[derive(Default)]
struct TimestampBuffer {
    bytes: [u8; 32],
    len: usize,
}

impl std::io::Write for TimestampBuffer {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let end = self.len.saturating_add(input.len());
        if end > self.bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "timestamp exceeds fixed buffer",
            ));
        }
        self.bytes[self.len..end].copy_from_slice(input);
        self.len = end;
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
