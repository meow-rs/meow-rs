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

use crate::app_lookup;
use dashmap::DashMap;
use meow_common::atomic::{AtomicI, Int};
use meow_common::conn_notes::ConnNotes;
pub use meow_common::traffic::ProxyTraffic;
use meow_common::traffic::ProxyTrafficSource;
use meow_common::traffic_ledger::{self, Route};
use meow_common::{Metadata, Proxy};
use parking_lot::Mutex;
use serde::Serialize;
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    /// Where the traffic ledger files this flow, while it records.
    ledger: Option<LedgerTag>,
}

/// A flow's row in the traffic ledger (`meow_common::traffic_ledger`): its
/// host, app and route (leaf proxy and `dialer-proxy` hop), and how much
/// of its counters the ledger has had. The ledger takes the rest every
/// minute and as the flow ends, never per chunk.
#[derive(Debug)]
struct LedgerTag {
    host: SmolStr,
    route: Route,
    /// Unset while the app of a flow from this host is looked up off its
    /// path ([`crate::app_lookup`]): the counters keep what it carries
    /// until then.
    app: OnceLock<SmolStr>,
    /// A UDP flow is a request once it sends, not as it opens, so a dial
    /// that lost the race for its NAT entry, or was flushed, is none.
    udp: bool,
    /// A connection's request, until it settles with its app known.
    owed: AtomicBool,
    /// The [`traffic_ledger::epoch`] the flow last settled under.
    epoch: AtomicU32,
    settled_upload: AtomicI,
    settled_download: AtomicI,
}

impl LedgerTag {
    /// The tag of a flow to `metadata`'s destination through `route`, or
    /// `None` while the ledger is off or the flow has no leaf; with the
    /// socket whose owner names its app when that takes a lookup.
    fn new(
        metadata: &Metadata,
        udp: bool,
        route: impl FnOnce() -> Option<Route>,
    ) -> Option<(Self, Option<SocketAddr>)> {
        if !traffic_ledger::enabled() {
            return None;
        }
        let host = if !traffic_ledger::hosts() {
            SmolStr::default()
        } else if !metadata.host.is_empty() {
            metadata.host.clone()
        } else if let Some(ip) = metadata.dst_ip {
            smol_str::format_smolstr!("{ip}")
        } else {
            SmolStr::default()
        };
        let app = OnceLock::new();
        let mut lookup = None;
        if !traffic_ledger::apps() {
            let _ = app.set(SmolStr::default());
        } else if !metadata.process.is_empty() || !metadata.process_path.is_empty() {
            let _ = app.set(traffic_ledger::app_name(
                &metadata.process,
                &metadata.process_path,
            ));
        } else {
            lookup = app_lookup::local_socket(metadata);
            if lookup.is_none() {
                let _ = app.set(SmolStr::default());
            }
        }
        let tag = Self {
            host,
            route: route()?,
            app,
            udp,
            owed: AtomicBool::new(!udp),
            epoch: AtomicU32::new(traffic_ledger::epoch()),
            settled_upload: AtomicI::new(0),
            settled_download: AtomicI::new(0),
        };
        Some((tag, lookup))
    }
}

/// What `count` gained since `settled`, marking it settled, and whether
/// this is the settle that took its first bytes. Racing settlers each take
/// a disjoint part; one alone takes the first bytes.
fn unsettled(count: &AtomicI, settled: &AtomicI) -> (u64, bool) {
    let now = count.load(Ordering::Relaxed);
    let before = settled.fetch_max(now, Ordering::Relaxed);
    (
        u64::try_from(now.saturating_sub(before)).unwrap_or(0),
        before == 0 && now > 0,
    )
}

impl ConnCounters {
    /// The counters of a flow to `metadata`'s destination, filed in the
    /// traffic ledger through `route` while it records (see
    /// [`LedgerTag::new`]). A connection is a request there as it opens
    /// and its app is known, a UDP flow once it sends.
    fn filed(
        notes: Option<ConnNotes>,
        proxy: Option<Arc<ProxyTraffic>>,
        metadata: &Metadata,
        udp: bool,
        route: impl FnOnce() -> Option<Route>,
    ) -> Arc<Self> {
        let (ledger, lookup) = LedgerTag::new(metadata, udp, route)
            .map_or((None, None), |(tag, lookup)| (Some(tag), lookup));
        let counters = Arc::new(Self {
            upload: AtomicI::new(0),
            download: AtomicI::new(0),
            closed: AtomicBool::new(false),
            close_notify: tokio::sync::Notify::new(),
            notes,
            proxy,
            ledger,
        });
        // A connection whose app is known is a request now.
        counters.settle_ledger();
        if let Some(local) = lookup {
            app_lookup::submit(metadata.network, local, &counters);
        }
        counters
    }

    /// The app [`app_lookup`] found for this flow, empty for none. The
    /// flow settles at once: what it carried while its app was looked up
    /// reaches the ledger even if it closed meanwhile, as nothing else may
    /// settle it again (a closed connection the notes keep).
    pub(crate) fn resolve_app(&self, app: SmolStr) {
        if self
            .ledger
            .as_ref()
            .is_some_and(|tag| tag.app.set(app).is_ok())
        {
            self.settle_ledger();
        }
    }

    /// Hand the traffic ledger what this flow carried since it last did; a
    /// connection is a request with its first settle, a UDP flow with its
    /// first bytes sent. Nothing while its app is looked up, unless the
    /// ledger dropped everything since the last settle (a clear): then what
    /// the flow carried until now, and its request, go with it.
    fn settle_ledger(&self) {
        let Some(tag) = &self.ledger else {
            return;
        };
        // Read before the bytes are taken, so a clear or a label change
        // landing meanwhile cannot file them as carried after it.
        let mark = traffic_ledger::mark();
        let epoch = mark.epoch();
        if tag.epoch.swap(epoch, Ordering::Relaxed) != epoch {
            unsettled(&self.upload, &tag.settled_upload);
            unsettled(&self.download, &tag.settled_download);
            tag.owed.store(false, Ordering::Relaxed);
            return;
        }
        let Some(app) = tag.app.get() else {
            return;
        };
        let (upload, sent) = unsettled(&self.upload, &tag.settled_upload);
        let (download, _) = unsettled(&self.download, &tag.settled_download);
        let requests = if tag.udp {
            sent
        } else {
            tag.owed.swap(false, Ordering::Relaxed)
        };
        mark.add(
            &tag.host,
            app,
            &tag.route,
            upload,
            download,
            u64::from(requests),
        );
    }

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

impl Drop for ConnCounters {
    /// What the flow carried after it left the tables (bytes still in
    /// flight as it was closed) reaches the ledger as the last handle goes.
    fn drop(&mut self) {
        self.settle_ledger();
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
    /// Live UDP flows the traffic ledger files, by counters address, so a
    /// settle reaches them as it reaches the connections.
    udp_flows: DashMap<usize, Arc<ConnCounters>>,
    /// Proxy names the traffic ledger filed with no
    /// [`Self::proxy_traffic`] entry to share them from: every one while
    /// headless, and `dialer-proxy` members yet to carry a hop.
    ledger_names: DashMap<Arc<str>, ()>,
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
            udp_flows: DashMap::new(),
            ledger_names: DashMap::new(),
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

    /// `proxy`'s name as one shared allocation — its totals' key, or while
    /// headless a copy kept for the ledger — so a flow's ledger tag
    /// allocates nothing of its own.
    pub(crate) fn proxy_name(&self, proxy: &str) -> Arc<str> {
        if let Some(entry) = self.proxy_traffic.get(proxy) {
            return Arc::clone(entry.key());
        }
        if let Some(entry) = self.ledger_names.get(proxy) {
            return Arc::clone(entry.key());
        }
        Arc::clone(self.ledger_names.entry(Arc::from(proxy)).or_default().key())
    }

    /// The ledger route of a flow through the leaf proxy `policy` whose
    /// `dialer-proxy` hop `via` carries.
    pub(crate) fn route(&self, policy: Arc<str>, via: Option<Arc<dyn Proxy>>) -> Route {
        Route {
            policy,
            via: via.map(|hop| self.proxy_name(hop.name())),
        }
    }

    /// Counters for a UDP flow through the leaf proxy `leaf`, whose
    /// `dialer-proxy` hop `via` carries: the proxy's totals, and the
    /// flow's row in the traffic ledger while it records. End it with
    /// [`Self::end_udp_flow`].
    pub(crate) fn begin_udp_flow(
        &self,
        leaf: &str,
        via: impl FnOnce() -> Option<Arc<dyn Proxy>>,
        metadata: &Metadata,
    ) -> Arc<ConnCounters> {
        let proxy = self.proxy_counters(leaf);
        let counters = ConnCounters::filed(None, proxy, metadata, true, || {
            Some(self.route(self.proxy_name(leaf), via()))
        });
        if counters.ledger.is_some() {
            self.udp_flows
                .insert(Arc::as_ptr(&counters).addr(), Arc::clone(&counters));
        }
        counters
    }

    /// See [`Self::begin_udp_flow`].
    pub(crate) fn end_udp_flow(&self, counters: &Arc<ConnCounters>) {
        self.udp_flows.remove(&Arc::as_ptr(counters).addr());
        counters.settle_ledger();
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
        self.track_connection_with_counters(metadata, rule, rule_payload, chains, None, || None)
            .0
    }

    pub(crate) fn track_connection_with_counters(
        &self,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
        notes: Option<ConnNotes>,
        via: impl FnOnce() -> Option<Arc<dyn Proxy>>,
    ) -> (Uuid, Arc<ConnCounters>) {
        let uuid = Uuid::new_v4();
        let counters = ConnCounters::filed(
            notes,
            chains.first().and_then(|leaf| self.proxy_counters(leaf)),
            &metadata,
            false,
            || Some(self.route(Arc::clone(chains.first()?), via())),
        );
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

    /// Register a headless connection to `metadata`'s destination, filed in
    /// the traffic ledger through `route`; `None` when not headless.
    pub(crate) fn begin_headless_connection(
        &self,
        metadata: &Metadata,
        route: impl FnOnce() -> Option<Route>,
    ) -> Option<Arc<ConnCounters>> {
        let connections = self.headless_connections.get()?;
        let counters = ConnCounters::filed(None, None, metadata, false, route);
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
            counters.settle_ledger();
        }
    }

    /// Signal the owner to drop its dial/relay future and remove the entry.
    pub fn close_connection(&self, id: Uuid) {
        if let Some((_, info)) = self.connections.remove(&id) {
            info.counters.close();
            info.counters.settle_ledger();
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
            info.counters.settle_ledger();
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
                counters.settle_ledger();
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

/// The ledger settles the connections and UDP flows of every live tunnel
/// before it writes.
impl traffic_ledger::Source for Statistics {
    fn settle(&self) {
        for entry in &self.connections {
            entry.counters.settle_ledger();
        }
        if let Some(connections) = self.headless_connections.get() {
            for entry in connections {
                entry.value().settle_ledger();
            }
        }
        for entry in &self.udp_flows {
            entry.value().settle_ledger();
        }
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

#[cfg(test)]
mod ledger_tests {
    use super::*;
    use meow_common::traffic_ledger::{self, GroupBy, Options, Query};

    /// The counters of a connection whose app is being looked up, and that
    /// no table holds: one that closed while the notes keep it.
    fn looked_up(host: &str) -> Arc<ConnCounters> {
        let metadata = Metadata {
            host: host.into(),
            ..Metadata::default()
        };
        let (mut tag, _) =
            LedgerTag::new(&metadata, false, || Some(Route::from("DIRECT"))).unwrap();
        tag.app = OnceLock::new();
        Arc::new(ConnCounters {
            upload: AtomicI::new(0),
            download: AtomicI::new(0),
            closed: AtomicBool::new(true),
            close_notify: tokio::sync::Notify::new(),
            notes: None,
            proxy: None,
            ledger: Some(tag),
        })
    }

    fn apps(host: &str) -> Vec<(String, u64, u64)> {
        report(host, GroupBy::App)
            .rows
            .into_iter()
            .map(|row| (row.name, row.upload, row.requests))
            .collect()
    }

    fn report(host: &str, by: GroupBy) -> traffic_ledger::Report {
        let today = traffic_ledger::today();
        traffic_ledger::query(&Query {
            from: today - 1,
            to: today,
            by,
            host: Some(host.into()),
            ..Query::default()
        })
        .unwrap()
        .unwrap()
    }

    /// A round-robin front in miniature: a dial commits the member
    /// `dialer_hop` peeks, so the next peek names the next one.
    struct RoundRobinHop {
        picks: std::sync::atomic::AtomicUsize,
        members: [Arc<dyn Proxy>; 2],
        health: meow_common::ProxyHealth,
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for RoundRobinHop {
        fn name(&self) -> &str {
            "Ledger Round Robin"
        }
        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Shadowsocks
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            true
        }
        async fn dial_tcp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            Err(meow_common::MeowError::NotSupported("tcp".into()))
        }
        async fn dial_udp(
            &self,
            metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            self.picks.fetch_add(1, Ordering::Relaxed);
            // REJECT's conn reports each write sent.
            meow_proxy::RejectAdapter::new(false)
                .dial_udp(metadata)
                .await
        }
        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
        fn dialer_hop(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
            let pick = self.picks.load(Ordering::Relaxed) % self.members.len();
            Some(Arc::clone(&self.members[pick]))
        }
    }

    #[test]
    fn connections_and_udp_flows_reach_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        traffic_ledger::install(dir.path(), Options::default()).unwrap();
        let stats = Arc::new(Statistics::new());
        let source: Arc<dyn traffic_ledger::Source> = Arc::clone(&stats) as _;
        traffic_ledger::register(Arc::downgrade(&source));

        let metadata = Metadata {
            host: "video.ledger-test.example".into(),
            ..Metadata::default()
        };
        let chains: SmallVec<[Arc<str>; 1]> =
            smallvec::smallvec![Arc::from("Ledger Node"), Arc::from("Auto")];
        let (id, counters) = stats.track_connection_with_counters(
            metadata,
            "MATCH".into(),
            "".into(),
            chains,
            None,
            || None,
        );
        stats.record_upload(&counters, 100);
        stats.record_download(&counters, 1000);
        // A query settles the live connection.
        let live = report("ledger-test.example", GroupBy::Policy);
        assert_eq!(live.rows.len(), 1);
        assert_eq!(live.rows[0].name, "Ledger Node");
        assert_eq!((live.upload, live.download, live.requests), (100, 1000, 1));

        // Bytes after the close still reach it as the last handle goes.
        stats.close_connection(id);
        stats.record_download(&counters, 24);
        drop(counters);

        let udp = Metadata {
            dst_ip: Some("198.51.100.7".parse().unwrap()),
            ..Metadata::default()
        };
        let flow = stats.begin_udp_flow("DIRECT", || None, &udp);
        stats.record_upload(&flow, 4);
        // A UDP flow is one request however often it settles.
        assert_eq!(report("198.51.100.7", GroupBy::Host).requests, 1);
        stats.record_upload(&flow, 3);
        stats.end_udp_flow(&flow);
        drop(flow);
        // One that never sent (a dial that lost the race for its NAT entry)
        // is none.
        let idle = Metadata {
            dst_ip: Some("198.51.100.8".parse().unwrap()),
            ..Metadata::default()
        };
        let lost = stats.begin_udp_flow("DIRECT", || None, &idle);
        stats.end_udp_flow(&lost);
        drop(lost);
        assert!(report("198.51.100.8", GroupBy::Host).rows.is_empty());

        // A chained outbound's flows count under the member that carried the
        // hop too, by policy only.
        let front: Arc<dyn Proxy> = Arc::new(meow_config::proxy_parser::WrappedProxy::new(
            Box::new(meow_proxy::HttpAdapter::new(
                "Ledger Front",
                "127.0.0.1",
                1,
                None,
                false,
                false,
                vec![],
                Arc::new(meow_proxy::dialer::DirectDialer),
            )),
        ));
        let chained = Metadata {
            host: "video.chained-ledger-test.example".into(),
            ..Metadata::default()
        };
        let chains: SmallVec<[Arc<str>; 1]> = smallvec::smallvec![Arc::from("Ledger Chained")];
        let (id, counters) = stats.track_connection_with_counters(
            chained,
            "MATCH".into(),
            "".into(),
            chains,
            None,
            || Some(Arc::clone(&front)),
        );
        stats.record_upload(&counters, 10);
        stats.record_download(&counters, 100);
        stats.close_connection(id);
        drop(counters);
        let chained_udp = Metadata {
            dst_ip: Some("198.51.100.9".parse().unwrap()),
            ..Metadata::default()
        };
        let flow =
            stats.begin_udp_flow("Ledger Chained", || Some(Arc::clone(&front)), &chained_udp);
        stats.record_upload(&flow, 2);
        stats.end_udp_flow(&flow);
        drop(flow);
        let policies = |host: &str| {
            let report = report(host, GroupBy::Policy);
            let rows: Vec<_> = report
                .rows
                .iter()
                .map(|row| {
                    (
                        row.name.clone(),
                        row.upload,
                        row.download,
                        row.via_upload,
                        row.via_requests,
                    )
                })
                .collect();
            (rows, (report.upload, report.download, report.requests))
        };
        assert_eq!(
            policies("chained-ledger-test.example"),
            (
                vec![
                    ("Ledger Chained".to_owned(), 10, 100, 0, 0),
                    ("Ledger Front".to_owned(), 10, 100, 10, 1),
                ],
                (10, 100, 1)
            )
        );
        assert_eq!(
            policies("198.51.100.9"),
            (
                vec![
                    ("Ledger Chained".to_owned(), 2, 0, 0, 0),
                    ("Ledger Front".to_owned(), 2, 0, 2, 1),
                ],
                (2, 0, 1)
            )
        );
        let hosts = report("chained-ledger-test.example", GroupBy::Host);
        assert_eq!(hosts.rows.len(), 1);
        assert_eq!((hosts.rows[0].upload, hosts.rows[0].via_upload), (10, 0));

        // A UDP flow names the member its dial took, not the one a
        // round-robin front has moved on to by the time the dial returns.
        let node = |name: &str| -> Arc<dyn Proxy> {
            Arc::new(meow_config::proxy_parser::WrappedProxy::new(Box::new(
                meow_proxy::HttpAdapter::new(
                    name,
                    "127.0.0.1",
                    1,
                    None,
                    false,
                    false,
                    vec![],
                    Arc::new(meow_proxy::dialer::DirectDialer),
                ),
            )))
        };
        let round_robin = RoundRobinHop {
            picks: std::sync::atomic::AtomicUsize::new(0),
            members: [node("Ledger RR-1"), node("Ledger RR-2")],
            health: meow_common::ProxyHealth::new(),
        };
        let tunnel = crate::Tunnel::new(Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        )));
        let target: SocketAddr = "198.51.100.10:443".parse().unwrap();
        let round_robin_udp = Metadata {
            network: meow_common::Network::Udp,
            dst_ip: Some(target.ip()),
            dst_port: target.port(),
            ..Metadata::default()
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let conn = tunnel
                    .inner()
                    .dial_udp(&round_robin, &round_robin_udp)
                    .await
                    .unwrap();
                conn.write_packet(b"rr!", &target).await.unwrap();
            });
        assert_eq!(round_robin.picks.load(Ordering::Relaxed), 1);
        assert_eq!(
            policies("198.51.100.10"),
            (
                vec![
                    ("Ledger RR-1".to_owned(), 3, 0, 3, 1),
                    ("Ledger Round Robin".to_owned(), 3, 0, 0, 0),
                ],
                (3, 0, 1)
            )
        );

        let tcp = report("ledger-test.example", GroupBy::Host);
        assert_eq!((tcp.upload, tcp.download, tcp.requests), (100, 1024, 1));
        let udp = report("198.51.100.7", GroupBy::Policy);
        assert_eq!(udp.rows[0].name, "DIRECT");
        assert_eq!((udp.upload, udp.download, udp.requests), (7, 0, 1));
        assert!(stats.udp_flows.is_empty());

        // A flow from this host is filed under the app that opened it, its
        // request and bytes held until the lookup names it.
        if meow_common::process_lookup::PROCESS_LOOKUP_SUPPORTED {
            meow_common::disable_socket_table_cache();
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let local = socket.local_addr().unwrap();
            let metadata = Metadata {
                host: "app-ledger-test.example".into(),
                conn_type: meow_common::ConnType::Http,
                src_ip: Some(local.ip()),
                src_port: local.port(),
                ..Metadata::default()
            };
            let chains: SmallVec<[Arc<str>; 1]> = smallvec::smallvec![Arc::from("DIRECT")];
            let (id, counters) = stats.track_connection_with_counters(
                metadata,
                "MATCH".into(),
                "".into(),
                chains,
                None,
                || None,
            );
            stats.record_upload(&counters, 5);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let apps = loop {
                let apps = report("app-ledger-test.example", GroupBy::App);
                if !apps.rows.is_empty() || std::time::Instant::now() > deadline {
                    break apps;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            let exe = std::env::current_exe().unwrap();
            let exe = exe.file_name().unwrap().to_string_lossy();
            let rows: Vec<_> = apps
                .rows
                .iter()
                .map(|row| (row.name.as_str(), row.upload, row.requests))
                .collect();
            assert_eq!(rows, [(&*exe, 5, 1)]);
            stats.close_connection(id);
        }

        // One that closed before its app was known is filed as it is.
        let closed = looked_up("www.closed-ledger-test.example");
        stats.record_upload(&closed, 50);
        closed.settle_ledger();
        assert!(apps("closed-ledger-test.example").is_empty(), "held");
        closed.resolve_app("org.example.app".into());
        assert_eq!(
            apps("closed-ledger-test.example"),
            [("org.example.app".to_owned(), 50, 1)]
        );

        // A clear while it is looked up drops what it carried until then,
        // and its request; what it carries after is counted.
        let cleared = looked_up("www.cleared-ledger-test.example");
        stats.record_upload(&cleared, 70);
        traffic_ledger::clear().unwrap();
        cleared.resolve_app("org.example.app".into());
        assert!(apps("cleared-ledger-test.example").is_empty());
        stats.record_upload(&cleared, 5);
        drop(cleared);
        assert_eq!(
            apps("cleared-ledger-test.example"),
            [("org.example.app".to_owned(), 5, 0)]
        );
        traffic_ledger::uninstall();
    }
}
