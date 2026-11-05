//! Rule-provider loader and runtime refresh (M1.D-5).
//!
//! Supports `http`, `file`, and `inline` provider types; `yaml`, `text`,
//! and `mrs` formats (auto-detected by magic bytes for http/file).
//! HTTP providers with `interval > 0` expose a `refresh()` method that is
//! called from per-provider tasks owned by
//! [`crate::rule_provider_refresh::RefreshSupervisor`].
//!
//! HTTP payloads load cache-first: a provider with an on-disk cache starts
//! from it without a request, and the ones without download concurrently
//! (bounded by [`crate::provider_fetch_deadline`]). Whatever the load left
//! owing — a cache to revalidate, an empty set to fill, a download still
//! running at the deadline — is fetched in the background once the provider
//! is committed ([`RuleProvider::spawn_initial_fetch`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use meow_common::adapter::Proxy;
use meow_common::atomic::AtomicU;
use meow_common::logbook::{self, Level};
use meow_common::{Metadata, RuleMatchHelper};
use meow_rules::{
    build_rule_set, build_rule_set_checked, build_rule_set_from_mrs_with_behavior, is_mrs_bytes,
    ParserContext, RuleSet, RuleSetBehavior, RuleSetFormat,
};
use parking_lot::RwLock;
use std::sync::atomic::Ordering;
use tracing::{debug, info, warn};

use crate::dropped_providers::DroppedProviders;
use crate::internal_http;
use crate::proxy_provider::{
    BACKGROUND_RETRY_MAX, BACKGROUND_RETRY_MIN, MAX_REVALIDATION_ATTEMPTS,
};
use crate::raw::RawRuleProvider;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    Http,
    File,
    Inline,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::File => write!(f, "file"),
            Self::Inline => write!(f, "inline"),
        }
    }
}

/// HTTP fetch context for http providers, captured at load time and reused
/// on every periodic `refresh()`: the download proxy (`None` = direct) and
/// the flattened custom request headers (name-sorted; one entry per value,
/// so multi-value headers repeat the name — RFC 9110 §5.2).
///
/// `_dialer_registry` retains the registry generation `proxy` was built from:
/// a provider object can outlive that generation — a geodata rules-only
/// rebuild binds the *live* providers into a fresh route table whose
/// dialers belong to a different generation — and a chained adapter's
/// `dialer-proxy` lookup resolves
/// through that cell weakly — without this keepalive its dials would fail
/// closed on the first refresh after a config reload (issue #533). The cell
/// pins that generation's *entire* snapshot map, not just this adapter —
/// bounded to one extra generation since a DNS rebuild swaps providers
/// wholesale and drops the old pin.
#[derive(Default)]
struct FetchContext {
    proxy: Option<Arc<dyn Proxy>>,
    headers: Vec<(String, String)>,
    _dialer_registry: Option<meow_proxy::dialer::ProxyRegistry>,
}

/// A loaded rule-provider. Cheap to share via `Arc`; rule-set reads are
/// protected by a short-held `RwLock` (just a pointer swap on write);
/// refresh parse work runs on a blocking thread (ADR-0008 §7 sub-area 3).
pub struct RuleProvider {
    pub name: String,
    pub provider_type: ProviderType,
    pub behavior: RuleSetBehavior,
    /// URL (http) or resolved path (file) for API display. Empty for inline.
    pub vehicle: String,
    /// Refresh interval in seconds. `0` = no background refresh.
    pub interval: u64,
    /// Unix timestamp (seconds) of last successful load/refresh.
    updated_at: AtomicU,
    rules: RwLock<Arc<dyn RuleSet>>,
    fetch: FetchContext,
    /// Top-level `strict: true` (issue #533): a malformed entry in a
    /// refreshed payload fails the parse — and thus the refresh — instead
    /// of being warn-skipped, so the last-good set stays installed rather
    /// than being replaced by a partial one.
    strict: bool,
    /// The parser context this provider was loaded with, retained so
    /// `refresh()` re-parses against the same geoip/geosite/asn handles —
    /// a `classical` payload containing GEOIP/GEOSITE entries must not
    /// degrade (lenient) or permanently fail (strict) just because the
    /// refresh caller handed in an empty context (issue #533 review).
    ctx: ParserContext,
    /// The declared `format:` (None = auto-detect from magic bytes).
    /// Retained for `refresh()` — a `format: text` file whose bytes aren't
    /// MRS must not be reparsed as YAML on refresh (issue #533 review).
    format: Option<RuleSetFormat>,
    /// What the installed payload parsed as, for [`Self::format`]: the
    /// declared format, except that MRS bytes parse as MRS whatever was
    /// declared. The declared format (YAML when undeclared) until a
    /// payload lands.
    payload_format: parking_lot::Mutex<RuleSetFormat>,
    /// Resolved on-disk cache location, http providers only (inside
    /// `cache_dir`; `None` when the build context has no cache directory).
    /// `refresh()` writes each successfully parsed payload here so a
    /// restart, which loads cache-first, starts from the newest refresh
    /// instead of the initial-load-era file (issue #543).
    cache_path: Option<PathBuf>,
    /// Serializes `write_cache` across concurrent `refresh()` calls —
    /// a supervisor tick and a `PUT /providers/rules/{name}` can run at
    /// once, and without ordering a slow writer carrying an older payload
    /// could win the rename last (issue #621). The `u64` is the highest
    /// refresh generation already persisted; an older generation
    /// acquiring the lock after a newer one wrote skips its write.
    cache_write_lock: Arc<parking_lot::Mutex<u64>>,
    /// Highest refresh generation installed into `self.rules`. A stale
    /// refresh that finishes parsing last must not regress live memory
    /// just because its cache write was already (correctly) skipped —
    /// file and memory stay on the same newest generation (issue #621).
    install_gen: parking_lot::Mutex<u64>,
    /// Monotonic refresh generation, taken after the awaited fetch.
    refresh_gen: meow_common::atomic::AtomicU,
    /// The remote fetch the load left owing, taken by
    /// [`Self::spawn_initial_fetch`] once the provider is committed.
    initial_fetch: parking_lot::Mutex<InitialFetch>,
    /// What the load has for the logbook, recorded once the provider is
    /// committed ([`Self::spawn_initial_fetch`]): a candidate that is built
    /// twice, or never committed, records nothing.
    load_note: parking_lot::Mutex<Option<LoadNote>>,
    /// Holds a payload: false only for the empty set a provider whose
    /// payload was unavailable is registered with, until one lands.
    filled: AtomicBool,
}

/// What a provider's load leaves for the logbook.
enum LoadNote {
    /// Registered empty: the payload was unavailable.
    Failed(String),
    /// Loaded a payload fetched or read for this load, not the on-disk
    /// cache: ends a failure the logbook shows.
    Fresh,
}

/// What an http provider's load left for the background to fetch.
enum InitialFetch {
    /// Loaded from a download (or not http): nothing owed.
    Settled,
    /// Serving its on-disk cache: refetch it, with bounded retries.
    Revalidate,
    /// Loaded empty: fetch until a payload lands.
    Retry,
    /// Loaded empty while its startup download was still running at the
    /// fetch deadline: adopt that download before fetching again.
    Adopt(PendingFetch),
}

impl std::fmt::Debug for RuleProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleProvider")
            .field("name", &self.name)
            .field("type", &self.provider_type)
            .field("behavior", &self.behavior)
            .finish()
    }
}

/// Live read-through: the provider *is* the `Arc<dyn RuleSet>` a `RULE-SET`
/// rule and the DNS `nameserver-policy` matcher hold (see
/// [`live_ruleset_map`]), so a `refresh()` — periodic or via
/// `PUT /providers/rules/{name}` — is observed by the very next match with
/// no config rebuild (issue #553).  Every call takes the `parking_lot` read
/// lock for the duration of the delegated call: two uncontended atomic ops,
/// no allocation and no `Arc` clone on the match path; `refresh()` swaps
/// the inner pointer under the write lock.
impl RuleSet for RuleProvider {
    fn behavior(&self) -> RuleSetBehavior {
        self.behavior
    }

    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules.read().matches(metadata, helper)
    }

    fn len(&self) -> usize {
        self.rules.read().len()
    }

    fn should_resolve_ip(&self) -> bool {
        self.rules.read().should_resolve_ip()
    }

    fn should_find_process(&self) -> bool {
        self.rules.read().should_find_process()
    }

    fn is_empty(&self) -> bool {
        self.rules.read().is_empty()
    }

    fn matches_domain(&self, domain: &str) -> bool {
        self.rules.read().matches_domain(domain)
    }
}

impl RuleProvider {
    /// Return a snapshot of the current rule set.
    ///
    /// A snapshot is detached from later `refresh()`es — anything that must
    /// keep following the provider (rules, DNS policy matchers) should hold
    /// the provider itself as its `Arc<dyn RuleSet>` instead (issue #553).
    pub fn snapshot(&self) -> Arc<dyn RuleSet> {
        self.rules.read().clone()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }

    /// The format this provider's rules come in: what its installed
    /// payload parsed as, or the declared `format:` (YAML when
    /// undeclared) before one has landed. MRS is detected from the bytes,
    /// so a payload that turns out to be MRS reports MRS whatever the
    /// config declared.
    pub fn format(&self) -> RuleSetFormat {
        *self.payload_format.lock()
    }

    pub fn updated_at_secs(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.updated_at.load(Ordering::Relaxed).into()
    }

    /// Fetch a fresh payload and swap the rule set atomically: http
    /// providers re-download through their captured fetch context, file
    /// providers re-read their resolved path, inline providers are a no-op.
    /// Parse work runs on a blocking thread so the tokio executor is not
    /// stalled. On any failure the last-good set stays installed; under
    /// `strict` a malformed entry fails the whole parse instead of being
    /// warn-skipped (issue #533).
    ///
    /// The payload is re-parsed in the *load-time* parser context
    /// (`self.ctx`): geo-dependent entries resolve against the same geo
    /// databases the initial load saw. Refresh callers therefore cannot
    /// accidentally pass a different (e.g. empty) context.
    pub async fn refresh(&self) -> Result<()> {
        let refreshed = self.fetch_and_install().await;
        if let Err(e) = &refreshed {
            self.logbook_failed(&format!("{e:#}"));
        }
        refreshed
    }

    async fn fetch_and_install(&self) -> Result<()> {
        let bytes = match self.provider_type {
            ProviderType::Http => {
                fetch_http_async(
                    &self.vehicle,
                    self.fetch.proxy.as_ref(),
                    &self.fetch.headers,
                )
                .await?
            }
            ProviderType::File => tokio::fs::read(&self.vehicle)
                .await
                .with_context(|| format!("reading provider file {}", self.vehicle))?,
            ProviderType::Inline => return Ok(()),
        };
        // Generation taken when the fetch completes: under the write lock
        // an older refresh that finishes after a newer one already wrote
        // skips its own write, so the file never regresses (issue #621).
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; narrows u64 on targets without 64-bit atomics"
        )]
        let gen: u64 = self.refresh_gen.fetch_add(1, Ordering::Relaxed).into();
        self.install_payload(Arc::new(bytes), gen).await
    }

    /// Install the startup download a deadline left running. `Ok(false)`
    /// when a refresh has already finished fetching: its payload is newer,
    /// since the startup download began before any refresh did.
    async fn adopt_download(&self, bytes: Arc<Vec<u8>>) -> Result<bool> {
        if self
            .refresh_gen
            .compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return Ok(false);
        }
        self.install_payload(bytes, 1).await.map(|()| true)
    }

    /// Parse fetched payload bytes on a blocking thread, persist them, and
    /// install them as refresh generation `gen`.
    async fn install_payload(&self, bytes: Arc<Vec<u8>>, gen: u64) -> Result<()> {
        let behavior = self.behavior;
        let strict = self.strict;
        let ctx_clone = self.ctx.clone();
        let format = self.format;
        let cache_path = self.cache_path.clone();
        let cache_write_lock = Arc::clone(&self.cache_write_lock);
        let (boxed, parsed_as) = crate::spawn_blocking_with_current_dispatcher(move || {
            let parsed =
                parse_bytes_to_ruleset_with_format(&bytes, behavior, format, &ctx_clone, strict)?;
            // Persist the payload only *after* the parse succeeds so the
            // cache always holds the last usable payload — a cache-first
            // restart then picks up the newest refresh rather than the
            // initial-load-era file (issue #543). The
            // write+rename runs on this blocking thread: synchronous fs
            // I/O on the async worker can stall the executor (issue #621).
            if let Some(path) = &cache_path {
                let mut written_gen = cache_write_lock.lock();
                if *written_gen < gen && write_cache(path, &bytes) {
                    *written_gen = gen;
                }
            }
            Ok::<_, anyhow::Error>(parsed)
        })
        .await
        .map_err(|e| anyhow!("parse task panicked: {e}"))??;
        let count = boxed.len();
        let new_rules: Arc<dyn RuleSet> = Arc::from(boxed);
        // The compiled rule table bakes each RULE-SET slot's "needs IP /
        // needs process" demand at build time; behavior is fixed per
        // provider, so only a classical set gaining or losing IP / PROCESS
        // entries can move them. Say so instead of silently matching with
        // stale demands until the next reload.
        let demands = |set: &dyn RuleSet| (set.should_resolve_ip(), set.should_find_process());
        // Install only the newest completed generation: two unlaned
        // refreshes (supervisor tick vs `PUT /providers/rules/{name}`) can
        // finish out of order, and without this gate the stale one's rules
        // would overwrite live memory even though its cache write was
        // already skipped (issue #621 review).
        let mut installed = self.install_gen.lock();
        if *installed >= gen {
            debug!(
                provider = %self.name,
                "rule-provider refresh gen {gen} superseded; not installing"
            );
            return Ok(());
        }
        let previous = self
            .filled
            .swap(true, Ordering::Relaxed)
            .then(|| self.rules.read().len());
        if demands(&**self.rules.read()) != demands(&*new_rules) {
            warn!(
                provider = %self.name,
                "rule-provider refresh changed whether the set needs IP resolution or \
                 process lookup; live RULE-SET rules keep the previous demand flags \
                 until the next config reload (entries requiring the new demand \
                 cannot fire until then — and inside a SUB-RULE block, the \
                 resolution gate can skip the whole block while metadata is \
                 unresolved)"
            );
        }
        *self.rules.write() = new_rules;
        *self.payload_format.lock() = parsed_as;
        *installed = gen;
        self.touch();
        debug!(provider = %self.name, "rule-provider refreshed: {} rules", count);
        self.logbook_updated(previous, count);
        Ok(())
    }

    /// Logbook: a payload of `count` rules replaced `previous` ones, or
    /// filled the provider (`None`).
    fn logbook_updated(&self, previous: Option<usize>, count: usize) {
        let name = &self.name;
        let failing = || logbook::failing(logbook::kind::RULE_PROVIDER_UPDATE, name);
        if let Some(message) = update_message(name, previous, count, failing) {
            logbook::event(logbook::kind::RULE_PROVIDER_UPDATE, Level::Info, message)
                .subject(name.as_str())
                .field("rules", count)
                .record();
        }
    }

    /// Logbook: fetching or parsing the payload failed. Repeats fold while
    /// the provider keeps failing.
    fn logbook_failed(&self, error: &str) {
        record_failure(&self.name, error);
    }

    /// Fetch, on a detached task, whatever remote payload this provider's
    /// load left owing:
    ///
    /// - serving its on-disk cache: refetch it, retrying with backoff up to
    ///   `MAX_REVALIDATION_ATTEMPTS` times, then leave it to the `interval`
    ///   loop with the cached rules installed;
    /// - loaded empty: retry with backoff (5 s doubling to 5 min) until a
    ///   payload lands;
    /// - its startup download was still running at the fetch deadline: wait
    ///   for that download first, so it is not requested twice.
    ///
    /// Ends early once any refresh — an `interval` tick or a manual one —
    /// installs a remote payload, and holds only a `Weak` between attempts,
    /// so a provider dropped by a config commit ends it. The obligation is
    /// taken, so this spawns at most once per provider: `None` when nothing
    /// is owed. A load failure is recorded here too, once. [`crate::rule_provider_refresh::RefreshSupervisor::reconcile`]
    /// calls it for every committed provider.
    pub fn spawn_initial_fetch(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        match self.load_note.lock().take() {
            Some(LoadNote::Failed(error)) => self.logbook_failed(&error),
            Some(LoadNote::Fresh) => self.logbook_updated(None, self.rule_count()),
            None => {}
        }
        let owed = std::mem::replace(&mut *self.initial_fetch.lock(), InitialFetch::Settled);
        if matches!(owed, InitialFetch::Settled) {
            return None;
        }
        Some(tokio::spawn(initial_fetch_loop(Arc::downgrade(self), owed)))
    }

    fn owe(&self, owed: InitialFetch) {
        *self.initial_fetch.lock() = owed;
    }

    /// Whether a refresh has installed a remote payload yet.
    fn fetched_remote(&self) -> bool {
        *self.install_gen.lock() > 0
    }

    fn touch(&self) {
        self.set_updated_at(SystemTime::now());
    }

    fn set_updated_at(&self, at: SystemTime) {
        let secs = at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.updated_at
            .store(secs as meow_common::atomic::Uint, Ordering::Relaxed);
    }

    /// Atomically install a freshly-parsed rule set (initial fill after an
    /// acquisition-then-parse load, or a refresh), with the format its
    /// payload parsed as.
    fn swap_rules(&self, (rules, format): (Box<dyn RuleSet>, RuleSetFormat)) {
        *self.rules.write() = Arc::from(rules);
        *self.payload_format.lock() = format;
        self.filled.store(true, Ordering::Relaxed);
        self.touch();
    }

    /// [`Self::swap_rules`] with a payload fetched or read for this load.
    fn fill_fresh(&self, parsed: (Box<dyn RuleSet>, RuleSetFormat)) {
        self.swap_rules(parsed);
        *self.load_note.lock() = Some(LoadNote::Fresh);
    }
}

/// The logbook message for a payload of `count` rules that replaced
/// `previous` ones, or filled the provider (`None`); `None` when there is
/// nothing to record. Recorded when the count changed, or when the update
/// ends a failure the logbook shows (`failing`): filling a provider is its
/// load, and a refresh that keeps the count is routine — providers refresh
/// daily in the dozens.
fn update_message(
    name: &str,
    previous: Option<usize>,
    count: usize,
    failing: impl FnOnce() -> bool,
) -> Option<String> {
    match previous {
        Some(previous) if previous != count => Some(format!(
            "Updated rule provider '{name}': {count} rules (was {previous})"
        )),
        _ if failing() => Some(format!("Updated rule provider '{name}': {count} rules")),
        _ => None,
    }
}

async fn initial_fetch_loop(provider: Weak<RuleProvider>, owed: InitialFetch) {
    let bounded = matches!(owed, InitialFetch::Revalidate);
    let mut delay = BACKGROUND_RETRY_MIN;
    if let InitialFetch::Adopt(pending) = owed {
        let outcome = pending.wait().await;
        let Some(p) = provider.upgrade() else {
            return;
        };
        match outcome {
            Ok(bytes) => match p.adopt_download(bytes).await {
                Ok(true) => {
                    info!(provider = %p.name, "rule-provider download finished in the background");
                    return;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(provider = %p.name, "rule-provider payload rejected: {e:#}");
                    p.logbook_failed(&format!("{e:#}"));
                }
            },
            Err(e) => {
                warn!(provider = %p.name, "rule-provider download failed: {e}");
                p.logbook_failed(&e);
            }
        }
        // A finished-but-failed download was the first attempt: back off
        // before the next one. Superseded means a refresh already fetched.
        if !p.fetched_remote() {
            drop(p);
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(BACKGROUND_RETRY_MAX);
        }
    }
    let mut failed_revalidations = 0;
    loop {
        let Some(p) = provider.upgrade() else {
            return;
        };
        if p.fetched_remote() {
            return;
        }
        let Err(e) = p.refresh().await else {
            return;
        };
        if bounded {
            failed_revalidations += 1;
            if failed_revalidations >= MAX_REVALIDATION_ATTEMPTS {
                warn!(provider = %p.name,
                    "rule-provider refetch failed; keeping the cached rules until the next refresh: {e:#}");
                return;
            }
        }
        warn!(provider = %p.name, retry_in = ?delay, "rule-provider fetch failed; retrying: {e:#}");
        drop(p);
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(BACKGROUND_RETRY_MAX);
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Payloads of file/http rule-providers, acquired once per (re)load and keyed
/// by provider name. Reused for both the geo-allowlist scan (issue #277) and
/// the provider parse passes, so each payload is fetched at most once per
/// (re)load: a failed download is recorded too, and the later passes
/// register that provider empty instead of fetching it again. Inline
/// providers never appear here — their payload lives in the raw config.
#[derive(Default)]
pub struct PrefetchedPayloads {
    entries: HashMap<String, Prefetched>,
}

impl PrefetchedPayloads {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `bytes` as `name`'s payload; the load passes parse it as-is.
    pub fn insert(&mut self, name: String, bytes: Vec<u8>) {
        self.entries.insert(name, Prefetched::Fresh(bytes));
    }

    /// Every acquired payload. Failed and still-running downloads have none.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .filter_map(|(name, entry)| Some((name.as_str(), entry.bytes()?)))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// How [`prefetch_payloads`] acquired one provider's payload.
enum Prefetched {
    /// Bytes parsed as-is: a `file` payload, or one a caller supplied.
    Fresh(Vec<u8>),
    /// An http download that just completed. The first load pass that
    /// parses it writes the provider's cache, so the cache only ever holds
    /// a payload that parsed.
    Downloaded {
        bytes: Vec<u8>,
        persisted: AtomicBool,
    },
    /// An http provider's on-disk cache, read without a request.
    Cached {
        bytes: Vec<u8>,
        modified: Option<SystemTime>,
    },
    /// The download failed; the load pass reports it.
    Failed(String),
    /// Still downloading at the fetch deadline.
    Pending(PendingFetch),
}

impl Prefetched {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Fresh(bytes) | Self::Downloaded { bytes, .. } | Self::Cached { bytes, .. } => {
                Some(bytes)
            }
            Self::Failed(_) | Self::Pending(_) => None,
        }
    }
}

type DownloadResult = Result<Arc<Vec<u8>>, Arc<str>>;

/// A download the fetch deadline left running. It keeps going on its own
/// thread; the provider built for it adopts the result when it lands.
#[derive(Clone)]
struct PendingFetch(tokio::sync::watch::Receiver<Option<DownloadResult>>);

impl PendingFetch {
    async fn wait(mut self) -> DownloadResult {
        match self.0.wait_for(Option::is_some).await {
            Ok(result) => result
                .clone()
                .unwrap_or_else(|| unreachable!("waited for Some")),
            Err(_) => Err(Arc::from("the download ended without a result")),
        }
    }
}

/// One http payload the prefetch has to download.
struct Download {
    name: String,
    url: String,
    proxy: Option<Arc<dyn Proxy>>,
    headers: Vec<(String, String)>,
}

enum DownloadState {
    Running,
    Done(Result<Vec<u8>, String>),
    /// The deadline passed first: the result goes to whoever adopts it.
    Detached(tokio::sync::watch::Sender<Option<DownloadResult>>),
    Taken,
}

/// Download progress shared between the prefetch and its worker thread.
struct DownloadBoard {
    states: parking_lot::Mutex<Vec<DownloadState>>,
    changed: parking_lot::Condvar,
}

impl DownloadBoard {
    fn complete(&self, index: usize, result: Result<Vec<u8>, String>) {
        let mut states = self.states.lock();
        match std::mem::replace(&mut states[index], DownloadState::Taken) {
            DownloadState::Detached(adopter) => {
                adopter.send_replace(Some(result.map(Arc::new).map_err(Arc::from)));
            }
            DownloadState::Running => {
                states[index] = DownloadState::Done(result);
                self.changed.notify_all();
            }
            done @ (DownloadState::Done(_) | DownloadState::Taken) => states[index] = done,
        }
    }
}

/// Fails every download still running when the worker exits, however it
/// exits — the prefetch must never wait on a result that cannot come.
struct AbandonRemaining(Arc<DownloadBoard>, usize);

impl Drop for AbandonRemaining {
    fn drop(&mut self) {
        for index in 0..self.1 {
            self.0
                .complete(index, Err("the download worker exited".to_string()));
        }
    }
}

/// Download every payload concurrently on one worker thread and wait for
/// them until `deadline`. Downloads still running then keep going and are
/// returned as [`Prefetched::Pending`].
fn download_all(downloads: Vec<Download>, deadline: Option<Duration>) -> Vec<(String, Prefetched)> {
    if downloads.is_empty() {
        return Vec::new();
    }
    let count = downloads.len();
    let names: Vec<String> = downloads.iter().map(|d| d.name.clone()).collect();
    let board = Arc::new(DownloadBoard {
        states: parking_lot::Mutex::new((0..count).map(|_| DownloadState::Running).collect()),
        changed: parking_lot::Condvar::new(),
    });
    let deadline_at = deadline.and_then(|d| std::time::Instant::now().checked_add(d));
    let worker_board = Arc::clone(&board);
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let spawned = std::thread::Builder::new()
        .name("rule-provider-fetch".to_string())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                let _abandon = AbandonRemaining(Arc::clone(&worker_board), count);
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        warn!("rule-provider downloads: cannot build a runtime: {e}");
                        return;
                    }
                };
                runtime.block_on(async {
                    let mut tasks = tokio::task::JoinSet::new();
                    let mut indexes = HashMap::with_capacity(count);
                    for (index, d) in downloads.into_iter().enumerate() {
                        let task = tasks.spawn(async move {
                            internal_http::fetch(&d.url, d.proxy.as_ref(), &d.headers).await
                        });
                        indexes.insert(task.id(), index);
                    }
                    while let Some(joined) = tasks.join_next_with_id().await {
                        let (id, result) = match joined {
                            Ok((id, result)) => (id, result.map_err(|e| format!("{e:#}"))),
                            Err(e) => (e.id(), Err(format!("download task failed: {e}"))),
                        };
                        worker_board.complete(indexes[&id], result);
                    }
                });
            });
        });
    if let Err(e) = spawned {
        let error = format!("cannot spawn the download thread: {e}");
        return names
            .into_iter()
            .map(|name| (name, Prefetched::Failed(error.clone())))
            .collect();
    }

    let mut states = board.states.lock();
    while states.iter().any(|s| matches!(s, DownloadState::Running)) {
        match deadline_at {
            None => board.changed.wait(&mut states),
            Some(at) => {
                if board.changed.wait_until(&mut states, at).timed_out() {
                    break;
                }
            }
        }
    }
    names
        .into_iter()
        .zip(states.iter_mut())
        .map(|(name, state)| {
            let entry = match std::mem::replace(state, DownloadState::Taken) {
                DownloadState::Done(Ok(bytes)) => Prefetched::Downloaded {
                    bytes,
                    persisted: AtomicBool::new(false),
                },
                DownloadState::Done(Err(e)) => {
                    debug!("rule-provider '{name}': download failed: {e}");
                    Prefetched::Failed(e)
                }
                DownloadState::Running => {
                    let (adopter, pending) = tokio::sync::watch::channel(None);
                    *state = DownloadState::Detached(adopter);
                    Prefetched::Pending(PendingFetch(pending))
                }
                DownloadState::Detached(_) | DownloadState::Taken => {
                    unreachable!("only this harvest detaches or takes a download")
                }
            };
            (name, entry)
        })
        .collect()
}

/// Resolves a per-provider `proxy:` name (mihomo compat, issue #377) to a
/// live proxy at load time. Returns `None` for names it cannot resolve.
pub type ProxyLookup<'a> = &'a dyn Fn(&str) -> Option<Arc<dyn Proxy>>;

/// Effective download proxy for one http provider: an explicit
/// `proxy: DIRECT` forces a direct fetch, any other explicit name must
/// resolve via `lookup`, and an absent field keeps the global default
/// (historically the first proxy in `proxies:`).
fn effective_download_proxy(
    cfg: &RawRuleProvider,
    default: Option<&Arc<dyn Proxy>>,
    lookup: ProxyLookup<'_>,
) -> Result<Option<Arc<dyn Proxy>>> {
    match cfg.proxy.as_deref() {
        None | Some("") => Ok(default.cloned()),
        // Whitespace-only is a typo, not a clear — same posture as
        // proxy-provider `proxy:`/`dialer-proxy:` (issue #625 review).
        Some(s) if s.trim().is_empty() => Err(anyhow!(
            "download proxy name is blank — expected a proxy/group name or DIRECT"
        )),
        Some(s) => {
            let name = s.trim();
            if name.eq_ignore_ascii_case("DIRECT") {
                Ok(None)
            } else {
                lookup(name)
                    .map(Some)
                    .ok_or_else(|| anyhow!("download proxy '{name}' is not a known proxy or group"))
            }
        }
    }
}

/// Acquire the payload of every file/http provider without parsing it.
///
/// - `file` payloads are read from their path.
/// - An http provider with an on-disk cache is served from it without a
///   request (mihomo's fetcher reads its local file first too); the load
///   marks it for a background revalidation.
/// - The remaining http payloads download concurrently. The wait is bounded
///   by [`crate::provider_fetch_deadline`] (unbounded by default); a download
///   still running then keeps going and is handed to its provider.
///
/// Failures are recorded (and logged at debug — the load pass reports them),
/// so `load_providers_prefetched` registers those providers empty instead of
/// downloading them again. A `proxy:` name `lookup` cannot resolve
/// (provider-sourced proxies are never indexed by the lookup, and the
/// prefetch layer can be absent when the caller had no need to build it)
/// skips the provider quietly — the load pass acquires it against the full
/// registry.
pub fn prefetch_payloads(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
    default_proxy: Option<&Arc<dyn Proxy>>,
    lookup: ProxyLookup<'_>,
) -> PrefetchedPayloads {
    prefetch_payloads_within(
        raw_providers,
        cache_dir,
        default_proxy,
        lookup,
        crate::provider_fetch_deadline(),
    )
}

/// [`prefetch_payloads`] with an explicit download deadline instead of the
/// process-wide [`crate::provider_fetch_deadline`].
pub fn prefetch_payloads_within(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
    default_proxy: Option<&Arc<dyn Proxy>>,
    lookup: ProxyLookup<'_>,
    deadline: Option<Duration>,
) -> PrefetchedPayloads {
    let mut out = PrefetchedPayloads::default();
    let mut downloads = Vec::new();
    for (name, cfg) in raw_providers {
        let entry = match cfg.provider_type.as_str() {
            "file" => read_file_payload(name, cfg, cache_dir).map(Prefetched::Fresh),
            "http" => {
                let proxy = match effective_download_proxy(cfg, default_proxy, lookup) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!(
                            "rule-provider '{}': prefetch skipped ({:#}); \
                             retried once proxies are built",
                            name, e
                        );
                        continue;
                    }
                };
                match http_source(name, cfg, cache_dir) {
                    Err(e) => Err(e),
                    Ok((url, cache_path)) => match read_cache(cache_path.as_deref()) {
                        Some(cached) => Ok(cached),
                        None if crate::is_offline_validate() => {
                            Ok(Prefetched::Failed(offline_miss(url)))
                        }
                        None => {
                            downloads.push(Download {
                                name: name.clone(),
                                url: url.to_string(),
                                proxy,
                                headers: provider_headers(cfg),
                            });
                            continue;
                        }
                    },
                }
            }
            _ => continue,
        };
        match entry {
            Ok(entry) => {
                out.entries.insert(name.clone(), entry);
            }
            Err(e) => warn!("rule-provider '{}': payload prefetch failed: {:#}", name, e),
        }
    }
    out.entries.extend(download_all(downloads, deadline));
    out
}

fn read_file_payload(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
) -> Result<Vec<u8>> {
    let path = resolve_path(cfg, cache_dir, name, false)?
        .ok_or_else(|| anyhow!("file provider '{name}' requires a 'path'"))?;
    std::fs::read(&path).with_context(|| format!("reading provider file {}", path.display()))
}

/// An http provider's `url:` and resolved cache location.
fn http_source<'a>(
    name: &str,
    cfg: &'a RawRuleProvider,
    cache_dir: Option<&Path>,
) -> Result<(&'a str, Option<PathBuf>)> {
    let url = cfg
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("http provider '{name}' requires a 'url'"))?;
    Ok((url, resolve_path(cfg, cache_dir, name, false)?))
}

/// The on-disk cache of an http provider, if it has a readable one.
fn read_cache(cache_path: Option<&Path>) -> Option<Prefetched> {
    let path = cache_path?;
    match std::fs::read(path) {
        Ok(bytes) => {
            debug!("rule-provider cache hit: {}", path.display());
            let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
            Some(Prefetched::Cached { bytes, modified })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                "rule-provider cache {} is unreadable, downloading instead: {}",
                path.display(),
                e
            );
            None
        }
    }
}

fn offline_miss(url: &str) -> String {
    format!("offline validation: no cached payload for rule provider {url}")
}

/// Whether a cache the load served needs a background refetch: always
/// without an `interval` (nothing else would ever update it), otherwise once
/// it is at least `interval` old — mihomo's fetcher refetches a stale local
/// file at startup the same way. An unknown age counts as stale.
fn cache_needs_revalidation(modified: Option<SystemTime>, interval: u64) -> bool {
    if interval == 0 {
        return true;
    }
    modified.is_none_or(|m| {
        SystemTime::now()
            .duration_since(m)
            .is_ok_and(|age| age.as_secs() >= interval)
    })
}

/// Load every configured rule-provider at startup.
///
/// Returns a map from provider name to `Arc<RuleProvider>`.  Providers that
/// fail to load are skipped with a `warn!` (best-effort keep-running);
/// under `strict`, definition defects and *local* (`file:`/`inline:`)
/// payload defects return `Err` instead, while remote payload defects
/// degrade like pure acquisition failures: the provider registers empty
/// in either mode and retries in the background (issue #533).
pub fn load_providers(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
    ctx: &ParserContext,
    download_proxy: Option<&Arc<dyn Proxy>>,
    strict: bool,
) -> Result<HashMap<String, Arc<RuleProvider>>> {
    load_providers_prefetched(
        raw_providers,
        cache_dir,
        ctx,
        download_proxy,
        &|_| None,
        &PrefetchedPayloads::default(),
        None,
        strict,
        &mut DroppedProviders::default(),
    )
}

/// Same as [`load_providers`] but reuses the payloads [`prefetch_payloads`]
/// acquired; a download it recorded as failed or still running registers the
/// provider empty without another request. Providers absent from
/// `prefetched` acquire their payload themselves (cache first).
/// `dialer_registry` should be the registry generation the resolved download
/// proxies were built from; each provider's fetch context retains a clone so
/// a chained adapter still resolves its front hop on later refreshes (issue
/// #533). `None` is fine only when no retained adapter can carry a
/// `dialer-proxy` chain. Providers left out leniently go into `dropped`,
/// for the commit to record.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct piece of one provider's load context"
)]
pub fn load_providers_prefetched(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
    ctx: &ParserContext,
    default_proxy: Option<&Arc<dyn Proxy>>,
    lookup: ProxyLookup<'_>,
    prefetched: &PrefetchedPayloads,
    dialer_registry: Option<&meow_proxy::dialer::ProxyRegistry>,
    strict: bool,
    dropped: &mut DroppedProviders,
) -> Result<HashMap<String, Arc<RuleProvider>>, anyhow::Error> {
    let mut out = HashMap::new();
    if raw_providers.is_empty() {
        return Ok(out);
    }
    for (name, cfg) in raw_providers {
        let download_proxy = if cfg.provider_type == "http" {
            match effective_download_proxy(cfg, default_proxy, lookup) {
                Ok(p) => p,
                Err(e) => {
                    if strict {
                        return Err(anyhow::anyhow!(
                            "rule-provider '{name}': download-proxy resolution failed \
                             (strict mode): {e:#}"
                        ));
                    }
                    warn!("Failed to load rule-provider '{}': {:#}", name, e);
                    dropped.rule(name, format!("{e:#}"));
                    continue;
                }
            }
        } else {
            None
        };
        let payload = prefetched.entries.get(name);
        match load_one(
            name,
            cfg,
            cache_dir,
            ctx,
            download_proxy.as_ref(),
            payload,
            dialer_registry,
            strict,
        ) {
            Ok(provider) => {
                debug!(
                    "Loaded rule-provider '{}' ({}/{}): {} entries",
                    name,
                    provider.provider_type,
                    provider.behavior,
                    provider.rule_count()
                );
                out.insert(name.clone(), Arc::new(provider));
            }
            Err(LoadError::Acquisition(provider, e)) => {
                // A fetch/read failure is transient, not a config defect —
                // register the provider with an empty rule set in BOTH
                // modes so `RULE-SET,<name>` references resolve (instead of
                // failing strict validation as "unknown provider") and a
                // later `PUT /providers/rules/{name}` refresh can heal it.
                // Matches mihomo, which registers failed providers.
                //
                // Remote *payload* parse defects funnel here too — a feed's
                // malformed bytes are third-party content the operator
                // cannot fix by editing the config, so they take the same
                // registered-empty + background-retry shape. That is a
                // deliberate lenient-side change: such a defect used to
                // drop the provider outright until the next config reload;
                // the spec (§4.2 "registered empty in both modes") and
                // upstream's failed-provider registration both prefer the
                // retryable shape.
                warn!("rule-provider '{name}': payload unavailable, starting empty: {e:#}");
                // A download still running at the deadline is not a
                // failure; the adopted download records its own outcome.
                if !matches!(*provider.initial_fetch.lock(), InitialFetch::Adopt(_)) {
                    *provider.load_note.lock() = Some(LoadNote::Failed(format!("{e:#}")));
                }
                out.insert(name.clone(), Arc::new(*provider));
            }
            Err(e) if strict => {
                return Err(anyhow::anyhow!(
                    "rule-provider '{name}' failed to load (strict mode): {e:#}"
                ));
            }
            Err(e) => {
                warn!("Failed to load rule-provider '{}': {:#}", name, e);
                dropped.rule(name, format!("{e:#}"));
            }
        }
    }
    Ok(out)
}

/// Logbook: loading or updating rule provider `name` failed. Repeats fold
/// while it keeps failing.
pub(crate) fn record_failure(name: &str, error: &str) {
    logbook::event(
        logbook::kind::RULE_PROVIDER_UPDATE,
        Level::Error,
        format!("Updating rule provider '{name}' failed: {error}"),
    )
    .subject(name)
    .field("error", error)
    .coalesce()
    .record();
}

/// Why a provider failed to load — the strict gate needs the failure
/// *stage*, not a post-hoc guess from whether payload bytes were present
/// (a malformed `format:` or a `file` provider on a cache-dir-less build
/// would otherwise masquerade as an acquisition failure — issue #533
/// review).
enum LoadError {
    /// Defective definition: bad `type`/`behavior`/`format`, missing
    /// `url:`/`path:`/`payload:`, a path escaping the provider cache dir,
    /// or `interval` on a type that cannot refresh.
    Defect(anyhow::Error),
    /// The payload could not be fetched/read — transient. Carries the
    /// fully-constructed provider (boxed: this variant would otherwise make
    /// the whole `Result` very large) so the caller can register it empty.
    Acquisition(Box<RuleProvider>, anyhow::Error),
    /// Acquired bytes (or an inline `payload:`) failed to parse.
    Payload(anyhow::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Defect(e) | Self::Payload(e) | Self::Acquisition(_, e) => {
                write!(f, "{e:#}")
            }
        }
    }
}

/// Build the `HashMap<name, Arc<dyn RuleSet>>` the rule parser needs.
///
/// Each value is the provider itself (see the [`RuleSet`] impl on
/// [`RuleProvider`]), *not* a snapshot of its current set: `RULE-SET` rules
/// built from this map keep following `refresh()` for as long as they live.
/// The previous snapshot map detached every rule from later refreshes, so a
/// provider with `interval:` logged "refreshed: N rules" while traffic kept
/// matching the startup content (issue #553).
pub fn live_ruleset_map(
    providers: &HashMap<String, Arc<RuleProvider>>,
) -> HashMap<String, Arc<dyn RuleSet>> {
    providers
        .iter()
        .map(|(name, p)| {
            let live = Arc::clone(p);
            let live: Arc<dyn RuleSet> = live;
            (name.clone(), live)
        })
        .collect()
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct piece of one provider's load context"
)]
fn load_one(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    ctx: &ParserContext,
    download_proxy: Option<&Arc<dyn Proxy>>,
    prefetched: Option<&Prefetched>,
    dialer_registry: Option<&meow_proxy::dialer::ProxyRegistry>,
    strict: bool,
) -> Result<RuleProvider, LoadError> {
    let behavior: RuleSetBehavior = cfg
        .behavior
        .parse()
        .map_err(|e: String| LoadError::Defect(anyhow!("{e}")))?;
    match cfg.provider_type.as_str() {
        "inline" => load_inline(name, cfg, behavior, ctx, strict),
        "file" => load_file(
            name,
            cfg,
            cache_dir,
            behavior,
            ctx,
            prefetched.and_then(Prefetched::bytes),
            strict,
        ),
        "http" => load_http(
            name,
            cfg,
            cache_dir,
            behavior,
            ctx,
            download_proxy,
            prefetched,
            dialer_registry,
            strict,
        ),
        other => Err(LoadError::Defect(anyhow!(
            "unknown rule-provider type: {other}"
        ))),
    }
}

/// An empty rule set of the right behavior for a provider whose payload is
/// unavailable — registered so `RULE-SET` references resolve. Matchers
/// hold the provider itself (issue #553 live read-through), so a later
/// `refresh()` fills it under their feet — no rebuild needed; `GET
/// /providers/rules` and DNS `rule-set:` policies observe the same fill.
fn empty_rule_set(behavior: RuleSetBehavior, ctx: &ParserContext) -> Box<dyn RuleSet> {
    build_rule_set(behavior, &[], ctx)
}

/// Parse payload bytes into a rule set, honoring `strict` per-entry: strict
/// uses [`build_rule_set_checked`] so one malformed line fails the payload
/// instead of installing a partial set (issue #533).
fn entries_to_rule_set(
    behavior: RuleSetBehavior,
    entries: &[String],
    ctx: &ParserContext,
    strict: bool,
) -> Result<Box<dyn RuleSet>, LoadError> {
    if strict {
        build_rule_set_checked(behavior, entries, ctx)
            .map_err(|e| LoadError::Payload(anyhow!("{e}")))
    } else {
        Ok(build_rule_set(behavior, entries, ctx))
    }
}

fn load_inline(
    name: &str,
    cfg: &RawRuleProvider,
    behavior: RuleSetBehavior,
    ctx: &ParserContext,
    strict: bool,
) -> Result<RuleProvider, LoadError> {
    if cfg.interval.is_some_and(|i| i > 0) {
        return Err(LoadError::Defect(anyhow!(
            "rule-provider '{name}': inline providers cannot refresh; \
             remove the `interval:` field (Class A per ADR-0002)"
        )));
    }
    let payload = cfg.payload.as_deref().ok_or_else(|| {
        LoadError::Defect(anyhow!(
            "rule-provider '{name}': inline type requires `payload:`"
        ))
    })?;
    let rules = entries_to_rule_set(behavior, payload, ctx, strict)?;
    // `format:` does not apply to a payload written in the config itself,
    // but a declared one is still what the provider reports.
    let declared = parse_explicit_format(cfg)
        .ok()
        .flatten()
        .unwrap_or(RuleSetFormat::Yaml);
    let provider = make_provider(
        name,
        ProviderType::Inline,
        behavior,
        String::new(),
        0,
        FetchContext::default(),
        strict,
        ctx.clone(),
        None,
        None,
    );
    provider.fill_fresh((rules, declared));
    Ok(provider)
}

fn load_file(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    behavior: RuleSetBehavior,
    ctx: &ParserContext,
    prefetched: Option<&[u8]>,
    strict: bool,
) -> Result<RuleProvider, LoadError> {
    if cfg.interval.is_some_and(|i| i > 0) {
        warn!(
            provider = %name,
            "rule-provider 'interval' is ignored for file providers in M1 \
             (Class B per ADR-0002)"
        );
    }
    // Check the field itself before `resolve_path` — without it the
    // implicit name-derived location would report a confusing error naming
    // a path the user never wrote (issue #533 review).
    if cfg.path.is_none() {
        return Err(LoadError::Defect(anyhow!(
            "file provider '{name}' requires a 'path'"
        )));
    }
    let path = resolve_path(cfg, cache_dir, name, false)
        .map_err(LoadError::Defect)?
        .ok_or_else(|| LoadError::Defect(anyhow!("file provider '{name}' requires a 'path'")))?;
    let explicit_format = parse_explicit_format(cfg).map_err(LoadError::Defect)?;
    // The provider object is constructed before acquisition so a read
    // failure can register it empty — a manual refresh re-reads the path.
    let provider = make_provider(
        name,
        ProviderType::File,
        behavior,
        path.display().to_string(),
        0,
        FetchContext::default(),
        strict,
        ctx.clone(),
        explicit_format,
        // A file provider's path *is* the payload source — `refresh()`
        // re-reads it; there is no separate cache to write.
        None,
    );
    let bytes_owned;
    let bytes: &[u8] = match prefetched {
        Some(b) => b,
        None => match std::fs::read(&path) {
            Ok(b) => {
                bytes_owned = b;
                &bytes_owned
            }
            // Move the empty provider into the error so the caller can
            // register it — the name stays resolvable for `RULE-SET` and a
            // manual refresh re-reads the path.
            Err(e) => {
                return Err(LoadError::Acquisition(
                    Box::new(provider),
                    anyhow!(e).context(format!("reading provider file {}", path.display())),
                ));
            }
        },
    };
    let parsed = parse_bytes_to_ruleset_with_format(bytes, behavior, explicit_format, ctx, strict)
        .map_err(LoadError::Payload)?;
    provider.fill_fresh(parsed);
    Ok(provider)
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct piece of one provider's load context"
)]
fn load_http(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    behavior: RuleSetBehavior,
    ctx: &ParserContext,
    download_proxy: Option<&Arc<dyn Proxy>>,
    prefetched: Option<&Prefetched>,
    dialer_registry: Option<&meow_proxy::dialer::ProxyRegistry>,
    strict: bool,
) -> Result<RuleProvider, LoadError> {
    let url = cfg
        .url
        .as_deref()
        .ok_or_else(|| LoadError::Defect(anyhow!("http provider '{name}' requires a 'url'")))?;
    // An unparseable `url:` is a permanent defect — under strict fail the
    // load instead of registering an empty provider that retries the same
    // bad URL on every interval (issue #533 review).
    if strict && url::Url::parse(url).is_err() {
        return Err(LoadError::Defect(anyhow!(
            "rule-provider '{name}': invalid url '{url}' (strict mode)"
        )));
    }
    let cache_path = resolve_path(cfg, cache_dir, name, false).map_err(LoadError::Defect)?;
    let explicit_format = parse_explicit_format(cfg).map_err(LoadError::Defect)?;
    let interval = cfg.interval.unwrap_or(0);
    let headers = provider_headers(cfg);
    // Constructed before acquisition: a fetch failure registers this
    // provider empty so `RULE-SET` references resolve, and the background
    // fetch the commit kicks off heals it (issue #533 review).
    let provider = make_provider(
        name,
        ProviderType::Http,
        behavior,
        url.to_string(),
        interval,
        FetchContext {
            proxy: download_proxy.cloned(),
            headers: headers.clone(),
            _dialer_registry: dialer_registry.cloned(),
        },
        strict,
        ctx.clone(),
        explicit_format,
        cache_path.clone(),
    );
    let acquired;
    let entry = match prefetched {
        Some(entry) => entry,
        None => {
            let fetched = match read_cache(cache_path.as_deref()) {
                Some(cached) => Ok(cached),
                None if crate::is_offline_validate() => Err(anyhow!(offline_miss(url))),
                None => fetch_http_blocking(url, download_proxy, &headers).map(|bytes| {
                    Prefetched::Downloaded {
                        bytes,
                        persisted: AtomicBool::new(false),
                    }
                }),
            };
            match fetched {
                Ok(entry) => {
                    acquired = entry;
                    &acquired
                }
                Err(e) => {
                    provider.owe(InitialFetch::Retry);
                    return Err(LoadError::Acquisition(Box::new(provider), e));
                }
            }
        }
    };
    let parse = |bytes: &[u8]| {
        parse_bytes_to_ruleset_with_format(bytes, behavior, explicit_format, ctx, strict)
    };
    match entry {
        // Caller-supplied bytes for an http provider are still remote
        // content — degrade a parse defect like a fetched one (registered
        // empty + retry), never a config verdict on third-party bytes.
        Prefetched::Fresh(bytes) => match parse(bytes) {
            Ok(parsed) => provider.fill_fresh(parsed),
            Err(e) => {
                provider.owe(InitialFetch::Retry);
                return Err(LoadError::Acquisition(
                    Box::new(provider),
                    e.context("ignoring the payload, which does not parse"),
                ));
            }
        },
        Prefetched::Downloaded { bytes, persisted } => {
            match parse(bytes) {
                // Remote bytes are third-party content: a strict parse
                // defect degrades to the acquisition shape rather than
                // rejecting the build — the feed's owner cannot veto the
                // daemon by serving malformed rules.
                Err(e) => {
                    provider.owe(InitialFetch::Retry);
                    return Err(LoadError::Acquisition(
                        Box::new(provider),
                        e.context("ignoring the payload, which does not parse"),
                    ));
                }
                Ok(parsed) => provider.fill_fresh(parsed),
            }
            // Rejected bytes never reach the cache — only a payload that
            // parsed is persisted.
            if let Some(path) = &cache_path {
                if !persisted.swap(true, Ordering::Relaxed) {
                    write_cache(path, bytes);
                }
            }
        }
        Prefetched::Cached { bytes, modified } => match parse(bytes) {
            Ok(parsed) => {
                provider.swap_rules(parsed);
                // Report the cache's age, not the load time.
                if let Some(modified) = modified {
                    provider.set_updated_at(*modified);
                }
                if cache_needs_revalidation(*modified, interval) {
                    provider.owe(InitialFetch::Revalidate);
                }
            }
            // A cache that no longer parses (a different `format:`, a
            // payload an older build cached unparsed) is remote content
            // at rest, not a config defect — even under `-t`, whose
            // verdict must match what the next boot does: start empty and
            // let the background fetch replace it.
            Err(e) => {
                provider.owe(InitialFetch::Retry);
                return Err(LoadError::Acquisition(
                    Box::new(provider),
                    e.context("ignoring the on-disk cache, which no longer parses"),
                ));
            }
        },
        Prefetched::Failed(e) => {
            provider.owe(InitialFetch::Retry);
            return Err(LoadError::Acquisition(Box::new(provider), anyhow!("{e}")));
        }
        Prefetched::Pending(pending) => {
            provider.owe(InitialFetch::Adopt(pending.clone()));
            return Err(LoadError::Acquisition(
                Box::new(provider),
                anyhow!("still downloading at the fetch deadline; it finishes in the background"),
            ));
        }
    }
    Ok(provider)
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a distinct piece of one provider's construction context"
)]
fn make_provider(
    name: &str,
    provider_type: ProviderType,
    behavior: RuleSetBehavior,
    vehicle: String,
    interval: u64,
    fetch: FetchContext,
    strict: bool,
    ctx: ParserContext,
    format: Option<RuleSetFormat>,
    cache_path: Option<PathBuf>,
) -> RuleProvider {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    // Empty until a payload lands (`swap_rules`).
    let rules_arc: Arc<dyn RuleSet> = Arc::from(empty_rule_set(behavior, &ctx));
    RuleProvider {
        name: name.to_string(),
        provider_type,
        behavior,
        vehicle,
        interval,
        updated_at: AtomicU::new(now as meow_common::atomic::Uint),
        rules: RwLock::new(rules_arc),
        fetch,
        strict,
        ctx,
        format,
        payload_format: parking_lot::Mutex::new(format.unwrap_or(RuleSetFormat::Yaml)),
        cache_path,
        cache_write_lock: Arc::new(parking_lot::Mutex::new(0)),
        install_gen: parking_lot::Mutex::new(0),
        // Starts at 1 so the first refresh (gen 1) beats the initial
        // `written_gen` of 0 under `cache_write_lock`.
        refresh_gen: meow_common::atomic::AtomicU::new(1),
        initial_fetch: parking_lot::Mutex::new(InitialFetch::Settled),
        load_note: parking_lot::Mutex::new(None),
        filled: AtomicBool::new(false),
    }
}

/// Minimal provider for supervisor/refresh tests — an empty domain ruleset
/// is fine because the loops under test never observe content.
#[cfg(test)]
pub(crate) fn test_provider(
    name: &str,
    provider_type: ProviderType,
    interval: u64,
) -> Arc<RuleProvider> {
    test_provider_with_vehicle(name, provider_type, interval, String::new())
}

/// [`test_provider`] with an explicit `vehicle` — file-provider refresh
/// tests point it at a real temp file.
#[cfg(test)]
pub(crate) fn test_provider_with_vehicle(
    name: &str,
    provider_type: ProviderType,
    interval: u64,
    vehicle: String,
) -> Arc<RuleProvider> {
    let provider = make_provider(
        name,
        provider_type,
        RuleSetBehavior::Domain,
        vehicle,
        interval,
        FetchContext::default(),
        false,
        ParserContext::empty(),
        None,
        None,
    );
    provider.swap_rules((
        meow_rules::build_rule_set(RuleSetBehavior::Domain, &[], &ParserContext::empty()),
        RuleSetFormat::Yaml,
    ));
    Arc::new(provider)
}

/// Flattened `header:` pairs for one provider; empty when none declared.
fn provider_headers(cfg: &RawRuleProvider) -> Vec<(String, String)> {
    cfg.header
        .as_ref()
        .map(crate::raw::flatten_header_map)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Format detection + parsing
// ---------------------------------------------------------------------------

fn parse_explicit_format(cfg: &RawRuleProvider) -> Result<Option<RuleSetFormat>> {
    cfg.format
        .as_deref()
        .map(|s| s.parse::<RuleSetFormat>().map_err(|e| anyhow!("{e}")))
        .transpose()
}

/// Parse payload bytes into a rule set, returned with the format they
/// parsed as: MRS when declared or when the bytes carry the MRS magic,
/// otherwise the declared format (YAML when undeclared).
fn parse_bytes_to_ruleset_with_format(
    bytes: &[u8],
    behavior: RuleSetBehavior,
    explicit_format: Option<RuleSetFormat>,
    ctx: &ParserContext,
    strict: bool,
) -> Result<(Box<dyn RuleSet>, RuleSetFormat)> {
    let use_mrs = explicit_format == Some(RuleSetFormat::Mrs) || is_mrs_bytes(bytes);
    if use_mrs {
        return build_rule_set_from_mrs_with_behavior(bytes, ctx, Some(behavior), strict)
            .map(|rules| (rules, RuleSetFormat::Mrs))
            .map_err(|e| anyhow!("mrs parse error: {e}"));
    }
    let text = std::str::from_utf8(bytes).context("payload is not valid UTF-8")?;
    let format = explicit_format.unwrap_or(RuleSetFormat::Yaml);
    let entries = match format {
        RuleSetFormat::Yaml => parse_yaml_payload(text, strict)?,
        RuleSetFormat::Text => parse_text_payload(text),
        RuleSetFormat::Mrs => unreachable!("handled above"),
    };
    if strict {
        return build_rule_set_checked(behavior, &entries, ctx)
            .map(|rules| (rules, format))
            .map_err(|e| anyhow!("rule-set entry error: {e}"));
    }
    Ok((build_rule_set(behavior, &entries, ctx), format))
}

fn parse_yaml_payload(raw: &str, strict: bool) -> Result<Vec<String>> {
    if !crate::yaml_within_depth(raw) {
        return Err(anyhow!("rule-set yaml exceeds the nesting-depth limit"));
    }
    // The whole document is converted up front — intentionally
    // fail-closed: a `!tag` node or complex mapping key anywhere in the
    // untrusted remote input rejects the entire ruleset rather than
    // slipping part of it through (`reject_unsupported_tags` in the
    // shared ingest options backs this at the parser level).
    let root: serde_json::Value =
        crate::parse_yaml_value(raw).context("rule-set yaml parse error")?;
    let payload = root
        .get("payload")
        .ok_or_else(|| anyhow!("rule-set yaml missing 'payload' key"))?
        .as_array()
        .ok_or_else(|| anyhow!("rule-set 'payload' is not a sequence"))?;
    let mut entries = Vec::with_capacity(payload.len());
    for (i, v) in payload.iter().enumerate() {
        match v.as_str() {
            Some(s) if !s.trim().is_empty() => entries.push(s.trim().to_string()),
            // Non-string items are silently dropped leniently (mihomo
            // parity); strict treats them as a malformed payload.
            None if strict => {
                return Err(anyhow!("rule-set 'payload' item {i} is not a string"));
            }
            _ => {}
        }
    }
    Ok(entries)
}

fn parse_text_payload(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(std::string::ToString::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Resolve the on-disk location of a provider's payload/cache, enforcing that
/// it stays inside `cache_dir` (issue #429).
///
/// `path:` is attacker-influenced whenever the config arrives over the REST
/// API (`PUT /configs`), and for http providers it is a **write** target, so:
///
/// - provider types that never read a path (`inline`) ignore a stray `path:`
///   entirely — mihomo parity: a harmless leftover field must not fail a
///   whole rebuild;
/// - with a `cache_dir`, the resolved path (absolute or relative, `..` and
///   symlinks included) must stay inside it — anything else is a hard error;
/// - without a `cache_dir` (runtime rebuilds such as `PUT /configs` or
///   `--config-string`) there is no containment root, so a `path:` is never
///   honoured: http providers fall back to fetching into memory, file
///   providers hard-error.
///
/// `emit_warnings` gates the ignoring-`path` warns. Every (re)build calls
/// [`validate_paths`] exactly once before any fetch/load pass, so only that
/// call passes `true` — otherwise the same warn would fire up to three times
/// per provider per rebuild (validate, prefetch, and load all resolve).
fn resolve_path(
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    name: &str,
    emit_warnings: bool,
) -> Result<Option<PathBuf>> {
    // Only file (payload location) and http (on-disk cache) providers ever
    // read the resolved path; other types must not fail on a stray `path:`.
    if !matches!(cfg.provider_type.as_str(), "file" | "http") {
        if cfg.path.is_some() && emit_warnings {
            warn!(
                "rule-provider '{}': ignoring 'path' — {} providers never read it",
                name, cfg.provider_type
            );
        }
        return Ok(None);
    }
    if let Some(p) = cfg.path.as_deref() {
        let Some(dir) = cache_dir else {
            if cfg.provider_type == "http" {
                if emit_warnings {
                    warn!(
                        "rule-provider '{}': ignoring 'path' (no provider cache directory in \
                         this context); fetching to memory without an on-disk cache",
                        name
                    );
                }
                return Ok(None);
            }
            return Err(anyhow!(
                "rule-provider '{name}': 'path' cannot be used without a provider cache directory"
            ));
        };
        let path = crate::safe_path::resolve_contained(dir, Path::new(p))
            .map_err(|e| anyhow!("rule-provider '{name}': {e}"))?;
        return Ok(Some(path));
    }
    let Some(dir) = cache_dir else {
        return Ok(None);
    };
    // The implicit location is derived from the provider *name* (a YAML map
    // key, also attacker-influenced), so it gets the same containment check.
    let implicit = Path::new("rule-providers").join(format!("{name}.yaml"));
    let path = crate::safe_path::resolve_contained(dir, &implicit)
        .map_err(|e| anyhow!("rule-provider '{name}': {e}"))?;
    Ok(Some(path))
}

/// Validate every provider's payload/cache path up front, so a hostile config
/// fails hard before any fetch or write happens (issue #429). Called by
/// `rebuild_from_raw_impl` for every path into a (re)build: startup,
/// `PUT`/`PATCH /configs`, and subscription refresh.
///
/// This is the one pass that emits the ignoring-`path` warns, so they fire
/// once per provider per rebuild (the prefetch and load passes resolve the
/// same paths again, silently).
pub(crate) fn validate_paths(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
) -> Result<()> {
    for (name, cfg) in raw_providers {
        resolve_path(cfg, cache_dir, name, true)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP fetch
// ---------------------------------------------------------------------------

fn fetch_http_blocking(
    url: &str,
    proxy: Option<&Arc<dyn Proxy>>,
    headers: &[(String, String)],
) -> Result<Vec<u8>> {
    let url = url.to_string();
    let thread_url = url.clone();
    let proxy = proxy.cloned();
    let headers = headers.to_vec();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building temporary tokio runtime for rule-provider fetch")?;
        rt.block_on(fetch_http_async(&thread_url, proxy.as_ref(), &headers))
    })
    .join()
    .map_err(|payload| {
        anyhow!(
            "rule-provider HTTP fetch thread panicked while fetching {url}: {}",
            panic_message(payload.as_ref())
        )
    })?
}

/// Extract a human-readable message from a thread panic payload.
pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

pub(crate) async fn fetch_http_async(
    url: &str,
    proxy: Option<&Arc<dyn Proxy>>,
    headers: &[(String, String)],
) -> Result<Vec<u8>> {
    internal_http::fetch(url, proxy, headers).await
}

fn write_cache(path: &Path, bytes: &[u8]) -> bool {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            warn!(
                "rule-provider cache: failed to create {}: {}",
                parent.display(),
                e
            );
            return false;
        }
    }
    // Write-then-rename (the same pattern `save_config` uses): a
    // `refresh()` and a commit's cache-first read can race outside the
    // config lane — a truncate-in-place write could be torn mid-read,
    // injecting mixed-generation bytes into the commit snapshot (issue
    // #543 review).
    // `.tmp` is appended to the full name (not `with_extension`) so
    // `live.yaml` and `live.mrs` in the same dir never share a temp file,
    // and the unique per-call suffix keeps two racing `refresh()` writes
    // (supervisor tick vs `PUT /providers/rules/{name}`, neither laned)
    // from splicing into each other (issue #543 review). Sweep scratch
    // siblings a crashed writer orphaned (issue #621) — this fn only ever
    // runs on blocking threads, so the read_dir is fine here.
    meow_common::fs_util::sweep_scratch_siblings(path, meow_common::fs_util::SCRATCH_STALE_AGE);
    let tmp = crate::unique_scratch_path(path);
    let result = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            "rule-provider cache: failed to write {}: {}",
            path.display(),
            e
        );
        false
    } else {
        debug!("rule-provider cache updated: {}", path.display());
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{eventually, Origin, TestLogbook};
    use meow_rules::mrs_parser::{write_ruleset_mrs, TYPE_DOMAIN};
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    fn ctx() -> ParserContext {
        ParserContext::empty()
    }

    #[test]
    fn a_payload_filling_a_provider_is_its_load_not_an_update() {
        let message = |previous, count, failing| update_message("p", previous, count, || failing);
        assert_eq!(message(None, 2, false), None);
        assert_eq!(
            message(None, 2, true).as_deref(),
            Some("Updated rule provider 'p': 2 rules"),
            "ends a failure, with no count to compare"
        );
        assert_eq!(
            message(Some(1), 2, false).as_deref(),
            Some("Updated rule provider 'p': 2 rules (was 1)")
        );
        assert_eq!(message(Some(2), 2, false), None, "routine");
        assert_eq!(
            message(Some(2), 2, true).as_deref(),
            Some("Updated rule provider 'p': 2 rules")
        );
    }

    fn http_cfg(proxy: Option<&str>) -> RawRuleProvider {
        RawRuleProvider {
            provider_type: "http".to_string(),
            behavior: "domain".to_string(),
            format: Some("yaml".to_string()),
            url: Some("http://127.0.0.1:1/rules.yaml".to_string()),
            path: None,
            interval: None,
            proxy: proxy.map(str::to_string),
            header: None,
            payload: None,
        }
    }

    fn direct_proxy() -> Arc<dyn Proxy> {
        let cfg: HashMap<String, serde_json::Value> =
            serde_saphyr::from_str("name: d\ntype: direct").unwrap();
        crate::proxy_parser::parse_proxy(&cfg, true).unwrap()
    }

    #[test]
    fn effective_download_proxy_follows_mihomo_policy() {
        let d = direct_proxy();
        // Absent field keeps the global default.
        assert!(
            effective_download_proxy(&http_cfg(None), Some(&d), &|_| None)
                .unwrap()
                .is_some()
        );
        // DIRECT (case-insensitive) forces a direct fetch even with a default.
        assert!(
            effective_download_proxy(&http_cfg(Some("direct")), Some(&d), &|_| None)
                .unwrap()
                .is_none()
        );
        // An explicit name resolves via the lookup.
        let hit = effective_download_proxy(&http_cfg(Some("d")), None, &|n| {
            (n == "d").then(|| Arc::clone(&d))
        })
        .unwrap();
        assert!(hit.is_some());
        // An unknown name is an error, never a silent fallback.
        assert!(effective_download_proxy(&http_cfg(Some("nope")), Some(&d), &|_| None).is_err());
    }

    #[test]
    fn http_provider_with_unknown_proxy_name_is_skipped() {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), http_cfg(Some("NoSuch")));
        // Payload already prefetched — resolution still fails first, so the
        // provider is skipped rather than loaded via the wrong proxy.
        let mut prefetched = PrefetchedPayloads::new();
        prefetched.insert("p".to_string(), b"payload:\n  - example.com\n".to_vec());
        let out = load_providers_prefetched(
            &providers,
            None,
            &ctx(),
            None,
            &|_| None,
            &prefetched,
            None,
            false,
            &mut DroppedProviders::default(),
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn http_provider_with_direct_proxy_loads_prefetched_payload() {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), http_cfg(Some("DIRECT")));
        let mut prefetched = PrefetchedPayloads::new();
        prefetched.insert("p".to_string(), b"payload:\n  - example.com\n".to_vec());
        let out = load_providers_prefetched(
            &providers,
            None,
            &ctx(),
            None,
            &|_| None,
            &prefetched,
            None,
            false,
            &mut DroppedProviders::default(),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out.get("p").unwrap().rule_count(), 1);
    }

    #[test]
    fn file_provider_ignores_proxy_field() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("list.yaml");
        std::fs::write(&file_path, "payload:\n  - example.com\n").unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "f".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: None,
                proxy: Some("NoSuch".to_string()),
                header: None,
                payload: None,
            },
        );
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn yaml_file_provider_loads() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("list.yaml");
        std::fs::write(&file_path, "payload:\n  - '+.example.com'\n  - foo.com\n").unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "test".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: None,
                proxy: None,
                header: None,
                payload: None,
            },
        );
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        assert_eq!(out.len(), 1);
        let p = out.get("test").unwrap();
        assert_eq!(p.behavior, RuleSetBehavior::Domain);
        assert_eq!(p.rule_count(), 2);
    }

    #[test]
    fn inline_provider_loads_payload() {
        let mut providers = HashMap::new();
        providers.insert(
            "my-rules".to_string(),
            RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                proxy: None,
                header: None,
                payload: Some(vec!["example.com".to_string(), "+.foo.com".to_string()]),
            },
        );
        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        assert_eq!(out.len(), 1);
        let p = out.get("my-rules").unwrap();
        assert_eq!(p.provider_type, ProviderType::Inline);
        assert_eq!(p.rule_count(), 2);
    }

    #[test]
    fn inline_with_interval_hard_errors() {
        let cfg = RawRuleProvider {
            provider_type: "inline".to_string(),
            behavior: "domain".to_string(),
            format: None,
            url: None,
            path: None,
            interval: Some(3600),
            proxy: None,
            header: None,
            payload: Some(vec!["example.com".to_string()]),
        };
        let err = load_inline("p", &cfg, RuleSetBehavior::Domain, &ctx(), false)
            .map(|_| ())
            .expect_err("inline + interval must hard-error");
        assert!(
            err.to_string().contains("inline providers cannot refresh"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn mrs_format_auto_detected_by_magic_bytes() {
        let bytes = write_ruleset_mrs(TYPE_DOMAIN, &["example.com", "+.foo.com"]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("rules.mrs");
        std::fs::write(&file_path, &bytes).unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "mrs-test".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: None,
                proxy: None,
                header: None,
                payload: None,
            },
        );
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        let p = out.get("mrs-test").expect("provider should load");
        assert_eq!(p.rule_count(), 2);
        assert_eq!(p.format(), RuleSetFormat::Mrs, "reports what it parsed as");
    }

    fn file_cfg(path: &Path, format: Option<&str>) -> RawRuleProvider {
        RawRuleProvider {
            provider_type: "file".to_string(),
            behavior: "domain".to_string(),
            format: format.map(str::to_string),
            url: None,
            path: Some(path.to_string_lossy().to_string()),
            interval: None,
            proxy: None,
            header: None,
            payload: None,
        }
    }

    /// `format()` is the declared format, in any case, or YAML when none
    /// is declared, except that an MRS payload reports MRS whatever was
    /// declared: the bytes decide how it parses. An inline provider
    /// reports its declared format too.
    #[test]
    fn format_reports_what_the_payload_parsed_as() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("rules.yaml");
        std::fs::write(&yaml, "payload:\n  - '+.example.com'\n").unwrap();
        let text = dir.path().join("rules.txt");
        std::fs::write(&text, "+.example.com\n").unwrap();
        let mrs = dir.path().join("rules.mrs");
        std::fs::write(
            &mrs,
            write_ruleset_mrs(TYPE_DOMAIN, &["example.com"]).unwrap(),
        )
        .unwrap();
        let inline = |format: Option<&str>| RawRuleProvider {
            provider_type: "inline".to_string(),
            path: None,
            payload: Some(vec!["+.example.com".to_string()]),
            ..file_cfg(&yaml, format)
        };
        let cases = [
            ("yaml", file_cfg(&yaml, Some("yaml")), RuleSetFormat::Yaml),
            ("text", file_cfg(&text, Some("text")), RuleSetFormat::Text),
            ("mrs", file_cfg(&mrs, Some("mrs")), RuleSetFormat::Mrs),
            ("absent", file_cfg(&yaml, None), RuleSetFormat::Yaml),
            ("upper", file_cfg(&text, Some("TEXT")), RuleSetFormat::Text),
            ("mrs-undeclared", file_cfg(&mrs, None), RuleSetFormat::Mrs),
            (
                "mrs-as-yaml",
                file_cfg(&mrs, Some("yaml")),
                RuleSetFormat::Mrs,
            ),
            ("inline", inline(None), RuleSetFormat::Yaml),
            ("inline-text", inline(Some("text")), RuleSetFormat::Text),
        ];
        let providers: HashMap<_, _> = cases
            .iter()
            .map(|(name, cfg, _)| ((*name).to_string(), cfg.clone()))
            .collect();
        let out = load_providers(&providers, Some(dir.path()), &ctx(), None, true)
            .expect("every provider loads");
        for (name, _, expected) in &cases {
            assert_eq!(out[*name].format(), *expected, "{name}");
        }
    }

    /// A refresh that lands a payload in another format reports the new
    /// one; until a payload lands, the declared format stands.
    #[tokio::test]
    async fn format_follows_a_refreshed_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules");
        std::fs::write(&path, "payload:\n  - '+.example.com'\n").unwrap();
        let providers = HashMap::from([("p".to_string(), file_cfg(&path, None))]);
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        let provider = &out["p"];
        assert_eq!(provider.format(), RuleSetFormat::Yaml);

        std::fs::write(
            &path,
            write_ruleset_mrs(TYPE_DOMAIN, &["example.com"]).unwrap(),
        )
        .unwrap();
        provider.refresh().await.expect("refresh must succeed");
        assert_eq!(provider.format(), RuleSetFormat::Mrs);

        let missing = dir.path().join("missing.txt");
        let providers = HashMap::from([("m".to_string(), file_cfg(&missing, Some("text")))]);
        let out = load_providers(&providers, Some(dir.path()), &ctx(), None, false)
            .expect("an unreadable file registers the provider empty");
        assert_eq!(
            out["m"].format(),
            RuleSetFormat::Text,
            "declared, no payload yet"
        );
    }

    /// An unknown `format:` never loads, so nothing reports one: strict
    /// fails the config, lenient leaves the provider out.
    #[test]
    fn unknown_format_never_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, "payload:\n  - '+.example.com'\n").unwrap();
        let providers = HashMap::from([("p".to_string(), file_cfg(&path, Some("json")))]);
        let err = load_providers(&providers, Some(dir.path()), &ctx(), None, true)
            .expect_err("strict rejects it");
        assert!(
            format!("{err:#}").contains("unsupported rule-set format"),
            "{err:#}"
        );
        let out = load_providers(&providers, Some(dir.path()), &ctx(), None, false)
            .expect("lenient keeps running");
        assert!(out.is_empty(), "left out leniently");
    }

    #[test]
    fn mrs_explicit_format_override() {
        let bytes = write_ruleset_mrs(TYPE_DOMAIN, &["example.com"]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("rules.bin");
        std::fs::write(&file_path, &bytes).unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "x".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: Some("mrs".to_string()),
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: None,
                proxy: None,
                header: None,
                payload: None,
            },
        );
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        assert_eq!(out.get("x").unwrap().rule_count(), 1);
    }

    #[test]
    fn bad_provider_is_skipped() {
        let mut providers = HashMap::new();
        providers.insert(
            "nope".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                proxy: None,
                header: None,
                payload: None,
            },
        );
        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        assert!(out.is_empty());
    }

    #[test]
    fn file_provider_interval_warns_but_loads() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("list.yaml");
        std::fs::write(&file_path, "payload:\n  - 'example.com'\n").unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "warn-test".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: Some(3600),
                proxy: None,
                header: None,
                payload: None,
            },
        );
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn http_provider_loads_inside_existing_tokio_runtime() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for HTTP client"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("HTTP test listener failed: {e}"),
                }
            };
            // The accepted stream can inherit the listener's nonblocking flag, which
            // would make the read/write below return `WouldBlock`. Force blocking mode.
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0_u8; 1024];
            // Consume the request bytes; the exact length is irrelevant for the test.
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "expected an HTTP request from the client");
            let body = "payload:\n  - 'example.com'\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let mut providers = HashMap::new();
        providers.insert(
            "http-test".to_string(),
            RawRuleProvider {
                provider_type: "http".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: Some(format!("http://{addr}/rules.yaml")),
                path: None,
                interval: None,
                proxy: None,
                header: None,
                payload: None,
            },
        );

        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        server.join().unwrap();
        let provider = out.get("http-test").expect("HTTP provider should load");
        assert_eq!(provider.provider_type, ProviderType::Http);
        assert_eq!(provider.rule_count(), 1);
    }

    #[test]
    fn raw_rule_provider_deserializes_list_header() {
        // The mihomo wiki form (map[string][]string): sequence values.
        let yaml = r#"
type: http
behavior: classical
url: "https://example.com/Google.yaml"
header:
  User-Agent:
    - "mihomo/1.18.3"
  Authorization:
    - 'token 1231231'
"#;
        let raw: RawRuleProvider = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(
            provider_headers(&raw),
            vec![
                ("Authorization".to_string(), "token 1231231".to_string()),
                ("User-Agent".to_string(), "mihomo/1.18.3".to_string()),
            ]
        );
    }

    #[test]
    fn raw_rule_provider_deserializes_single_string_header() {
        // meow-rs's legacy single-string form keeps working.
        let yaml = r#"
type: http
behavior: domain
url: "https://example.com/list.yaml"
header:
  Authorization: "Bearer token123"
"#;
        let raw: RawRuleProvider = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(
            provider_headers(&raw),
            vec![("Authorization".to_string(), "Bearer token123".to_string())]
        );
    }

    /// Custom `header:` entries must reach the wire as real field lines —
    /// one per list entry (RFC 9110 §5.2) — and a user-supplied
    /// User-Agent must replace the built-in default (mihomo parity).
    #[test]
    fn http_provider_sends_custom_headers_on_the_wire() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for HTTP client"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("HTTP test listener failed: {e}"),
                }
            };
            // The accepted stream can inherit the listener's nonblocking flag, which
            // would make the read/write below return `WouldBlock`. Force blocking mode.
            stream.set_nonblocking(false).unwrap();
            let mut buf = vec![0_u8; 2048];
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "expected an HTTP request from the client");
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = "payload:\n  - 'example.com'\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            head
        });

        let mut header = HashMap::new();
        header.insert(
            "User-Agent".to_string(),
            crate::raw::StringOrList::List(vec![
                "Clash/v1.18.0".to_string(),
                "mihomo/1.18.3".to_string(),
            ]),
        );
        let mut providers = HashMap::new();
        providers.insert(
            "hdr-test".to_string(),
            RawRuleProvider {
                provider_type: "http".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: Some(format!("http://{addr}/rules.yaml")),
                path: None,
                interval: None,
                proxy: None,
                header: Some(header),
                payload: None,
            },
        );

        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        let head = server.join().unwrap();
        let provider = out.get("hdr-test").expect("HTTP provider should load");
        assert_eq!(provider.rule_count(), 1);
        // Both list entries are on the wire as separate field lines, and the
        // built-in default UA is suppressed (exactly two User-Agent lines).
        assert_eq!(
            head.lines()
                .filter(|l| l.to_ascii_lowercase().starts_with("user-agent:"))
                .count(),
            2,
            "request head: {head}"
        );
        assert!(head.contains("User-Agent: Clash/v1.18.0\r\n"));
        assert!(head.contains("User-Agent: mihomo/1.18.3\r\n"));
    }

    /// A lone string value must reach the wire as one field line (and, as
    /// a UA, still replace the built-in default).
    #[test]
    fn http_provider_sends_single_string_header_on_the_wire() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for HTTP client"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("HTTP test listener failed: {e}"),
                }
            };
            // The accepted stream can inherit the listener's nonblocking flag, which
            // would make the read/write below return `WouldBlock`. Force blocking mode.
            stream.set_nonblocking(false).unwrap();
            let mut buf = vec![0_u8; 2048];
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "expected an HTTP request from the client");
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = "payload:\n  - 'example.com'\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            head
        });

        let mut header = HashMap::new();
        header.insert(
            "User-Agent".to_string(),
            crate::raw::StringOrList::Single("sing-string-ua/9.9".to_string()),
        );
        let mut providers = HashMap::new();
        providers.insert(
            "hdr-single-test".to_string(),
            RawRuleProvider {
                provider_type: "http".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: Some(format!("http://{addr}/rules.yaml")),
                path: None,
                interval: None,
                proxy: None,
                header: Some(header),
                payload: None,
            },
        );

        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        let head = server.join().unwrap();
        let provider = out
            .get("hdr-single-test")
            .expect("HTTP provider should load");
        assert_eq!(provider.rule_count(), 1);
        // Exactly one UA line: the user's single string, and the built-in
        // default is suppressed (replace semantics, not duplicate).
        assert_eq!(
            head.lines()
                .filter(|l| l.to_ascii_lowercase().starts_with("user-agent:"))
                .count(),
            1,
            "request head: {head}"
        );
        assert!(head.contains("User-Agent: sing-string-ua/9.9\r\n"));
    }

    #[test]
    fn live_ruleset_map_returns_all_providers() {
        let mut providers = HashMap::new();
        providers.insert(
            "p1".to_string(),
            RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                proxy: None,
                header: None,
                payload: Some(vec!["example.com".to_string()]),
            },
        );
        providers.insert(
            "p2".to_string(),
            RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "ipcidr".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                proxy: None,
                header: None,
                payload: Some(vec!["10.0.0.0/8".to_string()]),
            },
        );
        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        let ruleset_map = live_ruleset_map(&out);
        assert_eq!(ruleset_map.len(), 2);
        assert!(ruleset_map.contains_key("p1"));
        assert!(ruleset_map.contains_key("p2"));
        // The map hands out the providers themselves, not detached snapshots.
        assert!(Arc::ptr_eq(
            &(Arc::clone(&out["p1"]) as Arc<dyn RuleSet>),
            &ruleset_map["p1"]
        ));
        assert_eq!(ruleset_map["p1"].behavior(), RuleSetBehavior::Domain);
        assert_eq!(ruleset_map["p2"].behavior(), RuleSetBehavior::IpCidr);
        assert_eq!(ruleset_map["p1"].len(), 1);
    }

    /// Serve `bodies` one per accepted connection, in order, then exit.
    fn serve_in_order(
        listener: std::net::TcpListener,
        bodies: Vec<&'static str>,
    ) -> std::thread::JoinHandle<()> {
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            for body in bodies {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "timed out waiting for HTTP client"
                            );
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("HTTP test listener failed: {e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                let mut buf = [0_u8; 1024];
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "expected an HTTP request from the client");
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        })
    }

    /// Issue #553: a `RULE-SET` rule parsed against the provider map must
    /// observe `refresh()` without a config rebuild.  Before the fix the
    /// map held detached snapshots, so the same rule object kept matching
    /// the startup payload after a successful refresh.
    #[tokio::test]
    async fn rule_set_rule_observes_refresh_without_rebuild() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve_in_order(
            listener,
            vec![
                "payload:\n  - 'old.example'\n",
                "payload:\n  - 'new.example'\n",
            ],
        );

        let mut providers = HashMap::new();
        providers.insert(
            "live".to_string(),
            RawRuleProvider {
                url: Some(format!("http://{addr}/rules.yaml")),
                ..http_cfg(None)
            },
        );
        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        let provider = out.get("live").expect("HTTP provider should load");
        assert_eq!(provider.rule_count(), 1);

        // Exactly what the config rebuild does: parse `rules:` against the
        // provider map, then keep the resulting rule objects.
        let map = live_ruleset_map(&out);
        let rules = crate::rule_parser::parse_rules_full(
            &["RULE-SET,live,DIRECT".to_string()],
            &map,
            &ctx(),
            &HashMap::new(),
            false,
        )
        .expect("RULE-SET parses");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        let helper = RuleMatchHelper;
        let old = Metadata {
            host: "old.example".into(),
            ..Metadata::default()
        };
        let new = Metadata {
            host: "new.example".into(),
            ..Metadata::default()
        };
        assert!(rule.match_metadata(&old, &helper));
        assert!(!rule.match_metadata(&new, &helper));

        let before = provider.updated_at_secs();
        provider.refresh().await.expect("refresh");
        server.join().unwrap();
        assert!(provider.updated_at_secs() >= before);

        // Same rule object, no rebuild: the refreshed payload is what matches.
        assert!(
            rule.match_metadata(&new, &helper),
            "refreshed provider content must reach the live RULE-SET rule (issue #553)"
        );
        assert!(!rule.match_metadata(&old, &helper));
        assert_eq!(map["live"].len(), 1);
    }

    /// Issue #543: a successful `refresh()` must persist the payload to the
    /// provider's cache file — otherwise a cache-first restart reverts
    /// to the initial-load-era payload until the next tick.
    #[tokio::test]
    async fn refresh_writes_payload_cache_after_successful_parse() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve_in_order(
            listener,
            vec![
                "payload:\n  - 'old.example'\n",
                "payload:\n  - 'new.example'\n",
            ],
        );
        let dir = tempfile::tempdir().unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "live".to_string(),
            RawRuleProvider {
                url: Some(format!("http://{addr}/rules.yaml")),
                ..http_cfg(None)
            },
        );
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        let provider = out.get("live").unwrap();
        // The load wrote the implicit `<cache_dir>/rule-providers/live.yaml`.
        let cache = dir.path().join("rule-providers").join("live.yaml");
        assert_eq!(
            std::fs::read_to_string(&cache).unwrap(),
            "payload:\n  - 'old.example'\n"
        );

        provider.refresh().await.expect("refresh");
        server.join().unwrap();
        assert_eq!(
            std::fs::read_to_string(&cache).unwrap(),
            "payload:\n  - 'new.example'\n",
            "refresh must persist the new payload for cache-first restarts"
        );
    }

    // -- issue #429: provider paths must stay inside the cache dir ---------

    #[test]
    fn resolve_path_rejects_escaping_paths() {
        let dir = tempfile::tempdir().unwrap();
        for p in ["../../etc/pwned", "/etc/cron.d/pwned", "a/../../b"] {
            let mut cfg = http_cfg(None);
            cfg.path = Some(p.to_string());
            let err = resolve_path(&cfg, Some(dir.path()), "x", true)
                .expect_err("escaping path must be rejected");
            assert!(err.to_string().contains("escapes"), "path {p}: {err}");
        }
    }

    #[test]
    fn resolve_path_keeps_contained_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = http_cfg(None);
        cfg.path = Some("sub/rules.yaml".to_string());
        let got = resolve_path(&cfg, Some(dir.path()), "x", true)
            .unwrap()
            .unwrap();
        assert!(got.starts_with(dir.path()), "unexpected: {}", got.display());

        // Absolute paths are fine as long as they stay inside the cache dir.
        cfg.path = Some(dir.path().join("rules.yaml").to_string_lossy().to_string());
        assert!(resolve_path(&cfg, Some(dir.path()), "x", true)
            .unwrap()
            .is_some());
    }

    #[test]
    fn file_provider_path_requires_cache_dir() {
        let mut cfg = http_cfg(None);
        cfg.provider_type = "file".to_string();
        cfg.url = None;
        cfg.path = Some("/etc/passwd".to_string());
        let err =
            resolve_path(&cfg, None, "x", true).expect_err("file path without root must fail");
        assert!(
            err.to_string().contains("cache directory"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn implicit_path_from_hostile_provider_name_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = http_cfg(None); // no `path:` — implicit location from the name
        let err = resolve_path(&cfg, Some(dir.path()), "../../evil", true)
            .expect_err("traversal via provider name must be rejected");
        assert!(err.to_string().contains("escapes"), "unexpected: {err}");
    }

    /// PR #444 review follow-up: a stray `path:` on an inline provider must
    /// never fail a rebuild — inline providers never read it (mihomo ignores
    /// it too), so it is warn-and-ignored in every context.
    #[test]
    fn stray_path_on_inline_provider_is_ignored() {
        let inline_cfg = |path: &str| RawRuleProvider {
            provider_type: "inline".to_string(),
            behavior: "domain".to_string(),
            format: None,
            url: None,
            path: Some(path.to_string()),
            interval: None,
            proxy: None,
            header: None,
            payload: Some(vec!["example.com".to_string()]),
        };

        // No cache dir (the `PUT /configs` rebuild context): previously a
        // hard error, now ignored.
        let mut providers = HashMap::new();
        providers.insert("i".to_string(), inline_cfg("leftover.yaml"));
        validate_paths(&providers, None).expect("stray inline path must not fail validation");

        // Even an escaping path is irrelevant on a provider type that never
        // reads it.
        let dir = tempfile::tempdir().unwrap();
        providers.insert("i".to_string(), inline_cfg("../../etc/pwned"));
        validate_paths(&providers, Some(dir.path()))
            .expect("stray inline path must not be containment-checked");

        // And the provider itself still loads normally.
        let out =
            load_providers(&providers, Some(dir.path()), &ctx(), None, false).expect("load failed");
        assert_eq!(out.get("i").expect("inline must load").rule_count(), 1);
    }

    /// Regression test for issue #429: an http provider with a
    /// caller-supplied `path:` and no cache directory (the `PUT /configs`
    /// rebuild context) must fetch to memory and never write the path.
    #[test]
    fn http_provider_path_is_not_written_without_cache_dir() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return; // no fetch happened; the test still asserts no write
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("HTTP test listener failed: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let body = "payload:\n  - 'example.com'\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let victim_dir = tempfile::tempdir().unwrap();
        let victim = victim_dir.path().join("outside").join("pwned");

        let mut cfg = http_cfg(None);
        cfg.url = Some(format!("http://{addr}/rules.yaml"));
        cfg.path = Some(victim.to_string_lossy().to_string());
        let mut providers = HashMap::new();
        providers.insert("x".to_string(), cfg);

        let out = load_providers(&providers, None, &ctx(), None, false).expect("load failed");
        server.join().unwrap();

        // The provider still loads — payload fetched straight to memory…
        let p = out.get("x").expect("provider must load to memory");
        assert_eq!(p.rule_count(), 1);
        // …but the caller-named path was never written, nor its parents created.
        assert!(
            !victim.exists(),
            "attacker-controlled path was written: {}",
            victim.display()
        );
        assert!(
            !victim.parent().unwrap().exists(),
            "parent of the attacker-controlled path was created"
        );
    }

    /// PR #437 review follow-up: pin the body-size-cap *wiring* end to end —
    /// `fetch_http_async` (the direct, no-proxy fetch every rule-provider
    /// load/refresh goes through) must route its body read through
    /// `internal_http::response_bytes_with_limit`. The unit tests on
    /// `response_bytes_capped` cover the cap logic itself; here a local
    /// server declares a `Content-Length` above `MAX_BODY_BYTES` (so nothing
    /// close to 256 MiB is actually transferred) and the fetch must fail
    /// with the cap error before buffering the body.
    #[tokio::test]
    async fn fetch_http_async_rejects_oversized_response_end_to_end() {
        let oversized = internal_http::MAX_BODY_BYTES as u64 + 1;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let head =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {oversized}\r\n\r\ntiny-partial-body");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        let err = fetch_http_async(&format!("http://{addr}/rules.yaml"), None, &[])
            .await
            .expect_err("oversized response must be rejected");
        assert!(
            err.to_string().contains("exceeds max body size"),
            "unexpected error: {err:#}"
        );
    }

    /// Regression test for the issue #533 review: `refresh()` must re-parse
    /// the payload in the provider's *load-time* `ParserContext`, not a
    /// caller-supplied one. Both refresh callers (the interval task and
    /// `PUT /providers/rules/{name}`) previously passed
    /// `ParserContext::empty()`, which turned every `GEOSITE` entry in a
    /// refreshed classical payload into a never-matching rule — silent in
    /// lenient mode, a permanent refresh failure in strict mode.
    #[tokio::test]
    async fn file_provider_refresh_uses_load_time_parser_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.txt");
        std::fs::write(&path, "GEOSITE,testcat,DIRECT\n").unwrap();

        let mut geosite = meow_rules::geosite::GeositeDB::empty();
        geosite.insert("testcat", "first.example");
        let mut parse_ctx = ctx();
        parse_ctx.geosite = Some(Arc::new(geosite));

        let mut providers = HashMap::new();
        providers.insert(
            "geo-file".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "classical".to_string(),
                format: Some("text".to_string()),
                url: None,
                path: Some(path.to_string_lossy().to_string()),
                interval: None,
                proxy: None,
                header: None,
                payload: None,
            },
        );
        let out = load_providers(&providers, Some(dir.path()), &parse_ctx, None, false)
            .expect("load failed");
        let provider = out.get("geo-file").expect("provider must load");
        assert!(
            provider.snapshot().matches_domain("first.example"),
            "initial GEOSITE entry must match"
        );

        // Refresh with a payload that pairs the geosite entry with a plain
        // domain rule — proves both the swap happened (new rule visible)
        // and that the geosite entry still resolves (stored ctx used).
        std::fs::write(
            &path,
            "GEOSITE,testcat,DIRECT\nDOMAIN-SUFFIX,second.example,DIRECT\n",
        )
        .unwrap();
        provider.refresh().await.expect("refresh must succeed");
        let snap = provider.snapshot();
        assert_eq!(snap.len(), 2, "refreshed payload must replace the old");
        assert!(
            snap.matches_domain("second.example"),
            "new DOMAIN-SUFFIX rule must match"
        );
        assert!(
            snap.matches_domain("first.example"),
            "GEOSITE entry must keep matching — refresh used the stored ctx"
        );
    }

    // -- Cache-first load and the background initial fetch ----------------

    const OLD_RULES: &str = "payload:\n  - 'old.example'\n";
    const NEW_RULES: &str = "payload:\n  - 'new.example'\n  - 'newer.example'\n";

    fn http_provider(url: &str, interval: u64) -> RawRuleProvider {
        RawRuleProvider {
            url: Some(url.to_string()),
            interval: (interval > 0).then_some(interval),
            ..http_cfg(None)
        }
    }

    fn cache_file(dir: &Path, name: &str) -> PathBuf {
        dir.join("rule-providers").join(format!("{name}.yaml"))
    }

    fn write_cache_file(dir: &Path, name: &str, body: &str, age: Duration) -> PathBuf {
        let path = cache_file(dir, name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
        path
    }

    /// The prefetch waits on its downloads synchronously, so it runs off the
    /// test runtime, which keeps serving the origin.
    async fn prefetch_within(
        raw: &HashMap<String, RawRuleProvider>,
        dir: &Path,
        deadline: Option<Duration>,
    ) -> Arc<PrefetchedPayloads> {
        let (raw, dir) = (raw.clone(), dir.to_path_buf());
        tokio::task::spawn_blocking(move || {
            Arc::new(prefetch_payloads_within(
                &raw,
                Some(&dir),
                None,
                &|_| None,
                deadline,
            ))
        })
        .await
        .unwrap()
    }

    /// One load pass, off the test runtime too: an absent entry would make
    /// it download synchronously, and the origin must keep answering.
    async fn load_pass(
        raw: &HashMap<String, RawRuleProvider>,
        dir: &Path,
        prefetched: &Arc<PrefetchedPayloads>,
        strict: bool,
    ) -> HashMap<String, Arc<RuleProvider>> {
        let (raw, dir, prefetched) = (raw.clone(), dir.to_path_buf(), Arc::clone(prefetched));
        tokio::task::spawn_blocking(move || {
            load_providers_prefetched(
                &raw,
                Some(&dir),
                &ctx(),
                None,
                &|_| None,
                &prefetched,
                None,
                strict,
                &mut DroppedProviders::default(),
            )
            .unwrap()
        })
        .await
        .unwrap()
    }

    /// A cached provider loads with zero requests — startup runs two load
    /// passes over one prefetch, and neither touches the network — and the
    /// background fetch then replaces the cached generation and the cache.
    #[tokio::test]
    async fn cached_provider_loads_without_network_then_revalidates() {
        let origin = Origin::spawn(Some(NEW_RULES), true).await;
        let dir = tempfile::tempdir().unwrap();
        let cache = write_cache_file(dir.path(), "p", OLD_RULES, Duration::from_secs(600));
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 0))]);

        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let _first_pass = load_pass(&raw, dir.path(), &prefetched, false).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        let p = &providers["p"];
        assert_eq!(p.rule_count(), 1, "the cached generation is live");
        assert_eq!(
            origin.hits(),
            0,
            "a cached provider must not wait on the network"
        );
        let age = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - p.updated_at_secs();
        assert!(age >= 600, "updated_at reports the cache's age, got {age}s");

        let fetch = p
            .spawn_initial_fetch()
            .expect("a cache without `interval` is revalidated");
        fetch.await.unwrap();
        assert_eq!(p.rule_count(), 2);
        assert_eq!(origin.hits(), 1);
        assert_eq!(std::fs::read_to_string(&cache).unwrap(), NEW_RULES);
        assert!(
            p.spawn_initial_fetch().is_none(),
            "the obligation is taken once"
        );
    }

    /// With an `interval`, a cache younger than it is left to the refresh
    /// loop; one at least that old is revalidated at once.
    #[tokio::test]
    async fn cache_with_interval_is_revalidated_only_once_stale() {
        let origin = Origin::spawn(Some(NEW_RULES), true).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 3600))]);

        write_cache_file(dir.path(), "p", OLD_RULES, Duration::from_secs(60));
        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        assert!(providers["p"].spawn_initial_fetch().is_none());

        write_cache_file(dir.path(), "p", OLD_RULES, Duration::from_secs(7200));
        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        let p = &providers["p"];
        assert_eq!(p.rule_count(), 1);
        p.spawn_initial_fetch()
            .expect("a stale cache is revalidated")
            .await
            .unwrap();
        assert_eq!(p.rule_count(), 2);
        assert_eq!(origin.hits(), 1);
    }

    /// Uncached providers download concurrently: a gated origin sees every
    /// request before it answers any. Each payload lands in its cache.
    #[tokio::test]
    async fn uncached_providers_download_concurrently() {
        let origin = Origin::spawn(Some(NEW_RULES), false).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([
            ("a".to_string(), http_provider(&origin.url, 0)),
            ("b".to_string(), http_provider(&origin.url, 0)),
        ]);

        let prefetch = tokio::spawn({
            let (raw, dir) = (raw.clone(), dir.path().to_path_buf());
            async move { prefetch_within(&raw, &dir, None).await }
        });
        eventually("both downloads in flight", || origin.hits() == 2).await;
        origin.gate.send_replace(true);
        let prefetched = prefetch.await.unwrap();

        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        for name in ["a", "b"] {
            assert_eq!(providers[name].rule_count(), 2);
            assert!(providers[name].spawn_initial_fetch().is_none());
            assert_eq!(
                std::fs::read_to_string(cache_file(dir.path(), name)).unwrap(),
                NEW_RULES
            );
        }
        assert_eq!(origin.hits(), 2);
    }

    /// A failed download is not repeated by the load passes (startup ran
    /// it three times, one after another): the provider starts empty and
    /// the background fetch retries until the feed recovers.
    #[tokio::test]
    async fn failed_download_starts_empty_and_retries_in_background() {
        let origin = Origin::spawn(None, true).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 0))]);

        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let _first_pass = load_pass(&raw, dir.path(), &prefetched, false).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        let p = &providers["p"];
        assert_eq!(p.rule_count(), 0, "registered empty, so RULE-SET resolves");
        assert_eq!(origin.hits(), 1, "only the prefetch requested the payload");

        let fetch = p.spawn_initial_fetch().expect("an empty provider retries");
        eventually("a failed background attempt", || origin.hits() >= 3).await;
        *origin.body.lock() = Some(NEW_RULES);
        fetch.await.unwrap();
        assert_eq!(p.rule_count(), 2);
        assert_eq!(
            std::fs::read_to_string(cache_file(dir.path(), "p")).unwrap(),
            NEW_RULES
        );
    }

    /// A download still running at the deadline keeps going, and the
    /// provider adopts it when it lands instead of requesting it again.
    #[tokio::test]
    async fn deadline_hands_the_running_download_to_the_provider() {
        let origin = Origin::spawn(Some(NEW_RULES), false).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 0))]);

        let prefetched = prefetch_within(&raw, dir.path(), Some(Duration::from_millis(100))).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        let p = &providers["p"];
        assert_eq!(p.rule_count(), 0);

        let fetch = p
            .spawn_initial_fetch()
            .expect("the running download is owed");
        origin.gate.send_replace(true);
        fetch.await.unwrap();
        assert_eq!(p.rule_count(), 2);
        assert_eq!(
            origin.hits(),
            1,
            "the straggler is adopted, not re-requested"
        );
        assert_eq!(
            std::fs::read_to_string(cache_file(dir.path(), "p")).unwrap(),
            NEW_RULES
        );
    }

    /// Logbook: a provider's first payload is its load. Adopted after the
    /// fetch deadline it records nothing; ending the failure its commit
    /// recorded, it records the recovery without a count to compare.
    #[tokio::test]
    async fn logbook_counts_a_first_payload_as_the_load() {
        let book = TestLogbook::install();
        let dir = tempfile::tempdir().unwrap();

        let origin = Origin::spawn(Some(NEW_RULES), false).await;
        let raw = HashMap::from([("adopted".to_string(), http_provider(&origin.url, 0))]);
        let prefetched = prefetch_within(&raw, dir.path(), Some(Duration::from_millis(100))).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        let fetch = providers["adopted"].spawn_initial_fetch().unwrap();
        origin.gate.send_replace(true);
        fetch.await.unwrap();
        assert_eq!(providers["adopted"].rule_count(), 2);
        assert_eq!(book.entries("adopted"), vec![]);

        let origin = Origin::spawn(None, true).await;
        let raw = HashMap::from([("recovered".to_string(), http_provider(&origin.url, 0))]);
        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        assert_eq!(book.entries("recovered"), vec![], "not committed yet");
        let fetch = providers["recovered"].spawn_initial_fetch().unwrap();
        *origin.body.lock() = Some(NEW_RULES);
        fetch.await.unwrap();
        let entries = book.entries("recovered");
        let entries: Vec<_> = entries
            .iter()
            .map(|e| (e.level, e.message.as_str()))
            .collect();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(
            entries[0],
            (Level::Info, "Updated rule provider 'recovered': 2 rules")
        );
        assert_eq!(entries[1].0, Level::Error, "{entries:?}");
    }

    /// A cache that no longer parses is not a config defect, even under
    /// strict: the provider starts empty and the background fetch replaces
    /// the cache.
    #[tokio::test]
    async fn unparseable_cache_starts_empty_and_is_replaced() {
        let origin = Origin::spawn(Some(NEW_RULES), true).await;
        let dir = tempfile::tempdir().unwrap();
        let cache = write_cache_file(dir.path(), "p", "not a rule-set\n", Duration::ZERO);
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 3600))]);

        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, true).await;
        let p = &providers["p"];
        assert_eq!(p.rule_count(), 0);
        assert_eq!(origin.hits(), 0);
        p.spawn_initial_fetch()
            .expect("an unusable cache is refetched")
            .await
            .unwrap();
        assert_eq!(p.rule_count(), 2);
        assert_eq!(std::fs::read_to_string(&cache).unwrap(), NEW_RULES);
    }

    /// A cached provider whose feed stays down keeps its cached rules and
    /// gives up after `MAX_REVALIDATION_ATTEMPTS`.
    #[tokio::test]
    async fn cache_revalidation_retries_are_bounded() {
        let origin = Origin::spawn(None, true).await;
        let dir = tempfile::tempdir().unwrap();
        write_cache_file(dir.path(), "p", OLD_RULES, Duration::ZERO);
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 0))]);

        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        let p = &providers["p"];
        tokio::time::timeout(Duration::from_secs(10), p.spawn_initial_fetch().unwrap())
            .await
            .expect("revalidation gives up")
            .unwrap();
        assert_eq!(origin.hits(), MAX_REVALIDATION_ATTEMPTS as usize);
        assert_eq!(p.rule_count(), 1, "the cached rules stay installed");
    }

    #[tokio::test]
    async fn initial_fetch_ends_when_the_provider_is_dropped() {
        let origin = Origin::spawn(None, true).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 0))]);

        let prefetched = prefetch_within(&raw, dir.path(), None).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, false).await;
        let fetch = providers["p"].spawn_initial_fetch().unwrap();
        eventually("a background attempt", || origin.hits() >= 2).await;
        drop(providers);
        tokio::time::timeout(Duration::from_secs(5), fetch)
            .await
            .expect("the task ends with its provider")
            .unwrap();
    }

    /// Committing a provider through the refresh supervisor starts the
    /// fetch its load left owing.
    #[tokio::test]
    async fn reconcile_starts_the_owed_initial_fetch() {
        let origin = Origin::spawn(Some(NEW_RULES), true).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([("p".to_string(), http_provider(&origin.url, 0))]);

        let prefetched = prefetch_within(&raw, dir.path(), Some(Duration::ZERO)).await;
        let registry = Arc::new(RwLock::new(
            load_pass(&raw, dir.path(), &prefetched, false).await,
        ));
        let supervisor = crate::rule_provider_refresh::RefreshSupervisor::default();
        supervisor.reconcile(&registry);
        let p = Arc::clone(&registry.read()["p"]);
        eventually("the committed provider fills", || p.rule_count() == 2).await;
        supervisor.reconcile(&registry);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(origin.hits(), 1, "a later commit does not fetch again");
    }

    /// `123` is a non-string payload item — under strict the whole
    /// ruleset rejects, which used to make the *load* fatal too.
    const MIXED_BAD: &str = "payload:\n  - 'good.example'\n  - 123\n";

    /// A remote payload defect is third-party content: under strict it
    /// registers the provider empty and owes `InitialFetch::Retry` — the
    /// same acquisition shape a transport failure produces — instead of
    /// failing the build. The rejected bytes never reach the cache.
    #[tokio::test]
    async fn strict_remote_rule_payload_registers_empty() {
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([(
            "p".to_string(),
            http_provider("http://127.0.0.1:1/rules.yaml", 0),
        )]);
        let mut prefetched = PrefetchedPayloads::default();
        prefetched.entries.insert(
            "p".to_string(),
            Prefetched::Downloaded {
                bytes: MIXED_BAD.as_bytes().to_vec(),
                persisted: AtomicBool::new(false),
            },
        );
        let mut dropped = DroppedProviders::default();
        let out = load_providers_prefetched(
            &raw,
            Some(dir.path()),
            &ctx(),
            None,
            &|_| None,
            &prefetched,
            None,
            true,
            &mut dropped,
        )
        .expect("a remote payload defect must degrade under strict, not fail");
        let p = out.get("p").expect("the provider registers empty");
        assert_eq!(p.rule_count(), 0);
        assert!(
            dropped.is_empty(),
            "a degraded provider is registered, not dropped"
        );
        assert!(
            matches!(*p.initial_fetch.lock(), InitialFetch::Retry),
            "the provider owes the background retry"
        );
        // The cache write is gated on a successful parse — the rejected
        // bytes are never persisted.
        assert!(
            !cache_file(dir.path(), "p").exists(),
            "rejected remote bytes must not poison the cache"
        );
        // The owed fetch starts (127.0.0.1:1 refuses — a retry, not a spin).
        let fetch = p.spawn_initial_fetch();
        assert!(fetch.is_some(), "Retry must spawn the initial fetch");
    }

    /// A corrupt remote-derived cache degrades too — remote content at
    /// rest, not operator-authored bytes. The `is_offline_validate` fatal
    /// special case is gone, so the same arm serves `-t` and boot alike.
    /// The `-t` arm pins itself in a child process: `set_offline_validate`
    /// is a one-way process-global flag a parallel sibling test's prefetch
    /// could observe inside even the narrowest window.
    #[test]
    fn strict_corrupt_cache_degrades() {
        if std::env::var_os("MEOW_OFFLINE_VALIDATE_CHILD").is_some() {
            crate::set_offline_validate(true);
            corrupt_cache_degrades();
            return;
        }
        corrupt_cache_degrades();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "rule_provider::tests::strict_corrupt_cache_degrades",
                "--exact",
            ])
            .env("MEOW_OFFLINE_VALIDATE_CHILD", "1")
            .status()
            .expect("spawn the -t arm child");
        assert!(
            status.success(),
            "the corrupt cache must degrade under -t too"
        );
    }

    /// One `strict_corrupt_cache_degrades` pass — identical verdict under
    /// boot and under `set_offline_validate(true)` (the `-t` arm).
    fn corrupt_cache_degrades() {
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([(
            "p".to_string(),
            http_provider("http://127.0.0.1:1/rules.yaml", 0),
        )]);
        let mut prefetched = PrefetchedPayloads::default();
        prefetched.entries.insert(
            "p".to_string(),
            Prefetched::Cached {
                bytes: MIXED_BAD.as_bytes().to_vec(),
                modified: Some(SystemTime::now()),
            },
        );
        let mut dropped = DroppedProviders::default();
        let out = load_providers_prefetched(
            &raw,
            Some(dir.path()),
            &ctx(),
            None,
            &|_| None,
            &prefetched,
            None,
            true,
            &mut dropped,
        )
        .expect("a corrupt cache must degrade, not fail strict");
        let p = out.get("p").expect("the provider registers empty");
        assert_eq!(p.rule_count(), 0);
        assert!(dropped.is_empty());
        assert!(matches!(*p.initial_fetch.lock(), InitialFetch::Retry));
    }

    /// Whether a bad payload lands before or after the fetch deadline the
    /// strict verdict is identical: registered empty, retry owed. The
    /// pending download (deadline-exceeded) adopts instead — also
    /// registered empty — and fills when it lands.
    #[tokio::test]
    async fn strict_rule_deadline_race_gone() {
        let bad = Origin::spawn(Some(MIXED_BAD), true).await;
        let slow = Origin::spawn(Some(NEW_RULES), false).await;
        let dir = tempfile::tempdir().unwrap();
        let raw = HashMap::from([
            ("fast-bad".to_string(), http_provider(&bad.url, 0)),
            ("slow".to_string(), http_provider(&slow.url, 0)),
        ]);
        // `load_pass`/`prefetch_within` run off the test runtime so the
        // gated origin keeps answering.
        let prefetched = prefetch_within(&raw, dir.path(), Some(Duration::from_millis(50))).await;
        let providers = load_pass(&raw, dir.path(), &prefetched, true).await;
        for name in ["fast-bad", "slow"] {
            let p = &providers[name];
            assert_eq!(
                p.rule_count(),
                0,
                "{name} registers empty regardless of timing"
            );
        }
        assert!(matches!(
            *providers["fast-bad"].initial_fetch.lock(),
            InitialFetch::Retry
        ));
        assert!(matches!(
            *providers["slow"].initial_fetch.lock(),
            InitialFetch::Adopt(_)
        ));
        // The adopted download lands once the gate opens; the bad one
        // heals when the publisher fixes the payload.
        slow.gate.send_replace(true);
        let fetch = providers["slow"].spawn_initial_fetch().unwrap();
        eventually("the adopted download lands", || {
            providers["slow"].rule_count() == 2
        })
        .await;
        tokio::time::timeout(Duration::from_secs(5), fetch)
            .await
            .expect("the adopted fetch completes")
            .unwrap();
        *bad.body.lock() = Some(NEW_RULES);
        providers["fast-bad"].spawn_initial_fetch().unwrap();
        eventually("the retried payload heals", || {
            providers["fast-bad"].rule_count() == 2
        })
        .await;
    }
}
