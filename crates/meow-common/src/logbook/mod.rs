//! Logbook: a persistent, structured record of notable engine events.
//!
//! The runtime log (`GET /logs`) streams every line the engine emits and
//! keeps none of it. The logbook keeps the few events worth reading later
//! — a config reload, a provider update, members of a group going down, a
//! run that ended without a clean stop — on disk, so they are still there
//! after a restart or a crash. Entries are kept for [`RETENTION`] and the
//! database stays under [`MAX_SIZE`]. A meow extension; mihomo has no
//! equivalent.
//!
//! The logbook records engine and proxy events only, never the
//! destinations of user traffic: on a phone, a persistent list of hosts is
//! a browsing history.
//!
//! # Storage
//!
//! `<home>/logbook/logbook.db` is an SQLite database (bundled SQLite, WAL
//! mode) with one row per [`Entry`]; ADR-0014 documents the schema for
//! readers in other processes ([`read`]). An entry that is updated (a
//! repeat folded into it, see [`Event::coalesce`]) is written again in
//! place, at most once a minute. A committed write survives a killed
//! process; a power cut loses at most the writes since the last
//! checkpoint, never the database. A database that cannot be read is set
//! aside and the logbook starts over. A lock file keeps a second meow
//! process off the directory, and a run marker detects a run that ended
//! without [`engine_stopped`].
//!
//! Built without the `logbook` feature (the `minimal` bundle), the API
//! stays and nothing is recorded.
//!
//! # Recording
//!
//! Producers anywhere in the workspace build an [`event`] and
//! [`record`](Event::record) it. Recording never waits on the disk: the
//! write goes to a bounded queue that a writer thread drains. A write the
//! full queue refuses stays pending in memory and is tried again within a
//! minute, and a commit that fails is tried again too. With no logbook
//! installed (tests, benches, the `-t` config check) recording does
//! nothing.

#[cfg_attr(not(feature = "logbook"), path = "disabled.rs")]
mod store;
#[cfg(all(test, feature = "logbook"))]
mod tests;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use smol_str::SmolStr;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use store::Logbook;

/// How long entries are kept.
pub const RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Cap on the database, in bytes. Its write-ahead log adds up to a quarter
/// MiB while the logbook is open.
pub const MAX_SIZE: u64 = 2 * 1024 * 1024;

/// Newest entries kept in memory for queries and coalescing. Older pages
/// are read from the database.
pub const RECENT: usize = 256;

/// A repeat folds into the subject's latest entry only while that entry
/// last happened within this window.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Longest stored message, in bytes.
pub const MAX_MESSAGE: usize = 1024;

/// The logbook's directory under the meow home.
pub const DIR_NAME: &str = "logbook";

/// Event kinds: `<area>.<event>`. Clients filter, label and translate by
/// kind, so a kind is never renamed once released. The outcome of an event
/// is its [`Level`], not a separate kind.
pub mod kind {
    /// The engine started.
    pub const ENGINE_START: &str = "engine.start";
    /// The engine stopped cleanly.
    pub const ENGINE_STOP: &str = "engine.stop";
    /// The previous run ended without a clean stop: a crash, a kill, or a
    /// power cut.
    pub const ENGINE_UNCLEAN_EXIT: &str = "engine.unclean-exit";
    /// The logbook was cleared. Entries with a lower `id` are gone.
    pub const LOGBOOK_CLEARED: &str = "logbook.cleared";
    /// The database could not be read and the logbook started over; the
    /// old file is kept as `logbook.db.corrupt`. Ids start again from 1,
    /// so a client drops every entry it holds.
    pub const LOGBOOK_RESET: &str = "logbook.reset";
    /// The config was replaced (`PUT /configs`), or replacing it failed.
    pub const CONFIG_RELOAD: &str = "config.reload";
    /// The config was edited through the API: a subscription added or
    /// removed, a group or the rules changed. Never carries rule text.
    pub const CONFIG_CHANGE: &str = "config.change";
    /// A subscription refresh changed the config, or failed. Subject: the
    /// subscription.
    pub const SUBSCRIPTION_UPDATE: &str = "subscription.update";
    /// A proxy provider took a new payload, or fetching one failed.
    /// Subject: the provider.
    pub const PROXY_PROVIDER_UPDATE: &str = "proxy-provider.update";
    /// A rule provider took a new payload, or fetching one failed. Subject:
    /// the provider.
    pub const RULE_PROVIDER_UPDATE: &str = "rule-provider.update";
    /// The GeoIP, ASN or geosite database was downloaded, or downloading
    /// it failed. Subject: `GeoIP MMDB`, `ASN MMDB` or `geosite`.
    pub const GEODATA_UPDATE: &str = "geodata.update";
    /// A listener could not start. Subject: the listener.
    pub const LISTENER_START: &str = "listener.start";
    /// Outbound sockets were bound to another network interface, or no
    /// longer are.
    pub const NETWORK_INTERFACE: &str = "network.interface";
    /// Members of a health-checked group went down or came back. Subject:
    /// the group.
    pub const GROUP_HEALTH: &str = "group.health";
    /// A url-test or fallback group switched member. Subject: the group.
    pub const GROUP_SWITCH: &str = "group.switch";
}

/// Severity of an event, which is also its outcome: a failed reload is an
/// [`Error`](Level::Error) `config.reload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl std::str::FromStr for Level {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "unknown logbook level '{other}' (expected info, warning or error)"
            )),
        }
    }
}

/// One logbook entry, as stored and as served by `GET /logbook`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Identity and order: assigned at the first occurrence, increasing
    /// across restarts.
    pub id: u64,
    /// Write sequence: raised on every write of the entry, including a
    /// repeat folded into it, and increasing across restarts.
    /// `GET /logbook?since=<rev>` returns the entries written after `rev`.
    pub rev: u64,
    /// First occurrence.
    #[serde(with = "rfc3339")]
    pub time: SystemTime,
    /// Latest occurrence, once a repeat has been folded in.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub last: Option<SystemTime>,
    /// Occurrences folded into this entry.
    pub count: u32,
    pub kind: SmolStr,
    pub level: Level,
    /// What the event is about: a group, provider or listener name.
    #[serde(default, skip_serializing_if = "SmolStr::is_empty")]
    pub subject: SmolStr,
    /// One English sentence; for a folded entry, the latest occurrence's.
    pub message: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub fields: Map<String, Value>,
}

impl Entry {
    /// The latest occurrence.
    pub fn last_time(&self) -> SystemTime {
        self.last.unwrap_or(self.time)
    }
}

/// Retention and size bounds. The defaults are the documented ones; tests
/// shrink them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub retention: Duration,
    pub max_size: u64,
    pub recent: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            retention: RETENTION,
            max_size: MAX_SIZE,
            recent: RECENT,
        }
    }
}

/// Page size without `limit`, and the largest page.
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;

/// Which entries [`query`] and [`read`] return. All conditions must hold.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Page size, [`DEFAULT_LIMIT`] when unset, at most [`MAX_LIMIT`].
    pub limit: Option<usize>,
    /// Entries with a lower `id`: page back from the oldest one shown.
    pub before: Option<u64>,
    /// Entries written after this `rev`: poll with the last page's `rev`.
    pub since: Option<u64>,
    /// The lowest level returned.
    pub level: Option<Level>,
    /// A kind, or its area: `config` matches `config.reload`.
    pub kind: Option<String>,
    pub subject: Option<String>,
}

/// One page of entries, newest first.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Page {
    pub entries: Vec<Entry>,
    /// The latest `rev`: pass it as `since` to poll for what comes next.
    pub rev: u64,
    /// More matching entries exist past this page; page back with
    /// `before` set to the last entry's `id`.
    pub more: bool,
}

/// An event being built. Nothing is recorded until [`Event::record`].
#[must_use = "an event is recorded only by `record()`"]
#[derive(Debug, Clone)]
#[cfg_attr(
    not(feature = "logbook"),
    allow(dead_code, reason = "read by the store, which the feature leaves out")
)]
pub struct Event {
    kind: &'static str,
    level: Level,
    subject: SmolStr,
    message: String,
    fields: Map<String, Value>,
    coalesce: bool,
}

/// Start an event of `kind` (see [`kind`]) with its message.
pub fn event(kind: &'static str, level: Level, message: impl Into<String>) -> Event {
    let mut message = message.into();
    truncate_at_char_boundary(&mut message, MAX_MESSAGE);
    Event {
        kind,
        level,
        subject: SmolStr::default(),
        message,
        fields: Map::new(),
        coalesce: false,
    }
}

impl Event {
    /// What the event is about. Coalescing is per kind and subject.
    pub fn subject(mut self, subject: impl Into<SmolStr>) -> Self {
        self.subject = subject.into();
        self
    }

    /// A structured detail; a string is cut to [`MAX_MESSAGE`] like the
    /// message.
    pub fn field(mut self, key: &str, value: impl Into<Value>) -> Self {
        let mut value = value.into();
        if let Value::String(text) = &mut value {
            truncate_at_char_boundary(text, MAX_MESSAGE);
        }
        self.fields.insert(key.to_owned(), value);
        self
    }

    /// Fold this event into the latest entry of its kind and subject when
    /// that entry has the same level and last happened within
    /// [`COALESCE_WINDOW`]: the entry's count goes up and it takes this
    /// event's message and fields. Any other event of the kind for the
    /// subject in between starts a new entry, so a failure, a success and a
    /// failure stay three entries; events of other kinds do not interrupt.
    pub fn coalesce(mut self) -> Self {
        self.coalesce = true;
        self
    }

    /// Record the event in the installed logbook, if any.
    pub fn record(self) {
        if let Some(book) = current() {
            book.record(self);
        }
    }
}

static CURRENT: RwLock<Option<Arc<Logbook>>> = RwLock::new(None);

/// When the running engine started, between [`engine_started`] and
/// [`engine_stopped`].
static RUN: Mutex<Option<SystemTime>> = Mutex::new(None);

/// The installed logbook.
fn current() -> Option<Arc<Logbook>> {
    CURRENT
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Whether events are being recorded. Check it before building an
/// expensive event.
pub fn enabled() -> bool {
    CURRENT
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some()
}

/// Install a logbook in `dir`, replacing one installed elsewhere. A
/// logbook already installed in `dir` is kept. Installed while the engine
/// runs, it watches the rest of the run for an unclean exit. Fails with
/// [`io::ErrorKind::Unsupported`] when built without the `logbook`
/// feature.
pub fn install(dir: &Path, options: Options) -> io::Result<()> {
    if current().is_some_and(|book| book.dir() == dir) {
        return Ok(());
    }
    // Opened, and the previous one flushed, outside the lock: recording
    // goes on meanwhile.
    let book = Arc::new(Logbook::open(dir, options)?);
    let previous = CURRENT
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(Arc::clone(&book));
    if let Some(previous) = previous {
        previous.untrack_run();
        previous.flush();
    }
    let run = *RUN.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(started) = run {
        book.track_run(started, SystemTime::now());
    }
    Ok(())
}

/// Entries of the installed logbook matching `query`, newest first; `None`
/// when nothing is being recorded. Paging back past the newest
/// [`RECENT`] reads the database, so call it off the async runtime; that
/// read fails while the database cannot answer (another process holds its
/// lock, the disk fails).
pub fn query(query: &Query) -> Option<io::Result<Page>> {
    Some(current()?.query(query))
}

/// Delete every entry of the installed logbook, then record that it was
/// cleared ([`kind::LOGBOOK_CLEARED`]). Ids keep increasing, so a client
/// drops whatever it holds below that entry. Waits on the disk.
pub fn clear() {
    if let Some(book) = current() {
        book.clear();
    }
}

/// Entries matching `query` from the logbook in `dir`, read by a process
/// that does not write it: an app's UI while the engine runs in another
/// process, or after it stopped. Opens the database read-only for this one
/// read; repeats held back in the writer's memory (at most a minute) are
/// not seen yet. An empty page when there is no database.
pub fn read(dir: &Path, query: &Query) -> io::Result<Page> {
    store::read(dir, query)
}

/// The level of the latest entry of `kind` for `subject` in the installed
/// logbook, while it is among the newest [`RECENT`]. A producer that
/// records only changes asks it whether a success ends a failure the
/// logbook still shows: the object that saw the failure may have been
/// rebuilt since, or the engine restarted.
pub fn latest_level(kind: &str, subject: &str) -> Option<Level> {
    current()?.latest_level(kind, subject)
}

/// Whether the latest entry of `kind` for `subject` is an error (see
/// [`latest_level`]).
pub fn failing(kind: &str, subject: &str) -> bool {
    latest_level(kind, subject) == Some(Level::Error)
}

/// Set by [`apply`]: this process keeps a logbook under the meow home.
static MANAGED: AtomicBool = AtomicBool::new(false);

/// Apply the config's `logbook.enable` at startup: install the logbook
/// under the meow home ([`crate::resolved_home_dir`]) when enabled,
/// uninstall it when not. A failure to open it is logged and leaves
/// recording off. Called by the embedder (`meow` or a mobile FFI), never by
/// a library path, so a test never opens a logbook under the real home.
pub fn apply(enable: bool) {
    MANAGED.store(true, Ordering::Relaxed);
    if !enable {
        uninstall();
        return;
    }
    if enabled() {
        return;
    }
    let dir = crate::resolved_home_dir().join(DIR_NAME);
    match install(&dir, Options::default()) {
        Ok(()) => {}
        // `logbook.enable` defaults to true, so a `minimal` build would warn
        // at every start.
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            tracing::debug!("logbook: {e}; not recording");
        }
        Err(e) => tracing::warn!("logbook: cannot open {}: {e}; not recording", dir.display()),
    }
}

/// Apply a reloaded config's `logbook.enable`. Does nothing in a process
/// that never called [`apply`].
pub fn reconfigure(enable: bool) {
    if MANAGED.load(Ordering::Relaxed) {
        apply(enable);
    }
}

/// Stop recording, after writing out what is pending.
pub fn uninstall() {
    let previous = CURRENT
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(book) = previous {
        book.untrack_run();
        book.flush();
    }
}

/// Record the start of a run, and an unclean exit for a previous run that
/// never reached [`engine_stopped`]. Call it once the engine is up: a stop
/// requested while it was still starting may not reach [`engine_stopped`]
/// (a signal before its handler is installed kills the process), and would
/// be reported as an unclean exit. `config` names the config source (a
/// path, or `--config-string`).
pub fn engine_started(config: &str) {
    let now = SystemTime::now();
    *RUN.lock().unwrap_or_else(PoisonError::into_inner) = Some(now);
    if let Some(book) = current() {
        book.engine_started(config, now);
    }
}

/// How a run ended, for [`engine_stopped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop<'a> {
    /// Asked to stop; names what asked: `SIGTERM`, `service stop`, `app`.
    Requested(&'a str),
    /// Stopped on this error.
    Failed(&'a str),
}

/// Record the end of the run and write out what is pending. Either way the
/// run ended cleanly: it is not reported as an unclean exit.
pub fn engine_stopped(stop: Stop<'_>) {
    RUN.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some(book) = current() {
        book.engine_stopped(stop, SystemTime::now());
    }
}

/// `t` rounded down to whole milliseconds, the stored precision.
fn to_millis(t: SystemTime) -> SystemTime {
    t.duration_since(UNIX_EPOCH).map_or(UNIX_EPOCH, |since| {
        UNIX_EPOCH + Duration::new(since.as_secs(), since.subsec_millis() * 1_000_000)
    })
}

fn truncate_at_char_boundary(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let mut end = max - '…'.len_utf8();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push('…');
}

/// RFC 3339 times with millisecond precision, matching the rest of the API.
mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn format(t: SystemTime) -> String {
        OffsetDateTime::from(super::to_millis(t))
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
    }

    pub fn serialize<S: Serializer>(t: &SystemTime, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format(*t))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SystemTime, D::Error> {
        let s = <std::borrow::Cow<'_, str>>::deserialize(deserializer)?;
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(SystemTime::from)
            .map_err(serde::de::Error::custom)
    }
}

mod rfc3339_option {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;

    #[allow(
        clippy::ref_option,
        reason = "serde's `with` passes the field by reference"
    )]
    pub fn serialize<S: Serializer>(
        t: &Option<SystemTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => super::rfc3339::serialize(t, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "super::rfc3339")] SystemTime);
        Ok(Option::<Wrapper>::deserialize(deserializer)?.map(|Wrapper(t)| t))
    }
}
