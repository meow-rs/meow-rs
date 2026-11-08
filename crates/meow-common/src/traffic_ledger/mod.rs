//! Traffic ledger: how much each host, app, policy and network interface
//! carried, day by day, kept across restarts.
//!
//! [`crate::traffic`] counts what each proxy carried since the engine
//! started and forgets it at a stop. The ledger keeps, for every local day,
//! the bytes sent and received and the connections opened (and UDP flows
//! that sent something) per registrable domain, app, leaf proxy (and the
//! member that carried its `dialer-proxy` hop) and interface label, for
//! [`RETENTION_DAYS`] — enough for a client to show today, this month and
//! last month, grouped any of the four ways. A meow extension; mihomo has
//! no equivalent.
//!
//! Unlike the logbook (ADR-0014), the ledger records destinations: with
//! hosts on, it is a coarse browsing history (registrable domains, no
//! paths, no times finer than a day), and with apps on, one by app. It never
//! leaves the device; a config turns it off (`traffic-ledger.enable:
//! false`), keeps no hosts (`hosts: false`) or no apps (`apps: false`),
//! and [`clear`] empties it.
//!
//! # Storage
//!
//! `<home>/traffic/traffic.db` is an SQLite database (bundled SQLite, WAL
//! mode) with one row per day, host, app, policy, `dialer-proxy` hop and
//! interface; readers in
//! other processes ([`read`]) rely on its schema. A database that cannot be read
//! is set aside and the ledger starts over, and a lock file keeps a second
//! meow process off the directory, as for the logbook.
//!
//! Built without the `traffic-ledger` feature (the `minimal` bundle), the
//! API stays and nothing is recorded.
//!
//! # Recording
//!
//! The relay path is untouched: a connection keeps counting into its own
//! counters, and the tunnel, a [`Source`], hands the ledger what its
//! connections carried since the last time — every [`FLUSH_INTERVAL`], at
//! local midnight, before the interface label changes, at a query and at a
//! stop — and what a connection carried last as it closes. What it hands
//! over is counted under the interface label read as it takes it (a
//! [`Mark`]), and the writer thread commits it all in one transaction under
//! the current day.

#[cfg_attr(not(feature = "traffic-ledger"), path = "disabled.rs")]
mod store;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use store::Ledger;

/// Days kept, today included. 62 always covers last month in full: on the
/// 31st after a 31-day month, its 1st is 61 days back.
pub const RETENTION_DAYS: i32 = 62;

/// How often the tunnel's counts reach the disk while the engine runs. A
/// reader in another process sees the traffic up to this long late.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// The ledger's directory under the meow home.
pub const DIR_NAME: &str = "traffic";

/// Distinct IP-address hosts kept per day; past it, a day's other flows to
/// bare addresses (peer-to-peer swarms, a scan) fold into [`OTHER_IPS`].
pub const MAX_IP_HOSTS: usize = 8192;

/// The host of flows to bare IP addresses past a day's [`MAX_IP_HOSTS`].
pub const OTHER_IPS: &str = "*";

/// How the rows of a [`Report`] are grouped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupBy {
    /// The registrable domain (`example.co.uk` for `www.example.co.uk`),
    /// the address for a flow to a bare IP, empty with hosts off.
    #[default]
    Host,
    /// The app that opened the flow: the package name on Android, the
    /// `.app` bundle on macOS, the process name elsewhere; empty when the
    /// platform cannot tell or with apps off.
    App,
    /// The proxy that carried the traffic, as `/statistics` counts it: a
    /// group's member, never the group; `DIRECT` and `REJECT` too. A flow
    /// counts under the leaf proxy it left through and, when that proxy
    /// reaches its server through a `dialer-proxy`, under the member that
    /// carried that hop as well ([`Route::via`], [`Row::via_upload`]). The
    /// rows then add up to more than the [`Report`], which counts each flow
    /// once; the other groupings count each flow in one row.
    Policy,
    /// The label the platform set with [`set_interface`] when the traffic
    /// reached the ledger: `Wi-Fi`, `Cellular`; empty when none was set.
    Interface,
}

impl GroupBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::App => "app",
            Self::Policy => "policy",
            Self::Interface => "interface",
        }
    }
}

impl std::str::FromStr for GroupBy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "host" => Ok(Self::Host),
            "app" => Ok(Self::App),
            "policy" => Ok(Self::Policy),
            "interface" => Ok(Self::Interface),
            _ => Err(format!(
                "unknown grouping {s:?}: expected host, app, policy or interface"
            )),
        }
    }
}

/// What a [`Report`] covers: the days `from..=to` (local days since
/// 1970-01-01, see [`day_of_date`]), grouped `by` one column, keeping only
/// the rows whose other columns match the filters given. Drilling into a
/// row is the same query filtered on it and grouped another way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub from: i32,
    pub to: i32,
    pub by: GroupBy,
    pub host: Option<String>,
    pub app: Option<String>,
    /// The flows a [`GroupBy::Policy`] row of this proxy counts: the ones
    /// it left through and the ones whose `dialer-proxy` hop it carried.
    pub policy: Option<String>,
    pub interface: Option<String>,
}

/// One group of a [`Report`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub name: String,
    pub upload: u64,
    pub download: u64,
    pub requests: u64,
    /// Of the above, what this proxy carried as another one's
    /// `dialer-proxy` hop ([`GroupBy::Policy`]; zero in the other
    /// groupings).
    #[serde(default)]
    pub via_upload: u64,
    #[serde(default)]
    pub via_download: u64,
    #[serde(default)]
    pub via_requests: u64,
}

/// A [`Query`] answered: its rows by total bytes, largest first, and the
/// sums of the flows they cover, each counted once. Those are the sums of
/// the rows, but for [`GroupBy::Policy`] rows that carried hops.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// `YYYY-MM-DD`.
    pub from: String,
    /// `YYYY-MM-DD`, included.
    pub to: String,
    pub by: GroupBy,
    pub upload: u64,
    pub download: u64,
    pub requests: u64,
    pub rows: Vec<Row>,
}

/// How a ledger records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Record hosts; off, every row's host is empty.
    pub hosts: bool,
    /// Record the app that opened each flow; off, every row's app is
    /// empty, and no platform lookup runs for it.
    pub apps: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            hosts: true,
            apps: true,
        }
    }
}

/// The UTC offset that turns a Unix time into a local day. Set by the
/// embedder ([`set_time_zone`]), which knows the device's zone: UTC until
/// then.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeZone {
    /// Seconds east of UTC, now.
    pub offset: i32,
    /// The next change of offset (daylight saving), when known: the Unix
    /// second it happens and the offset from then on.
    pub next: Option<(i64, i32)>,
}

impl TimeZone {
    fn offset_at(&self, unix: i64) -> i32 {
        match self.next {
            Some((at, offset)) if unix >= at => offset,
            _ => self.offset,
        }
    }

    /// The local day `unix` falls on.
    pub fn day(&self, unix: i64) -> i32 {
        let local = unix + i64::from(self.offset_at(unix));
        i32::try_from(local.div_euclid(86_400)).unwrap_or(i32::MAX)
    }

    /// The Unix second the local day after `unix`'s begins: midnight on the
    /// offset in force then, or the change of offset itself when it skips
    /// past midnight (a zone that springs forward at 00:00).
    #[cfg_attr(not(feature = "traffic-ledger"), allow(dead_code))]
    fn next_midnight(&self, unix: i64) -> i64 {
        let start = (i64::from(self.day(unix)) + 1) * 86_400;
        let midnight = start - i64::from(self.offset_at(unix));
        match self.next {
            Some((at, offset)) if at <= midnight => (start - i64::from(offset)).max(at),
            _ => midnight,
        }
    }
}

/// Unix days since 1970-01-01 (local days, for the ledger) as `YYYY-MM-DD`.
pub fn date_of_day(day: i32) -> String {
    let date = time::Date::from_julian_day(day.saturating_add(UNIX_EPOCH_JULIAN_DAY))
        .unwrap_or(time::Date::MIN);
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// The day number of a `YYYY-MM-DD` date, as [`Query`] takes it.
pub fn day_of_date(date: &str) -> Option<i32> {
    let mut parts = date.splitn(3, '-');
    let year = parts.next()?.parse().ok()?;
    let month = time::Month::try_from(parts.next()?.parse::<u8>().ok()?).ok()?;
    let day = parts.next()?.parse().ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    Some(date.to_julian_day() - UNIX_EPOCH_JULIAN_DAY)
}

const UNIX_EPOCH_JULIAN_DAY: i32 = 2_440_588;

/// Something that counts traffic the ledger has not been handed yet: the
/// tunnel's connection table.
pub trait Source: Send + Sync {
    /// [`add`] what every live flow carried since the last call.
    fn settle(&self);
}

/// The proxies a flow is counted under ([`GroupBy::Policy`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    /// The leaf proxy the flow left through: a group's member, never the
    /// group.
    pub policy: Arc<str>,
    /// When `policy` reaches its server through a `dialer-proxy`, the
    /// member that carries that hop: the front's pick, or the front when it
    /// is no group.
    pub via: Option<Arc<str>>,
}

/// A flow through `policy` and no `dialer-proxy`.
impl From<&str> for Route {
    fn from(policy: &str) -> Self {
        Self {
            policy: Arc::from(policy),
            via: None,
        }
    }
}

/// Bytes and requests not yet written, by host, app, route and interface
/// label.
type Pending = HashMap<(SmolStr, SmolStr, Route, SmolStr), Counts>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    upload: u64,
    download: u64,
    requests: u64,
}

impl Counts {
    fn merge(&mut self, other: Self) {
        self.upload = self.upload.saturating_add(other.upload);
        self.download = self.download.saturating_add(other.download);
        self.requests = self.requests.saturating_add(other.requests);
    }
}

static CURRENT: RwLock<Option<Arc<Ledger>>> = RwLock::new(None);
/// Whether a ledger is installed, for producers that check per connection.
static ENABLED: AtomicBool = AtomicBool::new(false);
/// [`Options::hosts`] of the installed ledger.
static HOSTS: AtomicBool = AtomicBool::new(true);
/// [`Options::apps`] of the installed ledger.
static APPS: AtomicBool = AtomicBool::new(true);
/// Moved on as the ledger drops what every flow carried so far (see
/// [`epoch`]).
static EPOCH: AtomicU32 = AtomicU32::new(0);
static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
static SOURCES: Mutex<Vec<Weak<dyn Source>>> = Mutex::new(Vec::new());
static INTERFACE: Mutex<SmolStr> = Mutex::new(SmolStr::new_inline(""));
static ZONE: Mutex<TimeZone> = Mutex::new(TimeZone {
    offset: 0,
    next: None,
});

fn current() -> Option<Arc<Ledger>> {
    CURRENT
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Whether traffic is being recorded. A producer checks it once per
/// connection before keeping anything for the ledger.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Whether hosts are recorded; when not, a producer passes an empty host.
pub fn hosts() -> bool {
    HOSTS.load(Ordering::Relaxed)
}

/// Whether apps are recorded; when not, a producer passes an empty app and
/// looks none up.
pub fn apps() -> bool {
    APPS.load(Ordering::Relaxed)
}

/// Moves on as the ledger drops what every flow carried so far: at a
/// [`clear`], and as a ledger is installed while none recorded. A flow
/// that settles under an older epoch than its last settle drops what it
/// carried until then, and the request it has not counted, as a flow whose
/// app was still being looked up was not settled by the drop.
pub fn epoch() -> u32 {
    EPOCH.load(Ordering::Relaxed)
}

/// Count traffic toward `host` (a domain or an IP address as text, empty
/// for none) from `app` (see [`GroupBy::App`], empty for none) through
/// `route`, on the interface label set now: [`Mark::add`] with a [`mark`]
/// read now. Does nothing while no ledger is installed.
pub fn add(
    host: &SmolStr,
    app: &SmolStr,
    route: &Route,
    upload: u64,
    download: u64,
    requests: u64,
) {
    mark().add(host, app, route, upload, download, requests);
}

/// The [`epoch`] and the interface label traffic counts under, as a
/// settle reads them before it takes the bytes a flow carried. A clear or
/// a label change that lands while it takes them then cannot file them as
/// carried after it: a clear drops them, and a label change leaves them
/// under the label they were carried on.
pub struct Mark {
    epoch: u32,
    interface: SmolStr,
}

/// The [`Mark`] of this moment.
pub fn mark() -> Mark {
    Mark {
        epoch: epoch(),
        interface: interface(),
    }
}

impl Mark {
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Count traffic carried up to this mark, as [`add`] does: once per
    /// connection with its `requests`, then with its bytes as the tunnel
    /// settles. Dropped when the ledger dropped what flows carried since
    /// (a [`clear`]).
    pub fn add(
        self,
        host: &SmolStr,
        app: &SmolStr,
        route: &Route,
        upload: u64,
        download: u64,
        requests: u64,
    ) {
        if !enabled() || (upload == 0 && download == 0 && requests == 0) {
            return;
        }
        let held = {
            let mut pending = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
            // Read under the lock a clear takes what is pending under: a
            // clear moves the epoch on before it takes, so what is added
            // after its take sees the new epoch.
            if EPOCH.load(Ordering::Relaxed) != self.epoch {
                return;
            }
            let pending = pending.get_or_insert_with(HashMap::new);
            pending
                .entry((host.clone(), app.clone(), route.clone(), self.interface))
                .or_default()
                .merge(Counts {
                    upload,
                    download,
                    requests,
                });
            pending.len()
        };
        if held == EARLY_FLUSH {
            if let Some(ledger) = current() {
                ledger.nudge();
            }
        }
    }
}

/// Distinct hosts, apps and policies pending at which the writer is asked for a
/// flush ahead of [`FLUSH_INTERVAL`]: a burst of flows to distinct hosts (a
/// scan) does not hold more in memory than this, give or take what arrives
/// while the flush runs.
const EARLY_FLUSH: usize = 4096;

/// Ask every live [`Source`] to settle.
fn settle_sources() {
    let sources: Vec<Arc<dyn Source>> = {
        let mut sources = SOURCES.lock().unwrap_or_else(PoisonError::into_inner);
        sources.retain(|source| source.strong_count() > 0);
        sources.iter().filter_map(Weak::upgrade).collect()
    };
    for source in sources {
        source.settle();
    }
}

/// Take what is pending, after asking every live [`Source`] to settle.
fn take_pending() -> Pending {
    settle_sources();
    PENDING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap_or_default()
}

/// Drop what is pending and what every flow carried so far.
fn discard_pending() {
    EPOCH.fetch_add(1, Ordering::Relaxed);
    drop(take_pending());
}

/// Register `source`; it is asked to settle until it is dropped.
pub fn register(source: Weak<dyn Source>) {
    SOURCES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(source);
}

/// Held across a change of [`INTERFACE`] or [`ZONE`] and the settle or
/// flush before it, so a change racing another cannot be lost to it.
static CHANGING: Mutex<()> = Mutex::new(());

/// Set the label the platform gives the network the engine's traffic goes
/// out on (`Wi-Fi`, `Cellular`, `en0`). What the flows carried until now
/// is counted under the previous label first, here rather than by the
/// writer, so a writer held up by the disk cannot file it under the new
/// one. Kept across installs.
pub fn set_interface(label: &str) {
    let _changing = CHANGING.lock().unwrap_or_else(PoisonError::into_inner);
    if *INTERFACE.lock().unwrap_or_else(PoisonError::into_inner) == label {
        return;
    }
    if enabled() {
        settle_sources();
    }
    *INTERFACE.lock().unwrap_or_else(PoisonError::into_inner) = SmolStr::new(label);
}

/// The interface label traffic is written under now.
fn interface() -> SmolStr {
    INTERFACE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Set the device's time zone, which decides the day traffic is written
/// under; UTC until set. An embedder sets it before it starts the engine
/// and whenever the zone changes. What was counted is written under the
/// previous zone's day first, and the writer then waits for the new zone's
/// midnight. A writer held up past [`flush`]'s wait files that under the
/// new zone's day instead: unlike the interface label, the day is decided
/// as the writer takes what is pending.
pub fn set_time_zone(zone: TimeZone) {
    let _changing = CHANGING.lock().unwrap_or_else(PoisonError::into_inner);
    if *ZONE.lock().unwrap_or_else(PoisonError::into_inner) == zone {
        return;
    }
    let ledger = current();
    if let Some(ledger) = &ledger {
        ledger.flush();
    }
    *ZONE.lock().unwrap_or_else(PoisonError::into_inner) = zone;
    if let Some(ledger) = &ledger {
        ledger.flush();
    }
}

fn zone() -> TimeZone {
    *ZONE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Today, in the device's time zone, as [`Query`] counts days.
pub fn today() -> i32 {
    zone().day(unix_now())
}

/// Install a ledger in `dir`, replacing one installed elsewhere; a ledger
/// already installed in `dir` takes `options`. Fails with
/// [`io::ErrorKind::Unsupported`] when built without the `traffic-ledger`
/// feature.
pub fn install(dir: &Path, options: Options) -> io::Result<()> {
    if let Some(ledger) = current().filter(|ledger| ledger.dir() == dir) {
        if (options.hosts, options.apps) != (hosts(), apps()) {
            // What was counted is written under the options it was
            // counted with.
            ledger.flush();
            HOSTS.store(options.hosts, Ordering::Relaxed);
            APPS.store(options.apps, Ordering::Relaxed);
        }
        return Ok(());
    }
    let ledger = Arc::new(Ledger::open(dir)?);
    if enabled() {
        // What was counted goes to the ledger it was counted for, under its
        // options, before this one takes over.
        if let Some(previous) = current() {
            previous.flush();
        }
    } else {
        // Flows that outlived an earlier ledger carried traffic while none
        // recorded; dropping it keeps it out of this one.
        discard_pending();
    }
    let previous = CURRENT
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(ledger);
    HOSTS.store(options.hosts, Ordering::Relaxed);
    APPS.store(options.apps, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Relaxed);
    // Its writer writes what arrived since as it stops.
    drop(previous);
    Ok(())
}

/// Stop recording, after writing out what is pending.
pub fn uninstall() {
    let previous = CURRENT
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(ledger) = previous {
        // What the flows carried is counted while the ledger still
        // records, here rather than by a writer the disk may hold up past
        // a flush's wait.
        settle_sources();
        ENABLED.store(false, Ordering::Relaxed);
        // Hanging up, its writer writes what is pending as it stops.
        drop(ledger);
    }
}

/// Write out what the tunnel counted so far and wait for it. An embedder
/// calls it as the app goes to the background; [`uninstall`] does it too.
pub fn flush() {
    if let Some(ledger) = current() {
        ledger.flush();
    }
}

/// Answer `query` from the installed ledger, with what the tunnel counted
/// up to now; `None` when nothing is being recorded. Waits on the disk, so
/// call it off the async runtime.
pub fn query(query: &Query) -> Option<io::Result<Report>> {
    Some(current()?.query(query))
}

/// Delete everything the installed ledger holds, and what is pending; with
/// none installed, the database a process that called [`apply`] keeps
/// under the meow home, as a config that turned the ledger off leaves it
/// on disk. Waits on the disk.
pub fn clear() -> io::Result<()> {
    match current() {
        Some(ledger) => ledger.clear(),
        None if MANAGED.load(Ordering::Relaxed) => {
            match clear_at(&crate::resolved_home_dir().join(DIR_NAME)) {
                Err(e) if e.kind() == io::ErrorKind::Unsupported => Ok(()),
                result => result,
            }
        }
        None => Ok(()),
    }
}

/// Answer `query` from the ledger in `dir`, from a process that does not
/// write it: an app's UI while the engine runs in another process, or after
/// it stopped. Opens the database read-only for this one read; what the
/// engine counted since its last flush (at most [`FLUSH_INTERVAL`]) is not
/// in it yet. An empty report when there is no database.
pub fn read(dir: &Path, query: &Query) -> io::Result<Report> {
    store::read(dir, query)
}

/// Delete everything in the ledger in `dir` from a process that does not
/// write it. An engine running in another process notices at its next
/// write (at most [`FLUSH_INTERVAL`] later, or at a query) and drops what
/// it counted until then, as a [`clear`] there would, instead of writing
/// it over the clear.
pub fn clear_at(dir: &Path) -> io::Result<()> {
    store::clear_at(dir)
}

/// Set by [`apply`]: this process keeps a ledger under the meow home.
static MANAGED: AtomicBool = AtomicBool::new(false);

/// Apply a config's `traffic-ledger` at startup: install the ledger under
/// the meow home ([`crate::resolved_home_dir`]) when enabled, uninstall it
/// when not. A failure to open it is logged and leaves recording off.
/// Called by the embedder, never by a library path.
pub fn apply(enable: bool, options: Options) {
    MANAGED.store(true, Ordering::Relaxed);
    if !enable {
        uninstall();
        return;
    }
    let dir = crate::resolved_home_dir().join(DIR_NAME);
    match install(&dir, options) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            tracing::debug!("traffic ledger: {e}; not recording");
        }
        Err(e) => tracing::warn!(
            "traffic ledger: cannot open {}: {e}; not recording",
            dir.display()
        ),
    }
}

/// Apply a reloaded config's `traffic-ledger`. Does nothing in a process
/// that never called [`apply`].
pub fn reconfigure(enable: bool, options: Options) {
    if MANAGED.load(Ordering::Relaxed) {
        apply(enable, options);
    }
}

/// The key of a row: host (reduced to its registrable domain), app,
/// route and interface label.
type RowKey = (String, SmolStr, Route, SmolStr);

/// The rows written at a flush: pending counts by [`RowKey`], on one day.
#[cfg_attr(not(feature = "traffic-ledger"), allow(dead_code))]
struct Batch {
    day: i32,
    rows: HashMap<RowKey, Counts>,
}

#[cfg_attr(not(feature = "traffic-ledger"), allow(dead_code))]
impl Batch {
    /// What is pending, keyed for the rows. With hosts (apps) off, no host
    /// (app) is kept, even one a flow opened before they were turned off
    /// counted. A batch keeps every address `known` (the day's on disk) and
    /// new ones up to [`MAX_IP_HOSTS`] in all, the busiest first; the rest
    /// fold into [`OTHER_IPS`], so batches a failing disk holds for a retry
    /// stay small.
    fn take(day: i32, known: &HashSet<String>) -> Self {
        let (hosts, apps) = (hosts(), apps());
        let mut rows: HashMap<RowKey, Counts> = HashMap::new();
        for ((host, app, route, interface), counts) in take_pending() {
            let host = if hosts {
                host_key(&host)
            } else {
                String::new()
            };
            let app = if apps { app } else { SmolStr::default() };
            rows.entry((host, app, route, interface))
                .or_default()
                .merge(counts);
        }
        let mut new_ips: HashMap<&str, u64> = HashMap::new();
        for ((host, ..), counts) in &rows {
            if !known.contains(host) && host.parse::<std::net::IpAddr>().is_ok() {
                let bytes = new_ips.entry(host.as_str()).or_default();
                *bytes = bytes.saturating_add(counts.upload.saturating_add(counts.download));
            }
        }
        let room = MAX_IP_HOSTS.saturating_sub(known.len());
        if new_ips.len() > room {
            let mut busiest: Vec<_> = new_ips.into_iter().collect();
            busiest.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            let folded: HashSet<String> = busiest[room..]
                .iter()
                .map(|(host, _)| (*host).to_owned())
                .collect();
            let mut capped: HashMap<RowKey, Counts> = HashMap::new();
            for ((host, app, route, interface), counts) in rows {
                let host = if folded.contains(&host) {
                    OTHER_IPS.to_owned()
                } else {
                    host
                };
                capped
                    .entry((host, app, route, interface))
                    .or_default()
                    .merge(counts);
            }
            rows = capped;
        }
        Self { day, rows }
    }
}

/// The host a row keeps: an IP address in its canonical form (no
/// brackets, lowercase, shortest IPv6), a domain as its registrable domain
/// (`www.example.co.uk` → `example.co.uk`), lowercased and without a
/// trailing dot. A name with no registrable domain (`localhost`, a bare
/// public suffix) stays whole.
fn host_key(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host);
    let bare = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return ip.to_string();
    }
    let lower = host.to_ascii_lowercase();
    match registrable_domain(&lower) {
        Some(domain) => domain.to_owned(),
        None => lower,
    }
}

/// The app of a flow whose owner the platform named: the outermost app
/// bundle on `path` (`/Applications/Safari.app/Contents/...` is `Safari`,
/// so a browser's helper processes count as the browser), else the process
/// name, else the last component of `path`.
pub fn app_name(process: &str, path: &str) -> SmolStr {
    let mut parts = path.split(['/', '\\']).peekable();
    while let Some(part) = parts.next() {
        let bundle = part.strip_suffix(".app").filter(|name| !name.is_empty());
        if let Some(bundle) = bundle.filter(|_| parts.peek() == Some(&"Contents")) {
            return bundle.into();
        }
    }
    if process.is_empty() {
        path.rsplit(['/', '\\']).next().unwrap_or_default().into()
    } else {
        process.into()
    }
}

#[cfg(feature = "traffic-ledger")]
fn registrable_domain(host: &str) -> Option<&str> {
    psl::domain_str(host)
}

#[cfg(not(feature = "traffic-ledger"))]
fn registrable_domain(_host: &str) -> Option<&str> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_dates_round_trip() {
        assert_eq!(date_of_day(0), "1970-01-01");
        assert_eq!(day_of_date("1970-01-01"), Some(0));
        let day = day_of_date("2026-11-02").unwrap();
        assert_eq!(date_of_day(day), "2026-11-02");
        assert_eq!(day_of_date("2026-02-30"), None);
        assert_eq!(day_of_date("2026-11"), None);
        assert_eq!(day_of_date("x"), None);
    }

    #[test]
    fn a_day_is_local() {
        // 2026-11-02T16:30:00Z: still the 2nd in UTC, the 3rd at UTC+8.
        let unix = 1_793_637_000;
        let utc = TimeZone::default();
        let east = TimeZone {
            offset: 8 * 3600,
            next: None,
        };
        assert_eq!(date_of_day(utc.day(unix)), "2026-11-02");
        assert_eq!(date_of_day(east.day(unix)), "2026-11-03");
        let west = TimeZone {
            offset: -8 * 3600,
            next: None,
        };
        assert_eq!(date_of_day(west.day(unix)), "2026-11-02");
        assert_eq!(utc.next_midnight(unix), 1_793_664_000);
        assert_eq!(east.next_midnight(unix), 1_793_664_000 + 86_400 - 8 * 3600);
    }

    #[test]
    fn a_change_of_offset_moves_the_day() {
        // UTC-7 until 2026-11-01T09:00Z, UTC-8 after (US Pacific).
        let change = 1_793_523_600;
        let pacific = TimeZone {
            offset: -7 * 3600,
            next: Some((change, -8 * 3600)),
        };
        // 2026-11-02T07:30Z: 23:30 on the 1st at UTC-8, 00:30 on the 2nd at UTC-7.
        let unix = 1_793_604_600;
        assert_eq!(date_of_day(pacific.day(unix)), "2026-11-01");
        assert_eq!(pacific.next_midnight(unix), 1_793_606_400);
    }

    /// Every second up to the midnight reported falls on the same day, and
    /// that midnight starts the next one.
    fn assert_midnight(zone: TimeZone, unix: i64) {
        let midnight = zone.next_midnight(unix);
        assert!(
            midnight > unix,
            "{zone:?} at {unix}: {midnight} is not ahead"
        );
        assert_eq!(zone.day(midnight - 1), zone.day(unix), "{zone:?} at {unix}");
        assert!(zone.day(midnight) > zone.day(unix), "{zone:?} at {unix}");
    }

    #[test]
    fn midnight_is_ahead_across_a_change_of_offset() {
        // 00:00 → 01:00 at midnight (Havana, Santiago, Beirut, Cairo): the
        // change starts the day; midnight on the new offset is already past.
        let forward = TimeZone {
            offset: 0,
            next: Some((86_400, 3600)),
        };
        assert_eq!(forward.next_midnight(84_600), 86_400);
        // 00:00 → 23:00 the evening before: the day runs 25 hours.
        let back = TimeZone {
            offset: 3600,
            next: Some((86_400 - 3600, 0)),
        };
        assert_eq!(back.next_midnight(84_600 - 3600), 86_400);
        for zone in [
            forward,
            back,
            TimeZone {
                offset: -7 * 3600,
                next: Some((1_793_523_600, -8 * 3600)),
            },
            TimeZone {
                offset: 8 * 3600,
                next: None,
            },
        ] {
            for unix in (0..4 * 86_400).step_by(900) {
                assert_midnight(zone, unix);
            }
            for unix in (1_793_400_000..1_793_800_000).step_by(900) {
                assert_midnight(zone, unix);
            }
        }
    }

    #[test]
    fn hosts_reduce_to_registrable_domains() {
        assert_eq!(host_key("192.0.2.1"), "192.0.2.1");
        assert_eq!(host_key("2001:db8::1"), "2001:db8::1");
        assert_eq!(host_key("2001:0DB8:0::1"), "2001:db8::1");
        assert_eq!(host_key("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(host_key("localhost"), "localhost");
        assert_eq!(host_key(""), "");
        #[cfg(feature = "traffic-ledger")]
        {
            assert_eq!(host_key("WWW.Example.co.uk."), "example.co.uk");
            assert_eq!(host_key("a.b.example.com"), "example.com");
        }
    }

    #[test]
    fn apps_are_bundles_or_processes() {
        let helper = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome \
                      Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/\
                      Google Chrome Helper";
        assert_eq!(app_name("Google Chrome Helper", helper), "Google Chrome");
        assert_eq!(app_name("curl", "/usr/bin/curl"), "curl");
        assert_eq!(app_name("org.example.browser", ""), "org.example.browser");
        assert_eq!(
            app_name("", r"C:\Program Files\Example\example.exe"),
            "example.exe"
        );
        assert_eq!(app_name("", "/opt/.app/tool"), "tool");
        // Only a bundle's layout names the app, never a directory that
        // happens to end in `.app`, nor more than one path component.
        assert_eq!(
            app_name(
                "esbuild",
                "/home/alice/my-site.app/node_modules/.bin/esbuild"
            ),
            "esbuild"
        );
        assert_eq!(
            app_name("tool", r"C:\Users\Alice\Tools\tool.app\bin\tool.exe"),
            "tool"
        );
        assert_eq!(
            app_name("", r"D:\Apps\Example.app\Contents\MacOS\Example"),
            "Example"
        );
        assert_eq!(app_name("", ""), "");
    }

    #[test]
    fn group_by_parses() {
        assert_eq!("policy".parse::<GroupBy>(), Ok(GroupBy::Policy));
        assert_eq!("app".parse::<GroupBy>(), Ok(GroupBy::App));
        assert!("nodes".parse::<GroupBy>().is_err());
        assert_eq!(GroupBy::Interface.as_str(), "interface");
    }
}
