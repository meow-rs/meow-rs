//! Traffic ledger: how much each host, policy and network interface carried,
//! day by day, kept across restarts.
//!
//! [`crate::traffic`] counts what each proxy carried since the engine
//! started and forgets it at a stop. The ledger keeps, for every local day,
//! the bytes sent and received and the connections (and UDP flows) opened
//! per registrable domain, leaf proxy and interface label, for
//! [`RETENTION_DAYS`] — enough for a client to show today, this month and
//! last month, grouped any of the three ways. A meow extension; mihomo has
//! no equivalent.
//!
//! Unlike the logbook (ADR-0014), the ledger records destinations: with
//! hosts on, it is a coarse browsing history (registrable domains, no
//! paths, no times finer than a day). It never leaves the device; a config
//! turns it off (`traffic-ledger.enable: false`) or keeps the policies and
//! interfaces without hosts (`hosts: false`), and [`clear`] empties it.
//!
//! # Storage
//!
//! `<home>/traffic/traffic.db` is an SQLite database (bundled SQLite, WAL
//! mode) with one row per day, host, policy and interface; readers in other
//! processes ([`read`]) rely on its schema. A database that cannot be read
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
//! stop — and what a connection carried last as it closes. The writer
//! thread commits it all in one transaction under the current day and
//! interface label.

#[cfg_attr(not(feature = "traffic-ledger"), path = "disabled.rs")]
mod store;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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
pub const MAX_IP_HOSTS: usize = 1024;

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
    /// The leaf proxy that carried the traffic, as `/statistics` counts
    /// it: a group's member, never the group; `DIRECT` and `REJECT` too.
    Policy,
    /// The label the platform set with [`set_interface`] when the traffic
    /// reached the ledger: `Wi-Fi`, `Cellular`; empty when none was set.
    Interface,
}

impl GroupBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
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
            "policy" => Ok(Self::Policy),
            "interface" => Ok(Self::Interface),
            _ => Err(format!(
                "unknown grouping {s:?}: expected host, policy or interface"
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
}

/// A [`Query`] answered: its rows by total bytes, largest first, and their
/// sums.
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
}

impl Default for Options {
    fn default() -> Self {
        Self { hosts: true }
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

    /// The Unix second the local day after `unix`'s begins. A change of
    /// offset inside the day moves it by at most the change.
    #[cfg_attr(not(feature = "traffic-ledger"), allow(dead_code))]
    fn next_midnight(&self, unix: i64) -> i64 {
        let start = (i64::from(self.day(unix)) + 1) * 86_400;
        start - i64::from(self.offset_at(start - i64::from(self.offset_at(unix))))
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

/// Bytes and requests not yet written, by host and policy.
type Pending = HashMap<(SmolStr, Arc<str>), Counts>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    upload: u64,
    download: u64,
    requests: u64,
}

static CURRENT: RwLock<Option<Arc<Ledger>>> = RwLock::new(None);
/// Whether a ledger is installed, for producers that check per connection.
static ENABLED: AtomicBool = AtomicBool::new(false);
/// [`Options::hosts`] of the installed ledger.
static HOSTS: AtomicBool = AtomicBool::new(true);
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

/// Count traffic toward `host` (a domain or an IP address as text, empty
/// for none) through the leaf proxy `policy`. Called once per connection
/// with its `requests`, then with its bytes as the tunnel settles. Does
/// nothing while no ledger is installed.
pub fn add(host: &SmolStr, policy: &Arc<str>, upload: u64, download: u64, requests: u64) {
    if !enabled() || (upload == 0 && download == 0 && requests == 0) {
        return;
    }
    let mut pending = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
    let counts = pending
        .get_or_insert_with(HashMap::new)
        .entry((host.clone(), Arc::clone(policy)))
        .or_default();
    counts.upload = counts.upload.saturating_add(upload);
    counts.download = counts.download.saturating_add(download);
    counts.requests = counts.requests.saturating_add(requests);
}

/// Take what is pending, after asking every live [`Source`] to settle.
fn take_pending() -> Pending {
    let sources: Vec<Arc<dyn Source>> = {
        let mut sources = SOURCES.lock().unwrap_or_else(PoisonError::into_inner);
        sources.retain(|source| source.strong_count() > 0);
        sources.iter().filter_map(Weak::upgrade).collect()
    };
    for source in sources {
        source.settle();
    }
    PENDING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap_or_default()
}

/// Register `source`; it is asked to settle until it is dropped.
pub fn register(source: Weak<dyn Source>) {
    SOURCES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(source);
}

/// Set the label the platform gives the network the engine's traffic goes
/// out on (`Wi-Fi`, `Cellular`, `en0`). What was counted under the previous
/// label is written under it first. Kept across installs.
pub fn set_interface(label: &str) {
    if *INTERFACE.lock().unwrap_or_else(PoisonError::into_inner) == label {
        return;
    }
    if let Some(ledger) = current() {
        ledger.flush();
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
/// under; UTC until set. An embedder sets it at start and whenever the zone
/// changes.
pub fn set_time_zone(zone: TimeZone) {
    *ZONE.lock().unwrap_or_else(PoisonError::into_inner) = zone;
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
    if current().is_some_and(|ledger| ledger.dir() == dir) {
        HOSTS.store(options.hosts, Ordering::Relaxed);
        return Ok(());
    }
    let ledger = Arc::new(Ledger::open(dir)?);
    let previous = CURRENT
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(ledger);
    HOSTS.store(options.hosts, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Relaxed);
    if let Some(previous) = previous {
        previous.flush();
    }
    Ok(())
}

/// Stop recording, after writing out what is pending.
pub fn uninstall() {
    let previous = CURRENT
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(ledger) = previous {
        ledger.flush();
        ENABLED.store(false, Ordering::Relaxed);
        PENDING
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
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

/// Delete everything the installed ledger holds, and what is pending.
/// Waits on the disk.
pub fn clear() {
    if let Some(ledger) = current() {
        ledger.clear();
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
/// write it. An engine running in another process keeps what it counted
/// since its last flush, and writes it later.
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

/// The rows written at a flush: pending counts keyed by host (reduced to
/// its registrable domain), policy and interface, on one day.
#[cfg_attr(not(feature = "traffic-ledger"), allow(dead_code))]
struct Batch {
    day: i32,
    interface: SmolStr,
    rows: HashMap<(String, Arc<str>), Counts>,
}

#[cfg_attr(not(feature = "traffic-ledger"), allow(dead_code))]
impl Batch {
    fn take(day: i32) -> Self {
        let mut rows: HashMap<(String, Arc<str>), Counts> = HashMap::new();
        for ((host, policy), counts) in take_pending() {
            let row = rows.entry((host_key(&host), policy)).or_default();
            row.upload = row.upload.saturating_add(counts.upload);
            row.download = row.download.saturating_add(counts.download);
            row.requests = row.requests.saturating_add(counts.requests);
        }
        Self {
            day,
            interface: interface(),
            rows,
        }
    }
}

/// The host a row keeps: an IP address as it is, a domain as its
/// registrable domain (`www.example.co.uk` → `example.co.uk`), lowercased
/// and without a trailing dot. A name with no registrable domain
/// (`localhost`, a bare public suffix) stays whole.
fn host_key(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_owned();
    }
    let lower = host.to_ascii_lowercase();
    match registrable_domain(&lower) {
        Some(domain) => domain.to_owned(),
        None => lower,
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

    #[test]
    fn hosts_reduce_to_registrable_domains() {
        assert_eq!(host_key("192.0.2.1"), "192.0.2.1");
        assert_eq!(host_key("2001:db8::1"), "2001:db8::1");
        assert_eq!(host_key("localhost"), "localhost");
        assert_eq!(host_key(""), "");
        #[cfg(feature = "traffic-ledger")]
        {
            assert_eq!(host_key("WWW.Example.co.uk."), "example.co.uk");
            assert_eq!(host_key("a.b.example.com"), "example.com");
        }
    }

    #[test]
    fn group_by_parses() {
        assert_eq!("policy".parse::<GroupBy>(), Ok(GroupBy::Policy));
        assert!("nodes".parse::<GroupBy>().is_err());
        assert_eq!(GroupBy::Interface.as_str(), "interface");
    }
}
