//! The store behind the traffic ledger: a writer thread that commits what
//! the tunnel counted to an SQLite database.

use super::{
    date_of_day, unix_now, zone, Batch, GroupBy, Query, Report, Row, TimeZone, MAX_IP_HOSTS,
    OTHER_IPS, RETENTION_DAYS,
};
use rusqlite::{params, Connection, ErrorCode, OpenFlags};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::warn;

const DB_FILE: &str = "traffic.db";
/// An unreadable database is moved here and the ledger starts over.
const CORRUPT_FILE: &str = "traffic.db.corrupt";
const LOCK_FILE: &str = "traffic.lock";

/// `PRAGMA user_version` of [`SCHEMA`]. A database from a newer meow is
/// left alone, neither read nor rewritten. Schema 1, without `app`, was
/// only written by test builds before the ledger shipped; one is set aside.
/// Schema 2, without `via`, is moved to this one as the ledger opens it,
/// and read as it is until then.
const SCHEMA_VERSION: i64 = 3;

/// A contract with readers in other processes. `day` counts local days
/// since 1970-01-01; `host` is a registrable domain, an IP address,
/// [`OTHER_IPS`] or empty; `app` is a package name, an app bundle or a
/// process name, or empty; `policy` is the leaf proxy and `via` the
/// member that carried its `dialer-proxy` hop, or empty
/// ([`super::Route`]); `interface` is empty when the platform set no
/// label.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS traffic (
    day       INTEGER NOT NULL,
    host      TEXT NOT NULL,
    app       TEXT NOT NULL,
    policy    TEXT NOT NULL,
    via       TEXT NOT NULL,
    interface TEXT NOT NULL,
    upload    INTEGER NOT NULL,
    download  INTEGER NOT NULL,
    requests  INTEGER NOT NULL,
    PRIMARY KEY (day, host, app, policy, via, interface)
) WITHOUT ROWID;
";

/// Schema 2's rows, each with no `via`, after it was renamed out of the way.
const FROM_SCHEMA_2: &str = "
INSERT INTO traffic (day, host, app, policy, via, interface, upload, download, requests)
SELECT day, host, app, policy, '', interface, upload, download, requests FROM traffic_2;
DROP TABLE traffic_2;
";

/// The table of a database in [`SCHEMA_VERSION`] 2, as a reader sees it
/// until the ledger opens it.
const SCHEMA_2_TABLE: &str = "(SELECT *, '' AS via FROM traffic)";

/// As the logbook's: commits survive a killed process, a power cut loses at
/// most the last ones, and the log and cache stay small for an iOS network
/// extension.
const TUNING: &str = "
PRAGMA synchronous = NORMAL;
PRAGMA wal_autocheckpoint = 64;
PRAGMA journal_size_limit = 262144;
PRAGMA cache_size = -256;
";

const UPSERT: &str = "
INSERT INTO traffic (day, host, app, policy, via, interface, upload, download, requests)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
ON CONFLICT (day, host, app, policy, via, interface) DO UPDATE SET
    upload = upload + excluded.upload,
    download = download + excluded.download,
    requests = requests + excluded.requests
";

/// How long a flush, a query or a clear waits for the writer, queueing
/// included.
const WAIT: Duration = Duration::from_secs(5);

/// How late past midnight a flush still files what is pending under the
/// day that ended: the writer wakes at midnight, give or take its timers.
/// Later, the clock jumped (a resume from sleep, a clock set at boot) and
/// the pending traffic goes under today.
const LATE_FLUSH: i64 = 2 * super::FLUSH_INTERVAL.as_secs() as i64;

/// How long a connection waits for a lock held by another.
const BUSY_TIMEOUT: Duration = Duration::from_secs(1);

/// Batches a failing disk keeps for a retry; past it, the oldest go.
const BACKLOG: usize = 64;

/// The ledger in one directory, reached through [`super::current`].
pub struct Ledger {
    dir: PathBuf,
    tx: Option<SyncSender<Op>>,
    writer: Option<JoinHandle<()>>,
    /// Held while open: keeps a second meow process off the directory.
    _lock: File,
}

enum Op {
    Flush(SyncSender<()>),
    Query(Box<Query>, SyncSender<io::Result<Report>>),
    Clear(SyncSender<io::Result<()>>),
}

impl Ledger {
    /// Open the ledger in `dir`, creating it if needed. Fails when another
    /// process holds it, or when a newer meow wrote its database.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(LOCK_FILE))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "in use by another meow process",
                ));
            }
            Err(TryLockError::Error(e)) => return Err(e),
        }
        let path = dir.join(DB_FILE);
        let conn = match connect(&path) {
            Ok(conn) => conn,
            Err(Unusable::Damaged(error)) => {
                warn!(
                    "traffic ledger: cannot read {} ({error}); starting over and keeping it as {CORRUPT_FILE}",
                    path.display()
                );
                set_aside(dir)?;
                connect(&path).map_err(Unusable::into_io)?
            }
            Err(Unusable::Failed(e)) => return Err(e),
        };
        let data_version = data_version(&conn).map_err(io::Error::other)?;
        let writer = Writer {
            conn,
            data_version,
            pruned: i32::MIN,
            ip_hosts: None,
            backlog: Vec::new(),
            failing: false,
        };
        // Expired days go at the first flush, by when the embedder has set
        // the time zone.
        let (tx, rx) = mpsc::sync_channel(16);
        let thread = std::thread::Builder::new()
            .name("meow-traffic".into())
            .spawn(move || writer.run(&rx))?;
        Ok(Self {
            dir: dir.to_owned(),
            tx: Some(tx),
            writer: Some(thread),
            _lock: lock,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write out what is pending, waiting at most [`WAIT`].
    pub fn flush(&self) {
        let deadline = Instant::now() + WAIT;
        let (ack, done) = mpsc::sync_channel(1);
        if self.send_by(Op::Flush(ack), deadline).is_ok() {
            let _ = done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        }
    }

    /// Ask the writer for a flush without waiting for it, unless one is
    /// queued already.
    pub fn nudge(&self) {
        let (ack, _done) = mpsc::sync_channel(1);
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(Op::Flush(ack));
        }
    }

    pub fn query(&self, query: &Query) -> io::Result<Report> {
        let deadline = Instant::now() + WAIT;
        let (reply, answer) = mpsc::sync_channel(1);
        self.send_by(Op::Query(Box::new(query.clone()), reply), deadline)?;
        answer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| Err(busy()))
    }

    pub fn clear(&self) -> io::Result<()> {
        let deadline = Instant::now() + WAIT;
        let (ack, done) = mpsc::sync_channel(1);
        self.send_by(Op::Clear(ack), deadline)?;
        done.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| Err(busy()))
    }

    /// Queue `op` for the writer, waiting for room until `deadline`: a
    /// writer stuck on the disk never blocks the caller for longer.
    fn send_by(&self, mut op: Op, deadline: Instant) -> io::Result<()> {
        let Some(tx) = &self.tx else {
            return Err(stopped());
        };
        loop {
            match tx.try_send(op) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(back)) if Instant::now() < deadline => {
                    op = back;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(TrySendError::Full(_)) => return Err(busy()),
                Err(TrySendError::Disconnected(_)) => return Err(stopped()),
            }
        }
    }
}

fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the traffic ledger is busy")
}

fn stopped() -> io::Error {
    io::Error::other("the traffic ledger writer stopped")
}

impl Drop for Ledger {
    fn drop(&mut self) {
        // Hanging up ends the writer after a last flush.
        self.tx.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

struct Writer {
    conn: Connection,
    /// The database's `data_version` as this writer last saw it. It moves
    /// as another connection commits, and the one that can is a
    /// [`clear_at`] from another process: the process lock keeps out any
    /// other writer.
    data_version: i64,
    /// The day expired rows were last deleted on.
    pruned: i32,
    /// The IP-address hosts of one day, toward [`MAX_IP_HOSTS`].
    ip_hosts: Option<(i32, HashSet<String>)>,
    /// Batches whose commit failed, oldest first.
    backlog: Vec<Batch>,
    /// Whether the last commit failed; logged once until one succeeds.
    failing: bool,
}

impl Writer {
    fn run(mut self, rx: &Receiver<Op>) {
        let mut due = Instant::now() + super::FLUSH_INTERVAL;
        let mut day_end = zone().next_midnight(unix_now());
        loop {
            let to_midnight = Duration::from_secs(u64::try_from(day_end - unix_now()).unwrap_or(0));
            let wait = due
                .saturating_duration_since(Instant::now())
                .min(to_midnight);
            match rx.recv_timeout(wait) {
                Ok(Op::Flush(ack)) => {
                    let _ = self.flush(&mut day_end);
                    let _ = ack.send(());
                }
                Ok(Op::Query(query, reply)) => {
                    // A report without what could not be written is not
                    // current; the caller hears why instead.
                    let result = self
                        .flush(&mut day_end)
                        .and_then(|()| report(&self.conn, &query, "traffic"))
                        .map_err(io::Error::other);
                    let _ = reply.send(result);
                }
                Ok(Op::Clear(ack)) => {
                    super::discard_pending();
                    self.backlog.clear();
                    self.ip_hosts = None;
                    let result = clear(&self.conn).map_err(|e| {
                        warn!("traffic ledger: cannot clear: {e}");
                        io::Error::other(e)
                    });
                    let _ = ack.send(result);
                }
                Err(RecvTimeoutError::Timeout) => {
                    let _ = self.flush(&mut day_end);
                    due = Instant::now() + super::FLUSH_INTERVAL;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    if let Err(e) = self.flush(&mut day_end) {
                        warn!(
                            "traffic ledger: stopped with {} flushes not written: {e}",
                            self.backlog.len()
                        );
                    }
                    return;
                }
            }
        }
    }

    /// Take what is pending and commit it, with what failed before, under
    /// the day [`flush_day`] picks; the commit's error when it failed, and
    /// what it held is kept for the next flush.
    fn flush(&mut self, day_end: &mut i64) -> rusqlite::Result<()> {
        if self.cleared_elsewhere() {
            // What this process counted before an app's UI emptied the
            // database is not written over it, nor are the day's
            // addresses it held toward the cap.
            super::discard_pending();
            self.backlog.clear();
            self.ip_hosts = None;
        }
        let now = unix_now();
        let zone = zone();
        let day = flush_day(zone, now, *day_end);
        *day_end = zone.next_midnight(now);
        let none = HashSet::new();
        let known = ip_hosts_of(&self.conn, &mut self.ip_hosts, day).map_or(&none, |known| &*known);
        let batch = Batch::take(day, known);
        if !batch.rows.is_empty() {
            if self.backlog.len() == BACKLOG {
                self.backlog.remove(0);
            }
            self.backlog.push(batch);
        }
        let mut result = Ok(());
        if !self.backlog.is_empty() {
            match self.commit() {
                Ok(()) => {
                    self.backlog.clear();
                    self.failing = false;
                }
                Err(e) => {
                    if !self.failing {
                        warn!("traffic ledger: cannot write; retrying: {e}");
                    }
                    self.failing = true;
                    // The IP hosts counted toward the cap may not be on disk.
                    self.ip_hosts = None;
                    result = Err(e);
                }
            }
        }
        self.prune(zone.day(now));
        result
    }

    /// Write the backlog in one transaction. Hosts (apps) turned off since a
    /// batch was taken are not written either; the rows they merge into add
    /// up.
    fn commit(&mut self) -> rusqlite::Result<()> {
        let (hosts, apps) = (super::hosts(), super::apps());
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut upsert = tx.prepare(UPSERT)?;
            for batch in &self.backlog {
                for ((host, app, route, interface), counts) in &batch.rows {
                    let host = if hosts { host.as_str() } else { "" };
                    let host = cap_ip_host(&tx, &mut self.ip_hosts, batch.day, host)?;
                    upsert.execute(params![
                        batch.day,
                        host,
                        if apps { app.as_str() } else { "" },
                        &*route.policy,
                        route.via.as_deref().unwrap_or_default(),
                        interface.as_str(),
                        int(counts.upload),
                        int(counts.download),
                        int(counts.requests),
                    ])?;
                }
            }
        }
        tx.commit()
    }

    /// Whether another process emptied the database since the last flush.
    fn cleared_elsewhere(&mut self) -> bool {
        match data_version(&self.conn) {
            Ok(version) if version != self.data_version => {
                self.data_version = version;
                true
            }
            Ok(_) => false,
            Err(e) => {
                warn!("traffic ledger: cannot tell whether it was cleared: {e}");
                false
            }
        }
    }

    /// Delete the days past [`RETENTION_DAYS`], once a day.
    fn prune(&mut self, today: i32) {
        if self.pruned == today {
            return;
        }
        match prune(&self.conn, today) {
            Ok(()) => self.pruned = today,
            Err(e) => warn!("traffic ledger: cannot delete expired days: {e}"),
        }
    }
}

/// The day a flush at `now` files what is pending under: today, or the
/// day that ended at `day_end` for a flush that comes up to [`LATE_FLUSH`]
/// late for it, as what is pending was counted before it ended.
fn flush_day(zone: TimeZone, now: i64, day_end: i64) -> i32 {
    if (0..=LATE_FLUSH).contains(&(now - day_end)) {
        zone.day(day_end - 1)
    } else {
        zone.day(now)
    }
}

/// The IP-address hosts `day` has on disk, read once per day into
/// `ip_hosts`.
fn ip_hosts_of<'a>(
    conn: &Connection,
    ip_hosts: &'a mut Option<(i32, HashSet<String>)>,
    day: i32,
) -> rusqlite::Result<&'a mut HashSet<String>> {
    if ip_hosts.as_ref().is_none_or(|(loaded, _)| *loaded != day) {
        let mut statement = conn.prepare("SELECT DISTINCT host FROM traffic WHERE day = ?1")?;
        let hosts = statement
            .query_map([day], |row| row.get::<_, String>(0))?
            .filter_map(Result::ok)
            .filter(|host| host.parse::<std::net::IpAddr>().is_ok())
            .collect();
        *ip_hosts = Some((day, hosts));
    }
    Ok(&mut ip_hosts.get_or_insert_with(|| (day, HashSet::new())).1)
}

/// `host`, or [`OTHER_IPS`] for an IP address past `day`'s
/// [`MAX_IP_HOSTS`].
fn cap_ip_host<'a>(
    conn: &Connection,
    ip_hosts: &mut Option<(i32, HashSet<String>)>,
    day: i32,
    host: &'a str,
) -> rusqlite::Result<&'a str> {
    if host.parse::<std::net::IpAddr>().is_err() {
        return Ok(host);
    }
    let hosts = ip_hosts_of(conn, ip_hosts, day)?;
    if hosts.contains(host) {
        return Ok(host);
    }
    if hosts.len() < MAX_IP_HOSTS {
        hosts.insert(host.to_owned());
        return Ok(host);
    }
    Ok(OTHER_IPS)
}

fn prune(conn: &Connection, today: i32) -> rusqlite::Result<()> {
    let oldest = today.saturating_sub(RETENTION_DAYS - 1);
    if conn.execute("DELETE FROM traffic WHERE day < ?1", [oldest])? > 0 {
        vacuum(conn)?;
    }
    Ok(())
}

fn clear(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM traffic", [])?;
    vacuum(conn)?;
    // The deleted hosts leave the database file and the write-ahead log
    // once a checkpoint copies the log back whole and truncates it. A
    // reader in another process can hold it off past the busy timeout:
    // SQLite then reports it busy rather than failing, and so does this.
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    if busy == 0 {
        Ok(())
    } else {
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("a reader holds the deleted traffic on disk; clear again".into()),
        ))
    }
}

/// Hand the free pages back to the file system.
fn vacuum(conn: &Connection) -> rusqlite::Result<()> {
    let mut statement = conn.prepare("PRAGMA incremental_vacuum")?;
    let mut rows = statement.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

/// `query` answered from `conn`, whose rows are in `table`.
fn report(conn: &Connection, query: &Query, table: &str) -> rusqlite::Result<Report> {
    // A policy filter keeps the flows a Policy row of that proxy counts:
    // the ones it left through and the ones whose hop it carried.
    let filter = "day BETWEEN ?1 AND ?2 \
         AND (?3 IS NULL OR host = ?3) \
         AND (?4 IS NULL OR app = ?4) \
         AND (?5 IS NULL OR policy = ?5 OR (via = ?5 AND via != '')) \
         AND (?6 IS NULL OR interface = ?6)";
    let column = match query.by {
        GroupBy::Host => "host",
        GroupBy::App => "app",
        GroupBy::Policy => "policy",
        GroupBy::Interface => "interface",
    };
    // Each flow once under its group, and by Policy once more under the
    // member that carried its hop, as that member's `via_*`.
    let mut flows = format!(
        "SELECT {column} AS name, upload, download, requests, \
         0 AS hop_up, 0 AS hop_down, 0 AS hop_requests FROM {table} WHERE {filter}"
    );
    if query.by == GroupBy::Policy {
        flows = format!(
            "{flows} UNION ALL \
             SELECT via, upload, download, requests, upload, download, requests \
             FROM {table} WHERE via != '' AND {filter}"
        );
    }
    let sql = format!(
        "SELECT name, SUM(upload), SUM(download), SUM(requests), \
         SUM(hop_up), SUM(hop_down), SUM(hop_requests) FROM ({flows}) \
         GROUP BY name \
         ORDER BY SUM(upload) + SUM(download) DESC, SUM(requests) DESC, name"
    );
    let mut statement = conn.prepare(&sql)?;
    let rows = statement
        .query_map(
            params![
                query.from,
                query.to,
                query.host,
                query.app,
                query.policy,
                query.interface
            ],
            |row| {
                Ok(Row {
                    name: row.get(0)?,
                    upload: uint(row.get(1)?),
                    download: uint(row.get(2)?),
                    requests: uint(row.get(3)?),
                    via_upload: uint(row.get(4)?),
                    via_download: uint(row.get(5)?),
                    via_requests: uint(row.get(6)?),
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut report = empty_report(query);
    for row in &rows {
        // A hop's flow is counted once already, under its leaf proxy.
        let flows = (
            row.upload.saturating_sub(row.via_upload),
            row.download.saturating_sub(row.via_download),
            row.requests.saturating_sub(row.via_requests),
        );
        report.upload = report.upload.saturating_add(flows.0);
        report.download = report.download.saturating_add(flows.1);
        report.requests = report.requests.saturating_add(flows.2);
    }
    report.rows = rows;
    Ok(report)
}

fn empty_report(query: &Query) -> Report {
    Report {
        from: date_of_day(query.from),
        to: date_of_day(query.to),
        by: query.by,
        ..Report::default()
    }
}

/// Read the ledger in `dir` from another process (see [`super::read`]).
pub fn read(dir: &Path, query: &Query) -> io::Result<Report> {
    let path = dir.join(DB_FILE);
    if !path.exists() {
        return Ok(empty_report(query));
    }
    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(io::Error::other)?;
    conn.busy_timeout(BUSY_TIMEOUT).map_err(io::Error::other)?;
    let table = match schema_version(&conn).map_err(Unusable::into_io)? {
        // Created, and the schema not committed yet.
        0 => return Ok(empty_report(query)),
        2 => SCHEMA_2_TABLE,
        _ => "traffic",
    };
    report(&conn, query, table).map_err(io::Error::other)
}

/// Empty the ledger in `dir` from another process (see [`super::clear_at`]).
pub fn clear_at(dir: &Path) -> io::Result<()> {
    let path = dir.join(DB_FILE);
    if !path.exists() {
        return Ok(());
    }
    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(io::Error::other)?;
    conn.busy_timeout(BUSY_TIMEOUT).map_err(io::Error::other)?;
    if schema_version(&conn).map_err(Unusable::into_io)? == 0 {
        return Ok(());
    }
    clear(&conn).map_err(io::Error::other)
}

/// Why the database could not be opened.
enum Unusable {
    /// Not a database, or a damaged one: set it aside and start over.
    Damaged(String),
    Failed(io::Error),
}

impl From<rusqlite::Error> for Unusable {
    fn from(e: rusqlite::Error) -> Self {
        if matches!(
            e.sqlite_error_code(),
            Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase)
        ) {
            Self::Damaged(e.to_string())
        } else {
            Self::Failed(io::Error::other(e))
        }
    }
}

impl Unusable {
    fn into_io(self) -> io::Error {
        match self {
            Self::Damaged(error) => io::Error::new(io::ErrorKind::InvalidData, error),
            Self::Failed(e) => e,
        }
    }
}

/// Open the database for writing, creating its schema.
fn connect(path: &Path) -> Result<Connection, Unusable> {
    if path.exists() {
        // Refuse a newer meow's database before opening it for writing:
        // closing a writer checkpoints its log into the file.
        let probe = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        probe.busy_timeout(BUSY_TIMEOUT)?;
        schema_version(&probe)?;
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let version = schema_version(&conn)?;
    let check: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if check != "ok" {
        return Err(Unusable::Damaged(check));
    }
    if version == 0 {
        // Possible only before the first table: lets a delete hand its
        // pages back to the file system.
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL")?;
    }
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    conn.execute_batch(TUNING)?;
    if version == 0 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    } else if version == 2 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch("ALTER TABLE traffic RENAME TO traffic_2")?;
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch(FROM_SCHEMA_2)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        vacuum(&conn)?;
    }
    Ok(conn)
}

/// The database's `user_version`; one from a newer meow is an error, and
/// one no meow writes marks a database that is not the ledger's.
/// A value SQLite moves as other connections commit to the database.
fn data_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA data_version", [], |row| row.get(0))
}

fn schema_version(conn: &Connection) -> Result<i64, Unusable> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 0 {
        return Err(Unusable::Damaged(format!("unknown schema {version}")));
    }
    if version == 1 {
        return Err(Unusable::Damaged(format!(
            "schema {version} of a test build"
        )));
    }
    if version > SCHEMA_VERSION {
        return Err(Unusable::Failed(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("written by a newer meow (schema {version})"),
        )));
    }
    Ok(version)
}

/// Move an unreadable database out of the way.
fn set_aside(dir: &Path) -> io::Result<()> {
    fs::rename(dir.join(DB_FILE), dir.join(CORRUPT_FILE))?;
    for suffix in ["-wal", "-shm"] {
        match fs::remove_file(dir.join(format!("{DB_FILE}{suffix}"))) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => warn!("traffic ledger: cannot remove the old {suffix}: {e}"),
        }
    }
    Ok(())
}

/// An SQLite integer.
fn int(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn uint(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic_ledger::{self as ledger, add, Options, Query, Route, OTHER_IPS};
    use smol_str::SmolStr;
    use std::sync::{Arc, Mutex as StdMutex};

    /// The ledger is process-wide.
    static SERIAL: StdMutex<()> = StdMutex::new(());

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "meow-traffic-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn rows_of_day(conn: &Connection, day: i32) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM traffic WHERE day = ?1",
            [day],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn query(by: GroupBy) -> Query {
        let today = ledger::today();
        Query {
            from: today - 1,
            to: today,
            by,
            ..Query::default()
        }
    }

    #[test]
    fn traffic_is_kept_by_host_app_policy_and_interface() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("groups");
        ledger::install(&dir, Options::default()).unwrap();
        let proxy = Route::from("Node A");
        let direct = Route::from("DIRECT");
        let browser = SmolStr::new("org.example.browser");
        let none = SmolStr::default();
        ledger::set_interface("Wi-Fi");
        add(
            &SmolStr::new("www.example.com"),
            &browser,
            &proxy,
            100,
            1000,
            1,
        );
        add(&SmolStr::new("api.example.com"), &none, &proxy, 10, 100, 1);
        add(&SmolStr::new("192.0.2.1"), &none, &direct, 5, 5, 1);
        ledger::set_interface("Cellular");
        add(&SmolStr::new("example.org"), &browser, &direct, 1, 2, 1);

        let hosts = ledger::query(&query(GroupBy::Host)).unwrap().unwrap();
        let names: Vec<_> = hosts.rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["example.com", "192.0.2.1", "example.org"]);
        assert_eq!(hosts.rows[0].upload, 110);
        assert_eq!(hosts.rows[0].download, 1100);
        assert_eq!(hosts.rows[0].requests, 2);
        assert_eq!(hosts.requests, 4);
        assert_eq!(hosts.upload + hosts.download, 1223);

        let interfaces = ledger::query(&query(GroupBy::Interface)).unwrap().unwrap();
        let names: Vec<_> = interfaces
            .rows
            .iter()
            .map(|row| row.name.as_str())
            .collect();
        assert_eq!(names, ["Wi-Fi", "Cellular"]);

        let apps = ledger::query(&query(GroupBy::App)).unwrap().unwrap();
        let apps: Vec<_> = apps
            .rows
            .iter()
            .map(|row| (row.name.as_str(), row.upload + row.download))
            .collect();
        assert_eq!(apps, [("org.example.browser", 1103), ("", 120)]);

        // Drilling into an app.
        let mut drill = query(GroupBy::Host);
        drill.app = Some("org.example.browser".into());
        let browser_hosts = ledger::query(&drill).unwrap().unwrap();
        let names: Vec<_> = browser_hosts
            .rows
            .iter()
            .map(|row| row.name.as_str())
            .collect();
        assert_eq!(names, ["example.com", "example.org"]);

        // Drilling into a policy.
        let mut drill = query(GroupBy::Host);
        drill.policy = Some("DIRECT".into());
        let direct_hosts = ledger::query(&drill).unwrap().unwrap();
        let names: Vec<_> = direct_hosts
            .rows
            .iter()
            .map(|row| row.name.as_str())
            .collect();
        assert_eq!(names, ["192.0.2.1", "example.org"]);

        // Another process reads what was written.
        let read = ledger::read(&dir, &query(GroupBy::Policy)).unwrap();
        let names: Vec<_> = read.rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["Node A", "DIRECT"]);

        ledger::clear().unwrap();
        // The deleted hosts are not left in the write-ahead log.
        assert_eq!(
            fs::metadata(dir.join("traffic.db-wal")).map_or(0, |m| m.len()),
            0
        );
        assert!(ledger::query(&query(GroupBy::Host))
            .unwrap()
            .unwrap()
            .rows
            .is_empty());
        ledger::uninstall();
        ledger::set_interface("");
        add(&SmolStr::new("example.com"), &none, &proxy, 1, 1, 1);
        assert!(ledger::read(&dir, &query(GroupBy::Host))
            .unwrap()
            .rows
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// `(name, upload, download, requests, via_upload, via_requests)` of
    /// each row.
    fn rows(report: &Report) -> Vec<(&str, u64, u64, u64, u64, u64)> {
        report
            .rows
            .iter()
            .map(|row| {
                assert_eq!(row.via_download, row.via_upload * 10, "{}", row.name);
                (
                    row.name.as_str(),
                    row.upload,
                    row.download,
                    row.requests,
                    row.via_upload,
                    row.via_requests,
                )
            })
            .collect()
    }

    #[test]
    fn a_dialer_proxy_hop_counts_under_its_carrier_by_policy_only() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("via");
        ledger::install(&dir, Options::default()).unwrap();
        let through = |policy: &str, via: &str| Route {
            policy: Arc::from(policy),
            via: Some(Arc::from(via)),
        };
        let none = SmolStr::default();
        let (a, b, c) = (
            SmolStr::new("a.example"),
            SmolStr::new("b.example"),
            SmolStr::new("c.example"),
        );
        // A chained node through two members of its front group in turn,
        // one of them also an exit of its own, and a direct flow.
        add(&a, &none, &through("Chained", "Front 1"), 3, 30, 1);
        add(&a, &none, &through("Chained", "Front 2"), 1, 10, 1);
        add(&b, &none, &Route::from("Front 1"), 2, 20, 1);
        add(&c, &none, &Route::from("DIRECT"), 5, 50, 1);

        let policies = ledger::query(&query(GroupBy::Policy)).unwrap().unwrap();
        assert_eq!(
            rows(&policies),
            [
                ("Front 1", 5, 50, 2, 3, 1),
                ("DIRECT", 5, 50, 1, 0, 0),
                ("Chained", 4, 40, 2, 0, 0),
                ("Front 2", 1, 10, 1, 1, 1),
            ]
        );
        // Every flow once, though the rows add up to more.
        let totals = (policies.upload, policies.download, policies.requests);
        assert_eq!(totals, (11, 110, 4));

        // Any other grouping counts a flow in one row.
        let hosts = ledger::query(&query(GroupBy::Host)).unwrap().unwrap();
        assert_eq!(
            rows(&hosts),
            [
                ("c.example", 5, 50, 1, 0, 0),
                ("a.example", 4, 40, 2, 0, 0),
                ("b.example", 2, 20, 1, 0, 0),
            ]
        );
        assert_eq!((hosts.upload, hosts.download, hosts.requests), totals);

        // A member's row drills into what it carried, hops included.
        let mut drill = query(GroupBy::Host);
        drill.policy = Some("Front 1".into());
        let carried = ledger::query(&drill).unwrap().unwrap();
        assert_eq!(
            rows(&carried),
            [("a.example", 3, 30, 1, 0, 0), ("b.example", 2, 20, 1, 0, 0)]
        );
        assert_eq!(
            (carried.upload, carried.download, carried.requests),
            (5, 50, 2)
        );

        // A chained node's drills into the members that carried its hops.
        drill.by = GroupBy::Policy;
        drill.policy = Some("Chained".into());
        let fronts = ledger::query(&drill).unwrap().unwrap();
        assert_eq!(
            rows(&fronts),
            [
                ("Chained", 4, 40, 2, 0, 0),
                ("Front 1", 3, 30, 1, 3, 1),
                ("Front 2", 1, 10, 1, 1, 1),
            ]
        );
        assert_eq!(
            (fronts.upload, fronts.download, fronts.requests),
            (4, 40, 2)
        );

        // No hop matches an empty policy.
        drill.policy = Some(String::new());
        assert!(ledger::query(&drill).unwrap().unwrap().rows.is_empty());

        // Another process reads them alike.
        assert_eq!(
            ledger::read(&dir, &query(GroupBy::Policy)).unwrap(),
            policies
        );
        ledger::uninstall();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_schema_2_database_is_read_as_it_is_and_moved_on_as_the_ledger_opens() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("schema-2");
        fs::create_dir_all(&dir).unwrap();
        let today = ledger::today();
        let conn = Connection::open(dir.join(DB_FILE)).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE traffic (
                 day INTEGER NOT NULL, host TEXT NOT NULL, app TEXT NOT NULL,
                 policy TEXT NOT NULL, interface TEXT NOT NULL,
                 upload INTEGER NOT NULL, download INTEGER NOT NULL,
                 requests INTEGER NOT NULL,
                 PRIMARY KEY (day, host, app, policy, interface)
             ) WITHOUT ROWID;
             PRAGMA user_version = 2;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO traffic VALUES (?1, 'example.com', '', 'Node A', 'Wi-Fi', 1, 10, 1)",
            [today],
        )
        .unwrap();
        drop(conn);
        let before = (
            ledger::read(&dir, &query(GroupBy::Host)).unwrap(),
            ledger::read(&dir, &query(GroupBy::Policy)).unwrap(),
        );
        assert_eq!(rows(&before.0), [("example.com", 1, 10, 1, 0, 0)]);
        assert_eq!(rows(&before.1), [("Node A", 1, 10, 1, 0, 0)]);

        ledger::install(&dir, Options::default()).unwrap();
        assert!(!dir.join(CORRUPT_FILE).exists());
        let route = Route {
            policy: Arc::from("Node A"),
            via: Some(Arc::from("Front")),
        };
        ledger::set_interface("Wi-Fi");
        add(
            &SmolStr::new("example.com"),
            &SmolStr::default(),
            &route,
            2,
            20,
            1,
        );
        let policies = ledger::query(&query(GroupBy::Policy)).unwrap().unwrap();
        assert_eq!(
            rows(&policies),
            [("Node A", 3, 30, 2, 0, 0), ("Front", 2, 20, 1, 2, 1)]
        );
        ledger::uninstall();
        ledger::set_interface("");
        let conn = Connection::open(dir.join(DB_FILE)).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        drop(conn);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn counts_survive_a_restart_and_another_process_clears_them() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("restart");
        let proxy = Route::from("Node B");
        let none = SmolStr::default();
        ledger::install(&dir, Options::default()).unwrap();
        add(&SmolStr::new("example.com"), &none, &proxy, 1, 2, 1);
        ledger::uninstall();
        ledger::install(&dir, Options::default()).unwrap();
        add(&SmolStr::new("example.com"), &none, &proxy, 3, 4, 1);
        let report = ledger::query(&query(GroupBy::Host)).unwrap().unwrap();
        assert_eq!(report.rows.len(), 1);
        assert_eq!((report.upload, report.download, report.requests), (4, 6, 2));
        ledger::clear_at(&dir).unwrap();
        assert!(ledger::read(&dir, &query(GroupBy::Host))
            .unwrap()
            .rows
            .is_empty());
        ledger::uninstall();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_clear_from_another_process_drops_what_was_counted_before_it() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("cleared-elsewhere");
        let proxy = Route::from("Node C");
        let none = SmolStr::default();
        ledger::install(&dir, Options::default()).unwrap();
        // A day full of addresses on disk, and more counted, not written.
        for i in 0..MAX_IP_HOSTS {
            let ip = SmolStr::new(format!("10.0.{}.{}", i / 256, i % 256));
            add(&ip, &none, &proxy, 1, 1, 1);
        }
        ledger::flush();
        add(&SmolStr::new("example.com"), &none, &proxy, 5, 5, 1);

        // An app's UI empties it while the engine runs.
        ledger::clear_at(&dir).unwrap();
        let hosts = |by| ledger::query(&query(by)).unwrap().unwrap();
        assert!(
            hosts(GroupBy::Host).rows.is_empty(),
            "what was counted before is not written over the clear"
        );
        // Nor do the addresses it deleted count toward the cap.
        add(&SmolStr::new("192.0.2.1"), &none, &proxy, 7, 7, 1);
        let report = hosts(GroupBy::Host);
        let names: Vec<_> = report.rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["192.0.2.1"]);
        ledger::uninstall();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bytes_taken_across_a_clear_or_a_label_change_count_before_it() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("mark");
        let proxy = Route::from("Node D");
        let none = SmolStr::default();
        let host = SmolStr::new("example.com");
        ledger::install(&dir, Options::default()).unwrap();
        ledger::set_interface("Wi-Fi");

        // A settle reads its mark, a clear lands, then it adds what it took.
        let mark = ledger::mark();
        ledger::clear().unwrap();
        mark.add(&host, &none, &proxy, 1, 1, 1);
        assert!(
            ledger::query(&query(GroupBy::Host))
                .unwrap()
                .unwrap()
                .rows
                .is_empty(),
            "carried before the clear"
        );

        // A label change lands instead.
        let mark = ledger::mark();
        ledger::set_interface("Cellular");
        mark.add(&host, &none, &proxy, 2, 2, 1);
        add(&host, &none, &proxy, 3, 3, 1);
        let report = ledger::query(&query(GroupBy::Interface)).unwrap().unwrap();
        let rows: Vec<_> = report
            .rows
            .iter()
            .map(|row| (row.name.as_str(), row.upload))
            .collect();
        assert_eq!(rows, [("Cellular", 3), ("Wi-Fi", 2)]);
        ledger::uninstall();
        ledger::set_interface("");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_process_cannot_open_it() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("lock");
        let first = Ledger::open(&dir).unwrap();
        let error = Ledger::open(&dir).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(first);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_days_are_deleted_and_ip_hosts_are_capped() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("prune");
        fs::create_dir_all(&dir).unwrap();
        let conn = connect(&dir.join(DB_FILE)).ok().unwrap();
        let today = 20_000;
        for day in [today - RETENTION_DAYS, today - RETENTION_DAYS + 1, today] {
            conn.execute(
                UPSERT,
                params![day, "example.com", "", "DIRECT", "", "", 1, 1, 1],
            )
            .unwrap();
        }
        prune(&conn, today).unwrap();
        assert_eq!(rows_of_day(&conn, today - RETENTION_DAYS), 0);
        assert_eq!(rows_of_day(&conn, today - RETENTION_DAYS + 1), 1);

        let mut ip_hosts = None;
        for i in 0..MAX_IP_HOSTS {
            let host = format!("10.0.{}.{}", i / 256, i % 256);
            assert_eq!(
                cap_ip_host(&conn, &mut ip_hosts, today, &host).unwrap(),
                host
            );
        }
        assert_eq!(
            cap_ip_host(&conn, &mut ip_hosts, today, "192.0.2.9").unwrap(),
            OTHER_IPS
        );
        assert_eq!(
            cap_ip_host(&conn, &mut ip_hosts, today, "10.0.0.1").unwrap(),
            "10.0.0.1"
        );
        assert_eq!(
            cap_ip_host(&conn, &mut ip_hosts, today, "example.net").unwrap(),
            "example.net"
        );
        // Another day starts its own count.
        assert_eq!(
            cap_ip_host(&conn, &mut ip_hosts, today + 1, "192.0.2.9").unwrap(),
            "192.0.2.9"
        );
        drop(conn);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_batch_keeps_the_days_addresses_and_the_busiest_new_ones() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("batch-cap");
        ledger::install(&dir, Options::default()).unwrap();
        let direct = Route::from("DIRECT");
        let none = SmolStr::default();
        let hosts_of = |batch: &Batch| {
            let mut hosts: Vec<_> = batch.rows.keys().map(|(host, ..)| host.clone()).collect();
            hosts.sort();
            hosts
        };
        // Room for one more address on a day that has the rest.
        let mut known: HashSet<String> = (0..MAX_IP_HOSTS - 1)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect();
        add(&SmolStr::new("10.0.0.1"), &none, &direct, 1, 0, 1);
        add(&SmolStr::new("192.0.2.1"), &none, &direct, 100, 0, 1);
        add(&SmolStr::new("192.0.2.2"), &none, &direct, 10, 0, 1);
        let batch = Batch::take(20_000, &known);
        assert_eq!(hosts_of(&batch), [OTHER_IPS, "10.0.0.1", "192.0.2.1"]);
        // A full day folds every new address, never one it has, however
        // much busier the new ones are. A few stand for many: past
        // `EARLY_FLUSH` pending rows the writer would take them first.
        known.insert("10.0.255.255".into());
        add(&SmolStr::new("10.0.0.1"), &none, &direct, 1, 0, 1);
        for i in 0..16 {
            let host = SmolStr::new(format!("172.16.0.{i}"));
            add(&host, &none, &direct, 1_000, 0, 1);
        }
        let batch = Batch::take(20_000, &known);
        assert_eq!(hosts_of(&batch), [OTHER_IPS, "10.0.0.1"]);
        ledger::uninstall();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_query_or_clear_the_disk_refuses_fails() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("refused");
        ledger::install(&dir, Options::default()).unwrap();
        let proxy = Route::from("Node A");
        add(
            &SmolStr::new("example.com"),
            &SmolStr::default(),
            &proxy,
            1,
            2,
            1,
        );
        // Another process holds the write lock past the busy timeout: the
        // query is not current, and says so.
        let other = Connection::open(dir.join(DB_FILE)).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(ledger::query(&query(GroupBy::Host)).unwrap().is_err());
        other.execute_batch("COMMIT").unwrap();
        // What it could not write is written with the next flush.
        let report = ledger::query(&query(GroupBy::Host)).unwrap().unwrap();
        assert_eq!((report.upload, report.download, report.requests), (1, 2, 1));

        // A reader holding a snapshot past the busy timeout keeps the
        // deleted traffic on disk: the clear fails, and a later one does it.
        other.execute_batch("BEGIN").unwrap();
        let rows: i64 = other
            .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
        assert!(ledger::clear().is_err());
        other.execute_batch("COMMIT").unwrap();
        ledger::clear().unwrap();
        assert_eq!(
            fs::metadata(dir.join("traffic.db-wal")).map_or(0, |m| m.len()),
            0
        );
        drop(other);
        ledger::uninstall();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hosts_and_apps_off_keep_none_counted_after() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("hosts-off");
        ledger::install(&dir, Options::default()).unwrap();
        let proxy = Route::from("Node A");
        let host = SmolStr::new("www.example.com");
        let browser = SmolStr::new("org.example.browser");
        add(&host, &browser, &proxy, 1, 2, 1);
        ledger::install(
            &dir,
            Options {
                hosts: false,
                apps: false,
            },
        )
        .unwrap();
        // Counted after they went off, by a flow that opened with them on.
        add(&host, &browser, &proxy, 10, 20, 0);
        for (by, name) in [
            (GroupBy::Host, "example.com"),
            (GroupBy::App, "org.example.browser"),
        ] {
            let report = ledger::query(&query(by)).unwrap().unwrap();
            let rows: Vec<_> = report
                .rows
                .iter()
                .map(|row| (row.name.as_str(), row.upload))
                .collect();
            assert_eq!(rows, [("", 10), (name, 1)], "by {by:?}");
        }
        ledger::uninstall();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_late_flush_files_under_the_day_that_ended_unless_the_clock_jumped() {
        let zone = TimeZone::default();
        let midnight = 20_000 * 86_400;
        assert_eq!(flush_day(zone, midnight - 30, midnight), 19_999);
        assert_eq!(flush_day(zone, midnight + 1, midnight), 19_999);
        assert_eq!(flush_day(zone, midnight + LATE_FLUSH, midnight), 19_999);
        // A resume the next morning, a clock set from 1970 at boot.
        assert_eq!(flush_day(zone, midnight + 9 * 3600, midnight), 20_000);
        assert_eq!(flush_day(zone, midnight, 86_400), 20_000);
        // A clock set back.
        assert_eq!(flush_day(zone, midnight - 86_400 - 1, midnight), 19_998);
    }

    #[test]
    fn a_database_of_no_known_schema_is_set_aside() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Unknown, and the schema without `app` of test builds.
        for version in [-1, 1] {
            let dir = dir("schema");
            fs::create_dir_all(&dir).unwrap();
            let conn = Connection::open(dir.join(DB_FILE)).unwrap();
            conn.pragma_update(None, "user_version", version).unwrap();
            drop(conn);
            ledger::install(&dir, Options::default()).unwrap();
            assert!(dir.join(CORRUPT_FILE).exists(), "schema {version}");
            let direct = Route::from("DIRECT");
            add(
                &SmolStr::new("example.com"),
                &SmolStr::default(),
                &direct,
                1,
                1,
                1,
            );
            let report = ledger::query(&query(GroupBy::Host)).unwrap().unwrap();
            assert_eq!(report.requests, 1);
            ledger::uninstall();
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
