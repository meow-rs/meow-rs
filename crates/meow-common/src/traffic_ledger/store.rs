//! The store behind the traffic ledger: a writer thread that commits what
//! the tunnel counted to an SQLite database.

use super::{
    date_of_day, unix_now, zone, Batch, GroupBy, Query, Report, Row, MAX_IP_HOSTS, OTHER_IPS,
    RETENTION_DAYS,
};
use rusqlite::{params, Connection, ErrorCode, OpenFlags};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::warn;

const DB_FILE: &str = "traffic.db";
/// An unreadable database is moved here and the ledger starts over.
const CORRUPT_FILE: &str = "traffic.db.corrupt";
const LOCK_FILE: &str = "traffic.lock";

/// `PRAGMA user_version` of [`SCHEMA`]. A database from a newer meow is
/// left alone, neither read nor rewritten.
const SCHEMA_VERSION: i64 = 1;

/// A contract with readers in other processes. `day` counts local days
/// since 1970-01-01; `host` is a registrable domain, an IP address,
/// [`OTHER_IPS`] or empty; `interface` is empty when the platform set no
/// label.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS traffic (
    day       INTEGER NOT NULL,
    host      TEXT NOT NULL,
    policy    TEXT NOT NULL,
    interface TEXT NOT NULL,
    upload    INTEGER NOT NULL,
    download  INTEGER NOT NULL,
    requests  INTEGER NOT NULL,
    PRIMARY KEY (day, host, policy, interface)
) WITHOUT ROWID;
";

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
INSERT INTO traffic (day, host, policy, interface, upload, download, requests)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
ON CONFLICT (day, host, policy, interface) DO UPDATE SET
    upload = upload + excluded.upload,
    download = download + excluded.download,
    requests = requests + excluded.requests
";

/// How long a flush or a query waits for the writer.
const WAIT: Duration = Duration::from_secs(5);

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
    Clear(SyncSender<()>),
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
        let mut writer = Writer {
            conn,
            pruned: i32::MIN,
            ip_hosts: None,
            backlog: Vec::new(),
            failing: false,
        };
        writer.prune(zone().day(unix_now()));
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
        let (ack, done) = mpsc::sync_channel(1);
        if self.send(Op::Flush(ack)) {
            let _ = done.recv_timeout(WAIT);
        }
    }

    pub fn query(&self, query: &Query) -> io::Result<Report> {
        let (reply, answer) = mpsc::sync_channel(1);
        if !self.send(Op::Query(Box::new(query.clone()), reply)) {
            return Err(io::Error::other("the traffic ledger writer stopped"));
        }
        answer
            .recv_timeout(WAIT)
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "busy")))
    }

    pub fn clear(&self) {
        let (ack, done) = mpsc::sync_channel(1);
        if self.send(Op::Clear(ack)) {
            let _ = done.recv_timeout(WAIT);
        }
    }

    fn send(&self, op: Op) -> bool {
        self.tx.as_ref().is_some_and(|tx| tx.send(op).is_ok())
    }
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
                    self.flush(&mut day_end);
                    let _ = ack.send(());
                }
                Ok(Op::Query(query, reply)) => {
                    self.flush(&mut day_end);
                    let _ = reply.send(report(&self.conn, &query).map_err(io::Error::other));
                }
                Ok(Op::Clear(ack)) => {
                    drop(super::take_pending());
                    self.backlog.clear();
                    if let Err(e) = clear(&self.conn) {
                        warn!("traffic ledger: cannot clear: {e}");
                    }
                    self.ip_hosts = None;
                    let _ = ack.send(());
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.flush(&mut day_end);
                    due = Instant::now() + super::FLUSH_INTERVAL;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.flush(&mut day_end);
                    return;
                }
            }
        }
    }

    /// Take what is pending and commit it, with what failed before, under
    /// today — or under the day that ended at `day_end`, for a flush that
    /// comes late for it: what is pending was counted before it ended.
    fn flush(&mut self, day_end: &mut i64) {
        let now = unix_now();
        let zone = zone();
        let day = zone.day(now.min(*day_end - 1));
        *day_end = zone.next_midnight(now);
        let batch = Batch::take(day);
        if !batch.rows.is_empty() {
            if self.backlog.len() == BACKLOG {
                self.backlog.remove(0);
            }
            self.backlog.push(batch);
        }
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
                }
            }
        }
        self.prune(zone.day(now));
    }

    fn commit(&mut self) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut upsert = tx.prepare(UPSERT)?;
            for batch in &self.backlog {
                for ((host, policy), counts) in &batch.rows {
                    let host = cap_ip_host(&tx, &mut self.ip_hosts, batch.day, host)?;
                    upsert.execute(params![
                        batch.day,
                        host,
                        &**policy,
                        batch.interface.as_str(),
                        int(counts.upload),
                        int(counts.download),
                        int(counts.requests),
                    ])?;
                }
            }
        }
        tx.commit()
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
    if ip_hosts.as_ref().is_none_or(|(loaded, _)| *loaded != day) {
        let mut statement = conn.prepare("SELECT DISTINCT host FROM traffic WHERE day = ?1")?;
        let hosts = statement
            .query_map([day], |row| row.get::<_, String>(0))?
            .filter_map(Result::ok)
            .filter(|host| host.parse::<std::net::IpAddr>().is_ok())
            .collect();
        *ip_hosts = Some((day, hosts));
    }
    let Some((_, hosts)) = ip_hosts.as_mut() else {
        return Ok(host);
    };
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
    vacuum(conn)
}

/// Hand the free pages back to the file system.
fn vacuum(conn: &Connection) -> rusqlite::Result<()> {
    let mut statement = conn.prepare("PRAGMA incremental_vacuum")?;
    let mut rows = statement.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

/// `query` answered from `conn`.
fn report(conn: &Connection, query: &Query) -> rusqlite::Result<Report> {
    let column = match query.by {
        GroupBy::Host => "host",
        GroupBy::Policy => "policy",
        GroupBy::Interface => "interface",
    };
    let sql = format!(
        "SELECT {column}, SUM(upload), SUM(download), SUM(requests) FROM traffic \
         WHERE day BETWEEN ?1 AND ?2 \
         AND (?3 IS NULL OR host = ?3) \
         AND (?4 IS NULL OR policy = ?4) \
         AND (?5 IS NULL OR interface = ?5) \
         GROUP BY {column} \
         ORDER BY SUM(upload) + SUM(download) DESC, SUM(requests) DESC, {column}"
    );
    let mut statement = conn.prepare(&sql)?;
    let rows = statement
        .query_map(
            params![
                query.from,
                query.to,
                query.host,
                query.policy,
                query.interface
            ],
            |row| {
                Ok(Row {
                    name: row.get(0)?,
                    upload: uint(row.get(1)?),
                    download: uint(row.get(2)?),
                    requests: uint(row.get(3)?),
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut report = empty_report(query);
    for row in &rows {
        report.upload = report.upload.saturating_add(row.upload);
        report.download = report.download.saturating_add(row.download);
        report.requests = report.requests.saturating_add(row.requests);
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
    if schema_version(&conn).map_err(Unusable::into_io)? == 0 {
        // Created, and the schema not committed yet.
        return Ok(empty_report(query));
    }
    report(&conn, query).map_err(io::Error::other)
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
    }
    Ok(conn)
}

/// The database's `user_version`; one from a newer meow is an error.
fn schema_version(conn: &Connection) -> Result<i64, Unusable> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
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
    use super::super::{self as ledger, add, Options, Query, OTHER_IPS};
    use super::*;
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
    fn traffic_is_kept_by_host_policy_and_interface() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("groups");
        ledger::install(&dir, Options::default()).unwrap();
        let proxy: Arc<str> = Arc::from("Node A");
        let direct: Arc<str> = Arc::from("DIRECT");
        ledger::set_interface("Wi-Fi");
        add(&SmolStr::new("www.example.com"), &proxy, 100, 1000, 1);
        add(&SmolStr::new("api.example.com"), &proxy, 10, 100, 1);
        add(&SmolStr::new("192.0.2.1"), &direct, 5, 5, 1);
        ledger::set_interface("Cellular");
        add(&SmolStr::new("example.org"), &direct, 1, 2, 1);

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

        ledger::clear();
        assert!(ledger::query(&query(GroupBy::Host))
            .unwrap()
            .unwrap()
            .rows
            .is_empty());
        ledger::uninstall();
        ledger::set_interface("");
        add(&SmolStr::new("example.com"), &proxy, 1, 1, 1);
        assert!(ledger::read(&dir, &query(GroupBy::Host))
            .unwrap()
            .rows
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn counts_survive_a_restart_and_another_process_clears_them() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = dir("restart");
        let proxy: Arc<str> = Arc::from("Node B");
        ledger::install(&dir, Options::default()).unwrap();
        add(&SmolStr::new("example.com"), &proxy, 1, 2, 1);
        ledger::uninstall();
        ledger::install(&dir, Options::default()).unwrap();
        add(&SmolStr::new("example.com"), &proxy, 3, 4, 1);
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
            conn.execute(UPSERT, params![day, "example.com", "DIRECT", "", 1, 1, 1])
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
}
